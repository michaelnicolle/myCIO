/**
 * Bridge from Node.js to PowerShell 7 (`pwsh`) for collecting Exchange Online,
 * Security & Compliance, and Microsoft Teams signals that Microsoft Graph has no
 * API surface for (confirmed by prior research: no Graph v1.0/beta equivalent for
 * DKIM/DMARC, transport rules, Defender for Office policies, Teams federation, etc.).
 *
 * This module REUSES `GraphCertificateAuthConfig` (src/lib/graph/authClient.ts) rather
 * than inventing a new auth config type — it's the same per-tenant certificate already
 * used for Graph app-only auth, just handed to a PowerShell child process instead of
 * `@azure/identity`. See src/lib/powershell/README.md for the additional one-time
 * Entra role/permission grants (Exchange.ManageAsApp, Exchange Administrator, Teams
 * Administrator) a customer's Global Admin must complete before these collectors will
 * connect successfully.
 *
 * Design mirrors two existing patterns in this codebase:
 *   - src/lib/crypto/envelope.ts: decrypted/sensitive material has a minimal lifetime,
 *     is never logged, and errors are sanitized before propagating.
 *   - src/lib/graph/index.ts (`runCollector`): one signal failing must never prevent
 *     collection of the others. Here that's implemented *inside* the PowerShell scripts
 *     themselves (each `Get-*` wrapped in its own try/catch, see the .ps1 files), since
 *     the whole script is a single child-process invocation from Node's point of view.
 *
 * Security model for the temp credential files this module writes to disk:
 *   - A fresh, randomly-named temp directory is created per invocation via `fs.mkdtemp`.
 *   - `cert.pem` (public certificate) and `key.pem` (private key) are written as SEPARATE
 *     files, each mode 0o600 (owner read/write only).
 *   - If the certificate's private key is itself password-protected, the password is
 *     passed to the child process via an environment variable, NOT a CLI argument and
 *     NOT a file on disk — see the comment on `KEY_PASSWORD_ENV_VAR` below for the
 *     tradeoffs of that choice.
 *   - The temp directory is deleted, recursively and unconditionally, in a `finally`
 *     block — this is the primary guarantee against leaking key material to disk, and it
 *     does not depend on the PowerShell script's own (best-effort) cleanup.
 *   - Nothing in this module ever logs `certificatePem`, `certificatePassword`, temp file
 *     paths' *contents*, or stderr verbatim alongside those contents.
 */

import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { GraphCertificateAuthConfig } from '@/lib/graph/authClient';

/** Env var used to pass the certificate private-key password to the child `pwsh` process.
 *
 * Tradeoff (documented rather than treated as solved): environment variables passed
 * directly to a child process are not visible in `ps aux`/`/proc/[pid]/cmdline`-style
 * process listings the way CLI arguments are, which is why this is preferred over a
 * `-KeyPassword` argument. However, env vars ARE still readable via `/proc/[pid]/environ`
 * by the same OS user (or root), so this is a mitigation against the more common/casual
 * leak vector (process listing tools, shell history, CI log capture of argv), not an
 * absolute guarantee of confidentiality against a co-resident attacker with the same
 * privilege level as the worker process itself.
 */
const KEY_PASSWORD_ENV_VAR = 'PSBRIDGE_KEY_PASSWORD';

/** Grace period after SIGTERM before escalating to SIGKILL on timeout. */
const SIGKILL_GRACE_MS = 5_000;

/** How much of stdout to include (truncated) in a JSON-parse-failure error message for debugging. */
const STDOUT_SNIPPET_MAX_CHARS = 500;

export class PowerShellBridgeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PowerShellBridgeError';
  }
}

export class PowerShellBridgeTimeoutError extends PowerShellBridgeError {
  constructor(timeoutMs: number) {
    super(`PowerShell collector timed out after ${timeoutMs}ms and was killed.`);
    this.name = 'PowerShellBridgeTimeoutError';
  }
}

/**
 * Splits a combined PEM blob (as produced by `@azure/identity`'s `ClientCertificatePEMCertificate`
 * convention — see `authClient.ts`'s `buildCredential`, which hands `certificatePem` to
 * `ClientCertificateCredential` as a single string "PEM-encoded ... certificate ... contains both
 * the public and private keys") into separate certificate and private-key PEM blocks.
 *
 * We split here (rather than writing one combined file) because .NET's
 * `X509Certificate2.CreateFromPemFile(certPath, keyPath)` / `CreateFromEncryptedPemFile(certPath,
 * password, keyPath)` — used by the PowerShell scripts — take the certificate and key as two
 * distinct file paths. `CreateFromPemFile` documents that if `keyPemFilePath` is omitted it will
 * scan `certPemFilePath` for a key too, but we split explicitly for clarity and so each file can
 * be independently permissioned/audited.
 */
export function splitCombinedPem(combinedPem: string): { certificatePem: string; keyPem: string } {
  const certMatch = combinedPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
  const keyMatch = combinedPem.match(
    /-----BEGIN (?:ENCRYPTED PRIVATE KEY|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----[\s\S]*?-----END (?:ENCRYPTED PRIVATE KEY|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----/,
  );

  if (!certMatch) {
    throw new PowerShellBridgeError(
      'Certificate PEM material is missing a CERTIFICATE block; cannot construct cert.pem for the PowerShell bridge.',
    );
  }
  if (!keyMatch) {
    throw new PowerShellBridgeError(
      'Certificate PEM material is missing a PRIVATE KEY block; cannot construct key.pem for the PowerShell bridge.',
    );
  }

  return { certificatePem: `${certMatch[0]}\n`, keyPem: `${keyMatch[0]}\n` };
}

/** Truncates a string for safe inclusion in an error message (never used on secret material). */
function truncate(value: string, maxChars: number): string {
  return value.length > maxChars ? `${value.slice(0, maxChars)}...(truncated)` : value;
}

interface SpawnResult {
  stdout: string;
  stderr: string;
}

/**
 * Spawns `pwsh` with an argument array (never a shell string — this avoids any possibility of
 * shell metacharacter interpretation in paths/GUIDs, even though those values are expected to be
 * well-formed) and enforces `timeoutMs` via SIGTERM followed by SIGKILL after a grace period.
 */
function runPwsh(args: string[], env: NodeJS.ProcessEnv, timeoutMs: number): Promise<SpawnResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('pwsh', args, {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: false,
    });

    let stdout = '';
    let stderr = '';
    let settled = false;
    let killGraceTimer: NodeJS.Timeout | undefined;

    const timeoutTimer = setTimeout(() => {
      if (settled) return;
      child.kill('SIGTERM');
      killGraceTimer = setTimeout(() => {
        if (!settled) child.kill('SIGKILL');
      }, SIGKILL_GRACE_MS);
      settled = true;
      clearTimeout(timeoutTimer);
      reject(new PowerShellBridgeTimeoutError(timeoutMs));
    }, timeoutMs);

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (killGraceTimer) clearTimeout(killGraceTimer);
      reject(new PowerShellBridgeError(`Failed to spawn pwsh: ${err.message}`));
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (killGraceTimer) clearTimeout(killGraceTimer);

      if (code !== 0) {
        // stderr may contain diagnostic noise (module warnings, etc.) — log it via console.warn
        // per the contract, but never surface it as part of a thrown error message here, since
        // stderr content is outside this function's control and we don't want to risk it being
        // persisted somewhere errors get stored/displayed beyond a dev console.
        // eslint-disable-next-line no-console
        console.warn(`[powershell:bridge] pwsh exited with code ${code}; stderr follows:\n${stderr}`);
        reject(new PowerShellBridgeError(`pwsh exited with non-zero code ${code}.`));
        return;
      }

      if (stderr.trim().length > 0) {
        // eslint-disable-next-line no-console
        console.warn(`[powershell:bridge] pwsh stderr (diagnostic only, not parsed as data):\n${stderr}`);
      }

      resolve({ stdout, stderr });
    });
  });
}

/**
 * Runs one PowerShell collector script (under src/lib/powershell/scripts) and parses its single
 * line of stdout JSON into `T`. See src/lib/powershell/README.md for the full script contract.
 *
 * @param scriptRelativePath - Path relative to src/lib/powershell, e.g.
 *   'scripts/Collect-ExoComplianceSignals.ps1'.
 * @param authConfig - Already-decrypted certificate credential (same shape used for Graph auth).
 * @param timeoutMs - Hard wall-clock cap; the child process is killed (SIGTERM, then SIGKILL
 *   after a grace period) if exceeded.
 */
export async function runPowerShellCollector<T>(
  scriptRelativePath: string,
  authConfig: GraphCertificateAuthConfig,
  timeoutMs: number,
): Promise<T> {
  const scriptPath = join(__dirname, scriptRelativePath);

  const tempDirPrefix = join(tmpdir(), 'posture-ps-bridge-');
  const tempDir = await mkdtemp(tempDirPrefix);

  try {
    const { certificatePem, keyPem } = splitCombinedPem(authConfig.certificatePem);

    const certPath = join(tempDir, 'cert.pem');
    const keyPath = join(tempDir, 'key.pem');

    // mode 0o600: owner read/write only. Written with an explicit random subdirectory name
    // (from mkdtemp) so no other process can predict the path ahead of time either.
    // Both paths below are join(tempDir, ...) where tempDir came from this function's own
    // mkdtemp() call above, not from any external/user-controlled input.
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    await writeFile(certPath, certificatePem, { mode: 0o600 });
    // eslint-disable-next-line security/detect-non-literal-fs-filename
    await writeFile(keyPath, keyPem, { mode: 0o600 });

    const args = [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-File',
      scriptPath,
      '-CertPath',
      certPath,
      '-KeyPath',
      keyPath,
      '-EntraTenantId',
      authConfig.entraTenantId,
      '-ClientId',
      authConfig.clientId,
    ];

    const env: NodeJS.ProcessEnv = { ...process.env };
    if (authConfig.certificatePassword) {
      env[KEY_PASSWORD_ENV_VAR] = authConfig.certificatePassword;
    } else {
      delete env[KEY_PASSWORD_ENV_VAR];
    }

    const { stdout } = await runPwsh(args, env, timeoutMs);

    // The contract is "stdout contains exactly one line of JSON", but we defensively take the
    // last non-empty line rather than assuming the very first/only line is clean: some
    // PowerShell module import paths are known to emit stray Write-Output/Write-Information
    // noise ahead of a script's real output in edge cases, and the scripts here always emit
    // their JSON as the final Write-Output call.
    const nonEmptyLines = stdout.split(/\r?\n/).filter((l) => l.trim().length > 0);
    const line = (nonEmptyLines[nonEmptyLines.length - 1] ?? '').trim();
    try {
      return JSON.parse(line) as T;
    } catch {
      throw new PowerShellBridgeError(
        `Failed to parse PowerShell collector stdout as JSON. Received (truncated): ` +
          `"${truncate(line, STDOUT_SNIPPET_MAX_CHARS)}"`,
      );
    }
  } finally {
    // CRITICAL, non-negotiable: this always runs, regardless of success/throw/timeout-kill above.
    // This is the primary guarantee against leaking key material to disk — we do not rely on the
    // PowerShell script's own (best-effort) cleanup of anything it may have imported/created.
    await rm(tempDir, { recursive: true, force: true }).catch(() => {
      // Swallow: if this fails there is nothing more this function can do, and throwing from a
      // finally block would mask whatever error (or success) preceded it. The temp dir uses a
      // random, unpredictable name and 0o600 file permissions, and OS temp dirs are typically
      // cleaned on reboot, so residual risk is bounded even in this unlikely failure case.
      // eslint-disable-next-line no-console
      console.warn(`[powershell:bridge] failed to remove temp directory (non-fatal, see above).`);
    });
  }
}

