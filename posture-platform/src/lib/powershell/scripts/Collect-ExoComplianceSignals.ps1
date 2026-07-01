#Requires -Version 7.0
<#
.SYNOPSIS
    Collects Exchange Online / Security & Compliance security-configuration signals that
    Microsoft Graph has no API surface for (DKIM, DMARC, transport rules, remote domains,
    org mail config, mailbox audit bypass, sharing policies, Defender for Office 365
    policies, unified audit log ingestion state).

.DESCRIPTION
    Invoked by src/lib/powershell/bridge.ts (`runPowerShellCollector`) as a child `pwsh`
    process. Contract with the Node-side caller:
      - stdout: EXACTLY ONE line of compact JSON (the result object below).
      - stderr: diagnostic/warning noise only, never parsed as data by the caller.
      - Exit code 0 in both the success and "could not connect" cases (a connection
        failure is a graceful degradation recorded in `errors`, not a script crash -
        the Node-side caller decides how to interpret an empty/error-only result).
      - This script NEVER prints certificate/key file contents, and receives the private
        key password (if any) only via the PSBRIDGE_KEY_PASSWORD environment variable,
        never as a CLI argument (so it doesn't appear in process listings).

    Every individual `Get-*` call is wrapped in its own try/catch so one failing cmdlet
    (insufficient RBAC role, feature not enabled in this tenant, transient throttling,
    etc.) never blocks collection of the other signals - mirroring the `runCollector`
    isolation pattern in src/lib/graph/index.ts, just implemented at the script level
    since the whole script is a single child-process invocation from Node's perspective.

.NOTES
    VERIFICATION STATUS (see src/lib/powershell/README.md for the full caveat):
    This script has been syntax-checked with PowerShell's AST parser only. The
    ExchangeOnlineManagement module could NOT be installed in the authoring environment
    (PSGallery registration failed - proxy/network restriction specific to the PowerShell
    Gallery's OData protocol), so cmdlet parameter names below could not be verified by
    introspecting the installed module. Cmdlet/parameter names were verified against
    Microsoft Learn documentation where noted; anywhere that was not possible, the
    comment says so explicitly. This has NOT been run against a live tenant.
#>

param(
    [Parameter(Mandatory = $true)][string]$CertPath,
    [Parameter(Mandatory = $true)][string]$KeyPath,
    [Parameter(Mandatory = $true)][string]$EntraTenantId,
    [Parameter(Mandatory = $true)][string]$ClientId
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$result = [ordered]@{
    collectedAt = (Get-Date).ToUniversalTime().ToString('o')
    errors      = @()
}

function Add-CollectionError {
    param([string]$Signal, [string]$Message)
    # Defense-in-depth: never let a cmdlet's error message accidentally include the key
    # file *contents* (it shouldn't - .NET/EXO errors reference paths, not PEM bytes -
    # but truncate defensively in case an upstream SDK ever embeds unexpected detail).
    $safeMessage = if ($Message.Length -gt 500) { $Message.Substring(0, 500) + '...(truncated)' } else { $Message }
    $script:result.errors += [ordered]@{ signal = $Signal; message = $safeMessage }
}

$eomConnected = $false
$ippsConnected = $false

try {
    # Import the module explicitly so a missing-module failure produces a clear error
    # rather than an obscure "command not found" further down.
    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    # Build an in-memory X509Certificate2 from the separate cert/key PEM files written by
    # the Node bridge (see bridge.ts: cert.pem + key.pem, mode 0600, in a fresh temp dir).
    #
    # X509Certificate2.CreateFromPemFile(certPath, keyPath) and
    # X509Certificate2.CreateFromEncryptedPemFile(certPath, password, keyPath) are real,
    # documented static methods (System.Security.Cryptography.X509Certificates, .NET 5+/
    # available in PowerShell 7.6's .NET runtime) - verified against Microsoft Learn during
    # authoring of this script (learn.microsoft.com/dotnet/api/.../x509certificate2.createfrompemfile
    # and .../createfromencryptedpemfile). Not independently re-verified against a live
    # PowerShell 7.6 session in this environment.
    $keyPassword = $env:PSBRIDGE_KEY_PASSWORD
    if ([string]::IsNullOrEmpty($keyPassword)) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertPath, $KeyPath)
    } else {
        $securePassword = ConvertTo-SecureString -String $keyPassword -AsPlainText -Force
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromEncryptedPemFile($CertPath, $securePassword, $KeyPath)
    }
    # Clear the plaintext password variable reference as soon as it's no longer needed.
    # (PowerShell strings are immutable so this does not zero the underlying memory the
    # way envelope.ts's Buffer.fill(0) does for Node Buffers - noted as a known
    # limitation, not a false claim of a stronger guarantee.)
    $keyPassword = $null

    # On some EXO module versions, X509Certificate2 objects built via CreateFromPemFile
    # are "ephemeral" (not exportable/not associated with a persisted key storage flag),
    # which has been reported to cause issues with Connect-ExchangeOnline's -Certificate
    # parameter on Windows (it may expect a certificate backed by a key that supports
    # export/persistence). Re-importing through the PFX/export round-trip is the commonly
    # documented workaround. This may be unnecessary on Linux/pwsh 7 - UNVERIFIED, since a
    # live connection test was not possible in this environment - but is included
    # defensively since it is a no-op if not needed and cheap to perform.
    try {
        $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes,
            [string]::Empty,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
    } catch {
        # If the round-trip fails for any reason, fall back to the originally constructed
        # certificate object rather than aborting the whole script.
    }

    # Connect-ExchangeOnline -Certificate <X509Certificate2> -AppId <clientId>
    # -Organization <tenant> : parameter names verified against Microsoft Learn
    # (learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline)
    # during authoring - "The Certificate parameter specifies the certificate object used
    # for CBA... AppId specifies the application ID (GUID)... Organization: use the
    # Exchange Online primary .onmicrosoft.com domain."
    #
    # UNVERIFIED: whether -Organization strictly requires the *.onmicrosoft.com domain or
    # will also accept the raw Entra tenant GUID we have on hand ($EntraTenantId). Some
    # Microsoft docs/community threads suggest CBA connections accept the tenant GUID too;
    # this could not be confirmed against a live tenant in this environment. Passing the
    # GUID here as the best available value - if a real tenant's onboarding record also
    # stores its primary .onmicrosoft.com domain, prefer wiring that through as a future
    # improvement instead of the GUID.
    Connect-ExchangeOnline -Certificate $cert -AppId $ClientId -Organization $EntraTenantId `
        -ShowBanner:$false -ShowProgress:$false | Out-Null
    $eomConnected = $true

    # Get-AdminAuditLogConfig's UnifiedAuditLogIngestionEnabled property is documented to
    # always read as $false when queried over a Security & Compliance (IPPSSession)
    # connection - it must be queried over the plain Exchange Online session to reflect
    # the real tenant state. Verified against Microsoft Learn during authoring
    # (learn.microsoft.com/powershell/module/exchangepowershell/get-adminauditlogconfig).
    # This is why this script does NOT rely on Connect-IPPSSession for that signal.
    try {
        Connect-IPPSSession -Certificate $cert -AppId $ClientId -Organization $EntraTenantId `
            -ShowBanner:$false | Out-Null
        $ippsConnected = $true
    } catch {
        # None of the signals currently collected strictly require the Security &
        # Compliance session (see note above re: Get-AdminAuditLogConfig) - keep this
        # best-effort so a missing Compliance-side role grant doesn't block the rest.
        Add-CollectionError -Signal 'ippsSessionConnect' -Message $_.Exception.Message
    }
} catch {
    Add-CollectionError -Signal 'connection' -Message $_.Exception.Message
    Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
    exit 0
}

try {
    $result.dkimConfigs = @(Get-DkimSigningConfig | ForEach-Object {
        [ordered]@{ domain = $_.Domain; enabled = [bool]$_.Enabled }
    })
} catch {
    Add-CollectionError -Signal 'dkimConfigs' -Message $_.Exception.Message
}

try {
    # DMARC has no dedicated Exchange Online cmdlet - it is a DNS TXT record at
    # "_dmarc.<domain>", not tenant configuration. We enumerate accepted domains via
    # Get-AcceptedDomain (a real EXO cmdlet) and resolve each domain's DMARC TXT record
    # via Resolve-DnsName. NOTE: this requires outbound DNS resolution from wherever this
    # worker process runs (the machine executing this script), which may differ from
    # whatever DNS path a browser/admin center check would use - flagged here since it is
    # an environmental dependency this script cannot itself guarantee.
    $acceptedDomains = Get-AcceptedDomain
    $result.dmarcConfigs = @($acceptedDomains | ForEach-Object {
        $domainName = $_.DomainName
        $record = $null
        $policy = $null
        try {
            $dnsAnswers = Resolve-DnsName -Name "_dmarc.$domainName" -Type TXT -ErrorAction Stop
            $txt = ($dnsAnswers | Where-Object { $_.Strings } | Select-Object -First 1).Strings -join ''
            if ($txt) {
                $record = $txt
                if ($txt -match 'p=(none|quarantine|reject)') {
                    $policy = $Matches[1]
                }
            }
        } catch {
            # No DMARC record found, or DNS resolution failed for this domain - record
            # null rather than failing the whole dmarcConfigs signal for one bad domain.
        }
        [ordered]@{ domain = $domainName; record = $record; policy = $policy }
    })
} catch {
    Add-CollectionError -Signal 'dmarcConfigs' -Message $_.Exception.Message
}

try {
    $result.transportRules = @(Get-TransportRule | ForEach-Object {
        $isExternalForwarding = [bool]($_.RedirectMessageTo -or $_.BlindCopyTo -or $_.ForwardTo)
        [ordered]@{
            id                       = $_.Guid.ToString()
            name                     = $_.Name
            state                    = $_.State.ToString()
            isExternalForwardingRule = $isExternalForwarding
        }
    })
} catch {
    Add-CollectionError -Signal 'transportRules' -Message $_.Exception.Message
}

try {
    $result.remoteDomains = @(Get-RemoteDomain | ForEach-Object {
        [ordered]@{
            domainName         = $_.DomainName
            autoForwardEnabled = [bool]$_.AutoForwardEnabled
        }
    })
} catch {
    Add-CollectionError -Signal 'remoteDomains' -Message $_.Exception.Message
}

try {
    $orgConfig = Get-OrganizationConfig
    $transportConfig = Get-TransportConfig
    $result.organizationMailConfig = [ordered]@{
        smtpClientAuthenticationDisabled = [bool]$transportConfig.SmtpClientAuthenticationDisabled
        auditDisabled                    = [bool]$orgConfig.AuditDisabled
    }
} catch {
    Add-CollectionError -Signal 'organizationMailConfig' -Message $_.Exception.Message
}

try {
    $result.mailboxAuditBypass = @(
        Get-MailboxAuditBypassAssociation -ResultSize Unlimited |
        Where-Object { $_.AuditBypassEnabled } |
        ForEach-Object {
            [ordered]@{ identity = $_.Identity.ToString(); auditBypassEnabled = [bool]$_.AuditBypassEnabled }
        }
    )
} catch {
    Add-CollectionError -Signal 'mailboxAuditBypass' -Message $_.Exception.Message
}

try {
    # sharesCalendarDetailsExternally: best-effort derivation. SharingPolicy.Domains is a
    # collection of "<Domain>:<SharingPolicyAction>" strings (e.g. "*:CalendarSharingFreeBusyDetail",
    # "Anonymous:CalendarSharingFreeBusySimple"). We treat any entry that (a) targets "*" or
    # "Anonymous" AND (b) includes a "Detail"-level calendar sharing action as external
    # detail-sharing. UNVERIFIED against a live tenant's actual Domains string formatting -
    # this is a best-effort parse of the documented SharingPolicy shape, not a Microsoft-confirmed
    # regex.
    $result.sharingPolicies = @(Get-SharingPolicy | ForEach-Object {
        $domainEntries = @($_.Domains)
        $sharesExternally = [bool]($domainEntries | Where-Object {
            ($_ -match '^\*:' -or $_ -match '^Anonymous:') -and ($_ -match 'CalendarSharingFreeBusyDetail')
        })
        [ordered]@{
            id                              = $_.Guid.ToString()
            name                            = $_.Name
            sharesCalendarDetailsExternally = $sharesExternally
        }
    })
} catch {
    Add-CollectionError -Signal 'sharingPolicies' -Message $_.Exception.Message
}

try {
    # isEffectivelyDisabled: best-effort derivation - a hosted content filter policy is
    # treated as "effectively disabled" if every meaningful spam-action property is set to
    # a no-op value. Property names (SpamAction/HighConfidenceSpamAction/etc.) verified
    # against general Defender for Office 365 documentation knowledge; exact enum member
    # names for "no action" (commonly "MoveToJmf" / "NoAction" depending on property and
    # module version) were NOT independently re-verified against an installed module in
    # this environment - treat this derivation as a best-effort heuristic, not a precise
    # contract, until validated against a live tenant.
    $result.hostedContentFilterPolicies = @(Get-HostedContentFilterPolicy | ForEach-Object {
        $spamActions = @($_.SpamAction, $_.HighConfidenceSpamAction, $_.PhishSpamAction, $_.BulkSpamAction) |
            Where-Object { $_ -ne $null }
        $isEffectivelyDisabled = [bool]($spamActions.Count -gt 0 -and
            ($spamActions | ForEach-Object { $_.ToString() } | Where-Object { $_ -notmatch 'NoAction|MoveToJmf' }).Count -eq 0)
        [ordered]@{
            id                    = $_.Guid.ToString()
            name                  = $_.Name
            isDefault             = [bool]$_.IsDefault
            isEffectivelyDisabled = $isEffectivelyDisabled
        }
    })
} catch {
    Add-CollectionError -Signal 'hostedContentFilterPolicies' -Message $_.Exception.Message
}

try {
    $result.hostedConnectionFilterPolicies = @(Get-HostedConnectionFilterPolicy | ForEach-Object {
        [ordered]@{
            id           = $_.Guid.ToString()
            name         = $_.Name
            ipAllowList  = @($_.IPAllowList | ForEach-Object { $_.ToString() })
        }
    })
} catch {
    Add-CollectionError -Signal 'hostedConnectionFilterPolicies' -Message $_.Exception.Message
}

try {
    $result.antiPhishPolicies = @(Get-AntiPhishPolicy | ForEach-Object {
        [ordered]@{
            id                           = $_.Guid.ToString()
            isDefault                    = [bool]$_.IsDefault
            enableMailboxIntelligence    = [bool]$_.EnableMailboxIntelligence
            enableSpoofIntelligence      = [bool]$_.EnableSpoofIntelligence
            enableTargetedUserProtection = [bool]$_.EnableTargetedUserProtection
        }
    })
} catch {
    Add-CollectionError -Signal 'antiPhishPolicies' -Message $_.Exception.Message
}

try {
    $result.safeAttachmentsPolicies = @(Get-SafeAttachmentPolicy | ForEach-Object {
        [ordered]@{
            id        = $_.Guid.ToString()
            isDefault = [bool]$_.IsDefault
            enabled   = [bool]$_.Enable
            action    = $_.Action.ToString()
        }
    })
} catch {
    Add-CollectionError -Signal 'safeAttachmentsPolicies' -Message $_.Exception.Message
}

try {
    $result.safeLinksPolicies = @(Get-SafeLinksPolicy | ForEach-Object {
        [ordered]@{
            id                        = $_.Guid.ToString()
            isDefault                 = [bool]$_.IsDefault
            enableSafeLinksForEmail   = [bool]$_.EnableSafeLinksForEmail
            enableSafeLinksForTeams   = [bool]$_.EnableSafeLinksForTeams
            enableSafeLinksForOffice  = [bool]$_.EnableSafeLinksForOffice
        }
    })
} catch {
    Add-CollectionError -Signal 'safeLinksPolicies' -Message $_.Exception.Message
}

try {
    # Deliberately queried over the Exchange Online session, NOT the IPPSSession - see the
    # note above Connect-IPPSSession: UnifiedAuditLogIngestionEnabled always reads $false
    # over a Security & Compliance connection regardless of actual tenant state.
    $auditConfig = Get-AdminAuditLogConfig
    $result.unifiedAuditLogConfig = [ordered]@{
        unifiedAuditLogIngestionEnabled = [bool]$auditConfig.UnifiedAuditLogIngestionEnabled
    }
} catch {
    Add-CollectionError -Signal 'unifiedAuditLogConfig' -Message $_.Exception.Message
}

if ($eomConnected) {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}
if ($ippsConnected) {
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}

if ($result.errors.Count -eq 0) {
    $result.Remove('errors')
}

Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
exit 0
