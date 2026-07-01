#Requires -Version 7.0
<#
.SYNOPSIS
    Collects Microsoft Teams security-configuration signals that Microsoft Graph has no
    API surface for (tenant federation config, meeting policies, messaging policies,
    client config).

.DESCRIPTION
    Invoked by src/lib/powershell/bridge.ts (`runPowerShellCollector`) as a child `pwsh`
    process. Same stdout/stderr/exit-code contract as Collect-ExoComplianceSignals.ps1 -
    see that script's header comment for the full contract description (single-line JSON
    on stdout, diagnostics only on stderr, exit 0 even on connection failure, never prints
    certificate/key contents, key password only via PSBRIDGE_KEY_PASSWORD env var).

    Every individual `Get-Cs*` call is wrapped in its own try/catch so one failing cmdlet
    never blocks collection of the other signals.

.NOTES
    VERIFICATION STATUS (see src/lib/powershell/README.md for the full caveat):
    The MicrosoftTeams module could NOT be installed in the authoring environment
    (PSGallery registration failed). Cmdlet/parameter names below were verified against
    Microsoft Learn documentation during authoring where noted; this has NOT been run
    against a live tenant.

    AUTH MECHANISM CHOSEN: in-memory X509Certificate2 via `Connect-MicrosoftTeams
    -Certificate <cert> -ApplicationId <id> -TenantId <tenantId>`. Verified during
    authoring (via Microsoft Learn / the MicrosoftTeams module's documented parameter
    sets) that `-Certificate` accepting an in-memory X509Certificate2 object IS supported
    (the "ServicePrincipalCertificate" parameter set), as an alternative to
    `-CertificateThumbprint` (which requires the certificate to already be imported into a
    local certificate store, e.g. Cert:\CurrentUser\My, and is keyed by thumbprint only).
    We use the in-memory `-Certificate` form specifically to AVOID ever importing the
    private key into a persistent OS certificate store - no store import, so no store
    cleanup step is needed here. If a future MicrosoftTeams module version drops support
    for in-memory -Certificate, the fallback design (documented for that scenario) is:
    import the PFX to Cert:\CurrentUser\My, capture the thumbprint, connect via
    -CertificateThumbprint, and ALWAYS remove the imported cert in a try/finally so it
    never persists past this script's execution - this fallback is NOT implemented below
    since it should not be needed unless -Certificate support is actually removed.
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
    $safeMessage = if ($Message.Length -gt 500) { $Message.Substring(0, 500) + '...(truncated)' } else { $Message }
    $script:result.errors += [ordered]@{ signal = $Signal; message = $safeMessage }
}

$teamsConnected = $false

try {
    Import-Module MicrosoftTeams -ErrorAction Stop

    # See Collect-ExoComplianceSignals.ps1 for the CreateFromPemFile/CreateFromEncryptedPemFile
    # verification notes - identical construction here.
    $keyPassword = $env:PSBRIDGE_KEY_PASSWORD
    if ([string]::IsNullOrEmpty($keyPassword)) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($CertPath, $KeyPath)
    } else {
        $securePassword = ConvertTo-SecureString -String $keyPassword -AsPlainText -Force
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromEncryptedPemFile($CertPath, $securePassword, $KeyPath)
    }
    $keyPassword = $null

    # See Collect-ExoComplianceSignals.ps1 for why this PFX round-trip is performed
    # defensively (ephemeral-key export/persistence quirks reported on some platforms for
    # certs built via CreateFromPemFile) - UNVERIFIED whether it is actually necessary on
    # Linux/pwsh 7, included as a cheap no-op-if-unneeded safeguard.
    try {
        $pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $pfxBytes,
            [string]::Empty,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
        )
    } catch {
        # Fall back to the originally constructed certificate object.
    }

    # Connect-MicrosoftTeams -Certificate <X509Certificate2> -ApplicationId <clientId>
    # -TenantId <tenantId> : the "ServicePrincipalCertificate" parameter set, verified
    # against Microsoft Learn during authoring
    # (learn.microsoft.com/microsoftteams/teams-powershell-application-authentication and
    # learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams).
    # Reintroduced in MicrosoftTeams module 4.7.1-preview per community sources reviewed
    # during authoring - if the deployed module version predates that, this call will
    # fail and be recorded under the 'connection' signal below rather than crashing.
    Connect-MicrosoftTeams -Certificate $cert -ApplicationId $ClientId -TenantId $EntraTenantId | Out-Null
    $teamsConnected = $true
} catch {
    Add-CollectionError -Signal 'connection' -Message $_.Exception.Message
    Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
    exit 0
}

try {
    # Get-CsTenantFederationConfiguration verified against Microsoft Learn during
    # authoring. allowedDomainsIsUnrestricted derivation: best-effort - treated as
    # unrestricted only when federation is allowed AND no specific allow-list is
    # configured (AllowedDomains is commonly an "AllowAllKnownDomains"-shaped object when
    # unrestricted vs. an explicit list otherwise) - exact property shape for
    # AllowedDomains was NOT independently re-verified against an installed module in this
    # environment; treat as a heuristic pending live-tenant validation.
    $fedConfig = Get-CsTenantFederationConfiguration
    $allowFederatedUsers = [bool]$fedConfig.AllowFederatedUsers
    $allowedDomainsUnrestricted = $false
    if ($allowFederatedUsers) {
        $allowedDomainsRaw = $fedConfig.AllowedDomains
        $allowedDomainsText = if ($allowedDomainsRaw) { $allowedDomainsRaw.ToString() } else { '' }
        $hasExplicitAllowList = [bool]($fedConfig.PSObject.Properties['AllowedDomainsAsAList'] -and
            $fedConfig.AllowedDomainsAsAList -and $fedConfig.AllowedDomainsAsAList.Count -gt 0)
        $allowedDomainsUnrestricted = [bool](-not $hasExplicitAllowList -and
            ($allowedDomainsText -match 'AllowAllKnownDomains' -or [string]::IsNullOrEmpty($allowedDomainsText)))
    }
    $result.federationConfig = [ordered]@{
        allowFederatedUsers          = $allowFederatedUsers
        allowedDomainsIsUnrestricted = $allowedDomainsUnrestricted
    }
} catch {
    Add-CollectionError -Signal 'federationConfig' -Message $_.Exception.Message
}

try {
    $result.meetingPolicies = @(Get-CsTeamsMeetingPolicy | ForEach-Object {
        [ordered]@{
            id                                 = $_.Identity.ToString()
            allowAnonymousUsersToJoinMeeting   = [bool]$_.AllowAnonymousUsersToJoinMeeting
            allowAnonymousUsersToStartMeeting  = [bool]$_.AllowAnonymousUsersToStartMeeting
            allowCloudRecording                = [bool]$_.AllowCloudRecording
        }
    })
} catch {
    Add-CollectionError -Signal 'meetingPolicies' -Message $_.Exception.Message
}

try {
    $result.messagingPolicies = @(Get-CsTeamsMessagingPolicy | ForEach-Object {
        [ordered]@{
            id            = $_.Identity.ToString()
            allowUserChat = [bool]$_.AllowUserChat
        }
    })
} catch {
    Add-CollectionError -Signal 'messagingPolicies' -Message $_.Exception.Message
}

try {
    # Get-CsTeamsClientConfiguration is tenant-wide (singleton), not a per-policy list -
    # verified against Microsoft Learn during authoring.
    $clientConfig = Get-CsTeamsClientConfiguration
    $result.clientConfig = [ordered]@{
        allowExternalAccess = [bool]$clientConfig.AllowExternalAccess
        allowGuestUser      = [bool]$clientConfig.AllowGuestUser
    }
} catch {
    Add-CollectionError -Signal 'clientConfig' -Message $_.Exception.Message
}

if ($teamsConnected) {
    try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
}

if ($result.errors.Count -eq 0) {
    $result.Remove('errors')
}

Write-Output ($result | ConvertTo-Json -Depth 10 -Compress)
exit 0
