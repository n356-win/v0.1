#Requires -Version 5.1
<#
.SYNOPSIS
    Fingerprints an organisation's identity stack from four unauthenticated public lookups.

.DESCRIPTION
    Identity Stack Scanner v0.1.

    Answers one question per domain: who actually authenticates this organisation's
    users, and is the identity layer theirs to fix?

    It performs only lookups that any member of the public can perform without
    credentials, without consent, and without touching the target's tenant:

      1. MX  records          - which mail platform sits behind the domain
      2. SPF (TXT) records    - which platform is authorised to send as the domain
      3. OpenID configuration - whether an Entra tenant exists, and its GUID
      4. getuserrealm.srf     - the decisive test: Managed vs Federated

    No authentication. No tenant access. No write operations. Nothing that is not
    already public. See RESPONSIBLE USE in the README before running this at scale.

.PARAMETER Domain
    One or more domains to scan. Accepts pipeline input.

.PARAMETER Path
    Path to an input file: a plain text file with one domain per line, or a CSV
    containing a 'Domain' column. Lines beginning with # are ignored.

.PARAMETER CsvPath
    Optional. Write flat results to this CSV path.

.PARAMETER JsonPath
    Optional. Write full results, including raw records, to this JSON path.

.PARAMETER DnsMethod
    Auto (default), Native, or Doh.
      Auto   - use Resolve-DnsName when present (Windows), otherwise DNS-over-HTTPS
      Native - force Resolve-DnsName
      Doh    - force DNS-over-HTTPS (works on Linux and macOS)

.PARAMETER DelayMs
    Milliseconds to pause between domains. Default 250. Deliberate politeness;
    do not set this to 0 for large batches.

.PARAMETER TimeoutSec
    Per-request HTTP timeout. Default 15.

.PARAMETER CheckSpfLimit
    Also resolve nested SPF includes to count DNS lookups against the RFC 7208
    limit of 10. Off by default because it multiplies query volume.

.EXAMPLE
    .\Invoke-IdentityStackScan.ps1 -Domain contoso.com

.EXAMPLE
    .\Invoke-IdentityStackScan.ps1 -Path .\domains.txt -CsvPath .\results.csv

.EXAMPLE
    'contoso.com','fabrikam.com' | .\Invoke-IdentityStackScan.ps1 | Format-Table Domain,Verdict,NameSpaceType

.NOTES
    Version : 0.1.0
    Licence : MIT
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, Position = 0)]
    [string[]] $Domain,

    [Parameter()]
    [string] $Path,

    [Parameter()]
    [string] $CsvPath,

    [Parameter()]
    [string] $JsonPath,

    [Parameter()]
    [ValidateSet('Auto','Native','Doh')]
    [string] $DnsMethod = 'Auto',

    [Parameter()]
    [ValidateRange(0, 60000)]
    [int] $DelayMs = 250,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int] $TimeoutSec = 15,

    [Parameter()]
    [switch] $CheckSpfLimit,

    [Parameter()]
    [switch] $Quiet
)

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $script:ToolVersion = '0.1.0'
    $script:Collected   = New-Object System.Collections.Generic.List[object]

    # TLS 1.2 for Windows PowerShell 5.1, which still defaults lower on older hosts.
    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notmatch 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    } catch { Write-Verbose "Could not raise TLS version: $($_.Exception.Message)" }

    #region Signature tables

    # Mail platform signatures, matched against MX target hostnames.
    $script:MxSignatures = @(
        @{ Name = 'Exchange Online'; Platform = 'Microsoft'; Pattern = '\.mail\.protection\.outlook\.com$' }
        @{ Name = 'Google Workspace'; Platform = 'Google'; Pattern = '(^|\.)(aspmx\.l\.google\.com|alt\d\.aspmx\.l\.google\.com|googlemail\.com)$' }
        @{ Name = 'Google Workspace'; Platform = 'Google'; Pattern = '\.google\.com$' }
        @{ Name = 'Zoho'; Platform = 'Zoho'; Pattern = '\.zoho(mail)?\.(com|eu|in)$' }
    )

    # Security gateways. A gateway in MX hides the real platform; SPF settles it.
    $script:GatewaySignatures = @(
        @{ Name = 'Proofpoint'; Pattern = '(pphosted\.com|ppe-hosted\.com|proofpoint\.com)$' }
        @{ Name = 'Mimecast';   Pattern = '(mimecast\.com|mimecast\.co\.za)$' }
        @{ Name = 'Barracuda';  Pattern = 'barracudanetworks\.com$' }
        @{ Name = 'Sophos';     Pattern = '(sophos\.com|hydra\.sophos\.com)$' }
        @{ Name = 'Cisco/IronPort'; Pattern = 'iphmx\.com$' }
        @{ Name = 'Cloudflare Email Security'; Pattern = '(cf-emailsecurity\.net|area1\.cloudflare\.net)$' }
        @{ Name = 'Hornetsecurity'; Pattern = '(hornetsecurity\.com|antispameurope\.com)$' }
        @{ Name = 'Trend Micro'; Pattern = 'trendmicro\.com$' }
    )

    # SPF include signatures -> platform attribution.
    $script:SpfPlatformSignatures = @(
        @{ Name = 'Microsoft'; Pattern = 'spf\.protection\.outlook\.com' }
        @{ Name = 'Microsoft'; Pattern = 'spf\.protection\.office365\.us' }
        @{ Name = 'Google';    Pattern = '_spf\.google\.com' }
        @{ Name = 'Zoho';      Pattern = 'zoho(mail)?\.(com|eu|in)' }
    )

    # Security spend tells inside SPF. Presence means an existing budget line.
    $script:SpfSecuritySignatures = @(
        @{ Name = 'KnowBe4';    Pattern = 'knowbe4\.com' }
        @{ Name = 'Proofpoint'; Pattern = '(pphosted\.com|ppe-hosted\.com|proofpoint\.com)' }
        @{ Name = 'Mimecast';   Pattern = 'mimecast\.com' }
        @{ Name = 'Barracuda';  Pattern = 'barracuda(networks)?\.com' }
    )

    # HRIS tells inside SPF. Self-published proof of production use.
    $script:SpfHrisSignatures = @(
        @{ Name = 'Dayforce'; Pattern = 'dayforcehcm\.com' }
        @{ Name = 'Workday';  Pattern = 'workday\.com' }
        @{ Name = 'ADP';      Pattern = 'adp\.com' }
        @{ Name = 'UKG';      Pattern = '(ultipro|ukg)\.com' }
    )

    # Foreign IdP signatures, matched against the AuthURL returned by getuserrealm.
    $script:ForeignIdpSignatures = @(
        @{ Name = 'Okta';      Pattern = 'okta(preview)?\.com|oktapreview\.com' }
        @{ Name = 'Ping';      Pattern = 'pingone\.com|pingidentity\.com|ping-eng\.com' }
        @{ Name = 'OneLogin';  Pattern = 'onelogin\.com' }
        @{ Name = 'Duo';       Pattern = 'duosecurity\.com' }
        @{ Name = 'Google';    Pattern = 'accounts\.google\.com' }
        @{ Name = 'CyberArk';  Pattern = 'idaptive\.app|cyberark\.com' }
    )

    # On-premises Microsoft federation. Not a foreign IdP - a migration candidate.
    $script:LegacyFedSignatures = @(
        @{ Name = 'AD FS'; Pattern = '(adfs|sts|fs)\.' }
    )

    #endregion

    #region Lookup primitives

    function Test-NativeDnsAvailable {
        return [bool] (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)
    }

    function Resolve-DnsRecordSet {
        <# Returns a string[] of record data for the given type, or @() on failure. #>
        param(
            [Parameter(Mandatory)] [string] $Name,
            [Parameter(Mandatory)] [ValidateSet('MX','TXT')] [string] $Type,
            [Parameter(Mandatory)] [string] $Method,
            [Parameter()] [int] $TimeoutSec = 15
        )

        $useNative = ($Method -eq 'Native') -or ($Method -eq 'Auto' -and (Test-NativeDnsAvailable))

        if ($useNative) {
            try {
                $records = Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop
                switch ($Type) {
                    'MX'  { return @($records | Where-Object { $_.PSObject.Properties.Name -contains 'NameExchange' } | ForEach-Object { $_.NameExchange }) }
                    'TXT' { return @($records | Where-Object { $_.PSObject.Properties.Name -contains 'Strings' } | ForEach-Object { ($_.Strings -join '') }) }
                }
            } catch {
                Write-Verbose "Native DNS $Type lookup failed for ${Name}: $($_.Exception.Message)"
                return @()
            }
        }

        # DNS-over-HTTPS fallback. Cross-platform, no Resolve-DnsName dependency.
        try {
            $uri  = "https://dns.google/resolve?name=$([uri]::EscapeDataString($Name))&type=$Type"
            $resp = Invoke-RestMethod -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop
            if (-not $resp -or -not ($resp.PSObject.Properties.Name -contains 'Answer')) { return @() }
            $wanted = if ($Type -eq 'MX') { 15 } else { 16 }
            return @(
                $resp.Answer |
                    Where-Object { $_.type -eq $wanted } |
                    ForEach-Object {
                        $d = $_.data
                        if ($Type -eq 'MX') { ($d -replace '^\d+\s+','').TrimEnd('.') }
                        else { $d.Trim('"') -replace '"\s+"','' }
                    }
            )
        } catch {
            Write-Verbose "DoH $Type lookup failed for ${Name}: $($_.Exception.Message)"
            return @()
        }
    }

    function Get-MxProfile {
        param([string] $Domain, [string] $Method, [int] $TimeoutSec)

        $hosts = @(Resolve-DnsRecordSet -Name $Domain -Type MX -Method $Method -TimeoutSec $TimeoutSec)
        $platform = 'Unknown'; $vendor = $null; $gateway = $null

        foreach ($h in $hosts) {
            foreach ($sig in $script:MxSignatures) {
                if ($h -match $sig.Pattern) { $platform = $sig.Platform; $vendor = $sig.Name; break }
            }
            if ($platform -ne 'Unknown') { break }
        }
        foreach ($h in $hosts) {
            foreach ($sig in $script:GatewaySignatures) {
                if ($h -match $sig.Pattern) { $gateway = $sig.Name; break }
            }
            if ($gateway) { break }
        }
        if (@($hosts).Count -eq 0) { $platform = 'None' }
        elseif ($gateway -and $platform -eq 'Unknown') { $platform = 'Gateway' }

        [pscustomobject]@{
            Records  = $hosts
            Platform = $platform
            Vendor   = $vendor
            Gateway  = $gateway
        }
    }

    function Get-SpfProfile {
        param([string] $Domain, [string] $Method, [int] $TimeoutSec)

        $txt = @(Resolve-DnsRecordSet -Name $Domain -Type TXT -Method $Method -TimeoutSec $TimeoutSec)
        $spf = @($txt | Where-Object { $_ -match '^\s*v=spf1\b' }) | Select-Object -First 1

        $result = [pscustomobject]@{
            Raw            = $spf
            Present        = [bool] $spf
            Includes       = @()
            Ip4Count       = 0
            Ip6Count       = 0
            HasRedirect    = $false
            Platforms      = @()
            SecurityVendors= @()
            HrisVendors    = @()
            IpLiteralHeavy = $false
            LookupCount    = $null
            LookupOverLimit= $false
            MultipleSpf    = (@($txt | Where-Object { $_ -match '^\s*v=spf1\b' }).Count -gt 1)
        }
        if (-not $spf) { return $result }

        $tokens = $spf -split '\s+' | Where-Object { $_ }
        $includes = @(); $ip4 = 0; $ip6 = 0; $redirect = $false
        foreach ($t in $tokens) {
            if ($t -match '^(?:\+|-|~|\?)?include:(.+)$') { $includes += $Matches[1] }
            elseif ($t -match '^(?:\+|-|~|\?)?ip4:')       { $ip4++ }
            elseif ($t -match '^(?:\+|-|~|\?)?ip6:')       { $ip6++ }
            elseif ($t -match '^redirect=')                { $redirect = $true }
        }

        $platforms = @(); $sec = @(); $hris = @()
        foreach ($sig in $script:SpfPlatformSignatures) { if ($spf -match $sig.Pattern) { $platforms += $sig.Name } }
        foreach ($sig in $script:SpfSecuritySignatures) { if ($spf -match $sig.Pattern) { $sec += $sig.Name } }
        foreach ($sig in $script:SpfHrisSignatures)     { if ($spf -match $sig.Pattern) { $hris += $sig.Name } }

        $result.Includes        = @($includes)
        $result.Ip4Count        = $ip4
        $result.Ip6Count        = $ip6
        $result.HasRedirect     = $redirect
        $result.Platforms       = @($platforms | Select-Object -Unique)
        $result.SecurityVendors = @($sec | Select-Object -Unique)
        $result.HrisVendors     = @($hris | Select-Object -Unique)
        $result.IpLiteralHeavy  = (@($includes).Count -eq 0 -and ($ip4 + $ip6) -ge 4)

        if ($CheckSpfLimit) {
            $seen = New-Object System.Collections.Generic.HashSet[string]
            $count = Measure-SpfLookup -Spf $spf -Depth 0 -Seen $seen -Method $Method -TimeoutSec $TimeoutSec
            $result.LookupCount     = $count
            $result.LookupOverLimit = ($count -gt 10)
        }
        return $result
    }

    function Measure-SpfLookup {
        <# Counts DNS-querying mechanisms against the RFC 7208 limit of 10. #>
        param([string] $Spf, [int] $Depth, $Seen, [string] $Method, [int] $TimeoutSec)

        if (-not $Spf -or $Depth -gt 5) { return 0 }
        $count = 0
        foreach ($t in ($Spf -split '\s+' | Where-Object { $_ })) {
            if ($t -match '^(?:\+|-|~|\?)?include:(.+)$') {
                $target = $Matches[1]
                $count++
                if ($Seen.Add($target)) {
                    $childTxt = @(Resolve-DnsRecordSet -Name $target -Type TXT -Method $Method -TimeoutSec $TimeoutSec)
                    $childSpf = @($childTxt | Where-Object { $_ -match '^\s*v=spf1\b' }) | Select-Object -First 1
                    if ($childSpf) { $count += Measure-SpfLookup -Spf $childSpf -Depth ($Depth + 1) -Seen $Seen -Method $Method -TimeoutSec $TimeoutSec }
                }
            }
            elseif ($t -match '^(?:\+|-|~|\?)?(a|mx|ptr|exists)(:|$)') { $count++ }
            elseif ($t -match '^redirect=(.+)$') { $count++ }
        }
        return $count
    }

    function Get-EntraTenant {
        param([string] $Domain, [int] $TimeoutSec)
        try {
            $uri  = "https://login.microsoftonline.com/$([uri]::EscapeDataString($Domain))/v2.0/.well-known/openid-configuration"
            $resp = Invoke-RestMethod -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop
            $tid = $null
            if ($resp.PSObject.Properties.Name -contains 'issuer' -and $resp.issuer -match '([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})') {
                $tid = $Matches[1]
            }
            [pscustomobject]@{ Found = $true; TenantId = $tid; Issuer = $resp.issuer; Error = $null }
        } catch {
            [pscustomobject]@{ Found = $false; TenantId = $null; Issuer = $null; Error = $_.Exception.Message }
        }
    }

    function Get-UserRealm {
        param([string] $Domain, [int] $TimeoutSec)
        try {
            $uri  = "https://login.microsoftonline.com/getuserrealm.srf?login=test@$([uri]::EscapeDataString($Domain))&json=1"
            $resp = Invoke-RestMethod -Uri $uri -TimeoutSec $TimeoutSec -ErrorAction Stop
            $props = $resp.PSObject.Properties.Name
            [pscustomobject]@{
                Ok                  = $true
                NameSpaceType       = if ($props -contains 'NameSpaceType')       { $resp.NameSpaceType }       else { $null }
                FederationBrandName = if ($props -contains 'FederationBrandName') { $resp.FederationBrandName } else { $null }
                AuthUrl             = if ($props -contains 'AuthURL')             { $resp.AuthURL }             else { $null }
                CloudInstance       = if ($props -contains 'CloudInstanceName')   { $resp.CloudInstanceName }   else { $null }
                DomainName          = if ($props -contains 'DomainName')          { $resp.DomainName }          else { $null }
                Error               = $null
            }
        } catch {
            [pscustomobject]@{ Ok = $false; NameSpaceType = $null; FederationBrandName = $null; AuthUrl = $null; CloudInstance = $null; DomainName = $null; Error = $_.Exception.Message }
        }
    }

    #endregion

    #region Interpretation

    function ConvertTo-ComparableName {
        param([string] $Value)
        if (-not $Value) { return '' }
        return ($Value -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
    }

    function Resolve-IdentityVerdict {
        <#
            Pure function. Takes the four lookup profiles and returns a verdict plus
            the signals that produced it. No I/O, so it is directly unit-testable.
        #>
        param(
            [Parameter(Mandatory)] [string] $Domain,
            [Parameter(Mandatory)] $Mx,
            [Parameter(Mandatory)] $Spf,
            [Parameter(Mandatory)] $Tenant,
            [Parameter(Mandatory)] $Realm
        )

        $signals = New-Object System.Collections.Generic.List[object]
        function Add-Signal { param($Code, $Severity, $Detail)
            $signals.Add([pscustomobject]@{ Code = $Code; Severity = $Severity; Detail = $Detail })
        }

        # --- Tells that are independent of the verdict ---

        if ($Mx.Gateway) {
            Add-Signal 'GATEWAY_HIDING' 'Info' "$($Mx.Gateway) in MX - the real platform is behind it; SPF settles which."
        }
        if (@($Spf.SecurityVendors).Count -gt 0) {
            Add-Signal 'SECURITY_SPEND' 'Positive' "$($Spf.SecurityVendors -join ', ') in SPF - an existing security budget line."
        }
        if (@($Spf.HrisVendors).Count -gt 0) {
            Add-Signal 'HRIS_SELF_PUBLISHED' 'Positive' "$($Spf.HrisVendors -join ', ') in SPF - self-published proof of production use."
        }
        if ($Spf.IpLiteralHeavy) {
            Add-Signal 'UNGOVERNED_DNS' 'Opportunity' "SPF is $($Spf.Ip4Count + $Spf.Ip6Count) IP literals with no includes - DNS grew without governance; identity rarely governed either."
        }
        if (@($Spf.Platforms).Count -ge 2) {
            Add-Signal 'MIXED_ESTATE' 'Opportunity' "SPF authorises $($Spf.Platforms -join ' + ') - a reconciliation problem in miniature."
        }
        if ($Spf.MultipleSpf) {
            Add-Signal 'SPF_DUPLICATE' 'Defect' 'More than one v=spf1 record published - this is a permanent error under RFC 7208.'
        }
        if ($Spf.LookupOverLimit) {
            Add-Signal 'SPF_OVER_LIMIT' 'Defect' "SPF resolves to $($Spf.LookupCount) DNS lookups, over the RFC 7208 limit of 10."
        }
        if (-not $Spf.Present) {
            Add-Signal 'NO_SPF' 'Defect' 'No SPF record published.'
        }

        $brand = $Realm.FederationBrandName
        $isShell = $false
        if ($brand) {
            if ($brand -match '^\s*Default Directory\s*$') {
                $isShell = $true
                Add-Signal 'SHELL_TENANT' 'Disqualify' 'FederationBrandName is "Default Directory" - the tenant was never configured. A shell, not an identity backbone.'
            } else {
                $b = ConvertTo-ComparableName $brand
                $d = ConvertTo-ComparableName (($Domain -split '\.')[0])
                if ($b -and $d -and ($b -notlike "*$d*") -and ($d -notlike "*$b*")) {
                    Add-Signal 'BRAND_MISMATCH' 'Opportunity' "Tenant brand '$brand' does not match the domain - either an estate that grew by acquisition and was never tidied, or a parent company holding the decision authority."
                }
            }
        }

        # --- Verdict ---

        # A gateway in MX hides the real platform and SPF settles it. Resolve that
        # here, once, so every rule below reasons about the platform rather than
        # the appliance sitting in front of it.
        $effectiveMail = $Mx.Platform
        if (($effectiveMail -eq 'Unknown' -or $effectiveMail -eq 'Gateway' -or $effectiveMail -eq 'None') -and @($Spf.Platforms).Count -gt 0) {
            $effectiveMail = @($Spf.Platforms)[0]
        }
        if ($effectiveMail -eq 'Gateway') {
            # The gateway hid the platform and SPF did not give it up either, commonly
            # because the gateway publishes a macro include that resolves per-sender.
            # Four public lookups cannot settle it, so report that rather than guess.
            $effectiveMail = 'Unknown'
            Add-Signal 'PLATFORM_OPAQUE' 'Warn' "MX is $($Mx.Gateway) and SPF delegates to it without naming a platform - the mail platform cannot be resolved from public lookups alone. Identity is still settled by the realm check."
        }

        $ns = $Realm.NameSpaceType
        $verdict = 'Review'
        $reason  = 'Insufficient signal to classify.'

        if ($isShell) {
            $verdict = 'Disqualified'
            $reason  = 'Shell tenant - never configured, so there is no identity backbone to improve.'
        }
        elseif ($ns -eq 'Federated') {
            $foreign = $null
            foreach ($sig in $script:ForeignIdpSignatures) { if ($Realm.AuthUrl -and $Realm.AuthUrl -match $sig.Pattern) { $foreign = $sig.Name; break } }
            $legacy = $null
            foreach ($sig in $script:LegacyFedSignatures) { if ($Realm.AuthUrl -and $Realm.AuthUrl -match $sig.Pattern) { $legacy = $sig.Name; break } }

            if ($foreign) {
                $verdict = 'Requalify'
                $reason  = "Federated to $foreign - someone else owns the identity layer."
                Add-Signal 'FOREIGN_IDP' 'Disqualify' "AuthURL names $foreign. Requalify against that platform or drop."
            }
            elseif ($legacy) {
                $verdict = 'Opportunity'
                $reason  = 'Federated to on-premises AD FS - Microsoft-owned identity running legacy federation. A migration candidate, not a competitor.'
                Add-Signal 'LEGACY_FEDERATION' 'Opportunity' "AuthURL looks like on-premises AD FS ($($Realm.AuthUrl)). Cloud-authentication migration is the opening."
            }
            else {
                $verdict = 'Requalify'
                $reason  = 'Federated to an unidentified IdP - inspect the AuthURL before spending effort.'
                Add-Signal 'FOREIGN_IDP_UNKNOWN' 'Warn' "Federated, AuthURL '$($Realm.AuthUrl)' not matched to a known IdP."
            }
        }
        elseif ($ns -eq 'Managed') {
            if ($Tenant.Found) {
                $verdict = 'Qualified'
                $reason  = 'Managed - Entra authenticates directly, so the identity layer is theirs and the gap is real.'
                Add-Signal 'MANAGED_ENTRA' 'Positive' 'NameSpaceType is Managed with a resolvable tenant. Entra is the identity backbone.'
                if ($effectiveMail -and $effectiveMail -ne 'Microsoft' -and $effectiveMail -ne 'Unknown' -and $effectiveMail -ne 'None' -and $effectiveMail -ne 'Gateway') {
                    Add-Signal 'SPLIT_ESTATE' 'Opportunity' "Identity is Entra but mail resolves to $effectiveMail - identity and productivity are split across vendors, which is where reconciliation gaps live."
                }
            } else {
                $verdict = 'Review'
                $reason  = 'Reported Managed but no tenant metadata resolved - re-run before acting.'
            }
        }
        elseif ($effectiveMail -eq 'Google') {
            $verdict = 'Disqualified'
            $reason  = 'Google Workspace with no Entra namespace - not a Microsoft identity estate.'
            Add-Signal 'GOOGLE_ESTATE' 'Disqualify' 'MX resolves to Google Workspace and no Entra namespace was returned.'
        }
        elseif (-not $Tenant.Found) {
            $verdict = 'Disqualified'
            $reason  = 'No Entra tenant exists for this domain.'
            Add-Signal 'NO_TENANT' 'Disqualify' 'The OpenID configuration endpoint returned no tenant for this domain.'
        }

        # --- Confidence ---

        $ok = 0
        if (@($Mx.Records).Count -gt 0) { $ok++ }
        if ($Spf.Present)            { $ok++ }
        if ($Tenant.Found)           { $ok++ }
        if ($Realm.Ok)               { $ok++ }
        $confidence = switch ($ok) { 4 { 'High' } 3 { 'High' } 2 { 'Medium' } default { 'Low' } }
        if (-not $Realm.Ok) { $confidence = 'Low' }

        [pscustomobject]@{
            Verdict               = $verdict
            Reason                = $reason
            Confidence            = $confidence
            EffectiveMailPlatform = $effectiveMail
            Signals               = $signals.ToArray()
        }
    }

    #endregion

    function Invoke-SingleDomainScan {
        param([string] $Domain, [string] $Method, [int] $TimeoutSec)

        $d = $Domain.Trim().ToLowerInvariant()
        $d = $d -replace '^https?://','' -replace '/.*$','' -replace '^www\.',''
        $d = $d -replace '^.*@',''

        if ($d -notmatch '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') {
            Write-Warning "Skipping '$Domain' - not a valid domain."
            return $null
        }

        Write-Verbose "Scanning $d"
        $mx     = Get-MxProfile   -Domain $d -Method $Method -TimeoutSec $TimeoutSec
        $spf    = Get-SpfProfile  -Domain $d -Method $Method -TimeoutSec $TimeoutSec
        $tenant = Get-EntraTenant -Domain $d -TimeoutSec $TimeoutSec
        $realm  = Get-UserRealm   -Domain $d -TimeoutSec $TimeoutSec

        $v = Resolve-IdentityVerdict -Domain $d -Mx $mx -Spf $spf -Tenant $tenant -Realm $realm

        [pscustomobject]@{
            Domain              = $d
            Verdict             = $v.Verdict
            Confidence          = $v.Confidence
            Reason              = $v.Reason
            NameSpaceType       = $realm.NameSpaceType
            FederationBrandName = $realm.FederationBrandName
            AuthUrl             = $realm.AuthUrl
            TenantId            = $tenant.TenantId
            MailPlatform        = $mx.Platform
            EffectiveMail       = $v.EffectiveMailPlatform
            MailVendor          = $mx.Vendor
            MailGateway         = $mx.Gateway
            SpfPlatforms        = ($spf.Platforms -join '; ')
            SecurityVendors     = ($spf.SecurityVendors -join '; ')
            HrisVendors         = ($spf.HrisVendors -join '; ')
            SpfLookupCount      = $spf.LookupCount
            SignalCodes         = (($v.Signals | ForEach-Object { $_.Code }) -join '; ')
            Signals             = $v.Signals
            MxRecords           = ($mx.Records -join '; ')
            SpfRaw              = $spf.Raw
            CloudInstance       = $realm.CloudInstance
            ScannedUtc          = (Get-Date).ToUniversalTime().ToString('o')
            ToolVersion         = $script:ToolVersion
        }
    }

    # Resolve the effective DNS method once, and say so.
    $effectiveMethod = $DnsMethod
    if ($DnsMethod -eq 'Auto') {
        $effectiveMethod = if (Test-NativeDnsAvailable) { 'Native' } else { 'Doh' }
    }
    if (-not $Quiet) { Write-Host "Identity Stack Scanner v$script:ToolVersion  (DNS: $effectiveMethod)" -ForegroundColor Cyan }

    $inputDomains = New-Object System.Collections.Generic.List[string]
    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) { throw "Input file not found: $Path" }
        $raw = Get-Content -LiteralPath $Path -ErrorAction Stop
        if ($Path -match '\.csv$') {
            $rows = Import-Csv -LiteralPath $Path
            foreach ($r in $rows) {
                if ($r.PSObject.Properties.Name -contains 'Domain' -and $r.Domain) { $inputDomains.Add([string]$r.Domain) }
            }
        } else {
            foreach ($line in $raw) {
                $t = $line.Trim()
                if ($t -and -not $t.StartsWith('#')) { $inputDomains.Add($t) }
            }
        }
    }
}

process {
    if ($Domain) { foreach ($d in $Domain) { $inputDomains.Add($d) } }
}

end {
    $all = @($inputDomains | Where-Object { $_ } | Select-Object -Unique)
    if ($all.Count -eq 0) { throw 'No domains supplied. Use -Domain, -Path, or pipeline input.' }

    $i = 0
    foreach ($d in $all) {
        $i++
        if (-not $Quiet -and $all.Count -gt 1) {
            Write-Progress -Activity 'Identity Stack Scan' -Status "$i of $($all.Count): $d" -PercentComplete (($i / $all.Count) * 100)
        }
        $r = Invoke-SingleDomainScan -Domain $d -Method $effectiveMethod -TimeoutSec $TimeoutSec
        if ($r) { $script:Collected.Add($r); Write-Output $r }
        if ($DelayMs -gt 0 -and $i -lt $all.Count) { Start-Sleep -Milliseconds $DelayMs }
    }
    if (-not $Quiet -and $all.Count -gt 1) { Write-Progress -Activity 'Identity Stack Scan' -Completed }

    if ($CsvPath) {
        $script:Collected |
            Select-Object Domain,Verdict,Confidence,NameSpaceType,FederationBrandName,TenantId,MailPlatform,EffectiveMail,MailGateway,SpfPlatforms,SecurityVendors,HrisVendors,SignalCodes,AuthUrl,MxRecords,SpfRaw,Reason,ScannedUtc |
            Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
        if (-not $Quiet) { Write-Host "CSV written: $CsvPath" -ForegroundColor Green }
    }
    if ($JsonPath) {
        $script:Collected | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
        if (-not $Quiet) { Write-Host "JSON written: $JsonPath" -ForegroundColor Green }
    }
}