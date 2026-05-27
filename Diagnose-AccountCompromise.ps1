<#
.SYNOPSIS
    Investigate a potentially compromised Office 365 account and produce an HTML triage report.
.DESCRIPTION
    Collects indicators of compromise from:
      1. Entra ID sign-in logs (risk levels, new countries)
      2. Identity Protection risky user state
      3. MFA / authentication methods (newly registered methods)
      4. Exchange Online mailbox configuration (forwarding attributes)
      5. Inbox rules (forwarding, redirect, delete, mark-as-read)
      6. Mailbox audit log (SendAs, HardDelete, UpdateFolderPermissions)
      7. Tenant transport rules matching this sender

    Requires an active Connect-ExchangeOnline and Connect-MgGraph session.
    This script is read-only and never modifies any configuration.
.PARAMETER UserPrincipalName
    The UPN of the account to investigate (e.g. user@contoso.com).
.PARAMETER DaysBack
    Lookback window in days for all time-based queries. Default: 7.
.PARAMETER OutputHtml
    Path for the HTML report. Default: .\AccountCompromise-<UPN>-<yyyyMMdd>.html
.PARAMETER SkipUpdateCheck
    Skip the automatic version check at script start.
.EXAMPLE
    .\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com
.EXAMPLE
    .\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com -DaysBack 14 -OutputHtml C:\temp\report.html
.NOTES
    Requires: ExchangeOnlineManagement, Microsoft.Graph
    Graph scopes: AuditLog.Read.All, Directory.Read.All, UserAuthenticationMethod.Read.All, IdentityRiskyUser.Read.All
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [int]$DaysBack = 7,

    [string]$OutputHtml,

    [switch]$SkipUpdateCheck
)

$ScriptVersion   = '1.0.0'
$ScriptUpdateUrl = 'https://raw.githubusercontent.com/iamsplendid/diagnose-account-compromise/master/Diagnose-AccountCompromise.ps1'

if (-not $SkipUpdateCheck) {
    try {
        $remote = (Invoke-WebRequest -Uri $ScriptUpdateUrl -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop).Content
        if ($remote -match '\$ScriptVersion\s*=\s*[''"]([^''"]+)[''"]') {
            $remoteVersion = $Matches[1]
            if ([version]$remoteVersion -gt [version]$ScriptVersion) {
                Write-Host "[UPDATE] New version $remoteVersion available (running $ScriptVersion). Updating..." -ForegroundColor Cyan
                $scriptPath = $PSCommandPath
                if ($scriptPath -and (Test-Path $scriptPath)) {
                    [System.IO.File]::WriteAllText($scriptPath, $remote, [System.Text.Encoding]::UTF8)
                    Write-Host "[UPDATE] Script updated. Re-running new version..." -ForegroundColor Green
                    $fwd = @{} + $PSBoundParameters
                    $fwd['SkipUpdateCheck'] = $true
                    & $scriptPath @fwd
                    exit
                } else {
                    Write-Warning "[UPDATE] Cannot determine script path. Download latest from: $ScriptUpdateUrl"
                }
            } else {
                Write-Verbose "[UPDATE] Script is current (version $ScriptVersion)."
            }
        }
    } catch {
        Write-Verbose "[UPDATE] Version check skipped: $($_.Exception.Message)"
    }
}

if (-not $OutputHtml) {
    $safeName = $UserPrincipalName -replace '[^a-zA-Z0-9@._-]', '_'
    $OutputHtml = ".\AccountCompromise-$safeName-$(Get-Date -Format 'yyyyMMdd').html"
}

function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn { param([string]$m) Write-Warning $m }
function Write-Step { param([string]$m) Write-Host "[....] $m" -ForegroundColor Gray }
function Write-Done { param([string]$m) Write-Host "[ OK ] $m" -ForegroundColor Green }
function Write-Fail { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red }

function Assert-Sessions {
    $exo = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not ($exo | Where-Object { $_.State -eq 'Connected' })) {
        throw "No active Exchange Online session.`nRun: Connect-ExchangeOnline"
    }

    $graph = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $graph) {
        throw "No active Graph session.`nRun: Connect-MgGraph -Scopes 'AuditLog.Read.All','Directory.Read.All','UserAuthenticationMethod.Read.All','IdentityRiskyUser.Read.All'"
    }

    $required = @('AuditLog.Read.All', 'Directory.Read.All', 'UserAuthenticationMethod.Read.All', 'IdentityRiskyUser.Read.All')
    foreach ($scope in $required) {
        if ($graph.Scopes -notcontains $scope) {
            Write-Warn "Graph scope '$scope' not present. Some collectors may fail."
        }
    }
    Write-Done "Sessions validated (EXO: $($exo[0].Organization), Graph: $($graph.Account))"
}

function Get-UserProfile {
    param([string]$Upn)
    Write-Step "Collecting user profile..."
    try {
        $props = 'id,displayName,userPrincipalName,accountEnabled,createdDateTime,lastPasswordChangeDateTime,onPremisesSyncEnabled'
        $u = Get-MgUser -UserId $Upn -Property $props -ErrorAction Stop
        Write-Done "User profile: $($u.DisplayName)"
        return [PSCustomObject]@{ Ok = $true; Data = $u }
    } catch {
        Write-Fail "Get-UserProfile failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = $null }
    }
}

function Get-RiskyUserStatus {
    param([string]$Upn)
    Write-Step "Collecting Identity Protection risky user status..."
    try {
        $r = Get-MgRiskyUser -Filter "userPrincipalName eq '$Upn'" -ErrorAction Stop
        $first = $r | Select-Object -First 1
        Write-Done "Risky user state: $(if ($first) { $first.RiskState } else { 'not found' })"
        return [PSCustomObject]@{ Ok = $true; Data = $first }
    } catch {
        Write-Fail "Get-RiskyUserStatus failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = $null }
    }
}

function Get-AuthMethods {
    param([string]$Upn)
    Write-Step "Collecting authentication methods..."
    try {
        $raw = Get-MgUserAuthenticationMethod -UserId $Upn -All -ErrorAction Stop
        $parsed = @($raw | ForEach-Object {
            $ap = $_.AdditionalProperties
            $methodType = ($ap['@odata.type'] -replace '#microsoft.graph.', '') -replace 'AuthenticationMethod', ''
            [PSCustomObject]@{
                Id              = $_.Id
                MethodType      = $methodType
                CreatedDateTime = $ap['createdDateTime']
                DisplayName     = $ap['displayName']
                PhoneNumber     = $ap['phoneNumber']
            }
        })
        Write-Done "Auth methods: $($parsed.Count) found"
        return [PSCustomObject]@{ Ok = $true; Data = $parsed }
    } catch {
        Write-Fail "Get-AuthMethods failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = @() }
    }
}

function Get-SignInActivity {
    param([string]$Upn, [int]$DaysBack)
    Write-Step "Collecting sign-in logs (30-day window)..."
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $filter = "userPrincipalName eq '$Upn' and createdDateTime ge $thirtyDaysAgo"
        $all = @(Get-MgAuditLogSignIn -Filter $filter -All -ErrorAction Stop)
        $cutoff = (Get-Date).AddDays(-$DaysBack)
        $inWindow = @($all | Where-Object { [datetime]$_.CreatedDateTime -ge $cutoff })
        $baseline = @($all | Where-Object { [datetime]$_.CreatedDateTime -lt $cutoff })
        Write-Done "Sign-ins: $($inWindow.Count) in window, $($baseline.Count) in baseline"
        return [PSCustomObject]@{
            Ok       = $true
            All      = $all
            InWindow = $inWindow
            Baseline = $baseline
        }
    } catch {
        Write-Fail "Get-SignInActivity failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; All = @(); InWindow = @(); Baseline = @() }
    }
}

function Get-MailboxConfig {
    param([string]$Upn)
    Write-Step "Collecting mailbox configuration..."
    try {
        $mb = Get-Mailbox -Identity $Upn -ErrorAction Stop
        $data = [PSCustomObject]@{
            ForwardingAddress              = $mb.ForwardingAddress
            ForwardingSmtpAddress          = $mb.ForwardingSmtpAddress
            DeliverToMailboxAndForward     = $mb.DeliverToMailboxAndForward
            HiddenFromAddressListsEnabled  = $mb.HiddenFromAddressListsEnabled
            AuditEnabled                   = $mb.AuditEnabled
            RecipientTypeDetails           = $mb.RecipientTypeDetails
        }
        Write-Done "Mailbox config collected (ForwardingSmtp: $($mb.ForwardingSmtpAddress))"
        return [PSCustomObject]@{ Ok = $true; Data = $data }
    } catch {
        Write-Fail "Get-MailboxConfig failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = $null }
    }
}

function Get-InboxRules {
    param([string]$Upn)
    Write-Step "Collecting inbox rules..."
    try {
        $rules = @(Get-InboxRule -Mailbox $Upn -ErrorAction Stop)
        Write-Done "Inbox rules: $($rules.Count) found"
        return [PSCustomObject]@{ Ok = $true; Data = $rules }
    } catch {
        Write-Fail "Get-InboxRules failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = @() }
    }
}

function Get-MailboxAuditEvents {
    param([string]$Upn, [int]$DaysBack)
    Write-Step "Collecting mailbox audit log..."
    try {
        $start = (Get-Date).AddDays(-$DaysBack)
        $ops = @('SendAs','SendOnBehalf','HardDelete','MoveToDeletedItems','UpdateFolderPermissions')
        $results = @(Search-MailboxAuditLog -Identity $Upn -StartDate $start -EndDate (Get-Date) `
            -Operations $ops -LogonTypes Admin,Delegate,Owner -ResultSize 250000 -ErrorAction Stop)
        if ($results.Count -ge 250000) {
            Write-Warn "Mailbox audit result limit reached (250,000). Some events may be missing."
        }
        Write-Done "Audit events: $($results.Count) found"
        return [PSCustomObject]@{ Ok = $true; Data = $results }
    } catch {
        Write-Fail "Get-MailboxAuditEvents failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = @() }
    }
}

function Get-TransportRuleMatches {
    param([string]$Upn)
    Write-Step "Collecting transport rules..."
    try {
        $domain = ($Upn -split '@')[1]
        $all = @(Get-TransportRule -ErrorAction Stop)
        $matched = @($all | Where-Object {
            ($_.From -contains $Upn) -or
            ($_.FromMemberOf -contains $Upn) -or
            ($_.SenderDomainIs -contains $domain)
        })
        Write-Done "Transport rules: $($matched.Count) match this sender"
        return [PSCustomObject]@{ Ok = $true; Data = $matched }
    } catch {
        Write-Fail "Get-TransportRuleMatches failed: $($_.Exception.Message)"
        return [PSCustomObject]@{ Ok = $false; Error = $_.Exception.Message; Data = @() }
    }
}
