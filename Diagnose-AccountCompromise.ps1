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
    Lookback window in days. Default: 7. Applies to mailbox audit log and the investigation window for sign-in analysis. Sign-in logs always pull 30 days to enable baseline country comparison.
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
    Identity Protection (risky user status) requires Entra ID P2 licensing. The collector skips gracefully if unlicensed.
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
    $OutputHtml = "C:\temp\reports\AccountCompromise-$safeName-$(Get-Date -Format 'yyyyMMdd').html"
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
        $escapedUpn = $Upn -replace "'", "''"
        $r = Get-MgRiskyUser -Filter "userPrincipalName eq '$escapedUpn'" -ErrorAction Stop
        $first = $r | Select-Object -First 1
        Write-Done "Risky user state: $(if ($first) { $first.RiskState } else { 'not found' })"
        return [PSCustomObject]@{ Ok = $true; Data = $first }
    } catch {
        $msg = $_.Exception.Message
        $notLicensed = $msg -match 'Forbidden' -and $msg -match 'not licensed'
        if ($notLicensed) {
            Write-Warn "Get-RiskyUserStatus: tenant not licensed for Identity Protection (Entra ID P2 required). Skipping."
        } else {
            Write-Fail "Get-RiskyUserStatus failed: $msg"
        }
        return [PSCustomObject]@{ Ok = $false; NotLicensed = $notLicensed; Error = $msg; Data = $null }
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
        $escapedUpn = $Upn -replace "'", "''"
        $filter = "userPrincipalName eq '$escapedUpn' and createdDateTime ge $thirtyDaysAgo"
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
        $raw = @(Search-UnifiedAuditLog -UserIds $Upn -StartDate $start -EndDate (Get-Date) `
            -Operations $ops -ResultSize 5000 -ErrorAction Stop)
        if ($raw.Count -ge 5000) {
            Write-Warn "Mailbox audit result limit reached (5,000). Some events may be missing. Consider narrowing the lookback window."
        }
        $results = @($raw | ForEach-Object {
            $data = $_.AuditData | ConvertFrom-Json
            [PSCustomObject]@{
                LastAccessed         = $_.CreationDate
                Operation            = $data.Operation
                LogonType            = $data.LogonType
                LogonUserDisplayName = if ($data.LogonUserDisplayName) { $data.LogonUserDisplayName } else { $data.UserId }
                DestFolderPathName   = $data.DestFolderPathName
            }
        })
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

function Invoke-IocAnalysis {
    param(
        [string]$Upn,
        [int]$DaysBack,
        $UserProfile,
        $SignIn,
        $RiskyUser,
        $AuthMethods,
        $MailboxConfig,
        $InboxRules,
        $AuditEvents,
        $TransportRules
    )

    $domain = ($Upn -split '@')[1]
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    function Add-Finding {
        param([string]$Severity, [string]$Category, [string]$Finding, [string]$Detail)
        $findings.Add([PSCustomObject]@{
            Severity = $Severity
            Category = $Category
            Finding  = $Finding
            Detail   = $Detail
        })
    }

    # --- Mailbox forwarding ---
    if ($MailboxConfig.Ok -and $MailboxConfig.Data) {
        $mb = $MailboxConfig.Data
        if ($mb.ForwardingSmtpAddress) {
            Add-Finding 'High' 'Forwarding' 'External SMTP forwarding configured' "ForwardingSmtpAddress: $($mb.ForwardingSmtpAddress)"
        }
        if ($mb.ForwardingAddress) {
            Add-Finding 'Low' 'Forwarding' 'Internal forwarding configured' "ForwardingAddress: $($mb.ForwardingAddress)"
        }
        if ($mb.DeliverToMailboxAndForward -and ($mb.ForwardingSmtpAddress -or $mb.ForwardingAddress)) {
            Add-Finding 'Low' 'Forwarding' 'DeliverToMailboxAndForward is enabled' 'Mail is copied to the forwarding address while also staying in the mailbox.'
        }
        if (-not $mb.AuditEnabled) {
            Add-Finding 'Info' 'Identity' 'Mailbox auditing is disabled' 'AuditEnabled is false. The audit log collector will return no results for this mailbox.'
        }
    }

    # --- Inbox rules ---
    if ($InboxRules.Ok) {
        foreach ($rule in @($InboxRules.Data | Where-Object { $_.Enabled })) {
            $fwdTargets = @()
            if ($rule.ForwardTo)            { $fwdTargets += @($rule.ForwardTo | ForEach-Object { $_.ToString() }) }
            if ($rule.RedirectTo)           { $fwdTargets += @($rule.RedirectTo | ForEach-Object { $_.ToString() }) }
            if ($rule.ForwardAsAttachmentTo){ $fwdTargets += @($rule.ForwardAsAttachmentTo | ForEach-Object { $_.ToString() }) }

            if ($fwdTargets.Count -gt 0) {
                Add-Finding 'High' 'InboxRule' "Rule '$($rule.Name)' forwards or redirects mail" "Targets: $($fwdTargets -join '; ')"
            } elseif ($rule.DeleteMessage) {
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' deletes matching messages" "Description: $($rule.Description)"
            } elseif ($rule.MarkAsRead -and -not $fwdTargets) {
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' silently marks messages as read" "Description: $($rule.Description)"
            } elseif ($rule.MoveToFolder -and $rule.MoveToFolder -match 'Deleted') {
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' moves messages to Deleted Items" "MoveToFolder: $($rule.MoveToFolder)"
            }
        }
    }

    # --- Sign-in risk ---
    if ($SignIn.Ok) {
        $highRisk = @($SignIn.InWindow | Where-Object {
            $_.RiskLevelDuringSignIn -in @('high','medium') -or
            $_.RiskLevelAggregated   -in @('high','medium')
        })
        if ($highRisk.Count -gt 0) {
            $levels = ($highRisk | Select-Object -ExpandProperty RiskLevelDuringSignIn -Unique | Where-Object { $_ }) -join ', '
            Add-Finding 'High' 'SignIn' "$($highRisk.Count) high/medium-risk sign-in(s) in lookback window" "Risk levels observed: $levels"
        }

        $baselineCountries = @($SignIn.Baseline |
            Select-Object -ExpandProperty Location | Where-Object { $_ } |
            ForEach-Object { $_.CountryOrRegion } | Where-Object { $_ } | Sort-Object -Unique)
        $windowCountries = @($SignIn.InWindow |
            Select-Object -ExpandProperty Location | Where-Object { $_ } |
            ForEach-Object { $_.CountryOrRegion } | Where-Object { $_ } | Sort-Object -Unique)
        $newCountries = @($windowCountries | Where-Object { $_ -and $_ -notin $baselineCountries })
        if ($newCountries.Count -gt 0) {
            Add-Finding 'Medium' 'SignIn' "Sign-in from new country/region: $($newCountries -join ', ')" 'This country/region had no sign-ins in the baseline window (prior 30 days).'
        }
    }

    # --- Identity Protection ---
    if ($RiskyUser.Ok -and $RiskyUser.Data) {
        $ru = $RiskyUser.Data
        if ($ru.RiskState -in @('atRisk','confirmedCompromised')) {
            Add-Finding 'High' 'Identity' "Identity Protection risk state: '$($ru.RiskState)'" "Detail: $($ru.RiskDetail). Last updated: $($ru.RiskLastUpdatedDateTime)"
        }
    }

    # --- Auth methods registered in window ---
    if ($AuthMethods.Ok) {
        $cutoff = (Get-Date).AddDays(-$DaysBack)
        foreach ($m in @($AuthMethods.Data | Where-Object { $_.MethodType -ne 'password' })) {
            if ($m.CreatedDateTime) {
                try {
                    $created = [datetime]$m.CreatedDateTime
                    if ($created -ge $cutoff) {
                        Add-Finding 'High' 'AuthMethod' "Auth method registered during lookback window: $($m.MethodType)" "Registered: $($m.CreatedDateTime). Display: $($m.DisplayName)$($m.PhoneNumber)"
                    }
                } catch { }
            }
        }
    }

    # --- Audit log ---
    if ($AuditEvents.Ok) {
        $suspicious = @($AuditEvents.Data | Where-Object {
            $_.Operation -in @('HardDelete','MoveToDeletedItems','UpdateFolderPermissions','SendAs','SendOnBehalf') -and
            $_.LogonType -in @('Admin','Delegate')
        })
        foreach ($ev in $suspicious) {
            Add-Finding 'Medium' 'AuditLog' "$($ev.Operation) by $($ev.LogonType) ($($ev.LogonUserDisplayName))" "Time: $($ev.LastAccessed). Folder: $($ev.DestFolderPathName)"
        }
    }

    # --- Transport rules ---
    if ($TransportRules.Ok) {
        foreach ($rule in @($TransportRules.Data)) {
            $hasRedirectOrBcc = $rule.RedirectMessageTo -or $rule.BlindCopyTo -or $rule.CopyTo
            if ($hasRedirectOrBcc) {
                $dest = @()
                if ($rule.RedirectMessageTo) { $dest += "Redirect: $($rule.RedirectMessageTo -join ', ')" }
                if ($rule.BlindCopyTo)       { $dest += "BCC: $($rule.BlindCopyTo -join ', ')" }
                if ($rule.CopyTo)            { $dest += "Copy: $($rule.CopyTo -join ', ')" }
                Add-Finding 'Medium' 'TransportRule' "Transport rule '$($rule.Name)' redirects or BCCs this sender" ($dest -join '; ')
            }
        }
    }

    # --- Account disabled ---
    if ($UserProfile.Ok -and $UserProfile.Data -and -not $UserProfile.Data.AccountEnabled) {
        Add-Finding 'Info' 'Identity' 'Account is currently disabled' 'AccountEnabled is false. Post-incident remediation may have already occurred.'
    }

    $order = @{ High = 0; Medium = 1; Low = 2; Info = 3 }
    return @($findings | Sort-Object { $order[$_.Severity] })
}

function ConvertTo-HtmlReport {
    param(
        [string]$Upn,
        [int]$DaysBack,
        [string]$ScriptVersion,
        $Findings,
        $UserProfile,
        $SignIn,
        $RiskyUser,
        $AuthMethods,
        $MailboxConfig,
        $InboxRules,
        $AuditEvents,
        $TransportRules
    )

    $displayName = if ($UserProfile.Ok -and $UserProfile.Data) { $UserProfile.Data.DisplayName } else { $Upn }
    $generated   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'

    function Sev-Badge { param([string]$s)
        $cls = switch ($s) { 'High'{'sev-high'} 'Medium'{'sev-medium'} 'Low'{'sev-low'} default{'sev-info'} }
        "<span class='badge $cls'>$s</span>"
    }
    function Err-Row { param([string]$msg, [int]$cols)
        "<tr><td colspan='$cols' class='err'>Collector error: $msg</td></tr>"
    }
    function No-Data { param([int]$cols, [string]$msg = 'No data found.')
        "<tr><td colspan='$cols' class='muted'>$msg</td></tr>"
    }
    function HtmlEncode { param([string]$s) if ($null -eq $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    # IOC Summary
    $summaryRows = if ($Findings.Count -gt 0) {
        ($Findings | ForEach-Object {
            "<tr><td>$(Sev-Badge $_.Severity)</td><td>$(HtmlEncode $_.Category)</td><td>$(HtmlEncode $_.Finding)</td><td>$(HtmlEncode $_.Detail)</td></tr>"
        }) -join "`n"
    } else { No-Data 4 'No indicators of compromise identified.' }

    # Sign-in rows
    $signInRows = if (-not $SignIn.Ok) {
        Err-Row $SignIn.Error 7
    } elseif ($SignIn.InWindow.Count -eq 0) {
        No-Data 7 'No sign-ins in the lookback window.'
    } else {
        ($SignIn.InWindow | Sort-Object CreatedDateTime -Descending | ForEach-Object {
            $risk    = if ($_.RiskLevelDuringSignIn) { $_.RiskLevelDuringSignIn } else { 'none' }
            $success = $_.Status -and $_.Status.ErrorCode -eq 0
            $resultCell = if ($success) {
                "<span style='color:#166534;font-weight:600;'>Success</span>"
            } else {
                $reason = if ($_.Status -and $_.Status.FailureReason) { HtmlEncode $_.Status.FailureReason } else { 'Failed' }
                "<span style='color:#991b1b;font-weight:600;'>Failed</span> <span class='muted'>$reason</span>"
            }
            $rowStyle = if ($risk -in @('high','medium')) { " style='background:#fff1f2;'" }
                        elseif (-not $success)            { " style='background:#fff7ed;'" }
                        else                              { '' }
            $loc = if ($_.Location) { "$(HtmlEncode $_.Location.City), $(HtmlEncode $_.Location.CountryOrRegion)" } else { '' }
            "<tr$rowStyle><td>$($_.CreatedDateTime)</td><td>$(HtmlEncode $_.IpAddress)</td><td>$loc</td><td>$(HtmlEncode $_.AppDisplayName)</td><td>$(HtmlEncode $_.ConditionalAccessStatus)</td><td>$risk</td><td>$resultCell</td></tr>"
        }) -join "`n"
    }

    # Sign-in profile summary
    $profileRows = if (-not $SignIn.Ok -or $SignIn.All.Count -eq 0) {
        No-Data 8 'No sign-in data available.'
    } else {
        $baseCountrySet = @($SignIn.Baseline |
            ForEach-Object { if ($_.Location) { $_.Location.CountryOrRegion } } |
            Where-Object { $_ } | Sort-Object -Unique)

        $groups = $SignIn.All | Group-Object {
            $c  = if ($_.Location -and $_.Location.CountryOrRegion) { $_.Location.CountryOrRegion } else { 'Unknown' }
            $ap = if ($_.AppDisplayName) { $_.AppDisplayName } else { 'Unknown App' }
            $os = if ($_.DeviceDetail -and $_.DeviceDetail.OperatingSystem) { $_.DeviceDetail.OperatingSystem }
                  elseif ($_.ClientAppUsed) { $_.ClientAppUsed }
                  else { 'Unknown' }
            "$c|||$ap|||$os"
        }

        $profiles = @($groups | ForEach-Object {
            $parts   = $_.Name -split '\|\|\|'
            $entries = @($_.Group)
            $country = $parts[0]

            $isNewCountry = $country -notin @('Unknown', '') -and $country -notin $baseCountrySet
            $hasRisk      = @($entries | Where-Object {
                $_.RiskLevelDuringSignIn -in @('high','medium') -or
                $_.RiskLevelAggregated   -in @('high','medium')
            }).Count -gt 0
            $isLegacy     = @($entries | Where-Object {
                $_.ClientAppUsed -match 'SMTP|IMAP|POP|MAPI|ActiveSync|Other clients'
            }).Count -gt 0
            $uniqueIps    = @($entries | Select-Object -ExpandProperty IpAddress | Where-Object { $_ } | Sort-Object -Unique)
            $lastSeen     = ($entries | Sort-Object CreatedDateTime -Descending | Select-Object -First 1).CreatedDateTime
            $successCount = @($entries | Where-Object { $_.Status -and $_.Status.ErrorCode -eq 0 }).Count
            $failCount    = $entries.Count - $successCount

            $reasons = @()
            if ($isNewCountry) { $reasons += 'New country' }
            if ($hasRisk)      { $reasons += 'Risk detected' }
            if ($isLegacy)     { $reasons += 'Legacy auth' }

            [PSCustomObject]@{
                Country      = $country
                App          = $parts[1]
                DeviceOS     = $parts[2]
                Count        = $entries.Count
                UniqueIPs    = $uniqueIps.Count
                IpList       = $uniqueIps
                LastSeen     = $lastSeen
                SuccessCount = $successCount
                FailCount    = $failCount
                Reasons      = $reasons -join '; '
            }
        }) | Sort-Object { if ($_.Reasons -ne '') { 0 } else { 1 } }, { -$_.Count }

        ($profiles | ForEach-Object {
            $suspicious = $_.Reasons -ne ''
            $hasFailures = $_.FailCount -gt 0
            $rowStyle   = if ($suspicious)  { " style='background:#fff7ed;'" }
                          elseif ($hasFailures) { " style='background:#fff7ed;'" }
                          else                  { '' }
            $sevClass    = if ($_.Reasons -match 'Risk') { 'High' } elseif ($suspicious) { 'Medium' } else { '' }
            $rawFlagText = if ($suspicious) { $_.Reasons } else { '' }
            $flagCell    = if ($suspicious) { "$(Sev-Badge $sevClass) $(HtmlEncode $rawFlagText)" } else { "<span class='muted'>clean</span>" }
            $resultCell  = if ($_.FailCount -eq 0) {
                "<span style='color:#166534;font-weight:600;'>$($_.SuccessCount) success</span>"
            } elseif ($_.SuccessCount -eq 0) {
                "<span style='color:#991b1b;font-weight:600;'>$($_.FailCount) failed</span>"
            } else {
                "<span style='color:#166534;font-weight:600;'>$($_.SuccessCount) success</span> / <span style='color:#991b1b;font-weight:600;'>$($_.FailCount) failed</span>"
            }
            $ipCell = ($_.IpList | ForEach-Object { HtmlEncode $_ }) -join '<br>'
            "<tr$rowStyle><td>$(HtmlEncode $_.Country)</td><td>$(HtmlEncode $_.App)</td><td>$(HtmlEncode $_.DeviceOS)</td><td>$($_.Count)</td><td>$ipCell</td><td>$(HtmlEncode $_.LastSeen)</td><td>$resultCell</td><td>$flagCell</td></tr>"
        }) -join "`n"
    }

    # Identity Protection
    $idpContent = if (-not $RiskyUser.Ok -and $RiskyUser.NotLicensed) {
        "<div class='muted'>Identity Protection not available: tenant is not licensed for this feature (requires Entra ID P2).</div>"
    } elseif (-not $RiskyUser.Ok) {
        "<div class='err'>Collector error: $($RiskyUser.Error)</div>"
    } elseif (-not $RiskyUser.Data) {
        "<div class='muted'>User not found in Identity Protection risky users list.</div>"
    } else {
        $ru = $RiskyUser.Data
        $badge = if ($ru.RiskState -in @('atRisk','confirmedCompromised')) { Sev-Badge 'High' } else { Sev-Badge 'Info' }
        "<table><tr><th>Risk State</th><th>Risk Detail</th><th>Risk Level</th><th>Last Updated</th></tr>
        <tr><td>$badge $(HtmlEncode $ru.RiskState)</td><td>$(HtmlEncode $ru.RiskDetail)</td><td>$(HtmlEncode $ru.RiskLevel)</td><td>$(HtmlEncode $ru.RiskLastUpdatedDateTime)</td></tr></table>"
    }

    # Mailbox config
    $mbContent = if (-not $MailboxConfig.Ok) {
        "<div class='err'>Collector error: $($MailboxConfig.Error)</div>"
    } else {
        $mb = $MailboxConfig.Data
        "<table><tr><th>Property</th><th>Value</th></tr>
        <tr><td>ForwardingSmtpAddress</td><td>$(if ($mb.ForwardingSmtpAddress) { "<strong style='color:#991b1b;'>$(HtmlEncode $mb.ForwardingSmtpAddress)</strong>" } else { '<span class=''muted''>not set</span>' })</td></tr>
        <tr><td>ForwardingAddress</td><td>$(if ($mb.ForwardingAddress) { HtmlEncode($mb.ForwardingAddress) } else { '<span class=''muted''>not set</span>' })</td></tr>
        <tr><td>DeliverToMailboxAndForward</td><td>$(HtmlEncode $mb.DeliverToMailboxAndForward)</td></tr>
        <tr><td>HiddenFromAddressListsEnabled</td><td>$(HtmlEncode $mb.HiddenFromAddressListsEnabled)</td></tr>
        <tr><td>AuditEnabled</td><td>$(if (-not $mb.AuditEnabled) { "<strong style='color:#991b1b;'>False</strong>" } else { 'True' })</td></tr>
        <tr><td>RecipientTypeDetails</td><td>$(HtmlEncode $mb.RecipientTypeDetails)</td></tr></table>"
    }

    # Inbox rules
    $ruleRows = if (-not $InboxRules.Ok) {
        Err-Row $InboxRules.Error 5
    } elseif ($InboxRules.Data.Count -eq 0) {
        No-Data 5 'No inbox rules found.'
    } else {
        ($InboxRules.Data | ForEach-Object {
            $hasFwd = $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo
            $rowStyle = if ($hasFwd -or $_.DeleteMessage) { " style='background:#fff7ed;'" } else { '' }
            $actions = @()
            if ($_.ForwardTo)            { $actions += "Forward: $($_.ForwardTo -join ', ')" }
            if ($_.RedirectTo)           { $actions += "Redirect: $($_.RedirectTo -join ', ')" }
            if ($_.ForwardAsAttachmentTo){ $actions += "FwdAttachment: $($_.ForwardAsAttachmentTo -join ', ')" }
            if ($_.DeleteMessage)        { $actions += "Delete" }
            if ($_.MarkAsRead)           { $actions += "MarkAsRead" }
            if ($_.MoveToFolder)         { $actions += "Move: $($_.MoveToFolder)" }
            "<tr$rowStyle><td>$(HtmlEncode $_.Name)</td><td>$(HtmlEncode $_.Enabled)</td><td>$(HtmlEncode $_.Priority)</td><td>$(HtmlEncode $_.Description)</td><td>$(HtmlEncode ($actions -join '; '))</td></tr>"
        }) -join "`n"
    }

    # Auth methods
    $authRows = if (-not $AuthMethods.Ok) {
        Err-Row $AuthMethods.Error 4
    } elseif ($AuthMethods.Data.Count -eq 0) {
        No-Data 4 'No authentication methods found.'
    } else {
        $cutoff = (Get-Date).AddDays(-$DaysBack)
        ($AuthMethods.Data | ForEach-Object {
            $isNew = $false
            if ($_.CreatedDateTime) { try { $isNew = ([datetime]$_.CreatedDateTime) -ge $cutoff } catch {} }
            $rowStyle = if ($isNew) { " style='background:#fff1f2;'" } else { '' }
            $cd = if ($_.CreatedDateTime) { HtmlEncode($_.CreatedDateTime) } else { '<span class=''muted''>n/a</span>' }
            $rawDisp = if ($_.DisplayName) { $_.DisplayName } elseif ($_.PhoneNumber) { $_.PhoneNumber } else { '' }
            $dispVal = HtmlEncode $rawDisp
            "<tr$rowStyle><td>$(HtmlEncode $_.MethodType)</td><td>$cd</td><td>$dispVal</td><td>$(if ($isNew) { Sev-Badge 'High' } else { '' })</td></tr>"
        }) -join "`n"
    }

    # Audit events
    $auditRows = if (-not $AuditEvents.Ok) {
        Err-Row $AuditEvents.Error 5
    } elseif ($AuditEvents.Data.Count -eq 0) {
        No-Data 5 'No matching audit events found in the lookback window.'
    } else {
        ($AuditEvents.Data | Sort-Object LastAccessed -Descending | ForEach-Object {
            $isSusp = $_.LogonType -in @('Admin','Delegate') -and $_.Operation -in @('HardDelete','UpdateFolderPermissions','SendAs','SendOnBehalf')
            $rowStyle = if ($isSusp) { " style='background:#fff1f2;'" } else { '' }
            "<tr$rowStyle><td>$(HtmlEncode $_.LastAccessed)</td><td>$(HtmlEncode $_.Operation)</td><td>$(HtmlEncode $_.LogonType)</td><td>$(HtmlEncode $_.LogonUserDisplayName)</td><td>$(HtmlEncode $_.DestFolderPathName)</td></tr>"
        }) -join "`n"
    }

    # Transport rules
    $transportRows = if (-not $TransportRules.Ok) {
        Err-Row $TransportRules.Error 4
    } elseif ($TransportRules.Data.Count -eq 0) {
        No-Data 4 'No transport rules match this sender.'
    } else {
        ($TransportRules.Data | ForEach-Object {
            $actions = @()
            if ($_.RedirectMessageTo) { $actions += "Redirect: $($_.RedirectMessageTo -join ', ')" }
            if ($_.BlindCopyTo)       { $actions += "BCC: $($_.BlindCopyTo -join ', ')" }
            if ($_.CopyTo)            { $actions += "Copy: $($_.CopyTo -join ', ')" }
            if ($_.DeleteMessage)     { $actions += "Delete" }
            if ($_.RejectMessageWith) { $actions += "Reject" }
            "<tr><td>$(HtmlEncode $_.Name)</td><td>$(HtmlEncode $_.State)</td><td>$(HtmlEncode $_.Priority)</td><td>$(HtmlEncode ($actions -join '; '))</td></tr>"
        }) -join "`n"
    }

    # User profile summary
    $upData = if ($UserProfile.Ok -and $UserProfile.Data) {
        $u = $UserProfile.Data
        "<table><tr><th>Property</th><th>Value</th></tr>
        <tr><td>Display Name</td><td>$(HtmlEncode $u.DisplayName)</td></tr>
        <tr><td>UPN</td><td>$(HtmlEncode $u.UserPrincipalName)</td></tr>
        <tr><td>Account Enabled</td><td>$(if (-not $u.AccountEnabled) { "<strong style='color:#991b1b;'>False</strong>" } else { 'True' })</td></tr>
        <tr><td>Created</td><td>$(HtmlEncode $u.CreatedDateTime)</td></tr>
        <tr><td>Last Password Change</td><td>$(HtmlEncode $u.LastPasswordChangeDateTime)</td></tr>
        <tr><td>On-Premises Sync</td><td>$(HtmlEncode $u.OnPremisesSyncEnabled)</td></tr></table>"
    } else {
        "<div class='err'>Collector error: $($UserProfile.Error)</div>"
    }

    return @"
<!doctype html>
<html><head><meta charset="utf-8"/><title>Account Compromise Report - $(HtmlEncode $displayName)</title>
<style>
body { font-family: Arial, sans-serif; margin:20px; background:#f7f9fb; color:#111827; }
h1 { margin-bottom:4px; }
.card { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:14px; box-shadow:0 4px 12px rgba(0,0,0,0.05); margin-bottom:12px; }
.card h2 { margin:0 0 8px 0; font-size:18px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { padding:8px 10px; border-bottom:1px solid #edf0f5; text-align:left; vertical-align:top; }
th { background:#eef3fb; font-weight:700; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid transparent; font-weight:600; }
.sev-high   { background:#fee2e2; color:#991b1b; border-color:#fecdd3; }
.sev-medium { background:#fef3c7; color:#854d0e; border-color:#fde68a; }
.sev-low    { background:#dbeafe; color:#1e3a8a; border-color:#93c5fd; }
.sev-info   { background:#f3f4f6; color:#374151; border-color:#d1d5db; }
.muted { color:#6b7280; font-size:12px; }
.err   { color:#991b1b; font-style:italic; font-size:13px; }
.stat-block { display:flex; gap:12px; margin-bottom:10px; flex-wrap:wrap; }
.stat-tile { flex:1; min-width:100px; background:#f8fafc; border:1px solid #e5e7eb; border-radius:8px; padding:12px 16px; text-align:center; }
.stat-tile .stat-val { font-size:28px; font-weight:700; line-height:1.1; color:#111827; }
.stat-tile .stat-lbl { font-size:11px; color:#6b7280; margin-top:4px; text-transform:uppercase; letter-spacing:.05em; }
.stat-tile.alert-red .stat-val, .stat-tile.alert-red .stat-lbl { color:#991b1b; }
.stat-tile.alert-red { background:#fee2e2; border-color:#fecdd3; }
.stat-tile.alert-orange .stat-val, .stat-tile.alert-orange .stat-lbl { color:#c2410c; }
.stat-tile.alert-orange { background:#fff7ed; border-color:#fed7aa; }
</style></head><body>
  <h1>Account Compromise Report</h1>
  <div class="muted">User: <strong>$(HtmlEncode $displayName)</strong> ($(HtmlEncode $Upn)) &nbsp;|&nbsp; Lookback: ${DaysBack}d &nbsp;|&nbsp; Generated: $generated &nbsp;|&nbsp; Script v$ScriptVersion</div>

  <div class="card">
    <h2>IOC Summary</h2>
    <table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Detail</th></tr>
    $summaryRows
    </table>
  </div>

  <div class="card">
    <h2>Sign-In Profile Summary (30 days)</h2>
    <div class="muted" style="margin-bottom:6px;">One row per unique country / app / device combination across the full 30-day window. Suspicious profiles are highlighted. &ldquo;New country&rdquo; means no sign-ins from that country in the baseline period prior to the lookback window.</div>
    <table><tr><th>Country</th><th>App</th><th>Device / OS</th><th>Sign-ins</th><th>IPs</th><th>Last Seen</th><th>Result</th><th>Flags</th></tr>
    $profileRows
    </table>
  </div>

  <div class="card">
    <h2>User Profile</h2>
    $upData
  </div>

  <div class="card">
    <h2>Sign-In Activity (last ${DaysBack} days)</h2>
    <div class="muted" style="margin-bottom:6px;">$(if ($SignIn.Ok) { "Showing $($SignIn.InWindow.Count) sign-in(s). Baseline (days $DaysBack-30): $($SignIn.Baseline.Count) sign-in(s)." })</div>
    <table><tr><th>Timestamp</th><th>IP</th><th>Location</th><th>App</th><th>CA Status</th><th>Risk Level</th><th>Result</th></tr>
    $signInRows
    </table>
  </div>

  <div class="card">
    <h2>Identity Protection</h2>
    $idpContent
  </div>

  <div class="card">
    <h2>Mailbox Configuration</h2>
    $mbContent
  </div>

  <div class="card">
    <h2>Inbox Rules</h2>
    <table><tr><th>Name</th><th>Enabled</th><th>Priority</th><th>Description</th><th>Actions</th></tr>
    $ruleRows
    </table>
  </div>

  <div class="card">
    <h2>Authentication Methods</h2>
    <div class="muted" style="margin-bottom:6px;">Methods registered within the lookback window are highlighted.</div>
    <table><tr><th>Method Type</th><th>Registered</th><th>Display / Phone</th><th>Flag</th></tr>
    $authRows
    </table>
  </div>

  <div class="card">
    <h2>Mailbox Audit Log (last ${DaysBack} days)</h2>
    <table><tr><th>Timestamp</th><th>Operation</th><th>Logon Type</th><th>Performed By</th><th>Folder / Object</th></tr>
    $auditRows
    </table>
  </div>

  <div class="card">
    <h2>Transport Rules (matching this sender)</h2>
    <table><tr><th>Name</th><th>State</th><th>Priority</th><th>Actions</th></tr>
    $transportRows
    </table>
  </div>

</body></html>
"@
}

# =============================================================================
# Main execution
# =============================================================================
Write-Info "Diagnose-AccountCompromise v$ScriptVersion"
Write-Info "Target: $UserPrincipalName | Lookback: $DaysBack days"

try {
    Assert-Sessions
} catch {
    Write-Fail $_.Exception.Message
    exit 1
}

# Phase 1: Collect
Write-Info "--- Collect ---"
$userProfile    = Get-UserProfile     -Upn $UserPrincipalName
$signIn         = Get-SignInActivity  -Upn $UserPrincipalName -DaysBack $DaysBack
$riskyUser      = Get-RiskyUserStatus -Upn $UserPrincipalName
$authMethods    = Get-AuthMethods     -Upn $UserPrincipalName
$mailboxConfig  = Get-MailboxConfig   -Upn $UserPrincipalName
$inboxRules     = Get-InboxRules      -Upn $UserPrincipalName
$auditEvents    = Get-MailboxAuditEvents    -Upn $UserPrincipalName -DaysBack $DaysBack
$transportRules = Get-TransportRuleMatches  -Upn $UserPrincipalName

# Phase 2: Analyze
Write-Info "--- Analyze ---"
$findings = Invoke-IocAnalysis `
    -Upn             $UserPrincipalName `
    -DaysBack        $DaysBack `
    -UserProfile     $userProfile `
    -SignIn          $signIn `
    -RiskyUser       $riskyUser `
    -AuthMethods     $authMethods `
    -MailboxConfig   $mailboxConfig `
    -InboxRules      $inboxRules `
    -AuditEvents     $auditEvents `
    -TransportRules  $transportRules

$highCount   = @($findings | Where-Object { $_.Severity -eq 'High'   }).Count
$medCount    = @($findings | Where-Object { $_.Severity -eq 'Medium' }).Count
Write-Info "Findings: $($findings.Count) total | High: $highCount | Medium: $medCount"

# Phase 3: Render
Write-Info "--- Render ---"
$html = ConvertTo-HtmlReport `
    -Upn            $UserPrincipalName `
    -DaysBack       $DaysBack `
    -ScriptVersion  $ScriptVersion `
    -Findings       $findings `
    -UserProfile    $userProfile `
    -SignIn         $signIn `
    -RiskyUser      $riskyUser `
    -AuthMethods    $authMethods `
    -MailboxConfig  $mailboxConfig `
    -InboxRules     $inboxRules `
    -AuditEvents    $auditEvents `
    -TransportRules $transportRules

$resolvedPath = [System.IO.Path]::GetFullPath($OutputHtml)
if ($resolvedPath.EndsWith('\') -or $resolvedPath.EndsWith('/') -or (Test-Path $resolvedPath -PathType Container)) {
    $safeName = $UserPrincipalName -replace '[^a-zA-Z0-9@._-]', '_'
    $resolvedPath = [System.IO.Path]::Combine($resolvedPath.TrimEnd('\', '/'), "AccountCompromise-$safeName-$(Get-Date -Format 'yyyyMMdd').html")
}
$outDir = [System.IO.Path]::GetDirectoryName($resolvedPath)
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
[System.IO.File]::WriteAllText($resolvedPath, $html, [System.Text.Encoding]::UTF8)
Write-Done "Report written to $resolvedPath"

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    Invoke-Item $OutputHtml
}
