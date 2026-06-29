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
    Write-Step "Collecting sign-in logs..."
    try {
        $escapedUpn    = $Upn -replace "'", "''"
        $now           = Get-Date
        $windowStart   = $now.AddDays(-$DaysBack).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $baselineStart = $now.AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

        $windowFilter   = "userPrincipalName eq '$escapedUpn' and createdDateTime ge $windowStart"
        $baselineFilter = "userPrincipalName eq '$escapedUpn' and createdDateTime ge $baselineStart and createdDateTime lt $windowStart"

        $windowCap   = 2000
        $baselineCap = 500

        $windowRaw = @(Get-MgAuditLogSignIn -Filter $windowFilter -All -PageSize 999 -ErrorAction Stop |
            Select-Object -First ($windowCap + 1))
        $windowTruncated = $windowRaw.Count -gt $windowCap
        $inWindow = if ($windowTruncated) { @($windowRaw | Select-Object -First $windowCap) } else { $windowRaw }

        $baselineRaw = @(Get-MgAuditLogSignIn -Filter $baselineFilter -All -PageSize 999 -ErrorAction Stop |
            Select-Object -First ($baselineCap + 1))
        $baselineTruncated = $baselineRaw.Count -gt $baselineCap
        $baseline = if ($baselineTruncated) { @($baselineRaw | Select-Object -First $baselineCap) } else { $baselineRaw }

        $all = @($inWindow) + @($baseline)

        $windowLabel   = "$($inWindow.Count)$(if ($windowTruncated) { '+' })"
        $baselineLabel = "$($baseline.Count)$(if ($baselineTruncated) { '+' })"
        Write-Done "Sign-ins: $windowLabel in window, $baselineLabel in baseline"

        return [PSCustomObject]@{
            Ok                = $true
            All               = $all
            InWindow          = $inWindow
            Baseline          = $baseline
            WindowTruncated   = $windowTruncated
            BaselineTruncated = $baselineTruncated
        }
    } catch {
        Write-Fail "Get-SignInActivity failed: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Ok                = $false
            Error             = $_.Exception.Message
            All               = @()
            InWindow          = @()
            Baseline          = @()
            WindowTruncated   = $false
            BaselineTruncated = $false
        }
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
    # Built-in folders attackers use as staging areas — users rarely open these
    $suspiciousFolders = @('RSS Subscriptions', 'RSS Feeds', 'Deleted Items', 'Junk Email', 'Clutter', 'Sync Issues', 'Archive')
    # Keywords attackers filter for to suppress detection emails and hide BEC activity
    $securityKeywords  = @('phish', 'phishing', 'spam', 'suspicious', 'malware', 'virus', 'quarantine',
                           'security alert', 'unusual sign', 'blocked', 'invoice', 'payment', 'wire transfer',
                           'unusual activity', 'verify your', 'confirm your')

    if ($InboxRules.Ok) {
        foreach ($rule in @($InboxRules.Data | Where-Object { $_.Enabled })) {
            $fwdTargets = @()
            if ($rule.ForwardTo)            { $fwdTargets += @($rule.ForwardTo | ForEach-Object { $_.ToString() }) }
            if ($rule.RedirectTo)           { $fwdTargets += @($rule.RedirectTo | ForEach-Object { $_.ToString() }) }
            if ($rule.ForwardAsAttachmentTo){ $fwdTargets += @($rule.ForwardAsAttachmentTo | ForEach-Object { $_.ToString() }) }

            $moveFolder       = $rule.MoveToFolder
            $isObscureFolder  = $moveFolder -and ($suspiciousFolders -contains $moveFolder -or $moveFolder -eq 'Deleted Items')

            # Forwarding / redirect — always high
            if ($fwdTargets.Count -gt 0) {
                Add-Finding 'High' 'InboxRule' "Rule '$($rule.Name)' forwards or redirects mail" "Targets: $($fwdTargets -join '; ')"
            }

            # Delete — high (active evidence destruction)
            if ($rule.DeleteMessage) {
                Add-Finding 'High' 'InboxRule' "Rule '$($rule.Name)' deletes matching messages" "Description: $($rule.Description)"
            }

            # Move to obscure built-in folder — canonical BEC hiding pattern
            if ($isObscureFolder) {
                $detail = "MoveToFolder: $moveFolder"
                if ($rule.MarkAsRead) { $detail += ' + MarkAsRead' }
                Add-Finding 'High' 'InboxRule' "Rule '$($rule.Name)' moves mail to obscure folder '$moveFolder'" $detail
            } elseif ($rule.MarkAsRead -and $moveFolder) {
                # MarkAsRead + move to a named (non-built-in) folder — medium, but hides messages from user
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' moves and silently marks messages as read" "MoveToFolder: $moveFolder"
            } elseif ($rule.MarkAsRead -and -not $moveFolder) {
                # MarkAsRead alone — medium
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' silently marks messages as read" "Description: $($rule.Description)"
            }

            # Security keyword filtering — suppressing detection/financial emails
            $allKeywords = @()
            if ($rule.SubjectContainsWords)       { $allKeywords += $rule.SubjectContainsWords }
            if ($rule.SubjectOrBodyContainsWords)  { $allKeywords += $rule.SubjectOrBodyContainsWords }
            if ($rule.BodyContainsWords)           { $allKeywords += $rule.BodyContainsWords }
            $matchedKeywords = @($allKeywords | Where-Object {
                $kw = $_
                $securityKeywords | Where-Object { $kw -match $_ }
            })
            if ($matchedKeywords.Count -gt 0) {
                Add-Finding 'High' 'InboxRule' "Rule '$($rule.Name)' targets security or financial keywords" "Keywords: $($matchedKeywords -join ', ')"
            }

            # Nonsensical rule name — common attacker pattern
            if ($rule.Name -match '^[.\s;_\-]{1,3}$') {
                Add-Finding 'Medium' 'InboxRule' "Rule '$($rule.Name)' has a suspicious (nonsensical) name" 'Single-character or punctuation-only names are a common attacker pattern.'
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

    # Sign-in summary (stat block + anomaly table)
    $signInSummaryContent = if (-not $SignIn.Ok) {
        "<div class='err'>Collector error: $(HtmlEncode $SignIn.Error)</div>"
    } elseif ($SignIn.All.Count -eq 0) {
        "<div class='muted'>No sign-in data available.</div>"
    } else {
        $mfaErrorCodes = @(50074, 50076, 50079, 500121, 53004, 50158)

        # Credential-relevant: successful or MFA-blocked (valid creds regardless of MFA outcome)
        $crWindow = @($SignIn.InWindow | Where-Object {
            ($_.Status -and $_.Status.ErrorCode -eq 0) -or
            ($_.Status -and $_.Status.ErrorCode -in $mfaErrorCodes) -or
            ($_.Status -and $_.Status.FailureReason -match 'MFA|strong auth|multi.factor|authentication strength')
        })
        $crBaseline = @($SignIn.Baseline | Where-Object {
            ($_.Status -and $_.Status.ErrorCode -eq 0) -or
            ($_.Status -and $_.Status.ErrorCode -in $mfaErrorCodes) -or
            ($_.Status -and $_.Status.FailureReason -match 'MFA|strong auth|multi.factor|authentication strength')
        })

        # --- Stat block (all counts from InWindow) ---
        $statTotal   = $SignIn.InWindow.Count
        $statSuccess = @($SignIn.InWindow | Where-Object { $_.Status -and $_.Status.ErrorCode -eq 0 }).Count
        $statMfa     = @($SignIn.InWindow | Where-Object {
            ($_.Status -and $_.Status.ErrorCode -in $mfaErrorCodes) -or
            ($_.Status -and $_.Status.FailureReason -match 'MFA|strong auth|multi.factor|authentication strength')
        }).Count
        $statRisk    = @($SignIn.InWindow | Where-Object {
            $_.RiskLevelDuringSignIn -in @('high','medium') -or $_.RiskLevelAggregated -in @('high','medium')
        }).Count
        $statLegacy  = @($crWindow | Where-Object {
            $_.ClientAppUsed -match 'SMTP|IMAP|POP|MAPI|ActiveSync|Other clients'
        }).Count

        $totalLabel  = if ($SignIn.WindowTruncated) { "$statTotal+" } else { "$statTotal" }
        $tileTotal   = "<div class='stat-tile'><div class='stat-val'>$totalLabel</div><div class='stat-lbl'>Sign-ins</div></div>"
        $tileSuccess = "<div class='stat-tile'><div class='stat-val'>$statSuccess</div><div class='stat-lbl'>Successful</div></div>"
        $mfaClass    = if ($statMfa   -gt 0) { 'stat-tile alert-red'    } else { 'stat-tile' }
        $riskClass   = if ($statRisk  -gt 0) { 'stat-tile alert-red'    } else { 'stat-tile' }
        $legacyClass = if ($statLegacy -gt 0) { 'stat-tile alert-orange' } else { 'stat-tile' }
        $tileMfa     = "<div class='$mfaClass'><div class='stat-val'>$statMfa</div><div class='stat-lbl'>MFA Blocks</div></div>"
        $tileRisk    = "<div class='$riskClass'><div class='stat-val'>$statRisk</div><div class='stat-lbl'>Risk Events</div></div>"
        $tileLegacy  = "<div class='$legacyClass'><div class='stat-val'>$statLegacy</div><div class='stat-lbl'>Legacy Auth</div></div>"
        $statBlock   = "<div class='stat-block'>$tileTotal$tileSuccess$tileMfa$tileRisk$tileLegacy</div>"

        # --- Anomaly table (operates on credential-relevant sign-ins across 30 days) ---
        $anomalies = [System.Collections.Generic.List[PSCustomObject]]::new()

        # 1. New country: credential-relevant activity in window not seen in baseline
        $baselineCountries = @($crBaseline |
            ForEach-Object { if ($_.Location) { $_.Location.CountryOrRegion } } |
            Where-Object { $_ } | Sort-Object -Unique)
        $windowByCountry = @($crWindow | Where-Object { $_.Location -and $_.Location.CountryOrRegion } |
            Group-Object { $_.Location.CountryOrRegion })
        foreach ($grp in $windowByCountry) {
            if ($grp.Name -and $grp.Name -notin $baselineCountries) {
                $firstSeen = ($grp.Group | Sort-Object CreatedDateTime | Select-Object -First 1).CreatedDateTime
                $anomalies.Add([PSCustomObject]@{
                    Severity = 'High'
                    Anomaly  = 'New country'
                    Detail   = "$(HtmlEncode $grp.Name) &mdash; first seen $(HtmlEncode $firstSeen)"
                    Count    = $grp.Count
                })
            }
        }

        # 2. MFA-blocked credential attempts (valid creds stopped by MFA)
        $mfaBlocked = @($crWindow | Where-Object { $_.Status -and $_.Status.ErrorCode -ne 0 })
        if ($mfaBlocked.Count -gt 0) {
            $topLoc = ($mfaBlocked |
                Group-Object { if ($_.Location -and $_.Location.CountryOrRegion) { $_.Location.CountryOrRegion } else { 'Unknown' } } |
                Sort-Object Count -Descending | Select-Object -First 1).Name
            $anomalies.Add([PSCustomObject]@{
                Severity = 'High'
                Anomaly  = 'MFA-blocked credential attempt'
                Detail   = "Valid credentials blocked by MFA. Top location: $(HtmlEncode $topLoc)"
                Count    = $mfaBlocked.Count
            })
        }

        # 3. Risk events (high and medium reported separately)
        $highRiskCr = @($crWindow | Where-Object { $_.RiskLevelDuringSignIn -eq 'high' -or $_.RiskLevelAggregated -eq 'high' })
        $medRiskCr  = @($crWindow | Where-Object { $_.RiskLevelDuringSignIn -eq 'medium' -or $_.RiskLevelAggregated -eq 'medium' })
        if ($highRiskCr.Count -gt 0) {
            $anomalies.Add([PSCustomObject]@{
                Severity = 'High'
                Anomaly  = 'High-risk sign-in'
                Detail   = 'Entra Identity Protection flagged as high risk'
                Count    = $highRiskCr.Count
            })
        }
        if ($medRiskCr.Count -gt 0) {
            $anomalies.Add([PSCustomObject]@{
                Severity = 'Medium'
                Anomaly  = 'Medium-risk sign-in'
                Detail   = 'Entra Identity Protection flagged as medium risk'
                Count    = $medRiskCr.Count
            })
        }

        # 4. Legacy auth (credential-relevant -- bypasses MFA)
        $legacyCr = @($crWindow | Where-Object { $_.ClientAppUsed -match 'SMTP|IMAP|POP|MAPI|ActiveSync|Other clients' })
        if ($legacyCr.Count -gt 0) {
            $protocols = ($legacyCr | Select-Object -ExpandProperty ClientAppUsed | Sort-Object -Unique) -join ', '
            $anomalies.Add([PSCustomObject]@{
                Severity = 'High'
                Anomaly  = 'Legacy auth (bypasses MFA)'
                Detail   = "Protocol(s): $(HtmlEncode $protocols)"
                Count    = $legacyCr.Count
            })
        }

        # 5. Impossible travel: consecutive credential-relevant sign-ins from different countries < 4 hours apart
        $crSorted = @($crWindow | Sort-Object CreatedDateTime)
        $seenTravelPairs = @{}
        for ($i = 1; $i -lt $crSorted.Count; $i++) {
            $prev = $crSorted[$i - 1]
            $curr = $crSorted[$i]
            $prevCountry = if ($prev.Location) { $prev.Location.CountryOrRegion } else { $null }
            $currCountry = if ($curr.Location) { $curr.Location.CountryOrRegion } else { $null }
            if ($prevCountry -and $currCountry -and $prevCountry -ne $currCountry) {
                $gapMin = ([datetime]$curr.CreatedDateTime - [datetime]$prev.CreatedDateTime).TotalMinutes
                if ($gapMin -lt 240) {
                    $pairKey = "$prevCountry|||$currCountry"
                    if (-not $seenTravelPairs.ContainsKey($pairKey)) {
                        $seenTravelPairs[$pairKey] = $true
                        $h = [int]($gapMin / 60)
                        $m = [int]($gapMin % 60)
                        $anomalies.Add([PSCustomObject]@{
                            Severity = 'High'
                            Anomaly  = 'Impossible travel'
                            Detail   = "$(HtmlEncode $prevCountry) &rarr; $(HtmlEncode $currCountry) (${h}h ${m}m apart)"
                            Count    = 1
                        })
                    }
                }
            }
        }

        # Build anomaly HTML
        $anomalyContent = if ($anomalies.Count -eq 0) {
            "<div class='muted' style='padding:4px 0;'>No sign-in anomalies detected.</div>"
        } else {
            $rows = ($anomalies | ForEach-Object {
                "<tr><td>$(Sev-Badge $_.Severity)</td><td>$(HtmlEncode $_.Anomaly)</td><td>$($_.Detail)</td><td>$($_.Count)</td></tr>"
            }) -join "`n"
            "<table><tr><th>Severity</th><th>Anomaly</th><th>Detail</th><th>Count</th></tr>`n$rows</table>"
        }

        $truncationBanner = ''
        if ($SignIn.WindowTruncated -and $SignIn.BaselineTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Sign-in data capped at 2,000 records (most recent first). Older sign-ins in this window were not loaded. Baseline sample also capped at 500 records &mdash; new-country detection may be incomplete.</div>"
        } elseif ($SignIn.WindowTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Sign-in data capped at 2,000 records (most recent first). Older sign-ins in this window were not loaded.</div>"
        } elseif ($SignIn.BaselineTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Baseline sample capped at 500 records &mdash; new-country detection may be incomplete.</div>"
        }
        "$statBlock$truncationBanner$anomalyContent"
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
        $htmlSuspFolders = @('RSS Subscriptions', 'RSS Feeds', 'Deleted Items', 'Junk Email', 'Clutter', 'Sync Issues', 'Archive')
        ($InboxRules.Data | ForEach-Object {
            $hasFwd         = $_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo
            $isObscureMove  = $_.MoveToFolder -and $htmlSuspFolders -contains $_.MoveToFolder
            $rowStyle = if ($hasFwd -or $_.DeleteMessage -or $isObscureMove) { " style='background:#fff7ed;'" } else { '' }
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
    <h2>Sign-In Summary (last ${DaysBack} days)</h2>
    $signInSummaryContent
  </div>

  <div class="card">
    <h2>User Profile</h2>
    $upData
  </div>

  <div class="card">
    <h2>Sign-In Activity (last ${DaysBack} days)</h2>
    <div class="muted" style="margin-bottom:6px;">$(if ($SignIn.Ok) { "Showing $($SignIn.InWindow.Count)$(if ($SignIn.WindowTruncated) { '+' }) sign-in(s). Baseline (days $DaysBack-30): $($SignIn.Baseline.Count)$(if ($SignIn.BaselineTruncated) { '+' }) sign-in(s)." })</div>
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
    Invoke-Item $resolvedPath
}
