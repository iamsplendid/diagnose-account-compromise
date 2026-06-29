# Sign-In Log Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Do not ask for approval between steps. Only raise questions about design decisions.**

**Goal:** Replace the unbounded `Get-MgAuditLogSignIn -All` call with two date-scoped, capped queries so sign-in collection never times out, even for high-volume compromised accounts.

**Architecture:** Split the single 30-day query into a window query (last DaysBack days, cap 2,000) and a baseline query (days DaysBack–30, cap 500). Both use `-All -PageSize 999 | Select-Object -First N` for early pipeline termination. The renderer shows amber banners and a "+" on the Total tile when either is truncated.

**Tech Stack:** PowerShell 5.1+, Microsoft.Graph PowerShell SDK (Get-MgAuditLogSignIn)

## Global Constraints

- Single-file script: all changes are in `Diagnose-AccountCompromise.ps1`
- No external JS libraries; all HTML is inline strings
- `HtmlEncode` all user-derived strings in HTML output
- Em-dashes in PowerShell string literals must use `&mdash;` in HTML, not the Unicode character
- No changes to script parameters, collector function signatures, or `Invoke-IocAnalysis`

---

### Task 1: Rewrite `Get-SignInActivity` with two bounded queries

**Files:**
- Modify: `Diagnose-AccountCompromise.ps1:212-234`

**Interfaces:**
- Produces: `[PSCustomObject]` with fields `Ok`, `All`, `InWindow`, `Baseline`, `WindowTruncated`, `BaselineTruncated`, `Error`
  - `Ok` = `$true` / `$false`
  - `All` = `@($inWindow) + @($baseline)` (union array)
  - `InWindow` = sign-ins within last DaysBack days, newest first, max 2,000
  - `Baseline` = sign-ins from day DaysBack to day 30, newest first, max 500
  - `WindowTruncated` = `$true` if InWindow hit the 2,000-record cap
  - `BaselineTruncated` = `$true` if Baseline hit the 500-record cap
  - `Error` = error message string (only present when `Ok = $false`)

- [ ] **Step 1: Replace `Get-SignInActivity` (lines 212–234)**

Replace the entire function with this:

```powershell
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
```

- [ ] **Step 2: Verify the function compiles cleanly**

Run:
```powershell
# From a PowerShell prompt (not required to connect to Graph)
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    'C:\github\diagnose-account-compromise\Diagnose-AccountCompromise.ps1',
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output (empty `$errors`). If errors appear, fix them before continuing.

- [ ] **Step 3: Commit**

```bash
git add Diagnose-AccountCompromise.ps1
git commit -m "feat: replace unbounded sign-in query with two bounded date-scoped queries"
```

---

### Task 2: Update renderer for truncation display

**Files:**
- Modify: `Diagnose-AccountCompromise.ps1` (renderer section inside `ConvertTo-HtmlReport`)

**Interfaces:**
- Consumes: `$SignIn.WindowTruncated` (`$true`/`$false`) and `$SignIn.BaselineTruncated` (`$true`/`$false`) from Task 1

Changes in this task (all inside the `else` branch of `$signInSummaryContent`, starting around line 582):
1. Remove dead `$crAll` variable (lines ~590–594)
2. Change `$tileTotal` to display `N+` when window is truncated
3. Add `$truncationBanner` variable and insert it between `$statBlock` and `$anomalyContent`
4. Update the "Showing N sign-in(s)" subtitle text (line ~949) to reflect truncation

- [ ] **Step 4: Remove dead `$crAll` variable**

Find and delete these lines (they appear right after the `$crBaseline` block):

```powershell
        $crAll = @($SignIn.All | Where-Object {
            ($_.Status -and $_.Status.ErrorCode -eq 0) -or
            ($_.Status -and $_.Status.ErrorCode -in $mfaErrorCodes) -or
            ($_.Status -and $_.Status.FailureReason -match 'MFA|strong auth|multi.factor|authentication strength')
        })
```

- [ ] **Step 5: Change the Total KPI tile to show `N+` when truncated**

Find:
```powershell
        $tileTotal   = "<div class='stat-tile'><div class='stat-val'>$statTotal</div><div class='stat-lbl'>Sign-ins</div></div>"
```

Replace with:
```powershell
        $totalLabel  = if ($SignIn.WindowTruncated) { "$statTotal+" } else { "$statTotal" }
        $tileTotal   = "<div class='stat-tile'><div class='stat-val'>$totalLabel</div><div class='stat-lbl'>Sign-ins</div></div>"
```

- [ ] **Step 6: Add truncation banner and insert between stat block and anomaly table**

Find:
```powershell
        "$statBlock$anomalyContent"
```

Replace with:
```powershell
        $truncationBanner = ''
        if ($SignIn.WindowTruncated -and $SignIn.BaselineTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Sign-in data capped at 2,000 records (most recent first). Older sign-ins in this window were not loaded. Baseline sample also capped at 500 records &mdash; new-country detection may be incomplete.</div>"
        } elseif ($SignIn.WindowTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Sign-in data capped at 2,000 records (most recent first). Older sign-ins in this window were not loaded.</div>"
        } elseif ($SignIn.BaselineTruncated) {
            $truncationBanner = "<div style='background:#fff7ed;border:1px solid #fed7aa;border-radius:4px;padding:6px 10px;margin-bottom:8px;font-size:11px;color:#c2410c;'>Baseline sample capped at 500 records &mdash; new-country detection may be incomplete.</div>"
        }
        "$statBlock$truncationBanner$anomalyContent"
```

- [ ] **Step 7: Update the sign-in activity subtitle to reflect truncation**

Find (inside the here-string, around line 949):
```powershell
    <div class="muted" style="margin-bottom:6px;">$(if ($SignIn.Ok) { "Showing $($SignIn.InWindow.Count) sign-in(s). Baseline (days $DaysBack-30): $($SignIn.Baseline.Count) sign-in(s)." })</div>
```

Replace with:
```powershell
    <div class="muted" style="margin-bottom:6px;">$(if ($SignIn.Ok) { "Showing $($SignIn.InWindow.Count)$(if ($SignIn.WindowTruncated) { '+' }) sign-in(s). Baseline (days $DaysBack-30): $($SignIn.Baseline.Count)$(if ($SignIn.BaselineTruncated) { '+' }) sign-in(s)." })</div>
```

- [ ] **Step 8: Verify the script compiles cleanly**

Run:
```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    'C:\github\diagnose-account-compromise\Diagnose-AccountCompromise.ps1',
    [ref]$null, [ref]$errors
)
$errors
```

Expected: no output.

- [ ] **Step 9: Manual smoke test**

Run the script against any test account and confirm:
- Report generates without error
- Sign-In Summary card appears and stat tiles render
- No truncation banner appears for a normal low-volume account
- The "Showing N sign-in(s)" subtitle in Sign-In Activity is accurate

If you have access to a high-volume account or can temporarily lower `$windowCap` to 3 to force truncation, verify:
- Total tile shows `N+`
- Amber banner appears above the anomaly table
- Subtitle shows `N+`

- [ ] **Step 10: Commit**

```bash
git add Diagnose-AccountCompromise.ps1
git commit -m "feat: show truncation banner and N+ counts when sign-in data is capped"
```
