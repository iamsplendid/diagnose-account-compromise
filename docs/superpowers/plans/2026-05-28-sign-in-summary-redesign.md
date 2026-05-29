# Sign-In Summary Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the noisy Sign-In Profile Summary table with a stat block + anomaly table that focuses exclusively on credential-relevant sign-ins (successful or MFA-blocked).

**Architecture:** All changes are inside `ConvertTo-HtmlReport` in `Diagnose-AccountCompromise.ps1`. The `$profileRows` variable and its HTML card are replaced by `$signInSummaryContent`, which contains inline HTML for both the stat block and anomaly table. No changes to collectors or the data model.

**Tech Stack:** PowerShell 5.1+, Microsoft.Graph, ExchangeOnlineManagement. Verification is manual: run the script and inspect the HTML output in a browser.

---

### Task 1: Add CSS for KPI stat tiles

**Files:**
- Modify: `Diagnose-AccountCompromise.ps1` — `<style>` block inside the `return @"..."@` here-string (around line 672)

- [ ] **Step 1: Locate the style block closing tag**

Search for `.err   { color:#991b1b; font-style:italic; font-size:13px; }` — that is the last CSS rule before `</style>`.

- [ ] **Step 2: Add stat tile CSS after the `.err` rule**

Replace:
```powershell
.err   { color:#991b1b; font-style:italic; font-size:13px; }
</style></head><body>
```
With:
```powershell
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
```

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/github/diagnose-account-compromise
git add Diagnose-AccountCompromise.ps1
git commit -m "style: add KPI stat tile CSS for sign-in summary redesign"
```

---

### Task 2: Replace profile summary computation block

**Files:**
- Modify: `Diagnose-AccountCompromise.ps1` — replace the entire `# Sign-in profile summary` section (the `$profileRows = ...` block, approximately lines 476–549)

- [ ] **Step 1: Remove the old `$profileRows` block and replace with the new `$signInSummaryContent` block**

Find this comment and everything through the closing `}` of its `else` branch:
```powershell
    # Sign-in profile summary
    $profileRows = if (-not $SignIn.Ok -or $SignIn.All.Count -eq 0) {
```

Replace the entire block (from `# Sign-in profile summary` through the final `}` that closes the `else` at the end of `$profileRows`) with:

```powershell
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
        $crAll = @($SignIn.All | Where-Object {
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

        $tileTotal   = "<div class='stat-tile'><div class='stat-val'>$statTotal</div><div class='stat-lbl'>Sign-ins</div></div>"
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
        $windowByCountry = @($crAll | Where-Object { $_.Location -and $_.Location.CountryOrRegion } |
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
        $mfaBlocked = @($crAll | Where-Object { $_.Status -and $_.Status.ErrorCode -ne 0 })
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
        $highRiskCr = @($crAll | Where-Object { $_.RiskLevelDuringSignIn -eq 'high' -or $_.RiskLevelAggregated -eq 'high' })
        $medRiskCr  = @($crAll | Where-Object { $_.RiskLevelDuringSignIn -eq 'medium' -or $_.RiskLevelAggregated -eq 'medium' })
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

        # 4. Legacy auth (credential-relevant — bypasses MFA)
        $legacyCr = @($crAll | Where-Object { $_.ClientAppUsed -match 'SMTP|IMAP|POP|MAPI|ActiveSync|Other clients' })
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
        $crSorted = @($crAll | Sort-Object CreatedDateTime)
        for ($i = 1; $i -lt $crSorted.Count; $i++) {
            $prev = $crSorted[$i - 1]
            $curr = $crSorted[$i]
            $prevCountry = if ($prev.Location) { $prev.Location.CountryOrRegion } else { $null }
            $currCountry = if ($curr.Location) { $curr.Location.CountryOrRegion } else { $null }
            if ($prevCountry -and $currCountry -and $prevCountry -ne $currCountry) {
                $gapMin = ([datetime]$curr.CreatedDateTime - [datetime]$prev.CreatedDateTime).TotalMinutes
                if ($gapMin -lt 240) {
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

        # Build anomaly HTML
        $anomalyContent = if ($anomalies.Count -eq 0) {
            "<div class='muted' style='padding:4px 0;'>No sign-in anomalies detected.</div>"
        } else {
            $rows = ($anomalies | ForEach-Object {
                "<tr><td>$(Sev-Badge $_.Severity)</td><td>$(HtmlEncode $_.Anomaly)</td><td>$($_.Detail)</td><td>$($_.Count)</td></tr>"
            }) -join "`n"
            "<table><tr><th>Severity</th><th>Anomaly</th><th>Detail</th><th>Count</th></tr>`n$rows</table>"
        }

        "$statBlock$anomalyContent"
    }
```

- [ ] **Step 2: Verify the script parses cleanly**

```powershell
# Run from PowerShell on Windows — should return no errors
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    'C:\github\diagnose-account-compromise\Diagnose-AccountCompromise.ps1',
    [ref]$null, [ref]$errors
)
$errors
```
Expected: empty output (no parse errors).

- [ ] **Step 3: Commit**

```bash
cd /mnt/c/github/diagnose-account-compromise
git add Diagnose-AccountCompromise.ps1
git commit -m "feat: replace profile summary with stat block + anomaly table

Credential-relevant filter (successful or MFA-blocked) applied to all
anomaly detectors: new country, MFA-blocked attempts, risk events,
legacy auth, impossible travel."
```

---

### Task 3: Replace the HTML card in the here-string

**Files:**
- Modify: `Diagnose-AccountCompromise.ps1` — the `return @"..."@` here-string (the HTML card referencing `$profileRows`)

- [ ] **Step 1: Replace the old card with the new one**

Find:
```powershell
  <div class="card">
    <h2>Sign-In Profile Summary (30 days)</h2>
    <div class="muted" style="margin-bottom:6px;">One row per unique country / app / device combination across the full 30-day window. Suspicious profiles are highlighted. &ldquo;New country&rdquo; means no sign-ins from that country in the baseline period prior to the lookback window.</div>
    <table><tr><th>Country</th><th>App</th><th>Device / OS</th><th>Sign-ins</th><th>IPs</th><th>Last Seen</th><th>Result</th><th>Flags</th></tr>
    $profileRows
    </table>
  </div>
```

Replace with:
```powershell
  <div class="card">
    <h2>Sign-In Summary (last ${DaysBack} days)</h2>
    <div class="muted" style="margin-bottom:8px;">Stat block covers the lookback window. Anomaly detection uses the full 30-day window and considers only credential-relevant sign-ins: successful or MFA-blocked (valid credentials). &ldquo;New country&rdquo; means no credential-relevant activity from that country in the prior baseline period.</div>
    $signInSummaryContent
  </div>
```

- [ ] **Step 2: Verify the script parses cleanly**

```powershell
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    'C:\github\diagnose-account-compromise\Diagnose-AccountCompromise.ps1',
    [ref]$null, [ref]$errors
)
$errors
```
Expected: empty output.

- [ ] **Step 3: Run the script and open the report**

```powershell
cd C:\github\diagnose-account-compromise
.\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com -SkipUpdateCheck
```

Open the generated HTML and verify:
- The "Sign-In Profile Summary" card is gone.
- A "Sign-In Summary" card appears between IOC Summary and User Profile.
- Five KPI tiles render correctly in a flex row.
- Tiles with zero values for MFA blocks, risk events, and legacy auth display in neutral styling.
- The anomaly table shows "No sign-in anomalies detected." for a clean account, or populated rows for a flagged account.
- The existing Sign-In Activity table (per-sign-in rows) is unchanged further down the page.

- [ ] **Step 4: Commit**

```bash
cd /mnt/c/github/diagnose-account-compromise
git add Diagnose-AccountCompromise.ps1
git commit -m "feat: wire sign-in summary card into HTML report

Replaces Sign-In Profile Summary card. Stat block shows window-level
KPIs; anomaly table shows credential-relevant anomalies over 30 days."
```
