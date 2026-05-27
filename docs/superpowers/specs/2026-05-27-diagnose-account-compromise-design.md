# Design: Diagnose-AccountCompromise.ps1

**Date:** 2026-05-27
**Repo:** diagnose-account-compromise
**Script:** Diagnose-AccountCompromise.ps1

## Overview

A read-only PowerShell investigation tool that collects indicators of compromise for a single Office 365 user account and renders a self-contained HTML report. Targets security responders investigating a potentially compromised mailbox.

The script never modifies any configuration or state.

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-UserPrincipalName` | string | (required) | The UPN of the account to investigate |
| `-DaysBack` | int | 7 | Lookback window for all time-based queries |
| `-OutputHtml` | string | `.\AccountCompromise-<UPN>-<yyyyMMdd>.html` | Output path for the HTML report |
| `-SkipUpdateCheck` | switch | false | Skip the GitHub auto-update check at startup |

---

## Prerequisites

The caller must establish both sessions before running the script:

```powershell
Connect-ExchangeOnline
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All"
```

The script validates both sessions at startup and exits with a clear, actionable error message if either is missing.

---

## Architecture: Collect → Analyze → Render

The script is structured in three distinct phases to keep data collection, scoring logic, and presentation cleanly separated.

### Phase 1 — Collect

Eight collector functions, each returning a raw object or array. All errors are caught per-collector; a failed collector produces a structured error result rather than aborting the script.

| Function | Source | Data pulled |
|---|---|---|
| `Get-UserProfile` | Graph `/users/{upn}` | DisplayName, UPN, AccountEnabled, CreatedDateTime, LastPasswordChangeDateTime, OnPremisesSyncEnabled |
| `Get-SignInActivity` | Graph `/auditLogs/signIns` | All sign-ins in window: timestamp, IP, location, app, CA result, risk level, risk detail |
| `Get-RiskyUserStatus` | Graph `/identityProtection/riskyUsers` | Current risk state, risk detail, risk last updated |
| `Get-AuthMethods` | Graph `/users/{upn}/authentication/methods` | All registered auth methods with type and registration timestamp |
| `Get-MailboxConfig` | EXO `Get-Mailbox` | ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward, HiddenFromAddressListsEnabled, AuditEnabled |
| `Get-InboxRules` | EXO `Get-InboxRule` | All rules: name, enabled state, conditions, actions (ForwardTo, RedirectTo, DeleteMessage, MarkAsRead, MoveToFolder) |
| `Get-MailboxAuditEvents` | EXO `Search-MailboxAuditLog` | Operations in window for admin/delegate/owner: SendAs, SendOnBehalf, HardDelete, MoveToDeletedItems, UpdateFolderPermissions |
| `Get-TransportRuleMatches` | EXO `Get-TransportRule` | Tenant transport rules whose From/SenderDomain conditions include this user or their domain |

### Phase 2 — Analyze

`Invoke-IocAnalysis` consumes all collector output and returns a flat `[PSCustomObject[]]` of findings. Each finding:

```powershell
[PSCustomObject]@{
    Severity = 'High' | 'Medium' | 'Low' | 'Info'
    Category = 'SignIn' | 'Forwarding' | 'InboxRule' | 'AuditLog' | 'AuthMethod' | 'TransportRule' | 'Identity'
    Finding  = <short headline string>
    Detail   = <one or two sentences with specifics>
}
```

Scoring rules:

| Condition | Severity |
|---|---|
| `ForwardingSmtpAddress` set (external) | High |
| Inbox rule forwards or redirects to external address | High |
| Risky user state is `atRisk` or `confirmedCompromised` | High |
| Sign-in with High or Medium risk level | High |
| MFA auth method registered within the lookback window | High |
| Inbox rule deletes or marks-as-read without forwarding | Medium |
| Sign-in from a country not seen in prior sign-in history | Medium |
| Audit log shows HardDelete or MoveToDeletedItems by delegate or admin | Medium |
| Transport rule affects this sender with redirect or BCC | Medium |
| `ForwardingAddress` set to internal mailbox | Low |
| `DeliverToMailboxAndForward` is true (copies externally) | Low |
| Account is currently disabled | Info |
| `AuditEnabled` is false on mailbox | Info |

Findings are sorted: High → Medium → Low → Info.

### Phase 3 — Render

`ConvertTo-HtmlReport` takes the scored findings and all raw collector data and produces a self-contained HTML file. Uses the same card/badge CSS pattern as existing scripts in this family.

---

## HTML Report Structure

1. **Header** — DisplayName, UPN, report generated timestamp, lookback window, script version
2. **IOC Summary card** — Findings table (Severity badge | Category | Finding | Detail). Triage view.
3. **Sign-In Activity card** — All sign-ins in window. Columns: timestamp, IP, city/country, app, CA result, risk level. Rows with High/Medium risk highlighted.
4. **Identity Protection card** — Risky user state, risk detail, risk last updated.
5. **Mailbox Configuration card** — Forwarding addresses, DeliverToMailboxAndForward, HiddenFromAddressList, AuditEnabled.
6. **Inbox Rules card** — All rules with enabled state, conditions, and actions. Suspicious rules highlighted.
7. **Auth Methods card** — All registered auth methods with type and registration date.
8. **Mailbox Audit Log card** — Operations table: Operation | Performed by | Folder/Object | Timestamp.
9. **Transport Rules card** — Matching tenant transport rules with their conditions and actions.

The output file is written with UTF-8 encoding. On Windows, `Invoke-Item` opens it in the default browser automatically.

---

## Error Handling

- Session validation failures → fatal, exit with message listing missing connections
- Per-collector failures → non-fatal; the card for that collector renders an error notice instead of data
- Graph pagination handled transparently for sign-in logs (OData `@odata.nextLink`)
- `Search-MailboxAuditLog` limited to 250,000 results; warning emitted if result count is at the limit

---

## Auto-Update

Same pattern as Diagnose-Mailbox.ps1: compares `$ScriptVersion` to the raw GitHub URL, downloads and re-executes if a newer version is available. Skippable via `-SkipUpdateCheck`.

---

## Out of Scope

- Unified Audit Log (`Search-UnifiedAuditLog`) — too slow for a real-time investigation tool; a separate script can handle broader UAL searches
- Remediation actions — this script is strictly read-only
- Multi-user bulk mode — single account per run; loop outside the script if needed
