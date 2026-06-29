# Sign-In Log Pagination Design

**Date:** 2026-06-28  
**Status:** Approved

## Problem

`Get-SignInActivity` uses `Get-MgAuditLogSignIn -All`, which auto-paginates with no record or time limit. For high-volume accounts (e.g., compromised accounts used to send mass email), a single Graph API page request can exceed the SDK's default `HttpClient.Timeout` of 300 seconds, causing a hard failure with no sign-in data in the report.

## Goal

Ensure the script always returns useful sign-in data for triage, even for accounts with tens of thousands of sign-in records. Completeness is secondary to speed — responders need to see recent sign-ins (typically last 24 hours) to identify active threat actors.

## Design

### `Get-SignInActivity` — Two scoped queries replacing one unbounded query

Replace the single 30-day `-All` query with two date-scoped, manually-paged queries:

**Window query**
- Filter: `createdDateTime ge [DaysBack days ago]`
- Order: `createdDateTime desc` (newest first)
- Page size: 999 records per page
- Cap: stop after **2,000 records**
- Purpose: primary triage data — recent sign-ins, IPs, countries, risk events

**Baseline query**
- Filter: `createdDateTime ge [30 days ago] and createdDateTime lt [DaysBack days ago]`
- Order: `createdDateTime desc`
- Page size: 999 records per page
- Cap: stop after **500 records**
- Purpose: country baseline for new-country anomaly detection only; a sample is sufficient

Both queries use a manual paging loop (not `-All`) that breaks as soon as the cap is reached.

### Return object additions

Two new boolean fields on the return object:

```
WindowTruncated   = $true if window query hit the 2,000-record cap
BaselineTruncated = $true if baseline query hit the 500-record cap
```

The existing `All`, `InWindow`, and `Baseline` fields retain their current shape. `All` becomes the union of the two query results.

### Report changes — `ConvertTo-HtmlReport`

**When `WindowTruncated` is true:**
- The **Total** KPI tile displays `2,000+` instead of `2,000`
- An amber warning banner appears above the anomaly table:  
  `"Sign-in data capped at 2,000 records (most recent first). Older sign-ins in this window were not loaded."`

**When `BaselineTruncated` is true:**
- An inline note appears in the anomaly table near the new-country row:  
  `"Baseline sample capped at 500 records — new-country detection may be incomplete."`

**On collector failure** (e.g., even the first page times out): the existing `Ok = $false` error path handles it unchanged.

### Implementation assumption

The Graph sign-in logs API supports `$orderby=createdDateTime desc`. If the `Get-MgAuditLogSignIn` cmdlet does not expose an `-OrderBy` parameter, results will be sorted client-side after each page is fetched — but only within the capped record set, meaning the 2,000-record cap may not represent the 2,000 most recent records. The implementation step should verify this and document whichever path is taken.

### No changes needed

- `Invoke-IocAnalysis` — operates on `InWindow` and `Baseline`, unchanged
- All other collectors — unaffected
- Script parameters — unaffected
