# Sign-In Summary Redesign

**Date:** 2026-05-28
**Status:** Approved

## Problem

The current "Sign-In Profile Summary" groups sign-ins by country × app × device/OS, producing nearly as many rows as the raw sign-in list itself. It is too noisy to be useful as a summary for an investigator doing account compromise triage.

## Goal

Replace the table with a compact, anomaly-focused section that answers one question: **is anything suspicious about this account's sign-in pattern?**

Investigators are primarily interested in sign-ins that were successful, or would have been successful if not for MFA. Failed sign-ins due to wrong passwords are noise and are excluded from anomaly detection.

## Credential-Relevant Filter

All anomaly detectors and country/location analysis operate only on **credential-relevant** sign-ins — defined as:

- **Successful** — `Status.ErrorCode -eq 0`
- **MFA-blocked** — credentials were valid but MFA stopped the sign-in. Detected by matching `Status.ErrorCode` against known MFA error codes (`50074, 50076, 50079, 500121, 53004, 50158`) OR `Status.FailureReason` matching the pattern `MFA|strong auth|multi.factor|authentication strength`.

## Section Structure

The "Sign-In Profile Summary" card is replaced by a "Sign-In Summary" card containing two parts.

### Part 1 — Stat Block

Five KPI tiles displayed in a flex row:

| Tile | Value | Alert color |
|---|---|---|
| Total sign-ins | All sign-ins in the lookback window | None |
| Successful | Count where `ErrorCode = 0` | None |
| MFA blocks | Count of MFA-blocked sign-ins | Red if > 0 |
| Risk events | Count of high/medium-risk sign-ins | Red if > 0 |
| Legacy auth | Count of credential-relevant sign-ins via legacy protocol | Orange if > 0 |

Tiles with alert conditions display their value and label in the alert color. Clean tiles are rendered in neutral styling.

### Part 2 — Anomaly Table

Only rendered when at least one anomaly exists. If no anomalies are detected, a single muted line reads: "No sign-in anomalies detected."

**Columns:** Severity badge · Anomaly · Detail · Count

**Anomaly detectors** (all operate on credential-relevant sign-ins only):

1. **New country** — a country has credential-relevant activity in the lookback window but zero credential-relevant sign-ins in the baseline period (days DaysBack–30). Severity: High. Detail: country name + first-seen date. One row per new country.

2. **MFA-blocked credential attempt** — any MFA-blocked sign-ins exist, meaning an attacker had valid credentials. Severity: High. Detail: top country/IP of the blocked attempts. Count: total MFA-blocked sign-ins.

3. **Risk events** — Entra Identity Protection flagged sign-ins as high or medium risk. Severity: High for `high`, Medium for `medium`. Detail: distinct risk levels observed.

4. **Legacy auth** — credential-relevant sign-ins via SMTP, IMAP, POP, MAPI, ActiveSync, or `Other clients`. Severity: High (legacy auth bypasses MFA). Detail: protocol(s) used. Count: total legacy-auth credential-relevant sign-ins.

5. **Impossible travel** — two consecutive credential-relevant sign-ins from different countries where the time gap is under 4 hours. Severity: High. Detail: "Country A → Country B (Xh Ym apart)". One row per flagged pair.

## Implementation Notes

- The section is computed inside `ConvertTo-HtmlReport`, consistent with how all other rendered sections are built.
- The baseline country set for new-country detection already exists in the codebase (`$SignIn.Baseline`); the filter simply restricts which sign-ins from each set are considered.
- Impossible travel compares consecutive sign-ins after sorting `$SignIn.All` (credential-relevant subset) by `CreatedDateTime`. It does not require geolocation beyond the `Location.CountryOrRegion` field already present on the sign-in object.
- The 4-hour impossible travel threshold is a hardcoded constant. It is intentionally conservative — same-continent moves within 4 hours are possible but rare enough to warrant a flag.
- The existing detailed sign-in activity table (one row per sign-in) is unchanged.
