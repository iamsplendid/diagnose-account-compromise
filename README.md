# Diagnose-AccountCompromise

Read-only PowerShell investigation tool for potentially compromised Office 365 accounts. Collects indicators of compromise from Entra sign-in logs, Identity Protection, Exchange Online mailbox configuration, inbox rules, mailbox audit logs, and MFA auth methods. Outputs a self-contained HTML triage report.

## Prerequisites

- ExchangeOnlineManagement module
- Microsoft.Graph module

## Usage

Connect first, then run:

    Connect-ExchangeOnline
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "UserAuthenticationMethod.Read.All", "IdentityRiskyUser.Read.All"

    .\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com
    .\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com -DaysBack 14
    .\Diagnose-AccountCompromise.ps1 -UserPrincipalName user@contoso.com -OutputHtml C:\temp\report.html

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-UserPrincipalName` | (required) | UPN of the account to investigate |
| `-DaysBack` | 7 | Lookback window in days for all time-based queries |
| `-OutputHtml` | `.\AccountCompromise-<UPN>-<date>.html` | Output path for HTML report |
| `-SkipUpdateCheck` | (switch) | Skip the GitHub auto-update check |

## What It Checks

- Entra sign-in logs (new countries, risk levels)
- Identity Protection risky user state
- MFA/auth methods (newly registered methods)
- Mailbox forwarding (SMTP forwarding, internal forwarding, DeliverToMailboxAndForward)
- Inbox rules (forwarding, redirect, delete, mark-as-read)
- Mailbox audit log (HardDelete, SendAs, UpdateFolderPermissions by delegate/admin)
- Transport rules matching this sender
