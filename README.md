# Windows Security Event ID cheat sheet

The Windows event IDs that matter for security - what each one means, where it is logged, and what to watch for. Every ID links to a full guide with the fields, PowerShell to read it (field names, so it works on any Windows language) and what to do.

> Free, public knowledge from Microsoft's documentation. Maintained by [Coinetic AI Security](https://coinetic.io). For a quick hardening check of a Windows Server, see [windows-hardening-tools](https://github.com/Coinetic-AI-Security/windows-hardening-tools).

## Contents

- [Logon and logoff](#logon-and-logoff)
- [Accounts and groups](#accounts-and-groups)
- [Kerberos and NTLM (domain controllers)](#kerberos-and-ntlm-domain-controllers)
- [Processes, services and scheduled tasks](#processes-services-and-scheduled-tasks)
- [Audit policy and logs](#audit-policy-and-logs)
- [Firewall and file shares](#firewall-and-file-shares)

## Logon and logoff

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [4624](https://coinetic.io/event-id-4624) | Security | An account was successfully logged on | Type 10 or 3 from an internet address, logons at unusual times, a new account, or a success right after many failures from the same address. |
| [4625](https://coinetic.io/event-id-4625) | Security | An account failed to log on | Many failures from one address (password guessing on RDP / SMB); status 0xC000006A = wrong password, 0xC0000064 = unknown user; logon type 10 = Remote Desktop. |
| [4634 / 4647](https://coinetic.io/event-id-4634-4647) | Security | An account was logged off | A long Remote Desktop session at night from an unknown address; match logon and logoff by the Logon ID to get the session length. |
| [4648](https://coinetic.io/event-id-4648) | Security | A logon was attempted using explicit credentials | Admin credentials used from a normal PC, many different target Servers in a short time, or tools such as PsExec. |
| [4672](https://coinetic.io/event-id-4672) | Security | Special privileges assigned to new logon | Real user accounts with admin rights, especially from a new place or at an unusual time. |

## Accounts and groups

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [4720](https://coinetic.io/event-id-4720) | Security | A user account was created | Created at night, by an unexpected account or by SYSTEM, an inconspicuous name (support, admin2, defaultuser), and added to Administrators within minutes. |
| [4722-4726](https://coinetic.io/event-id-4722-4726) | Security | Account enabled, password changed or reset, disabled, deleted | A reset (4724) of an admin account by someone else, a disabled account enabled again (4722), deletions right after an incident. |
| [4732](https://coinetic.io/event-id-4732) | Security | A member was added to a security-enabled local group | Anyone added to Administrators (S-1-5-32-544) or Remote Desktop Users (S-1-5-32-555) you did not expect - check by SID, names differ by language. |
| [4740](https://coinetic.io/event-id-4740-4771) | Security | A user account was locked out | Caller Computer Name = the device with the old password or the attacker; repeated lockouts of admin accounts. |

## Kerberos and NTLM (domain controllers)

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [4768 / 4769](https://coinetic.io/event-id-4768-4769) | Security | Kerberos ticket requests | Failures 0x6 / 0x12 in bulk; Kerberoasting: many 4769 with encryption type 0x17 (RC4) for different service accounts from one user. |
| [4771](https://coinetic.io/event-id-4740-4771) | Security | Kerberos pre-authentication failed | Failure code 0x18 = wrong password (domain controller); many from one address = password spraying. |
| [4776](https://coinetic.io/event-id-4776) | Security | The computer attempted to validate the credentials for an account | Many 0xC000006A (wrong password) for one account, or many 0xC0000064 (unknown user) from one workstation; NTLM where Kerberos should be used. |

## Processes, services and scheduled tasks

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [4688](https://coinetic.io/event-id-4688) | Security | A new process has been created | Office or a browser starting cmd.exe / powershell.exe, -enc (encoded) commands, programs from Temp or Downloads, vssadmin delete shadows. |
| [4698](https://coinetic.io/event-id-4698) | Security | A scheduled task was created | A task running powershell, cmd or a program from a user or Temp folder, as SYSTEM, at startup or every few minutes, with an odd or Microsoft-like name. |
| [7045](https://coinetic.io/event-id-7045) | System | A service was installed in the system | PSEXESVC or random names, program paths in Temp, user or ProgramData folders, cmd /c or powershell in the path. |

## Audit policy and logs

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [4719](https://coinetic.io/event-id-4719) | Security | System audit policy was changed | Success or Failure removed for Logon, Process Creation, Account Management, Audit Policy Change - by a user account, outside a planned change. |
| [1102](https://coinetic.io/event-id-1102) | Security | The audit log was cleared | Any clearing you cannot explain - often right before or after an attack; check the logons of the account in the event. |
| [4673](https://coinetic.io/event-id-4673) | Security | A privileged service was called | A flood of Audit Failure from chrome.exe / msedgewebview2.exe / Code.exe slows the Event Log service - untick Failure in "Audit privilege use". |

## Firewall and file shares

| ID | Log | Event | What to watch for |
|---|---|---|---|
| [5156](https://coinetic.io/event-id-5156) | Security | The Windows Filtering Platform has permitted a connection | Only switch on briefly: shows every allowed connection - which program talks to which address and port. |
| [5157](https://coinetic.io/event-id-5157) | Security | The Windows Filtering Platform has blocked a connection | One address trying many different ports (port scan); outbound blocks from a program you do not know. Many addresses on 1-2 ports each = normal background scanning. |
| [5140 / 5145](https://coinetic.io/event-id-5140-5145) | Security | A network share was accessed | ADMIN$ or C$ from a computer that is not an admin workstation; many shares from one address; access at night. |

## Read any event by field name (PowerShell)

Works on every Windows display language - fields are read by name, not from the translated message text:

```powershell
function Get-EventFields($e) { $d = [ordered]@{}; ([xml]$e.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }; [pscustomobject]$d }
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} | ForEach-Object { Get-EventFields $_ } |
  Group-Object IpAddress | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
```

## Several events are off by default

Process creation (4688), scheduled tasks (4698), file shares (5140) and the firewall events (5156/5157) need their audit subcategory switched on. Each guide shows the exact `auditpol` command (with the subcategory GUID, so it works on any language) and the Group Policy path.

## Contributing

Spotted an error or a missing event ID? [Open an issue](https://github.com/Coinetic-AI-Security/windows-security-event-ids/issues).

## Licence

Text: [CC BY 4.0](LICENSE) (c) 2026 Salus Alpha Group AG - share and adapt with a link back.
