# Outlook NTLM Hash Leak Investigation (CVE-2026-124194)

A SOC L1 investigation of a phishing attack that used the Outlook zero-day **CVE-2026-124194** to leak a user's NTLM hash, which the attacker then used to log in to the mail server.

The company (Nordwell), users and logs are **simulated**. The investigation steps, searches and response are the same ones a SOC analyst would use in a real case.

## Summary

| | |
|---|---|
| **Alert** | SOC-311: Outlook NTLM hash leak |
| **Date** | 9 Nov 2026 |
| **Verdict** | True Positive |
| **Severity** | High |
| **Escalated to L2** | Yes |
| **MITRE ATT&CK** | T1566.001 Spearphishing Attachment · T1187 Forced Authentication · T1550.002 Pass the Hash |

On 9 Nov 2026 a phishing email with a malicious Word file was sent to 6 users. One user opened it. Outlook sent her NTLM hash to an attacker's SMB server on the internet, and 9 minutes later the attacker used that hash to log in to the mail server as her.

## Attack timeline (CET)

| Time | Event | Source |
|---|---|---|
| 07:10 | Email "Q4 invoice - please review" from `invoices@supp1ier-portal.com` delivered to 6 users, SPF softfail | email logs |
| 07:22:00 | `marie.pokorna` opens `Q4_Invoice_Nov.docx` on WS-12 (`outlook.exe` → `winword.exe`) | Windows 4688 |
| 07:22:05 | `outlook.exe` on WS-12 (10.0.4.32) connects to `198.51.100.23:445` (SMB). The firewall **allowed** it, so the NTLM hash leaked | Windows 5156, firewall |
| 07:31:00 | NTLM authentication for `marie.pokorna` from workstation `WIN-ATTK01` | Windows 4776 (DC01) |
| 07:31:03 | Successful network logon (type 3, NTLM) to **MAIL01** as `marie.pokorna` from `198.51.100.23` / `WIN-ATTK01` | Windows 4624 |

## Investigation

Searches are in [`queries.spl`](queries.spl). The logs are in [`logs/`](logs).

**1. Who received the email?**
```
index=email sender="invoices@supp1ier-portal.com"
| table _time sender recipient subject attachment spf
```
6 recipients. The sender domain uses the number `1` instead of the letter `l` ("supp1ier"), and SPF is softfail.

**2. Who opened the attachment?**
```
index=windows EventCode=4688 command_line="*Q4_Invoice*"
| table _time host user parent_process process command_line
```
Only `marie.pokorna` on WS-12. Word was started by Outlook, so she opened it from the email.

**3. Did the computer connect anywhere strange after that?**
```
index=windows host=WS-12 EventCode=5156 dest_port=445
| table _time process src_ip dest_ip dest_port result
```
`outlook.exe` connected to the public IP `198.51.100.23` on port 445. SMB should never leave the company network. The firewall log confirms the connection was allowed.

**4. Was the stolen hash used?**
```
index=windows user=marie.pokorna (EventCode=4624 OR EventCode=4776) auth_package=NTLM
| table _time host EventCode src_ip workstation logon_type auth_package result
```
Yes. A successful NTLM logon to MAIL01 from the attacker's IP and workstation `WIN-ATTK01`, not from her own PC (WS-12).

## Threat intelligence

| Indicator | Type | Finding |
|---|---|---|
| `198.51.100.23` | IP | Malicious. Rogue SMB server that captures NTLM hashes |
| `supp1ier-portal.com` | Domain | Registered 2 days before the email, look-alike (typosquatting) |
| `invoices@supp1ier-portal.com` | Sender | Phishing sender |
| `9f2c7e41b8a35d0c6e1f4a27b9d83c5e0a6f1b2c3d4e5f60718293a4b5c6d7e8` | SHA256 | `Q4_Invoice_Nov.docx`, low detection (new exploit). Low detection does not mean safe |
| `WIN-ATTK01` | Hostname | Attacker workstation, not a company asset |

## Response actions

- Purged all 6 phishing emails from user mailboxes
- Blocked `198.51.100.23` and `supp1ier-portal.com` on the firewall, proxy and EDR
- Reset the password of `marie.pokorna`
- Escalated to L2 to check what the attacker accessed on MAIL01

## Root cause and weaknesses

1. **Outbound SMB (port 445) to the internet was allowed.** This is what let the hash leave the network.
2. **MAIL01 accepted NTLM logons from an external IP.** This is what let the stolen hash work.
3. **No MFA** on mail access.
4. **The email gateway delivered mail with SPF softfail** from a domain registered 2 days earlier.
5. **Outlook was unpatched.** The fix was released on 10 Nov, one day after the attack (zero-day).

## Recommendations

- Block outbound TCP 445 to the internet on the firewall
- Install the CVE-2026-124194 Outlook update on all machines
- Restrict NTLM and use Kerberos where possible; do not accept NTLM from outside the network
- Enforce MFA on email and remote access
- Quarantine email from newly registered domains and with SPF fail/softfail
- L2: review Marie's mailbox on MAIL01 (forwarding rules, sent items, downloads)
- Confirm the other 5 recipients did not open the attachment
- Phishing awareness reminder for the Finance team

## Ticket

```
SOC-311 | Outlook NTLM hash leak (CVE-2026-124194)
Verdict: True Positive | Severity: High | Escalated to L2

Phishing email from invoices@supp1ier-portal.com (SPF softfail) delivered
to 6 users. marie.pokorna opened Q4_Invoice_Nov.docx on WS-12 at 07:22.
outlook.exe connected to 198.51.100.23:445 (allowed by firewall) and leaked
her NTLM hash. At 07:31 the attacker used it to log in to MAIL01 (4624,
type 3, NTLM) from WIN-ATTK01.
Actions: emails purged, IP and domain blocked, password reset.
L2: check MAIL01 for mailbox access and forwarding rules.
```

## Repository

```
README.md        this report
queries.spl      all searches used
logs/
  email_logs.csv
  windows_logs.csv
  firewall_logs.csv
```
