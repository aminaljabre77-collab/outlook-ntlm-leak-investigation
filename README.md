# CVE-2026-124194: Detecting the Outlook NTLM Hash Leak

Research into how the Outlook zero-day **CVE-2026-124194** leaks NTLM credentials, how a SOC can detect it in logs, and what stops it. The detections are tested on a simulated attack scenario.

## Research questions

1. How does the attack work, step by step?
2. What does it leave in the logs (email, Windows, firewall)?
3. Which searches can detect it, and how early?
4. What weaknesses make it successful, and how can they be fixed?

## 1. Background

| | |
|---|---|
| **Vulnerability** | CVE-2026-124194, Microsoft Outlook |
| **Impact** | Leak of the user's NTLMv2 hash to an attacker-controlled server |
| **Patched** | 10 Nov 2026 (November Patch Tuesday) |
| **Exploited in the wild** | Yes. Added to the CISA Known Exploited Vulnerabilities catalog on 10 Nov 2026 |
| **Trigger** | The victim opens a crafted Outlook message file. The Preview Pane alone is not an attack vector |

When the crafted message is opened, Outlook connects to an attacker-controlled network location over SMB (TCP 445) without the usual external-content warning. Windows then sends the user's NTLMv2 authentication data to that server.

## 2. How the attack works

```
Phishing email with crafted .msg attached
        │
        ▼
User opens the .msg in Outlook
        │
        ▼
outlook.exe connects to the attacker's SMB server (TCP 445)
        │
        ▼
Windows sends the user's NTLMv2 hash
        │
        ▼
Attacker cracks the hash offline (weak password) or relays it
        │
        ▼
Attacker logs in as the user (e.g. to the mail server)
```

**MITRE ATT&CK:** T1566.001 Spearphishing Attachment · T1187 Forced Authentication · T1110.002 Password Cracking · T1078 Valid Accounts

## 3. Detection opportunities

Each stage of the attack leaves a trace. These are the signals a SOC can alert on:

| Stage | Signal | Log source | Event |
|---|---|---|---|
| Delivery | Email from a newly registered or look-alike domain, SPF fail/softfail, `.msg` attachment | Email gateway | – |
| Execution | User opens the `.msg` file in Outlook | Windows / EDR | 4688 |
| Hash leak | **`outlook.exe` making an SMB connection to a public IP** | Windows Filtering Platform, firewall | 5156 |
| Credential use | NTLM logon for the user from an unknown workstation or external IP | Domain controller, target server | 4776, 4624 (type 3) |

The strongest signal is the **hash leak**: `outlook.exe` should never talk SMB to the internet. A search for this catches the attack **before** the attacker uses the credentials.

```
index=windows EventCode=5156 process="outlook.exe" dest_port=445 NOT dest_ip=10.*
| table _time host user dest_ip dest_port result
```

All searches are in [`queries.spl`](queries.spl).

## 4. Testing the detections: simulated case

To test the searches, I built a simulated scenario for a fictional company (Nordwell) with email, Windows and firewall logs ([`logs/`](logs)), then investigated it as an L1 SOC analyst would.

### Timeline (9 Nov 2026, CET)

| Time | Event | Source |
|---|---|---|
| 07:10 | Email "Q4 invoice - please review" from `invoices@supp1ier-portal.com` delivered to 6 users, SPF softfail | email logs |
| 07:22:00 | `marie.pokorna` opens `Q4_Invoice_Nov.msg` on WS-12 in Outlook | Windows 4688 |
| 07:22:05 | `outlook.exe` on WS-12 (10.0.4.32) connects to `198.51.100.23:445`. The firewall **allowed** it, so the hash leaked | Windows 5156, firewall |
| 07:31:00 | NTLM authentication for `marie.pokorna` from workstation `WIN-ATTK01` | Windows 4776 (DC01) |
| 07:31:03 | Successful network logon (type 3, NTLM) to **MAIL01** as `marie.pokorna` from `198.51.100.23` | Windows 4624 |

The attacker used the credentials **9 minutes** after the file was opened. An alert on the hash-leak signal (07:22:05) would have given the SOC that time to block the IP and reset the password.

### Investigation steps

**Who received the email?**
```
index=email sender="invoices@supp1ier-portal.com"
| table _time sender recipient subject attachment spf
```
6 recipients. The domain uses the number `1` instead of the letter `l` ("supp1ier"), and SPF is softfail.

**Who opened it?**
```
index=windows EventCode=4688 command_line="*Q4_Invoice*"
| table _time host user parent_process process command_line
```
Only `marie.pokorna` on WS-12.

**Did the computer connect out over SMB?**
```
index=windows host=WS-12 EventCode=5156 dest_port=445
| table _time process src_ip dest_ip dest_port result
```
`outlook.exe` connected to the public IP `198.51.100.23` on port 445, and the firewall log confirms it was allowed.

**Were the credentials used?**
```
index=windows user=marie.pokorna (EventCode=4624 OR EventCode=4776) auth_package=NTLM
| table _time host EventCode src_ip workstation logon_type auth_package result
```
Yes. A successful NTLM logon to MAIL01 from the attacker's IP and workstation `WIN-ATTK01`, not from her own PC.

### Indicators of compromise (simulated)

| Indicator | Type | Note |
|---|---|---|
| `198.51.100.23` | IP | Attacker SMB server |
| `supp1ier-portal.com` | Domain | Look-alike, registered 2 days before the email |
| `invoices@supp1ier-portal.com` | Sender | Phishing sender |
| `Q4_Invoice_Nov.msg` | File | Crafted message file |
| `WIN-ATTK01` | Hostname | Attacker workstation |

### Response

- Purged all 6 emails from user mailboxes
- Blocked `198.51.100.23` and `supp1ier-portal.com`
- Reset the user's password
- Escalated to L2 to review what was accessed on MAIL01

## 5. Findings: why the attack worked

1. **Outbound SMB (TCP 445) to the internet was allowed.** This let the hash leave the network.
2. **The mail server accepted NTLM logons from an external IP.** This let the attacker log in with the stolen credentials.
3. **No MFA** on mail access, and a password weak enough to crack quickly.
4. **The email gateway delivered mail with SPF softfail** from a 2-day-old domain.
5. **Outlook was unpatched.** The fix came one day after the attack (zero-day).

## 6. Recommendations

- Block outbound TCP 445 to the internet
- Install the CVE-2026-124194 Outlook update
- Restrict NTLM and use Kerberos where possible; do not accept NTLM from outside the network
- Enable SMB signing and Extended Protection for Authentication against NTLM relay
- Enforce strong passwords and MFA on email and remote access
- Quarantine email from newly registered domains and with SPF fail/softfail
- Alert on `outlook.exe` (and other Office processes) making SMB connections to public IPs

## 7. Limitations

- The logs are simulated, not captured from a real exploit. They model the behaviour described in public reporting.
- All names, domains and internal IPs are fictional. `198.51.100.0/24` is a documentation IP range.
- The searches are written in Splunk SPL. Field names will differ in other SIEMs.

## References

- [SOC Prime: CVE-2026-124194 Microsoft Outlook Zero-Day Exploited to Steal NTLM Hashes](https://socprime.com/?p=57962)
- [Outlook CVE-2026-124194 in CISA KEV: Fixed Office Builds](https://braindetox.kr/en/posts/microsoft_office_cve_2026_124194_kev.html)
- [Microsoft fixes exploited Outlook zero-day CVE-2026-124194](https://magica.com/news/microsoft-patches-exploited-outlook-credential-theft-zero-day)
- [MITRE ATT&CK T1187: Forced Authentication](https://attack.mitre.org/techniques/T1187/)
