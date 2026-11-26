---
type: daily
week: 1
day: 4
date: 2026-11-26
topic: NIST 800-61 incident handling and the Cyber Kill Chain
mitre: [T1566.002, T1204.002, T1071.001, T1053.003, T1564.001, T1078]
tags: [soc, daily]
status: todo
---

# W1D4: NIST 800-61 and the Cyber Kill Chain

> [!info] Tonight's plan (8:00–10:00 PM Dubai)
> Week 1 theme: [[SOC Fundamentals]], [[Alert Lifecycle]], [[NIST 800-61]], [[Cyber Kill Chain]].
> The D2 and D3 notes never reached your Inbox, so tonight covers both of their topics in one lesson: **NIST 800-61** (how *defenders* handle an incident) and the **Cyber Kill Chain** (how *attackers* run one). They work best side by side anyway. Tomorrow (D5) adds the [[Pyramid of Pain]] and [[MITRE ATT&CK]] as the bridge to Week 9. Saturday is a mini-incident and Sunday is review plus a mock interview.
>
> Your W1D1 note is still `status: todo`. If you didn't finish it, do its log drill before Saturday. It is the foundation for everything below.

---

## 1. Recall (0–10 min)

All five come from W1D1. Answer out loud first, then open each one.

**Q1.** Name the four possible verdicts for an alert, and which one you can only find by hunting.
> [!question]- Answer
> True Positive, False Positive, Benign True Positive, and False Negative. A false negative is an attack that never alerted, so you only find it by [[Threat Hunting]] or after the damage is done.

**Q2.** In a 4625 event, what is the difference between status `0xC0000064` and `0xC000006A`, and why does it matter during a brute-force?
> [!question]- Answer
> `0xC0000064` = the username doesn't exist. `0xC000006A` = the username exists and the password was wrong. When the failures switch from `...64` to `...6A`, the attacker has found a **real account** and is now guessing its password. Raise priority.

**Q3.** How do you set an alert's priority at triage? Give an example of one alert type rated High on one host and Low on another.
> [!question]- Answer
> Priority = **severity × asset/identity criticality**. The same "3 failed logons" alert is High on a domain admin account on a DC and Low on a guest account on a lobby kiosk.

**Q4.** In the W1D1 drill, `SRV-FILE01` accepted RDP from `185.220.101.47`. Name the **two** problems this revealed.
> [!question]- Answer
> (1) A successful brute-force of the admin-level account `j.thomas` (T1110.001 → T1078 → T1021.001). (2) A misconfiguration: RDP should only have been reachable from the VPN range `10.20.0.0/16`, so a firewall/NSG rule exposed it to the internet.

**Q5.** In the Target breach, which stage of the alert lifecycle failed?
> [!question]- Answer
> **Triage/escalation.** The malware detection tool fired and the outsourced team flagged it, but nobody acted on it. Detection worked and the process around it failed.

---

## 2. Learn (10–30 min)

### Two lenses on the same incident
- **[[Cyber Kill Chain]]** (Lockheed Martin, 2011) is the **attacker's** to-do list. It describes the steps an intrusion has to go through.
- **[[NIST 800-61]]** is the **defender's** playbook. It describes how you handle an incident once you spot one.

A useful way to put it in an interview: *"The Kill Chain tells me where the attacker is. NIST tells me what to do about it."*

### The Cyber Kill Chain: 7 stages
| # | Stage | What the attacker does | What an L1 might see |
|---|---|---|---|
| 1 | **Reconnaissance** | Researches targets: LinkedIn staff lists, exposed services, leaked passwords | Port scans in firewall logs, lots of 4625s with non-existent usernames |
| 2 | **Weaponization** | Builds the payload: malicious macro doc, ZIP with a script, exploit | Nothing. This happens on the attacker's side |
| 3 | **Delivery** | Sends it: phishing email, malicious link, USB, exposed RDP | Email gateway alert, proxy download from a newly registered domain |
| 4 | **Exploitation** | Gets code to run: user opens the file, or a vuln is exploited | EDR alert on `winword.exe → powershell.exe`, Sysmon Event ID 1 |
| 5 | **Installation** | Gets persistence: scheduled task, service, Run key, cron job | 4698 (scheduled task created), 7045 (new service), Sysmon 13 (registry) |
| 6 | **Command & Control (C2)** | Malware "phones home" for instructions | Regular, same-sized connections to one rare domain, a.k.a. [[Beaconing]] |
| 7 | **Actions on Objectives** | Steals data, encrypts files, moves laterally | Large uploads, mass file renames, logons to many hosts |

**Key idea: break the chain early.** Stopping an attack at Delivery (blocking the email) costs minutes. Stopping it at stage 7 (ransomware running) costs days and millions. Most L1 wins happen at stages 3–6.

**Known weakness** (interviewers like to ask): the model is built around malware and perimeter attacks. It doesn't handle insider threats, cloud and identity attacks, or lateral movement well. That's why SOCs now use [[MITRE ATT&CK]] for detail (tomorrow) and the [[Unified Kill Chain]] as a broader 18-phase version.

### NIST SP 800-61: the incident response lifecycle
Interviews almost always expect the **Rev. 2 four phases**:

```
 ┌──────────────┐   ┌──────────────────────┐   ┌─────────────────────────────┐   ┌────────────────────┐
 │ 1. Preparation│ ─►│ 2. Detection &        │ ─►│ 3. Containment, Eradication │ ─►│ 4. Post-Incident    │
 │               │   │    Analysis           │ ◄─│    & Recovery               │   │    Activity         │
 └──────────────┘   └──────────────────────┘   └─────────────────────────────┘   └────────────────────┘
        ▲                                                                                   │
        └──────────────────────────── lessons learned feed back in ─────────────────────────┘
```

1. **Preparation**: playbooks, logging turned on, EDR deployed, contact lists, a jump bag, staff training. *(IT support analogy: having the asset inventory, admin tools and escalation list ready before the outage.)*
2. **Detection & Analysis**: spot it, confirm it's real, scope it (which hosts and users), prioritise, notify. **This is where L1 spends most of its time.** Your whole alert lifecycle from Monday sits inside this phase.
3. **Containment, Eradication & Recovery**
   - *Containment*: stop it spreading. Isolate the host, disable the account, block the IP or domain. **Preserve evidence first** (memory, logs, copies of files).
   - *Eradication*: remove the cause. Delete the malware, remove persistence, patch the vulnerability, reset credentials.
   - *Recovery*: restore to normal and monitor closely for re-infection.
   - The arrow goes **back** to phase 2 because containment often turns up new evidence (another infected host), so you analyse again.
4. **Post-Incident Activity**: lessons-learned meeting within about two weeks. Root cause, what worked, what didn't, new detections and tuning. *(Same as ITIL **problem management** after an incident: fix the cause so the ticket doesn't come back.)*

> [!note] Rev. 3 (April 2025)
> NIST SP 800-61 **Rev. 3** replaced the four-phase cycle with a mapping onto the **NIST CSF 2.0** functions: *Govern, Identify, Protect* (preparation), *Detect, Respond, Recover* (the incident itself), with improvement running through all of them. If you're asked, give the Rev. 2 phases and then mention that Rev. 3 aligns IR to CSF 2.0. That shows you're current.

### Event vs alert vs incident
- **Event**: anything that happened (a logon, a file opened). Millions a day.
- **Alert**: an event (or group of events) a rule flagged as worth a look.
- **Incident**: a confirmed violation, or imminent threat of violation, of security policy. Only some alerts become incidents. **Declaring** one starts the NIST phase 3 machinery.

### Real-world example: Colonial Pipeline (May 2021)
Mapped on both lenses:

| Kill Chain | What happened |
|---|---|
| Recon / Delivery | Attackers logged into the company **VPN** with the password of a **legacy account with no MFA**. The password had appeared in a leak. ([[T1078]] Valid Accounts) |
| Installation / C2 | DarkSide ransomware affiliates set up inside the IT network |
| Actions on Objectives | About **100 GB of data stolen**, then IT systems encrypted |

| NIST phase | What happened |
|---|---|
| Detection & Analysis | An employee found the ransom note on 7 May 2021 |
| Containment | The company **proactively shut down the pipeline** (≈45% of the US East Coast's fuel) because it couldn't be sure the OT network was safe. Containment is a *business* decision, not just a technical one |
| Recovery | A ransom of about $4.4M was paid. The decryptor was slow, so backups were used too. The US DOJ later recovered about $2.3M of it |
| Post-Incident | Industry-wide push for MFA on remote access and new TSA pipeline security directives |

**Lesson for an L1:** one unused account with no MFA was the whole Delivery stage. An alert on a **dormant account suddenly logging in via VPN** could have broken the chain at stage 3.

---

## 3. Lab (30–60 min): run a harmless "kill chain" on your own PC, then respond with NIST

You'll play attacker for 10 minutes, then switch hats and handle it as an incident. **Only do this on your own Linux PC.** The "malware" only writes a line to a file and fetches `example.com`.

### Part A: Attacker hat (10 min)
```bash
# Weaponization + Delivery: drop a hidden script in /tmp
cat > /tmp/.sysupdate.sh <<'EOF'
#!/bin/bash
# LAB SIMULATION - harmless "beacon"
echo "$(date -Is) beacon" >> /tmp/.beacon.log
curl -s -o /dev/null -A "lab-beacon/1.0" https://example.com
EOF
chmod +x /tmp/.sysupdate.sh

# Installation (persistence): run it every minute via your user crontab
# (any cron jobs you already have are kept)
(crontab -l 2>/dev/null; echo "* * * * * /tmp/.sysupdate.sh # lab-sim") | crontab -
```
> If `crontab` isn't found: Ubuntu/Debian `sudo apt install cron`, Fedora `sudo dnf install cronie && sudo systemctl enable --now crond`. If you can't install, run `/tmp/.sysupdate.sh` by hand three times and skip the cron parts.

Now **wait 3 minutes**. Read the Colonial table again while you wait.

### Part B: Analyst hat: Detection & Analysis (10 min)
Pretend a user said "my PC is making odd connections" and you don't know what's there.
```bash
# Persistence check: scheduled jobs
crontab -l
ls -la /etc/cron.d/ /var/spool/cron/ 2>/dev/null

# Hidden files in temp folders (attackers love /tmp and dotfiles)
ls -la /tmp | grep ' \.'

# Cron execution evidence
sudo grep -i cron /var/log/syslog | tail -15        # Ubuntu/Debian
sudo journalctl -u cron  --since "15 min ago"       # Debian/Ubuntu (systemd)
sudo journalctl -u crond --since "15 min ago"       # Fedora/RHEL

# What did it do?
cat /tmp/.sysupdate.sh
cat /tmp/.beacon.log
```
**Expected evidence:**
```
cron[812]: (coffee) RELOAD (crontabs/coffee)
CRON[24517]: (coffee) CMD (/tmp/.sysupdate.sh # lab-sim)
CRON[24602]: (coffee) CMD (/tmp/.sysupdate.sh # lab-sim)
```
and `.beacon.log` with one line per minute. That regular one-minute rhythm is exactly what **C2 beaconing** looks like in proxy logs (see Practice).

### Part C: Containment → Eradication → Recovery (10 min)
```bash
# 1. Preserve evidence BEFORE you delete anything
mkdir -p ~/ir-lab
cp /tmp/.sysupdate.sh /tmp/.beacon.log ~/ir-lab/
crontab -l > ~/ir-lab/crontab_at_detection.txt
sha256sum ~/ir-lab/* > ~/ir-lab/hashes.txt

# 2. Contain: remove only the malicious cron line
crontab -l | grep -v 'lab-sim' | crontab -

# 3. Eradicate: remove the payload
rm /tmp/.sysupdate.sh /tmp/.beacon.log

# 4. Recover/verify: wait 2 minutes, then confirm nothing new runs
crontab -l
sudo journalctl -u cron --since "3 min ago" | grep lab-sim   # (crond on Fedora) should be empty
```

### Part D: Post-Incident (fill this in)
> [!example] My mini incident report
> - **Timeline** (detection → containment → eradication):
> - **Kill Chain stages observed:** (hint: 3, 5, 6)
> - **MITRE:** [[T1053.003]] Cron · [[T1564.001]] Hidden Files · [[T1071.001]] Web Protocols C2
> - **Evidence preserved & hashes:**
> - **What detection would have caught it sooner?**
> - **Lesson learned:**

How this looks in a SIEM later (W5/W7):
```spl
index=linux (sourcetype=syslog OR sourcetype=linux_secure) "CRON" "CMD"
| rex "\((?<cron_user>[^)]+)\) CMD \((?<cron_cmd>.+)\)"
| search cron_cmd="/tmp/*" OR cron_cmd="*/.*"
| stats count min(_time) as first max(_time) as last by host, cron_user, cron_cmd
```
```kql
Syslog
| where ProcessName in ("CRON", "cron", "crond") and SyslogMessage has "CMD"
| where SyslogMessage has "/tmp/" or SyslogMessage matches regex @"/\.[A-Za-z]"
| summarize Runs = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Computer, SyslogMessage
```

---

## 4. Practice (60–90 min): proxy log drill

**Scenario:** You're L1 on the morning shift at the same Dubai logistics firm. The web proxy (all staff traffic goes through it) exported this 9-minute slice. Find the **one** malicious activity, tell its story through the Kill Chain stages, and say which NIST step you'd take next.

```
Time (GST)  SrcIP        User         Method URL                                                         Status Bytes   Category                 User-Agent
09:10:02    10.10.4.12   l.dsouza     GET    https://outlook.office365.com/mail/                         200    48211   Business/Email           Edge/131
09:10:15    10.10.8.77   s.khan       GET    https://outlook.office365.com/mail/                         200    51022   Business/Email           Edge/131
09:10:41    10.10.6.30   r.menon      GET    https://www.linkedin.com/feed/                              200    120334  Social Networking        Chrome/131
09:11:03    10.10.4.12   l.dsouza     GET    https://teams.microsoft.com/v2/                             200    88410   Business/Collaboration   Edge/131
09:11:20    10.10.2.15   svc_monitor  GET    http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab 200 6120 Software Updates Microsoft-CryptoAPI/10.0
09:11:47    10.10.8.77   s.khan       GET    https://awb-dhl-tracking.top/track?id=44871                 200    3120    Newly Registered Domain  Edge/131
09:11:52    10.10.8.77   s.khan       GET    https://awb-dhl-tracking.top/files/AWB_44871_invoice.zip    200    18944   Newly Registered Domain  Edge/131
09:12:10    10.10.6.30   r.menon      GET    https://www.youtube.com/                                    403    0       Streaming Media (Blocked) Chrome/131
09:12:31    10.10.3.44   h.ali        GET    https://www.emiratesnbd.com/en/                             200    64210   Financial Services       Chrome/131
09:12:58    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    412     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:13:05    10.10.5.20   svc_backup   GET    https://backup-vendor-portal.example.com/api/heartbeat      200    220     Business/IT Services     BackupAgent/8.2
09:13:22    10.10.3.44   h.ali        GET    https://wetransfer.com/downloads/7f3a91c2                   200    26214400 File Sharing            Chrome/131
09:13:40    10.10.4.12   l.dsouza     GET    https://outlook.office365.com/mail/inbox                    200    40877   Business/Email           Edge/131
09:13:59    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    412     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:14:20    10.10.6.30   r.menon      GET    https://www.google.com/search?q=uae+public+holidays+2026    200    90122   Search Engines           Chrome/131
09:14:58    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    412     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:15:10    10.10.2.15   svc_monitor  GET    http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab 200 18233 Software Updates Microsoft-CryptoAPI/10.0
09:15:33    10.10.4.12   l.dsouza     GET    https://contoso.sharepoint.com/sites/Ops/Shared%20Documents  200    150990  Business/Collaboration   Edge/131
09:16:01    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    409     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:16:12    10.10.6.30   r.menon      GET    https://www.khaleejtimes.com/business                       200    210331  News/Media               Chrome/131
09:16:40    10.10.3.44   h.ali        GET    https://outlook.office365.com/mail/                         200    47019   Business/Email           Chrome/131
09:17:00    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    412     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:17:21    10.10.5.20   svc_backup   GET    https://backup-vendor-portal.example.com/api/heartbeat      200    220     Business/IT Services     BackupAgent/8.2
09:17:45    10.10.4.12   l.dsouza     GET    https://teams.microsoft.com/v2/                             200    79230   Business/Collaboration   Edge/131
09:17:59    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    4096    Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:18:14    10.10.6.30   r.menon      GET    https://www.youtube.com/watch?v=dQ9x                        403    0       Streaming Media (Blocked) Chrome/131
09:18:30    10.10.3.44   h.ali        GET    https://www.google.com/maps                                 200    130455  Search Engines           Chrome/131
09:19:01    10.10.8.77   s.khan       POST   https://cdn-sync-telemetry.net/api/v2/status                200    412     Uncategorized            Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041
09:19:20    10.10.2.15   svc_monitor  GET    http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab 200 6120 Software Updates Microsoft-CryptoAPI/10.0
```

Hints if you're stuck after 10 minutes: (1) look at the **Category** column, (2) look at the **User-Agent** column, (3) look at the **time gaps** for each destination.

> [!question]- Answer
> **Malicious activity:** `s.khan` on **10.10.8.77** downloaded a ZIP from a newly registered lookalike domain, ran something from it, and the host is now **beaconing to a C2 server** over HTTPS using PowerShell.
>
> **Kill Chain story:**
> | Stage | Evidence |
> |---|---|
> | 3 Delivery | 09:11:47 `awb-dhl-tracking.top/track?id=44871` → 09:11:52 download `AWB_44871_invoice.zip`. A fake DHL airway bill is a classic lure for a logistics company. It most likely arrived by email (s.khan had Outlook open at 09:10:15), so it fits [[T1566.002]] Spearphishing Link |
> | 4 Exploitation | Between 09:11:52 and 09:12:58 the user opened the ZIP and ran the file inside (often `.js`, `.lnk` or `.vbs`). [[T1204.002]] User Execution: Malicious File. Confirm on the host with Sysmon Event ID 1 (process creation) and 11 (file create) |
> | 5 Installation | Likely, not yet proven. Check for a scheduled task (4698), Run key (Sysmon 13) or startup folder file |
> | 6 C2 | 09:12:58 onward: `POST` to `cdn-sync-telemetry.net` **every ~60 s** (12:58, 13:59, 14:58, 16:01, 17:00, 17:59, 19:01), **same small size** (412 bytes), **Uncategorized** domain, and a **PowerShell user-agent**. Normal users don't browse with PowerShell. [[T1071.001]] Web Protocols. The 4096-byte request at 09:17:59 may be the implant sending back command output. That's an important detail to put in the escalation |
> | 7 Actions | Not seen yet. **This is the window to break the chain** |
>
> **Red herrings you correctly ignored:**
> - `r.menon` blocked on YouTube: a policy violation for HR/manager, not a security incident.
> - `h.ali` 25 MB from WeTransfer: it's a **GET** (download, not upload), to a known site, from a normal browser. It's worth knowing that uploads to file-sharing sites are an exfil pattern, but this one isn't.
> - `svc_monitor` Windows Update certificate trust-list checks and `svc_backup` heartbeats every ~4 minutes are regular, expected service traffic. Rhythm alone doesn't mean malicious; **rhythm + rare domain + odd user-agent** does.
>
> **NIST next steps (you are in phase 2 → 3):**
> 1. Declare an incident and escalate to L2 now with the timeline above (priority **High**: active C2).
> 2. **Contain:** isolate 10.10.8.77 via EDR (keeps it powered on so memory evidence survives), block both domains at the proxy and DNS.
> 3. **Scope:** search the proxy for *any other host* contacting `awb-dhl-tracking.top` or `cdn-sync-telemetry.net`. Search email logs for the phishing message and pull it from every mailbox.
> 4. **Eradicate/Recover** (L2/IR): remove persistence, reimage if needed, reset `s.khan`'s password and revoke sessions.
> 5. **Post-incident:** block newly registered domains by default? Alert on the PowerShell user-agent at the proxy?
>
> **SPL: find beaconing (regular gaps to one destination):**
> ```spl
> index=proxy earliest=-1h
> | sort 0 _time
> | streamstats current=f last(_time) as prev_time by src_ip, dest_host
> | eval gap=_time-prev_time
> | stats count as requests avg(gap) as avg_gap stdev(gap) as jitter avg(bytes) as avg_bytes values(http_user_agent) as ua by src_ip, dest_host
> | where requests>=5 AND jitter<10
> | sort jitter
> ```
> **KQL (Sentinel, proxy logs in CommonSecurityLog):**
> ```kql
> CommonSecurityLog
> | where TimeGenerated > ago(1h)
> | project TimeGenerated, SourceIP, DestinationHostName, RequestClientApplication, SentBytes
> | sort by SourceIP asc, DestinationHostName asc, TimeGenerated asc
> | extend Gap = datetime_diff('second', TimeGenerated, prev(TimeGenerated)),
>          SameFlow = SourceIP == prev(SourceIP) and DestinationHostName == prev(DestinationHostName)
> | where SameFlow
> | summarize Requests = count(), AvgGap = avg(Gap), Jitter = stdev(Gap), UA = make_set(RequestClientApplication) by SourceIP, DestinationHostName
> | where Requests >= 5 and Jitter < 10
> ```
> Quick win for a real proxy: alert on `RequestClientApplication has "WindowsPowerShell"` going to uncategorized or newly registered domains.

**Suggested rooms (pick one):** TryHackMe, search **"Cyber Kill Chain"** (then **"Unified Kill Chain"** if you have time). Or, in the SOC Level 1 path, the incident response fundamentals room. LetsDefend: the free **Incident Management 101** / **Phishing Email Analysis** courses.

---

## 5. Interview (90–110 min)

Answer out loud first (record on your phone), then open the model answer.

**I1. "Walk me through the NIST incident response lifecycle."**
> [!question]- Model answer
> "NIST SP 800-61 Rev. 2 has four phases. **Preparation**: playbooks, logging, tools and training in place before anything happens. **Detection and Analysis**: spotting the activity, confirming it's a real incident, scoping and prioritising it. That's where an L1 spends most of their time. **Containment, Eradication and Recovery**: stop the spread, preserve evidence, remove the root cause, then restore and monitor. It loops back to analysis because containment often reveals more affected systems. And **Post-Incident Activity**: a lessons-learned review that feeds new detections and better preparation. Rev. 3, published in 2025, re-maps this onto the NIST CSF 2.0 functions, but the logic is the same. Coming from IT support, it feels a lot like ITIL incident and problem management: fix the outage, then fix the cause."

**I2. "What is the Cyber Kill Chain, and how does it help you as an analyst?"**
> [!question]- Model answer
> "It's Lockheed Martin's seven-stage model of an intrusion: reconnaissance, weaponization, delivery, exploitation, installation, command and control, and actions on objectives. As an analyst it helps me in two ways. First, when I see one piece of evidence I can ask what came before and what comes next. If I see C2 beaconing, I go back and look for the delivery, like the phishing email, and forward for lateral movement or exfil. Second, it reminds me that the earlier we break the chain the cheaper the incident is. Its limitation is that it's very malware- and perimeter-focused, so for insider threats or cloud identity attacks I'd lean on MITRE ATT&CK, which gives much more granular techniques."

**I3. "What's the difference between containment and eradication? Why not just wipe the infected machine straight away?"**
> [!question]- Model answer
> "Containment stops the damage spreading: isolating the host through EDR, disabling the compromised account, blocking the C2 domain. Eradication removes the cause: deleting the malware and its persistence, patching the vulnerability, resetting credentials. If you wipe straight away you destroy the evidence you need to answer the important questions: how did they get in, what did they take, and is anything else infected? You might reimage one laptop while the attacker still has a foothold on three others, or never find the phishing email that hit forty people. So you isolate first, preserve memory and logs, scope the incident, and only then eradicate everywhere at once."

---

## 6. Capture (110–120 min)

- [ ] Fill in the mini incident report in Lab Part D
- [ ] Confirm the lab cron job is gone (`crontab -l`)
- [ ] Tick off the TryHackMe room
- [ ] Tell Claude: **"save today's note to my vault"**
- [ ] Mark `status: done` in the front matter

#flashcards

Name the 7 stages of the Cyber Kill Chain in order.::Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives.
Name the 4 phases of the NIST SP 800-61 Rev. 2 incident response lifecycle.::Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity.
What three proxy-log clues together suggest C2 beaconing?::Regular time gaps to one destination, consistent small request sizes, and a rare/uncategorized domain (bonus: unusual user-agent such as PowerShell).
Why preserve evidence before eradication?::Wiping destroys what you need to find the entry point, scope other infected hosts and see what was taken. Isolate, preserve, scope, then eradicate.
Event vs alert vs incident?::Event = anything that happened; alert = event(s) a rule flagged for review; incident = confirmed (or imminent) violation of security policy.
