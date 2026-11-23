---
type: daily
week: 1
day: 1
date: 2026-11-23
topic: SOC fundamentals, analyst tiers and the alert lifecycle
mitre: [T1110, T1110.001, T1078, T1021.001]
tags: [soc, daily]
status: todo
---

# W1D1 — SOC fundamentals & the alert lifecycle

> [!info] Tonight's plan (8:00–10:00 PM Dubai)
> Week 1 theme: [[SOC Fundamentals]], [[Alert Lifecycle]], [[NIST 800-61]], [[Cyber Kill Chain]].
> Today is the foundation: what a SOC is, who does what, and what happens to an alert from the moment it fires to the moment it's closed. Tomorrow (D2) builds on this with NIST 800-61 incident handling phases.

---

## 1. Recall (0–10 min)

Your only completed note so far is Week 0 setup, so tonight's recall is a warm-up on that and on last night's preview. Answer out loud before you open each one.

**Q1.** What two things does the Spaced Repetition plugin need to turn a line into a flashcard?
> [!question]- Answer
> The note (or section) must carry the `#flashcards` tag, and each card is written as `Question::Answer` on one line.

**Q2.** Last night's preview listed four stages of the alert lifecycle. Name them in order.
> [!question]- Answer
> Detect → Triage → Investigate → Escalate *or* Close. (Tonight we add the "document" step that wraps around all of them.)

**Q3.** Why does the plan ask for ~16 GB RAM and ~250 GB free disk before Week 4?
> [!question]- Answer
> The W4 home lab runs several VMs at once: a Domain Controller, a Windows 10 endpoint (with Sysmon), and a Wazuh server. Each needs 2–4 GB RAM and 40–80 GB disk.

**Q4.** "An alert is a ticket with an attacker behind it." Give one way an alert is *different* from a normal IT support ticket.
> [!question]- Answer
> Any of: a ticket comes from a user who wants help, an alert comes from a tool and the "requester" may be trying to hide; most alerts are false positives you must prove harmless; evidence is time-sensitive (logs roll over, attackers move); the outcome can be escalation to IR, not just "resolved".

**Q5.** What is NIST SP 800-61 in one sentence?
> [!question]- Answer
> NIST's guide to computer security incident handling. Rev. 2 gives the classic 4-phase lifecycle (Preparation; Detection & Analysis; Containment, Eradication & Recovery; Post-Incident Activity). Rev. 3 (2025) maps incident response onto the NIST CSF 2.0 functions. Interviewers still mostly ask for the Rev. 2 phases. Full detail tomorrow.

---

## 2. Learn (10–30 min)

### What a SOC actually is
A **Security Operations Centre** is a team (plus tools and processes) that watches an organisation's systems 24/7, spots malicious activity, and responds before it becomes a breach. Think of it as the service desk for security, except the "users" raising issues are your detection tools, and some of the "users" are attackers trying not to be noticed.

**People, Process, Technology**: the three legs every SOC interview loves.
- **People**: analysts in tiers (below), detection engineers, threat hunters, IR leads, SOC manager.
- **Process**: playbooks/runbooks, escalation matrix, SLAs, shift handover, ticketing.
- **Technology**: [[SIEM]] (Splunk, Sentinel, Wazuh), [[EDR]] (Defender for Endpoint, CrowdStrike), firewalls/proxies, email gateway, [[SOAR]], ticketing (ServiceNow/Jira), threat intel platforms.

### The tiers (and where you fit)
| Tier | Role | Your IT-support equivalent |
|---|---|---|
| **L1 – Triage** | Watches the alert queue, does first-pass analysis, closes false positives, escalates true positives with good notes | Service desk L1: take the ticket, gather info, fix the easy ones, escalate the rest |
| **L2 – Investigation/IR** | Deep-dives escalations, correlates across log sources, scopes the incident, starts containment (isolate host, disable user) | Desktop/infra L2: remote in, check logs, find root cause |
| **L3 – Hunt/Engineering** | Threat hunting, detection engineering, malware analysis, tuning rules | Sysadmin/engineering team that fixes the underlying problem |

You already know the hardest soft skills: working a queue, writing clear ticket notes, knowing when to escalate, talking to stressed users. Lean on that in interviews.

### The alert lifecycle
```
 Detection ─► Triage ─► Investigation ─► Decision ─► Escalate / Contain ─► Close ─► Lessons learned/tuning
 (rule fires)  (is it    (what, who,      (TP / FP /    (hand to L2/IR,        (documented
               real?     when, where,     benign TP)    or remediate)           verdict)
               priority?) how far?)
```
1. **Detection**: a SIEM rule, EDR detection, or user report creates an alert.
2. **Triage** (L1, minutes): Is this real? How bad? Check the asset (DC or kiosk PC?), the user (admin or intern?), and quick context. Set priority = **severity × asset criticality**.
3. **Investigation**: answer the **5 W's**: *who* (account), *what* (action), *when* (timeline), *where* (host/IP), *how* (technique, map to [[MITRE ATT&CK]]).
4. **Verdict**:
   - **True Positive (TP)**: malicious, act on it.
   - **False Positive (FP)**: rule fired wrongly, close and suggest tuning.
   - **Benign True Positive**: rule worked correctly but the activity is authorised (e.g. the IT team's vulnerability scanner). Close with a note, possibly whitelist.
   - (False Negative = an attack that *didn't* alert. You only find these by hunting or after the fact.)
5. **Escalate/Contain**: hand to L2/IR with a clean summary, or follow the playbook (reset password, isolate host).
6. **Close & document**: verdict, evidence, actions, time. If it isn't written down, it didn't happen.
7. **Feedback**: noisy rule? Recommend tuning. This loop is what keeps a SOC from drowning in [[Alert Fatigue]].

Key metrics you'll hear: **MTTD** (mean time to detect), **MTTA** (to acknowledge), **MTTR** (to respond/resolve), FP rate, alerts per analyst per shift.

### Real-world example: the Target breach (2013)
Attackers got in using credentials stolen from Target's HVAC contractor, then moved to the payment systems and installed card-stealing malware on POS terminals. Target's malware-detection tool **did fire alerts**, and the outsourced monitoring team in Bangalore flagged them to the Minneapolis SOC. The alerts weren't acted on. About 40 million card numbers were stolen.

Lesson for an L1: the detection worked, the **lifecycle failed** at triage/escalation. Good notes, correct priority and a confident escalation are the job. "I saw it but assumed someone else would handle it" is the failure mode.

---

## 3. Lab (30–60 min)

Your home lab isn't built until W4, so tonight you'll do two things: the first TryHackMe SOC room, and generate and triage *your own* authentication alerts on your own Linux PC. Only touch your own machine.

### Part A: TryHackMe (15 min)
Open the **SOC Level 1** path and complete its first introductory room on SOC fundamentals and the analyst role. Note in this file any term you didn't know.

### Part B: Make your own "brute-force" evidence (15 min)
On your Linux PC (this vault's machine):

```bash
# 1. Generate 3 failed sudo authentications. Type a WRONG password 3 times when prompted.
sudo -k            # forget cached sudo credentials
sudo ls            # enter wrong password x3

# 2. Now succeed
sudo -k && sudo ls # enter correct password

# 3. Find the evidence (Ubuntu/Debian: auth.log; Fedora/Arch: journal)
sudo grep -E "authentication failure|incorrect password|COMMAND" /var/log/auth.log | tail -20
# or
sudo journalctl _COMM=sudo --since "10 min ago"
```

**Expected evidence** (exact wording varies by distro):
```
pam_unix(sudo:auth): authentication failure; logname=coffee uid=1000 euid=0 tty=/dev/pts/0 ruser=coffee rhost=  user=coffee
sudo: coffee : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/coffee ; USER=root ; COMMAND=/usr/bin/ls
sudo: coffee : TTY=pts/0 ; PWD=/home/coffee ; USER=root ; COMMAND=/usr/bin/ls
```

### Part C: Triage it like an L1 (remaining time)
Write a mini ticket below, as if a SIEM rule "3+ failed privilege escalation attempts" had fired:

> [!example] My triage ticket
> - **Alert:**
> - **Who / what / when / where:**
> - **Verdict (TP / FP / Benign TP) and why:**
> - **Would you escalate? Why/why not:**
> - **Tuning suggestion:**

What this looks like in a SIEM (you'll run these for real in W5 and W7):

```spl
index=linux sourcetype=linux_secure "authentication failure"
| stats count min(_time) as first max(_time) as last by host, user
| where count >= 3
```

```kql
Syslog
| where ProcessName == "sudo" and SyslogMessage has "authentication failure"
| summarize Failures = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Computer, HostName
| where Failures >= 3
```

---

## 4. Practice (60–90 min): log drill

**Scenario:** You're L1 on the night shift at a Dubai logistics firm. The SIEM shows this Windows Security log extract from `SRV-FILE01` (file server, RDP exposed only to the VPN range `10.20.0.0/16`). Internal LAN is `10.10.0.0/16`. Somewhere in here is **one** malicious activity. Find it, then write the 5 W's.

```
Time (GST)           EventID  Account          LogonType  SourceIP        Workstation   Result
2026-11-23 01:58:02  4624     SYSTEM           5          -               SRV-FILE01    Success
2026-11-23 02:00:11  4624     svc_backup       3          10.10.5.20      BKP-01        Success
2026-11-23 02:00:12  4634     svc_backup       3          10.10.5.20      BKP-01        Logoff
2026-11-23 02:03:45  4625     a.rahman         3          10.10.8.41      LT-0841       Fail 0xC000006A
2026-11-23 02:03:51  4624     a.rahman         3          10.10.8.41      LT-0841       Success
2026-11-23 02:10:00  4624     svc_monitor      3          10.10.2.15      MON-01        Success
2026-11-23 02:10:01  4634     svc_monitor      3          10.10.2.15      MON-01        Logoff
2026-11-23 02:14:27  4625     administrator    10         185.220.101.47  -             Fail 0xC0000064
2026-11-23 02:14:29  4625     admin            10         185.220.101.47  -             Fail 0xC0000064
2026-11-23 02:14:31  4625     j.thomas         10         185.220.101.47  -             Fail 0xC000006A
2026-11-23 02:14:33  4625     test             10         185.220.101.47  -             Fail 0xC0000064
2026-11-23 02:14:35  4625     j.thomas         10         185.220.101.47  -             Fail 0xC000006A
2026-11-23 02:14:38  4625     backup           10         185.220.101.47  -             Fail 0xC0000064
2026-11-23 02:14:40  4625     j.thomas         10         185.220.101.47  -             Fail 0xC000006A
2026-11-23 02:15:02  4624     svc_backup       3          10.10.5.20      BKP-01        Success
2026-11-23 02:15:03  4634     svc_backup       3          10.10.5.20      BKP-01        Logoff
2026-11-23 02:16:19  4625     j.thomas         10         185.220.101.47  -             Fail 0xC000006A
2026-11-23 02:16:44  4624     j.thomas         10         185.220.101.47  -             Success
2026-11-23 02:17:02  4672     j.thomas         -          -               SRV-FILE01    Special privileges assigned
2026-11-23 02:20:00  4624     svc_monitor      3          10.10.2.15      MON-01        Success
2026-11-23 02:20:01  4634     svc_monitor      3          10.10.2.15      MON-01        Logoff
2026-11-23 02:22:13  4625     m.fernandes      2          -               SRV-FILE01    Fail 0xC000006A
2026-11-23 02:22:20  4624     m.fernandes      2          -               SRV-FILE01    Success
2026-11-23 02:30:00  4624     svc_backup       3          10.10.5.20      BKP-01        Success
2026-11-23 02:30:01  4634     svc_backup       3          10.10.5.20      BKP-01        Logoff
2026-11-23 02:31:55  4624     a.rahman         3          10.10.8.41      LT-0841       Success
2026-11-23 02:38:09  4634     a.rahman         3          10.10.8.41      LT-0841       Logoff
2026-11-23 02:40:00  4624     svc_monitor      3          10.10.2.15      MON-01        Success
```

Cheat sheet: `4624` success logon · `4625` failed logon · `4634` logoff · `4672` admin-level privileges at logon · Logon type `2` = console, `3` = network (file share), `5` = service, `10` = RDP · `0xC0000064` = username doesn't exist · `0xC000006A` = username exists, wrong password.

> [!question]- Answer
> **Malicious activity:** a successful **RDP brute-force / password-guessing** against `j.thomas` from the external IP **185.220.101.47** (an address in a range commonly associated with Tor exit nodes).
>
> - **Who:** `j.thomas`, and the account has admin rights (4672 at 02:17:02).
> - **What:** 8 failed RDP logons (type 10) from one external IP, cycling generic usernames (`administrator`, `admin`, `test`, `backup` → `0xC0000064` = don't exist) then focusing on `j.thomas` (`0xC000006A` = real account, wrong password), followed by a **success** at 02:16:44.
> - **When:** 02:14:27 → 02:16:44 GST, outside business hours.
> - **Where:** `SRV-FILE01`, which should only accept RDP from `10.20.0.0/16`. A public IP means a firewall/NSG misconfiguration too.
> - **How:** MITRE **T1110.001** (Brute Force: Password Guessing) → **T1078** (Valid Accounts) → **T1021.001** (Remote Services: RDP).
>
> **Noise you correctly ignored:** `a.rahman` and `m.fernandes` each mistyped once then logged in from expected places (classic typo pattern); `svc_backup` / `svc_monitor` are regular service-account heartbeats every 10–15 min.
>
> **L1 action:** Priority **High/Critical** (admin account + file server + external access). Escalate to L2 immediately with the timeline. Recommend: disable/reset `j.thomas`, kill the RDP session, block 185.220.101.47 at the perimeter, review what `j.thomas` did after 02:17 (4663 file access, 4688 process creation), and fix the firewall rule exposing RDP.
>
> **SPL that would catch it:**
> ```spl
> index=wineventlog EventCode IN (4625,4624) Logon_Type=10
> | eval outcome=if(EventCode=4624,"success","fail")
> | stats count(eval(outcome="fail")) as fails count(eval(outcome="success")) as successes values(user) as users by src_ip
> | where fails>=5 AND successes>=1
> ```
> **KQL (Sentinel):**
> ```kql
> SecurityEvent
> | where EventID in (4625, 4624) and LogonType == 10
> | summarize Fails = countif(EventID == 4625), Successes = countif(EventID == 4624), Accounts = make_set(TargetUserName) by IpAddress
> | where Fails >= 5 and Successes >= 1
> ```

**Extra practice:** LetsDefend **SOC Fundamentals** course (free) and, if time allows, try the first few alerts in the LetsDefend **Monitoring** page to feel what an L1 queue looks like.

---

## 5. Interview (90–110 min)

Answer each out loud (record yourself on your phone if you can), *then* open the model answer.

**I1. "Walk me through what you do when an alert lands in your queue."**
> [!question]- Model answer
> "First I acknowledge it so nobody duplicates work, then I triage: what rule fired, which asset and user, and how critical they are. That gives me priority. Then I investigate the 5 W's: who, what, when, where, how, pulling context from the SIEM, EDR and threat intel (e.g. IP reputation). I decide true positive, false positive or benign true positive. A false positive I close with evidence and suggest tuning. A true positive I either handle per the playbook or escalate to L2 with a clear timeline, IOCs and what I've already checked. Everything goes in the ticket. In IT support I learned that a good escalation note saves the next person twenty minutes, and it's even more important in security."

**I2. "What's the difference between a false positive and a benign true positive? Give an example."**
> [!question]- Model answer
> "A false positive is when the rule fires but the activity doesn't match what it's meant to detect, like a 'malware' alert on a clean file because of a bad signature. A benign true positive is when the rule fires correctly on the behaviour it looks for, but the behaviour is authorised. For example, a port-scan alert from the IT team's Nessus scanner. Both get closed, but the fix differs: an FP means the rule logic needs tuning, a benign TP usually means a documented exclusion for that approved source."

**I3. "Your queue has 60 alerts and you're alone on shift. How do you prioritise?"**
> [!question]- Model answer
> "I sort by severity times asset criticality, not by arrival time. Anything touching domain controllers, privileged accounts, or showing signs of active compromise like a successful login after brute-force, ransomware behaviour, or data exfil goes first. I look for clusters: ten alerts from one host are probably one incident, so I handle them together. Low-severity alerts on low-value assets wait. If I'm overwhelmed I escalate to the on-call L2 or shift lead early rather than letting a critical alert sit. And afterwards I'd flag the noisiest rules for tuning, because 60 alerts for one analyst is itself a problem to fix."

---

## 6. Capture (110–120 min)

- [ ] Fill in your triage ticket in the Lab section
- [ ] Tick off the TryHackMe room
- [ ] Tell Claude: **"save today's note to my vault"**
- [ ] Mark `status: done` in the front matter

#flashcards

What are the three SOC tiers and their main job?::L1 = triage & escalate; L2 = investigate, scope & contain; L3 = threat hunting, detection engineering, malware analysis.
What is a benign true positive?::The rule fired correctly on the behaviour it detects, but the activity was authorised (e.g. IT's vulnerability scanner).
How do you set alert priority at triage?::Severity × asset/identity criticality (e.g. admin account on a DC beats a guest account on a kiosk).
Windows Event ID 4625 vs 4624 vs 4672?::4625 = failed logon; 4624 = successful logon; 4672 = special (admin) privileges assigned at logon.
Logon type 10 vs 3 vs 2?::10 = RemoteInteractive (RDP); 3 = Network (e.g. file share); 2 = Interactive (at the console).
