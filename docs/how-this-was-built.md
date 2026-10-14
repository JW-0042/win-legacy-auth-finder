# How this was built

Legacy Auth Finder is the third tool in a small series of Windows administration and security tools that I build with an AI coding agent (Claude Code). The others are [Hardening Checker](https://github.com/JW-0042/win-hardening-checker) and [Event Triage](https://github.com/JW-0042/win-event-triage).

## Where it came from

A real task: before the 2026 RC4 changes, find out which accounts, clients and services in a domain still use NTLMv1, RC4 or DES. The only evidence was a folder of archived Security logs copied from the servers, some of them over 4 GB each.

## Who did what

**My part:**
- the problem and the requirements,
- the decision to group results into a to-do list,
- review of the detection logic,
- testing.

**My requirements:**
- open a whole folder,
- recognize which log each file is,
- handle 4 GB files,
- make everything searchable.

**The AI agent's part:**
- researching the current event fields, including the fields and events Microsoft added in 2025 and 2026 for the RC4 phase-out,
- the code, the tests and the demo domain,
- the CI pipeline and the documentation.

## Decisions that mattered

- **Let Windows do the filtering.** The XPath filter runs inside the event log API, so a 4 GB file is streamed and only matching records reach .NET. Fields are read by name with a property selector, which is much faster than rendering every event as XML and is safe across event versions.
- **Trust the content, not the file name.** The first record of each file tells which log it is. Archive names get renamed and copied around.
- **A to-do list first.** The summary groups millions of events into a few hundred rows of account, client and service. That is what an admin actually works through.
- **Bounded memory.** Repeated strings (accounts, hosts, services) are shared, and the event list stops at 5 million events while the summary keeps counting.
- **Check the current documentation.** RC4 handling changed in 2025 and 2026, with new fields in 4768 and 4769 and new KDCSVC events 201 to 209. The agent looked these up instead of relying on older knowledge, and every reference link was checked.

## Testing without a domain

No real NTLMv1 or RC4 traffic was available on my machine, so the tests come in layers:
- **Unit tests** check the classification with hand-made events, including the cases that must be ignored, such as AES tickets, NTLMv2 logons and failed requests.
- **Integration tests** export real logs with `wevtutil` and read them through the actual Windows API. They check that each file's log is detected, that all XPath queries are accepted, that named fields come back correctly and how fast the scan is.
- **CI** has admin rights, so it also exports and scans the runner's real Security log.
- **The demo domain** runs through the real scanner and summary.

## Version 0.2: listening to the user

After the first release I asked whether the Directory Service log should be scanned too. It should, but for a different problem: domain controllers log unsigned and cleartext LDAP binds there, which Windows Server 2025 refuses by default. Version 0.2 adds:
- unsigned LDAP (2889 and 2887),
- LDAP channel binding (3039, 3074, 3075),
- Kerberos requests that already fail for lack of a common encryption type (KDC 14/16/26/27 and status 0xE). These show what will break when RC4 or DES is switched off.

Two usability changes came from real use: opening a folder no longer starts the scan right away, so you can check the file list first, and up to 16 files can be scanned at once for fast disks and network shares.

These older events have no field names, only numbered insertion strings. Their order comes from the message text Microsoft documents, and an integration test checks that positional reading returns real values in the right order.

## Version 0.2.2: a scan that looked stuck

With 16 files at once and 19 archives, the scan seemed to stand still, and after Cancel the running files finished one by one while the waiting ones never started. With 2 or 4 files at once everything was fine. Reproducing it on an SSD did not work, so I looked at what the Windows API actually does.

The answer was in the API, not in the tool's threads. A query asks the event log service for the next matching record. In a file with no findings that is one call that scans the whole file, blocks until the end and cannot be interrupted. Sixteen such calls on one hard disk make the disk seek between sixteen files, so each one crawls, and nothing on screen changes because nothing matches. Cancel only takes effect when a call returns, which is why the files finished one after another.

Three things fixed it:
- Reads now use a half second limit and resume where they stopped. I tested that no record is lost. Cancel takes effect within a second, and a file without findings shows that it is still being read.
- The tool checks whether the folder is on an SSD, a hard disk or a network share (no admin rights needed) and picks the number of files to scan at once. On one hard disk that is 2.
- The progress of a file was wrong for exported logs, because their record numbers do not start at 1. It now uses the real first and last record IDs.

I also tried splitting a file into ranges of record IDs to get real progress. The API scans the whole file for every range, so 20 ranges were 16 times slower than one query. That idea went into the documentation as a dead end instead of into the code.

## Version 0.3: when you cannot get the data

The scan still stalled on a real archive of almost 90 GB, and 90 GB of security logs cannot be sent to anyone. So instead of guessing again, the tool got a diagnostic log the user can send. It records timings, file sizes and the state of every running file every 10 seconds, never the content of the events. A file whose read has not returned for 15 seconds is marked as stalled, together with how busy the Windows Event Log service is at that moment.

Building it settled an old question. Measured on a test machine, the Event Log service read the files at 1.2 GB per second on 7 cores while the tool's own process read nothing. The service does all the file work for EvtQuery, so with many files at once that one service is the bottleneck. The log reads its counters from the system process list, which works without admin rights.

The same release added the NTLM Operational log (with the reason Windows logs for every NTLM use), SMBv1 clients from the SMB audit log, and a ranked fix list that says what to change on which client, account or service account. The field names come from the provider manifests on Windows itself, not from blog posts.

## Version 0.4: reading the files ourselves

The diagnostic log answered the question in one run. Nothing was stuck. The Windows Event Log service was using 8 CPU cores and read about 370 MB per second for the NTLMv1 question, then only 95 MB per second for the RC4 question, because it evaluates the XPath filter on every record. Each Security file was read three times, once per question. On 99 GB the scan would have needed most of an hour and looked frozen, because the RC4 pass found nothing for minutes.

So the tool got its own `.evtx` parser. The format is public: a file header, 64 KB chunks with their own string and template tables, records in binary XML. The parser reads each file once, checks the event ID of every record first and decodes the rest only for the events it looks for.

The hard part was not the format but matching Windows exactly. A test exports real logs and compares every record and every value with the Windows API. It found six rules nobody documents, for example that exported files renumber their record headers while the event keeps its original ID, and that Windows returns the low byte of a 16-bit signed number. After those fixes, about 79,000 records from four logs match without a single difference. CI adds the Security log.

## Version 0.4.1: a full audit

With the scan finally fast, I asked the agent for a full code audit of the tool and then had it fix everything it found. The list was long and most of it was the kind of thing that only shows up in real environments.

- **Wrong advice is a bug.** Two of the 2026 KDCSVC warning events pointed to the wrong side, the client instead of the service account. Anonymous sessions were reported as NTLMv1 users, although Microsoft says to ignore them. A service name in event 4769 is an account, not an SPN, so the advice now says `setspn -L <account>`. These were checked against Microsoft's documentation, not guessed.
- **New detections.** Accounts without Kerberos pre-authentication (AS-REP roasting), NTLM validation on domain controllers (4776) for networks without the new NTLM events, the blocked NTLM events, rejected LDAP binds and the channel binding summary.
- **The parser got stricter.** It now checks the checksum of every chunk, recovers records that a crashed writer left behind, and limits nested templates so a crafted file cannot make it run forever. Since real logs do not contain these cases, a new test builds `.evtx` files byte by byte.
- **Matching Windows, round two.** The KDC warnings are read the way the event XML shows them. A second comparison against the Windows XML found six more rules: lowercase GUIDs, line endings, whole 16-bit numbers, empty values, string arrays split into elements and whitespace-only values. Again zero differences after the fixes.
- **Honest results.** Overlapping exports no longer count the same event twice, a file that fails half way is shown as an error instead of a silent gap, and the event list keeps the newest events instead of the oldest.
- **The details.** Exports no longer freeze the window, CSV files use the regional separator so Excel opens them, the version is shown in the app, the command line has exit codes for incomplete scans and failed exports, and the GitHub Actions are pinned to exact commits.

## Quality gates

- The build treats warnings as errors.
- GitHub Actions builds the tool, runs all tests and scans the runner's own Security, System and Application logs on every push. The actions are pinned to commit hashes.
- A release is only built when its tag matches the version in the code.
- Releases are self-contained single-file builds with signed build provenance.
