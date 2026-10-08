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

## Quality gates

- The build treats warnings as errors.
- GitHub Actions builds the tool, runs all tests and scans the runner's own Security, System and Application logs on every push.
- Releases are self-contained single-file builds with signed build provenance.
