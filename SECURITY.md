# Security policy

Legacy Auth Finder is a read-only tool. It reads event log files and never changes them or any system settings. It sends nothing over the network.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). You will get an answer within a few days.

Useful things to include: the Windows version and build, the event ID and a sample of the event XML (with names removed), what you expected and what happened.

## Verifying a release

Every release binary is built by GitHub Actions and has a signed build provenance attestation. You can verify a download with the GitHub CLI:

```
gh attestation verify LegacyAuthFinder-win-x64.zip --repo JW-0042/win-legacy-auth-finder
```
