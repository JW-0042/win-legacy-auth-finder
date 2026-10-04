# Notes for AI coding agents

## Build and test

- Target: .NET 10 and WPF, Windows only.
- Build: `dotnet build LegacyAuthFinder.slnx`
- Test: `dotnet test LegacyAuthFinder.slnx`
- Warnings are treated as errors.

## Rules for the code

- **The tool is read-only.** Never write to the scanned files or folders.
- **All file access goes through `IEvtxReader`.** The real reader is `WindowsEvtxReader`.
- **Filter inside the event log API.** Queries are XPath strings in `Queries` (EvtxReader.cs), and fields are read by name with `EventLogPropertySelector`. Do not switch to reading every record or rendering XML for the big Security queries, because it makes 4 GB files slow.
- **Classification lives in `Classifier`.** Every change needs tests in `ClassifierTests`, including cases that must be ignored.
- **Event field names.** Check them against current Microsoft documentation. They change: 4768 and 4769 got new fields in 2025, and KDCSVC events 201 to 209 were added in 2026.
- **The demo data must contain every type.** `Demo_covers_every_kind_and_file_state` enforces this.

## Text style

Plain English. No em dashes and no semicolons joining sentences.

## README screenshots

Screenshot mode always uses the demo data, so no real names end up in public images. Regenerate the screenshots with:

```
LegacyAuthFinder.exe --screenshot docs/screenshot-summary-light.png --theme light --tab summary
LegacyAuthFinder.exe --screenshot docs/screenshot-summary-dark.png --theme dark --tab summary
LegacyAuthFinder.exe --screenshot docs/screenshot-events-light.png --theme light --tab events
LegacyAuthFinder.exe --screenshot docs/screenshot-files-light.png --theme light --tab files
```

`--folder <path>` in screenshot mode scans a real folder instead of the demo. It is for local testing only and must never be used for images that get published.
