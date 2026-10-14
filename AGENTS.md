# Notes for AI coding agents

## Build and test

- Target: .NET 10 and WPF, Windows only.
- Build: `dotnet build LegacyAuthFinder.slnx`
- Test: `dotnet test LegacyAuthFinder.slnx`
- Warnings are treated as errors.

## Rules for the code

- **The tool is read-only.** Never write to the scanned files or folders.
- **All file access goes through `IEvtxReader`.** The default reader is the built-in parser `EvtxFileReader` (EvtxParser.cs), with `WindowsEvtxReader` as fallback for files that are not `.evtx` and as an option for comparison.
- **Every query has two forms.** The XPath string is used by the Windows API. `EventIds`, `Providers` and `Filter` are used by the parser and must select exactly the same records. Change both together.
- **The parser must match the Windows API.** `EvtxParserTests.Every_record_matches_the_windows_api` compares every record and value of real logs. Rules learned from it: the record ID comes from System/EventRecordID (exported files renumber the record headers), null values are not properties, string arrays in unnamed Data elements (classic events) are split into separate properties while named arrays stay one value, a nested template instance under UserData returns all its values, and Int16 comes back as its low byte, HexInt32 as int.
- **Classic events split their string array, nothing else does.** Windows returns the elements of a string array in an unnamed Data element as separate properties only when the Data element sits in a nested template instance, which is how classic events are stored. The same array in a top-level template stays one property. `RecordFields.Positional` tracks this with the `Nested` flag.
- **Typed values follow Windows, not the obvious type.** Properties: SByte comes back as Byte, ANSI strings use the system code page (GetACP, not the thread culture, which the app sets to en-US), HexInt32 arrays are UInt32. The XML shows SByte signed, ANSI text as Latin-1, a SYSTEMTIME as UTC without conversion, every array of any type as one element per item, and control characters as underscores.
- **XML-style values must match too.** Queries without `Fields` (KDC warnings) read values the way `WindowsEvtxReader.EventDataFromXml(record.ToXml())` does, and the same test compares `RecordFields.XmlStyle` with it. Rules learned from it: GUIDs in lowercase with braces, CR LF becomes LF, Int16 as the full number, an unnamed Data with only a null value is left out, every string array (named, unnamed or in UserData) becomes one element per string, and a value that is only whitespace reads as empty.
- **Crafted files for what real logs do not have.** `CraftedEvtxTests` builds `.evtx` files byte by byte (`EvtxWriter`) to test damaged sizes, stale free offsets, checksums, dirty headers and the expansion limits. Add a case there for every parser fix that real logs cannot reproduce.
- **Tests that measure time or export logs run serially.** They use `[Collection(SerialCollection.Name)]`, otherwise parallel tests make them flaky.
- **Damaged input is normal.** Every read in `ChunkParser` is bounds-checked against the 64 KB chunk. A damaged record or chunk is skipped and counted in `ReadStats`, never fatal.
- **Classification lives in `Classifier`.** Every change needs tests in `ClassifierTests` or `NtlmSmbTests`, including cases that must be ignored.
- **The fix list lives in `Remediation`.** Every summary row becomes exactly one fix item, so the fix list always adds up to the total. Tests in `RemediationTests` and `AuditFixTests`. KDCSVC 201, 203, 206 and 208 point to the client, 202, 204, 207 and 209 to the service account, 205 to `DefaultDomainSupportedEncTypes`. A service name in 4769 is an account, so the advice uses `setspn -L <account>`.
- **Duplicates need record ID and time.** Record IDs start again at 1 after a log is cleared. `Scanner.Overlaps` pairs files only when their record ranges and time ranges overlap, and the duplicate key is log, record ID and time, checked only inside the shared record range.
- **Partly read is incomplete.** Damaged chunks, unreadable records, a file cut off inside a chunk (`ReadStats.MissingBytes`) and failed fallback queries all mark the file as an error and the result as incomplete (`ReadStats.Partial`).
- **The header is not trusted for the order.** `EvtxFileReader.Ends` follows the chunk record numbers from the newest chunk the header names, and takes the next chunk as the oldest when it holds lower numbers. Inspect and the scan use the same walk over a chunk (`ChunkRecords`).
- **Memory stays near the event limit.** Files hand their events to the shared list in batches (`EventBatch`), and once the list is full, events older than its oldest one are only counted, not kept.
- **Advice must name the party that can fix it.** KDC event 16 names the account to reset in %6, not %2. A failed 4769 points to the target service, never to the requesting user. krbtgt without AES keys is a domain controller fix. Service account steps go keys first, AES only last (Microsoft's CVE-2026-20833 guidance, 0x24 as the stopgap).
- **Scanning never aborts on one file.** An unexpected exception becomes an error on that file and the result is marked incomplete. Duplicates are skipped only between files whose record ranges overlap.
- **Diagnostic log.** `DiagLog` writes timings, file names and process counters, never event content (accounts, addresses, services). `ScanMonitor` writes the heartbeat and `STALL` lines. Keep it that way, users send these files for support.
- **The Event Log service does the reading.** EvtQuery on a file runs in the Windows Event Log service (measured: the service reads the file, this process reads nothing). Its counters come from the system process list, which needs no admin rights.
- **Event field names.** Check them against current Microsoft documentation. They change: 4768 and 4769 got new fields in 2025, and KDCSVC events 201 to 209 were added in 2026. The NTLM Operational and SMBServer Audit names come from the provider manifests (`(Get-WinEvent -ListProvider Microsoft-Windows-NTLM).Events`). XPath compares field names case-sensitively, and Microsoft uses both `Username` and `UserName`.
- **The demo data must contain every type.** `Demo_covers_every_kind_and_file_state` enforces this. CI also checks the demo totals per type.
- **Every release shows its version.** `Directory.Build.props` holds it, the app shows it in the title and side panel, reports include it, and the release workflow refuses a tag that does not match it.

## Text style

Plain English. No em dashes and no semicolons joining sentences.

## README screenshots

Screenshot mode always uses the demo data, so no real names end up in public images. Regenerate the screenshots with:

```
LegacyAuthFinder.exe --screenshot docs/screenshot-fix-light.png --theme light --tab fix
LegacyAuthFinder.exe --screenshot docs/screenshot-summary-light.png --theme light --tab summary
LegacyAuthFinder.exe --screenshot docs/screenshot-summary-dark.png --theme dark --tab summary
LegacyAuthFinder.exe --screenshot docs/screenshot-events-light.png --theme light --tab events
LegacyAuthFinder.exe --screenshot docs/screenshot-files-light.png --theme light --tab files
```

`--folder <path>` in screenshot mode scans a real folder instead of the demo (add `--no-scan` to stop after the file list). It is for local testing only and must never be used for images that get published.

## Reading files

- `WindowsEvtxReader.Read` reads in slices (`ReadSlice`, half a second). An expired slice is an `EventLogException` whose message equals the Win32 ERROR_TIMEOUT message. Keep that loop: without it a file without findings is one blocking call that ignores cancellation.
- Do not split a file into EventRecordID ranges to show progress. The service scans the whole file for every range, measured 16 times slower.
- Exported logs keep their original record IDs. Progress must use `FirstRecordId` and `LastRecordId` from `Inspect`, not `OldestRecordNumber`.
- `Storage.Detect` picks the number of files scanned at once. Keep the hard disk default at 2.

## Event data without names

Older events (KDC 14/16/26/27, Directory Service 2887/2889/30xx) have unnamed insertion strings. Their queries use `Positional: true` and the classifier reads them with `RawEvent.At(index)`. The order is taken from Microsoft's documented message text. Keep the comments in `Classifier` in sync when you change it.
