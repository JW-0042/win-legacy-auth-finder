using System.Buffers.Binary;
using System.Diagnostics.Eventing.Reader;
using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

/// <summary>
/// The fixes of version 0.4.2, from the second audit (Claude reviewers, Codex and Grok): duplicates across cleared logs,
/// memory, partly read files, wrapped logs with a stale header, XML-style values, and advice that pointed to the wrong
/// account or party.
/// </summary>
[Collection(SerialCollection.Name)]
public sealed class Release042Tests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("laf-042-").FullName;
    private static readonly StringPool Pool = new();
    private static readonly DateTime T0 = new(2026, 10, 1, 8, 0, 0);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string Save(string name, byte[] bytes)
    {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static AuthEvent? Classify(RawEvent e) => Classifier.Classify(e, "f.evtx", Pool);

    private static RawEvent Ev(int id, string provider, params (string Name, string Value)[] data) =>
        new(id, provider, T0, "DC01.lab.local", 1, data.ToDictionary(d => d.Name, d => d.Value));

    private static RawEvent Pos(int id, string provider, params string[] values) =>
        new(id, provider, T0, "DC01.lab.local", 1, new Dictionary<string, string>(), values);

    private static SummaryRow Row(params AuthEvent[] events)
    {
        var rows = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        foreach (var e in events) SummaryRow.Add(rows, e);
        return rows.Values.Single();
    }

    private static (FixTarget Type, string Target, string Problem, string Action) Fix(params AuthEvent[] events) => Remediation.Rule(Row(events));

    /// <summary>Returns every event for every query, like two Windows API queries that both match one record.</summary>
    private sealed class EchoReader(List<RawEvent> events) : IEvtxReader
    {
        public LogFileInfo Inspect(string path) => throw new NotSupportedException();

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null) => events;
    }

    private static RawEvent Rc4(DateTime time, long record, string computer = "DC01") =>
        new(4769, Providers.SecurityAuditing, time, computer, record,
            new Dictionary<string, string> { ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = "bob", ["IpAddress"] = "10.0.0.9", ["ServiceName"] = "svc-sql" });

    private static LogFileInfo Security(string path, long first, long last, DateTime from, DateTime to) =>
        new(path, 1000, Channels.Security, "DC01", last - first + 1, first, from, to, FirstRecordId: first, LastRecordId: last);

    // ---------------- Scanner ----------------

    [Fact]
    public void A_cleared_log_next_to_an_old_archive_is_not_a_duplicate()
    {
        // Record IDs start again at 1 after a log is cleared: same IDs, different events.
        var old = new DateTime(2025, 3, 1);
        var reader = new FakeReader();
        reader.Events["old.evtx"] = [Rc4(old, 1), Rc4(old.AddMinutes(1), 2), Rc4(old.AddMinutes(2), 3)];
        reader.Events["new.evtx"] = [Rc4(T0, 1), Rc4(T0.AddMinutes(1), 2), Rc4(T0.AddMinutes(2), 3)];
        LogFileInfo[] files = [Security("old.evtx", 1, 3, old, old.AddMinutes(2)), Security("new.evtx", 1, 3, T0, T0.AddMinutes(2))];
        Assert.Empty(Scanner.Overlaps(files));
        var r = Scanner.Scan(reader, files, "t", new ScanOptions());
        Assert.Equal(6, r.TotalHits);
        Assert.Equal(0, r.Duplicates);
    }

    [Fact]
    public void Overlapping_copies_still_count_each_record_once()
    {
        var reader = new FakeReader();
        reader.Events["weekly.evtx"] = [Rc4(T0, 1), Rc4(T0.AddMinutes(1), 2), Rc4(T0.AddMinutes(2), 3)];
        reader.Events["daily.evtx"] = [Rc4(T0.AddMinutes(1), 2), Rc4(T0.AddMinutes(2), 3), Rc4(T0.AddMinutes(3), 4)];
        LogFileInfo[] files = [Security("weekly.evtx", 1, 3, T0, T0.AddMinutes(2)), Security("daily.evtx", 2, 4, T0.AddMinutes(1), T0.AddMinutes(3))];
        var r = Scanner.Scan(reader, files, "t", new ScanOptions(Threads: 2));
        Assert.Equal(4, r.TotalHits);
        Assert.Equal(2, r.Duplicates);
    }

    [Fact]
    public void A_record_two_queries_return_is_counted_once_and_not_as_a_duplicate()
    {
        var reader = new EchoReader([Rc4(T0, 7)]);
        var r = Scanner.Scan(reader, [Security("a.evtx", 7, 7, T0, T0)], "t", new ScanOptions());
        Assert.Equal(1, r.TotalHits);
        Assert.Equal(0, r.Duplicates);
    }

    [Fact]
    public void The_event_list_keeps_the_newest_events_across_files_and_batches()
    {
        // More events per file than one batch, so the shared list fills up and the cutoff is used.
        const int PerFile = 70_000;
        var reader = new FakeReader();
        var data = new Dictionary<string, string> { ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = "bob", ["IpAddress"] = "10.0.0.9", ["ServiceName"] = "svc-sql" };
        var files = new List<LogFileInfo>();
        for (var f = 0; f < 3; f++)
        {
            var path = $"f{f}.evtx";
            reader.Events[path] = [.. Enumerable.Range(0, PerFile).Select(i => new RawEvent(4769, Providers.SecurityAuditing, T0.AddSeconds(i * 3 + f), $"DC{f}", i + 1, data))];
            files.Add(new LogFileInfo(path, 1000, Channels.Security, $"DC{f}", PerFile, 1, null, null));
        }
        var r = Scanner.Scan(reader, files, "t", new ScanOptions(Threads: 3, MaxEvents: 1000));
        Assert.Equal(3L * PerFile, r.TotalHits);
        Assert.True(r.Truncated);
        Assert.Equal(1000, r.Events.Count);
        var newest = Enumerable.Range(0, 3).SelectMany(f => Enumerable.Range(0, PerFile).Select(i => T0.AddSeconds(i * 3 + f))).OrderDescending().Take(1000).ToList();
        Assert.Equal(newest.Order(), r.Events.Select(e => e.Time));
    }

    [Fact]
    public void A_file_cut_off_inside_a_chunk_is_partly_read()
    {
        var chunk = new EvtxWriter().Add(new(100, 4769, Providers.SecurityAuditing,
            [new("TargetUserName", 0x01, EvtxWriter.Utf16("bob")), new("TicketEncryptionType", 0x14, EvtxWriter.U32(0x17))])).Chunk();
        var bytes = EvtxWriter.File(0, chunk, new byte[EvtxFileReader.ChunkSize]);
        var path = Save("cut.evtx", bytes.AsSpan(0, bytes.Length - 1000).ToArray());
        var stats = new ReadStats();
        Assert.Single(new EvtxFileReader().ReadAll(path, [Queries.Kerberos], CancellationToken.None, null, stats));
        Assert.True(stats.MissingBytes > 0);
        var r = Scanner.Scan(new EvtxFileReader(), [new EvtxFileReader().Inspect(path)], "t", new ScanOptions());
        Assert.Equal(FileState.Error, r.FileResults[path].State);
        Assert.Contains("cut off", r.FileResults[path].Message);
        Assert.True(r.Incomplete);
    }

    [Fact]
    public void The_windows_api_fallback_returns_a_record_once_although_two_queries_match()
    {
        var path = Save("not-evtx.evtx", "not an event log"u8.ToArray());
        var tgt = new RawEvent(4768, Providers.SecurityAuditing, T0, "DC01", 5,
            new Dictionary<string, string> { ["PreAuthType"] = "0", ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = "svc-old" });
        var reader = new EvtxFileReader(new EchoReader([tgt]));
        var stats = new ReadStats();
        Assert.Single(reader.ReadAll(path, [Queries.Kerberos, Queries.NoPreAuth], CancellationToken.None, null, stats));
        Assert.NotNull(stats.Fallback);
    }

    [Fact]
    public void Paths_that_differ_only_in_case_are_two_files()
    {
        var reader = new FakeReader();
        reader.Events["Sec.evtx"] = [Rc4(T0, 1)];
        reader.Events["sec.evtx"] = [Rc4(T0.AddDays(-30), 1, "DC02")];
        LogFileInfo[] files = [Security("Sec.evtx", 1, 1, T0, T0), Security("sec.evtx", 1, 1, T0.AddDays(-30), T0.AddDays(-30)) with { Computer = "DC02" }];
        var r = Scanner.Scan(new CaseReader(reader), files, "t", new ScanOptions());
        Assert.Equal(2, r.FileResults.Count);
    }

    /// <summary>FakeReader keys paths case-insensitively, this one exactly.</summary>
    private sealed class CaseReader(FakeReader inner) : IEvtxReader
    {
        public LogFileInfo Inspect(string path) => throw new NotSupportedException();

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null) =>
            inner.Events.Where(kv => kv.Key == path).SelectMany(kv => kv.Value).Where(e => DemoData.QueryOf(e) == query);
    }

    [Fact]
    public void An_unknown_disk_is_read_like_a_hard_disk() => Assert.Equal(2, Storage.RecommendedThreads(StorageKind.Unknown));

    // ---------------- Parser ----------------

    private static byte[] Chunk(long first, int count)
    {
        var w = new EvtxWriter();
        for (var i = 0; i < count; i++) w.Add(new(first + i, 4769, Providers.SecurityAuditing, [new("TicketEncryptionType", 0x14, EvtxWriter.U32(0x17))]));
        return w.Chunk(firstNumber: first);
    }

    [Fact]
    public void A_full_log_copied_with_a_stale_header_is_read_from_its_real_oldest_chunk()
    {
        // Physically: chunk 0 holds the newest records (31 to 40), chunk 1 the oldest (11 to 20). The header still says
        // chunk 0 is the oldest and chunk 2 the newest: a full DC Security log copied while Windows was writing.
        var path = Save("stale.evtx", EvtxWriter.File(0, 2, Chunk(31, 10), Chunk(11, 10), Chunk(21, 10)));
        var info = new EvtxFileReader().Inspect(path);
        Assert.Equal((11L, 40L), (info.FirstRecordId, info.LastRecordId));
        var ids = new EvtxFileReader().ReadAll(path, [Queries.Kerberos], CancellationToken.None).Select(x => x.Event.RecordId).ToList();
        Assert.Equal(Enumerable.Range(11, 30).Select(i => (long)i), ids);
    }

    [Fact]
    public void A_header_chunk_number_past_the_end_counts_around_the_file()
    {
        // Two chunks, the header says the oldest is chunk 3 (that is chunk 1 of 2).
        var path = Save("absolute.evtx", EvtxWriter.File(3, 2, Chunk(31, 5), Chunk(21, 5)));
        Assert.Equal(21, new EvtxFileReader().Inspect(path).FirstRecordId);
    }

    [Fact]
    public void Records_written_after_a_chunk_header_with_no_free_space_are_recovered()
    {
        var w = new EvtxWriter();
        for (var i = 0; i < 3; i++) w.Add(new(100 + i, 4769, Providers.SecurityAuditing, [new("TicketEncryptionType", 0x14, EvtxWriter.U32(0x17))]));
        var path = Save("header-first.evtx", EvtxWriter.File(0, w.Chunk(firstNumber: 100, free: 512, firstId: 100)));
        var stats = new ReadStats();
        Assert.Equal(3, new EvtxFileReader().ReadAll(path, [Queries.Kerberos], CancellationToken.None, null, stats).Count());
        Assert.Equal(3, stats.RecordsPastFree);
    }

    [Fact]
    public void Inspect_sees_the_records_the_scan_recovers_past_the_free_space()
    {
        var w = new EvtxWriter();
        for (var i = 0; i < 3; i++) w.Add(new(100 + i, 4769, Providers.SecurityAuditing, [new("TicketEncryptionType", 0x14, EvtxWriter.U32(0x17))]));
        var path = Save("dirty.evtx", EvtxWriter.File(0, w.Chunk(firstNumber: 100, free: w.RecordOffsets[1])));
        Assert.Equal(102, new EvtxFileReader().Inspect(path).LastRecordId);
    }

    private static ParsedRecord One(string path) => EvtxFileReader.ReadEverything(path).Single();

    private static byte[] Ints(params int[] values) => [.. values.SelectMany(v => EvtxWriter.U32((uint)v))];

    [Fact]
    public void A_string_array_in_a_top_level_unnamed_data_stays_one_value()
    {
        // Windows splits the array only in classic events, where it sits in a nested template instance.
        var path = Save("array.evtx", EvtxWriter.File(0, new EvtxWriter().Add(new(1, 1004, "Probe",
            [new(null, 0x81, EvtxWriter.Utf16("p\0q\0r\0")), new(null, 0x01, EvtxWriter.Utf16("s"))])).Chunk()));
        Assert.Equal(["System.String[]", "s"], One(path).Positional);
    }

    [Fact]
    public void Xml_style_values_follow_the_windows_xml()
    {
        var time = new byte[16];
        ushort[] parts = [2026, 3, 3, 4, 5, 6, 7, 89];
        for (var i = 0; i < 8; i++) BinaryPrimitives.WriteUInt16LittleEndian(time.AsSpan(i * 2), parts[i]);
        var path = Save("xml.evtx", EvtxWriter.File(0, new EvtxWriter().Add(new(1, 1000, "Probe",
        [
            new("Numbers", 0x87, Ints(1, -2)),
            new("Hex", 0x94, Ints(1, 255)),
            new("When", 0x12, time),
            new("Small", 0x03, [0xFE]),
            new("Control", 0x01, EvtxWriter.Utf16("a\u0001b")),
        ])).Chunk()));
        var r = One(path);
        // Every array item is its own element, a SYSTEMTIME is UTC already, SByte is signed in XML but a Byte as a property.
        Assert.Equal(["1", "-2", "0x1", "0xff", "2026-03-04T05:06:07.0890000Z", "-2", "a_b"], r.Xml.Values);
        Assert.Equal("254", r.Named["Small"]);
    }

    // ---------------- Detection and advice ----------------

    [Fact]
    public void Kdc_event_16_points_to_the_account_in_its_sixth_string()
    {
        var e = Classify(Pos(16, Providers.Kdc, "cifs/netappcifs", "user@LAB.LOCAL", "1", "18 17 23", "23", "NETAPPCIFS"))!;
        Assert.Equal(("NETAPPCIFS", "user@LAB.LOCAL"), (e.Account, e.Client));
        var fix = Fix(e);
        Assert.Equal((FixTarget.ServiceAccount, "NETAPPCIFS"), (fix.Type, fix.Target));
        Assert.DoesNotContain("user@LAB.LOCAL", fix.Action);
    }

    [Fact]
    public void A_request_without_aes_to_an_account_with_aes_points_to_the_requester()
    {
        var e = Classify(Pos(27, Providers.Kdc, "http/foo", "abc@DOMAIN.COM", "1", "23 3 1", "23 18 17"))!;
        Assert.Contains("without AES", e.Variant);
        Assert.Equal(FixTarget.Client, Fix(e).Type);
        Assert.DoesNotContain("Reset the password", Fix(e).Action);
    }

    [Fact]
    public void A_failed_service_ticket_without_key_data_points_to_the_target_service()
    {
        // Microsoft's own example: every key field is "-", the target vm01 allows only RC4.
        var e = Classify(Ev(4769, Providers.SecurityAuditing, ("Status", "0xE"), ("TargetUserName", "adele@CONTOSO.COM"), ("ServiceName", "HOST/vm01.contoso.com"),
            ("AccountAvailableKeys", "-"), ("ServiceAvailableKeys", "-"), ("ClientAdvertizedEncryptionTypes", "-")))!;
        var fix = Fix(e);
        Assert.Equal((FixTarget.ServiceAccount, "HOST/vm01.contoso.com"), (fix.Type, fix.Target));
        Assert.Contains("setspn -Q HOST/vm01.contoso.com", fix.Action);
        Assert.DoesNotContain("adele", fix.Action);
    }

    [Fact]
    public void Service_account_advice_puts_the_keys_before_aes_only()
    {
        var e = Classify(Ev(4769, Providers.SecurityAuditing, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob"), ("ServiceName", "svc-sql")))!;
        var action = Fix(e).Action;
        Assert.True(action.IndexOf("Reset the password", StringComparison.Ordinal) < action.IndexOf("AES only (0x18)", StringComparison.Ordinal));
        Assert.Contains("keytab", action);
        Assert.Contains("0x24", action);
    }

    [Fact]
    public void A_name_with_a_dollar_sign_gets_advice_for_computers_and_managed_service_accounts()
    {
        var e = Classify(Ev(4769, Providers.SecurityAuditing, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob"), ("ServiceName", "svc-sql$")))!;
        var fix = Fix(e);
        Assert.Equal(FixTarget.ComputerAccount, fix.Type);
        Assert.Contains("Set-ADServiceAccount", fix.Action);
    }

    [Fact]
    public void Rc4_tgts_from_a_krbtgt_without_aes_point_to_krbtgt()
    {
        var e = Classify(Ev(4768, Providers.SecurityAuditing, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob"), ("ServiceName", "krbtgt"),
            ("PreAuthType", "2"), ("ServiceAvailableKeys", "RC4")))!;
        var fix = Fix(e);
        Assert.Equal((FixTarget.DomainControllers, "krbtgt"), (fix.Type, fix.Target));
        Assert.Contains("twice", fix.Action);
    }

    [Fact]
    public void Rc4_pre_authentication_from_a_client_without_aes_points_to_the_client()
    {
        var e = Classify(Ev(4768, Providers.SecurityAuditing, ("TicketEncryptionType", "0x12"), ("PreAuthEncryptionType", "0x17"), ("PreAuthType", "2"),
            ("TargetUserName", "bob"), ("ServiceName", "krbtgt"), ("IpAddress", "10.0.0.5"), ("ClientAdvertizedEncryptionTypes", "RC4-HMAC-NT")))!;
        Assert.Equal((FixTarget.Client, "10.0.0.5"), (Fix(e).Type, Fix(e).Target));
    }

    [Fact]
    public void An_account_without_pre_authentication_and_rc4_tickets_also_gets_the_aes_advice()
    {
        var e = Classify(Ev(4768, Providers.SecurityAuditing, ("PreAuthType", "0"), ("Status", "0x0"), ("TargetUserName", "svc-old"), ("TicketEncryptionType", "0x17")))!;
        Assert.Equal(LegacyKind.NoPreAuth, e.Kind);
        Assert.Contains("reset the password so it gets AES keys", Fix(e).Action);
    }

    [Theory]
    [InlineData(4004)]
    [InlineData(4005)]
    [InlineData(4006)]
    public void Ntlm_blocked_on_a_domain_controller_is_found(int id)
    {
        var e = Classify(Ev(id, Providers.Netlogon, ("SChannelName", "WS01$"), ("UserName", "bob"), ("DomainName", "LAB"), ("WorkstationName", "WS01")))!;
        Assert.Equal((LegacyKind.Ntlm, "bob", "WS01"), (e.Kind, e.Account, e.Client));
        Assert.Contains("blocked", Fix(e).Problem);
        Assert.Contains(id, Queries.NtlmOperational.EventIds!);
    }

    [Fact]
    public void A_local_sign_in_logged_as_4776_is_not_ntlm_use()
    {
        var local = new RawEvent(4776, Providers.SecurityAuditing, T0, "SRV01.lab.local", 1,
            new Dictionary<string, string> { ["TargetUserName"] = "admin", ["Workstation"] = "SRV01", ["Status"] = "0x0" });
        Assert.Null(Classify(local));
        Assert.NotNull(Classify(local with { Data = new Dictionary<string, string> { ["TargetUserName"] = "admin", ["Workstation"] = "WS07", ["Status"] = "0x0" } }));
    }

    [Fact]
    public void Ntlmv1_single_sign_on_advice_does_not_suggest_credential_guard_as_a_fix()
    {
        // 4013 is NTLMv1 single sign-on that Credential Guard blocked.
        var e = Classify(Ev(4013, Providers.Ntlm, ("TargetName", "vpn01"), ("UserName", "bob")))!;
        var fix = Fix(e);
        Assert.Equal("Single sign-on with NTLMv1-derived credentials", fix.Problem);
        Assert.Contains("EAP-TLS", fix.Action);
        Assert.DoesNotContain("turn on Credential Guard", fix.Action);
    }

    [Fact]
    public void Kdc_warnings_with_the_same_names_get_a_row_per_event()
    {
        AuthEvent Warn(int id) => Classify(Ev(id, Providers.KdcSvc, ("AccountName", "bob"), ("ServiceName", "svc-app"), ("IpAddress", "10.0.0.5")))!;
        var rows = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        SummaryRow.Add(rows, Warn(206));
        SummaryRow.Add(rows, Warn(207));
        Assert.Equal(2, rows.Count);
        var fixes = Remediation.Build(rows.Values);
        Assert.Contains(fixes, f => f.TargetType == FixTarget.Client);
        Assert.Contains(fixes, f => f.TargetType == FixTarget.ServiceAccount);
    }

    [Fact]
    public void The_same_name_in_two_domains_is_pointed_out()
    {
        AuthEvent Logon(string domain) => Classify(Ev(4624, Providers.SecurityAuditing, ("LmPackageName", "NTLM V1"), ("TargetUserName", "Administrator"),
            ("TargetDomainName", domain), ("WorkstationName", "OLDPC")))!;
        string Action(params AuthEvent[] events) => Remediation.Build([Row(events)]).Single().Action;
        Assert.Contains("more than one domain", Action(Logon("CONTOSO"), Logon("FABRIKAM")));
        // NetBIOS and DNS name of one domain are the same domain.
        Assert.DoesNotContain("more than one domain", Action(Logon("CONTOSO"), Logon("contoso.local")));
    }

    [Fact]
    public void Pre_authentication_type_is_shown_in_hex() => Assert.Equal("0x17", WindowsEvtxReader.Format("PreAuthEncryptionType", 23u));

    [Fact]
    public void Fix_items_know_their_summary_rows()
    {
        var result = DemoData.Create(T0);
        Assert.All(result.Fixes, f => Assert.Equal(f.Rows, f.SourceRows.Count));
        Assert.Equal(result.TotalHits, result.Fixes.Sum(f => f.SourceRows.Sum(r => r.Count)));
    }
}
