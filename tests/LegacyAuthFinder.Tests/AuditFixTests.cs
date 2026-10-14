using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

/// <summary>Fixes from the 0.4.1 code audit: scan engine, storage, detection and fix rules.</summary>
public class AuditFixTests
{
    private static readonly StringPool Pool = new();

    private static RawEvent Ev(int id, string provider, long record = 1, params (string, string)[] data) =>
        new(id, provider, new DateTime(2026, 10, 1, 10, 0, 0), "DC01.lab.local", record,
            data.ToDictionary(d => d.Item1, d => d.Item2, StringComparer.OrdinalIgnoreCase));

    private static AuthEvent? Classify(RawEvent e) => Classifier.Classify(e, "f.evtx", Pool);

    private sealed class ThrowingReader(string bad) : IEvtxReader
    {
        public LogFileInfo Inspect(string path) => throw new NotSupportedException();

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken, Action? alive = null)
        {
            if (path == bad) throw new InvalidOperationException("something nobody expected");
            if (query == Queries.Kerberos)
            {
                yield return Ev(4769, Providers.SecurityAuditing, 5, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob"), ("ServiceName", "svc"));
            }
        }
    }

    private static LogFileInfo Security(string path, long first = 0, long last = 0) =>
        new(path, 1000, "Security", "DC01.lab.local", 10, 1, null, null, FirstRecordId: first, LastRecordId: last);

    [Fact]
    public void An_unexpected_error_in_one_file_keeps_the_rest_of_the_scan()
    {
        var r = Scanner.Scan(new ThrowingReader("bad.evtx"), [Security("bad.evtx"), Security("good.evtx")], "t", new ScanOptions(Threads: 2));
        Assert.Equal(FileState.Error, r.FileResults["bad.evtx"].State);
        Assert.Equal(FileState.Done, r.FileResults["good.evtx"].State);
        Assert.Equal(1, r.TotalHits);
        Assert.True(r.Incomplete);
        Assert.Equal(1, r.FailedFiles);
    }

    [Fact]
    public void Overlapping_exports_count_their_shared_records_once()
    {
        var reader = new FakeReader();
        RawEvent Rc4(long id) => Ev(4769, Providers.SecurityAuditing, id, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob"), ("ServiceName", "svc"));
        reader.Events["a.evtx"] = [Rc4(100), Rc4(101), Rc4(102)];
        reader.Events["b.evtx"] = [Rc4(101), Rc4(102), Rc4(103)];
        // A third file of another log with the same record numbers is not a duplicate.
        reader.Events["c.evtx"] = [Rc4(101)];
        LogFileInfo[] files = [Security("a.evtx", 100, 102), Security("b.evtx", 101, 103), Security("c.evtx", 101, 101) with { Computer = "DC02.lab.local" }];
        Assert.Single(Scanner.Overlaps(files));
        var r = Scanner.Scan(reader, files, "t", new ScanOptions(Threads: 1));
        Assert.Equal(5, r.TotalHits);
        Assert.Equal(2, r.Duplicates);
    }

    [Fact]
    public void The_event_list_keeps_the_newest_events()
    {
        var reader = new FakeReader();
        reader.Events["a.evtx"] = Enumerable.Range(1, 50).Select(i => new RawEvent(4769, Providers.SecurityAuditing, new DateTime(2026, 1, 1).AddDays(i), "DC01", i,
            new Dictionary<string, string> { ["TicketEncryptionType"] = "0x17", ["TargetUserName"] = "bob" })).ToList();
        var r = Scanner.Scan(reader, [Security("a.evtx")], "t", new ScanOptions(MaxEvents: 10));
        Assert.True(r.Truncated);
        Assert.Equal(50, r.TotalHits);
        Assert.Equal(10, r.Events.Count);
        Assert.Equal(new DateTime(2026, 1, 1).AddDays(41), r.Events[0].Time);
        Assert.Equal(new DateTime(2026, 1, 1).AddDays(50), r.Events[^1].Time);
    }

    [Fact]
    public void Storage_understands_long_and_network_paths()
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        Assert.NotNull(Storage.Volume(windows, out var network));
        Assert.False(network);
        Assert.NotNull(Storage.Volume(@"\\?\" + windows, out network));
        Assert.False(network);
        Storage.Volume(@"\\fileserver\logs", out network);
        Assert.True(network);
        Storage.Volume(@"\\?\UNC\fileserver\logs", out network);
        Assert.True(network);
        Assert.Equal(StorageKind.Network, Storage.Detect(@"\\fileserver\logs"));
    }

    [Fact]
    public void Anonymous_logons_are_not_ntlmv1()
    {
        Assert.Null(Classify(Ev(4624, Providers.SecurityAuditing, 1, ("LmPackageName", "NTLM V1"), ("TargetUserName", "ANONYMOUS LOGON"), ("TargetUserSid", "S-1-5-7"))));
        Assert.Null(Classify(Ev(4624, Providers.SecurityAuditing, 1, ("LmPackageName", "NTLM V1"), ("TargetUserName", "x"), ("TargetUserSid", Classifier.AnonymousSid))));
        Assert.NotNull(Classify(Ev(4624, Providers.SecurityAuditing, 1, ("LmPackageName", "NTLM V1"), ("TargetUserName", "bob"), ("TargetUserSid", "S-1-5-21-1-2-3-1105"))));
    }

    [Theory]
    [InlineData("bob@LAB.LOCAL", "", "bob", "LAB.LOCAL")]
    [InlineData("bob@LAB.LOCAL", "LAB", "bob", "LAB")]
    [InlineData("bob", "LAB", "bob", "LAB")]
    [InlineData("@x", "", "@x", "")]
    public void Realm_is_split_from_the_account(string account, string domain, string expectedAccount, string expectedDomain) =>
        Assert.Equal((expectedAccount, expectedDomain), Classifier.SplitRealm(account, domain));

    [Theory]
    [InlineData("AES256-CTS-HMAC-SHA1-96, RC4-HMAC-NT", true)]
    [InlineData("0x12 0x17", true)]
    [InlineData("18 17 23", true)]
    [InlineData("RC4-HMAC-NT", false)]
    [InlineData("DES-CBC-MD5, DES-CBC-CRC", false)]
    [InlineData("", false)]
    public void Aes_is_recognized_in_type_lists(string list, bool expected) => Assert.Equal(expected, Classifier.HasAes(list));

    [Fact]
    public void Etype_failures_blame_the_side_without_aes()
    {
        AuthEvent Fail(params (string, string)[] extra) => Classify(Ev(4769, Providers.SecurityAuditing, 1,
            [("Status", "0xe"), ("TargetUserName", "bob@LAB.LOCAL"), ("ServiceName", "svc-old"), .. extra]))!;
        Assert.StartsWith("No common encryption type, client offered", Fail(("ClientAdvertizedEncryptionTypes", "DES-CBC-MD5")).Variant);
        var service = Fail(("ClientAdvertizedEncryptionTypes", "AES256-CTS-HMAC-SHA1-96"), ("ServiceAvailableKeys", "RC4"));
        Assert.Contains("service account has no AES keys", service.Variant);
        Assert.Equal(("bob", "LAB.LOCAL"), (service.Account, service.Domain));
        Assert.Equal("No common encryption type (0xE)", Fail(("ClientAdvertizedEncryptionTypes", "AES256-CTS-HMAC-SHA1-96"), ("ServiceAvailableKeys", "AES-SHA1, RC4")).Variant);
    }

    [Fact]
    public void Tgt_without_pre_authentication_is_found()
    {
        var e = Classify(Ev(4768, Providers.SecurityAuditing, 1, ("PreAuthType", "0"), ("Status", "0x0"), ("TargetUserName", "svc-old"), ("TicketEncryptionType", "0x17")))!;
        Assert.Equal(LegacyKind.NoPreAuth, e.Kind);
        Assert.Contains("RC4-HMAC", e.Variant);
        // A failed request with type 0 is not a roastable ticket.
        Assert.NotEqual(LegacyKind.NoPreAuth, Classify(Ev(4768, Providers.SecurityAuditing, 1, ("PreAuthType", "0"), ("Status", "0x6"), ("TicketEncryptionType", "0x17")))?.Kind);
        Assert.Equal((FixTarget.Account, "svc-old"), (Remediation.Rule(Row(e)).Item1, Remediation.Rule(Row(e)).Item2));
    }

    [Fact]
    public void Rc4_pre_authentication_is_found_and_points_to_the_account()
    {
        var e = Classify(Ev(4768, Providers.SecurityAuditing, 1, ("PreAuthType", "2"), ("TargetUserName", "old-admin"), ("ServiceName", "krbtgt"),
            ("TicketEncryptionType", "0x12"), ("SessionKeyEncryptionType", "0x12"), ("PreAuthEncryptionType", "0x17")))!;
        Assert.Equal(LegacyKind.Rc4, e.Kind);
        Assert.Equal("Pre-auth RC4-HMAC", e.Variant);
        var (type, target, _, _) = Remediation.Rule(Row(e));
        Assert.Equal((FixTarget.Account, "old-admin"), (type, target));
    }

    [Fact]
    public void Ntlm_validation_and_new_ntlm_events_are_read()
    {
        var v = Classify(Ev(4776, Providers.SecurityAuditing, 1, ("TargetUserName", "bob"), ("Workstation", "PC7"), ("Status", "0x0")))!;
        Assert.Equal((LegacyKind.Ntlm, "bob", "PC7"), (v.Kind, v.Account, v.Client));
        Assert.Equal(LegacyKind.Ntlmv1, Classify(Ev(4013, Providers.Ntlm, 1, ("TargetName", "fs01"), ("UserName", "bob")))!.Kind);
        Assert.Contains("would be blocked", Classify(Ev(4026, Providers.Ntlm, 1, ("Username", "bob"), ("NtlmVersion", "2")))!.Variant);
        Assert.Contains("blocked by policy", Classify(Ev(4027, Providers.Ntlm, 1, ("Username", "bob")))!.Variant);
        var server = Classify(Ev(4002, Providers.Ntlm, 1, ("ClientUserName", "SYSTEM")))!;
        Assert.Equal(("", "DC01"), (server.Account, server.Service));
        Assert.Equal(FixTarget.Server, Remediation.Rule(Row(server)).Item1);
    }

    [Fact]
    public void Ldap_daily_summaries_for_rejected_and_ldaps_binds()
    {
        var rejected = Classify(new RawEvent(2888, Providers.DirectoryService, DateTime.Now, "DC01", 1, new Dictionary<string, string>(), ["3", "7"]))!;
        Assert.Contains("rejected", rejected.Variant);
        Assert.Equal(FixTarget.DomainControllers, Remediation.Rule(Row(rejected)).Item1);
        var cbt = Classify(new RawEvent(3040, Providers.DirectoryService, DateTime.Now, "DC01", 1, new Dictionary<string, string>(), ["12"]))!;
        Assert.Equal(LegacyKind.LdapChannelBinding, cbt.Kind);
        Assert.Contains("12 LDAPS binds", cbt.Variant);
        Assert.Equal(FixTarget.DomainControllers, Remediation.Rule(Row(cbt)).Item1);
        Assert.Equal("localhost", Classifier.LdapClient("[::1]:389"));
        Assert.Equal("localhost", Classifier.LdapClient("127.0.0.1:50000"));
    }

    [Fact]
    public void Computer_accounts_get_computer_advice()
    {
        var e = Classify(Ev(4769, Providers.SecurityAuditing, 1, ("TicketEncryptionType", "0x17"), ("TargetUserName", "bob@LAB"), ("ServiceName", "OLD-APP$")))!;
        var (type, target, _, action) = Remediation.Rule(Row(e));
        Assert.Equal((FixTarget.ComputerAccount, "OLD-APP$"), (type, target));
        Assert.Contains("Configure encryption types allowed for Kerberos", action);
    }

    [Theory]
    [InlineData(201, FixTarget.Client)]
    [InlineData(203, FixTarget.Client)]
    [InlineData(206, FixTarget.Client)]
    [InlineData(208, FixTarget.Client)]
    [InlineData(202, FixTarget.ServiceAccount)]
    [InlineData(204, FixTarget.ServiceAccount)]
    [InlineData(207, FixTarget.ServiceAccount)]
    [InlineData(209, FixTarget.ServiceAccount)]
    [InlineData(205, FixTarget.DomainPolicy)]
    public void Kdc_events_point_where_microsoft_says(int id, FixTarget expected)
    {
        var e = Classify(Ev(id, Providers.KdcSvc, 1, ("AccountName", "bob"), ("ServiceName", "svc-hr")))!;
        var (type, target, _, _) = Remediation.Rule(Row(e));
        Assert.Equal(expected, type);
        if (expected == FixTarget.ServiceAccount) Assert.Equal("svc-hr", target);
    }

    [Fact]
    public void Csv_can_use_the_regional_separator()
    {
        using var w = new StringWriter();
        Reports.WriteFixesCsv(w, DemoData.Create(DateTime.Now).Fixes, ';');
        var lines = w.ToString().Split('\n');
        Assert.StartsWith("Rank;Type;FixOn;Target", lines[0]);
        Assert.Equal("\"a;b\"", Reports.Csv("a;b", ';'));
    }

    [Fact]
    public void Json_report_streams_and_marks_incomplete_results()
    {
        var demo = DemoData.Create(DateTime.Now) with { Cancelled = true };
        using var stream = new MemoryStream();
        Reports.WriteJson(stream, demo);
        using var doc = System.Text.Json.JsonDocument.Parse(stream.ToArray());
        Assert.True(doc.RootElement.GetProperty("incomplete").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("totals").GetProperty("noPreAuth").GetInt64() > 0);
        Assert.Equal(Reports.Version, doc.RootElement.GetProperty("version").GetString());
    }

    private static SummaryRow Row(AuthEvent e)
    {
        var rows = new Dictionary<SummaryKey, SummaryRow>(SummaryKey.Comparer);
        SummaryRow.Add(rows, e);
        return rows.Values.Single();
    }
}
