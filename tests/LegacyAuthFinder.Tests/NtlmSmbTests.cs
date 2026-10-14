using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

/// <summary>NTLM Operational (4020 to 4025, 4030 to 4033, 8001 to 8004) and SMBServer Audit (3000).</summary>
public class NtlmSmbTests
{
    private static readonly StringPool Pool = new();

    private static RawEvent Ev(int id, string provider, params (string, string)[] data) =>
        new(id, provider, new DateTime(2026, 10, 1, 10, 0, 0), "APP02.lab.local", 7,
            data.ToDictionary(d => d.Item1, d => d.Item2, StringComparer.OrdinalIgnoreCase));

    private static AuthEvent? Classify(RawEvent e) => Classifier.Classify(e, "Archive-NTLM.evtx", Pool);

    [Fact]
    public void Outgoing_ntlm_names_the_reason_and_the_target()
    {
        var e = Classify(Ev(4020, Providers.Ntlm, ("Username", "svc-report"), ("DomainName", "LAB"), ("Hostname", "APP02"),
            ("TargetMachine", "10.0.10.21"), ("TargetIP", "10.0.10.21"), ("NtlmUsageId", "7"), ("NtlmUsageReason", "whatever the text is"), ("NtlmVersion", "2")));
        Assert.NotNull(e);
        Assert.Equal(LegacyKind.Ntlm, e.Kind);
        Assert.Equal("svc-report", e.Account);
        Assert.Equal("APP02", e.Client);
        Assert.Equal("10.0.10.21", e.Service);
        Assert.Equal("Outgoing NTLMv2, target name is an IP address", e.Variant);
        Assert.Contains(e.Fields, f => f.Key == "Reason" && f.Value == "target name is an IP address");
    }

    [Fact]
    public void Unknown_reason_ids_fall_back_to_the_logged_text()
    {
        var e = Classify(Ev(4020, Providers.Ntlm, ("Username", "a"), ("NtlmUsageId", "42"), ("NtlmUsageReason", "Some new reason"), ("NtlmVersion", "NTLMv2")));
        Assert.Equal("Outgoing NTLMv2, Some new reason", e!.Variant);
    }

    [Theory]
    [InlineData(4021, "1", LegacyKind.Ntlmv1)]
    [InlineData(4023, "NTLMv1", LegacyKind.Ntlmv1)]
    [InlineData(4022, "2", LegacyKind.Ntlm)]
    [InlineData(4023, "2", LegacyKind.Ntlm)]
    public void Ntlm_version_1_in_the_enhanced_events_counts_as_ntlmv1(int id, string version, LegacyKind expected)
    {
        var e = Classify(Ev(id, Providers.Ntlm, ("Username", "j.novak"), ("DomainName", "LAB"), ("ClientIP", "::ffff:10.0.30.7"),
            ("RemoteClientMachine", "LEGACY-XP01"), ("Hostname", "APP02"), ("NtlmVersion", version)));
        Assert.Equal(expected, e!.Kind);
        if (id is 4022 or 4023) Assert.Equal("LEGACY-XP01", e.Client);
    }

    [Fact]
    public void A_downgrade_warning_without_ntlmv1_is_marked()
    {
        var e = Classify(Ev(4023, Providers.Ntlm, ("Username", "u"), ("ClientIP", "10.0.0.9"), ("NtlmVersion", "2")));
        Assert.Equal(LegacyKind.Ntlm, e!.Kind);
        Assert.EndsWith("security downgrade", e.Variant);
    }

    [Theory]
    [InlineData(4032, "2", LegacyKind.Ntlm)]
    [InlineData(4033, "1", LegacyKind.Ntlmv1)]
    public void Domain_controller_events_name_account_machine_and_server(int id, string version, LegacyKind expected)
    {
        var e = Classify(Ev(id, Providers.Netlogon, ("AccountName", "h.simon"), ("AccountDomain", "LAB"), ("AccountMachine", "KIOSK-03"),
            ("ServerName", "FS01"), ("NtlmVersion", version), ("DCName", "DC01")));
        Assert.Equal(expected, e!.Kind);
        Assert.Equal("h.simon", e.Account);
        Assert.Equal("KIOSK-03", e.Client);
        Assert.Equal("FS01", e.Service);
    }

    [Theory]
    [InlineData(4024, "(audit)")]
    [InlineData(4025, "blocked")]
    public void Ntlmv1_derived_single_sign_on_is_ntlmv1(int id, string ending)
    {
        var e = Classify(Ev(id, Providers.Ntlm, ("TargetName", "vpn01.lab.local"), ("UserName", "m.kovac"), ("DomainName", "LAB")));
        Assert.Equal(LegacyKind.Ntlmv1, e!.Kind);
        Assert.Equal("m.kovac", e.Account);
        Assert.Equal("APP02", e.Client);
        Assert.Equal("vpn01.lab.local", e.Service);
        Assert.Contains("single sign-on", e.Variant);
        Assert.EndsWith(ending, e.Variant);
    }

    [Fact]
    public void Old_audit_events_are_read()
    {
        var e8004 = Classify(Ev(8004, Providers.Netlogon, ("SChannelName", "FS01"), ("UserName", "scanner"), ("DomainName", "LAB"), ("WorkstationName", "PRN-OLD-1F")));
        Assert.Equal(("scanner", "PRN-OLD-1F", "FS01"), (e8004!.Account, e8004.Client, e8004.Service));
        var e8003 = Classify(Ev(8003, Providers.Ntlm, ("UserName", "bob"), ("DomainName", "LAB"), ("Workstation", "PC7")));
        Assert.Equal(("bob", "PC7"), (e8003!.Account, e8003.Client));
        var e8001 = Classify(Ev(8001, Providers.Ntlm, ("TargetName", "fs01"), ("UserName", "bob")));
        Assert.Equal(("bob", "APP02", "fs01"), (e8001!.Account, e8001.Client, e8001.Service));
        // 8002 names the local server process, not the remote user: no account, the server is the target.
        var e8002 = Classify(Ev(8002, Providers.Ntlm, ("ClientUserName", "SYSTEM"), ("ClientDomainName", "NT AUTHORITY")));
        Assert.Equal(LegacyKind.Ntlm, e8002!.Kind);
        Assert.Equal(("", "", "APP02"), (e8002.Account, e8002.Client, e8002.Service));
    }

    [Fact]
    public void Same_ids_from_other_providers_are_ignored()
    {
        Assert.Null(Classify(Ev(4020, Providers.SecurityAuditing, ("Username", "x"))));
        Assert.Null(Classify(Ev(3000, "Microsoft-Windows-Something", ("ClientName", "10.0.0.1"))));
    }

    [Theory]
    [InlineData("1", "NTLMv1")]
    [InlineData("NTLM V1", "NTLMv1")]
    [InlineData("NTLMv2", "NTLMv2")]
    [InlineData("2", "NTLMv2")]
    [InlineData("LM", "LM")]
    [InlineData("-", "")]
    [InlineData("odd", "odd")]
    public void Ntlm_versions_are_normalized(string value, string expected) => Assert.Equal(expected, Classifier.NtlmVersion(value));

    [Theory]
    [InlineData("10.0.20.15", "10.0.20.15")]
    [InlineData(@"\\PRN-COPIER-2F", "PRN-COPIER-2F")]
    [InlineData("::ffff:10.0.20.40", "10.0.20.40")]
    public void Smb1_access_names_the_client(string clientName, string expected)
    {
        var e = Classify(Ev(3000, Providers.SmbServer, ("ClientName", clientName)));
        Assert.Equal(LegacyKind.Smb1, e!.Kind);
        Assert.Equal(expected, e.Client);
        Assert.Equal("SMB", e.Service);
    }

    [Fact]
    public void Other_smb_audit_events_are_ignored() =>
        Assert.Null(Classify(Ev(3021, Providers.SmbServer, ("ClientName", "10.0.0.1"))));

    [Fact]
    public void New_logs_are_scanned_with_their_own_query()
    {
        var reader = new FakeReader();
        LogFileInfo[] files =
        [
            new("n.evtx", 1, Channels.NtlmOperational, "", 1, 1, null, null),
            new("s.evtx", 1, Channels.SmbServerAudit, "", 1, 1, null, null),
        ];
        Scanner.Scan(reader, files, "test", new ScanOptions());
        Assert.Equal(["NTLM use"], reader.Calls.Where(c => c.Path == "n.evtx").Select(c => c.Query));
        Assert.Equal(["SMBv1 access"], reader.Calls.Where(c => c.Path == "s.evtx").Select(c => c.Query));
        Assert.Contains("'Mic Status'", string.Join(",", Queries.NtlmOperational.Fields!.Select(f => $"'{f}'")));
    }
}
