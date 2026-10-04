using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

public class ClassifierTests
{
    private static readonly StringPool Pool = new();

    private static RawEvent Ev(int id, params (string, string)[] data) =>
        new(id, Providers.SecurityAuditing, new DateTime(2026, 9, 1, 10, 0, 0), "DC01.lab.local", 42,
            data.ToDictionary(d => d.Item1, d => d.Item2, StringComparer.OrdinalIgnoreCase));

    private static AuthEvent? Classify(RawEvent e) => Classifier.Classify(e, "Archive-Security.evtx", Pool);

    [Theory]
    [InlineData("NTLM V1", "NTLM V1")]
    [InlineData("LM", "LM")]
    public void Ntlmv1_and_lm_logons_are_found(string lm, string variant)
    {
        var e = Classify(Ev(4624, ("LmPackageName", lm), ("TargetUserName", "alice"), ("TargetDomainName", "LAB"),
            ("IpAddress", "::ffff:10.0.0.5"), ("WorkstationName", "OLDPC")));
        Assert.NotNull(e);
        Assert.Equal(LegacyKind.Ntlmv1, e.Kind);
        Assert.Equal(variant, e.Variant);
        Assert.Equal("10.0.0.5", e.Client);
        Assert.Equal("alice", e.Account);
        Assert.Contains(e.Fields, f => f.Key == "WorkstationName" && f.Value == "OLDPC");
    }

    [Theory]
    [InlineData("NTLM V2")]
    [InlineData("-")]
    [InlineData("")]
    public void Ntlmv2_and_kerberos_logons_are_ignored(string lm) =>
        Assert.Null(Classify(Ev(4624, ("LmPackageName", lm), ("TargetUserName", "alice"))));

    [Fact]
    public void Ntlm_without_ip_uses_the_workstation_name()
    {
        var e = Classify(Ev(4625, ("LmPackageName", "NTLM V1"), ("IpAddress", "-"), ("WorkstationName", "OLDPC")));
        Assert.Equal("OLDPC", e!.Client);
        Assert.Equal("Failed logon", e.What);
    }

    [Theory]
    [InlineData("0x17", "0x12", LegacyKind.Rc4)]
    [InlineData("0x12", "0x17", LegacyKind.Rc4)]
    [InlineData("0x18", "", LegacyKind.Rc4)]
    [InlineData("0x3", "0x17", LegacyKind.Des)]
    [InlineData("0x12", "0x1", LegacyKind.Des)]
    [InlineData("23", "", LegacyKind.Rc4)]
    public void Weak_ticket_or_session_key_is_found(string ticket, string session, LegacyKind expected)
    {
        var e = Classify(Ev(4769, ("TicketEncryptionType", ticket), ("SessionKeyEncryptionType", session),
            ("TargetUserName", "bob@LAB.LOCAL"), ("ServiceName", "MSSQLSvc/sql01"), ("IpAddress", "::ffff:10.0.0.9")));
        Assert.NotNull(e);
        Assert.Equal(expected, e.Kind);
        Assert.Equal("MSSQLSvc/sql01", e.Service);
        Assert.Equal("10.0.0.9", e.Client);
    }

    [Theory]
    [InlineData("0x12", "0x12")]
    [InlineData("0x11", "")]
    [InlineData("0xffffffff", "")]
    [InlineData("-", "-")]
    public void Aes_and_failed_requests_are_ignored(string ticket, string session) =>
        Assert.Null(Classify(Ev(4769, ("TicketEncryptionType", ticket), ("SessionKeyEncryptionType", session))));

    [Fact]
    public void Variant_says_which_part_was_weak()
    {
        var e = Classify(Ev(4769, ("TicketEncryptionType", "0x12"), ("SessionKeyEncryptionType", "0x17")));
        Assert.Equal("Session key RC4-HMAC", e!.Variant);
        Assert.Equal("AES256-SHA1", e.TicketEncryption);
        Assert.Equal("RC4-HMAC", e.SessionEncryption);
    }

    [Fact]
    public void Kdc_rc4_warnings_from_the_system_log_are_found()
    {
        var raw = new RawEvent(201, Providers.KdcSvc, DateTime.Now, "DC01", 1, new Dictionary<string, string> { ["AccountName"] = "svc-erp", ["Extra"] = "x" });
        var e = Classifier.Classify(raw, "System.evtx", Pool);
        Assert.NotNull(e);
        Assert.Equal(LegacyKind.Rc4, e.Kind);
        Assert.Equal("svc-erp", e.Account);
        Assert.Contains(e.Fields, f => f.Key == "Extra");
        Assert.StartsWith("KDC:", e.What);
    }

    [Fact]
    public void Same_event_ids_from_other_providers_are_ignored()
    {
        var raw = new RawEvent(201, "Some-Other-Provider", DateTime.Now, "DC01", 1, new Dictionary<string, string>());
        Assert.Null(Classifier.Classify(raw, "System.evtx", Pool));
        var other = new RawEvent(4624, "Not-Security-Auditing", DateTime.Now, "X", 1, new Dictionary<string, string> { ["LmPackageName"] = "NTLM V1" });
        Assert.Null(Classifier.Classify(other, "x.evtx", Pool));
    }

    [Theory]
    [InlineData("0x17", 0x17u)]
    [InlineData("0X3", 0x3u)]
    [InlineData("23", 23u)]
    [InlineData("0x1F (DES, RC4, AES128-SHA96, AES256-SHA96)", 0x1Fu)]
    public void Encryption_types_parse(string text, uint expected) => Assert.Equal(expected, Classifier.ParseEtype(text));

    [Fact]
    public void String_pool_shares_instances()
    {
        var pool = new StringPool();
        var a = pool.Get(new string("CONTOSO".ToCharArray()));
        var b = pool.Get(new string("CONTOSO".ToCharArray()));
        Assert.Same(a, b);
    }

    [Fact]
    public void Search_needs_every_term()
    {
        var e = Classify(Ev(4769, ("TicketEncryptionType", "0x17"), ("TargetUserName", "svc-erp@LAB"), ("ServiceName", "HTTP/erp"), ("IpAddress", "10.0.0.50")))!;
        Assert.True(e.Matches(["erp", "10.0.0.50"]));
        Assert.True(e.Matches(["rc4"]));
        Assert.False(e.Matches(["erp", "10.0.0.51"]));
        Assert.True(e.Matches(["4769"]));
    }
}
