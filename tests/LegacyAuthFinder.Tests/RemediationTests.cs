using LegacyAuthFinder.Core;

namespace LegacyAuthFinder.Tests;

public class RemediationTests
{
    private static readonly ScanResult Demo = DemoData.Create(new DateTime(2026, 10, 14));

    private static FixItem Find(Func<FixItem, bool> match) => Assert.Single(Demo.Fixes, f => match(f));

    [Fact]
    public void Rc4_service_tickets_point_to_the_service_account()
    {
        var f = Find(f => f.Kind == LegacyKind.Rc4 && f.Target == "HTTP/erp.contoso.local" && f.TargetType == FixTarget.ServiceAccount && f.Problem == "Service tickets with RC4");
        Assert.Contains("setspn -Q HTTP/erp.contoso.local", f.Action);
        Assert.Contains("msDS-SupportedEncryptionTypes", f.Action);
    }

    [Fact]
    public void Rc4_tgts_point_to_the_account()
    {
        var f = Find(f => f.Kind == LegacyKind.Rc4 && f.Target == "scanner" && f.TargetType == FixTarget.Account);
        Assert.Equal("Gets RC4 TGTs", f.Problem);
    }

    [Fact]
    public void Rc4_session_keys_point_to_the_client()
    {
        // The copier gets AES tickets for LDAP with an RC4 session key.
        var f = Find(f => f.Kind == LegacyKind.Rc4 && f.Target == "10.0.20.15");
        Assert.Equal(FixTarget.Client, f.TargetType);
        Assert.Equal("Asks for RC4 session keys", f.Problem);
    }

    [Fact]
    public void Ntlmv1_from_the_security_log_and_the_ntlm_log_merge_per_client()
    {
        // LEGACY-XP01 shows up in 4624, 4625 and in the enhanced event 4023 with NTLM version 1.
        var f = Find(f => f.Kind == LegacyKind.Ntlmv1 && f.Target == "10.0.30.7");
        Assert.Equal(FixTarget.Client, f.TargetType);
        Assert.True(f.Rows >= 2);
        Assert.Equal(212 + 18 + 25, f.Events);
        Assert.Contains("j.novak", f.Accounts);
        Assert.Contains("m.kovac", f.Accounts);
    }

    [Fact]
    public void Ntlmv1_single_sign_on_gets_its_own_fix()
    {
        var f = Find(f => f.Problem == "Single sign-on with NTLMv1-derived credentials");
        Assert.Contains("EAP-TLS", f.Action);
    }

    [Fact]
    public void Ntlm_reasons_turn_into_concrete_steps()
    {
        var ip = Find(f => f.Kind == LegacyKind.Ntlm && f.Problem.Contains("IP address"));
        Assert.Contains("host name", ip.Action);
        var spn = Find(f => f.Kind == LegacyKind.Ntlm && f.Problem.Contains("not resolved"));
        Assert.Contains("setspn -S", spn.Action);
    }

    [Fact]
    public void Smb1_clients_are_listed()
    {
        Assert.Equal(410, Find(f => f.Kind == LegacyKind.Smb1 && f.Target == "10.0.20.15").Events);
        Assert.Equal(95, Find(f => f.Kind == LegacyKind.Smb1 && f.Target == "10.0.20.40").Events);
    }

    [Fact]
    public void Ldap_daily_summary_asks_for_the_diagnostic_setting()
    {
        var f = Find(f => f.TargetType == FixTarget.DomainControllers);
        Assert.Contains("16 LDAP Interface Events", f.Action);
        var simple = Find(f => f.Kind == LegacyKind.LdapSigning && f.Target == "10.0.20.15");
        Assert.Equal("Simple LDAP bind with a cleartext password", simple.Problem);
    }

    [Fact]
    public void Kdc_warnings_follow_the_event_meaning()
    {
        Assert.Contains(Demo.Fixes, f => f.Kind == LegacyKind.Rc4 && f.Problem == "Offers only RC4");
        Assert.Contains(Demo.Fixes, f => f.Kind == LegacyKind.Rc4 && f.Problem == "Service without AES keys");
        Assert.Contains(Demo.Fixes, f => f.Kind == LegacyKind.Rc4 && f.Problem == "Account without AES keys");
    }

    [Fact]
    public void Fix_list_is_ranked_by_urgency_then_size()
    {
        Assert.Equal(Enumerable.Range(1, Demo.Fixes.Count), Demo.Fixes.Select(f => f.Rank));
        Assert.Equal(LegacyKind.Des, Demo.Fixes[0].Kind);
        Assert.Equal(LegacyKind.Ntlm, Demo.Fixes[^1].Kind);
        var order = Demo.Fixes.Select(f => Scanner.KindOrder(f.Kind)).ToList();
        Assert.Equal(order.Order(), order);
        Assert.Equal(Demo.TotalHits, Demo.Fixes.Sum(f => f.Events));
    }

    [Fact]
    public void Every_kind_produces_a_fix()
    {
        Assert.All(Enum.GetValues<LegacyKind>(), k => Assert.Contains(Demo.Fixes, f => f.Kind == k));
    }

    [Fact]
    public void Fix_texts_follow_the_house_style()
    {
        Assert.All(Demo.Fixes.SelectMany(f => new[] { f.Problem, f.Action }), t =>
        {
            Assert.DoesNotContain("—", t);
            Assert.DoesNotContain("; ", t);
        });
    }

    [Fact]
    public void Fix_list_exports_to_csv_and_html()
    {
        using var w = new StringWriter();
        Reports.WriteFixesCsv(w, Demo.Fixes);
        var lines = w.ToString().TrimEnd().Split('\n');
        Assert.Equal(Demo.Fixes.Count + 1, lines.Length);
        Assert.StartsWith("Rank,Type,FixOn,Target", lines[0]);
        Assert.Contains("What to fix first", Reports.ToHtml(Demo));
        using var doc = System.Text.Json.JsonDocument.Parse(Reports.ToJson(Demo));
        Assert.Equal(Demo.Fixes.Count, doc.RootElement.GetProperty("fixes").GetArrayLength());
        Assert.True(doc.RootElement.GetProperty("totals").GetProperty("smb1").GetInt64() > 0);
    }

    [Fact]
    public void Search_finds_fixes_by_account_and_target()
    {
        Assert.Contains(Demo.Fixes, f => f.Matches(["svc-erp"]));
        Assert.Contains(Demo.Fixes, f => f.Matches(["10.0.20.15", "SMBv1"]));
        Assert.DoesNotContain(Demo.Fixes, f => f.Matches(["no-such-thing"]));
    }
}
