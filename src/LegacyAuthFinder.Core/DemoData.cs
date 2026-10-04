namespace LegacyAuthFinder.Core;

/// <summary>
/// A made-up CONTOSO domain with two domain controllers and a file server. Old copiers and a legacy XP box use
/// NTLMv1, service accounts with old passwords get RC4 tickets and one Unix service still asks for DES.
/// The events go through the real scanner, classifier and summary, only the file reading is simulated.
/// Addresses are private ranges, names are fictional.
/// </summary>
public static class DemoData
{
    private const string Domain = "CONTOSO";
    private const string Realm = "CONTOSO.LOCAL";

    public static ScanResult Create(DateTime now)
    {
        var reader = new DemoReader(now);
        return Scanner.Scan(reader, reader.Files, @"D:\Logs\contoso-archive (demo data)", new ScanOptions(Threads: 1));
    }

    private sealed class DemoReader : IEvtxReader
    {
        private readonly DateTime _start;
        private readonly Dictionary<string, List<RawEvent>> _events = new(StringComparer.OrdinalIgnoreCase);

        public DemoReader(DateTime now)
        {
            _start = now.Date.AddDays(-14);
            Files =
            [
                File(@"DC01\Archive-Security-2026-09-20-08-14-02-311.evtx", Channels.Security, "DC01.contoso.local", 4_291_821_568, 0, 7),
                File(@"DC01\Archive-Security-2026-09-27-11-40-55-902.evtx", Channels.Security, "DC01.contoso.local", 4_294_901_760, 7, 14),
                File(@"DC01\Archive-System-2026-09-20-00-00-00-000.evtx", Channels.System, "DC01.contoso.local", 68_157_440, 0, 14),
                File(@"DC02\Archive-Security-2026-09-21-02-12-47-118.evtx", Channels.Security, "DC02.contoso.local", 3_872_391_168, 0, 14),
                File(@"FS01\Archive-Security-2026-09-20-17-03-12-555.evtx", Channels.Security, "FS01.contoso.local", 1_073_676_288, 0, 14),
                File(@"FS01\Archive-Application-2026-09-20-17-03-12-555.evtx", "Application", "FS01.contoso.local", 20_975_616, 0, 14),
                new(@"D:\Logs\contoso-archive\FS01\Archive-Security-2026-08-30-copy-broken.evtx", 512_000, "", "", 0, 0, null, null,
                    "The event log file is corrupted."),
            ];

            var random = new Random(42);
            // NTLMv1 on the file server.
            Ntlm(random, "FS01", "svc-scan", "PRN-COPIER-2F", "10.0.20.15", "NTLM V1", 640);
            Ntlm(random, "FS01", "j.novak", "LEGACY-XP01", "10.0.30.7", "NTLM V1", 212);
            Ntlm(random, "FS01", "backup-svc", "NAS01", "10.0.20.40", "NTLM V1", 1_480);
            Ntlm(random, "FS01", "scanner", "PRN-OLD-1F", "10.0.20.11", "LM", 37);
            Ntlm(random, "FS01", "m.kovac", "LEGACY-XP01", "10.0.30.7", "NTLM V1", 18, failed: true);

            // RC4 service tickets on both domain controllers.
            Kerberos(random, ["DC01", "DC02"], 4769, "j.novak", "MSSQLSvc/sql01.contoso.local:1433", "10.0.10.21", 0x17, 0x17, 4_210);
            Kerberos(random, ["DC01", "DC02"], 4769, "a.horvath", "MSSQLSvc/sql01.contoso.local:1433", "10.0.10.34", 0x17, 0x12, 2_870);
            Kerberos(random, ["DC01", "DC02"], 4769, "svc-erp", "HTTP/erp.contoso.local", "10.0.10.50", 0x17, 0x17, 3_960);
            Kerberos(random, ["DC01"], 4769, "PRN-COPIER-2F$", "ldap/dc01.contoso.local", "10.0.20.15", 0x12, 0x17, 1_220);
            Kerberos(random, ["DC02"], 4769, "it.admin", "host/legacy-app01.contoso.local", "10.0.10.12", 0x17, 0x17, 340);
            // RC4 TGTs for accounts whose passwords predate AES.
            Kerberos(random, ["DC01", "DC02"], 4768, "admin-old", "krbtgt", "10.0.10.12", 0x17, 0x17, 95);
            Kerberos(random, ["DC01", "DC02"], 4768, "scanner", "krbtgt", "10.0.20.11", 0x17, 0x17, 410);
            // DES for an old Unix integration.
            Kerberos(random, ["DC01"], 4769, "unix-svc", "host/aix01.contoso.local", "10.0.40.5", 0x3, 0x3, 46);
            // AES traffic that the classifier must ignore.
            Kerberos(random, ["DC01"], 4769, "a.horvath", "cifs/fs01.contoso.local", "10.0.10.34", 0x12, 0x12, 200);

            // KDC RC4 audit warnings.
            Kdc(random, "DC01", 201, "PRN-COPIER-2F$", "ldap/dc01.contoso.local", 12);
            Kdc(random, "DC01", 202, "svc-erp", "HTTP/erp.contoso.local", 9);
            Kdc(random, "DC01", 207, "admin-old", "krbtgt", 4);
        }

        public IReadOnlyList<LogFileInfo> Files { get; }

        private LogFileInfo File(string relative, string channel, string computer, long size, int fromDay, int toDay) =>
            new($@"D:\Logs\contoso-archive\{relative}", size, channel, computer, size / 1_100, 1, _start.AddDays(fromDay), _start.AddDays(toDay));

        private string PathFor(string host, string channel) =>
            Files.Where(f => f.Channel == channel && f.Computer.StartsWith(host + ".", StringComparison.OrdinalIgnoreCase)).Select(f => f.Path).First();

        private DateTime RandomTime(Random r) =>
            _start.AddDays(r.Next(0, 14)).AddHours(r.Next(6, 20)).AddMinutes(r.Next(0, 60)).AddSeconds(r.Next(0, 60));

        private void Add(string path, RawEvent e)
        {
            if (!_events.TryGetValue(path, out var list)) _events[path] = list = [];
            list.Add(e);
        }

        private void Ntlm(Random r, string host, string user, string workstation, string ip, string lm, int count, bool failed = false)
        {
            var path = PathFor(host, Channels.Security);
            for (var i = 0; i < count; i++)
            {
                Add(path, new RawEvent(failed ? 4625 : 4624, Providers.SecurityAuditing, RandomTime(r), $"{host}.contoso.local", 0, new Dictionary<string, string>
                {
                    ["TargetUserName"] = user,
                    ["TargetDomainName"] = Domain,
                    ["WorkstationName"] = workstation,
                    ["IpAddress"] = ip,
                    ["IpPort"] = r.Next(49152, 65535).ToString(),
                    ["LogonType"] = "3",
                    ["AuthenticationPackageName"] = "NTLM",
                    ["LmPackageName"] = lm,
                    ["KeyLength"] = lm == "LM" ? "0" : "128",
                    ["LogonProcessName"] = "NtLmSsp",
                }));
            }
        }

        private void Kerberos(Random r, string[] hosts, int id, string user, string service, string ip, uint ticket, uint session, int count)
        {
            for (var i = 0; i < count; i++)
            {
                var host = hosts[i % hosts.Length];
                var account = id == 4769 && !user.EndsWith('$') ? $"{user}@{Realm}" : user;
                Add(PathFor(host, Channels.Security), new RawEvent(id, Providers.SecurityAuditing, RandomTime(r), $"{host}.contoso.local", 0, new Dictionary<string, string>
                {
                    ["TargetUserName"] = account,
                    ["TargetDomainName"] = Realm,
                    ["ServiceName"] = service,
                    ["IpAddress"] = "::ffff:" + ip,
                    ["IpPort"] = r.Next(49152, 65535).ToString(),
                    ["TicketOptions"] = "0x40810000",
                    ["Status"] = "0x0",
                    ["TicketEncryptionType"] = $"0x{ticket:x}",
                    ["SessionKeyEncryptionType"] = $"0x{session:x}",
                    ["ClientAdvertizedEncryptionTypes"] = ticket == 0x17 && session == 0x17 ? "RC4-HMAC-NT" : "AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96, RC4-HMAC-NT",
                    ["ServiceAvailableKeys"] = ticket == 0x17 ? "RC4" : "AES-SHA1, RC4",
                    ["DCAvailableKeys"] = "AES-SHA1, RC4",
                }));
            }
        }

        private void Kdc(Random r, string host, int id, string account, string service, int count)
        {
            for (var i = 0; i < count; i++)
            {
                Add(PathFor(host, Channels.System), new RawEvent(id, Providers.KdcSvc, RandomTime(r), $"{host}.contoso.local", 0, new Dictionary<string, string>
                {
                    ["AccountName"] = account,
                    ["ServiceName"] = service,
                }));
            }
        }

        public LogFileInfo Inspect(string path) => Files.First(f => f.Path == path);

        public IEnumerable<RawEvent> Read(string path, EvtxQuery query, CancellationToken cancellationToken)
        {
            if (!_events.TryGetValue(path, out var list)) yield break;
            foreach (var e in list.OrderBy(e => e.Time))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var matches = query == Queries.Ntlmv1 ? e.EventId is 4624 or 4625
                    : query == Queries.Kerberos ? e.EventId is 4768 or 4769 or 4770
                    : Providers.IsKdc(e.Provider);
                if (matches) yield return e;
            }
        }
    }
}
