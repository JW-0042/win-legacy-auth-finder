namespace LegacyAuthFinder.Core;

public sealed record Reference(string Label, string Url);

public sealed record KindGuidance(string Label, string What, string Risk, string Fix, IReadOnlyList<Reference> References);

/// <summary>Plain-language explanation of each finding type, shown next to the events.</summary>
public static class Guidance
{
    public static KindGuidance For(LegacyKind kind) => All[kind];

    /// <summary>Display order, most urgent first.</summary>
    public static IReadOnlyList<LegacyKind> Order { get; } =
    [
        LegacyKind.Des, LegacyKind.Ntlmv1, LegacyKind.Smb1, LegacyKind.LdapSigning, LegacyKind.Rc4, LegacyKind.NoPreAuth,
        LegacyKind.LdapChannelBinding, LegacyKind.EtypeFailure, LegacyKind.Ntlm,
    ];

    public static string Label(LegacyKind kind) => kind switch
    {
        LegacyKind.Ntlmv1 => "NTLMv1",
        LegacyKind.Rc4 => "RC4",
        LegacyKind.Des => "DES",
        LegacyKind.LdapSigning => "LDAP unsigned",
        LegacyKind.LdapChannelBinding => "LDAP CBT",
        LegacyKind.Smb1 => "SMBv1",
        LegacyKind.Ntlm => "NTLM",
        LegacyKind.NoPreAuth => "No pre-auth",
        _ => "Etype error",
    };

    public static IReadOnlyDictionary<LegacyKind, KindGuidance> All { get; } = new Dictionary<LegacyKind, KindGuidance>
    {
        [LegacyKind.Ntlmv1] = new(
            "NTLMv1",
            "A logon used the NTLMv1 or LM challenge response. Windows records this in the \"Package Name (NTLM only)\" field of events 4624 and 4625, and as NTLM version 1 in the enhanced NTLM events 4021, 4023, 4031 and 4033. Event 4013 is NTLMv1 single sign-on that Credential Guard blocked. Events 4024 and 4025 show single sign-on with NTLMv1-derived credentials, for example Wi-Fi, wired or VPN profiles with MS-CHAPv2. Anonymous logons (ANONYMOUS LOGON) are always logged as NTLM V1 because they have no key material, so the tool leaves them out, as Microsoft recommends.",
            "NTLMv1 and LM responses can be cracked quickly and relayed to other servers. One old client is enough to expose the password of every account that signs in from it.",
            "Find the client in the summary and update or reconfigure it to use NTLMv2 or Kerberos. When no NTLMv1 is left, set \"Network security: LAN Manager authentication level\" to \"Send NTLMv2 response only. Refuse LM & NTLM\" on servers and domain controllers. For events 4024, 4025 and 4013, move the network profile from MS-CHAPv2 to certificates (EAP-TLS or PEAP-TLS). Credential Guard already stops single sign-on with NTLMv1-derived credentials (event 4013), and Microsoft switches BlockNtlmv1SSO from audit to enforce, which does the same on the other devices.",
            [
                new("Microsoft: Upcoming changes to NTLMv1 (BlockNtlmv1SSO)", "https://support.microsoft.com/help/5066470"),
                new("Microsoft: Credential Guard and Wi-Fi or VPN single sign-on", "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues"),
                new("Microsoft: Audit use of NTLMv1 on a domain controller", "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1"),
                new("Microsoft: LAN Manager authentication level", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"),
                new("Microsoft: Event 4624", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624"),
            ]),
        [LegacyKind.Rc4] = new(
            "RC4",
            "A Kerberos ticket or session key was issued with RC4-HMAC, or the domain controller logged an RC4 warning (KDCSVC events 201 to 209).",
            "RC4 tickets can be cracked offline (Kerberoasting). Microsoft is turning RC4 off by default on domain controllers in 2026, so whatever still depends on it will stop working.",
            "Use the fix list. A service ticket with RC4 points to the service account (in a successful 4769 the ServiceName is the account, in a failed one the SPN): reset its password so it gets AES keys and update it wherever the service runs, then set its msDS-SupportedEncryptionTypes to AES. The other order makes the domain controller block its tickets. A pre-authentication with RC4 points to the user account, or to the client when it offers no AES. Clients that offer only RC4 need an update. Computer accounts take their encryption types from the computer's own Kerberos policy, so fix the policy or the operating system there. Check the KDCSVC events on your domain controllers before you enforce.",
            [
                new("Microsoft: KDC events 201 to 209 (CVE-2026-20833)", "https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc"),
                new("Microsoft: How to manage RC4 hardening", "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/how-to-manage-rc4-hardening-%E2%80%93-definitive-guide/4515923"),
                new("Microsoft: Event 4769", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769"),
                new("MITRE ATT&CK T1558.003: Kerberoasting", "https://attack.mitre.org/techniques/T1558/003/"),
            ]),
        [LegacyKind.Des] = new(
            "DES",
            "A Kerberos ticket or session key was issued with DES (DES-CBC-CRC or DES-CBC-MD5).",
            "DES is broken and was removed from Windows Server 2025. Any DES ticket points to an account with the \"Use only Kerberos DES encryption types\" flag or to a very old system.",
            "Remove the DES flag from the account and reset its password so it gets AES keys, then set msDS-SupportedEncryptionTypes to AES. Replace or reconfigure the system that asked for DES.",
            [
                new("Microsoft: The end is nigh for DES", "https://techcommunity.microsoft.com/blog/askds/the-end-is-nigh-for-des-and-an-update-for-hunting-down-rc4/4499821"),
                new("Microsoft: Event 4768", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768"),
            ]),
        [LegacyKind.LdapSigning] = new(
            "LDAP unsigned",
            "A client signed in to a domain controller over LDAP without signing, or with a simple bind that sends the password in clear text (Directory Service events 2889 and 2887).",
            "Unsigned LDAP can be relayed and changed on the way, and a simple bind without TLS exposes the password on the network. Windows Server 2025 domain controllers require signing by default, so these clients will stop working.",
            "Use the client address and account to find the device or application. Switch it to LDAPS or signed binds, or update it. Event 2889 needs the \"16 LDAP Interface Events\" diagnostic value set to 2 on the domain controllers. Without it you only get the daily summary 2887.",
            [
                new("Microsoft: How to enable LDAP signing", "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server"),
                new("Microsoft: Event ID 2889", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd941849(v=ws.10)"),
                new("MITRE ATT&CK T1557: Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"),
            ]),
        [LegacyKind.LdapChannelBinding] = new(
            "LDAP CBT",
            "A client connected over LDAPS without a valid channel binding token (Directory Service events 3039, 3074 and 3075).",
            "Without channel binding, an attacker who relays an authentication can reuse it on an LDAPS connection. Once channel binding is enforced, these clients are refused.",
            "Update or reconfigure the client so it supports channel binding, then set the domain controller policy to require it. Event 3074 shows clients that would fail before you enforce, 3039 shows the ones that fail. These two and 3075 need the \"16 LDAP Interface Events\" diagnostic value set to 2 and the channel binding policy set to \"When supported\" or \"Always\". With the policy at \"Never\" you only get the daily count 3040.",
            [
                new("Microsoft: LDAP channel binding and signing, Server 2025 updates", "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/ldap-channel-binding-and-ldap-signing-requirements---server-2025-updates/921536"),
                new("MITRE ATT&CK T1557: Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"),
            ]),
        [LegacyKind.EtypeFailure] = new(
            "Etype error",
            "A Kerberos request failed because the client, the account and the domain controller had no encryption type in common (KDC events 14, 16, 26, 27 and status 0xE in events 4768, 4769 and 4771).",
            "These are the requests that break when RC4 or DES is turned off. They often point to old accounts without AES keys or to devices that only support RC4 or DES.",
            "The details show which side has no AES: the client's offer, the service account's keys or the account's keys. Reset the password of accounts that have no AES keys, and update or reconfigure clients that only offer old ciphers. Status 0xE in event 4769 is logged only when KdcExtraLogLevel 0x10 is set on the domain controllers.",
            [
                new("Microsoft: KDC event 16 or 27", "https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kdc-event-16-27-des-encryption-disabled"),
                new("Microsoft: Event 4771", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771"),
            ]),
        [LegacyKind.Smb1] = new(
            "SMBv1",
            "A client connected to this server with SMB version 1 (SMBServer Audit event 3000). The event is logged only after Set-SmbServerConfiguration -AuditSmb1Access $true.",
            "SMBv1 has no protection against tampering and downgrade and was how WannaCry and NotPetya spread. Windows has shipped without it since Windows 10 1709 and Windows Server 2019, so the clients that still need it are usually old copiers, scanners, NAS boxes and embedded systems.",
            "Update or reconfigure each client to SMB 2 or 3, or replace it. When the audit has stayed empty for a few weeks, remove SMB1 from the server with Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
            [
                new("Microsoft: Detect, enable and disable SMBv1", "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"),
                new("Microsoft: Stop using SMB1", "https://techcommunity.microsoft.com/blog/filecab/stop-using-smb1/425858"),
            ]),
        [LegacyKind.Ntlm] = new(
            "NTLM",
            "Something authenticated with NTLM. Windows 11 24H2 and Windows Server 2025 write events 4020 to 4023 on clients and servers and 4030 to 4033 on domain controllers to the NTLM Operational log, Server 2019 and 2022 since the October 2026 updates. They name the reason NTLM was used. 4026 and 4027 mean NTLM would be or was blocked. The older events 8001 to 8004 (audit) and 4001 to 4006 (blocked) appear when a \"Restrict NTLM\" policy is set. Domain controllers also log 4776 in the Security log for every NTLM validation (4776 for a local sign-in on the computer itself is left out). The same sign-in can show up on the client, the server and the domain controller.",
            "NTLM can be relayed and its hashes cracked much more easily than Kerberos tickets. Microsoft is phasing NTLM out of Windows, so everything that still uses it needs a fix or an exception before it is turned off.",
            "Read the reason in the details. A target given as an IP address, a missing or duplicate service principal name and local accounts are the usual causes. Connect by host name, register the missing SPN with setspn -S, list duplicates with setspn -X, and change applications that ask for NTLM directly to use Negotiate. The reason is logged only with \"NTLM Enhanced Logging\" (clients and servers) and \"Log Enhanced Domain-wide NTLM Logs\" (domain controllers), which are on by default.",
            [
                new("Microsoft: NTLM auditing enhancements", "https://support.microsoft.com/en-us/topic/overview-of-ntlm-auditing-enhancements-in-windows-11-version-24h2-and-windows-server-2025-b7ead732-6fc5-46a3-a943-27a4571d9e7b"),
                new("Microsoft: Active Directory hardening, disabling NTLM", "https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/active-directory-hardening-series---part-8-%E2%80%93-disabling-ntlm/4485782"),
                new("MITRE ATT&CK T1557.001: LLMNR/NBT-NS poisoning and SMB relay", "https://attack.mitre.org/techniques/T1557/001/"),
            ]),
        [LegacyKind.NoPreAuth] = new(
            "No pre-auth",
            "A domain controller issued a TGT without Kerberos pre-authentication (event 4768 with pre-authentication type 0). The account has \"Do not require Kerberos preauthentication\" set.",
            "Anyone on the network can ask for a TGT of such an account and crack its password offline, without knowing anything about it (AS-REP roasting). With RC4 the cracking is fast.",
            "Clear \"Do not require Kerberos preauthentication\" on the account (Set-ADAccountControl -DoesNotRequirePreAuth $false). If an old system really needs it, give the account a long random password and AES keys.",
            [
                new("Microsoft: Event 4768", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768"),
                new("MITRE ATT&CK T1558.004: AS-REP Roasting", "https://attack.mitre.org/techniques/T1558/004/"),
            ]),
    };

    public static string KdcEventText(int id) => id switch
    {
        201 => "KDC: client offers only RC4 (audit)",
        202 => "KDC: service account has no AES keys (audit)",
        203 => "KDC: blocked, client offers only RC4",
        204 => "KDC: blocked, service account has no AES keys",
        205 => "KDC: DefaultDomainSupportedEncTypes allows more than AES",
        206 => "KDC: AES-only service, client offers only RC4 (audit)",
        207 => "KDC: AES-only service, service account has no AES keys (audit)",
        208 => "KDC: blocked, AES-only service and RC4-only client",
        209 => "KDC: blocked, AES-only service account has no AES keys",
        14 => "KDC: no suitable key for a TGT (AS request)",
        16 => "KDC: no common key for a service ticket",
        26 => "KDC: unsupported encryption type in AS request",
        27 => "KDC: unsupported encryption type in service ticket request",
        _ => $"Event {id}",
    };
}
