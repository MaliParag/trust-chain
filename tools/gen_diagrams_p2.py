#!/usr/bin/env python3
"""Part 2 diagram definitions: Chapters 10-20 (Credentials & Access + ETW + Cloud + Finale)."""
import math
import os
from diagram_lib import (
    SvgCanvas, THEMES, build_vertical_flow, build_sequence, build_split_domains,
    build_fan_bands, build_matrix, build_timeline_spine, build_dual_rail_timeline,
)


def generate_part2(diag_dir: str):
    def P(name):
        return os.path.join(diag_dir, name)

    # 33. Ch 10: 25-access-control-token-descriptor.svg
    build_split_domains(
        P("25-access-control-token-descriptor.svg"),
        "Inputs Evaluated by Kernel SeAccessCheck on Every Object Open",
        left={
            "label": "Subject: Access Token (_TOKEN)",
            "theme": "green",
            "cards": [
                {"tag": "Identity & Groups", "title": "User SID + Group SIDs + Logon SID", "body": "Primary or impersonation token attached to calling thread/process", "theme": "white"},
                {"tag": "Mandatory Label (Checked First)", "title": "Token Integrity Level (S-1-16-xxxx)", "body": "Untrusted (0x0000), Low (0x1000), Medium (0x2000), High (0x3000), System (0x4000)", "theme": "teal"},
                {"tag": "Capabilities & Sandbox", "title": "Privileges & Restricted / AppContainer SIDs", "body": "SeDebugPrivilege, SeImpersonatePrivilege, SeBackupPrivilege; LPAC capabilities", "theme": "white"},
            ],
        },
        right={
            "label": "Object: Security Descriptor",
            "theme": "slate",
            "cards": [
                {"tag": "Ownership", "title": "Owner SID & Primary Group SID", "body": "Owner implicitly receives READ_CONTROL and WRITE_DAC unless restricted by MIC", "theme": "white"},
                {"tag": "SACL (Evaluated First for MIC)", "title": "SYSTEM_MANDATORY_LABEL_ACE + Audit ACEs", "body": "Default No-Write-Up policy (0x1); missing label defaults to Medium Integrity", "theme": "amber"},
                {"tag": "DACL (Canonical Order)", "title": "Explicit Deny -> Explicit Allow -> Inherited", "body": "First-match accumulation over RequestedAccess bits; NULL DACL != Empty DACL", "theme": "white"},
            ],
        },
        bridges=[
            (1, 1, "both", "Gate 1: MIC check", "amber"),
            (2, 2, "both", "Gate 2: DACL walk", "teal"),
        ],
        boundary_label="SRM Reference Monitor",
        footer="Mandatory Integrity Control (SACL label) executes BEFORE the DACL walk: Low IL cannot write a Medium object even if DACL grants Everyone Full Control."
    )

    # 34. Ch 10: 26-integrity-levels-seaccesscheck.svg
    build_vertical_flow(
        P("26-integrity-levels-seaccesscheck.svg"),
        "Two-Gate Kernel SeAccessCheck Evaluation Pipeline",
        [
            {"tag": "Request", "title": "Thread Requests DesiredAccess Mask on Kernel Object", "body": "Uses thread ImpersonationToken if active (and SecurityImpersonation+), else process PrimaryToken", "theme": "slate"},
            {"tag": "Gate 1 · Mandatory Integrity (MIC)", "title": "Compare Token Integrity Level vs. Object SACL Label", "body": "Enforces SYSTEM_MANDATORY_LABEL_NO_WRITE_UP (plus NO_READ_UP / NO_EXECUTE_UP where set)", "theme": "amber"},
            {"tag": "Gate 2 · Discretionary ACL (DACL)", "title": "Walk Ordered ACEs Until All DesiredAccess Bits Granted", "body": "Evaluates Explicit Deny ACEs before Explicit Allow ACEs ( plus Restricted/AppContainer SIDs if present)", "theme": "teal", "edge_label": "MIC passed"},
            {"tag": "Outcome", "title": "STATUS_SUCCESS: Handle Created with GrantedAccess", "body": "Access mask frozen into handle table entry at open time (not re-evaluated on ReadFile/WriteFile)", "theme": "green", "edge_label": "all bits granted"},
        ],
        side_notes={
            1: {"tag": "Blocked at Gate 1", "title": "STATUS_ACCESS_DENIED", "body": "Caller IL < Object IL on write", "theme": "red", "edge_label": "IL too low"},
            2: {"tag": "Blocked at Gate 2", "title": "STATUS_ACCESS_DENIED", "body": "Explicit Deny or ungranted bit", "theme": "red", "edge_label": "DACL deny"},
        },
        footer="UIPI extends the same integrity lattice to window messages, blocking Medium/Low processes from PostMessage injection into High-IL windows."
    )

    # 35. Ch 10: 26-integrity-levels-elevation.svg
    build_sequence(
        P("26-integrity-levels-elevation.svg"),
        "UAC Split-Token Logon & AppInfo (aisvc) Elevation Flow",
        [
            {"title": "lsass.exe", "sub": "Interactive Logon", "theme": "slate"},
            {"title": "explorer.exe", "sub": "Medium IL Filtered Token", "theme": "amber"},
            {"title": "aisvc + consent.exe", "sub": "SYSTEM Secure Desktop", "theme": "teal"},
            {"title": "Elevated Process", "sub": "High IL Linked Token", "theme": "green"},
        ],
        [
            (0, 1, "1 · Mint High-IL Full Token + Medium-IL Filtered Token (Admin SID = DENY_ONLY)", "slate", False),
            (1, 2, "2 · ShellExecute('runas') -> RPC RAiLaunchAdminProcess to AppInfo", "amber", False),
            (2, 2, "3 · Switch to Winlogon Secure Desktop & prompt user via consent.exe", "teal", False),
            (2, 3, "4 · Retrieve linked High-IL token & spawn elevated child process", "green", False),
        ],
        footer="Microsoft does not service default same-user UAC as a security boundary because auto-elevating signed binaries share user profile state."
    )

    # 36. Ch 10: 27-seimpersonate-three-piece.svg
    build_fan_bands(
        P("27-seimpersonate-three-piece.svg"),
        "The SeImpersonatePrivilege (Potato Family) Local Escalation Theorem",
        [
            [
                {"id": "p1", "tag": "Piece 1 · Default Service Grant", "title": "SeImpersonatePrivilege", "body": "Granted by default to IIS AppPools, MSSQL, LOCAL SERVICE, and NETWORK SERVICE tokens", "theme": "amber"},
                {"id": "p2", "tag": "Piece 2 · Coercion Primitive", "title": "Force SYSTEM Authentication", "body": "COM marshaling (OXID / IStorage) or RPC (EfsRpc / Spooler) makes SYSTEM connect to local endpoint", "theme": "red"},
                {"id": "p3", "tag": "Piece 3 · Loopback Carve-Out", "title": "Local Named-Pipe / RPC Auth", "body": "ImpersonateNamedPipeClient / RpcImpersonateClient yields SecurityImpersonation token locally", "theme": "purple"},
            ],
            [{"id": "and", "tag": "Conjunctive Composition (P1 AND P2 AND P3)", "title": "DuplicateTokenEx -> CreateProcessWithTokenW / CreateProcessAsUser", "body": "Service process converts captured SYSTEM impersonation token into a full SYSTEM primary process", "theme": "red"}],
        ],
        [
            ("p1", "and", "authorizes impersonation", "amber", False),
            ("p2", "and", "supplies SYSTEM caller", "red", False),
            ("p3", "and", "delivers usable token", "purple", False),
        ],
        footer="Point patches closed individual Piece-2 vectors (Hot, Rotten, Juicy, Rogue, PrintSpoofer), while Piece 1 + Piece 3 keep the class alive (GodPotato)."
    )

    # 37. Ch 11: 08-credential-guard-vtl-boundary.svg
    build_split_domains(
        P("08-credential-guard-vtl-boundary.svg"),
        "Credential Guard Architectural Split: VTL0 Broker vs. VTL1 Vault",
        left={
            "label": "VTL0 · lsass.exe (Protocol Broker)",
            "theme": "amber",
            "cards": [
                {"tag": "SSPs & Parsers", "title": "msv1_0 · kerberos · cloudap · schannel", "body": "Handles network sockets, ASN.1/NDR wire decoding, and logon session tables", "theme": "white"},
                {"tag": "Zero Raw Long-Term Keys", "title": "Holds Encrypted [LSA Isolated Data] Blob", "body": "sekurlsa::logonpasswords reads only VTL1-wrapped ciphertext; TGS service tickets remain in VTL0", "theme": "amber", "in_arrow": True},
            ],
        },
        right={
            "label": "VTL1 · LsaIso.exe (IUM Trustlet ID 1)",
            "theme": "green",
            "cards": [
                {"tag": "Isolated Secret Custody", "title": "NTOWF Hashes, AES Kerberos Keys, & TGT Keys", "body": "Decrypted only inside VTL1 RAM unmapped from VTL0's Hyper-V SLAT tables", "theme": "green"},
                {"tag": "Narrow Crypto Oracle", "title": "Computes NTLMv2 HMAC / Decrypts TGS Session Key", "body": "Returns only per-request derived response; never exports raw NTOWF or TGT key", "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "LSA_ISO_RPC_SERVER (ALPC)", "teal"),
            (1, 1, "rl", "derived response only", "green"),
        ],
        boundary_label="Hyper-V SLAT Isolation",
        footer="Even with SYSTEM + BYOVD Ring 0 read/write in VTL0, long-term Active Directory secrets inside LsaIso.exe remain unreachable."
    )

    # 38. Ch 11: 08-credential-guard-ntlm-roundtrip.svg
    build_sequence(
        P("08-credential-guard-ntlm-roundtrip.svg"),
        "Per-Authentication NTLMv2 Challenge Calculation Across VTL0 and VTL1",
        [
            {"title": "Remote Server", "sub": "SMB / HTTP Verifier", "theme": "slate"},
            {"title": "lsass.exe (VTL0)", "sub": "msv1_0.dll Broker", "theme": "amber"},
            {"title": "securekernel.exe", "sub": "VTL1 Ring 0 Gate", "theme": "teal"},
            {"title": "LsaIso.exe (VTL1)", "sub": "Credential Vault", "theme": "green"},
        ],
        [
            (0, 1, "1 · 8-byte NTLM ServerChallenge + TargetInfo", "slate", False),
            (1, 2, "2 · ALPC / VMCALL: CalculateNtResponse(sealedBlob, challenge)", "amber", False),
            (2, 3, "3 · Validate RPC ordinal & dispatch into IUM trustlet", "teal", False),
            (3, 3, "4 · Unwrap NTOWF in VTL1 & compute HMAC-MD5 NTLMv2 proof", "green", False),
            (3, 1, "5 · Return 24-byte/NTLMv2 response (zero NTOWF bytes)", "green", False),
            (1, 0, "6 · Transmit NTLM AUTHENTICATE message on wire", "slate", False),
        ],
        boundary_after=1,
        boundary_label="VTL0 | VTL1 SLAT Boundary",
        footer="VTL0 lsass.exe never touches the plaintext NTOWF hash during challenge-response calculation."
    )

    # 39. Ch 11: 08-credential-guard-pass-the-challenge.svg
    build_vertical_flow(
        P("08-credential-guard-pass-the-challenge.svg"),
        "Pass-the-Challenge (Lyak, 2022): Abusing the Authorized LsaIso Oracle",
        [
            {"tag": "Step 1 · VTL0 Injection", "title": "Admin / SYSTEM Injects SSP DLL into VTL0 lsass.exe", "body": "Requires bypassing or disabling RunAsPPL; operates inside the legitimate VTL0 caller of LsaIso.exe", "theme": "amber"},
            {"tag": "Step 2 · Blob Harvest", "title": "Locate Encrypted [LSA Isolated Data] Credential Context", "body": "Extracts opaque VTL1-encrypted user credential blob from VTL0 lsass memory", "theme": "slate"},
            {"tag": "Step 3 · Chosen Challenge", "title": "Invoke LsaIso NTLMv1 Verb with Challenge 1122334455667788", "body": "If LmCompatibilityLevel < 5 permits NTLMv1 inside LsaIso, requests DES response over chosen nonce", "theme": "red", "edge_label": "authorized ALPC call"},
            {"tag": "Step 4 · Faithful VTL1 Reply", "title": "LsaIso.exe Returns Valid 24-Byte DES Ciphertext", "body": "Zero VTL1 memory bugs exploited; trustlet performs its documented API contract", "theme": "teal"},
            {"tag": "Step 5 · Offline DES Crack", "title": "crack.sh / Rainbow Tables Invert 56-Bit DES -> NTOWF", "body": "Recovers raw NT hash offline despite VTL1 isolation; closed by enforcing LmCompatibilityLevel >= 5", "theme": "red"},
        ],
        footer="Isolating key storage cannot prevent oracle abuse if weak legacy primitives (NTLMv1 DES) remain enabled inside the vault."
    )

    # 40. Ch 11: 08-credential-guard-residual-taxonomy.svg
    build_fan_bands(
        P("08-credential-guard-residual-taxonomy.svg"),
        "Four Credential Surfaces Intentionally Outside Credential Guard's Scope",
        [
            [{"id": "cg", "tag": "Protected Inside VTL1 LsaIso.exe", "title": "Domain NTOWF Hashes, Kerberos AES Keys, & TGT Session Keys", "body": "Local memory dumping (sekurlsa::logonpasswords) returns zero plaintext domain keys", "theme": "green"}],
            [
                {"id": "r1", "tag": "1 · Active Tickets in VTL0", "title": "Issued Service Tickets (TGS)", "body": "Cached in VTL0 lsass for active sessions -> Kerberos (Chapter 14)", "theme": "amber"},
                {"id": "r2", "tag": "2 · Cloud & Local Vaults", "title": "CloudAP PRTs, DPAPI, & Certs", "body": "In-use SSO cookies & software PFXs -> Chapters 11, 15, 16", "theme": "red"},
                {"id": "r3", "tag": "3 · Token Impersonation", "title": "Live Access Tokens & Potatoes", "body": "Stealing tokens needs no password -> Access Control (Chapter 10)", "theme": "amber"},
                {"id": "r4", "tag": "4 · Off-Box Directory Stores", "title": "DC ntds.dit & Unbound Relays", "body": "DCSync on DCs & NTLM/Krb relay -> Chapters 13, 14, 15, 19", "theme": "red"},
            ],
        ],
        [
            ("cg", "r1", "outside VTL1", "amber", True),
            ("cg", "r2", "outside VTL1", "red", True),
            ("cg", "r3", "outside VTL1", "amber", True),
            ("cg", "r4", "outside VTL1", "red", True),
        ],
        footer="Credential Guard closes local domain-secret extraction on member hosts; downstream chapters govern tickets, PRTs, tokens, and DCs."
    )

    # 41. Ch 12: 09-ntlm-handshake.svg
    build_sequence(
        P("09-ntlm-handshake.svg"),
        "Three-Message NTLMv2 Wire Handshake & Relay Exposure",
        [
            {"title": "Client", "sub": "Holds NTOWF(password)", "theme": "slate"},
            {"title": "Application Server", "sub": "SMB / HTTP / LDAP", "theme": "teal"},
            {"title": "Domain Controller", "sub": "Netlogon Verify", "theme": "green"},
        ],
        [
            (0, 1, "1 · NEGOTIATE_MESSAGE (capability flags; no identity)", "slate", False),
            (1, 0, "2 · CHALLENGE_MESSAGE (8-byte ServerChallenge + TargetInfo AV_PAIRs)", "teal", False),
            (0, 0, "3 · NTOWFv2 = HMAC_MD5(NTOWF, Upper(User)||Domain); compute NTProofStr", "amber", False),
            (0, 1, "4 · AUTHENTICATE_MESSAGE (NTProofStr + optional MIC + optional EPA CBT)", "slate", False),
            (1, 2, "5 · NetrLogonSamLogonEx pass-through validation", "teal", False),
            (2, 1, "6 · Recompute HMAC from AD NTOWF -> STATUS_SUCCESS + user SIDs", "green", False),
        ],
        bottom_note={
            "tag": "Structural Relay Flaw",
            "title": "Unbound Challenge-Response Without Mandatory Signing + Channel Binding (EPA)",
            "body": "Unless SMB/LDAP Signing and TLS Channel Binding Tokens (MsvAvChannelBindings) are enforced on the target, an attacker forwards all 3 messages across protocols (SMB -> AD CS HTTP ESC8 or LDAP).",
            "theme": "red",
        },
        footer="Because the verifier stores unsalted NTOWF = MD4(UTF-16LE(password)), the hash itself is password-equivalent (Pass-the-Hash)."
    )

    # 42. Ch 12: 09-ntlm-fallback-closure.svg
    build_fan_bands(
        P("09-ntlm-fallback-closure.svg"),
        "Eliminating SPNEGO Fallback to NTLM: Four Engineered Kerberos Replacements",
        [
            [
                {"id": "g1", "tag": "Legacy Gap 1", "title": "No Client Line-of-Sight to KDC", "body": "Remote laptop can reach server TCP/445, not DC TCP/88", "theme": "amber"},
                {"id": "g2", "tag": "Legacy Gap 2", "title": "Local SAM / Workgroup Accounts", "body": "No Active Directory domain controller exists", "theme": "amber"},
                {"id": "g3", "tag": "Legacy Gap 3", "title": "Raw IP Address Connections", "body": "Connects to \\\\10.1.2.3\\share with no DNS SPN", "theme": "amber"},
                {"id": "g4", "tag": "Legacy Gap 4", "title": "Hardcoded NTLM SSPI Callers", "body": "Legacy code requesting 'NTLM' package directly", "theme": "amber"},
            ],
            [
                {"id": "f1", "tag": "Closure 1 (Win 11 24H2+)", "title": "IAKerb Proxy", "body": "Target server proxies AS/TGS messages to DC inside SPNEGO", "theme": "green"},
                {"id": "f2", "tag": "Closure 2 (Win 11 24H2+)", "title": "Local KDC", "body": "Built-in KDC in lsass issues local tickets over SAM accounts", "theme": "green"},
                {"id": "f3", "tag": "Closure 3", "title": "IP-SPN Kerberos Policy", "body": "Maps IP endpoints to host Kerberos SPN entries", "theme": "green"},
                {"id": "f4", "tag": "Closure 4", "title": "Negotiate Refactor & Logs", "body": "KB5064479 telemetry + AcquireCredentialsHandle upgrades", "theme": "green"},
            ],
            [{"id": "spn", "tag": "Unified Result Inside SSPI / NEGOEX", "title": "SPNEGO Selects AES Kerberos by Default -> Network NTLM Disabled Safely", "body": "Existing Win32 / .NET callers using 'Negotiate' upgrade transparently without code changes", "theme": "teal"}],
        ],
        [
            ("g1", "f1", "solved by", "teal", False),
            ("g2", "f2", "solved by", "teal", False),
            ("g3", "f3", "solved by", "teal", False),
            ("g4", "f4", "solved by", "teal", False),
            ("f1", "spn", None, "green", False),
            ("f2", "spn", None, "green", False),
            ("f3", "spn", None, "green", False),
            ("f4", "spn", None, "green", False),
        ],
        footer="NTLM survived for 25 years because Kerberos could not serve off-DC, local-account, or IP-addressed connections; IAKerb and Local KDC close that gap."
    )

    # 43. Ch 12: 09-ntlm-disablement-roadmap.svg
    build_vertical_flow(
        P("09-ntlm-disablement-roadmap.svg"),
        "Three-Phase Microsoft Windows NTLM Deprecation & Disablement Roadmap",
        [
            {"tag": "Phase 1 · Shipping (24H2 / Server 2025)", "title": "NTLMv1 Removed & Enhanced NTLM Audit Telemetry (KB5064479)", "body": "Removes legacy NTLMv1 SSP path and records granular per-caller process/target NTLMv2 usage logs", "theme": "amber"},
            {"tag": "Phase 2 · Pre-Release Rollout (2025-2026)", "title": "IAKerb, Local KDC, IP-SPN, & Per-Machine Scope Policies", "body": "Closes valid NTLM fallback scenarios and refactors remaining inbox OS NTLM callers to Negotiate", "theme": "teal", "edge_label": "audit logs identify callers"},
            {"tag": "Phase 3 · Next Major Windows Release", "title": "Network NTLM Disabled by Default OS-Wide", "body": "Inbound and outbound network NTLM blocked out of the box; binaries remain only for explicit break-glass policy", "theme": "green", "edge_label": "all fallbacks closed"},
        ],
        footer="Disabling network NTLM shifts 100% of domain authentication onto Kerberos (Chapter 14), PKI (Chapter 15), and cloud tokens (Chapter 16)."
    )

    # 44. Ch 13: 10-kerberos-message-triple.svg
    build_sequence(
        P("10-kerberos-message-triple.svg"),
        "The Six-Message Active Directory Kerberos Protocol (RFC 4120 + [MS-KILE])",
        [
            {"title": "Domain Client", "sub": "kerberos.dll (SSPI)", "theme": "slate"},
            {"title": "KDC · Auth Service (AS)", "sub": "kdcsvc.dll on DC", "theme": "teal"},
            {"title": "KDC · Ticket-Granting (TGS)", "sub": "kdcsvc.dll on DC", "theme": "teal"},
            {"title": "Application Server", "sub": "SPN Key Holder", "theme": "green"},
        ],
        [
            (0, 1, "1 · AS-REQ (cname, realm, PA-ENC-TIMESTAMP / PKINIT / FAST)", "slate", False),
            (1, 0, "2 · AS-REP: TGT (enc to krbtgt + PAC) + session key K_c,tgs", "teal", False),
            (0, 2, "3 · TGS-REQ: TGT + Authenticator(K_c,tgs) + target SPN", "slate", False),
            (2, 0, "4 · TGS-REP: Service Ticket (enc to SPN key + PAC) + K_c,s", "teal", False),
            (0, 3, "5 · AP-REQ: Service Ticket + Authenticator(K_c,s)", "green", False),
            (3, 0, "6 · AP-REP: Mutual server authentication proof (optional)", "green", True),
        ],
        footer="In Step 5, the Application Server decrypts the Service Ticket locally in O(1) time using its own key without contacting the KDC."
    )

    # 45. Ch 13: 23-krbtgt-pac-convergence.svg
    build_fan_bands(
        P("23-krbtgt-pac-convergence.svg"),
        "Four [MS-PAC] Cryptographic Signatures Converging on One krbtgt Key",
        [
            [{"id": "pac", "tag": "Inside TGT EncTicketPart.authorization-data", "title": "Privilege Attribute Certificate ([MS-PAC] Buffer)", "body": "User SID, Group RIDs, ExtraSIDs (SIDHistory), UPN, LogonInfo, and Claims", "theme": "amber"}],
            [
                {"id": "s1", "tag": "Type 6", "title": "PAC_SERVER_CHECKSUM", "body": "HMAC under target service key (for a TGT, krbtgt itself)", "theme": "slate"},
                {"id": "s2", "tag": "Type 7", "title": "PAC_PRIVSVR_CHECKSUM", "body": "KDC HMAC under krbtgt over Server Checksum bytes", "theme": "slate"},
                {"id": "s3", "tag": "Type 16 · CVE-2020-17049", "title": "PAC_TICKET_CHECKSUM", "body": "krbtgt HMAC binding PAC to outer EncTicketPart flags", "theme": "teal"},
                {"id": "s4", "tag": "KB5020805 · CVE-2022-37967", "title": "PAC_FULL_CHECKSUM", "body": "krbtgt HMAC over entire serialized PAC buffer", "theme": "green"},
            ],
            [{"id": "root", "tag": "Single Realm Trust Root (S-1-5-21-<domain>-502)", "title": "krbtgt Long-Term Key Set (Current + Previous History Slots)", "body": "Encrypts outer TGT EncTicketPart AND keys all four TGT PAC signatures; DCSync theft enables Golden/Diamond/Sapphire forgery", "theme": "red"}],
        ],
        [
            ("pac", "s1", None, "slate", False),
            ("pac", "s2", None, "slate", False),
            ("pac", "s3", None, "teal", False),
            ("pac", "s4", None, "green", False),
            ("s1", "root", "keyed by", "red", False),
            ("s2", "root", "keyed by", "red", False),
            ("s3", "root", "keyed by", "red", False),
            ("s4", "root", "keyed by", "red", False),
        ],
        footer="Evicting a compromised krbtgt key requires two password resets separated by > MaxTicketAge (10h) plus full Tier-0 remediation."
    )

    # 46. Ch 13: 10-kerberos-rbcd-chain.svg
    build_sequence(
        P("10-kerberos-rbcd-chain.svg"),
        "Post-NTLM Resource-Based Constrained Delegation (RBCD) Escalation Chain",
        [
            {"title": "Low-Priv User", "sub": "Controls ATTACKER$", "theme": "amber"},
            {"title": "Domain Controller", "sub": "LDAP + KDC", "theme": "slate"},
            {"title": "Target Server (fs01)", "sub": "Victim Host", "theme": "red"},
        ],
        [
            (0, 1, "1 · Create computer ATTACKER$ with SPN (if MachineAccountQuota > 0)", "amber", False),
            (0, 1, "2 · Write ATTACKER$ SID to fs01 msDS-AllowedToActOnBehalfOfOtherIdentity (via ACL / KrbRelayUp)", "red", False),
            (0, 1, "3 · AS-REQ -> Receive TGT for ATTACKER$", "slate", False),
            (0, 1, "4 · S4U2Self: Request ticket as Administrator to ATTACKER$", "teal", False),
            (0, 1, "5 · S4U2Proxy: Present evidence ticket -> Receive forwardable TGS for cifs/fs01 as Administrator", "red", False),
            (0, 2, "6 · AP-REQ: Authenticate to fs01 as Administrator (zero NTLM packets used)", "red", False),
        ],
        footer="Closed by setting ms-DS-MachineAccountQuota = 0, enforcing LDAP signing + channel binding, and auditing RBCD attributes."
    )

    # 47. Ch 14: 11-pth-prt-storage-class-ladder.svg
    build_vertical_flow(
        P("11-pth-prt-storage-class-ladder.svg"),
        "29-Year Credential Replay Progression: Isolating Storage vs. Exposing Use",
        [
            {"tag": "Gen 1 · On-Disk & VTL0 Cache (1997 / 2008)", "title": "Pass-the-Hash: NTOWF in SAM & VTL0 lsass.exe", "body": "Substitutes MD4 password hash directly into SMB/NTLM challenge responses", "theme": "slate"},
            {"tag": "Gen 2 & 3 · VTL0 Kerberos Cache (2011-2014)", "title": "Pass-the-Ticket & Overpass-the-Hash (.kirbi / AES & RC4 Keys)", "body": "Closed locally on non-DC endpoints when Credential Guard moves NTOWF & TGT keys into VTL1 LsaIso", "theme": "teal", "edge_label": "Credential Guard -> VTL1"},
            {"tag": "Gen 4 · PKI Key Containers (2021)", "title": "Pass-the-Certificate & AD CS ESC1-ESC16 (PKINIT / LDAPS)", "body": "SAN spoofing closed by KB5014754 SID OID, while software PFXs & template ACL flaws remain", "theme": "amber", "edge_label": "pivots outside LsaIso"},
            {"tag": "Gen 5 · CloudAP Broker Seam (2020-Present)", "title": "Pass-the-PRT: TPM-Sealed Root vs. VTL0 CloudAP KDF Context Key", "body": "Even with TPM transport key protection, SYSTEM drives VTL0 cloudap.dll / KDF context keys to mint x-ms-RefreshTokenCredential cookies", "theme": "red", "edge_label": "storage != in-use derivation", "edge_color": "#8d2d3b"},
        ],
        footer="Closing credential replay requires hardware root isolation + isolated per-request signing + downstream verifier Token Protection (PoP)."
    )

    # 48. Ch 14: 11-pth-prt-attack-defense-matrix.svg
    m_rows = [
        ("1 · Pass-the-Hash", "NTOWF substitution"),
        ("2 · Pass-the-Ticket", ".kirbi TGT + session key"),
        ("3 · Overpass-the-Hash", "NTOWF/AES -> AS-REQ"),
        ("4 · Pass-the-Certificate", "AD CS PKINIT / LDAPS"),
        ("5 · Pass-the-PRT", "CloudAP SSO cookie"),
    ]
    m_cols = [
        ("PtH Guidance", "2012-2014 Docs"),
        ("Protected Users", "+ RunAsPPL"),
        ("Credential Guard", "VTL1 LsaIso"),
        ("KB5014754", "Strong SID Map"),
        ("Token Protection", "+ Entra CAE"),
    ]
    m_cells = [
        [("OPEN", "stone"), ("PARTIAL", "amber"), ("CLOSED*", "green"), ("N/A", "stone"), ("N/A", "stone")],
        [("OPEN", "stone"), ("PARTIAL", "amber"), ("CLOSED*", "green"), ("N/A", "stone"), ("N/A", "stone")],
        [("OPEN", "stone"), ("PARTIAL", "amber"), ("CLOSED*", "green"), ("N/A", "stone"), ("N/A", "stone")],
        [("OPEN", "stone"), ("OPEN", "red"), ("OPEN", "red"), ("PARTIAL", "amber"), ("N/A", "stone")],
        [("N/A", "stone"), ("N/A", "stone"), ("OPEN (Use)", "red"), ("N/A", "stone"), ("PARTIAL", "amber")],
    ]
    build_matrix(
        P("11-pth-prt-attack-defense-matrix.svg"),
        "Five-by-Five Credential Replay vs. Defensive Era Matrix",
        "Evaluated on a fully patched Windows 11 endpoint against a local SYSTEM adversary (*CLOSED for local VTL0 extraction)",
        m_rows, m_cols, m_cells,
        "KB5014754 closes SAN spoofing (Certifried) while ESC2-ESC16 require template hardening; Token Protection currently covers supported native apps, not browsers."
    )

    # 49. Ch 15: 12-hello-auth-flow.svg
    build_split_domains(
        P("12-hello-auth-flow.svg"),
        "Windows Hello & Passkey Separation: Local Gesture vs. Remote Signature",
        left={
            "label": "Local Endpoint (Never Leaves Device)",
            "theme": "green",
            "cards": [
                {"tag": "1 · User Verification (UV)", "title": "Device-Bound PIN or ESS Biometric Match", "body": "ESS isolates NIR face matching in VTL1 BioIso.exe and fingerprint matching on SDCP sensors", "theme": "white", "in_arrow": True},
                {"tag": "2 · Hardware Key Gate", "title": "TPM 2.0 NGC Non-Exportable Private Key", "body": "Anti-hammering lockout enforced in silicon; signs challenge inside TPM without exporting sk", "theme": "green", "in_edge": "authorizes key use"},
            ],
        },
        right={
            "label": "Remote Relying Party (Entra / KDC / Web)",
            "theme": "slate",
            "cards": [
                {"tag": "Freshness", "title": "Issues Per-Ceremony Cryptographic Nonce", "body": "Prevents replay of captured assertions", "theme": "white"},
                {"tag": "Zero Shared Secrets Stored", "title": "Verifies Signature Against Enrolled Public Key", "body": "Checks clientDataJSON.origin + SHA256(rpId); database breach leaks zero authenticators", "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "rl", "1 · fresh challenge", "slate"),
            (1, 1, "lr", "2 · origin-bound signature", "green"),
        ],
        boundary_label="Network Boundary",
        footer="Biometric templates and PINs never cross the wire: they unlock a local hardware key operation."
    )

    # 50. Ch 15: 24-webauthn-hybrid-transport.svg
    build_sequence(
        P("24-webauthn-hybrid-transport.svg"),
        "WebAuthn Hybrid Transport (caBLE): Phone Authenticating a Borrowed PC",
        [
            {"title": "Relying Party", "sub": "HTTPS Origin", "theme": "slate"},
            {"title": "Windows Browser", "sub": "webauthn.dll Client", "theme": "teal"},
            {"title": "Cloud Tunnel Relay", "sub": "Untrusted Forwarder", "theme": "amber"},
            {"title": "Phone Authenticator", "sub": "Secure Enclave / TEE", "theme": "green"},
        ],
        [
            (0, 1, "1 · navigator.credentials.get(challenge, rpId)", "slate", False),
            (1, 3, "2 · Display QR code (ephemeral ECDH pubkey + tunnel seed)", "amber", False),
            (3, 1, "3 · BLE encrypted proximity advertisement (physical co-presence)", "teal", True),
            (1, 2, "4 · E2EE CTAP2 GetAssertion(origin, rpIdHash, challenge)", "teal", False),
            (2, 3, "5 · Forward opaque ECDH-encrypted CTAP2 frame", "amber", False),
            (3, 1, "6 · Local biometric UV -> return E2EE origin-bound assertion", "green", False),
            (1, 0, "7 · Submit signed WebAuthn assertion (no key left on PC)", "green", False),
        ],
        footer="The QR code anchors E2EE cryptography, BLE proves physical proximity, and the Phone signs the PC browser's exact origin."
    )

    # 51. Ch 15: 24-webauthn-windows-registration.svg
    build_split_domains(
        P("24-webauthn-windows-registration.svg"),
        "Windows webauthn.dll OS Dispatcher & 24H2 Plug-In Architecture",
        left={
            "label": "Browser / Native Application",
            "theme": "slate",
            "cards": [
                {"tag": "Origin Enforcement", "title": "Edge / Chrome / Firefox / Native App", "body": "Constructs clientDataJSON with actual HTTPS origin so page JS cannot spoof rpId", "theme": "white", "in_arrow": True},
                {"tag": "RP Response", "title": "Receives Public Key + Attestation / Assertion", "body": "Browsers never touch raw USB-HID, BLE, or TPM handles directly", "theme": "white", "in_arrow": True},
            ],
        },
        right={
            "label": "OS Platform Layer (webauthn.dll)",
            "theme": "teal",
            "cards": [
                {"tag": "Unified Win32 Surface", "title": "webauthn.dll Ceremony Router", "body": "Mediates Conditional UI autofill, Windows Hello UV, and provider selection", "theme": "white", "in_arrow": True},
                {"tag": "Three Backing Tiers", "title": "1) TPM 2.0 (BE=0, AAL3) · 2) CTAP2 Key · 3) 24H2 IPluginAuthenticator (BE=1, AAL2)", "body": "Vault plug-ins (1Password / Bitwarden) delegate UV back to Windows Hello via WebAuthNPluginPerformUserVerification", "theme": "green", "in_edge": "dispatches to provider"},
            ],
        },
        bridges=[
            (0, 0, "lr", "MakeCredential / GetAssertion", "teal"),
            (1, 1, "rl", "signed WebAuthn bytes", "green"),
        ],
        boundary_label="OS Dispatch Boundary",
        footer="Device-bound TPM/FIDO2 keys (BE=0) qualify for NIST AAL3; synced and vault-backed passkeys (BE=1) cap at AAL2."
    )

    # 52. Ch 15: 24-webauthn-recovery-floor.svg
    build_fan_bands(
        P("24-webauthn-recovery-floor.svg"),
        "The Account-Recovery Floor Theorem: System AAL = min(Ceremony, Recovery)",
        [
            [{"id": "top", "tag": "Front-Door Sign-In Ceremony (AAL2 / AAL3 Phishing-Resistant)", "title": "Origin-Bound WebAuthn / Windows Hello Signature (clientDataJSON.origin + rpIdHash)", "body": "Defeats AitM reverse-proxy phishing kits (Evilginx / Tycoon 2FA) mathematically", "theme": "green"}],
            [
                {"id": "p1", "tag": "Apple iCloud", "title": "ADP Sync", "body": "28-char Recovery Key, Contact, or trusted device + SMS bootstrap", "theme": "amber"},
                {"id": "p2", "tag": "Google / MSA", "title": "Synced Passkeys", "body": "Recovery key or fallback to recovery email / SMS-OTP", "theme": "amber"},
                {"id": "p3", "tag": "24H2 Plug-Ins", "title": "3rd-Party Vaults", "body": "Master password + Secret Key / 2FA recovery code", "theme": "amber"},
                {"id": "p4", "tag": "Entra ID", "title": "Enterprise WHfB", "body": "Helpdesk Temporary Access Pass (TAP) or dual BE=0 FIDO2 keys", "theme": "slate"},
            ],
            [{"id": "bot", "tag": "Effective Account Assurance Ceiling", "title": "Out-of-Band Fallback Determines Whole-System Security", "body": "If lost-device recovery falls back to SMS, email, or unverified helpdesk TAP, attackers bypass WebAuthn entirely via the recovery door", "theme": "red"}],
        ],
        [
            ("top", "p1", None, "amber", False),
            ("top", "p2", None, "amber", False),
            ("top", "p3", None, "amber", False),
            ("top", "p4", None, "slate", False),
            ("p1", "bot", "recovery path", "red", False),
            ("p2", "bot", "recovery path", "red", False),
            ("p3", "bot", "recovery path", "red", False),
            ("p4", "bot", "if unproofed TAP", "red", True),
        ],
        footer="Achieving end-to-end AAL3 requires enrolling >= 2 physically separate BE=0 authenticators and identity-proofed recovery."
    )

    # 53. Ch 16: 28-etw-vista-fanout.svg
    build_fan_bands(
        P("28-etw-vista-fanout.svg"),
        "Windows Vista Unified Manifest ETW Model: Lock-Free Buffers & 8-Session Fan-Out",
        [
            [{"id": "prov", "tag": "Unified Event Provider", "title": "EventRegister + EventWrite (Kernel or User-Mode Provider)", "body": "Compiled XML manifest (mc.exe / wevtutil im) or inline TraceLogging TLV schema", "theme": "slate"}],
            [
                {"id": "ring", "tag": "Real-Time ETW Path", "title": "Lock-Free Per-CPU Kernel Ring Buffers", "body": "CPU k writes to CPU k buffer with zero cross-core lock contention; async writer thread drains", "theme": "teal"},
                {"id": "evtx", "tag": "Event Log Path", "title": "Channel Demultiplexer (.evtx)", "body": "Persists Admin / Operational events to Windows Event Log service", "theme": "amber"},
            ],
            [{"id": "sub", "tag": "Multi-Agent Coexistence (Up to 8 Concurrent Sessions per Manifest Provider)", "title": "Defender (MsMpEng) · CrowdStrike · Elastic · SentinelOne · Sysmon · Research Tap", "body": "Replaced Windows 2000 MOF single-session limit where a second subscriber silently stole events from the first", "theme": "green"}],
        ],
        [
            ("prov", "ring", "hot-path copy", "teal", False),
            ("prov", "evtx", "channel match", "amber", False),
            ("ring", "sub", "OpenTrace + ProcessTrace", "green", False),
            ("evtx", "sub", "Event Log / SIEM", "amber", True),
        ],
        footer="ETW guarantees bounded producer latency by making delivery asynchronous and lossy under extreme consumer backpressure."
    )

    # 54. Ch 16: 28-etw-catalogue-layers.svg
    build_vertical_flow(
        P("28-etw-catalogue-layers.svg"),
        "Security Provider Emission Layers: Why 0xC3 User-Mode Patching Cannot Blind EtwTi",
        [
            {"tag": "Layer 1 · Caller User Mode (Patchable In-Process)", "title": "DotNETRuntime · PowerShell (4104) · AMSI · WebAuthN", "body": "Emitted through ntdll!EtwEventWrite -> NtTraceEvent inside the target process; muted locally by writing 0xC3 (RET) or DR0-DR3 hooks", "theme": "amber"},
            {"tag": "Layer 2 · Kernel Manifest & Callback Providers (VTL0 Ring 0)", "title": "Microsoft-Windows-Kernel-Process / File / Network / Registry & SysmonDrv.sys", "body": "Emitted inside ntoskrnl.exe beyond user-mode ntdll; readable by local SYSTEM/Admin sessions", "theme": "slate", "edge_label": "crosses syscall boundary"},
            {"tag": "Layer 3 · Protected Kernel Syscall Sensor (VTL0 Ring 0)", "title": "Microsoft-Windows-Threat-Intelligence (EtwTi: {f4e1897c-...})", "body": "Fires inside ntoskrnl syscall handlers for VirtualAlloc, ProtectVM, MapView, QueueUserAPC, SetThreadContext, and ReadVM(lsass)", "theme": "teal"},
            {"tag": "Consumer Turnstile", "title": "Antimalware-PPL + ELAM Boot Certificate Gate (1.3.6.1.4.1.311.61.4.1)", "body": "EnableTraceEx2 on EtwTi returns ERROR_ACCESS_DENIED to plain SYSTEM/Admin; admits only ELAM-enrolled Antimalware-PPL EDRs", "theme": "green", "edge_label": "gated subscription"},
        ],
        footer="Blinding EtwTi requires crossing into VTL0 Ring 0 (BYOVD), which HVCI and the Vulnerable Driver Blocklist exist to block."
    )

    # 55. Ch 16: 28-etw-attack-defense-timeline.svg
    build_dual_rail_timeline(
        P("28-etw-attack-defense-timeline.svg"),
        "Five Generations of ETW Tampering vs. Structural Platform Defenses",
        left_label="Offensive Blinding Tradecraft",
        right_label="Windows Architectural Countermeasure",
        rows=[
            {"year": "2014-18", "left": {"tag": "Gen 1 · Boot Config", "title": "Autologger Registry & ControlTrace Tampering", "body": "Disables HKLM\\...\\WMI\\Autologger sessions as SYSTEM before reboot", "theme": "amber"},
             "right": {"tag": "Configuration Integrity", "title": "PPL-Protected Sessions & Sysmon Event ID 13", "body": "Blocks non-PPL session stop calls and alerts on Autologger registry writes", "theme": "green"}},
            {"year": "RS-Era", "right": {"tag": "Proactive Kernel Sensor", "title": "EtwTi + Antimalware-PPL / ELAM Gate", "body": "Moves memory-syscall emission into ntoskrnl.exe years before 0xC3 patching popularized", "theme": "teal"}},
            {"year": "2020", "left": {"tag": "Gen 2 · User Mode", "title": "0xC3 RET Patch & Hardware Breakpoints on ntdll", "body": "Silences DotNETRuntime / AMSI / PowerShell inside the offensive PID only", "theme": "red"},
             "right": {"tag": "Survives Intact", "title": "EtwTi Fires Kernel-Side on Syscall Entry", "body": "ALLOCVM, PROTECTVM, and READVM(lsass) still trigger EDR detections", "theme": "green"}},
            {"year": "2021-26", "left": {"tag": "Gen 3 · Ring 0 BYOVD", "title": "Kernel Struct Corruption (EtwThreatIntProvRegHandle)", "body": "Uses vulnerable signed driver to zero EtwTi handles in VTL0 kernel RAM", "theme": "red"},
             "right": {"tag": "Default-On Win 11 22H2+", "title": "HVCI + Vulnerable Driver Blocklist (+ VTL1 EtwSi*)", "body": "Blocks known LOLDrivers at load time, narrowing Ring 0 write access", "theme": "green"}},
        ],
        footer="ETW is observation, not inline prevention: sub-flush payloads still require synchronous kernel callbacks (PsSetCreateProcessNotifyRoutineEx)."
    )

    # 56. Ch 17: 13-zero-trust-lineage.svg
    build_timeline_spine(
        P("13-zero-trust-lineage.svg"),
        "Intellectual & Regulatory Lineage of Zero Trust Architecture",
        [
            {"year": "2010", "tag": "Conceptual Origin", "title": "John Kindervag (Forrester): 'No More Chewy Centers'", "body": "Rejects trusted internal LAN vs. untrusted WAN perimeter assumptions in favor of ubiquitous verification.", "theme": "slate"},
            {"year": "2014-17", "tag": "Production Exemplar", "title": "Google BeyondCorp (Ward & Beyer)", "body": "Demonstrates enterprise-scale access gated on managed-device and user identity over untrusted networks without VPNs.", "theme": "teal"},
            {"year": "2017-18", "tag": "Continuous Risk Framing", "title": "Forrester ZTX & Gartner CARTA", "body": "Extends point-in-time login checks into continuous risk and posture evaluation across workloads and data.", "theme": "slate"},
            {"year": "Aug 2020", "tag": "Normative Architecture", "title": "NIST SP 800-207: Zero Trust Architecture", "body": "Defines vendor-neutral Control Plane (Policy Engine + Policy Administrator = PDP) and Data Plane (PEP), four months before SUNBURST.", "theme": "amber"},
            {"year": "2022-25", "tag": "Federal & Cloud Mandate", "title": "OMB M-22-09, CISA ZTMM v2.0, & Microsoft Entra Conditional Access", "body": "Mandates phishing-resistant MFA, device compliance, and explicit per-request verification across enterprise/federal estates.", "theme": "green"},
        ],
        footer="Zero Trust turns every on-box guarantee from Chapters 1-18 into an evaluable input signal at the Policy Decision Point."
    )

    # 57. Ch 19: 13-zero-trust-conditional-access.svg
    build_vertical_flow(
        P("13-zero-trust-conditional-access.svg"),
        "NIST SP 800-207 Control & Data Plane Loop in Microsoft Entra ID",
        [
            {"tag": "1 · Attested Endpoint", "title": "Windows 11 Client (TPM 2.0 + VBS/HVCI + WHfB + Sense EDR)", "body": "Presents PRT PoP cookie (x-ms-RefreshTokenCredential), phishing-resistant assertion, and Intune DeviceId", "theme": "slate"},
            {"tag": "2 · Signal Ingestion", "title": "Intune Compliance + Entra ID Protection + Defender XDR", "body": "Supplies isCompliant, machineRiskScore, signInRisk, and authenticationStrength claims", "theme": "teal", "edge_label": "device + risk signals"},
            {"tag": "3 · Policy Decision Point (PDP)", "title": "Microsoft Entra Conditional Access Engine", "body": "Evaluates all matching policies in parallel: explicit Block wins; Grant controls combine conjunctively (AND)", "theme": "purple", "edge_label": "evaluates all policies"},
            {"tag": "4 · Policy Enforcement Point (PEP)", "title": "Entra STS + Cloud Resource Server (Exchange, SharePoint, Graph)", "body": "Issues & verifies scoped access token enforcing Token Protection (PoP) and session constraints", "theme": "green", "edge_label": "grant + session controls"},
        ],
        side_notes={
            3: {"tag": "Post-Issuance Loop (t > 0)", "title": "Continuous Access Evaluation", "body": "Pushes critical revocations back to PEP within <= 15 min (Chapter 20)", "theme": "amber", "dashed": False, "edge_label": "CAE push", "edge_color": "#b07926", "reverse": True},
        },
        footer="Network location grants zero implicit access; compromising the IdP signing key itself bypasses PDP evaluation (Chapter 23)."
    )

    # 58. Ch 17: 13-zero-trust-defender-xdr.svg
    build_fan_bands(
        P("13-zero-trust-defender-xdr.svg"),
        "Microsoft Defender XDR Cross-Domain Signal Composition Plane",
        [
            [
                {"id": "mde", "tag": "Endpoints", "title": "Defender for Endpoint", "body": "ETW / EtwTi, process trees (w3wp->cmd), device risk", "theme": "slate"},
                {"id": "mdi", "tag": "On-Premises AD", "title": "Defender for Identity", "body": "DC 4662 DCSync SACLs, Kerberos & AD FS anomalies", "theme": "teal"},
                {"id": "mda", "tag": "Cloud Sessions", "title": "Defender for Cloud Apps", "body": "OAuth/SAML token anomalies & mass exfiltration", "theme": "green"},
                {"id": "mdo", "tag": "Collaboration", "title": "Defender for Office 365", "body": "Phishing links, payload detonation, BEC signals", "theme": "amber"},
            ],
            [{"id": "xdr", "tag": "Unified Correlation Plane", "title": "Shared KQL Hunting Schema & Cross-Domain Incident Graph", "body": "Fuses endpoint, AD, AD FS, and cloud-token alerts from one intrusion into a single correlated incident", "theme": "purple"}],
            [{"id": "act", "tag": "Automated Response -> Zero Trust PDP", "title": "Elevates Device / User Risk -> Conditional Access & CAE Revoke Access", "body": "Contains compromised hosts or identities across cloud resources automatically", "theme": "red"}],
        ],
        [
            ("mde", "xdr", None, "slate", False),
            ("mdi", "xdr", None, "teal", False),
            ("mda", "xdr", None, "green", False),
            ("mdo", "xdr", None, "amber", False),
            ("xdr", "act", "risk elevation", "red", False),
        ],
        footer="Supply-chain campaigns (SUNBURST) span build server -> AD -> AD FS -> M365; isolated single-plane sensors see only fragments."
    )

    # 59. Ch 17: sunburst-golden-saml.svg
    build_vertical_flow(
        P("sunburst-golden-saml.svg"),
        "SUNSPOT -> SUNBURST -> Golden SAML: Bypassing Code Signing & Cloud MFA",
        [
            {"tag": "1 · Build-Pipeline Injection", "title": "SUNSPOT Monitors MsBuild.exe on SolarWinds Build Server", "body": "Atomically swaps InventoryManager.cs before C# compilation and restores clean source on disk afterward", "theme": "amber"},
            {"tag": "2 · Valid Vendor Signature", "title": "SolarWinds Signs Orion DLL with Legitimate Authenticode Cert", "body": "< 18,000 enterprises validate the genuine publisher signature and execute SUNBURST inside trusted monitoring", "theme": "slate", "edge_label": "signed post-injection"},
            {"tag": "3 · On-Premises Escalation", "title": "Selective TEARDROP / Raindrop Pivot (~100 High-Value Targets)", "body": "Harvests credentials and extracts on-premises AD FS SAML token-signing private key", "theme": "red"},
            {"tag": "4 · Golden SAML Forgery", "title": "Mint Arbitrary SAML 2.0 Assertions Offline (Including MFA Claims)", "body": "Cloud tenant trusts federated AD FS cert and issues M365 tokens without touching a DC or prompting MFA", "theme": "red", "edge_label": "stolen AD FS key", "edge_color": "#8d2d3b"},
        ],
        footer="Closed upstream by SLSA Build Level 3 + Sigstore ephemeral signing, and in identity by retiring AD FS for cloud-native auth."
    )

    # 60. Ch 18: 14-cae-timeline.svg
    build_dual_rail_timeline(
        P("14-cae-timeline.svg"),
        "13-Year Evolution from Static OAuth Expiry to Continuous Access Evaluation",
        left_label="IETF & OpenID Standards Track",
        right_label="Zero Trust & Microsoft Entra CAE",
        rows=[
            {"year": "2012-13", "left": {"tag": "RFC 6749 & RFC 7009", "title": "Static Bearer JWTs & Client /revoke", "body": "O(1) local RP validation scales cloud APIs, creating the 1-hour fired-employee window", "theme": "amber"}},
            {"year": "2015-18", "left": {"tag": "RFC 7662 & RFC 8417", "title": "/introspect Poll vs. Signed SET Envelope", "body": "Per-request introspection bottlenecks hyperscale IdPs; RFC 8417 defines Security Event Tokens", "theme": "slate"}},
            {"year": "2019-20", "left": {"tag": "RFC 8935 / 8936", "title": "Tulshibagwale CAEP & SET Push/Poll", "body": "Proposes pub-sub push from IdP to RP so cost scales with events, not requests", "theme": "teal"},
             "right": {"tag": "NIST 800-207 + Entra Preview", "title": "Microsoft Entra CAE Public Preview", "body": "Replaces failed 5-minute short-token experiments with push revocation + 28h tokens", "theme": "green"}},
            {"year": "Jan 2022", "right": {"tag": "Production Hyperscale GA", "title": "Microsoft Entra CAE General Availability", "body": "<= 15 min critical-event revocation & instant IP enforcement across Exchange, SharePoint, Teams, Graph", "theme": "green"}},
            {"year": "Sep 2025", "left": {"tag": "Vendor-Neutral Final Specs", "title": "OpenID SSF 1.0, CAEP 1.0, & RISC 1.0 Approved", "body": "Standardizes cross-vendor SaaS session revocation and risk sharing atop RFC 8417", "theme": "teal"}},
        ],
        footer="Decoupling revocation from token expiry lets CAE-capable MSAL clients (cp1) safely use 28-hour tokens while revoking in minutes."
    )

    # 61. Ch 18: 14-cae-roundtrip.svg
    build_vertical_flow(
        P("14-cae-roundtrip.svg"),
        "End-to-End CAE Push Revocation & HTTP 401 Claims-Challenge Handshake",
        [
            {"tag": "1 · Control-Plane Trigger", "title": "Admin Disables Account / Resets Password / Revokes Sessions", "body": "Or Entra ID Protection elevates User Risk to High (five critical CAE events)", "theme": "amber"},
            {"tag": "2 · Out-of-Band Push (<= 15 Min SLO)", "title": "Entra ID Pushes Revocation Watermark to Subscribed RPs", "body": "Exchange Online, SharePoint Online, Teams, and MS Graph cache subject nbf watermark in memory", "theme": "teal", "edge_label": "async pub-sub push"},
            {"tag": "3 · Data-Plane Hot Path (O(1))", "title": "Client Presents Unexpired Pre-Revocation Bearer JWT", "body": "RP verifies JWT signature locally and compares token iat against cached subject revocation watermark", "theme": "slate"},
            {"tag": "4 · In-Band Wire Rejection", "title": "HTTP 401 + WWW-Authenticate: error=\"insufficient_claims\"", "body": "Base64URL claims JSON demands fresh token with nbf >= revocation timestamp", "theme": "red", "edge_label": "token iat < watermark", "edge_color": "#8d2d3b"},
            {"tag": "5 · MSAL Re-Acquisition Blocked", "title": "cp1-Enlightened MSAL Calls Entra ID -> Access Denied", "body": "MSAL bypasses local cache and queries Entra STS, which enforces disabled/risk policy and terminates session", "theme": "green", "edge_label": "MSAL retries STS"},
        ],
        footer="Strict Location IP changes enforce instantaneously (0 propagation lag) because the RP observes the client IP directly on the socket."
    )

    # 62. Ch 18: 14-cae-design-space.svg
    c = SvgCanvas(900, 490)
    y = c.add_header("Cloud Session Security Plane: Stale Authorization vs. Stolen Token Possession") + 14
    top_banner_h = c.add_card(112.0, y, 748.0, tag="Orthogonal Edge Layer",
                              title="Identity-Aware Reverse Proxies (Global Secure Access / IAP / Cloudflare)",
                              body="Terminate connections inline for proxied apps, whereas CAE & PoP operate inside native cloud APIs",
                              theme="stone", dashed=True, align="center", title_size=11.5, body_size=10.0)
    ax_x, ax_y = 112.0, y + top_banner_h + 22.0
    pw, ph = 748.0, 290.0
    c.add_rect(ax_x, ax_y, pw, ph, fill="#faf8f5", stroke="#bfb8ad", rx=6, layer="bg")
    c.add_line(ax_x + pw / 2, ax_y, ax_x + pw / 2, ax_y + ph, color="#cbd5e1", width=1.4, dash="5,4", layer="bg", is_connector=False)
    c.add_line(ax_x, ax_y + ph / 2, ax_x + pw, ax_y + ph / 2, color="#cbd5e1", width=1.4, dash="5,4", layer="bg", is_connector=False)

    cw, ch = (pw - 36.0 - 116.0) / 2, ph / 2 - 32.0
    lx_card = ax_x + 18.0
    rx_card = ax_x + pw - 18.0 - cw
    c.add_card(lx_card, ax_y + 16, cw, h=ch, tag="Push + Cached O(1)",
               title="Microsoft CAE & OpenID SSF/CAEP 1.0", body="Revokes legitimately issued tokens within minutes of state/risk change",
               theme="green", align="center", title_size=11.5, body_size=10.0)
    c.add_card(rx_card, ax_y + 16, cw, h=ch, tag="Cryptographic Binding",
               title="Entra Token Protection, DPoP (RFC 9449), & mTLS", body="Requires TPM/client private-key proof so stolen bearer tokens fail replay",
               theme="teal", align="center", title_size=11.5, body_size=10.0)
    c.add_line(lx_card + cw, ax_y + 16 + ch / 2, rx_card, ax_y + 16 + ch / 2,
               color="#2b6a4c", width=1.6, dash="4,3", arrow_start=True, arrow_end=True,
               label="compose", label_pos=0.50, label_color="#2b6a4c")

    c.add_card(lx_card, ax_y + ph / 2 + 16, cw, h=ch, tag="Poll / Static Expiry",
               title="RFC 7662 /introspect & Short Lifetimes", body="Introspection bottlenecks hyperscale IdPs; short TTLs amplify refresh load",
               theme="amber", align="center", title_size=11.5, body_size=10.0)
    c.add_card(rx_card, ax_y + ph / 2 + 16, cw, h=ch, tag="Default RFC 6749",
               title="Unbound Bearer Access Tokens", body="Any party who copies the token string authenticates until expiry/revocation",
               theme="red", dashed=True, align="center", title_size=11.5, body_size=10.0)

    c.add_text(ax_x + pw / 4, ax_y + ph + 22, "Solves Stale Authorization", size=10.5, fill="#2b6a4c", bold=True, anchor="middle")
    c.add_text(ax_x + 3 * pw / 4, ax_y + ph + 22, "Solves Stolen Bearer Possession", size=10.5, fill="#236b66", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + ph / 4, "Modern", size=10.2, fill="#2b6a4c", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + ph / 4 + 14, "Controls", size=10.2, fill="#2b6a4c", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + 3 * ph / 4, "Legacy", size=10.2, fill="#875a14", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + 3 * ph / 4 + 14, "Trade-Offs", size=10.2, fill="#875a14", bold=True, anchor="middle")
    c.height = ax_y + ph + 44.0
    c.save(P("14-cae-design-space.svg"))

    # 63. Ch 19: 29-confidential-vms-azure-stack.svg
    build_split_domains(
        P("29-confidential-vms-azure-stack.svg"),
        "Azure Confidential VM Stack: Orthogonal VMPL/TD x VTL Isolation & SKR Attestation",
        left={
            "label": "Hardware Memory Protection Stack",
            "theme": "green",
            "cards": [
                {"tag": "Silicon Root of Trust", "title": "AMD SEV-SNP (AMD-SP + RMP) / Intel TDX (SEAM + PAMT)", "body": "Inline AES memory encryption + hardware page-ownership tables + VCEK / DCAP signing", "theme": "slate"},
                {"tag": "Outside Memory TCB (Untrusted Host)", "title": "Azure Hyper-V Host VMM (Sees Ciphertext Only)", "body": "Schedules vCPUs; blocked from reading or remapping private pages by RMP / PAMT", "theme": "red", "dashed": True, "in_edge": "blocks host reads", "in_dir": "up"},
                {"tag": "Inside TEE · VMPL0 / L1 TD", "title": "OpenHCL Rust Paravisor + Synthesized vTPM", "body": "Mediates shared I/O bounce buffers and hosts per-VM vTPM inside encrypted RAM", "theme": "teal", "in_edge": "CONFIDENTIALITY BOUNDARY", "in_dir": "up"},
                {"tag": "Inside TEE · VMPL2 / L2 TD", "title": "Windows Server Guest (VTL0 Kernel | VTL1 VBS + LsaIso)", "body": "VTL1 still isolates Credential Guard & HVCI from a compromised guest VTL0 kernel", "theme": "green", "in_edge": "synthetic devices + vTPM", "in_dir": "up"},
            ],
        },
        right={
            "label": "RATS Passport Attestation & Key Release",
            "theme": "purple",
            "cards": [
                {"tag": "1 · Hardware + Boot Evidence", "title": "SNP_REPORT / TD Quote + OpenHCL vTPM Quote", "body": "Signed by AMD VCEK or Intel Quoting Enclave over launch digest, PCR[7], & nonce", "theme": "white"},
                {"tag": "2 · Verifier (Policy v1.2)", "title": "Microsoft Azure Attestation (MAA)", "body": "Checks TEE type, golden measurement, Secure Boot, VBS, & TCB SVN in authorizationrules", "theme": "purple", "in_edge": "evaluates evidence"},
                {"tag": "3 · Attestation Result", "title": "Signed MAA JWT (sevsnpvm / tdxvm)", "body": "Carries verified runtime, compliance, and TCB claims", "theme": "amber", "in_edge": "mints signed JWT"},
                {"tag": "4 · Relying Party (SKR)", "title": "Azure Key Vault / Managed HSM", "body": "Executes Secure Key Release to unwrap OS-disk / workload keys into CVM", "theme": "green", "in_edge": "releases HSM key"},
            ],
        },
        bridges=[
            (0, 0, "lr", "TEE + vTPM quote", "teal"),
            (3, 3, "rl", "unwrapped key", "green"),
        ],
        footer="VMPL / TD partitioning excludes the cloud host; VBS VTL1 excludes the guest kernel; MAA authorizationrules bind both to HSM key release."
    )

    # 64. Ch 19: 29-confidential-vms-attack-rings.svg
    c = SvgCanvas(900, 500)
    y = c.add_header("Confidential VM Attack Surface: Intact RMP/PAMT Core vs. Outer Architectural Seams",
                     "None of the 2024 attacks broke inline AES or RMP/PAMT; every exploit targeted surrounding notification, cache, or policy seams") + 12
    cx, cy = 450.0, y + 196.0
    rings = [
        (176.0, "#f4f1ea", "#8c857b", "Ring 4 · Relying-Party Policy"),
        (132.0, "#efeaf7", "#5c4282", "Ring 3 · Firmware & TCB SVN"),
        (88.0,  "#f9f1e1", "#b07926", "Ring 2 · Exit & Interrupt Seams"),
        (44.0,  "#e6f4ec", "#2b6a4c", "RMP / PAMT"),
    ]
    for r, fill, stroke, lbl in rings:
        c.add_circle(cx, cy, r, fill=fill, stroke=stroke, stroke_width=1.5, layer="bg")
        if r > 50:
            c.add_pill_label(cx, cy - r + 15.0, lbl, size=9.2, color=stroke, bg="#ffffff",
                             border=stroke, bold=True, allow_card_touch=True)
        else:
            c.add_text(cx, cy - 3.0, "RMP / PAMT", size=9.8, fill="#1e5139", bold=True, anchor="middle")
            c.add_text(cx, cy + 11.0, "Core Intact", size=9.0, fill="#1e5139", anchor="middle")

    # Four corner attack callouts aligned horizontally with exact ring boundary points!
    cw = 230.0
    corners = [
        # (card_x, mid_y_offset, ring_radius, tag, title, body)
        (24.0,  -92.0, 176.0, "Policy Seam", "MAA issuancerules Bug", "Putting gates in issuancerules or omitting GPU quote check"),
        (646.0, -52.0,  88.0, "CVE-2024-25742", "WeSee (#VC Injection)", "Spoofed #VC traps trick SEV-SNP guest handler into leaking keys"),
        (24.0,  +86.0, 132.0, "CVE-2023-20592 · Glitch", "CacheWarp & One Glitch", "INVD drops dirty cache writes; physical glitching hits AMD-SP"),
        (646.0, +52.0,  88.0, "CVE-2024-25743 / 25744", "Heckler (Interrupts)", "Injected int 0x80 / signal vectors corrupt TDX & SEV-SNP flow"),
    ]
    for bx, dy_off, rad, tag, ti, bo in corners:
        bh = SvgCanvas.measure_card_height(cw, tag=tag, title=ti, body=bo, title_size=11.2, body_size=9.8)
        sy = cy + dy_off
        by = sy - bh / 2
        c.add_card(bx, by, cw, h=bh, tag=tag, title=ti, body=bo, theme="red", title_size=11.2, body_size=9.8)
        dx_ring = math.sqrt(rad * rad - dy_off * dy_off)
        if bx < cx:
            c.add_line(bx + cw, sy, cx - dx_ring, sy, color="#8d2d3b", width=1.5, dash="4,3", arrow_end=True)
        else:
            c.add_line(bx, sy, cx + dx_ring, sy, color="#8d2d3b", width=1.5, dash="4,3", arrow_end=True)

    c.height = y + 408.0
    c.save(P("29-confidential-vms-attack-rings.svg"))

    # 65. Ch 20: 15-storm0558-lineage.svg
    build_vertical_flow(
        P("15-storm0558-lineage.svg"),
        "Five Generations of Identity-Authority Forgery: Widening Blast Radius (1997-2023)",
        [
            {"tag": "1997 · Scope: Single Host / Shared Local Admin", "title": "Gen 1: Pass-the-Hash (Ashton / Ochoa)", "body": "Replays stolen user NTOWF hash without cracking password; bounded to systems accepting that account", "theme": "slate", " main_w": 520},
            {"tag": "2014 · Scope: Active Directory Domain / Forest", "title": "Gen 2: Golden, Diamond, & Sapphire Tickets (Delpy / Mimikatz)", "body": "Steals RID 502 krbtgt key via DCSync to forge arbitrary Kerberos TGTs across an entire AD realm", "theme": "teal"},
            {"tag": "2017 · Scope: Customer Cloud Federation", "title": "Gen 3: Golden SAML (Reiner / CyberArk)", "body": "Steals customer AD FS token-signing key to forge SAML assertions across every federated SaaS app", "theme": "slate"},
            {"tag": "2020 · Scope: Multi-Enterprise Supply Chain", "title": "Gen 4: SUNBURST -> Federated Golden SAML (Midnight Blizzard)", "body": "Uses trojanized SolarWinds build to harvest AD FS keys across ~100 targeted organizations", "theme": "amber"},
            {"tag": "2023 · Scope: Cloud Identity Provider Signing Root", "title": "Gen 5: Storm-0558 (2016 Microsoft MSA Signing Key)", "body": "Compromises the cloud provider's own consumer signing key + cross-tier validator flaw to read enterprise mail", "theme": "red"},
        ],
        main_w=580.0,
        footer="Generations 1-4 compromised customer-operated secrets; Generation 5 compromised a multi-tenant cloud provider's own signing root."
    )

    # 66. Ch 20: 15-storm0558-jwt-validation.svg
    build_vertical_flow(
        P("15-storm0558-jwt-validation.svg"),
        "RFC 8725 JWT Validation Pipeline: Where OWA / Exchange Online Snapped",
        [
            {"tag": "Step 1 · Header Parse", "title": "Read JWT Header (alg = RS256, kid = 2016 MSA Key)", "body": "Restricts algorithm family and extracts key identifier", "theme": "green"},
            {"tag": "Step 2 · Converged Metadata", "title": "Fetch Public Keys from Common 2018 Metadata Endpoint", "body": "Endpoint publishes keys for both Consumer MSA and Enterprise Entra ID apps", "theme": "green"},
            {"tag": "Step 3 · Key Lookup", "title": "Match Header kid -> 2016 MSA Public Key", "body": "7-year-old key remained active because manual MSA rotation paused after a 2021 outage", "theme": "amber"},
            {"tag": "Step 4 · Signature Check", "title": "Verify RS256 Signature Over Header.Payload", "body": "Cryptographically VALID: token genuinely signed by the stolen 2016 MSA private key", "theme": "green"},
            {"tag": "Step 5 · RFC 8725 §§3.8-3.9 (OMITTED IN 2022 MAIL PATH)", "title": "Enforce iss == Enterprise Tenant GUID & aud == Exchange Online", "body": "Consumer MSA iss (9188040d-...) was NEVER authorized for State Dept enterprise mailboxes, but caller omitted check", "theme": "red", "dashed": True, "edge_label": "SKIPPED BY CALLER", "edge_color": "#8d2d3b"},
            {"tag": "Impact", "title": "Forged Consumer-Signed Token Granted Enterprise Mailbox Access", "body": "Signature authenticity was mistaken for cross-realm tenant authorization", "theme": "red"},
        ],
        footer="Under EUF-CMA, signature verification proves only which key signed the bytes; Step 5 determines whether that key has authority here."
    )

    # 67. Ch 20: 15-storm0558-attack-chain.svg
    build_vertical_flow(
        P("15-storm0558-attack-chain.svg"),
        "End-to-End Storm-0558 Intrusion & Customer-First Detection Chain",
        [
            {"tag": "Precondition (2016-2021)", "title": "Software-Resident 2016 MSA Signing Key Left Unrotated", "body": "Stored outside FIPS L3 HSM; manual rotation paused after 2021 outage with no automated replacement", "theme": "amber"},
            {"tag": "Stage 1 · Acquisition (Unconfirmed)", "title": "Storm-0558 Obtains 2016 MSA Private Key", "body": "2023 crash-dump artifact retracted in Mar 2024; CSRB (Apr 2024): exact theft vector remains unknown", "theme": "purple", "dashed": True, "edge_label": "mechanism unconfirmed", "edge_dashed": True},
            {"tag": "Stage 2 · Offline Forgery (May 15, 2023+)", "title": "Mint RS256 OIDC Tokens Naming Target Enterprise Mailboxes", "body": "Zero victim endpoints touched; Conditional Access & CAE never see an Entra token-issuance event", "theme": "red"},
            {"tag": "Stage 3 · Cross-Tier Acceptance", "title": "OWA / Exchange Online Accepts MSA-Signed Enterprise Tokens", "body": "~60,000 State Dept emails exfiltrated across 22 enterprise orgs and ~503 personal accounts", "theme": "red"},
            {"tag": "Stage 4 · Detection Inversion (June 15, 2023)", "title": "State Dept SOC Spots Anomalous AppID in MailItemsAccessed", "body": "Caught by a customer paying for Purview Audit Premium -> CISA AA23-193A -> baseline free logging reversal", "theme": "teal", "edge_label": "detected downstream"},
        ],
        footer="Every on-box and session link (Chapters 1-22) held intact; the chain broke where a cloud root secret and a missing issuer check met."
    )

    # 68. Ch 23: 15-storm0558-hardened-path.svg
    build_vertical_flow(
        P("15-storm0558-hardened-path.svg"),
        "Post-Incident Identity-Plane Re-Architecture (Secure Future Initiative)",
        [
            {"tag": "1 · Attested Execution (Closes Host/Dump Exposure)", "title": "Token-Signing Service Runs Inside Azure Confidential VMs", "body": "100% of MSA & Entra ID signing keys across public & US Gov clouds inside SEV-SNP / TDX (Jul 2026)", "theme": "teal"},
            {"tag": "2 · Hardware Key Custody + Rotation (Closes 2016 Key Theft)", "title": "FIPS 140-3 Level 3 Azure Managed HSM + Integrated HSM", "body": "Non-exportable signing keys (exportable=False) with automated rotation across MSA and Entra ID (Sep 2024)", "theme": "green", "edge_label": "attested HSM call"},
            {"tag": "3 · Library-Enforced Isolation (Closes OWA Step-5 Omission)", "title": "Single Hardened Identity SDK Enforces iss, aud, kid, & tid", "body": "Validates 93% of Entra ID traffic across Microsoft apps by default; 1.4M unused apps retired", "theme": "green", "edge_label": "issues scoped JWT"},
            {"tag": "4 · Commodity Telemetry (Closes Detection Inversion)", "title": "Baseline Free MailItemsAccessed + 2-Year Internal Log Retention", "body": "180-day default customer Purview audit retention across commercial and government clouds", "theme": "slate"},
        ],
        footer="Open industry frontiers: multi-party threshold IdP signing (FROST RFC 9591 / DKLs) and Certificate-Transparency-style key/token logs."
    )

    # 69. Ch 11: 30-bitlocker-key-hierarchy.svg
    build_vertical_flow(
        P("30-bitlocker-key-hierarchy.svg"),
        "BitLocker Three-Tier Key Hierarchy & Hardware-Encryption Failure Seam",
        [
            {"tag": "Tier 1 · Key Protectors", "title": "TPM2_Seal(PCR 7, 11) + Pre-Boot PIN + 48-Digit Recovery Key", "body": "Multiple independent protectors wrap the same 256-bit VMK inside -FVE-FS- volume metadata", "theme": "slate"},
            {"tag": "Tier 2 · Volume Master Key", "title": "256-Bit VMK (Wrapped Under AES-CCM)", "body": "Rotating a compromised PIN or recovery password re-wraps only the 32-byte VMK in milliseconds", "theme": "teal", "edge_label": "TPM2_Unseal + PIN"},
            {"tag": "Tier 3 · Full Volume Encryption Key", "title": "256-Bit / 512-Bit FVEK Held in fvevol.sys Pool", "body": "Unwrapped into kernel RAM at boot; never written in cleartext to storage media", "theme": "amber", "edge_label": "AES-CCM unwrap"},
            {"tag": "Inline Block Cipher", "title": "fvevol.sys Software XTS-AES-128 / XTS-AES-256", "body": "Encrypts every 16-byte block per sector tweak T = E_K2(sector) * alpha^j below ntfs.sys", "theme": "green", "edge_label": "sector I/O"},
        ],
        side_notes={
            1: {"tag": "WinRE / Bus Seam", "title": "TPM-Only Physical Bypasses", "body": "SPI sniffing, Bitpixie, & WinRE swaps hit unattended VMK unseal", "theme": "red", "edge_label": "if no PIN"},
            3: {"tag": "ADV190023 · S&P 2019", "title": "Broken TCG Opal SEDs", "body": "Drive firmware decoupled MEK from password; Windows defaults to software XTS", "theme": "red", "edge_label": "avoid Opal"},
        },
        footer="TPM+PIN + Kernel DMA Protection + software XTS-AES closes bus sniffing, unattended WinRE unseal, and broken SSD controller firmware."
    )

    # 70. Ch 11: 30-dpapi-keyiso-custody.svg
    build_split_domains(
        P("30-dpapi-keyiso-custody.svg"),
        "Online Secret Custody: User-Scoped DPAPI vs. VTL1 KeyIso & Enclave Isolation",
        left={
            "label": "Ambient User-SID Scope (VTL0 Exposure)",
            "theme": "amber",
            "cards": [
                {"tag": "CryptProtectData (DPAPI)", "title": "Per-User 512-Bit Rotating MasterKey", "body": "Any process running as the logged-in user SID calls LRPC to lsass to decrypt cookies & tokens", "theme": "white"},
                {"tag": "Forest Escrow ([MS-BKRP])", "title": "Domain Controller RSA BackupKey", "body": "DCSync theft of G$BCKUPKEY_* decrypts every domain user's DPAPI blobs offline across the forest", "theme": "red", "dashed": True, "in_edge": "escrowed to AD"},
            ],
        },
        right={
            "label": "Process & Hardware-Isolated Custody",
            "theme": "green",
            "cards": [
                {"tag": "App-Bound (IElevator) + VBS KeyIso", "title": "Path-Verified Cookies & VTL1 LsaIso Keys", "body": "IElevator binds cookies to browser binary; VBS KeyIso wraps CNG private keys inside VTL1 RAM", "theme": "teal"},
                {"tag": "VTL1 VBS Enclave (vertdll)", "title": "Presence-Gated Enclave Stores (Recall)", "body": "Keys sealed to TPM + Enclave AuthorId/SVN; released only on live Windows Hello ESS user presence", "theme": "green", "in_edge": "adds presence gate"},
            ],
        },
        bridges=[(0, 0, "lr", "hardens secret custody", "teal")],
        boundary_label="Process + VTL1 Wall",
        footer="Classic DPAPI isolates users from offline disk readers, not from same-user malware; VTL1 KeyIso and VBS Enclaves isolate keys from VTL0."
    )

    # 71. Ch 11: 30-recall-enclave-gate.svg
    build_sequence(
        P("30-recall-enclave-gate.svg"),
        "Copilot+ Recall Presence-Gated VBS Enclave Decryption Ceremony",
        [
            {"title": "Windows Hello ESS", "sub": "VTL1 BioIso.exe UV", "theme": "green"},
            {"title": "Recall VBS Enclave", "sub": "VTL1 IUM Enclave", "theme": "teal"},
            {"title": "TPM 2.0 / Pluton", "sub": "Sealed Enclave Key", "theme": "slate"},
            {"title": "Recall UKP Store", "sub": "VTL0 Encrypted SQLite", "theme": "amber"},
        ],
        [
            (0, 1, "1 · Live NIR face / SDCP fingerprint match verdict inside VTL1", "green", False),
            (1, 2, "2 · Unseal per-user master key bound to VBS Enclave identity + SVN", "teal", False),
            (2, 1, "3 · Release master key exclusively into VTL1 enclave memory", "slate", False),
            (3, 1, "4 · Stream AES-GCM encrypted snapshot / vector index pages", "amber", False),
            (1, 1, "5 · Decrypt & evaluate query inside VTL1 (keys never enter VTL0)", "teal", False),
        ],
        footer="Neither offline NVMe imaging nor background user-mode infostealers can bulk-decrypt snapshots without interactive ESS verification."
    )

    # 72. Ch 15: 31-adcs-esc1-pkinit.svg
    build_sequence(
        P("31-adcs-esc1-pkinit.svg"),
        "AD CS ESC1 + PKINIT Domain Escalation & KB5014754 Strong SID Mapping",
        [
            {"title": "Low-Priv Domain User", "sub": "Certipy / Certify", "theme": "amber"},
            {"title": "Enterprise CA", "sub": "certsvc (NTAuth Trust)", "theme": "slate"},
            {"title": "Domain Controller", "sub": "KDC PKINIT Verifier", "theme": "teal"},
        ],
        [
            (0, 1, "1 · Submit CSR on ESC1 template with SAN UPN = Administrator@corp", "red", False),
            (1, 0, "2 · Issue signed X.509 Client Auth cert (omits requester SID on ESC1)", "amber", False),
            (0, 2, "3 · PKINIT AS-REQ presenting issued X.509 certificate", "red", False),
            (2, 2, "4 · KB5014754 Full Enforcement checks OID 1.3.6.1.4.1.311.25.2 == target objectSid", "green", False),
            (2, 0, "5 · Pre-patch / ESC1: issues Admin TGT; KB5014754 blocks Certifried SAN spoofing", "teal", False),
        ],
        footer="Enterprise CAs in NTAuthCertificates hold realm-wide identity authority co-equal with krbtgt (RID 502) and belong in Tier 0."
    )

    # 73. Ch 15: 31-dmsa-badsuccessor.svg
    build_vertical_flow(
        P("31-dmsa-badsuccessor.svg"),
        "BadSuccessor (CVE-2025-53779): Windows Server 2025 dMSA Attribute Escalation",
        [
            {"tag": "1 · Delegated OU Permission", "title": "Attacker Holds CreateChild on Any Organizational Unit", "body": "Commonly delegated to regional helpdesk or server-operator groups outside Tier 0", "theme": "amber"},
            {"tag": "2 · Rogue dMSA Creation", "title": "Create msDS-DelegatedManagedServiceAccount Object", "body": "Attacker owns the newly created dMSA object and holds WriteProperty over its attributes", "theme": "slate", "edge_label": "LDAP Add"},
            {"tag": "3 · Unilateral Forward Pointer", "title": "Set msDS-ManagedAccountPrecededByLink = CN=Administrator", "body": "Sets msDS-DelegatedMSAState = 2 claiming completed migration of Domain Administrator", "theme": "red", "edge_label": "no target write check"},
            {"tag": "4 · KDC PAC Synthesis Flaw", "title": "Server 2025 KDC Copies Target SIDs into dMSA TGT PAC", "body": "Pre-Aug 2025 kdcsvc.dll granted full Domain Admin RID 512 memberships without modifying Administrator", "theme": "red", "edge_label": "S4U / TGS-REQ"},
        ],
        side_notes={
            2: {"tag": "Aug 2025 Fix", "title": "Bidirectional Consent", "body": "KDC verifies authorization on target superseded account before copying SIDs", "theme": "green", "dashed": False, "edge_label": "patched", "edge_color": "#2b6a4c"},
        },
        footer="Delegation links must always be verified on the target principal being impersonated, never solely on the caller's own object."
    )

    # 74. Ch 21: 32-windows-agent-workspace-mcp.svg
    build_split_domains(
        P("32-windows-agent-workspace-mcp.svg"),
        "Windows 11 Agentic OS Containment: Primary User Desktop vs. Agent Workspace",
        left={
            "label": "Primary User Session (Human SID)",
            "theme": "slate",
            "cards": [
                {"tag": "Ambient Personal State", "title": "Interactive Desktop, Browser Vault, & DPAPI", "body": "Holds unlocked user MasterKeys, personal mail, SSH keys, and elevated admin prompts", "theme": "white"},
                {"tag": "Explicit Authorization", "title": "OS Consent & Folder Delegation Broker", "body": "User approves scoped Known-Folder ACLs and reviews high-impact MCP tool actions", "theme": "teal", "in_arrow": True},
            ],
        },
        right={
            "label": "Agent Workspace (Distinct Local Agent SID)",
            "theme": "green",
            "cards": [
                {"tag": "Isolated Session & Identity", "title": "Separate Desktop + Dedicated Agent SID", "body": "Zero access to human DPAPI or primary UIPI windows; distinct ETW & 4688/4663 audit trail", "theme": "green"},
                {"tag": "Mediated Tool Execution", "title": "LPAC Sandboxes + Signed Windows MCP Proxy", "body": "Verifies MCP server publisher signatures (WDAC) and enforces static JSON-RPC schemas", "theme": "teal", "in_edge": "invokes vetted tools"},
            ],
        },
        bridges=[
            (0, 0, "lr", "isolated (no ambient access)", "red"),
            (1, 1, "lr", "scoped ACL + MCP consent", "green"),
        ],
        boundary_label="Session + SID Boundary",
        footer="Separating the agent's Windows SID and desktop prevents indirect prompt injection from inheriting the user's ambient DPAPI and browser state."
    )

    # 75. Ch 21: 32-entra-agent-id-blueprint.svg
    build_fan_bands(
        P("32-entra-agent-id-blueprint.svg"),
        "Microsoft Entra Agent ID Governance: Blueprints, OBO Intersection, & Agent CA",
        [
            [{"id": "bp", "tag": "Parent Definition & Credential Lifecycle", "title": "Agent Identity Blueprint (Verified Publisher + Human Sponsor + Scope Ceiling)", "body": "Manages credential rotation via Auth SDK sidecar, sponsor lifecycle transfer, and maximum inheritable permissions", "theme": "slate"}],
            [
                {"id": "obo", "tag": "Interactive / Delegated", "title": "OBO Agent Identity", "body": "Carries user sub + agent act claims; grants Perm(User) AND Scope(Agent)", "theme": "green"},
                {"id": "aut", "tag": "Background Task", "title": "Autonomous Agent Identity", "body": "Ephemeral or persistent non-OBO token; platform-blocked from Tier-0 admin roles", "theme": "teal"},
                {"id": "usr", "tag": "Collaboration Shim", "title": "1:1 Paired Agent User", "body": "Provisioned only when Exchange / Teams requires a directory user object", "theme": "amber"},
            ],
            [{"id": "pep", "tag": "Runtime Cloud Control Plane", "title": "Conditional Access for Agents + Entra ID Protection Risk Block + CAE Revocation", "body": "Blocks high-risk or unsponsored agents in real time and logs distinct agent principal telemetry across Microsoft Graph", "theme": "purple"}],
        ],
        [
            ("bp", "obo", "instantiates", "green", False),
            ("bp", "aut", "instantiates", "teal", False),
            ("bp", "usr", "pairs 1:1", "amber", False),
            ("obo", "pep", "evaluated by", "purple", False),
            ("aut", "pep", "evaluated by", "purple", False),
            ("usr", "pep", "evaluated by", "purple", False),
        ],
        footer="Unlike static Service Principals, Entra Agent ID enforces human sponsorship, OBO permission intersection, and Tier-0 role ceilings."
    )

    # 76. Ch 21: 32-agent-confused-deputy-xpia.svg
    build_vertical_flow(
        P("32-agent-confused-deputy-xpia.svg"),
        "Indirect Prompt Injection (XPIA) as a Confused Deputy: EchoLeak (CVE-2025-32711)",
        [
            {"tag": "1 · Untrusted External Input", "title": "Attacker Sends Benign-Looking External Email with Hidden Instructions", "body": "Evades inbound XPIA text classifiers without requiring the victim to open or click the message", "theme": "amber"},
            {"tag": "2 · RAG Context Collapse", "title": "Copilot Retrieves External Email Alongside Confidential Internal Files", "body": "System instructions, internal SharePoint data, and untrusted email merge in one LLM token stream", "theme": "red", "edge_label": "retrieved into context"},
            {"tag": "3 · Confused-Deputy Execution", "title": "Injected Tokens Steer Model to Encode Secrets into Allowed Proxy URL", "body": "Exercises victim's ambient OBO Graph read scope and formats secret bytes into Markdown image/link query", "theme": "red", "edge_label": "instruction-data confusion"},
            {"tag": "4 · Deterministic Architectural Closure", "title": "Enforce Strict Egress Origin Locks, Scope Separation, & Out-of-Model Gates", "body": "Security boundaries must sit outside the LLM (CSP/egress allowlist + LPAC/Workspace + OBO intersection)", "theme": "green", "edge_label": "blocked at PEP"},
        ],
        footer="Because natural-language prompt filtering is non-separable in general, deterministic OS and network PEPs must bound blast radius."
    )
    print("Part 2: Generated and collision-verified 44 diagrams!")
