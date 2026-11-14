# Credential Guard and LSASS Isolation

## Overview

* **Role in the Chain:** Hardware-isolated credential vault bridging local `VTL1` hypervisor isolation ([Chapter 6](05-secure-kernel.md)) and enterprise authentication protocols; splits `lsass.exe` so long-term domain secrets move out of `VTL0` user-mode memory into the `LsaIso.exe` (`Trustlet ID 1`) Isolated User Mode process.
* **Core Security Invariant:** Signed-in users' NTLM password hashes (`NTOWF`), Kerberos long-term encryption keys, and Kerberos Ticket Granting Tickets (`TGTs`) reside exclusively in `VTL1` pages unmapped in `VTL0` `SLAT` tables; `VTL0` `lsass.exe` holds only opaque `AES-GCM`-wrapped blobs (`[LSA Isolated Data]`) and context handles.
* **Trusted Computing Base (TCB):** The Hyper-V hypervisor (`hvix64.exe` / `hvax64.exe`), `securekernel.exe`, `LsaIso.exe` in `VTL1` Ring 3, the TPM 2.0 sealing the persistent `VSM master key`, and UEFI NVRAM when configured with UEFI Lock (`LsaCfgFlags = 1`).
* **Primary Failure Modes:** Brokered oracle abuse via `\RPC Control\LSA_ISO_RPC_SERVER` (`Pass-the-Challenge` extracting `NTLMv1`/`NTLMv2` responses without reading `VTL1` memory), harvesting unprotected `VTL0` Kerberos service tickets (`TGS` `Pass-the-Ticket`), capturing cleartext passwords at entry (`SSP` injection, `CredSSP`, keylogging), and out-of-scope Domain Controller `NTDS.dit` attacks (`DCSync`).
* **Handoff:** Eliminates offline extraction of cached `NTOWF` hashes and `TGT` keys from compromised workstations and member servers; relies on [The Death of NTLM (Chapter 12)](09-ntlm.md) to close challenge-response oracle relays, [Kerberos and Ticket Forgery (Chapter 13)](10-kerberos.md) to bound ticket abuse, and [Windows Hello and Passkeys (Chapter 15)](12-hello.md) to eliminate shared password secrets altogether.

## Core Engineering Problem & Threat Model

Windows Single Sign-On (`SSO`) rests on an unforgiving operational requirement: a user types a credential once at interactive logon, and the operating system transparently authenticates that user to SMB file shares, RPC endpoints, IIS web apps, and SQL servers for the remainder of the session without re-prompting [424, 425]. Because legacy challenge-response and ticket protocols (`NTLM`, `Kerberos`, `HTTP Digest`) prove identity using deterministic derivatives of the user's password, `lsass.exe` (the Local Security Authority Subsystem Service, introduced in Windows NT 3.1) historically cached those raw secrets directly inside its `VTL0` user-mode virtual address space [424, 425].

Between 1997 and 2014, adversaries turned that `SSO` cache into the decisive pivot of enterprise post-exploitation. Paul Ashton observed in 1997 that because `NTLM` proves possession of `NTOWF = MD4(UTF-16LE(password))` rather than the cleartext password, the hash itself is a bearer credential (`Pass-the-Hash`) [426, 427]. Hernan Ochoa's `Pass-the-Hash Toolkit` (2008) [428] and Benjamin Delpy's `Mimikatz` (`2011` release; open-sourced April 2014 [283, 429, 430]) automated wholesale extraction from `lsass.exe` memory (`sekurlsa::logonpasswords`), harvesting `NTOWF` hashes (`Pass-the-Hash`), Kerberos `TGTs` and service tickets (`Pass-the-Ticket`), `NTOWF`-as-`RC4` pre-authentication keys (`Overpass-the-Hash`), and even cleartext passwords cached alongside their symmetric decryption keys inside `wdigest.dll` [283, 424]. Every per-binary defense shipped between 2009 and 2014 (`AppLocker`, `Secure Boot`, `ELAM`, `AppContainer`) governed *which code ran*, leaving `lsass.exe` defenseless once an attacker achieved `Administrator` / `SYSTEM` execution (`SeDebugPrivilege`).

Microsoft's initial 2013-2014 counter-pivot exhausted what `VTL0`-only engineering could achieve [431, 432]:
* **`KB2871997` (May 2014) and `Restricted Admin RDP`:** Disabled `WDigest` cleartext caching by default (`UseLogonCredential = 0` on Windows 8.1 / Server 2012 R2+) and allowed RDP clients to authenticate via network logon without sending cleartext passwords to target servers [433, 434], closing *cleartext* disclosure while leaving `NTOWF` hashes intact and `Restricted Admin` itself usable via `Pass-the-Hash`.
* **Active Directory `Protected Users` (2013) and Tiering (`Tier 0/1/2`):** Blocked `NTLM`, `Digest`, `CredSSP`, `DES`/`RC4`, and offline verifiers for sensitive accounts while capping `TGT` lifetimes at four hours [435], paired with administrative host tiering [431, 432].
* **LSA Protection (`RunAsPPL`, [Chapter 8](18-ppl.md)):** Blocked user-mode `OpenProcess(PROCESS_VM_READ)` against `lsass.exe` (`0x41`), yet fell immediately to `BYOVD` kernel drivers (including Delpy's `mimidrv.sys`) zeroing `EPROCESS.Protection` in `VTL0` RAM [283, 292, 300].

Because any secret stored in `VTL0` memory remains readable to a compromised `VTL0` kernel, Microsoft shipped Credential Guard in Windows 10 version 1507 (July 2015) [436, 437] and enabled it by default on eligible domain-joined non-DC installations starting with Windows 11 22H2 (2022) and Windows Server 2025 (2024) [69, 438]. The threat model assumes an adversary holds full `SYSTEM` and `VTL0` Ring 0 read/write control on a workstation or member server; against that adversary, Credential Guard prevents extracting long-term `NTOWF` hashes, Kerberos keys, and `TGTs`, while explicitly excluding active session misuse on the already-compromised host [69, 182].

## Architectural Deep Dive

### The `VTL0` / `VTL1` Agent-Trustlet Split (`lsass.exe` vs. `LsaIso.exe`)

Rather than moving millions of lines of complex network authentication parsers into `VTL1`, Credential Guard splits the Local Security Authority across the hypervisor `SLAT` boundary (`diagrams/08-credential-guard-vtl-boundary.svg`) [182, 439]:

![Figure: Architectural split under Credential Guard. Left, VTL0 lsass.exe retains protocol parsers and short-lived service tickets while holding zero raw NTOWF or TGT keys; right, VTL1 LsaIso.exe holds long-term secrets across the SLAT boundary, reachable only through mediated LSA_ISO_RPC_SERVER calls.](diagrams/08-credential-guard-vtl-boundary.svg)

* **`lsass.exe` (`VTL0` Protocol Broker):** Continues running in `VTL0` Ring 3 (ideally hardened at `PPL/Lsa`, [Chapter 8](18-ppl.md)) and loads all inbox Security Support Providers and Authentication Packages (`msv1_0.dll` for NTLM, `kerberos.dll` for Kerberos, `negoexts.dll`, `cloudap.dll` for Entra ID, `tspkg.dll` for CredSSP, `pku2u.dll`, and `schannel.dll` for TLS [425, 440]). `lsass.exe` owns socket I/O, ASN.1/NDR wire parsing, logon session bookkeeping, and `TGS` service-ticket caches, *but holds zero plaintext `NTOWF` bytes, Kerberos long-term keys, or raw `TGT` session keys* after initial ingestion [182].
* **`LsaIso.exe` (`VTL1` Vault, `Trustlet ID 1`):** Admitted into `VTL1` Isolated User Mode (`IUM`) at boot via the five Secure Kernel gates (`PsAttributeSecureProcess`, Signing Level 12 with `WSCV` `1.3.6.1.4.1.311.10.3.6` + `IUM` `1.3.6.1.4.1.311.10.3.37` EKUs, and `.tpolicy` `s_IumPolicyMetadata`, [Chapter 6](05-secure-kernel.md)) [177, 178, 439]. `LsaIso.exe` generates an ephemeral symmetric wrapping hierarchy in `VTL1`-private pages, internalizes long-term secrets immediately upon logon, and exposes only restricted cryptographic *use* verbs over ALPC [182, 441].

### `[LSA Isolated Data]` Memory Layout and `LSA_ISO_RPC_SERVER` Round-Trips

When an attacker bypasses `RunAsPPL` and dumps `lsass.exe` on a Credential-Guard-protected host (for example using `Mimikatz` or `Pypykatz`), `msv1_0.dll`'s logon-session heap no longer contains 16-byte `NTOWF` digests. Instead, the structure holds an `[LSA Isolated Data]` record containing four distinct elements [441, 442]:

1. **Serialized Header & Type Metadata:** Begins with a versioned protection header (e.g., `0xa0...`) and plaintext routing tags such as ASCII `NtlmHash` (`4e746c6d48617368`) identifying the credential schema without exposing secret bytes [441].
2. **`Context Handle` & `Proxy Info`:** An opaque RPC context reference into `LsaIso.exe`'s session table paired with `VTL0` `lsass.exe` proxy state.
3. **`Encrypted Blob` (`AES-GCM` Ciphertext):** The user's `NTOWF` or Kerberos key material encrypted and authenticated under symmetric keys held exclusively inside `VTL1` RAM, computationally useless offline even if exfiltrated from a full physical memory dump [441].
4. **`DPAPI` Binding GUID:** Links the isolated logon credential to the user's on-disk `DPAPI` master-key hierarchy so `lsass.exe` can request `DPAPI` unwrapping via `LsaIso.exe` without learning the underlying password hash [182, 441].

During a legitimate outbound `NTLMv2` network authentication (`diagrams/08-credential-guard-ntlm-roundtrip.svg`), `msv1_0.dll` receives the remote server's 8-byte challenge in `VTL0`, constructs a client blob (timestamp, target info, client nonce), and sends an RPC request over `\RPC Control\LSA_ISO_RPC_SERVER` (marshaled across `securekernel!IumInvokeSecureService`) supplying the `Context Handle`, `Encrypted Blob`, and challenge parameters [182, 441, 443]. Inside `VTL1`, `LsaIso.exe` unwraps the `Encrypted Blob`, computes `HMAC-MD5` (`NTProofStr` and session base key), and returns *only* the one-time response and session key to `msv1_0.dll`, leaving the `NTOWF` permanently sealed inside `VTL1`. Analogously, for Kerberos `TGS-REQ` exchanges, `LsaIso.exe` holds the `TGT` and TGT session key in `VTL1`, signing authenticators and decrypting KDC `TGS-REP` replies to hand only scoped *service tickets* back to `kerberos.dll` in `VTL0` [182].

![Figure: The per-authentication NTLM round-trip across the agent / trustlet boundary. msv1_0.dll in lsass.exe is the network-side parser; the Secure Kernel mediates the hypercall; LsaIso.exe in VTL1 holds the key and returns only the derived response: the NTOWF never crosses back to VTL0.](diagrams/08-credential-guard-ntlm-roundtrip.svg)

### Persistent `VSM Master Key` and Enforced Protocol Restrictions

Credential Guard normally keeps user `NTOWF` and `TGT` state purely volatile across reboots; whenever `VTL1` trustlets (including Key Guard for `CNG` machine keys) must persist wrapped state across restarts, `LsaIso.exe` seals it under the `VSM master key`, which is itself bound to hardware TPM 2.0 PCR measurements ([Chapter 2](01-tpm.md), [Chapter 4](03-measured-boot.md)) so offline disk theft or boot tampering blocks key unsealing [182].

Because `LsaIso.exe` refuses any API that exports raw password hashes or cleartext equivalents to `VTL0`, enabling Credential Guard enforces hard protocol restrictions by construction [182, 444]:
* **Blocked for Signed-In `SSO` Credentials:** `NTLMv1` (on current builds), `MS-CHAPv2` (breaking legacy `PEAP-MSCHAPv2` Wi-Fi/VPN single sign-on and forcing migration to certificate-based `EAP-TLS`), `WDigest`, and `CredSSP` default delegation [182, 444].
* **Blocked Globally (Even for Prompted Credentials):** Unconstrained Kerberos delegation (`TRUSTED_FOR_DELEGATION`) and Kerberos `DES` encryption (while Constrained Delegation and Resource-Based Constrained Delegation continue functioning) [182].
* **Blocked Third-Party `SSP` Hash Queries:** Custom authentication packages calling `KerbQuerySupplementalCredentialsMessage` to retrieve raw hashes fail by design [444].
* **Default-On Without UEFI Lock (`LsaCfgFlags = 2`):** On Windows 11 22H2+ Enterprise/Education and Windows Server 2025 non-DC domain members, Microsoft enables Credential Guard by default *without* the UEFI NVRAM lock (`LsaCfgFlags = 2`) so administrators discovering broken `PEAP-MSCHAPv2` networks can remotely roll back via Group Policy/Intune without physical BIOS visits; high-security fleets explicitly set `LsaCfgFlags = 1` to anchor enforcement in UEFI NVRAM against `SYSTEM` registry tampering [69, 445].

## Attack Catalog & Gap Analysis

Credential Guard ended the era of passive `sekurlsa` hash extraction on protected endpoints, forcing adversaries onto six distinct bypass and residual pathways: exploiting `CG`-off hosts, abusing `LsaIso.exe` as an active RPC oracle (`Pass-the-Challenge`), stealing unprotected `VTL0` `TGS` tickets, intercepting cleartext inputs prior to `VTL1` ingestion, or attacking Domain Controllers directly.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `VTL0` `LSASS` Dumping (`Mimikatz` / `Nanodump` / `Pypykatz`) | 2011-present | `NTOWF`, `TGT`, and `WDigest` confidentiality on `CG`-off hosts | `SYSTEM` / `SeDebugPrivilege` (plus `BYOVD` `mimidrv.sys` if `RunAsPPL` is on) | Reads `msv1_0.dll`, `kerberos.dll`, and `wdigest.dll` heaps directly from `lsass.exe` memory or minidumps | Enable Credential Guard (`LsaCfgFlags = 1` UEFI-locked) + `RunAsPPL = 1` + `UseLogonCredential = 0` [69, 283, 300, 433] |
| `Pass-the-Challenge` (`PtC`, Lyak) | 2022-present | Operational reuse of `VTL1`-isolated NTLM credentials | `SYSTEM` code injection into `VTL0` `lsass.exe` (`RunAsPPL` bypassed or off) | Injects `SecurityPackage.dll` into `lsass.exe`; invokes `LSA_ISO_RPC_SERVER` with static (`1122334455667788` `NTLMv1` → `crack.sh` in ~30s) or relayed `NTLMv2` challenges | Upgrade to Win11 24H2 / Server 2025 (removes `NTLMv1`), enforce `RunAsPPL = 1` + `HVCI`, and disable `NTLM` ([Chapter 12](09-ntlm.md)) [441, 443, 446] |
| `VTL0` Service-Ticket Theft (`Pass-the-Ticket` / `Rubeus`) | Architectural | Confidentiality of active Kerberos `TGS` service tickets | `SYSTEM` access to `lsass.exe` or user-session `LSA` APIs | Extracts already-minted `TGS` service tickets (e.g., `cifs/`, `http/`, `ldap/`) that remain in `VTL0` `kerberos.dll` caches | Enforce `RunAsPPL = 1`, short ticket lifetimes (`Protected Users`), and monitor anomalous `4769` usage ([Chapter 13](10-kerberos.md)) [182, 435] |
| Registry Downgrade (`LsaCfgFlags = 0` Without UEFI Lock) | 2022-present | Persistence of default-on Credential Guard across reboot | `SYSTEM` / `Administrator` on host using `LsaCfgFlags = 2` (no UEFI lock) | Modifies `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags` (or BCD `DISABLE-LSA-ISO`) and reboots to harvest newly typed logons | Configure Enabled with UEFI Lock (`LsaCfgFlags = 1`) + UEFI Secure Boot ([Chapter 1](16-secure-boot.md)) [69, 170, 445] |
| Pre-Ingestion Cleartext Capture (`SSP` Hook, `CredSSP`, Keylogger) | Architectural | Confidentiality of newly entered or saved generic passwords | Malware in user session or `VTL0` `lsass.exe` prior to/during logon | Captures keystrokes, `CredSSP`/RDP Gateway prompted strings, or Windows Credential Manager generic web secrets in `VTL0` | Replace passwords with hardware-bound Windows Hello / FIDO2 Passkeys ([Chapter 15](12-hello.md)) and dedicated Tier-0 PAWs [182, 431, 444] |
| Domain Controller `NTDS.dit` & `Skeleton Key` (`DCSync`) | 2014-present | Forest-wide `NTOWF` and `krbtgt` secret storage on DCs | Domain Admin / `DS-Replication-Get-Changes-All` rights on DC | Replicates all domain hashes over `MS-DRSR` (`DCSync`) or patches DC `lsass.exe` (`misc::skeleton`), where Credential Guard is unsupported | Enforce strict Tier-0 PAW isolation, `RunAsPPL` + `HVCI` on DCs, and regular `krbtgt` rotation ([Chapter 13](10-kerberos.md)) [69, 182, 447, 448] |

### The RPC Oracle Seam: `Pass-the-Challenge` (Lyak, 2022)

Disclosed by Oliver Lyak in December 2022 [441, 443], Pass-the-Challenge (`PtC`) is the definitive demonstration of where Credential Guard's guarantee stops (`diagrams/08-credential-guard-pass-the-challenge.svg`):

![Figure: The Pass-the-Challenge attack flow. The trustlet is faithful (no page is read and no bug is exploited) but its RPC output is exactly the NTLMv1 response the attacker asked for, and crack.sh recovers the NT hash in ~30 seconds.](diagrams/08-credential-guard-pass-the-challenge.svg)

After obtaining `SYSTEM` and injecting a custom Security Support Provider (`SecurityPackage.dll`) into `VTL0` `lsass.exe` (requiring a `RunAsPPL` bypass or `BYOVD` driver if LSA Protection is active), the implant inherits `lsass.exe`'s legitimate ALPC handle to `\RPC Control\LSA_ISO_RPC_SERVER` [441, 443]. Parsing `[LSA Isolated Data]` in `lsass.exe` RAM yields the victim's `Context Handle`, `Proxy Info`, and `Encrypted Blob`. On pre-24H2 builds where `LsaIso.exe` still exposed its legacy `NTLMv1` calculation routine (`nthash`), `PtC` submitted the chosen challenge `0x1122334455667788`; `LsaIso.exe` faithfully returned a 24-byte `DESL(NTOWF)` response without leaking a single byte of `VTL1` memory, which rainbow tables (`crack.sh`) inverted back into the raw 16-byte `NTOWF` in roughly 30 seconds [441, 443]! Even after Windows 11 24H2 and Windows Server 2025 removed `NTLMv1` ([Chapter 12](09-ntlm.md)) [446], `PtC`'s `challenge` verb can still ask `LsaIso.exe` to sign live `NTLMv2` server challenges on demand, turning the infected workstation into a real-time NTLM relay oracle until `NTLM` itself is disabled [441, 443].

### Documented Exclusions: `TGS` Tickets, Prompted Secrets, and Domain Controllers

Microsoft's architecture documentation explicitly enumerates four boundaries Credential Guard never claims to defend (`diagrams/08-credential-guard-residual-taxonomy.svg`) [69, 182, 444]:

![Figure: The four-class residual taxonomy Credential Guard was never going to close: credential use (not theft), tickets already in lsass, token attacks, and off-box replay, each routed to the chapter that owns it.](diagrams/08-credential-guard-residual-taxonomy.svg)

1. **Kerberos Service Tickets (`TGS`):** While `LsaIso.exe` isolates the `TGT` so an attacker cannot mint arbitrary new service tickets offline, any `TGS` ticket *already requested* by the user during the active session (`cifs/fileserver`, `http/intranet`) resides in `VTL0` `kerberos.dll` memory and remains extractable until expiry [182].
2. **Typed Plaintext and Generic Vaults:** Keyloggers, malicious `CredSSP` prompts, and applications reading generic "Web Credentials" from Windows Credential Manager access secrets in `VTL0` outside `LsaIso.exe` [182, 444].
3. **Off-Box Protocol Attacks:** Network attacks that never touch client memory, such as `Kerberoasting`, `AS-REP Roasting`, and `RBCD` ([Chapter 13](10-kerberos.md)) [449, 450, 451], are completely unaffected by endpoint `VTL1` isolation.
4. **Active Directory Domain Controllers:** Credential Guard is unsupported on Domain Controllers because DC `lsass.exe` (`kdcsvc.dll`, `ntdsa.dll`) must continuously read every domain account's `NTOWF` and Kerberos keys from `NTDS.dit` to verify logons and replicate directory changes (`MS-DRSR` / `DCSync`) [69, 182, 448].

## Theoretical Limits & Structural Invariants

### Storage Isolation vs. Use Isolation (`The Oracle Bound`)

Credential Guard proves a fundamental theorem of compartmentalized systems: isolating a cryptographic key's storage (`VTL1`) while leaving protocol parsing and session initiation in an untrusted broker (`VTL0`) converts key extraction into an oracle-access problem.

Why not move `msv1_0.dll`, `kerberos.dll`, `schannel.dll`, and `cloudap.dll` inside `VTL1` alongside `LsaIso.exe`? Because those providers parse millions of complex, unauthenticated ASN.1, NDR, TLS, and SPNEGO network packets directly from untrusted sockets (as `MS14-066` *WinShock* demonstrated in `schannel.dll` [452]). Importing full network protocol stacks into `VTL1` would balloon the Secure World TCB and turn a single network-parser bug into direct `VTL1` code execution. Keeping `LsaIso.exe` tiny preserves `VTL1` memory integrity at the unavoidable cost of trusting `VTL0` `lsass.exe` to decide *when* to request a challenge signature [182, 443].

### Decoupling Long-Term Secrets from Ephemeral Bearer Artifacts

Consistent with Law 16, protecting the long-term root credential (`NTOWF` or `TGT`) does not protect downstream bearer artifacts derived from it (`VTL0` access tokens, `TGS` service tickets, or HTTP session cookies).

> **Key idea.**
> On a fully hardened endpoint running both **UEFI-locked Credential Guard (`LsaCfgFlags = 1`)* and *UEFI-locked LSA Protection (`RunAsPPL = 1`)**, an attacker who reaches `Administrator` is blocked at `NtOpenProcess` by `PPL`, and an attacker who escalates further to `VTL0` Ring 0 (`BYOVD`) is still blocked at `SLAT` from extracting the `NTOWF` or `TGT` for persistent off-box replay. What the attacker retains is bounded strictly to *in-place session hijacking* on that single compromised machine for as long as the user remains signed in [182, 292].

## Inspecting and Verifying on a Running System

Microsoft explicitly warns against using Task Manager (`LsaIso.exe` process presence) as proof that Credential Guard is protecting credentials [445]. Authoritative verification cross-checks `Win32_DeviceGuard`, `Wininit` Event ID `13`, and registry `LsaCfgFlags` / `WDigest` settings.

### Verifying Active Credential Guard via `Win32_DeviceGuard` and `Wininit` Event `13`

Confirm both that Hyper-V/VBS reports Credential Guard (`1`) inside `SecurityServicesRunning` and that `wininit.exe` logged Event ID `13` on the current boot (elevated PowerShell) [445, 453]:

```powershell
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
[PSCustomObject]@{ VbsStatus = $dg.VirtualizationBasedSecurityStatus; CredGuardRunning = ($dg.SecurityServicesRunning -contains 1) }
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=13,15,16,17} -MaxEvents 2 | Select-Object TimeCreated, Id, Message
```

Expected output on an actively protected endpoint:

```text
VbsStatus CredGuardRunning
--------- ----------------
        2             True

TimeCreated           Id Message
-----------           -- -------
11/14/2026 8:14:52 AM 13 Credential Guard (LsaIso.exe) was started and will protect LSA credentials.
```

In `Wininit`, Event ID `13` confirms active protection, whereas `15` (Secure Kernel not running), `16` (launch failed), or `17` (UEFI variable error) diagnoses why configured policy failed to engage [445].

### Auditing UEFI-Lock Persistence (`LsaCfgFlags`), `WDigest`, and Cached Logons

Inspect `LsaCfgFlags` (`1` = enabled with UEFI lock, `2` = enabled without UEFI lock, `0` = disabled), confirm `WDigest` cleartext caching is disabled (`UseLogonCredential = 0` or absent), and verify offline cached domain verifier count (`CachedLogonsCount`) [69, 433, 445]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags','RunAsPPL' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -ErrorAction SilentlyContinue
Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount'
```

Expected output on a hardened enterprise workstation:

```text
LsaCfgFlags : 1
RunAsPPL    : 1
UseLogonCredential : 0
10
```

Note that on Windows 11 22H2+ default-on systems where Group Policy has not explicitly written `LsaCfgFlags`, `LsaCfgFlags` may be absent while `Win32_DeviceGuard` still reports `CredGuardRunning = True` (operating in UEFI-unlocked default mode; Pro/Pro Education carry-over upgrades additionally write `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\IsolatedCredentialsRootSecret`) [69].

### Verifying `Protected Users` Security Group Membership

Check whether a privileged administrative session carries the `Protected Users` domain RID (`-525`), enforcing `NTLM` block, AES-only Kerberos, and 4-hour `TGT` lifetimes alongside Credential Guard [435]:

```powershell
whoami /groups | Select-String 'Protected Users|-525$'
```

Expected output for a `Protected Users` member:

```text
CONTOSO\Protected Users  Group  S-1-5-21-194827361-847261920-319283746-525  Mandatory group, Enabled by default, Enabled group
```

Absence of `-525` on Tier-0 or Tier-1 administrative accounts leaves `NTLMv2` fallback (`Pass-the-Challenge` v2) and standard 10-hour `TGT` lifetimes active even when Credential Guard is running [435, 443].

## Summary & Handoff

Credential Guard resolved a twenty-year architectural vulnerability at the heart of Windows authentication: by relocating `NTOWF` password hashes, Kerberos long-term keys, and `TGTs` out of `VTL0` `lsass.exe` into `VTL1` `LsaIso.exe` (`Trustlet ID 1`), Windows ensured that neither `Mimikatz` in user mode nor a `BYOVD` driver in Ring 0 can dump reusable long-term secrets from memory. Layered with `KB2871997` (`WDigest` off), `RunAsPPL = 1` ([Chapter 8](18-ppl.md)), and `Protected Users`, Credential Guard transforms workstation compromise from instant domain-wide credential harvesting into a contained single-host incident.

Yet `Pass-the-Challenge` and `VTL0` ticket residuals prove that vaulting the secret on the client cannot cure weaknesses in the *wire protocols* that spend it:

* **Retiring Symmetric Challenge-Response Relays:** Why `NTLM` lacks server authentication and cryptographic channel binding by default (`PetitPotam`, `ESC8`, `Pass-the-Challenge`), and how Windows 11 24H2 / Server 2025 dismantle `NTLM` via `SMB`/`LDAP` signing, `EPA`, and `IAKerb`, is owned by [The Death of NTLM (Chapter 12)](09-ntlm.md).
* **Hardening Domain Ticket Infrastructure and `KRBTGT`:** Defending Active Directory against `Kerberoasting`, `RBCD`, `PAC` spoofing, `DCSync`, and `Golden`/`Silver` tickets belongs to [Kerberos and Ticket Forgery (Chapter 13)](10-kerberos.md).
* **Securing Cloud Bearer Tokens and Eliminating Passwords:** Protecting `CloudAP` `Primary Refresh Tokens` ([Chapter 14](11-pth-prt.md)) and replacing symmetric password secrets with TPM-bound `Windows Hello` and `FIDO2` passkeys ([Chapter 15](12-hello.md)) complete Part III.
