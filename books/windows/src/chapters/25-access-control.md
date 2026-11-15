# Windows Access Control, Integrity Levels, and Impersonation

## Overview

* **Role in the Chain:** Foundational local authorization plane of the Windows NT kernel (`ntoskrnl.exe`); opens Part III (Credentials & Access) by deciding whether a running process or thread (`access token`) may open a securable kernel object (`security descriptor`) or send window messages across trust tiers (`UIPI`).
* **Core Security Invariant:** Every handle open to a securable object passes through the Security Reference Monitor's `SeAccessCheck` routine, which enforces Mandatory Integrity Control (`MIC`, `NO_WRITE_UP`) *before* walking the object's Discretionary Access Control List (`DACL`) in ACE order against the caller's bearer token SIDs and enabled privileges.
* **Trusted Computing Base (TCB):** The `VTL0` Security Reference Monitor (`SeAccessCheck`), Object Manager namespace resolution (`\Device`, `\RPC Control`, `\GLOBAL??`), `win32k.sys` `UIPI` message filtering, `lsass.exe` token creation, and the `LocalSystem` `Appinfo` service + `Winlogon` Secure Desktop brokering administrative elevation.
* **Primary Failure Modes:** Pre-check Object Manager symlink and NTFS hard-link path redirection (`CVE-2020-0668`), overly permissive `DACLs` (`HiveNightmare` `CVE-2021-36934`), split-token `UAC` auto-elevation hijacks across shared `HKCU` state (`UACMe` / `fodhelper`) and `uiAccess=true` carve-outs, and service-to-`SYSTEM` escalation abusing enabled `SeImpersonatePrivilege` across coerced authentication (`Potato` lineage).
* **Handoff:** Governs how minted tokens spend local authority; delegates protecting the authentication secrets inside `LSASS` that *mint* those tokens to Credential Guard ([Chapter 12](08-credential-guard.md)), eliminating network/loopback NTLM coercion to [Chapter 13](09-ntlm.md), and securing domain and cloud identity tokens to [Chapter 14](10-kerberos.md) through [Chapter 17](12-hello.md).

## Core Engineering Problem & Threat Model

Part II ([Chapter 6](05-secure-kernel.md) through [Chapter 9](19-mitigations.md)) established which binaries may execute and how processes defend their control flow. Once code executes legitimately inside a process, the operating system must answer a different question billions of times per second: *may this subject perform this operation on that resource?* Formalized by Butler Lampson's 1971 access matrix [348] and codified as a federal procurement requirement by the 1985 DoD TCSEC C2 ("Orange Book") standard [349], Dave Cutler's Windows NT 3.1 team (July 1993) built Windows around a centralized kernel Security Reference Monitor (`SRM`) evaluating identity-based Access Control Lists (`DACLs`) against per-process access tokens [350, 351].

Across three decades of deployment, pure discretionary `DACLs` collided with two structural failure modes that forced major architectural additions to the NT security model. The first failure mode stemmed from ambient user authority combined with interactive administrative sessions. Because discretionary owners can rewrite their own ACLs and early Windows XP users logged on interactively as full members of `BUILTIN\Administrators`, every browser exploit or office macro inherited administrative group membership and elevated privileges automatically [352, 353]. At the same time, Win32 desktop windows lacked sender authentication, enabling lower-privileged processes on the same interactive desktop to trigger arbitrary callbacks inside `SYSTEM` services through `WM_TIMER` shatter attacks, as demonstrated by Chris Paget in 2002 [354]. Windows Vista (2006) addressed both desktop exposures by introducing Mandatory Integrity Control (`MIC`), User Interface Privilege Isolation (`UIPI`), and User Account Control (`UAC`) split tokens [352, 355, 356].

A second structural failure mode emerged inside background service hosting. Early network worms including `Code Red`, `Nimda`, `SQL Slammer`, and `MSBlast` [357, 358] turned memory-corruption bugs in network daemons into immediate `SYSTEM` compromises because services ran almost universally under `NT AUTHORITY\SYSTEM`. Windows XP SP2 and Windows Server 2003 responded by partitioning services into reduced-privilege `LOCAL SERVICE` and `NETWORK SERVICE` accounts, yet granted both accounts `SeImpersonatePrivilege` in the enabled state by default so RPC, IIS, and SQL Server workloads could continue impersonating connecting clients. Preserving ambient impersonation rights on reduced-privilege service accounts instantiated Norm Hardy's 1988 Confused Deputy problem directly inside Windows service isolation [359, 360, 361, 362, 363].

The local authorization threat model distinguishes boundaries Microsoft commits to servicing with security updates (`User → Kernel`, `AppContainer` sandboxes, and Windows 11 Administrator Protection [173, 364]) from mechanisms Microsoft explicitly classifies as non-boundary safety or UX features (`UAC` split-token elevation and Windows Service Hardening `LOCAL/NETWORK SERVICE → SYSTEM` transitions [173, 365, 366]).

## Architectural Deep Dive

### `SeAccessCheck`, Bearer Tokens, SIDs, and the `DACL` Walk

Whenever a thread opens a handle to a securable kernel object (file, registry key, process, thread, service, named pipe, section, or ALPC port), the Object Manager resolves the object's path, extracts its `SECURITY_DESCRIPTOR`, and invokes `SeAccessCheck` against five logical inputs: the object's security descriptor, the caller's effective access token, the desired access mask, the object type's generic-rights mapping (`GENERIC_READ/WRITE/EXECUTE/ALL` to specific bits), and any previously granted access [367, 368, 369, 370].

![Figure: The anatomy of the two inputs SeAccessCheck reads on every call. Left, the access token (the subject): the caller's user SID, group SIDs, logon SID, privileges, integrity level, token type, and any restricting SIDs. Right, the security descriptor (the object): owner and primary-group SIDs, a deny-first DACL of allow/deny ACEs in canonical order, and a SACL carrying audit and mandatory-integrity-label entries. The token's SIDs are matched against the DACL's ACE SIDs; the token's integrity level against the SACL's mandatory label.](diagrams/25-access-control-token-descriptor.svg)

Subjects and groups on Windows are named by variable-length immutable Security Identifiers (`SIDs`, formatted `S-R-I-S1-...-RID`), including well-known authorities such as `SYSTEM` (`S-1-5-18`), `LocalService` (`S-1-5-19`), `NetworkService` (`S-1-5-20`), `Everyone` (`S-1-1-0`), deterministic per-service identifiers (`NT SERVICE\<Name>`, derived as the SHA-1 hash of the uppercased service name [371]), and machine or domain accounts such as the `RID 500` built-in Administrator [372, 373]. At logon, `lsass.exe` packages the authenticated user's SIDs, privileges, and integrity label into a kernel access token. Every process holds one primary token (`TOKEN_PRIMARY`), while individual threads serving RPC or named-pipe clients may attach a temporary impersonation token (`TOKEN_IMPERSONATION`) bounded by one of four `SECURITY_IMPERSONATION_LEVEL` ceilings: `SecurityAnonymous`, `SecurityIdentification` (which permits querying ACLs without opening objects), `SecurityImpersonation` (which allows acting locally as the client), or `SecurityDelegation` (which permits authenticating off-box as the client) [369, 374]. Crucially, a Windows access token is a pure bearer credential: `SeAccessCheck` inspects only the SIDs, privileges, and integrity label recorded inside the referenced token structure, never *how* the calling thread acquired the handle.

Inside `SeAccessCheck`, evaluation proceeds through two strict gates. Mandatory Integrity Control executes Gate 1 first; only when the caller satisfies the object's mandatory integrity policy does Gate 2 evaluate direct privilege grants (`SeTakeOwnershipPrivilege` satisfying `WRITE_OWNER` and `SeSecurityPrivilege` satisfying `ACCESS_SYSTEM_SECURITY`, while object-specific open paths separately honor `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege` [375]) and walk the `DACL` sequentially from first ACE to last [368, 376]. Canonical `DACL` ordering places explicit `ACCESS_DENIED_ACE` entries ahead of explicit `ACCESS_ALLOWED_ACE` entries, followed by inherited pairs [376]. Because `SeAccessCheck` stops as soon as all requested access bits are accumulated, appending an explicit deny ACE *after* a broad allow ACE such as `Everyone` leaves the trailing deny entry unreachable once the earlier allow ACE satisfies the mask.

Two edge cases in Gate 2 account for subtle deployment bugs and sandbox policies. First, Windows distinguishes sharply between a missing `DACL` and an empty one: a security descriptor with a `NULL` `DACL` pointer grants unconditional full access to `Everyone`, whereas an initialized empty `DACL` containing zero ACEs grants nothing and denies all requests apart from implicit `READ_CONTROL` and `WRITE_DAC` rights held by the object's Owner SID (unless those implicit owner rights are themselves suppressed by an `OWNER RIGHTS` `S-1-3-4` ACE) [368]. Second, when a caller carries a restricted token created via `CreateRestrictedToken` or `SERVICE_SID_TYPE_RESTRICTED`, `SeAccessCheck` executes the `DACL` walk *twice*, once against enabled regular SIDs and once against the `RestrictingSid` array, granting only the bitwise intersection of both passes [377, 378, 379].

![Figure: The two-gate SeAccessCheck pipeline. Mandatory Integrity Control (Gate 1) compares the subject and object integrity levels before the DACL; a lower-IL write, read, or execute against a NO_WRITE_UP / NO_READ_UP / NO_EXECUTE_UP class short-circuits straight to ACCESS_DENIED, and only an integrity-safe request reaches the deny-then-allow DACL walk (Gate 2).](diagrams/26-integrity-levels-seaccesscheck.svg)

### Mandatory Integrity Control (`MIC`), `UIPI`, and `AppContainer`

To bound untrusted or unelevated processes running under the *same user SID*, Windows Vista introduced an orthogonal integrity axis carried in `TokenIntegrityLevel` (`S-1-16-X`) and stored on objects inside the `SACL` as a `SYSTEM_MANDATORY_LABEL_ACE` [370, 373, 380].

| Integrity Tier | SID | Primary Windows Consumers |
|---|---|---|
| `Untrusted` / `Low` | `S-1-16-0` / `S-1-16-4096` | Browser content renderers, `AppContainer` / `LPAC` sandboxes, Protected View [373, 381, 382] |
| `Medium` | `S-1-16-8192` | Standard users and unelevated split-token administrators (`explorer.exe`) [352, 370] |
| `Medium Plus` (`UIAccess`) | `S-1-16-8448` | Signed assistive/accessibility binaries carrying `uiAccess="true"` (`TokenUIAccess`) [373, 383] |
| `High` | `S-1-16-12288` | Elevated administrative processes launched via `Appinfo` [352, 370] |
| `System` | `S-1-16-16384` | `NT AUTHORITY\SYSTEM`, core services, and kernel-mode objects [370, 373] |

On securable kernel objects, any resource lacking an explicit mandatory label defaults to `Medium` integrity with the `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` policy bit (`0x1`), while `NO_READ_UP` (`0x2`) and `NO_EXECUTE_UP` (`0x4`) remain opt-in flags commonly applied to process objects to prevent cross-integrity memory reads [370, 380]. Because `MIC` runs ahead of the `DACL` walk, a `Low-IL` browser renderer executing under `Alice`'s user SID cannot modify `Alice`'s `Medium-IL` profile files even though `Alice` owns those files and their `DACLs` grant `Alice:(F)` [370].

Securable kernel handles are not the only local IPC channel on a Windows desktop: Win32 window messages (`SendMessage`, `PostMessage`) route through `win32k.sys` without invoking `SeAccessCheck`. To close the shatter-attack surface, User Interface Privilege Isolation (`UIPI`) enforces the same integrity lattice inside `win32k.sys`, blocking lower-IL threads from sending mutating messages (`WM_SETTEXT`, `WM_TIMER` callbacks, `WM_USER+`), installing window hooks (`SetWindowsHookEx`), or injecting synthetic keystrokes (`SendInput`) into higher-IL windows on the same desktop. Cross-integrity delivery fails with `ERROR_ACCESS_DENIED` unless the higher-IL target window explicitly allowlisted the message number via `ChangeWindowMessageFilterEx` or the sender carries `TokenUIAccess`, a privilege reserved for Authenticode-signed accessibility binaries with `uiAccess="true"` residing under `%ProgramFiles%` or `System32` [383, 384, 385].

Vertical integrity levels still cannot isolate two `Medium-IL` or two `Low-IL` processes owned by the same user on the same desktop. Windows 8 therefore introduced horizontal capability sandboxing through `AppContainer` (`LowBox` tokens), assigning each sandboxed application a unique Package SID (`S-1-15-2-*`), explicit Capability SIDs (`S-1-15-3-*`), and a private `\Sessions\<N>\AppContainerNamedObjects\` namespace. Windows 10 tightened that model further with Less-Privileged AppContainer (`LPAC`), stripping the broad `ALL APPLICATION PACKAGES` group (`S-1-15-2-1`) so world-readable operating-system files and registry keys become deny-by-default unless explicitly tagged for `LPAC` access [381, 382].

### Split-Token `UAC` vs. Windows 11 `Administrator Protection`

Under Vista's Admin Approval Mode (`UAC`), logging on as an administrator causes `lsass.exe` to mint two tokens joined by `TokenLinkedToken` [352, 355]: a filtered `Medium-IL` token (where `BUILTIN\Administrators` is marked `SE_GROUP_USE_FOR_DENY_ONLY` [386] and `SeDebugPrivilege`/`SeLoadDriverPrivilege`/`SeImpersonatePrivilege` are stripped) used to start `explorer.exe`, and a dormant full `High-IL` token.

![Figure: The split-token elevation flow. At logon LSASS mints the High-IL full token (held dormant) and the Medium-IL filtered token, joined by TokenLinkedToken; at elevation explorer.exe's runas RPC reaches Appinfo, consent.exe confirms on the Winlogon Secure Desktop, and Appinfo's RAiLaunchAdminProcess path spawns a new High-IL process under the same dormant full token. No new token is minted at prompt time.](diagrams/26-integrity-levels-elevation.svg)

When elevation is requested, either whole-process via `ShellExecuteEx` (`"runas"`) [387] or per-COM-object via the COM Elevation Moniker (`Elevation:Administrator!new:{CLSID}` spawning an elevated `dllhost.exe`) [388], the `LocalSystem` Application Information (`Appinfo`, `appinfo.dll`) broker (`RAiLaunchAdminProcess`) switches the display to the isolated Secure Desktop (`\Sessions\<n>\Windows\WindowStations\WinSta0\Winlogon`, protected by desktop `DACL` within the user's session and distinct from Session 0 Isolation, which segregates background services [352]), displays `consent.exe`, and spawns the new process with the linked `High-IL` token. To reduce prompt fatigue since Windows 7, `Appinfo` silently auto-elevates binaries without prompting if they carry `<autoElevate>true</autoElevate>`, a Microsoft Authenticode signature, a trusted `System32`/`SysWOW64` path, and membership on `appinfo.dll`'s internal allowlist [389, 390].

Because both split tokens shared the exact same User SID, `%USERPROFILE%`, `HKCU` registry hive, and logon-session LUID, Microsoft explicitly disclaimed `UAC` as a security boundary in February 2007 [173, 365, 391]. In 2024-2026, Microsoft introduced Administrator Protection (`Adminless`) as a true MSRC-serviced security boundary [364, 392, 393]: the interactive user holds *no* dormant linked admin token; upon Windows Hello authentication, Windows provisions a separate, hidden System Managed Administrator Account (`SMAA`) with its own distinct User SID, `C:\Users\ADMIN_*` profile, isolated `HKCU` hive, and fresh logon session to issue a just-in-time admin token destroyed on process exit [364, 392].

### Service Impersonation (`SeImpersonatePrivilege`) and the Substitution Ladder

When `LOCAL SERVICE`, `NETWORK SERVICE`, or SCM-managed virtual service accounts (`NT SERVICE\*` carrying the `S-1-5-6` `SERVICE` SID) start, Windows grants `SeImpersonatePrivilege` (`SE_IMPERSONATE_NAME`) in the `Enabled` state by default [360, 361, 362]. While legitimate RPC and named-pipe servers call `ImpersonateNamedPipeClient` or `RpcImpersonateClient` to check client access rights, the Win32 token API converts any `SecurityImpersonation`- or `SecurityDelegation`-level client handle into full process execution across a five-step chain [374, 394, 395, 396, 397]. First, the service process creates an authenticated endpoint such as a named pipe, local RPC interface, or loopback NTLM listener, and coerces or waits for a `NT AUTHORITY\SYSTEM` service to connect without restricting Security Quality of Service (`SQOS`) down to `SecurityIdentification`. Once connected, calling `ImpersonateNamedPipeClient` (or `AcceptSecurityContext` followed by `QuerySecurityContextToken`) yields a live `SYSTEM` impersonation handle at `SecurityImpersonation` or higher, which `DuplicateTokenEx` converts into a `TOKEN_PRIMARY` handle without requiring any special privilege. Finally, `CreateProcessWithTokenW` verifies that the caller holds enabled `SeImpersonatePrivilege` (or `CreateProcessAsUser` checks `SeAssignPrimaryTokenPrivilege`) and spawns an unrestricted `SYSTEM` process [395, 397].

## Attack Catalog & Gap Analysis

Twenty-five years of Windows local privilege escalation (`LPE`) map directly onto `SeAccessCheck` and its surrounding brokers: attackers either corrupt the *lookup path* before `SeAccessCheck`, exploit a misconfigured *descriptor*, redirect `UAC`'s *shared-identity elevation flow*, or feed a coerced `SYSTEM` *token* into `SeImpersonatePrivilege`.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `UAC` AutoElevate & COM Redirects (`UACMe`: `sysprep`, `eventvwr`, `fodhelper`, `ICMLuaUtil`) | 2009-present | `Medium-IL` → `High-IL` split-token `UAC` gate | Unelevated user in local `Administrators` group | Writes payload command to shared `HKCU\Software\Classes` (`ms-settings`, `mscfile`) or invokes auto-approved COM monikers (`IFileOperation`, `CMSTPLUA`) consumed by `autoElevate` binaries | Enable Windows 11 Administrator Protection (`SMAA`) separating `HKCU`/SID, or enforce standard-user accounts (`Always Notify` UAC) [364, 389, 398, 399, 400] |
| NTFS Hard-Link & Object-Manager Symlink Redirects (`CVE-2015-4481`, `CVE-2020-0668`) | 2015-2025 | Pre-`SeAccessCheck` path resolution by `SYSTEM` services | Standard user writing to shared log/temp folders | Redirects `SYSTEM` file operations via NTFS junctions into `\RPC Control` object symlinks (`CreateMountPoint` + `CreateSymlink`) or hard links to overwrite system DLLs | Patch per-service writable log paths; enforce `MS15-115` hard-link rules and `ProcessRedirectionTrustPolicy` (`RedirectionGuard`, [Chapter 9](19-mitigations.md)) [339, 401, 402, 403] |
| `Potato` Lineage (`Hot`, `Rotten`, `JuicyPotato`, `PrintSpoofer`, `GodPotato`) | 2008-2026 | Windows Service Hardening (`LOCAL/NETWORK SERVICE` → `SYSTEM`) | Compromised service holding `SeImpersonatePrivilege` (`IIS`, `MSSQL`) | Coerces `SYSTEM` authentication via WPAD/SMB (`MS16-075`), DCOM `OXID` (`Juicy`), `MS-RPRN`/`MS-EFSR` pipes (`PrintSpoofer`), or `RPCSS` cached session tokens (`GodPotato`) → `CreateProcessWithTokenW` | Strip unneeded privileges via SCM `RequiredPrivileges`; apply `CVE-2021-26414` DCOM integrity, `LPAC`, and disable unneeded `Spooler`/NTLM ([Chapter 13](09-ntlm.md)) [404, 405, 406, 407, 408, 409] |
| `HiveNightmare` / `SeriousSAM` (`CVE-2021-36934`) | 2021 | Confidentiality of `SAM`, `SYSTEM`, and `SECURITY` registry hives | Standard local user + existing Volume Shadow Copy | Reads `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*\Windows\System32\config\SAM`, which inherited a buggy `BUILTIN\Users:(R)` `DACL` without live file locks | Apply Aug 2021 patch tightening `config\` `DACLs` and delete historical shadow copies [410] |
| `LocalPotato` (`CVE-2023-21746`) & `SilverPotato` (`CVE-2024-38061`) | 2023-2024 | Standard-user → `SYSTEM` NTLM loopback & cross-host DCOM relay | Standard user (`LocalPotato`) or `DCOM Users` (`SilverPotato`) | Swaps NTLM Type-2 `Reserved` context handles during local SMB/HTTP auth (`21746`) or relays cross-session `sppui` DCOM auth to ADCS (`38061`) | Apply `CVE-2023-21746` and July 2024 `CVE-2024-38061` patches; enforce SMB/LDAP/EPA signing ([Chapter 13](09-ntlm.md)) [411, 412, 413, 414] |
| `Administrator Protection` `UIAccess` Bypasses (Project Zero) | 2026 | `Medium-IL` → `SMAA` `High-IL` boundary via `UIPI` carve-out | Local user abusing signed `uiAccess="true"` executables | Coerces signed accessibility/system binaries holding `TokenUIAccess` to inject input or abuse `RAiLaunchAdminProcess` channels (5 of 9 pre-GA bugs) | Apply 2026 pre-GA `Appinfo` / `UIAccess` fixes; audit installed `uiAccess=true` binaries [383, 392] |

### Pre-Check Name Redirects and Descriptor Bugs (`CVE-2020-0668` and `HiveNightmare`)

`SeAccessCheck` is mathematically deterministic, yet completely blind to *how* the Object Manager arrived at an object pointer. Because Windows resolves path strings before checking the destination `DACL`, planting an NTFS junction redirecting a `SYSTEM`-writable directory (such as `HKLM\SOFTWARE\Microsoft\Tracing` in Clément Labro's `CVE-2020-0668` [401]) to the user-writable `\RPC Control` Object Manager namespace lets a standard user place twin object symlinks (`MODULE.LOG` and `MODULE.OLD`) that trick a `SYSTEM` service into overwriting arbitrary `System32` DLLs under `SYSTEM`'s own token [401, 402]. Conversely, `HiveNightmare` (`CVE-2021-36934`) demonstrated pure descriptor misconfiguration: Windows 10 1809+ inadvertently granted `BUILTIN\Users` read rights on `System32\config\SAM`, turning unlocked Volume Shadow Copies (`HarddiskVolumeShadowCopy*`) into instant local hash dumps for any standard user [410].

### Shared-Identity `UAC` Hijacks and the `UIAccess` Residual

Over seventy public `UAC` bypasses cataloged in `UACMe` [398] prove why `MIC` (`NO_WRITE_UP`) cannot isolate two tokens sharing one User SID. Because Windows merges per-user `HKCU\Software\Classes` *ahead* of machine-wide `HKLM\Software\Classes` inside `HKCR`, an unelevated `Medium-IL` process legitimately writes to its own `HKCU\Software\Classes\ms-settings\shell\open\command` (or `mscfile`) and launches `fodhelper.exe` or `eventvwr.exe` [398, 400, 415]. `Appinfo` auto-elevates the Microsoft-signed binary to `High-IL`, which then reads the *same user's* poisoned `HKCU` hive and executes the payload as Administrator. While Windows 11 Administrator Protection (`SMAA`) structurally kills the entire `HKCU`/profile hijack class by running elevated processes under a separate `ADMIN_*` account, James Forshaw's 2026 Project Zero audit showed that five of nine pre-GA `Administrator Protection` bypasses pivoted instead onto Vista's `uiAccess="true"` `UIPI` accessibility exemption, highlighting the permanent tension between strict cross-IL isolation and assistive-technology access [364, 383, 392].

### The Three-Piece `SeImpersonate` System (The `Potato` Lineage)

Across five offensive generations from Cesar Cerrudo's *Token Kidnapping* (`MS09-012` [416, 417]) and *HotPotato* (`2016` [404]) through *Rotten/JuicyPotato* (`DCOM OXID` [405, 418, 419]), *PrintSpoofer* (`MS-RPRN` [406]), and *GodPotato* (`RPCSS` `OXID` + LSASS cached session tokens [407, 408]), service-to-`SYSTEM` escalation persists as a closed three-piece architectural system:

![Figure: The three-piece theorem is an AND composition, not a menu: default service-account impersonation privilege, a coercion path that makes SYSTEM authenticate to the attacker-controlled endpoint, and the MSRC servicing carve-out must all remain in place before the chain becomes service account to SYSTEM. Removing any one piece breaks the chain, but Microsoft has not serviced the class by removing any of them.](diagrams/27-seimpersonate-three-piece.svg)

Even when Windows Service Hardening adds `NT SERVICE\*` SIDs, write-restricted tokens (`S-1-5-33`), `gMSAs` [420], and `CVE-2021-26414` DCOM packet-integrity enforcement [379, 409], Microsoft preserves enabled `SeImpersonatePrivilege` and `ImpersonateNamedPipeClient` so IIS, SQL Server, and RPC workloads do not break, and treats `WSH` service-to-`SYSTEM` escalation as a *safety boundary* rather than an MSRC-serviced security boundary unless standard users or network boundaries are crossed (as in `LocalPotato` `CVE-2023-21746` and `SilverPotato` `CVE-2024-38061`) [173, 366, 412, 414].

## Theoretical Limits & Structural Invariants

### Ambient Authority, Hardy's Confused Deputy, and `HRU` Undecidability

Because Windows is an identity-and-ACL operating system rather than a pure object-capability system (such as `KeyKOS` or `seL4` [164, 359, 363]), processes exercise *ambient authority* attached to their token across forgeable path strings, and privileged servers hold two authorities simultaneously (their own and their impersonated callers'). Furthermore, by the Harrison-Ruzzo-Ullman (`HRU`, 1976) theorem [421], determining whether an arbitrary initial discretionary access-matrix configuration can eventually leak a right to an unauthorized subject is undecidable, explaining why Windows had to bolt a non-discretionary, fixed-lattice `MIC` gate *ahead* of owner-mutable `DACLs` [370].

### Access Control (`NO_WRITE_UP`) Is Not Information-Flow Control (Biba's Invocation Gap)

Kenneth Biba's 1977 formal integrity model requires *both* `No Write Up` (a low-integrity subject cannot modify a high-integrity object) and `No Read Down` (a high-integrity subject must not consume untrusted low-integrity data or code) [422]. For usability, Windows `MIC` enforces `NO_WRITE_UP` by default while omitting `No Read Down`: a `High-IL` administrator binary freely reads `Medium-IL` files, environment blocks, and `HKCU` registry keys. Every `fodhelper`-style `UAC` hijack operates squarely inside that deliberate gap between object write protection and downward information flow [391].

### Decoupling Account Identity from Privilege Equivalence

Auditing a subject's User or Group SID (`NETWORK SERVICE`, `Backup Operators`, or non-admin service account) without auditing its token privilege array misstates its true authority.

> **Key idea.**
> Five token privileges (`SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, `SeBackupPrivilege` / `SeRestorePrivilege`, and `SeLoadDriverPrivilege` / `SeTcbPrivilege`) are architecturally equivalent to `NT AUTHORITY\SYSTEM` on `VTL0` (`"if you have SeAssignPrimaryToken or SeImpersonate privilege, you are SYSTEM"` [406]). True least privilege requires stripping dangerous privileges from custom service manifests (`RequiredPrivileges`) rather than merely moving a service off the `SYSTEM` SID [379, 423].

## Inspecting and Verifying on a Running System

Operational diagnostics inspect four live surfaces: token integrity labels and `Deny-Only` vs. enabled privileges, object `DACLs` and mandatory `SACL` labels, `UAC` / `Administrator Protection` registry policies, and host-wide `SeImpersonatePrivilege` assignments.

### Inspecting Current Token Integrity, Groups, and Dangerous Privileges

Examine the active process token's integrity SID (`S-1-16-*`), `BUILTIN\Administrators` state (`Use for deny only` vs. `Enabled`), and enabled `SYSTEM`-equivalent privileges [360, 369, 386]:

```powershell
whoami /groups | Select-String 'Administrators|Mandatory Label'
whoami /priv | Select-String 'SeImpersonate|SeAssignPrimary|SeDebug|SeBackup|SeRestore|SeLoadDriver'
```

Expected output in an unelevated vs. elevated split-token administrator shell:

```text
# Unelevated (Medium IL filtered token):
BUILTIN\Administrators  Alias  S-1-5-32-544  Group used for deny only
Mandatory Label\Medium Mandatory Level  Label  S-1-16-8192

# Elevated (High IL linked token):
BUILTIN\Administrators  Alias  S-1-5-32-544  Enabled by default, Enabled group, Group owner
Mandatory Label\High Mandatory Level    Label  S-1-16-12288
SeDebugPrivilege          Debug programs                        Disabled
SeImpersonatePrivilege    Impersonate a client after auth...    Enabled
```

Comparing both outputs confirms whether a shell holds the filtered `Medium-IL` token (`S-1-16-8192`) or an elevated/service token carrying `SeImpersonatePrivilege` in the immediately actionable `Enabled` state [352, 360].

### Auditing Object `DACLs` (`NULL` vs. Canonical) and Mandatory Labels

Verify file or directory `DACLs` and mandatory integrity labels (checking for overly broad `BUILTIN\Users` access as seen in `HiveNightmare` or accidental `Everyone:(F)` `NULL` `DACLs`) using inbox `icacls` [367, 368, 410]:

```powershell
icacls 'C:\Windows\System32\config\SAM'
```

Expected output on a patched Windows 11 host:

```text
C:\Windows\System32\config\SAM BUILTIN\Administrators:(I)(F)
                               NT AUTHORITY\SYSTEM:(I)(F)
```

Absence of `BUILTIN\Users:(I)(R)` confirms `CVE-2021-36934` (`HiveNightmare`) remediation [410]. For registry keys, named pipes (`\\.\pipe\*`), and kernel objects, `(Get-Acl -Path <path>).Access` enumerates ordered `IdentityReference`, `AccessControlType` (`Deny` before `Allow`), and `FileSystemRights` / `RegistryRights`.

### Auditing `SeImpersonatePrivilege` Holders and Service Privilege Narrowing

Export local User Rights Assignment policy to verify which SIDs receive `SeImpersonatePrivilege` (`*S-1-5-32-544` Administrators, `*S-1-5-19` LocalService, `*S-1-5-20` NetworkService, `*S-1-5-6` Service) and inspect per-service `RequiredPrivileges` narrowing [360, 423]:

```powershell
secedit /export /areas USER_RIGHTS /cfg "$env:TEMP\ur.inf" /quiet
Select-String -Path "$env:TEMP\ur.inf" -Pattern 'SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege|SeDebugPrivilege'
Remove-Item "$env:TEMP\ur.inf" -Force
```

Expected default policy output:

```text
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeDebugPrivilege = *S-1-5-32-544
SeImpersonatePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20,*S-1-5-6
```

Any unexpected domain user or broad workstation group SID appearing on these three lines grants immediate local `SYSTEM` escalation paths (`Potato` or `LSASS` debugging) and should be removed via Group Policy or MDM `UserRights` CSP [360].

## Summary & Handoff

Windows local authorization funnels every securable operation through `SeAccessCheck`, pairing 1993 discretionary `DACLs` and bearer tokens with 2006 Mandatory Integrity Control (`MIC`) and `UIPI`, `AppContainer` capability sandboxes, and 2024+ `Administrator Protection` (`SMAA`) identity separation. Yet because Windows tokens are ambient bearer credentials and legacy RPC compatibility preserves enabled `SeImpersonatePrivilege` on service accounts, attackers systematically bypass `SeAccessCheck` at its boundaries: redirecting Object Manager paths before the check, poisoning shared `HKCU` hives across `UAC`, or coercing `SYSTEM` pipes through the `Potato` lineage.

Once an attacker escalates to `High-IL` Administrator or `NT AUTHORITY\SYSTEM` inside `VTL0` (or executes inside an interactive user session), the operational objective shifts immediately from *local authorization* to *decrypting persistent data stores and replaying network credentials*. [Data Protection and Local Secret Custody (Chapter 11)](30-data-protection.md) examines how `BitLocker` (`fvevol.sys`), `DPAPI` and `DPAPI-NG`, `VTL1` `CNG KeyIso`, browser `App-Bound Encryption`, and `Recall` `VBS Enclaves` protect persistent local secrets, and where same-user malware or Active Directory domain backup keys break through. [Credential Guard and LSASS Isolation (Chapter 12)](08-credential-guard.md) then traces how `Mimikatz` harvested `LSASS` memory for a decade and how `LsaIso.exe` severs `VTL0` secret extraction while leaving `Pass-the-Challenge` open. Closing the local and network challenge-response coercion surfaces exploited by `HotPotato`, `LocalPotato`, `SilverPotato`, and `PetitPotam` belongs to [The Death of NTLM (Chapter 13)](09-ntlm.md), after which securing `Kerberos` ([Chapter 14](10-kerberos.md)), `AD CS` and `dMSA` ([Chapter 15](31-enterprise-pki.md)), `Primary Refresh Tokens` ([Chapter 16](11-pth-prt.md)), and `Windows Hello` / `Passkeys` ([Chapter 17](12-hello.md)) completes Part III.
