# Protected Process Light

## Overview

* **Role in the Chain:** Kernel-enforced process-isolation lattice operating inside `VTL0` (`ntoskrnl.exe`); restricts cross-process handle permissions based on cryptographic code-signing provenance rather than caller token privileges, shielding critical user-mode daemons (`csrss.exe`, `lsass.exe`, and anti-malware services) from `Administrator` and `SYSTEM` tampering.
* **Core Security Invariant:** During `NtOpenProcess` and `NtOpenThread`, `PspCheckForInvalidAccessByProtection` evaluates the caller and target 1-byte `EPROCESS.Protection` structures against `RtlProtectedAccess[]` *before* `SeAccessCheck` inspects tokens or `SeDebugPrivilege`, stripping memory-read, memory-write, thread-injection, and (for protected tiers) termination rights whenever the caller's signer rung falls below the target's.
* **Trusted Computing Base (TCB):** The `VTL0` NT kernel (`ntoskrnl.exe`), `ci.dll` image and DLL signing-level checks (`SignatureLevel` / `SectionSignatureLevel`), Microsoft's protected-process EKU certificate authorities (`1.3.6.1.4.1.311.10.3.*`), and Early Launch Anti-Malware (`ELAM`) resource-section certificate registries.
* **Primary Failure Modes:** Arbitrary `VTL0` Ring 0 write primitives zeroing `EPROCESS.Protection` via vulnerable signed drivers (`BYOVD`), and user-mode channel-versus-behavior bypasses loading attacker-controlled logic through trusted conduits: COM scriptlets (`scrobj.dll`), `\KnownDlls\` CSRSS confused-deputy symlinks (`PPLdump`), section-creation `CloudFilter` `TOCTOU` races (`PPLFault`), and vulnerable historical Microsoft DLLs (`BYOVDLL` / `KeyIso`).
* **Handoff:** Raises a mandatory `VTL0` handle barrier in front of `lsass.exe` and endpoint detection sensors; relies on Process Mitigation Policies ([Chapter 9](19-mitigations.md)) for intra-process memory-corruption hardening and on Credential Guard ([Chapter 11](08-credential-guard.md)) in `VTL1` to protect secrets when `VTL0` Ring 0 or `PPL` user space is breached.

## Core Engineering Problem & Threat Model

Under the classic Windows NT discretionary access-control model ([Chapter 10](25-access-control.md)), any caller running as `NT AUTHORITY\SYSTEM` or holding `SeDebugPrivilege` in an elevated `Administrator` token bypasses per-object Discretionary Access Control Lists (`DACLs`) and opens `PROCESS_ALL_ACCESS` handles to arbitrary user-mode processes. Once adversaries routinely achieved local administrative execution, two user-mode targets collapsed immediately: `lsass.exe` (yielding NTLM hashes and Kerberos tickets to tools like `Mimikatz` [283]) and `csrss.exe` (where Mateusz Jurczyk documented over seventy Win32k syscalls gated solely by `PsGetCurrentProcess() == gpepCsrss` [284]), alongside user-mode anti-malware daemons that attackers simply terminated or hollowed before deploying ransomware.

Microsoft originally introduced a binary Protected Process (`PP`) bit in Windows Vista (2006) strictly for Digital Rights Management (`Protected Media Path`, isolating Blu-ray/HD-DVD audio-video pipelines in `audiodg.exe` against local administrators) [285, 286]. Because a single boolean bit rooted in one DRM certificate could neither rank `csrss.exe` above `lsass.exe` nor admit third-party Endpoint Detection and Response (`EDR`) agents safely, Windows 8.1 (October 2013) generalized the mechanism into a graduated, multi-tier Protected Process Light (`PPL`) signer lattice [287, 288].

The `PPL` threat model targets an elevated user-mode adversary holding full `Administrator` and `SYSTEM` tokens (including `SeDebugPrivilege`) inside `VTL0` who attempts to read `lsass.exe` memory (`PROCESS_VM_READ`), inject threads into `csrss.exe`, or terminate `MsMpEng.exe` and third-party `EDR` services. Conversely, because `EPROCESS.Protection` resides in ordinary `VTL0` kernel pool memory and because Microsoft classifies `PPL` under its Security Servicing Criteria as defense in depth rather than a formal security boundary [173, 289], `PPL` is never designed to withstand an attacker with `VTL0` Ring 0 read/write access (`BYOVD`, [Chapter 7](06-code-integrity.md)).

## Architectural Deep Dive

### The `_PS_PROTECTION` Byte and Signer Rungs

To evaluate process dominance on every `NtOpenProcess` syscall without expensive X.509 parsing on the hot path, `ci.dll` validates a binary's Authenticode certificate chain and Microsoft Enhanced Key Usage (`EKU`, `1.3.6.1.4.1.311.10.3.*`) *once* at `NtCreateUserProcess` and packs the resulting trust state into a single `UCHAR` inside `EPROCESS` (`_PS_PROTECTION`) [287, 290, 291]:

| Bit Range | Field | Width | Defined Values & Runtime Semantics |
|---|---|---|---|
| `Bits 0..2` | `Type` | 3 bits | `0` = `PsProtectedTypeNone` (unprotected); `1` = `PsProtectedTypeProtectedLight` (`PPL`); `2` = `PsProtectedTypeProtected` (Vista-style full `PP`) [287] |
| `Bit 3` | `Audit` | 1 bit | Reserved / audit flag (`0` in standard enforcement) [287, 292] |
| `Bits 4..7` | `Signer` | 4 bits | `0` = `None`, `1` = `Authenticode`, `2` = `CodeGen`, `3` = `Antimalware`, `4` = `Lsa`, `5` = `Windows`, `6` = `WinTcb`, `7` = `WinSystem`, `8` = `App` [287, 293] |

Decoding the raw hexadecimal byte (`Level = (Signer << 4) | (Audit << 3) | Type`) immediately identifies the runtime tier of core Windows processes [287]:
* **`0x31` (`Signer = 3`, `Type = 1`):** `PPL/Antimalware` (`MsMpEng.exe` and MVI-certified third-party `EDR` agents).
* **`0x41` (`Signer = 4`, `Type = 1`):** `PPL/Lsa` (`lsass.exe` when `RunAsPPL` is active).
* **`0x61` (`Signer = 6`, `Type = 1`):** `PPL/WinTcb` (`csrss.exe`, `services.exe`, `smss.exe`, `WerFaultSecure.exe`).

Alongside `EPROCESS.Protection`, the kernel populates `EPROCESS.SignatureLevel` and `EPROCESS.SectionSignatureLevel` [294]. While `Protection` governs *which external processes may open handles to this process*, `SectionSignatureLevel` governs *which DLLs this process is permitted to map into its own address space* after startup, preventing a protected process from loading unsigned user-supplied DLLs.

### The Dominance Lattice and `NtOpenProcess` Ordering

Cross-process handle mediation follows three dominance rules over caller signer $S_c$ and target signer $S_t$ (`diagrams/18-ppl-signer-lattice.svg`) [288, 295]:

1. **Full `PP` Caller:** A `PP` (`Type = 2`) may open a `PP` or `PPL` with full access if and only if $S_c \ge S_t$.
2. **`PPL` Caller:** A `PPL` (`Type = 1`) may open another `PPL` with full access if and only if $S_c \ge S_t$, and can *never* open a full `PP` (`Type = 2`) with full access regardless of signer rung.
3. **Unprotected Caller (`None`, `0x00`):** An unprotected process, including an elevated `SYSTEM` command prompt holding `SeDebugPrivilege`, is denied full access to *every* `PP` and `PPL` target.

![Figure: The signer lattice as a 6x6 dominance grid: caller signer rung (rows) against target signer rung (columns). A caller opens a target with full access if and only if its rung is greater-or-equal to the target's, so the grant region is the lower-left triangle and the denied region is the upper-right (where only the limited mask still applies per the target's DACL). The gold-outlined diagonal marks equal-rung peers where every PPL can open another at its own rung.](diagrams/18-ppl-signer-lattice.svg)

Why does `SeDebugPrivilege` fail to rescue `Mimikatz`? Because of strict execution ordering inside `ntoskrnl.exe` (`diagrams/18-ppl-access-check.svg`) [288]:

![Figure: The ordering inside NtOpenProcess that makes PPL work. OpenProcess → NtOpenProcess → PspProcessOpen → PspCheckForInvalidAccessByProtection, which splits the requested mask: the full mask (PROCESS_VM_READ / WRITE / CREATE_THREAD) is run through RtlTestProtectedAccess (indexing RtlProtectedAccess[] by the caller's signer rung and the target's type) and is stripped when the caller's rung is below the target's, so it never reaches SeAccessCheck; only the limited mask survives. SeDebugPrivilege is weighed only at the SeAccessCheck box, after the lattice has already pruned the dangerous bits. Which is why a SYSTEM administrator still receives STATUS_ACCESS_DENIED on the read.](diagrams/18-ppl-access-check.svg)

When a caller invokes `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsass_pid)`, `NtOpenProcess` invokes the process object-type callback `PspProcessOpen`, which executes `PspCheckForInvalidAccessByProtection` prior to calling `SeAccessCheck` [288]. Looking up the `(Caller Signer, Target Type/Signer)` entry in the static kernel table `RtlProtectedAccess[]`, the routine partitions access bits into two masks [288]:

* **Denied Full-Access Mask (`0xFC7FE` or `0xFC7FF`):** Covers `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`, `PROCESS_SET_INFORMATION`, and `PROCESS_QUERY_INFORMATION`. Crucially, for `Antimalware` (`3`), `Lsa` (`4`), and `WinTcb` (`6`) targets, `RtlProtectedAccess[]` sets bit `0` (`0xFC7FF`), denying `PROCESS_TERMINATE` as well so an administrator cannot kill `lsass.exe` or an `EDR` daemon with `taskkill /F` [288].
* **Permitted Limited Mask:** Leaves `SYNCHRONIZE` and `PROCESS_QUERY_LIMITED_INFORMATION` intact so diagnostic tools can still inspect basic process metadata if allowed by the target's `DACL`.

When `Mimikatz` requests only full-mask bits (`PROCESS_VM_READ`) from an unprotected process (`0x00`) against `PPL/Lsa` (`0x41`), `PspCheckForInvalidAccessByProtection` strips all requested bits and aborts with `STATUS_ACCESS_DENIED` (`0xC0000022`, mapped to Win32 `0x00000005`) before `SeAccessCheck` ever evaluates `SeDebugPrivilege` [288, 292, 296]. Conversely, notice two intentional consequences of the $\ge$ relation: `MsMpEng.exe` (`PPL/Antimalware`, `3`) cannot read `lsass.exe` (`PPL/Lsa`, `4`), whereas `WerFaultSecure.exe` (`PPL/WinTcb`, `6`) *can* read `lsass.exe` (`6 \ge 4`) during crash reporting, and two co-resident `PPL/Antimalware` agents (`3 \ge 3`) can open one another as equal-rung peers.

### Third-Party Admission via ELAM and MVI (`PPL/Antimalware`)

Microsoft reserves rungs `4` (`Lsa`), `5` (`Windows`), and `6` (`WinTcb`) exclusively for first-party Microsoft-signed binaries. Third-party security vendors enter `PPL/Antimalware` (`0x31`) through a hardware- and boot-anchored chain coupling Early Launch Anti-Malware (`ELAM`, [Chapter 1](16-secure-boot.md)) with the Microsoft Virus Initiative (`MVI`) [26, 297, 298]:

1. **Vendor Qualification and Signing:** The vendor maintains active `MVI` membership (requiring annual independent anti-malware lab certification and Azure Trusted Signing custody) and submits its boot-start `ELAM` kernel driver (carrying the Early Launch EKU `1.3.6.1.4.1.311.61.4.1`, modeled after inbox `WdBoot.sys`) for Microsoft WHQL co-signing [298, 299].
2. **Embedded Certificate Registry (`MicrosoftElamCertificateInfo`):** Inside the signed `ELAM` `.sys` binary, the vendor embeds a read-only resource section enumerating the SHA-256 thumbprints and EKUs of the X.509 certificates used to sign its user-mode anti-malware service executables and DLLs [297, 299].
3. **Service Launch Validation:** During early boot, `ntoskrnl.exe` parses the `ELAM` resource section and caches the vendor's allowed certificate hashes. When the Service Control Manager subsequently starts the service configured with `LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`, `ci.dll` verifies that the service binary and every DLL it maps chain to those cached `ELAM` certificates before granting `Protection = 0x31` [297].

### Hardening LSASS (`RunAsPPL`) and `PPL` vs. Credential Guard

Enabling LSA Protection launches `lsass.exe` at `PPL/Lsa` (`0x41`), controlled via `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` [292, 300]:

* **`RunAsPPL = 1` (UEFI-Locked Enforcement):** On UEFI Secure Boot hosts, Windows mirrors the policy into a firmware-protected UEFI NVRAM variable (`LsaPplConfig`). Deleting or zeroing the `RunAsPPL` registry value from a `SYSTEM` shell has no effect on subsequent boots; clearing the UEFI lock requires physical firmware presence or Microsoft's signed EFI opt-out tool [300].
* **`RunAsPPL = 2` (Registry-Only Enforcement, Windows 11 22H2+):** Launches `lsass.exe` at `0x41` without writing the UEFI variable (also used by automatic enablement on clean enterprise-joined, HVCI-capable Windows 11 22H2+ installations), allowing administrative rollback via registry edit and reboot [300].
* **Plugin Audit Mode (`IFEO\LSASS.exe\AuditLevel = 8`):** Because `PPL/Lsa` enforces strict Microsoft code-signing requirements on every authentication package, password filter, and smart-card `CSP` loaded into `lsass.exe`, non-compliant third-party DLLs fail to load under enforcement. Setting `AuditLevel = 0x8` under a *separate* hive (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe`, enabled by default since Windows 11 22H2) logs would-be DLL rejections as Event IDs `3065` and `3066` in `Microsoft-Windows-CodeIntegrity/Operational` prior to flipping enforcement on [300].

Practitioners must treat `RunAsPPL` and Credential Guard ([Chapter 11](08-credential-guard.md)) as complementary layers rather than substitutes [69, 292]: `RunAsPPL` shields the entire `VTL0` `lsass.exe` address space (including live Kerberos ticket caches, `DPAPI` master keys in flight, and authentication broker logic) from user-mode `Administrator`/`SYSTEM` handle opens, whereas Credential Guard relocates long-term NTLM hashes and Kerberos TGT keys into `VTL1` `LsaIso.exe` so they survive even a `VTL0` Ring 0 kernel compromise or a user-mode `PPL` bypass.

## Attack Catalog & Gap Analysis

Because `RtlTestProtectedAccess` is a tiny, deterministic table lookup inside `ntoskrnl.exe`, public attacks never break the lattice comparison itself. Instead, adversaries either drop to Ring 0 (`BYOVD`) to overwrite `EPROCESS.Protection` directly, or exploit the channel-versus-behavior seam: coercing a `PPL` process to map code through a trusted admission channel (`COM`, `\KnownDlls\`, `CloudFilter` section caching, or older signed Microsoft DLLs) that subsequently executes attacker-controlled instructions.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| COM Scriptlet Injection (Forshaw) | 2018 | `PPL` code-integrity restriction via signed script engines | Local `Administrator` instantiating COM inside `PPL` target | Forces `PPL` process to load Microsoft-signed `scrobj.dll` / `jscript.dll` via COM and execute arbitrary attacker JScript in-process | Patched in Win10 1803: `ci.dll!g_BlockedDllsForPPL` blocks 5 scripting DLLs inside `PPL` [293, 297] |
| `BYOVD` Kernel Tampering (`KProcessHacker`, `RTCore64.sys`) | 2018-present | `VTL0` `EPROCESS.Protection` integrity & `0xFC7FF` kill block | Local `Administrator` loading unblocked vulnerable signed `.sys` | Uses driver `ZwTerminateProcess` (`KProcessHacker`) or Ring 0 memory write (`RTCore64`/`gdrv`) to zero `EPROCESS.Protection` byte in RAM | Enforce `HVCI` + updated `DriverSiPolicy.p7b` ([Chapter 7](06-code-integrity.md)) and Credential Guard ([Chapter 11](08-credential-guard.md)) [159, 215, 262] |
| `PPLdump` (`DefineDosDevice` + `\KnownDlls\`) | 2018-2022 | `PPL` section-load signature verification (`PPL/Lsa` & `WinTcb`) | Local `Administrator` abusing `CSRSS` symlink creation | Tricks `PPL/WinTcb` `csrss.exe` via `DefineDosDevice` into linking an unverified section into `\KnownDlls\`, mapped without re-checking by `PPL` | Patched July 2022 (`19044.1826`): `ntdll!LdrpInitializeProcess` skips `\KnownDlls\` for all `PPL`s [295, 301, 302, 303] |
| `PPLFault` (`MiValidateSectionCreate` `TOCTOU`) | 2023-2024 | Page-in integrity after `NtCreateSection` `ci.dll` check | Local `Administrator` registering `CloudFilter` `FetchDataCallback` | Passes `ci.dll` signature validation at section creation using genuine Microsoft DLL, then swaps in unsigned payload bytes during lazy demand paging | Patched Feb 2024: extended per-page hash enforcement on remote/redirector-backed `PPL` loads [289, 304, 305] |
| `BYOVDLL` (`Ghost in the PPL` / `KeyIso` Chain) | 2024 | Memory safety inside `PPL/Lsa` (`lsass.exe`) via historical Microsoft DLLs | Local `Administrator` editing `Services\KeyIso\Parameters\ServiceDll` | Loads older, genuinely Microsoft-signed `keyiso.dll` into `lsass.exe` and chains `CVE-2023-36906` (OOB read) + `CVE-2023-28229` (UAF) for `PPL/Lsa` RCE | Apply cumulative OS updates; block legacy vulnerable DLL hashes via signed `App Control` (`WDAC`) policies [306, 307, 308, 309] |
| `WerFaultSecure` Peer Crash-Dump Abuse | 2023-2025 | Confidentiality of `PPL/Lsa` memory against `PPL/WinTcb` (`6 >= 4`) | Local `Administrator` invoking signed `WerFaultSecure.exe` with crafted flags | Abuses legitimate `WinTcb`-signed crash reporter (`0x61 >= 0x41`) to create encrypted/unencrypted memory dumps of `lsass.exe` or freeze `EDR` threads | Patch `WerFaultSecure` argument/encryption handling; enable Credential Guard so `VTL0` dumps lack long-term secrets [69, 288] |

### Trusted Scripting and Confused-Deputy Channels: COM and `PPLdump`

The first two waves of user-mode `PPL` bypasses exploited trusted OS mechanisms that predated Windows 8.1. In 2018, James Forshaw demonstrated that activating COM objects inside a protected process could map Microsoft-signed scripting engines (`scrobj.dll`, `jscript.dll`, `vbscript.dll`), turning valid Microsoft code into an arbitrary script interpreter; Microsoft responded by hardcoding `g_BlockedDllsForPPL[]` inside `ci.dll!CipMitigatePPLBypassThroughInterpreters` to return `STATUS_DYNAMIC_CODE_BLOCKED` [293, 297].

In April 2021, Clément Labro (`itm4n`) weaponized a subtle architectural discrepancy between full `PP` and `PPL` in `PPLdump` [295, 301, 303]. Whereas Vista-era full `PP` processes ignored the `\KnownDlls\` object directory, Windows 8.1 `PPL` processes trusted `\KnownDlls\` sections without re-running `ci.dll` file verification, assuming only `WinTcb` processes could populate `\KnownDlls\`. By calling `DefineDosDevice`, an ordinary `Administrator` coerced `csrss.exe` (`PPL/WinTcb`, `0x61`) into creating a symbolic link inside `\KnownDlls\` pointing to an attacker-crafted transacted section, mapping arbitrary dumping code straight into `PPL` processes until Microsoft patched `ntdll!LdrpInitializeProcess` in July 2022 (`KB5015878` / build `19044.1826`) to align `PPL` with `PP` and skip `\KnownDlls\` entirely [302, 303].

### Lazy Page-In `TOCTOU` (`PPLFault`) and Historical Signed Code (`BYOVDLL`)

Once `\KnownDlls\` closed, researchers targeted the temporal and lifecycle assumptions of `ci.dll` itself:
* **`PPLFault` (Gabriel Landau, Black Hat Asia 2023):** When a `PPL` maps a DLL via `NtCreateSection`, `MiValidateSectionCreate` invokes `ci.dll` at section creation, *before* the Memory Manager lazily faults pages from disk [289, 304]. Using Windows' `CloudFilter` (`cldflt.sys`) sync-root API and opportunistic locks, Landau served genuine signed Microsoft bytes during `ci.dll`'s header/hash check and swapped in unsigned shellcode inside `FetchDataCallback` at page-fault time, forcing Microsoft (February 2024) to enforce demand-fault page-hash validation on redirector-backed `PPL` loads [289, 305].
* **Bring Your Own Vulnerable DLL (`BYOVDLL`, Landau & Labro, 2022-2024):** Mirroring `BYOVD` in Ring 0 ([Chapter 7](06-code-integrity.md)), `BYOVDLL` loads an authentic, older Microsoft-signed DLL carrying known memory-corruption flaws into a running `PPL` [306]. In `Ghost in the PPL` (August 2024), Labro pointed `HKLM\SYSTEM\CurrentControlSet\Services\KeyIso\Parameters\ServiceDll` at an unrevoked 2023 build of `keyiso.dll`, restarted the `KeyIso` service hosted inside `lsass.exe` (`0x41`), and chained an out-of-bounds read (`CVE-2023-36906`) with a use-after-free (`CVE-2023-28229`) to achieve arbitrary code execution inside `PPL/Lsa` while satisfying every signature and EKU check [306, 307, 308, 309].

## Theoretical Limits & Structural Invariants

### `VTL0` Kernel Mutability and the Defense-in-Depth Ceiling

`PPL` is enforced entirely by `ntoskrnl.exe` reading `EPROCESS.Protection` in `VTL0` pool memory. Unlike `VTL1` trustlets ([Chapter 6](05-secure-kernel.md)), whose pages are unmapped in `VTL0` `SLAT` tables, every page of a `PPL` process (and the `EPROCESS` kernel structure itself) remains readable and writable to `VTL0` Ring 0 code. Any `BYOVD` driver exposing arbitrary kernel read/write (`RTCore64.sys`, `gdrv.sys`) can locate the target `EPROCESS` and write `0x00` to its `Protection` offset in a single instruction, instantly dropping `lsass.exe` or an `EDR` sensor back to an unprotected process [215, 262]. This architectural dependency on an uncompromised `VTL0` kernel is the primary reason MSRC classifies `PPL` as defense in depth rather than a security boundary [173, 289].

### Decoupling Channel Admission from Runtime Conduct

Consistent with Law 16, verifying the cryptographic signer rung of an executable or DLL at load time proves who authored the binary, never that the binary cannot be driven into unsafe behavior via untrusted IPC, registry parameters, or memory corruption.

> **Key idea.**
> Every user-mode `PPL` bypass (`COM` scriptlets, `PPLdump`, `PPLFault`, `BYOVDLL`, and `WerFaultSecure` peer abuse) respects the `RtlProtectedAccess[]` handle lattice completely; instead of opening `lsass.exe` from below, the attacker supplies malicious configuration, RPC payloads, or older signed modules across an already-admitted channel ($S_c \ge S_t$). Protecting `PPL` targets therefore requires pairing signer-lattice admission with intra-process exploit mitigations (`CFG`, `ACG`, `CET`, [Chapter 9](19-mitigations.md)) and `App Control` DLL blocklists ([Chapter 7](06-code-integrity.md)).

### Peer Equivalence Within a Rung ($S_c = S_t$)

Because `RtlProtectedAccess[]` grants full access whenever $S_c \ge S_t$, `PPL` provides vertical hierarchy isolation, not horizontal compartment isolation [288]. Every process running at `PPL/Antimalware` (`0x31`) can open every other `PPL/Antimalware` process with `PROCESS_ALL_ACCESS`, and any compromised `PPL/WinTcb` (`0x61`) service dominates every `Windows`, `Lsa`, and `Antimalware` process on the host. True per-instance horizontal isolation requires `VTL1` trustlets scoped by `(Trustlet ID, Instance GUID)` ([Chapter 6](05-secure-kernel.md)).

## Inspecting and Verifying on a Running System

Operational verification of `PPL` must separate *configured registry intent* (`RunAsPPL`) from *actual runtime protection on the current boot* (`Wininit` Event ID `12`) and *pre-enforcement DLL compatibility telemetry* (`CodeIntegrity` Events `3065`/`3066`).

### Checking Configured `RunAsPPL` Policy vs. Live Boot Confirmation

Verify both the configured `RunAsPPL` registry value (`1` = UEFI-locked, `2` = registry-only) and `Microsoft-Windows-Wininit` Event ID `12` in the `System` log, which Microsoft documents as the authoritative confirmation that `lsass.exe` actually launched at `PsProtectedSignerLsa` (`level: 4`, byte `0x41`) on the current boot (elevated PowerShell) [287, 300]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL','RunAsPPLBoot' -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12} -MaxEvents 1 |
    Select-Object TimeCreated, Id, Message
```

Expected output on an actively protected host:

```text
RunAsPPL     : 1
RunAsPPLBoot : 2

TimeCreated           Id Message
-----------           -- -------
11/14/2026 8:14:52 AM 12 LSASS.exe was started as a protected process with level: 4.
```

If `RunAsPPL` is `1` or `2` in the registry but `Wininit` Event ID `12` is absent since the last boot time, `lsass.exe` is running unprotected (`0x00`), indicating a pending reboot or policy-application failure [300].

### Auditing LSASS Plugin Compatibility Before Enforcement

Before switching `RunAsPPL` from audit to enforced across an enterprise fleet, verify `AuditLevel = 8` under `IFEO\LSASS.exe` and query `Microsoft-Windows-CodeIntegrity/Operational` for Event IDs `3065` and `3066` (unsigned or non-Microsoft-signed authentication/password-filter DLLs that would break logon under enforcement) [300]:

```powershell
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe' -Name 'AuditLevel' -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3033,3065,3066} -MaxEvents 5 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

Expected output when third-party LSASS plugins are clean (or flagging a non-compliant module):

```text
AuditLevel : 8

TimeCreated           Id Message
-----------           -- -------
11/14/2026 8:14:55 AM 3066 Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\lsass.exe) attempted to load \Device\HarddiskVolume3\Windows\System32\LegacyPwdFilter.dll that did not meet the Microsoft signing level requirements (or violated code integrity policy). However, due to policy, the image was allowed to load.
```

Resolving all `3065`/`3066` audit hits prior to setting `RunAsPPL = 1` prevents fleet-wide authentication outages when UEFI-locked `PPL/Lsa` blocks legacy smart-card or password-filter DLLs [300].

### Verifying Anti-Malware Service `LaunchProtected` Configuration

Confirm that Windows Defender (`WinDefend`) or third-party `MVI`/`ELAM` services register `LaunchProtected = 3` (`LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`, corresponding to `0x31` at runtime) in the Service Control Manager registry [297]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' -Name 'LaunchProtected'
```

Expected output:

```text
LaunchProtected : 3
```

A `LaunchProtected` value of `3` instructs the Service Control Manager and `ntoskrnl.exe` to validate the binary against cached `ELAM` certificate hashes (`WdBoot.sys` for `WinDefend`) and initialize `MsMpEng.exe` with `EPROCESS.Protection = 0x31` [297, 299].

## Summary & Handoff

Protected Process Light (`PPL`) inserts a fast, 1-byte cryptographic provenance check (`_PS_PROTECTION`) into `NtOpenProcess` ahead of `SeAccessCheck`, stripping memory-read, injection, and termination rights even from `SYSTEM` callers holding `SeDebugPrivilege`. Through `PPL/WinTcb` (`csrss.exe`), UEFI-locked `RunAsPPL` (`lsass.exe` at `0x41`), and `ELAM`/`MVI`-admitted `PPL/Antimalware` (`0x31`), Windows neutralizes casual post-exploitation credential dumping and sensor termination in `VTL0`. Yet a decade of offensive research (`COM` scriptlets, `PPLdump`, `PPLFault`, `BYOVDLL`, and `BYOVD` Ring 0 writes) demonstrates that handle lattices govern *who may enter or open a process*, not whether admitted code contains memory-corruption bugs or whether `VTL0` kernel memory stays intact.

Closing those two remaining exposures bridges the end of Part II into Part III:

* **Hardening Admitted Code Against Memory Corruption (`BYOVDLL` / RCE):** Preventing use-after-free and out-of-bounds bugs inside running processes (such as `CVE-2023-28229` in `keyiso.dll`) from turning into arbitrary code execution requires `ASLR`, `DEP`, `ACG`, `CIG`, `CFG`, `XFG`, and hardware `CET` shadow stacks in [Process Mitigation Policies (Chapter 9)](19-mitigations.md).
* **Moving Secrets Out of `VTL0` Entirely:** Ensuring that even a `BYOVD` kernel write or a `BYOVDLL` `lsass.exe` compromise cannot dump domain NTLM hashes or Kerberos TGT keys is the architectural mandate of [Credential Guard and LSASS Isolation (Chapter 11)](08-credential-guard.md).
