# ETW: The EDR Substrate

## Overview

* **Role in the Chain:** Host-wide observability substrate beneath Parts I through III; captures high-rate process, thread, image-load, script (`AMSI`/PowerShell), `.NET` CLR, authentication (`Security-Auditing`/`WebAuthN`), and kernel memory-modification (`EtwTi`) telemetry consumed by Endpoint Detection and Response (`EDR`) sensors and cloud risk engines.
* **Core Security Invariant:** User-mode processes cannot suppress kernel-emitted `Microsoft-Windows-Threat-Intelligence` (`EtwTi`) events by patching their own `ntdll.dll` stubs because `EtwTi` fires inside `ntoskrnl.exe` after the `syscall` boundary, while `EnableTraceEx2` consumer subscription to `EtwTi` is restricted to `Antimalware-PPL` services anchored by an `ELAM` boot certificate.
* **Trusted Computing Base (TCB):** `ntoskrnl.exe` event-tracing routines and per-CPU ring buffers, provider emission sites (`VTL0` user-mode `ntdll!EtwEventWrite` vs. kernel `EtwWrite`), `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger` boot configurations, the `PPL` + `ELAM` consumer gate, and `HVCI` + the Vulnerable Driver Blocklist protecting kernel ETW structures.
* **Primary Failure Modes:** Boot `Autologger` registry tampering, in-process `0xC3` (`RET`) patching or hardware-breakpoint unhooking of `ntdll!EtwEventWrite` / `NtTraceEvent` / `AmsiScanBuffer` (blinding user-mode CLR/script providers), 8-session provider exhaustion, `BYOVD` kernel-memory corruption of `_ETW_GUID_ENTRY` / `EtwThreatIntProvRegHandle`, and sub-flush asynchronous execution before consumer delivery.
* **Handoff:** Translates local host behavior into endpoint risk telemetry without offering inline prevention or lossless guarantees; hands device-risk evaluation and dynamic access enforcement to [Zero Trust (Chapter 17)](13-zero-trust.md) and [Continuous Access Evaluation (Chapter 18)](14-cae.md).

## Core Engineering Problem & Threat Model

Every preventive link in Parts I through III (Code Integrity in [Chapter 7](06-code-integrity.md), Protected Process Light in [Chapter 8](18-ppl.md), Access Control in [Chapter 10](25-access-control.md), Credential Guard in [Chapter 11](08-credential-guard.md), Kerberos in [Chapter 13](10-kerberos.md), `CloudAP` in [Chapter 14](11-pth-prt.md), and `WebAuthn` in [Chapter 15](12-hello.md)) requires an observability plane that records both blocked attempts and post-unlock abuse. Designing that plane on a 64-core server or laptop poses a severe systems-engineering constraint: synchronous `DbgPrint`-style logging serializes CPUs and stalls hot-path system calls, whereas placing trace emitters inside user-mode DLLs lets malware silence its own telemetry with a single-byte memory write [612, 613].

Windows solved the throughput half in Windows 2000 with Event Tracing for Windows (`ETW`), engineered by Insung Park and Ricky Buch's performance team around four primitives: lock-free per-CPU ring buffers, asynchronous kernel writer threads, dynamic runtime activation (`EnableTraceEx2`), and a strict separation of Providers, Controllers, and Consumers [613, 614, 615, 616]. Windows Vista (January 2007) solved multi-vendor coexistence by replacing single-consumer `MOF` providers, where a second subscriber silently stole the stream from the first [617], with the unified manifest provider model supporting up to 8 concurrent real-time sessions per provider (`diagrams/28-etw-vista-fanout.svg`) [613, 618].

![Figure: Vista's unified provider model (2007). A single EventWrite fans out to the per-CPU ring buffer (drained by the writer thread to an .etl file or real-time delivery) and to the evtx channel, and up to eight independent real-time sessions read the same manifest provider at once; the classic/MOF model allowed only one, the second consumer silently stealing the first.](diagrams/28-etw-vista-fanout.svg)

The threat model assumes an adversary executing on the endpoint at Medium Integrity (targeting in-process user-mode `ntdll.dll` and `amsi.dll` stubs), High/`SYSTEM` Integrity (targeting `Autologger` registry keys and unguarded trace sessions), or `VTL0` Ring 0 via Bring Your Own Vulnerable Driver (`BYOVD`, targeting kernel `_ETW_SILODRIVERSTATE` and `EtwTi` registration handles) [612, 619, 620, 621].

## Architectural Deep Dive

### Ring Buffers, Provider Classes, and `Autologger` Boot Persistence

When a controller (`logman`, Windows Performance Recorder, or an EDR service) calls `StartTrace` with an `EVENT_TRACE_PROPERTIES` structure (typically `32-64 KB` buffers, minimum two per logical processor, up to `64` global sessions per host) and subscribes to a provider GUID via `EnableTraceEx2`, dormant trace sites become active [614, 616, 622]. A producer on CPU $k$ copies its event payload directly into CPU $k$'s kernel buffer without cross-core locks; an asynchronous kernel thread drains filled buffers either to `.etl` files (`File` or `Circular` mode) or to subscribers calling `OpenTrace` + `ProcessTrace` with `EVENT_TRACE_REAL_TIME_MODE` [613, 614].

Across 26 years, Microsoft shipped four `ETW` provider classes with distinct security trade-offs [613, 617, 618, 623, 624]:

| Provider Class | Introduced | Schema Location | Max Sessions | EDR Telemetry Role |
|---|---|---|---|---|
| Classic / `MOF` | Windows 2000 | `WMI` repository (`mofcomp`) | `1` (`8` for `SystemTraceProvider` on Win 8+ [625]) | Legacy `NT Kernel Logger` [617, 626] |
| `WPP` (Software PreProcessor) | Windows XP era | Producer `.pdb` (`TMF` format) | Implementation-specific | Internal Microsoft kernel debugging; unusable without `.pdb` symbols [623, 627] |
| Manifest-Based (`Crimson`) | Windows Vista (2007) | Compiled XML resource (`mc.exe` / `wevtutil im`), decoded via `TDH` | `8` concurrent | Primary EDR & Windows Event Log (`.evtx`) security substrate [613, 618, 628] |
| `TraceLogging` | Windows 10 (2015) | Self-describing inline `TLV` fields inside each event | `8` concurrent | Modern C++, `.NET` `EventSource`, and WinRT services without XML manifests [624, 629] |

To capture pre-logon and early-service activity before user-mode EDR services finish starting, the kernel reads `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\` (and `GlobalLogger`) during boot, instantiating configured sessions and enabling nested `<ProviderGuid>` subkeys at their specified `Level` and `MatchAnyKeyword` bitmasks [614, 619].

### The Security Provider Catalog and the Emission-Layer Split

Roughly `1,300` manifest providers ship on Windows 11 `24H2` [630, 631], but endpoint security centers on an architectural divide between user-mode in-process emitters and kernel-mode emitters (`diagrams/28-etw-catalogue-layers.svg`):

![Figure: The security-provider catalog as a layered emission map. User-mode providers (DotNETRuntime, PowerShell, AMSI) funnel through the ntdll!EtwEventWrite stub the 0xC3 patch can reach, kernel-emitted manifest providers sit beyond the user/kernel line, and the kernel-side EtwTi provider is gated by a PPL+ELAM turnstile that admits only an Antimalware-signed consumer.](diagrams/28-etw-catalogue-layers.svg)

| Provider Name | GUID | Emission Context | Primary Security Signal | Consumer Gate |
|---|---|---|---|---|
| `Microsoft-Windows-DotNETRuntime` | `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}` | Caller user mode (`clr.dll` → `ntdll`) | In-memory `.NET` `Assembly.Load` (`execute-assembly`), JIT [612] | Local Admin / `SYSTEM` |
| `Microsoft-Windows-PowerShell` | `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}` | Caller user mode (`System.Management.Automation`) | Script-block logging (`Event ID 4104`), pipeline execution [632] | Local Admin / `SYSTEM` |
| `Microsoft-Antimalware-Scan-Interface` | `{2A576B87-09A7-520E-C21A-4942F0271D67}` | Caller user mode (`amsi.dll`) | Post-deobfuscation PowerShell, VBA, JScript, WSH, CLR buffers [619, 633] | Local Admin / `SYSTEM` |
| `Microsoft-Windows-Security-Auditing` | `{54849625-5478-4994-A5BA-3E3B0328C30D}` | `lsass.exe` user mode | Logons (`4624`/`4625`), process cmdline (`4688`), Kerberos (`4768`/`4769`) [634, 635] | Audit policy / `SYSTEM` |
| `Microsoft-Windows-Sysmon` | `{5770385F-C22A-43E0-BF4C-06F5698FFBD9}` | `SysmonDrv.sys` kernel callbacks → `Sysmon` service | Process/hash/cmdline (`1`), `LSASS` open (`10`), registry (`13`) [630, 636] | Local Admin / `SYSTEM` |
| `Microsoft-Windows-Kernel-Process` (+ `File`, `Network`, `Registry`) | `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}` | `ntoskrnl.exe` (`VTL0` Ring 0) | Real-time process/thread create, `ImageLoad`, file/socket/reg I/O [625, 630, 637] | Local Admin / `SYSTEM` |
| `Microsoft-Windows-Threat-Intelligence` (`EtwTi`) | `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}` | `ntoskrnl.exe` syscall handlers (`VTL0` Ring 0) | Cross-process/local `VirtualAlloc`, `ProtectVM`, `MapView`, `QueueUserAPC`, `SetThreadContext`, `ReadVM` (`LSASS`), `WriteVM` [638, 639] | `Antimalware-PPL` + `ELAM` (`1.3.6.1.4.1.311.61.4.1`) |

### `EtwTi` and the `Antimalware-PPL` + `ELAM` Turnstile

User-mode providers (`DotNETRuntime`, `PowerShell`, `AMSI`, `WebAuthN`) format events inside the target process and call `ntdll!EtwEventWrite` → `ntdll!NtTraceEvent`. Because that code resides in writable/reprotectable user-mode memory belonging to the process itself, malware executing Cobalt Strike `execute-assembly` can overwrite `EtwEventWrite`'s prologue with `0xC3` (`ret`) and mute `.NET` CLR events locally [612, 640].

`Microsoft-Windows-Threat-Intelligence` (`EtwTi`) defeats user-mode patching structurally by placing its `EtwWrite` calls inside `ntoskrnl.exe`'s memory-management and thread-scheduling syscall implementations (`KERNEL_THREATINT_TASK_ALLOCVM`, `PROTECTVM`, `MAPVIEW`, `QUEUEUSERAPC`, `SETTHREADCONTEXT`, `READVM`, `WRITEVM`, `SUSPENDRESUME_THREAD`, `SUSPENDRESUME_PROCESS`, `DRIVER_DEVICE`) [638, 639]. Even if an attacker unhooks `ntdll.dll` completely and invokes direct or indirect `syscall` instructions to allocate `RWX` shellcode or read `lsass.exe`, execution must cross into `ntoskrnl.exe`, firing `EtwTi` out of reach of user mode [638].

To prevent non-EDR processes (or attackers) from subscribing to sensitive memory pointers in `EtwTi`, or saturating its 8-session cap, Windows enforces a strict consumer gate: `EnableTraceEx2` against `{f4e1897c-...}` returns `ERROR_ACCESS_DENIED` unless the calling process runs as `PsProtectedSignerAntimalware-Light` (`Antimalware-PPL`, [Chapter 8](18-ppl.md)) signed with EKU `1.3.6.1.4.1.311.61.4.1` and allow-listed at boot inside an Early Launch Antimalware (`ELAM`, [Chapter 1](16-secure-boot.md)) driver (`MsMpEng.exe` for Defender; third-party EDRs such as CrowdStrike `CSFalconService.exe` verified via live `_ETW_REALTIME_CONSUMER` kernel debugger inspection) [26, 297, 620, 622, 638]. `EtwTi` is thus the observational dual of `Credential Guard` ([Chapter 11](08-credential-guard.md)): one places secrets across a privilege boundary so user mode cannot read them; the other places syscall sensors across the boundary so user mode cannot blind them.

### Synchronous Kernel Callbacks vs. Asynchronous `ETW`

Commercial EDRs pair `ETW` with synchronous kernel notify routines (`PsSetCreateProcessNotifyRoutineEx`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, and `FltMgr` file-system minifilters) [641, 642]:
* **Kernel Callbacks (Inline Veto, High Blast Radius):** Execute synchronously in the originating thread at `PASSIVE_LEVEL` *before* process creation completes, allowing an EDR driver (`WdFilter.sys`, Falcon, Elastic) to block execution by writing an error status into `CreationStatus` [641]. That synchronous Ring 0 authority carries severe operational risk: in July 2024, an out-of-bounds read triggered by a malformed CrowdStrike Falcon content configuration file crashed `8.5 million` Windows hosts worldwide [643, 644].
* **`ETW` Streams (Broad Visibility, Zero Veto):** Decouple consumers from the kernel hot path so a crashed user-mode `ETW` consumer never bugchecks Windows, at the cost of asynchronous post-facto delivery: `ETW` observes what happened; it cannot block a syscall in flight [618].

## Attack Catalog & Gap Analysis

Five generations of offensive tradecraft trace an escalating climb from boot registry configuration to user-mode stubs to Ring 0 kernel structures (`diagrams/28-etw-attack-defense-timeline.svg`).

![Figure: Five generations of ETW tradecraft, 2014-2026. Attack generations climb from boot-config (autologger) to user-mode (0xC3 patch) to kernel (BYOVD), while each structural defense answers the attack class at the layer it targets: the Antimalware-PPL+ELAM gate on EtwTi pre-dates the user-mode patch by three years, and the default-on Vulnerable Driver Blocklist closes the BYOVD primitive.](diagrams/28-etw-attack-defense-timeline.svg)

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `Autologger` & Live Session Tampering (`logman`, `ControlTrace`) | 2014-2018 | Unprotected `ETW` session continuity across boot or runtime | Local `SYSTEM` / Administrator | Disables `HKLM\...\WMI\Autologger` subkeys before reboot or calls `ControlTrace` / `DISABLE_PROVIDER` on non-`PPL` sessions | Protect EDR sessions under `Antimalware-PPL`; alert on `Sysmon 13` / registry writes to `WMI\Autologger` [619, 636, 645] |
| In-Process User-Mode Patching (`0xC3 RET`, Hardware Breakpoints) | 2020-present | User-mode `ETW` (`DotNETRuntime`, `PowerShell`, `AMSI`) inside current PID | Code execution inside caller's own `VTL0` user process | Patches `ntdll!EtwEventWrite` / `NtTraceEvent` / `AmsiScanBuffer` or intercepts via `DR0-DR3` `VEH` without touching page permissions | Rely on kernel-emitted `EtwTi` (`ALLOCVM`, `PROTECTVM`, `READVM`) unreachable from user mode [612, 638, 640, 646] |
| Manifest 8-Session Exhaustion | 2018-present | Availability of unguarded manifest providers to late subscribers | Local Admin starting dummy `EnableTraceEx2` sessions | Saturates all `8` session slots on a manifest provider so subsequent consumers receive `ERROR_NO_SYSTEM_RESOURCES` | Register EDRs as early-boot `Autologgers`; monitor failed `EnableTraceEx2` sensor health telemetry [618, 622] |
| Kernel `ETW` Blinding via `BYOVD` (`Lazarus`, `_ETW_SILODRIVERSTATE`) | 2021-present | All `VTL0` kernel `ETW` providers including `EtwTi` | Admin + signed vulnerable driver not yet on Microsoft blocklist | Uses arbitrary Ring 0 write primitive to zero `EtwThreatIntProvRegHandle`, unlink `_ETW_GUID_ENTRY`, or disable consumer handles | Enforce `HVCI` + Microsoft Vulnerable Driver Blocklist ([Chapter 7](06-code-integrity.md)) and alert on `LOLDrivers` loads [159, 271, 620, 621] |
| Sub-Flush Execution & Keyword Drift | Architectural | Real-time prevention & complete syscall coverage | Payload completing inside `< 1` writer flush or uninstrumented section API | Executes shellcode/exfiltration before async ring buffer drains, or uses section-mapping variants outside `EtwTi` bitmasks | Pair `ETW` with synchronous `PsSetCreate*` / `ObRegisterCallbacks` and `Credential Guard` `VTL1` isolation [618, 638, 641] |

### User-Mode Patching vs. `EtwTi`: Why `0xC3` Stopped Being Universal

When Adam Chester published *Hiding your .NET - ETW* in March 2020 [612], overwriting `ntdll!EtwEventWrite` (or `NtTraceEvent` [646]) silenced `Microsoft-Windows-DotNETRuntime` inside the offensive process without affecting other processes on the host. Against SIEM pipelines relying solely on `.NET` or PowerShell user-mode events, the process vanished. Against an `Antimalware-PPL` EDR subscribed to `EtwTi`, however, the surrounding actions (allocating executable memory via `ALLOCVM` / `PROTECTVM`, injecting APCs via `QUEUEUSERAPC`, or opening `lsass.exe` via `READVM`) fired directly from `ntoskrnl.exe` [638, 639].

### The Ring 0 Frontier: `BYOVD` vs. `HVCI` and Future `VTL1` `EtwSi*`

Because `EtwTi` lives in `VTL0` `ntoskrnl.exe`, an attacker who crosses into Ring 0 via a signed vulnerable driver (`BYOVD`, documented in real-world Lazarus Group intrusions [620, 621]) can corrupt `EtwThreatIntProvRegHandle` or `_ETW_REALTIME_CONSUMER` structures directly. Windows 11 `22H2+` narrows that vector structurally by enabling `HVCI` and the Vulnerable Driver Blocklist ([Chapter 7](06-code-integrity.md)) by default, leaving only the 1-to-3-month lag window for newly discovered `LOLDrivers` [159, 271]. Looking ahead, undocumented Secure Kernel tracing (`EtwSi*` in `VTL1`, [Chapter 6](05-secure-kernel.md)) foreshadows moving critical security telemetry producers above `VTL0` Ring 0 altogether, though no public third-party consumer API exists in 2026.

## Theoretical Limits & Structural Invariants

### Asynchronous Observation Cannot Provide Inline Prevention or Lossless Audit

By design, `ETW`'s lock-free per-CPU ring buffers prioritize bounded producer latency over guaranteed delivery. Microsoft's specification explicitly warns that events are dropped whenever an event exceeds `64 KB`, disk I/O lags, or a real-time consumer falls behind a burst of syscalls [618]. Furthermore, because buffer draining is asynchronous, a payload that allocates memory, executes, and exits inside a single flush interval is *observed after execution*, never prevented [618]. Pre-`GlobalLogger` early-boot execution is likewise invisible to `ETW`, belonging exclusively to **Measured Boot ([Chapter 4](03-measured-boot.md))* and *Attestation ([Chapter 5](04-attestation.md))**.

### Decoupling Endpoint Telemetry from Ground-Truth Integrity

Consistent with Law 16, receiving clean or silent `ETW` telemetry from an endpoint does not prove the endpoint is uncompromised, nor does `ETW` alone establish forensic chain-of-custody completeness.

> **Key idea.**
> `ETW` is a high-throughput, best-effort behavioral sensor, not a synchronous access-control monitor or tamper-proof flight recorder [618]. Downstream cloud policy engines (Zero Trust, [Chapter 17](13-zero-trust.md) and Continuous Access Evaluation, [Chapter 18](14-cae.md)) consume EDR device-risk scores derived from `ETW` to revoke or gate tokens, but sound architecture never mistakes the absence of an `ETW` alert for cryptographic proof of host integrity.

## Inspecting and Verifying on a Running System

Defenders verify `ETW` sensor integrity on a live Windows host by auditing active real-time trace sessions and lost-event counters, inspecting the `EtwTi` manifest and `Autologger` boot persistence keys, and confirming `HVCI` + Vulnerable Driver Blocklist enforcement.

### Enumerating Active `ETW` Trace Sessions and Buffer Drop Counts

Query live kernel and user trace sessions (`-ets`) to confirm EDR/Defender real-time consumers are active and check `Events Lost` / `Buffers Lost` under load [614, 616]:

```powershell
Get-EtwTraceSession | Select-Object Name, LogFileMode, BufferSize, MaximumBuffers, EventsLost, BuffersLost |
    Select-Object -First 8 | Format-Table -AutoSize
```

Expected output (non-zero `EventsLost` on security sessions indicates consumer backpressure or buffer undersizing):

```text
Name                        LogFileMode BufferSize MaximumBuffers EventsLost BuffersLost
----                        ----------- ---------- -------------- ---------- -----------
Circular Kernel Context ...   268435840         64            128          0           0
DefenderApiLogger              67109120         64             64          0           0
EventLog-Security              67109120         64             64          0           0
SenseNdrPpl                   268435712         64            128          0           0
```

### Auditing `Microsoft-Windows-Threat-Intelligence` (`EtwTi`) and `Autologger` Persistence

Verify that `Microsoft-Windows-Threat-Intelligence` (`{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`) is registered with its `KERNEL_THREATINT_TASK_*` schema, and audit boot-persistent `Autologger` sessions for unauthorized `Start = 0` tampering [619, 638]:

```powershell
wevtutil gp Microsoft-Windows-Threat-Intelligence | Select-String 'name:|guid:|KERNEL_THREATINT_TASK_' | Select-Object -First 8
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\*' -Name Start -ErrorAction SilentlyContinue |
    Select-Object PSChildName, Start | Select-Object -First 8
```

Expected output:

```text
name: Microsoft-Windows-Threat-Intelligence
guid: f4e1897c-bb5d-5668-f1d8-040f4d8dd344
    name: KERNEL_THREATINT_TASK_ALLOCVM
    name: KERNEL_THREATINT_TASK_PROTECTVM
    name: KERNEL_THREATINT_TASK_MAPVIEW
    name: KERNEL_THREATINT_TASK_QUEUEUSERAPC
```

### Verifying `HVCI` and Vulnerable Driver Blocklist Protection Against `BYOVD`

Confirm that `HVCI` (`2` in `SecurityServicesRunning`) and `VulnerableDriverBlocklistEnable` (`1` or `2`) are active to block known `BYOVD` drivers from corrupting kernel `ETW` structures [159, 183]:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue
```

Expected output on a hardened Windows 11 `22H2+` endpoint:

```text
VirtualizationBasedSecurityStatus SecurityServicesRunning
--------------------------------- -----------------------
                                2 {1, 2}
VulnerableDriverBlocklistEnable : 1
```

## Summary & Handoff

Event Tracing for Windows (`ETW`) turned a Windows 2000 lock-free ring-buffer profiler and Vista's 8-session manifest fan-out into the central nervous system of modern Windows endpoint security. While user-mode providers (`DotNETRuntime`, `PowerShell`, `AMSI`) remain valuable deobfuscation lenses, `Microsoft-Windows-Threat-Intelligence` (`EtwTi`), emitted inside `ntoskrnl.exe` and gated behind `Antimalware-PPL` + `ELAM`, neutralized in-process `0xC3` `ntdll` patching, leaving `BYOVD` kernel writes (narrowed by `HVCI` and the Vulnerable Driver Blocklist) and asynchronous flush latency as its durable boundaries.

Everything up to Chapter 16 has executed on a single Windows machine; Part IV (*Cloud*) lifts the trust chain across the internet into Microsoft Entra ID and Azure hardware roots of trust:

* **Turning Device Attestation, Auth Strength, and EDR Risk into Access Policy:** How endpoint compliance, `ETW`/Defender risk scores, `Phishing-Resistant MFA`, and `Token Protection` converge inside a policy engine is the subject of [Zero Trust (Chapter 17)](13-zero-trust.md).
* **Shrinking Post-Compromise Bearer-Token Dwell Time:** How Microsoft Entra ID propagates risk and revocation signals inside active OAuth lifetimes belongs to [Continuous Access Evaluation (Chapter 18)](14-cae.md).
* **Moving the Entire Guest OS Inside Hardware-Encrypted Cloud Silicon:** Protecting cloud workloads even from a compromised hypervisor host is examined in [Confidential VMs (Chapter 19)](29-confidential-vms.md).
