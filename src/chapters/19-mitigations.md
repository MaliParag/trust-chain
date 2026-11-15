# Process Mitigation Policies

## Overview

* **Role in the Chain:** Intra-process exploit-mitigation layer operating across Ring 3 and Ring 0; constrains memory permissions (`DEP`, `ACG`), address predictability (`ASLR`), image-load provenance (`CIG`), forward/backward control-flow transfers (`CFG`, `XFG`, `CET` shadow stacks), and syscall/namespace pivot surfaces (`DisableWin32k`, `RedirectionGuard`) inside code that Code Integrity ([Chapter 7](06-code-integrity.md)) and `PPL` ([Chapter 8](18-ppl.md)) already admitted.
* **Core Security Invariant:** In a maximally hardened process launched with `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`, writable pages never execute (`DEP`), executable pages are never dynamically allocated or mutated (`ACG`), unsigned DLLs cannot map (`CIG`), indirect calls target only compiler-enumerated entries (`CFG`), and `RET` instructions must match hardware-protected CPU shadow-stack frames (`CET` `#CP`).
* **Trusted Computing Base (TCB):** MSVC compile/link instrumentation (`/guard:cf`, `/CETCOMPAT`, `/DYNAMICBASE`), `ntdll.dll` loader and call-target validators (`LdrpValidateUserCallTarget`), CPU `NX` and `CET` shadow-stack silicon, `ntoskrnl.exe` process-creation attribute enforcement, and `VTL1` `HVCI` protecting kernel `kCFG` bitmaps.
* **Primary Failure Modes:** Prototype-compatible C++ virtual-method chaining (`COOP`), non-control-data corruption that never alters the control-flow graph (`Data-Oriented Programming`, `DOP`), startup races when policies self-apply post-`CreateProcess`, IPC bugs in split out-of-process JIT servers, and signed-but-vulnerable DLL side effects (`CIG` gap).
* **Handoff:** Completes Part II (Kernel & Code) by raising the cost of turning C/C++ memory-safety defects into arbitrary code execution; hands off to Part III (Credentials & Access) ([Chapter 10](25-access-control.md) through [Chapter 17](12-hello.md)), which governs the tokens, privileges, and authentication secrets an attacker pursues once code executes.

## Core Engineering Problem & Threat Model

Code Integrity ([Chapter 7](06-code-integrity.md)) and Protected Process Light ([Chapter 8](18-ppl.md)) ensure that only trusted, signed binaries load into sensitive processes and block lower-privileged handles from outside. Neither mechanism prevents an attacker from feeding crafted network packets, media files, or RPC buffers into a memory-safety vulnerability (buffer overflow, use-after-free, type confusion, integer overflow) *inside* a legitimately signed C or C++ binary, such as `CVE-2023-28229` inside Microsoft's signed `keyiso.dll` ([Chapter 8](18-ppl.md)) or a parser bug in a browser renderer.

Historically, memory corruption translated directly into arbitrary code execution across three offensive eras. First, classic stack smashing (`Aleph One`, 1996 [310]) overwrote saved return addresses to jump straight into attacker bytes on the stack, prompting hardware `NX`/`XD` page-table bits (2003 [311]), Windows XP SP2 Data Execution Prevention (`DEP`, 2004 [312]), and Windows Vista Address Space Layout Randomization (`ASLR`, 2007 [313]). Second, once `DEP` blocked injected shellcode, Hovav Shacham demonstrated in October 2007 that Return-Oriented Programming (`ROP`) achieves Turing-complete computation purely by chaining short instruction sequences ending in `ret` ("gadgets") already present in legitimate DLLs [314, 315, 316]. Third, after heuristic ROP-detection shims in Microsoft's Enhanced Mitigation Experience Toolkit (`EMET`, 2009-2018 [317]) repeatedly fell to gadget substitution, Windows pivoted to formal Control-Flow Integrity (`CFI`) invariants (Abadi et al., 2005 [318]) and process-scoped capability lockdowns exposed through `SetProcessMitigationPolicy` (`20` policies in Windows 11 24H2) [319, 320].

The process-mitigation threat model assumes an adversary already possesses a deterministic read/write or type-confusion primitive inside an application process (or inside `VTL0` kernel mode for `kCFG`/`kCET`). Because enterprise compatibility forbids applying every restriction globally (Microsoft Outlook requires third-party COM add-ins (`CIG` incompatible) and Microsoft Defender's `MsMpEng.exe` compiles signature emulators dynamically (`ACG` incompatible)), Windows enforces mitigations per process. Under MSRC's Security Servicing Criteria, individual exploit mitigations are classified as defense in depth rather than standalone security boundaries: bypassing `CFG` or `CET` without a memory-corruption bug grants nothing, while pairing mitigations forces an attacker to chain multiple distinct primitives before reaching a sandbox or kernel boundary [173].

## Architectural Deep Dive

### Memory Permissions and Layout Randomization (`DEP` and `ASLR`)

Every modern exploit mitigation builds on two baseline invariants enforced jointly by the CPU MMU and the NT Memory Manager [312, 313, 319]. First, Data Execution Prevention (`DEP`, exposed as `ProcessDEPPolicy`) sets the hardware `NX`/`XD` bit (bit 63 of 64-bit x86 PAE and long-mode PTEs) across stacks, heaps, and writable data sections so fetching instructions from non-code pages faults immediately with `STATUS_ACCESS_VIOLATION` [311, 312]. On 64-bit Windows, `DEP` is unconditionally enabled for all native 64-bit processes, leaving `ProcessDEPPolicy` primarily to lock legacy 32-bit `WoW64` processes.

Non-executable data pages alone cannot stop code-reuse chains if every system DLL maps at a predictable base address. High-Entropy Address Space Layout Randomization (`ASLR`, `ProcessASLRPolicy`) randomizes image load bases (`/DYNAMICBASE`), thread stacks, heaps, and PEBs across virtual memory: `/HIGHENTROPYVA` supplies up to 24 bits of module entropy across the 64-bit user address space, paired with `BottomUpRandomization` and `ForceRelocateImages` to rebase legacy DLLs lacking relocation flags [313, 319]. Without `ASLR`, every `CFI` bitmap and `ROP` gadget address would sit at a static constant; with `ASLR` active, an attacker must first acquire an *information-disclosure* read primitive to leak live module pointers.

### Forward-Edge Control-Flow Integrity: `CFG`, `XFG`, and `kCFG`

To prevent corrupted function pointers and C++ `vtable` pointers from jumping into arbitrary mid-function `ROP`/`JOP` gadgets, Windows 10 (2015) shipped Control Flow Guard (`CFG`, `ProcessControlFlowGuardPolicy`) across a four-phase compiler-to-kernel pipeline [321, 322, 323, 324]:

![Figure: Control Flow Guard as a four-phase pipeline, and a debugging checklist. Compile (`/guard:cf`) inserts a guard thunk before every indirect call; link (`/GUARD:CF` + `/DYNAMICBASE`) writes the Guard CF Function Table into the PE load-config directory: without `/DYNAMICBASE` it is a silent no-op; load unions every image's FID table into a sparse per-process bitmap, one bit per 8 bytes of virtual address space; runtime sends every indirect call through `LdrpValidateUserCallTarget`, which tests the target's bit. Bit set: the validator returns and the call proceeds. Bit clear: `__fastfail` raises `STATUS_STACK_BUFFER_OVERRUN` and the process terminates. Each handoff is a separate failure mode.](diagrams/19-mitigations-cfg-pipeline.svg)

Control Flow Guard spans four coupled stages from compilation to execution. At compile time (`/guard:cf`), MSVC inserts a dispatch call through `__guard_dispatch_icall_fptr` (or `__guard_check_icall_fptr`) before every indirect `CALL` or `JMP`, passing the target address in `rcx` [323]. At link time (`/GUARD:CF` paired with `/DYNAMICBASE`), the linker populates `IMAGE_LOAD_CONFIG_DIRECTORY` with `GuardFlags` (`IMAGE_GUARD_CF_INSTRUMENTED | IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT`) and the sorted Guard CF Function Table (`FID` table) enumerating every valid address-taken and exported function entry point in the PE, whereas omitting `/DYNAMICBASE` silently suppresses `FID` enforcement [324]. As each DLL maps at load time (`ntdll!LdrpProtectAndRelocateImage`), the loader merges its `FID` entries into a sparse, copy-on-write CFG bitmap covering the process virtual address space at one bit per 8-byte aligned slot, with `ExportSuppression` optionally keeping exported APIs non-callable until resolved explicitly [322]. At runtime, `ntdll!LdrpValidateUserCallTarget` shifts `rcx` right on every indirect call to test its bitmap bit, transferring control when set or executing `int 0x29` (`__fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)`) to terminate the process non-recoverably with `STATUS_STACK_BUFFER_OVERRUN` (`0xC0000409`) without consulting exception handlers [322, 325].

In Ring 0, Kernel CFG (`kCFG`) enforces the identical invariant across kernel indirect calls, storing the `kCFG` bitmap inside `VTL1`-protected memory whenever `HVCI` is active ([Chapter 7](06-code-integrity.md)) so a `VTL0` kernel write primitive cannot flip arbitrary call-target bits [326]. Because both `CFG` and `kCFG` are *coarse-grained* (treating every valid function entry in the address space as interchangeable regardless of argument count or types), Microsoft also designed eXtended Flow Guard (`XFG`, `/guard:xfg`), placing a 64-bit truncated SHA-256 hash of each function's static C/C++ type signature at `[target - 8]` and verifying it inline via `__guard_xfg_dispatch_icall_fptr` prior to jumping [327, 328]. However, because pervasive C function-pointer casts across Win32 and COM broke strict prototype matching while hardware backward-edge `CET` arrived concurrently, `XFG` was never enabled broadly and has since been deprecated in favor of `CFG` paired with `CET` [326].

### Backward-Edge Hardware CFI: Shadow Stacks (`CET` and `kCET`)

`CFG` inspects only forward-edge indirect calls; it never inspects `RET` instructions, leaving pure stack-smashing and heap-pivoted `ROP` chains untouched. Beginning on Intel Tiger Lake (2020) and AMD Zen 3 (2020) processors, Windows enforces backward-edge CFI in silicon via Hardware-enforced Stack Protection (`ProcessUserShadowStackPolicy`, Intel `CET` Shadow Stack) [329, 330, 331]. When `CET` is active for a thread, the CPU maintains a dedicated Shadow Stack Pointer (`SSP`) alongside `RSP` so every `CALL` pushes the return address to *both* the ordinary data stack (`[RSP]`) and the shadow stack (`[SSP]`). Shadow-stack pages carry a dedicated hardware PTE attribute (`Dirty=1, Read/Write=0`) that makes them unreadable and unwritable by ordinary `MOV` instructions; only `CALL`/`RET` microcode and privileged `WRSS`/`WRUSS` instructions can modify them, while legitimate `SEH` and C++ exception unwinders advance `SSP` cleanly via `INCSSP` [329, 330]. Every `RET` pops both stacks and compares the two 64-bit addresses in hardware, raising a CPU Control Protection fault (`#CP`) on any single-bit mismatch that Windows surfaces as `STATUS_CONTROL_PROTECTION_EXCEPTION` (`0xC0000602`) to terminate the compromised process immediately [329, 331].

Modules opt into shadow-stack enforcement via `/CETCOMPAT` (`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`) and `/guard:ehcont` exception-continuation tables [330]. Critically, `ProcessUserShadowStackPolicy` also enables `SetContextIpValidation`, preventing an attacker from sidestepping `RET` checks via `NtSetContextThread` or `SetThreadContext` to overwrite `RIP` directly, while `BlockNonCetBinaries` refuses legacy uninstrumented DLLs [331]. On modern Secured-core Windows 11 builds, Kernel CET (`kCET`) extends hardware shadow stacks into `VTL0` Ring 0 [326], while Windows on ARM64 exposes cryptographic pointer signing via `ProcessUserPointerAuthPolicy` (`ARM PAC`) [320].

### Lifetime `W^X` (`ACG`), Image Provenance (`CIG`), and Attack-Surface Reduction

Even with `CFG` and `CET` active, an attacker could previously coerce an in-process Just-In-Time (`JIT`) compiler into emitting shellcode (`JIT spray`) or invoke `LoadLibrary` to map a rogue DLL. Windows closes dynamic code-origin paths first through Arbitrary Code Guard (`ACG`, `ProcessDynamicCodePolicy`), which elevates `W^X` from a single-moment page permission into an *immutable process-lifetime invariant* [319, 320, 332, 333]. With `ProhibitDynamicCode` set, `VirtualAlloc(PAGE_EXECUTE_*)` and `VirtualProtect` transitions adding execute rights fail with `STATUS_DYNAMIC_CODE_BLOCKED`, and `NtMapViewOfSection(SECTION_MAP_EXECUTE)` succeeds only for signed file-backed images. Enabling `ACG` forced modern browsers (`Microsoft Edge` [332]) to move JavaScript `JIT` compilation into a separate out-of-process `JIT` server that maps read-execute compiled code sections back into the untrusted renderer.

![Figure: Arbitrary Code Guard rearchitected the browser into two trust zones. Before ACG, one renderer parses untrusted JavaScript and JITs native bytes into an RWX (write-then-execute) heap it then jumps into: a `W^X` violation living in the same process that touches attacker input. After ACG, the renderer runs with dynamic code prohibited (no `PAGE_EXECUTE_*` allocation, no `VirtualProtect` write→execute transition, signed sections only) and the JIT moves out of process; compiled code returns through a brokered shared-section mapping. ACG denies both halves of the old pattern: allocations that start executable, and permission transitions that later add execute.](diagrams/19-mitigations-acg-split.svg)

Complementing `ACG` on disk-backed modules, Code Integrity Guard (`CIG`, `ProcessSignaturePolicy`) invokes User-Mode Code Integrity (`UMCI`) inside `NtMapViewOfSection` to block mapping any DLL not chaining to Microsoft (`MicrosoftSignedOnly`), the Microsoft Store (`StoreSignedOnly`), or WHQL (`MitigationOptIn`), failing unapproved loads with `STATUS_INVALID_IMAGE_HASH` [332, 334]. To eliminate post-spawn initialization races, sandboxes apply both `ACG` and `CIG` atomically inside `CreateProcess` via `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY)` before the child's first user-mode instruction executes [335].

A surrounding ring of `PROCESS_MITIGATION_POLICY` flags severs the kernel-syscall, child-process, loader, and filesystem pivot surfaces that post-exploitation chains rely upon after gaining initial control [319, 320]. `ProcessSystemCallDisablePolicy` (`DisableWin32kSystemCalls`) blocks all `win32k.sys` (`NTUser` and `GDI`) syscalls from headless parsers and browser renderers, removing the largest historical Windows Ring 0 privilege-escalation surface [319, 326, 336], while `ProcessChildProcessPolicy` blocks `CreateProcess` from sandboxed workers so a compromised renderer cannot spawn `cmd.exe` or `powershell.exe` [319]. At the loader boundary, `ProcessExtensionPointDisablePolicy` and `ProcessImageLoadPolicy` disable legacy `AppInit_DLLs`, global `SetWindowsHookEx` hooks, and Winsock `LSPs`, block UNC (`NoRemoteImages`) and low-integrity (`NoLowMandatoryLabelImages`) DLLs, and enforce `PreferSystem32Images` against search-order hijacking [319, 337]. Rounding out the containment matrix, `ProcessRedirectionTrustPolicy` (`RedirectionGuard`, introduced in June 2025) blocks privileged processes from following NTFS junctions and mount points created by lower-privileged users [338, 339], operating alongside `ProcessFontDisablePolicy`, `ProcessStrictHandleCheckPolicy`, and `ProcessSideChannelIsolationPolicy` (`STIBP`, `IBPB`, `DisablePageCombine`, `SSBD`) [319].

![Figure: Process mitigation profile across five representative Windows workloads (Edge content renderer, Defender MsMpEng, lsass.exe, Outlook, and an unmodified legacy application) across seven core mitigation families. Edge content enables the full stack, while disabled or partial cells reflect concrete architectural constraints such as Defender's signature JIT blocking ACG, Outlook's COM/MAPI add-in model constraining ACG and CIG, and GUI workloads requiring win32k.sys syscalls.](diagrams/19-mitigations-policy-matrix.svg)

## Attack Catalog & Gap Analysis

The thirty-year interplay between Windows mitigations and offensive exploit development forms a strict evolutionary ladder: each mitigation extinguished one dominant primitive and forced adversaries onto narrower structural seams.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Counterfeit OOP (`COOP`, Schuster et al.) | 2015-present | Coarse-grained forward-edge `CFG` + balanced `CET` | Heap read/write + `ASLR` info leak in C++ target | Crafts counterfeit vtables pointing exclusively to legitimate, `CFG`-valid C++ virtual method entries; `CALL`/`RET` pairs stay balanced | Prototype-hashed CFI (`XFG` where supported) or hardware pointer authentication (`ARM PAC`) [320, 328, 340] |
| `JIT` Spray `CFG` Bypass (Theori / `MS16-119`) | 2016 | In-process `CFG` target bitmap integrity | Script execution in browser with in-process `JIT` | Coerces Chakra `JIT` into emitting controlled constant byte sequences inside pages whitelisted via `SetProcessValidCallTargets` | Enable `ACG` (`ProhibitDynamicCode`) and isolate `JIT` out-of-process [332, 341] |
| Post-Spawn `ACG` Race (Project Zero `#1437`) | 2017-2018 | Self-applied `SetProcessMitigationPolicy(ACG)` | Compromised peer renderer in same `AppContainer` | Races newly spawned `MicrosoftEdgeCP.exe` via `WriteProcessMemory` to flip internal flags before `SetProcessMitigationPolicy` executes | Apply mitigations in-kernel at spawn via `UpdateProcThreadAttribute` [335, 342] |
| Out-of-Process `JIT` Server Exploit (Fratric) | 2018 | Renderer-to-`JIT`-broker IPC boundary | Compromised `ACG`-enforced renderer process | Sends malformed bytecode/IPC requests to the remote `JIT` compiler process (which must run with `ACG` off to emit code) | Harden `JIT` IPC schema; eliminate dynamic `JIT` (`Super Duper Secure Mode` / V8 sandbox) [343, 344] |
| `NtSetContextThread` `RIP` Pivot | 2020-2021 | `CET` shadow-stack backward-edge enforcement | Arbitrary call or peer-thread handle access | Invokes `SetThreadContext` / `NtSetContextThread` to set `RIP` directly without executing a `RET` instruction | Enable `SetContextIpValidation` inside `ProcessUserShadowStackPolicy` [331] |
| `kCFG` / `kCET` Kernel Call Abuse (McGarr) | 2025 | Ring 0 control-flow integrity (`kCFG` + `kCET`) | Arbitrary `VTL0` kernel read/write primitive | Corrupts writable non-`KDP` kernel function pointers or cross-subsystem `Win32k`/`NT` valid `kCFG` targets | Enable `HVCI` + `KDP` ([Chapter 7](06-code-integrity.md)) and `DisableWin32kSystemCalls` in untrusted processes [234, 326] |
| Data-Oriented Programming (`DOP`, Hu et al.) | 2016-present | All control-flow mitigations (`CFG`, `XFG`, `CET`, `PAC`) | Memory read/write primitive in target process | Mutates non-control data (`is_admin` booleans, ACL pointers, buffer lengths, UIDs) while executing 100% unmodified control-flow paths | Migrate parsers to memory-safe languages (`Rust`) or hardware memory tagging (`MTE`) [345, 346] |

![Figure: The defender-to-attacker bypass ladder, read as gap analysis rather than an exploit recipe. Each rung names the primitive a mitigation removed ("closed by") and the residual class that survived to force the next mitigation: stack injection to DEP/NX; fixed-address code reuse to ASLR; return-oriented programming to CFG and CET; coarse forward-edge CFI to XFG-style type hashes and PAC; in-process JIT spray to ACG; loader-based code entry to CIG and image-load policy; post-start mitigation races to kernel-installed `UpdateProcThreadAttribute`. CET closes classical ROP on modern CPUs; kCFG and kCET in the kernel remain the live frontier. A mature threat model can say at every rung either "we closed this" or "we accept this residual."](diagrams/19-mitigations-bypass-ladder.svg)

### Coarse Forward Edges (`COOP`) and Kernel `kCFG`/`kCET` Seams

Demonstrated at IEEE S&P 2015 by Schuster et al. [340], Counterfeit Object-Oriented Programming (`COOP`) exposes the fundamental precision gap of `CFG`: because `ntdll!LdrpValidateUserCallTarget` checks a 1-bit-per-8-bytes table lacking call-site type context, *every* exported or address-taken function in `ntdll.dll`, `kernelbase.dll`, or the host application (`VirtualProtect`, `LoadLibraryA`, `RpcBindingFromStringBindingW`, or C++ virtual methods) has its bitmap bit set to `1`. By chaining whole virtual functions whose `CALL` and `RET` pairs execute normally, `COOP` satisfies both `CFG` on entry and `CET` shadow stacks on return. In Ring 0, Connor McGarr's Black Hat USA 2025 analysis of `kCFG` and `kCET` demonstrated analogous architectural pressure: while `HVCI` prevents `VTL0` writes to the `kCFG` bitmap itself, attackers holding a kernel read/write primitive target unprotected global function-pointer structures or valid cross-module `kCFG` targets [326].

### Startup Races and Trust-Boundary Relocation (`ACG` and `JIT` Brokers)

Project Zero's 2017-2018 audits of Microsoft Edge (`#1437`) proved two enduring lessons about mitigation deployment [335, 342, 343]. First, any mitigation enabled by user-mode code inside the child process after startup is subject to a `TOCTOU` window: a compromised sibling process in the same `AppContainer` opened the newly spawned child before `SetProcessMitigationPolicy` ran and patched two global bytes to skip `ACG` initialization, permanently solved only by passing `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` into `CreateProcess` so `ntoskrnl.exe` locks the flags prior to user-mode entry [335]. Second, when `ACG` pushed `JIT` compilation into an external process, Ivan Fratric demonstrated RCE by exploiting bugs in the `JIT` server itself, illustrating that splitting privileges relocates rather than deletes parser complexity [343].

## Theoretical Limits & Structural Invariants

### Control-Flow Integrity Cannot Detect Non-Control Data Attacks (`DOP`)

Abadi et al.'s foundational 2005 theorem bounds every CFI mechanism (`CFG`, `XFG`, `CET`, `PAC`) to enforcing paths inside the static Control-Flow Graph [318]. In 2016, Hu et al. proved that Data-Oriented Programming (`DOP`) (corrupting non-control variables such as privilege booleans, loop counters, SQL/command strings, or `EPROCESS.Token` pointers while letting the program's legitimate instructions run unmodified) is Turing-complete in real-world C applications [346]. Because neither indirect call targets nor return addresses are altered, `CFG` and `CET` never fire on pure data corruption.

### Decoupling Syntactic Target Validity from Semantic Intent

Proving that an indirect call lands on a legitimate function entry (`CFG`) or maps a Microsoft-signed DLL (`CIG`) does not prove the call or module load was authorized by program logic.

> **Key idea.**
> Exploit mitigations attack the *translation from memory bug to arbitrary instruction stream*, never the underlying memory-corruption bug itself. Calling `WinExec` or `LoadLibraryExW` with attacker-corrupted registers passes `CFG` (`bit = 1`), and loading a vulnerable Microsoft-signed DLL passes `CIG` (`MicrosoftSignedOnly`), leaving spatial/temporal memory safety (Rust adoption or hardware memory tagging such as `ARM MTE` [345]) as the only structural way to eliminate the root defect class.

## Inspecting and Verifying on a Running System

Operational verification evaluates active per-process flags on running sandboxes/services, system-wide Exploit Protection baselines, and PE binary compile/link flags (`CFG` and `CET`).

### Auditing Active Mitigations on a Running Process

Query the live mitigation flags enforced on high-exposure processes (such as `msedge` renderers or `lsass`) via the built-in `ProcessMitigations` module [347]:

```powershell
Get-ProcessMitigation -Name msedge | Select-Object ProcessName, Id,
    @{N='CFG';E={$_.CFG.Enable}}, @{N='CET';E={$_.UserShadowStack.UserShadowStack}},
    @{N='ACG';E={$_.DynamicCode.ProhibitDynamicCode}}, @{N='CIG';E={$_.BinarySignature.MicrosoftSignedOnly}}, @{N='NoWin32k';E={$_.SystemCall.DisableWin32kSystemCalls}}, @{N='NoChild';E={$_.ChildProcess.DisallowChildProcessCreation}}
```

Expected output across `msedge.exe` broker vs. sandboxed renderer processes:

```text
ProcessName   Id CFG CET  ACG   CIG NoWin32k NoChild
-----------   -- --- ---  ---   --- -------- -------
msedge      4120  ON  ON  OFF   OFF      OFF     OFF
msedge      7844  ON  ON   ON    ON       ON      ON
```

Notice the architectural split directly in live telemetry: PID `4120` (browser UI broker) draws windows (`NoWin32k = OFF`) and spawns workers (`NoChild = OFF`), whereas PID `7844` (untrusted content renderer) enforces the full six-mitigation lockdown (`CFG`, `CET`, `ACG`, `CIG`, `NoWin32k`, `NoChild` = `ON`) [332, 347].

### Inspecting System-Wide Windows Exploit Protection Defaults

Inspect the host-level baseline policies applied by Windows Defender Exploit Guard (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`) [347]:

```powershell
Get-ProcessMitigation -System | Format-List DEP, ASLR, CFG, SEHOP, Heap
```

Expected output format on a standard 64-bit Windows 11 installation:

```text
DEP   : Enable: ON, EmulateAtlThunks: OFF
ASLR  : BottomUp: ON, ForceRelocateImages: NOTSET, HighEntropy: NOTSET
CFG   : Enable: ON, SuppressExports: NOTSET
```

System-wide `ForceRelocateImages` or `StrictCFG` overrides should be staged via XML (`Set-ProcessMitigation -PolicyFilePath`) per application rather than toggled globally, avoiding crashes in legacy un-relocatable utilities [347].

### Verifying Binary `/guard:cf` and `/CETCOMPAT` PE Headers

Confirm without external SDK tools whether an executable or DLL on disk was compiled with `ASLR` (`0x0040`), `NX`/`DEP` (`0x0100`), and `CFG` (`0x4000`) in its PE `DllCharacteristics` header [16, 324, 330]:

```powershell
$b = [IO.File]::ReadAllBytes('C:\Windows\System32\lsass.exe')
$pe = [BitConverter]::ToInt32($b, 0x3C); $dc = [BitConverter]::ToUInt16($b, $pe + 0x5E)
[PSCustomObject]@{ DynamicBase = [bool]($dc -band 0x0040); NXCompat = [bool]($dc -band 0x0100); GuardCF = [bool]($dc -band 0x4000) }
```

Expected output on modern inbox Windows binaries:

```text
DynamicBase NXCompat GuardCF
----------- -------- -------
       True     True    True
```

When Visual Studio build tools are installed, running `dumpbin.exe /headers /loadconfig <binary>` additionally verifies `FID Table present` (`CFG`) and `CET compatible` (`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`) inside the extended load configuration directory [324, 330].

## Summary & Handoff

Process Mitigation Policies complete Part II (Kernel & Code) by hardening execution *inside* allowed binaries. Across three decades of offense and defense, Windows evolved from non-executable pages (`DEP`) and address randomization (`ASLR`) to coarse forward-edge bitmaps (`CFG` / `kCFG`), hardware-enforced backward-edge shadow stacks (`Intel CET` / `kCET`), process-lifetime `W^X` (`ACG`), signed-only DLL mapping (`CIG`), and targeted syscall/reparse gates (`DisableWin32k`, `RedirectionGuard`). Yet because control-flow integrity cannot see non-control data corruption (`DOP`) and `CIG` cannot judge the logic of signed modules, memory mitigations bound exploit mechanics rather than access authority.

Once code executes inside a process (legitimately or via an exploit), every operation it attempts against files, services, registry keys, or credentials is governed by Part III (Credentials & Access). That transition begins in [Windows Access Control, Integrity Levels, and Impersonation (Chapter 10)](25-access-control.md), which traces how the NT Security Reference Monitor constructs access tokens, enforces `DACLs` and Mandatory Integrity Control (`MIC` / `UIPI`), and exposes local service boundaries to `SeImpersonatePrivilege`. From local authorization, the identity stack ascends through isolating `LSASS` secrets inside `VTL1` ([Chapter 12](08-credential-guard.md)), retiring `NTLM` relay surfaces ([Chapter 13](09-ntlm.md)), hardening `Kerberos` tickets and `KRBTGT` ([Chapter 14](10-kerberos.md)), protecting cloud `Primary Refresh Tokens` ([Chapter 16](11-pth-prt.md)), and replacing shared secrets with hardware-bound `Passkeys` ([Chapter 17](12-hello.md)).
