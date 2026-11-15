# The Secure Kernel and VBS

## Overview

* **Role in the Chain:** Hardware-enforced runtime isolation substrate beneath the standard Windows operating system; uses the Microsoft Hyper-V hypervisor and Second-Level Address Translation (`SLAT`) to partition a single machine into an untrusted Normal World (`VTL0`) and an isolated Secure World (`VTL1`).
* **Core Security Invariant:** Guest-physical memory pages assigned to `VTL1` (`securekernel.exe`, Isolated User Mode trustlets, and VBS Enclaves) are unmapped or marked inaccessible in `VTL0`'s hypervisor-owned `SLAT` tables, preventing even `SYSTEM`-privileged ring-0 code in `ntoskrnl.exe` from reading, modifying, or executing `VTL1` state directly.
* **Trusted Computing Base (TCB):** The Hyper-V hypervisor (`hvix64.exe` / `hvax64.exe`), `securekernel.exe` and `skci.dll` in `VTL1` ring 0, five-gate admitted `IUM` trustlets in `VTL1` ring 3, IOMMU/SMM hardware protections, and the anti-rollback servicing policies governing which signed VBS binaries may load.
* **Primary Failure Modes:** Memory corruption or MDL validation bugs in the `VTL0`-to-`VTL1` secure-call interface (`CVE-2020-0917`, `CVE-2020-0918`) or hypercall ABI (`CVE-2024-21407`), root-partition VSP bugs (`CVE-2021-28476`), update-pipeline downgrades to older signed VBS builds (`Windows Downdate`, `CVE-2024-21302`), `VTL0` broker oracle abuse (`Pass-the-Challenge`), and opaque enclave misuse (`BYOVE`).
* **Handoff:** Establishes the tamper-resistant `VTL1` execution and page-permission floor consumed by Code Integrity and HVCI ([Chapter 7](06-code-integrity.md)), Credential Guard ([Chapter 12](08-credential-guard.md)), and Windows Hello Enhanced Sign-in Security ([Chapter 17](12-hello.md)), while leaving guest-versus-cloud-host isolation to Confidential VMs ([Chapter 22](29-confidential-vms.md)).

## Core Engineering Problem & Threat Model

From Windows NT 3.1 (1993) through Windows 8.1, the Windows security architecture rested on a single hardware privilege boundary: user mode (Ring 3) versus kernel mode (Ring 0) [157]. The Security Reference Monitor (`SRM`), process tokens, and Protected Process Light (`PPL`) all executed inside `ntoskrnl.exe` under the implicit assumption that all Ring 0 code was equally trustworthy. In practice, Direct Kernel Object Manipulation (`DKOM`) rootkits [158], kernel pool exploits, and Bring Your Own Vulnerable Driver (`BYOVD`) attacks [159] routinely granted adversaries arbitrary Ring 0 read/write primitives.

Microsoft's initial response, Kernel Patch Protection (`PatchGuard`, introduced on x64 Windows in 2005) [160], ran into an irreducible architectural ceiling: the Same-Privilege Paradox. Because `PatchGuard`'s timer DPCs, obfuscated context blocks, and `KeBugCheckEx` routines reside inside the exact same Ring 0 virtual address space as an attacker's kernel driver, any defense reachable by a Ring 0 `mov` instruction can be located and neutralized by a Ring 0 `mov` instruction [161, 162]. Likewise, Secure Boot ([Chapter 1](16-secure-boot.md)) and Measured Boot ([Chapter 4](03-measured-boot.md)) guarantee only that the kernel *started* from signed binaries, not that `ntoskrnl.exe` remains uncompromised at runtime.

To defend critical OS secrets and code-integrity verdicts against a compromised Ring 0 kernel without rewriting the Win32 ecosystem on a tiny separation microkernel [163, 164], Microsoft repurposed its Type-1 Hyper-V hypervisor (`Windows Server 2008` [165, 166]). Using x86 hardware virtualization (`Intel VT-x` VMX root operation and `AMD-V` SVM host mode [167, 168]) combined with Second-Level Address Translation (`SLAT`), David Hepkin and Arun Kishan formalized Virtual Secure Mode (`VSM`) and hierarchical Virtual Trust Levels (`VTLs`) in 2013 [169], shipping Virtualization-Based Security (`VBS`) in Windows 10 build 10240 (July 2015) [170, 171, 172].

The VBS threat model assumes an adversary has already achieved full `SYSTEM` and arbitrary Ring 0 code execution inside the standard Windows kernel (`VTL0`), or controls a child guest virtual machine attempting to escape to the host. Microsoft defines both `VTL0 → VTL1` and `L1 guest → host/guest` as serviced security boundaries [173, 174]. Conversely, VBS explicitly excludes denial of service (`VTL0` starving `VTL1` scheduling), unmediated physical attacks where IOMMU/Secure Boot preconditions are disabled, and authorized protocol use brokered through `VTL0` agents [170, 173, 175].

## Architectural Deep Dive

### The Micro-Kernelized Hypervisor and Its Five Primitives

When VBS or Hyper-V is enabled, `hvloader.efi` launches the platform hypervisor binary (`hvix64.exe` on Intel VT-x; `hvax64.exe` on AMD-V) *before* `ntoskrnl.exe` initializes [176]. The hypervisor claims VMX root / SVM host mode, takes ownership of the system IOMMU, and places the main Windows operating system inside the *root partition*. Unlike monolithic VMMs that embed massive device-driver stacks inside the hypervisor, Hyper-V follows a micro-kernelized split (`diagrams/07-hypervisor-hyperv-stack.svg`) [165].

![Figure: The layered 2008 Hyper-V stack. The micro-kernel hypervisor owns only CPU virtualization, scheduling, and the second-level page tables, while the root partition (a full Windows install) runs the VSPs, vmswitch.sys, and vmwp.exe and a child partition reaches its VSCs over the VMBus. A child network packet crosses four trust domains: guest NDIS and the NIC VSC, then VMBus/SynIC, then the root VSP and vmswitch.sys, then the physical NIC driver: the division that kept the hypervisor's Trusted Computing Base small and is the design fact behind the later CVE record.](diagrams/07-hypervisor-hyperv-stack.svg)

As specified in the Hyper-V Top-Level Functional Specification (`TLFS`) [171, 176], every VBS and virtualization guarantee is constructed from five hypervisor primitives. Logical isolation begins with *partitions* and the *VSP/VSC split*: physical hardware drivers, VM Worker Processes (`vmwp.exe`), and Virtualization Service Providers (`VSPs`, such as `vmswitch.sys`) execute inside the root partition rather than inside `hvix64.exe` or `hvax64.exe`, communicating with child-partition Virtualization Service Clients (`VSCs`) over shared-memory `VMBus` ring buffers [165]. Whenever a partition requests hypervisor operations explicitly, it invokes the *hypercall ABI* via `vmcall` on Intel or `vmmcall` on AMD; on x64, `rcx` carries a 64-bit control word encoding a 16-bit call code, a Fast flag, variable header sizes, and repetition counts, with *fast* hypercalls passing arguments directly in registers (`rdx`, `r8`) and *slow* hypercalls passing Guest Physical Addresses (`GPAs`) of input and output parameter pages [176].

Complementing explicit hypercalls, the hypervisor enforces mandatory boundaries and cross-domain signaling through hardware traps, synthetic interrupts, and two-stage paging. Through *intercepts*, Hyper-V configures Intel `VMCS` or AMD `VMCB` control fields to trigger `VM-EXIT` traps on sensitive guest events, including instruction intercepts (`CPUID`, MSR writes, and control-register pinning), exception intercepts, and memory-access (`EPT`/`NPT`) faults [176]. For asynchronous notification, each virtual processor exposes a *Synthetic Interrupt Controller* (`SynIC`) providing 16 Synthetic Interrupt Source (`SINT`) lines, a message page, an event-flag page, and synthetic timers that power both cross-partition `VMBus` signaling and intra-partition `VTL0 ↔ VTL1` transitions [176]. Beneath all four mechanisms sits *per-VTL Second-Level Address Translation* (`SLAT`): under Intel Extended Page Tables (`EPT`) or AMD Nested Page Tables (`NPT`), the guest OS translates a Guest Virtual Address (`GVA`) to a `GPA`, and the CPU's hardware page-table walker then translates that `GPA` to a System Physical Address (`SPA`) using hypervisor-owned `SLAT` tables that no guest kernel can map or edit [176].

### Virtual Trust Levels (`VTL0` vs. `VTL1`) and the Secure Kernel

Rather than spinning up a separate heavyweight virtual machine to hold OS secrets, VBS partitions *a single partition* vertically into hierarchical Virtual Trust Levels (`VTLs`) [169, 171]. Although the `TLFS` architecture reserves 4 bits for up to 16 levels, production Windows implements `#define HV_NUM_VTLS 2` [171]. The lower level, `VTL0` (the *Normal World*), hosts `ntoskrnl.exe` in Ring 0 alongside device drivers, file systems, the network stack, `lsass.exe`, system services, and all standard Win32 and UWP applications in Ring 3 [177]. Above it, `VTL1` (the *Secure World*) hosts the minimal Secure Kernel (`securekernel.exe` and `skci.dll` in `VTL1` Ring 0) together with Isolated User Mode (`IUM`) trustlets and enclaves in `VTL1` Ring 3 (`diagrams/05-secure-kernel-vtl-architecture.svg`) [177, 178, 179].

![Figure: The VTL stack. The Hyper-V hypervisor owns SLAT at the base, and VTL1 (securekernel.exe plus the IUM trustlets lsaiso.exe and VBS enclaves) sits beside VTL0 (ntoskrnl.exe, lsass.exe, drivers, and any Ring 0 malware); SLAT denies VTL0 any mapping of VTL1 pages, so the only VTL0→VTL1 crossing is the Secure Service Call.](diagrams/05-secure-kernel-vtl-architecture.svg)

Isolation between `VTL0` and `VTL1` is enforced asymmetrically in hardware via per-VTL SLAT trees (`diagrams/07-hypervisor-slat-double-walk.svg`):

![Figure: The per-VTL SLAT double walk for one guest-physical page G. The first walk through the guest's own page tables (virtual address to guest-physical) succeeds for both a VTL0 kernel load and a VTL1 access (VTL0 can even forge a PTE to G) but the decisive second walk is the hypervisor-owned SLAT: VTL0's tree omits G, so the CPU raises an EPT/NPT violation before the load retires, while VTL1's tree maps G read-only to the one real frame. Same guest-physical address, two second translations, two authorities.](diagrams/07-hypervisor-slat-double-walk.svg)

Suppose `LsaIso.exe` in `VTL1` stores an NTLM hash at guest-physical frame `G`. Even if an attacker compromises `ntoskrnl.exe` in `VTL0` and crafts a valid Ring 0 Page Table Entry (`PTE`) mapping a kernel virtual address to `G`, the CPU's second-level walk consults the active `VTL0` SLAT tree, where `G` carries no read/write/execute permissions. The load faults in silicon (`EPT`/`NPT` violation) before retiring a single byte [176, 177]. Conversely, when the virtual processor transitions to `VTL1` (saving `VTL0` registers, switching the active SLAT root pointer, and entering `securekernel.exe`), the `VTL1` SLAT tree maps both `VTL1`-private pages and shared `VTL0` request buffers, allowing `VTL1` to inspect `VTL0` without `VTL0` ever inspecting `VTL1` [171].

Beyond protecting `VTL1` memory, the hypervisor and Secure Kernel harden `VTL0` Ring 0 invariants via HyperGuard (`SkpgContext` for `VTL1`): pinning sensitive CPU control registers (`CR0.WP`, `CR4.SMEP`, `CR4.SMAP`), MSRs (`IA32_LSTAR` syscall entry), and critical descriptor tables via hypervisor intercepts so Ring 0 rootkits cannot disable supervisor protections or redirect system-call MSRs [175, 176].

### Isolated User Mode (`IUM`) Trustlets and the Five Load-Time Gates

User-mode processes inside `VTL1` Ring 3 are termed trustlets (`IUM` processes) [178, 179]. Because `VTL1` user mode sits inside the platform TCB, third-party developers cannot ship inbox trustlets. As reverse-engineered by Alex Ionescu [178] and documented in *Windows Internals* [180], a PE binary becomes a running trustlet only by passing five cumulative admission gates (`diagrams/17-vbs-trustlets-five-gates.svg`):

![Figure: The five load-time gates that turn a binary into a trustlet (process attribute, signing EKUs at Level 12, `.tpolicy` metadata, Instance GUID, and the stripped-down IUM loader) each shown with its distinct failure outcome.](diagrams/17-vbs-trustlets-five-gates.svg)

1. **Secure-Process Creation Attribute (`PsAttributeSecureProcess`):** Ordinary Win32 `CreateProcess` cannot spawn a trustlet; kernel/broker code must invoke `NtCreateUserProcess` carrying `PsAttributeSecureProcess` with a 64-bit requested `Trustlet ID` [178].
2. **Dual-EKU Signing at Level 12 (`ci.dll` / `skci.dll`):** Evaluated in `VTL1`, the image signature must achieve Signing Level $\ge 12$ (`Windows`) and carry *both* the Windows System Component Verification EKU (`1.3.6.1.4.1.311.10.3.6`) and the Isolated User Mode EKU (`1.3.6.1.4.1.311.10.3.37`) [178, 181].
3. **Embedded `.tpolicy` Metadata (`SkpspFindPolicy`):** The signed PE image must contain a read-only `.tpolicy` section exporting `s_IumPolicyMetadata` (version `1`, embedded 64-bit `Trustlet ID` matching Gate 1's request, and static policy rules governing ETW, crash-dump encryption, and debuggability) [178].
4. **Runtime `Trustlet Instance GUID` Binding (`IumSetTrustletInstance`):** After start, the trustlet invokes secure call `0x80000001` (`IumSetTrustletInstance`) to bind an instance GUID (for example, a specific Hyper-V VM's partition GUID). Secure-storage capabilities in `SkCapabilities` authorize access across the tuple `(operation, caller Trustlet ID, Instance GUID)` [178].
5. **Stripped-Down `IUM` Loader (`LdrpIsSecureProcess`) and Syscall Filter:** Inside `ntdll.dll`, `LdrpIsSecureProcess` disables `VTL0` injection vectors (skipping Image File Execution Options (`IFEO`), Application Verifier, Side-by-Side (`SxS`) redirection, `CSRSS` startup connections, and `VTL0`-initiated DLL loads) while restricting the process to a minimal `securekernel.exe` system-call subset (approximately 48 syscalls rather than the full ~450+ NT syscall table) [178, 179]. Standard `VTL0` introspection APIs (`ReadProcessMemory`, `WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`) fail architecturally against trustlet handles [179].

### The Agent/Trustlet Broker Pattern, Inbox Roster, and VBS Enclaves

Because `VTL1` contains no network stack, filesystem, or GUI, almost every trustlet pairs with an untrusted `VTL0` agent process over an Advanced Local Procedure Call (`ALPC`) channel (`diagrams/17-vbs-trustlets-agent-trustlet-split.svg`) [182]:

![Figure: The canonical agent/trustlet split. The VTL0 agent (lsass.exe) keeps the protocol, session, and network state while the VTL1 trustlet (LsaIso.exe) holds the secret; only the request and response cross the LSA_ISO_RPC_SERVER ALPC channel the Secure Kernel marshals.](diagrams/17-vbs-trustlets-agent-trustlet-split.svg)

`VTL0` writes structured request parameters into shared memory and invokes the `SynIC`-backed secure-call gate (`securekernel!IumInvokeSecureService`), marshaling the request into `VTL1` and returning computed outputs without exposing raw keys [175, 178, 182]. Across shipping Windows releases, VBS isolates three tiers of workloads:

| Workload Tier | Identifier / Binary | `VTL0` Broker / Host | Protected Asset or Authority |
|---|---|---|---|
| Confirmed Inbox Trustlet | `Trustlet ID 0` (Secure Kernel process) | Internal (`ntoskrnl` / `ci.dll`) | Kernel Code Integrity (`HVCI`) and `SiPolicy` verification verdicts ([Chapter 7](06-code-integrity.md)) [178, 183] |
| Confirmed Inbox Trustlet | `Trustlet ID 1` (`LsaIso.exe`) | `lsass.exe` (`\RPC Control\LSA_ISO_RPC_SERVER`) | Credential Guard NTLM hashes, Kerberos TGTs/keys, Key Guard secrets ([Chapter 12](08-credential-guard.md)) [178, 182] |
| Confirmed Inbox Trustlet | `Trustlet ID 2` (`vmsp.exe`) & `ID 3` (Provisioning) | `vmwp.exe` (scoped by VM Partition GUID) | Host-side Hyper-V Shielded VM / Trusted Launch `vTPM` state (`Get` = ID 2, `Set` = ID 3) [178, 184] |
| VBS-Isolated Subsystem | Enhanced Sign-in Security (`ESS`) & System Guard | Biometric / attestation brokers (unpublished IDs) | Isolated face-matching memory/camera pipe ([Chapter 17](12-hello.md)) [185] and runtime health reports [128] |
| Third-Party VBS Enclave | Signed Enclave DLL (no Trustlet ID) | Host Win32 process (`CreateEnclave` / `CallEnclave`) | Application-specific secrets (e.g., SQL Server Always Encrypted) inside `VTL1`-backed VA regions [186, 187] |

Opened broadly to third-party developers on Windows 11 24H2 (build 26100.2314+) and Windows Server 2025, VBS Enclaves load a Trusted-Signing-certified DLL built with Enclave Definition Language (`EDL`) stubs and bound via `veiid.exe` into an isolated `VTL1` address range inside an ordinary host process [186, 187, 188]. Unlike inbox trustlets, enclaves execute as passive library call targets (`CallEnclave`) rather than standalone scheduled processes.

## Attack Catalog & Gap Analysis

Public compromises across the Hyper-V and VBS boundary cluster cleanly into five structural seams: root-partition device emulation, hypercall lifetime/input parsers, the `IumInvokeSecureService` marshaling boundary, `VTL0` update-pipeline downgrades, and agent/enclave operational abuse.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Secure-Call Bugs (`Hyperseed`: CVE-2020-0917, CVE-2020-0918) | 2020 | `VTL0` Ring 0 → `VTL1` `securekernel.exe` isolation | `VTL0` kernel execution invoking `IumInvokeSecureService` | Triggers OOB write in `SkmmObtainHotPatchUndoTable` (`0917`) or passes crafted MDL to `SkmmUnmapMdl` / `SkmiReleaseUnknownPTEs` (`0918`) | Apply 2020 patches; Secure Kernel segment heap, `W^X` cleanup, and `SkpgContext` hardening [175, 189, 190] |
| Root-Partition VSP Bugs (CVE-2021-28476, CVE-2025-21333) | 2021, 2025 | Child VM → Host (`vmswitch.sys`) & Sandbox → `SYSTEM` (`vkrnlintvsp.sys`) | Guest NIC access (`28476`) or local sandbox execution (`21333`, CISA KEV) | Sends crafted `OID_SWITCH_NIC_REQUEST` dereferencing host pointer (`28476`) or heap overflow in NT Kernel Integration VSP (`21333`) | Patch root-partition `VSP` drivers; isolate management plane [191, 192] |
| Pass-the-Challenge (`lsass` RPC Oracle) | 2022 | Operational misuse of `LsaIso.exe`-protected NTLM credentials | `SYSTEM` access in `VTL0` (`lsass.exe` memory/RPC control) | Uses `lsass.exe` → `LSA_ISO_RPC_SERVER` channel as a signing oracle to compute valid NetNTLMv2 challenge responses without reading the raw hash | Disable/restrict NTLM ([Chapter 13](09-ntlm.md)) and enforce Credential Guard + Kerberos policies ([Chapter 12](08-credential-guard.md)) [182, 193, 194] |
| Hypercall ABI Bugs (CVE-2024-21407, CVE-2024-30092, CVE-2024-49117) | 2024 | Guest / `VTL0` → `hvix64.exe` / `hvax64.exe` hypervisor core | Ability to issue crafted `vmcall`/`vmmcall` sequences | Exploits hypervisor object use-after-free (`21407`), untrusted control-sphere dispatch (`30092`), or wrong status-code state machines (`49117`) | Apply cumulative hypervisor updates; enforce strict hypercall copy-and-pin lifetime invariants [195, 196, 197] |
| Windows Downdate (CVE-2024-21302) | 2024 | Version freshness of `securekernel.exe`, `ci.dll`, and `hvix64.exe` | Local `Administrator` manipulating Windows Update staging | Hijacks update servicing to downgrade VBS binaries to older, Microsoft-signed vulnerable revisions while OS telemetry reports fully patched | Deploy KB5042562 UEFI-locked `SkuSiPolicy.p7b` VBS anti-rollback revocations and `dbx` updates [198, 199, 200, 201] |
| BYOVE / Mirage (VBS Enclave Abuse) | 2025 | Defensive visibility of `VTL0` EDR over malicious `VTL1` code | Ability to load a signed vulnerable or attacker-signed VBS Enclave DLL | Executes malicious logic inside `VTL1` enclave memory where `VTL0` kernel/EDR scanners are architecturally blocked by `SLAT` from inspecting | Enforce strict `WDAC` / Trusted Signing enclave admission and MSRC copy-before-check enclave rules [186, 188, 202] |

### Crossing Parsers: VSPs, Hypercalls, and `IumInvokeSecureService`

Empirical CVE history validates Hyper-V's micro-kernelized split while pinpointing where isolation breaks: wherever higher-privileged code parses complex, untrusted structures from a lower trust level. In multi-tenant virtualization, root-partition `VSP` drivers expose the widest parser surface, exemplified by `CVE-2021-28476` (`CVSS 9.9` arbitrary pointer dereference in `vmswitch.sys` found via `hAFL1` fuzzing [191]) and `CVE-2025-21333` (an in-the-wild heap overflow in `vkrnlintvsp.sys` [192]). Inside the hypervisor binary itself (`hvix64.exe`/`hvax64.exe`), bugs concentrate in the `vmcall` dispatcher (`CVE-2024-21407` use-after-free [195], `CVE-2024-30092` [196], and `CVE-2024-49117` status-lifetime mismatch [197]), where handlers must copy guest GPA descriptors once and bind object reference counts across asynchronous retries.

Across the intra-partition `VTL0 → VTL1` boundary, Saar Amar and Daniel King demonstrated at Black Hat USA 2020 that retargeting MSRC's `Hyperseed` fuzzer at `securekernel!IumInvokeSecureService` uncovered five `VTL0`-to-`VTL1` vulnerabilities in two weeks (ten total with manual review) [175, 203]. Notably, `CVE-2020-0917` triggered an out-of-bounds write inside `securekernel!SkmmObtainHotPatchUndoTable`, while `CVE-2020-0918` allowed a compromised `VTL0` kernel to pass a forged Memory Descriptor List (`MDL`) to `SkmmUnmapMdl` (`SkmiReleaseUnknownPTEs`) [175, 189, 190]. In response, Microsoft migrated the Secure Kernel pool to the hardened segment heap, eliminated `W+X` pages inside `VTL1`, and introduced `SkpgContext` integrity verification [175].

### Versioned-Trust Failure: Windows Downdate (CVE-2024-21302)

At Black Hat USA 2024, Alon Leviev (SafeBreach Labs) demonstrated *Windows Downdate* (`CVE-2024-21302`), proving that spatial SLAT isolation collapses if an attacker controls *temporal binary version selection* [199, 200, 201]. Using local administrative privileges to craft custom Component-Based Servicing (`CBS`) / Windows Update actions, `Windows Downdate` replaced patched `hvix64.exe`, `securekernel.exe`, `ci.dll`, and `LsaIso.exe` binaries with older, legitimately Microsoft-signed builds containing known vulnerabilities (`CVE-2020-0917` class), while keeping user-facing OS build numbers current. Because UEFI Secure Boot and Gate 2 EKU checks verified only *signature validity* rather than *minimum version freshness*, `VTL1` booted obsolete code cleanly and neutralized its own patches. Microsoft addressed the gap via `KB5042562` and subsequent 2025 servicing waves, shipping UEFI-variable-locked `SkuSiPolicy.p7b` policies that revoke outdated VBS component Security Version Numbers [198, 200].

### Oracle Abuse (`Pass-the-Challenge`) and Defensive Blindness (`BYOVE`)

Two non-memory-corruption classes illustrate the structural dual edges of `VTL1` when hardware isolation interacts with `VTL0` brokers and defensive telemetry. The first is broker oracle abuse (`Pass-the-Challenge`), disclosed by Oliver Lyak in 2022 [193, 194]: an attacker with `SYSTEM` privileges in `VTL0` cannot read `LsaIso.exe` memory directly, *but* can inject into `lsass.exe` or invoke `\RPC Control\LSA_ISO_RPC_SERVER` to submit attacker-chosen NTLM challenges to `LsaIso.exe` ([Chapter 12](08-credential-guard.md)). Because the request arrives over the authorized broker channel, `LsaIso.exe` faithfully computes and returns valid challenge responses without ever leaking the underlying NTLM hash.

The converse edge is offensive enclave hiding (`BYOVE` / `Mirage`), demonstrated at DEF CON 33 in August 2025 by Akamai researchers [202]. The exact same per-VTL `SLAT` opacity that shields SQL Server encryption keys from a compromised kernel also shields attacker shellcode from `VTL0` Endpoint Detection and Response (`EDR`) scanners whenever an adversary loads a vulnerable or attacker-signed VBS Enclave DLL (*Bring Your Own Vulnerable Enclave*). Closing that blind spot requires pairing `SLAT` isolation with strict `WDAC` enclave publisher rules and MSRC's host-pointer copy-before-check discipline [188, 202].

## Theoretical Limits & Structural Invariants

### Placement, Mediation, and Excluded Liveness

VBS enforces a selective confidentiality and integrity invariant rather than whole-system immunity. First, protection requires explicit placement into `VTL1`: assets left in `VTL0`, including browser session cookies, cleartext `WDigest` or CredSSP passwords typed post-compromise, Kerberos service tickets in normal caches, and application memory outside enclaves, receive zero protection from the Secure Kernel ([Chapter 12](08-credential-guard.md), [Chapter 16](11-pth-prt.md)) [182]. Second, VBS provides no liveness guarantee: because `VTL0` schedules ordinary workloads and brokers `ALPC` traffic, a compromised `VTL0` kernel can starve, hang, or refuse to invoke `VTL1` at any time (`"VTL0 can DOS VTL1 by design"` [175]).

### Decoupling Secret Isolation from Capability Authorization

Consistent with Law 16, hardware memory isolation (`SLAT`) must be decoupled from operational capability authorization (`RPC` / `CallEnclave`) and version freshness.

> **Key idea.**
> Placing a key or policy engine inside `VTL1` prevents a compromised `ntoskrnl.exe` from *extracting* the secret or *overwriting* the code. It does not prevent `VTL0` from exercising whatever legitimate API `VTL1` exposes (`Pass-the-Challenge`), nor does signature verification alone prevent an administrator from booting yesterday's buggy `securekernel.exe` (`Windows Downdate`) unless paired with anti-rollback `SiPolicy` version floors [193, 198, 200].

### Beneath, Beside, and Across Shared Silicon

As mapped in Hyper-V's residual boundary geometry, `hvix64.exe` and `securekernel.exe` depend on three hardware and platform co-anchors outside `SLAT` itself. Below the hypervisor in `Ring -2`, unconstrained System Management Mode (`SMM`) handlers can overwrite hypervisor DRAM unless the platform boots via System Guard Secure Launch (`DRTM` `PCR[17..22]`) with `SMM Supervisor` or `STM` page-table sandboxing ([Chapter 4](03-measured-boot.md)) [128, 137]. Beside the CPU on the PCIe fabric, external Thunderbolt, USB4, and PCIe bus masters bypass CPU `MMU` and `SLAT` walks entirely unless Kernel DMA Protection programs the system `IOMMU` (`Intel VT-d` or `AMD-Vi`) to block unauthenticated hot-plug DMA and restrict device drivers to explicit remapped buffers [111, 170, 204].

Across shared core microarchitecture, because `VTL0` and `VTL1` time-share physical cores, `L1D` caches, branch predictors, and Simultaneous Multithreading (`SMT`) pipelines, transient-execution leaks (`Spectre`, `L1TF`, `MDS`) require microcode barriers (`IBRS`, `STIBP`), `Retpoline`, and Hyper-V `HyperClear` core-scheduling and `L1D` flushing rather than page tables alone [205, 206]. This microarchitectural reality explains why client Windows favored hypervisor-backed `VTL1` over `Intel SGX` user-mode enclaves [756]: `SGX` excluded the OS and hypervisor from a small encrypted `EPC` region, yet repeatedly leaked attestation keys to unprivileged co-resident threads via transient-execution attacks (`Foreshadow`, `SgxPectre`, `SGAxe` [754, 755, 757]), leading Intel to deprecate client `SGX` while Windows scaled `VBS` across `LsaIso.exe` (`Trustlet ID 1`), `vmsp.exe` (`Trustlet ID 2` host `vTPM`), `BioIso.exe` (`ESS` biometrics), `KeyIso`, and `VBS Enclaves`. Unlike formally verified ~8,700-line microkernels (`seL4` [164, 207]), Hyper-V plus `securekernel.exe` spans hundreds of thousands of lines whose assurance rests on narrow interfaces, continuous fuzzing, and active servicing.

## Inspecting and Verifying on a Running System

Verifying VBS requires distinguishing *policy intent* (`Configured`) from *enforced runtime reality* (`Running`), confirming boot loader hypervisor flags, and checking active `IUM` trustlet processes.

### Auditing VBS Status, Hardware Capabilities, and Running Services

Query the `Win32_DeviceGuard` CIM provider to verify that VBS is actively running (`Status = 2`) alongside hardware prerequisites and `VTL1` services (elevated PowerShell) [170, 182, 183]:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, RequiredSecurityProperties,
        AvailableSecurityProperties, SecurityServicesConfigured, SecurityServicesRunning
```

Expected output on a Secured-core Windows 11 endpoint:

```text
VirtualizationBasedSecurityStatus : 2
RequiredSecurityProperties        : {1, 2, 3}
AvailableSecurityProperties       : {1, 2, 3, 5, 6, 7}
SecurityServicesConfigured        : {1, 2, 3}
SecurityServicesRunning           : {1, 2, 3}
```

Key enum mappings [170, 183]: `VirtualizationBasedSecurityStatus = 2` confirms VBS is *enabled and running* (`1` means enabled in policy but failed to start, often due to disabled firmware VT-x/AMD-V or an incompatible driver). In `AvailableSecurityProperties`, `1` = Hypervisor support, `2` = Secure Boot, `3` = DMA protection (`IOMMU`), `6` = SMM mitigations, and `7` = Mode-Based Execution Control (`MBEC`/`GMET`, [Chapter 7](06-code-integrity.md)). In `SecurityServicesRunning`, `1` = Credential Guard, `2` = Memory Integrity (`HVCI`), and `3` = System Guard Secure Launch.

### Checking Boot Hypervisor Launch Policy and Opt-Out Flags

Verify in the active Boot Configuration Data (`BCD`) store that the hypervisor is set to `Auto` and no boot `loadoptions` (`DISABLE-VBS` or `DISABLE-LSA-ISO`) suppress `VTL1` bring-up (elevated PowerShell) [170]:

```powershell
bcdedit /enum '{current}' | Select-String 'hypervisorlaunchtype|vsmlaunchtype|loadoptions'
```

Expected output on an enforcing host:

```text
hypervisorlaunchtype    Auto
```

If `hypervisorlaunchtype` is `Off` or `loadoptions` contains `DISABLE-VBS`, `hvloader.efi` skips launching `hvix64.exe`/`hvax64.exe` and `VTL1` never initializes regardless of registry policy.

### Verifying the Agent/Trustlet Split (`lsass.exe` and `LsaIso.exe`)

Confirm that the `VTL1` Isolated LSA trustlet (`LsaIso.exe`, `Trustlet ID 1`) is running alongside its `VTL0` broker (`lsass.exe`) [179, 182]:

```powershell
Get-Process -Name lsass, LsaIso -ErrorAction SilentlyContinue |
    Select-Object Name, Id, SessionId
```

Expected output when Credential Guard or Key Guard is active in `VTL1`:

```text
Name     Id SessionId
----     -- ---------
LsaIso  612         0
lsass   824         0
```

Although `LsaIso` appears in the kernel process table (`EPROCESS` with `IsSecureProcess` set), its user-mode pages are backed exclusively by `VTL1` `SLAT` mappings; any `VTL0` attempt to invoke `ReadProcessMemory` or create a memory dump of `LsaIso` fails at the hardware translation boundary [177, 179].

## Summary & Handoff

Virtualization-Based Security and the Secure Kernel represent the most consequential privilege-architecture shift in Windows since the 1993 NT kernel. By placing `hvix64.exe`/`hvax64.exe` beneath `ntoskrnl.exe` and enforcing asymmetric per-VTL `SLAT` trees inside a single partition, Windows broke the thirty-year rule that Ring 0 compromise exposes every secret and rewrites every security policy on the box. Through five strict admission gates, `VTL1` Isolated User Mode (`IUM`) trustlets and modern third-party VBS Enclaves keep high-value keys and integrity decisions out of `VTL0`'s reach, bounded by secure-call parser hygiene, anti-rollback `SiPolicy` enforcement (`KB5042562`), and `VTL0` broker semantics.

Every remaining defense in Part II (Kernel & Code) and Part III (Credentials & Access) builds directly on or alongside this `VTL0`/`VTL1` split. At the code-execution floor, [Code Integrity and Application Control (Chapter 7)](06-code-integrity.md) consumes `VTL1` (`skci.dll` plus `SLAT` `W^X` and `MBEC`) to govern Authenticode, catalogs, `HVCI`, `WDAC`, and vulnerable-driver blocklists. Within `VTL0` itself, [Protected Process Light (Chapter 8)](18-ppl.md) and [Process Mitigation Policies (Chapter 9)](19-mitigations.md) harden services and application address spaces through cryptographic signer lattices (`RunAsPPL`) and hardware exploit mitigations (`CFG`, `XFG`, and `CET` shadow stacks). Moving up into identity custody, [Credential Guard and LSASS Isolation (Chapter 12)](08-credential-guard.md) examines how `lsass.exe` and `LsaIso.exe` partition NTLM, Kerberos, and DPAPI secrets across `VTL0` and `VTL1` and where `Pass-the-Challenge` still operates, while [Confidential VMs (Chapter 22)](29-confidential-vms.md) inverts the hypervisor trust direction through AMD SEV-SNP and Intel TDX to protect guest Windows VMs when the *cloud host hypervisor itself* is untrusted.
