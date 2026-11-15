# Foundations

Every chapter in this volume builds upon five architectural substrates shared across Apple Silicon hardware and the `Darwin` operating-system family: the heterogeneous system-on-chip (`SoC`) fabric and its hardware DMA translation units, the orthogonal split between standard `ARM64` Exception Levels and Apple's proprietary Guarded Execution Facility (`GXF`), the hybrid `XNU` kernel uniting `Mach` object capabilities with `BSD` POSIX semantics under the `Mandatory Access Control Framework` (`MACF`), the cryptographic algorithms and `ASN.1` `DER` `Image4` container grammar that authenticate firmware and OS state, and a four-tier adversary taxonomy that separates local physical custody from mercenary zero-click exploitation and sovereign cloud compulsion [1, 67]. Establishing these five substrates at register and data-structure fidelity once allows subsequent chapters to analyze silicon monitors, trust caches, keybags, and cloud transparency protocols without repetitive introductory scaffolding.

## The Apple Silicon SoC Fabric, AppleDART, and Co-Processor Isolation

Unlike modular x86 motherboards that wire a discrete CPU package to an external Platform Controller Hub (`PCH`), socketed SPI flash chip, and discrete `TPM` across exposed circuit-board traces, an Apple Silicon `SoC` (`A`-series on `iPhone` and `iPad`, `M`-series on `Mac`, `iPad Pro`, `Vision Pro`, and Private Cloud Compute blades, and `S`-series on `Apple Watch`) integrates heterogeneous CPU clusters, cryptographic enclaves, neural accelerators, storage controllers, and PCIe/USB I/O bridges onto a single coherent silicon die (or multi-die UltraFusion package) sharing unified physical LPDDR DRAM [1, 32]. Monolithic integration eliminates passive inter-chip SPI bus sniffing, yet placing Wi-Fi, cellular baseband, USB, Thunderbolt/PCIe, GPU, display, and neural direct-memory-access (`DMA`) engines onto one high-bandwidth coherent fabric creates an acute containment hazard: without strict bus-level address translation, a single firmware vulnerability inside an untrusted wireless chip or external Thunderbolt peripheral could issue arbitrary physical memory reads and writes straight into `XNU` data structures or kernel page tables.

Apple enforces peripheral containment across the SoC fabric through per-bus I/O memory management units termed `AppleDART` (Device Address Resolution Table, with hardware generations `dart,t8020` on `M1`, `dart,t6000` on `M1 Pro`/`Max`, and `dart,t8110` on `M2` and newer silicon) paired with `SART` (System Address Resolution Table) physical region filters on internal storage controllers [32, 68, 69]. Rather than sharing one global IOMMU across the entire system, each DMA-capable peripheral complex sits behind a dedicated `AppleDART` hardware block on the SoC fabric. On `t8020` and `t6000` silicon, each `AppleDART` exposes sixteen hardware stream IDs (`stream` $\in \{0,\dots,15\}$), each governed by an independent Translation Control Register (`TCR[stream]` at offset `0x100 + 4*stream`, controlling `TRANSLATE_ENABLE` at bit `7`, `BYPASS_DART` at bit `8`, and `BYPASS_DAPF` at bit `12`) and four Level-0 Translation Table Base Registers (`TTBR[stream, 0..3]` at `0x200 + 16*stream`, carrying `VALID` at bit `31` and physical base bits `ADDR[30:0]` shifted by 12 bits) [68].

When `TRANSLATE_ENABLE` is active for a stream, `AppleDART` translates a 36-bit device-visible I/O virtual address (`IOVA`) into a host physical address through a two-level page-table hierarchy operating at 16 KB page granularity (`PAGE_BITS = 14`, with 4 KB support on external Thunderbolt PCIe bridges): bits `[37:36]` select one of the four `TTBR` roots, bits `[35:25]` index the 2,048-entry Level-1 directory, and bits `[24:14]` index the 2,048-entry Level-2 leaf table [68]. Leaf descriptors in `PTE_T8020` and `PTE_T6000` go beyond whole-page granularity by embedding sub-page protection bounds (`SP_START` in bits `[63:52]` and `SP_END` in bits `[51:40]` alongside `SP_PROT_DIS` at bit `1` and `VALID` at bit `0`), preventing sub-page buffer over-reads when small network or USB descriptors share a 16 KB frame [68]. Any peripheral transaction targeting an unmapped `IOVA`, violating read/write permissions, or stepping outside `[SP_START, SP_END]` aborts inside the `AppleDART` fabric port, latches the offending stream and 64-bit address in `ERROR` (`+0x40`, setting `READ_FAULT`, `WRITE_FAULT`, `NO_PTE`, or `SUBPAGE_PROT`) and `ERROR_ADDR_LO`/`HI` (`+0x50`/`+0x54`), and raises a hardware fault interrupt via the Apple Interrupt Controller (`AIC`) [32, 68]. Furthermore, early boot firmware can assert `R_CONFIG.LOCK` (bit `15` at `+0x60`) and `R_DAPF_LOCK` (`+0xf0`) to freeze critical `DART` registers against runtime tampering [68].

Complementing full `IOVA` translation in `AppleDART`, high-throughput internal co-processors such as the Apple `ANS2`/`ANS3` NVMe controller sit behind `SART` (`drivers/soc/apple/sart.c` across `SARTv0`, `SARTv2`, and `SARTv3`) [69]. Unlike a remapping IOMMU, `SART` implements a sixteen-slot physical address allowlist (`APPLE_SART_MAX_ENTRIES = 16`): each slot pairs a `CONFIG(idx)` flags register (`0xff` allow mask in `SARTv2`/`v3`) with 4 KB-aligned `PADDR(idx)` and `SIZE(idx)` registers (`SHIFT = 12`), rejecting any NVMe DMA transfer outside the explicitly whitelisted physical bounce regions while marking bootloader-initialized slots immutable in `protected_entries` [69]. Most auxiliary co-processors on the SoC (`ANS`, `SMC`, `DCP` display controller, `ISP`, and audio DSPs) run Apple's real-time `RTKit` firmware stack and communicate with `XNU` exclusively over 64-bit hardware mailbox FIFOs (`EP_MGMT = 0`, `EP_CRASHLOG = 1`, `EP_SYSLOG = 2`, `EP_IOREPORT = 4`, `EP_OSLOG = 8`, negotiating shared memory buffers via `APPLE_RTKIT_BUFFER_REQUEST` inside `AppleDART`-fenced `IOVA` windows) [70].

Around this `AppleDART`-governed fabric sit four security-critical co-processor complexes whose execution state is physically or cryptographically partitioned from the main Application Processor (`AP`) cores [1, 32]. First, the `Secure Enclave Processor` (`SEP`) is an independent `ARM64` (`Kingfisher`) core subsystem with its own immutable mask `SEPROM`, hardware true random number generator (`TRNG`), silicon-fused `UID`/`GID` `AES` engine, 64-bit `AKF` mailbox FIFO, and inline memory encryption/authentication engine guarding its carved-out DRAM region (`TZ0`) [1, 67]. Second, the Always-On Processor (`AOP`) processes low-power inertial, proximity, and acoustic trigger queues inside bounded SRAM without waking `XNU`. Third, on `A17 Pro`, `M3`, `M4`, and `M5` silicon, `Secure Exclaves` host isolated execution domains atop a dedicated `cL4` (`seL4`-lineage) microkernel (`Secure Kernel`, `SK`) that owns camera and microphone privacy indicator ledgers and sensor ring buffers accessed via `xnuproxy` and `Tightbeam` IPC, guaranteeing that even a compromised `EL1` `XNU` kernel cannot stream audio or video frames without illuminating visible display indicator pixels [1, 71]. Fourth, on `Apple Vision Pro`, the companion `R1` co-processor ingests twelve cameras, five sensors, and six microphones along a deterministic 12-millisecond photon-to-photon pipeline, keeping raw near-infrared eye-tracking imagery unreachable by `visionOS` applications on the `AP` [1].

## ARM64 Exception Levels and Orthogonal Guarded Execution (GXF)

On standard `AArch64` (`ARMv8-A` and `ARMv9-A`) processors, execution privilege is arranged vertically across four architectural Exception Levels (`EL0` through `EL3`) [34]. User-space applications, system daemons, and `DriverKit` extensions execute unprivileged at `EL0`; the `XNU` kernel executes at `EL1`, entered synchronously from `EL0` when user code executes a Supervisor Call (`SVC #0x80`) instruction or asynchronously on `AIC` interrupts and MMU data/instruction aborts; the virtualization hypervisor (`Hypervisor.framework` and `Virtualization.framework`) executes at `EL2`, entered upward via Hypervisor Call (`HVC`) traps and translating guest physical addresses (`IPA`) to host physical addresses (`PA`) through Stage-2 page tables rooted at `VTTBR_EL2` [34]; and `EL3` (Secure Monitor, entered via `SMC`) traditionally hosts `ARM TrustZone` firmware on third-party mobile SoCs. Apple Silicon deliberately omits `EL3` `TrustZone` Secure World software on the `AP` altogether, delegating hardware key custody to the physically separate `SEP` core so vulnerabilities in complex `EL3` monitor callouts can never expose device-unique keys [1, 32, 67].

![Figure: Apple Silicon SoC privilege planes showing ARM64 EL0-EL2 alongside orthogonal Guarded Execution (GL0-GL2) hosting SPTM and TXM, fenced from SEP, Exclaves, and R1 over the AppleDART-governed fabric.](diagrams/00b-apple-soc-privilege-planes.svg)

A purely vertical `EL0` $\to$ `EL1` $\to$ `EL2` hierarchy creates a severe architectural conflict whenever a high-performance kernel like `XNU` must enforce immutable page-table integrity while simultaneously supporting native hardware virtualization. Placing kernel page-table verification inside `EL2` (as hypervisor-based security monitors do on x86) either forces every `macOS` virtual machine (`Virtualization.framework`) through expensive nested virtualization or bloats the `EL2` root monitor with multi-guest scheduling and device-emulation code. Conversely, leaving raw page-table write access inside `EL1` allows a single `XNU` arbitrary kernel write vulnerability to overwrite `TTBR1_EL1` descriptors and map unsigned kernel shellcode.

Apple resolved this dilemma in custom CPU silicon by introducing *Guarded Execution Mode* (`GXF`, enabled via bit `1` of implementation-defined system register `S3_6_C15_C1_2`) paired with *System Permission Remapping Registers* (`SPRR`, configured via `SYS_SPRR_CONFIG_EL1` at `S3_6_C15_C1_0`) [32, 72, 73]. Rather than stacking `EL3` above `EL2`, `GXF` constructs an *orthogonal, lateral* privilege plane (`GL0`, `GL1`, and `GL2`) alongside `EL0`, `EL1`, and `EL2` that shares the exact same virtual address translation tables (`TTBR0_EL1` / `TTBR1_EL1` / `TTBR0_EL2`) while enforcing completely disjoint read, write, and execute permissions per page [72].

Hardware transitions between unguarded `ELx` and guarded `GLx` do not use `SVC` or `HVC` exception vectors; instead, Apple added two proprietary `A64` instructions in the `0x0020xxxx` encoding space that fault as `UNDEFINED` unless `GXF` is enabled in silicon [72, 73]:

```text
0x00201420 | imm5   genter #<imm5>   ; Lateral entry ELx -> GLx, PC := SYS_GXF_ENTER_EL1 (S3_6_C15_C8_1)
0x00201400          gexit            ; Lateral return GLx -> prior mode recorded in SYS_ASPSR_GL1
```

When `XNU` at `EL1` (or the hypervisor at `EL2`) executes `genter #imm5`, the CPU core switches laterally into guarded mode (`GL1` or `GL2`), records the 5-bit immediate selector inside `ESR_GLx[5:0]`, swaps to dedicated banked guarded system registers (`SYS_TPIDR_GL1`, `SYS_VBAR_GL1`, `SYS_SPSR_GL1`, `SYS_ASPSR_GL1`, `SYS_ESR_GL1`, `SYS_ELR_GL1`, and `SYS_FAR_GL1` in `S3_6_C15_C10_1..7`), and forces the program counter (`PC`) exclusively to the hardware-locked target address held in `SYS_GXF_ENTER_EL1` (`S3_6_C15_C8_1`) [72, 73]. An attacker with arbitrary `ROP`/`JOP` gadget control in `EL1` cannot `genter` into the middle of a guarded function: every lateral entry lands at the single audited gate in `SYS_GXF_ENTER_EL1`, and `gexit` returns strictly according to `SYS_ASPSR_GL1` [72].

Permission isolation across `ELx` and `GLx` without flushing `TLB`s is enforced by `SPRR` [72]. Under `SPRR`, the four architectural permission bits `(AP[1], AP[0], UXN, PXN)` stored in each 64-bit ARMv8 page-table descriptor no longer directly encode RWX rights; instead, those four bits form a 4-bit index $i \in \{0,\dots,15\}$ into two 64-bit hardware permission registers: `SYS_SPRR_PERM_EL0` (`S3_6_C15_C1_5`) and `SYS_SPRR_PERM_EL1` (`S3_6_C15_C1_6`, with lock bits `SPRR_CONFIG_LOCK_PERM_EL0` at bit `4` and `LOCK_PERM_EL1` at bit `5`) [72]:

$$\text{Perm}(i) = \bigl(\text{SYS\_SPRR\_PERM\_EL1} \gg (4i)\bigr) \mathbin{\&} \texttt{0xF} = \langle \text{GL}[1{:}0],\; \text{EL}[1{:}0] \rangle$$

Each 4-bit nibble encodes independent permissions for standard `EL` execution and guarded `GL` execution: for example, nibble value `0b0100` grants `---` (no access) in `EL1` and `R-X` (executable code) exclusively in `GL`, nibble `0b1110` grants `R--` (read-only) in `EL1` and `RW-` (read-write) in `GL`, and nibble `0b0011` grants `RW-` in `EL1` while stripping all access (`---`) in `GL` so guarded monitor code cannot accidentally dereference untrusted `XNU` pointers or execute `EL1` text (`PAN`/`PXN` across lateral planes) [72]. Crucially, no valid 4-bit `SPRR` encoding permits simultaneous write and execute (`RWX`) within any single domain [72].

On `A15` and `M2` silicon onward, Apple places the `Secure Page Table Monitor` (`SPTM`) at the apex of this guarded plane in `GL2` [1, 72]. `SPTM` owns all physical frame-type transitions, CPU page tables (`SPRR` index `0b1110`: `R--` to `XNU`, `RW-` to `SPTM`), `AppleDART` stream roots, and `EL2` Stage-2 tables. Directly beneath `SPTM` in deprivileged guarded user mode (`GL0`, whose `SVC` calls are conditionally routed straight to `SPTM` in `GL2` via `HCR_EL2.TGE`-class trapping while `Exclave` `Secure Kernel` calls enter `GL2` from `GL1` via `HVC`) runs the `Trusted Execution Monitor` (`TXM`), isolating complex `ASN.1` `DER` entitlement and `CodeDirectory` verification away from both untrusted `XNU` (`EL1`) and root `SPTM` (`GL2`) [1, 71, 72].

## The XNU Hybrid Kernel: Mach Capabilities, ipc_port, and MACF

Executing inside unguarded `EL1` (`osfmk/`, `bsd/`, `iokit/`, `libkern/`, and `security/` in Apple's open-source `xnu` distribution) is `XNU`, a hybrid kernel uniting a Carnegie Mellon `Mach 3.0`-derived capability core with a FreeBSD-derived POSIX layer and the C++ `IOKit` driver runtime inside one kernel virtual address space [74, 75]. Countless user-space privilege-escalation vulnerabilities across `macOS` and `iOS` trace directly to architectural impedance mismatches between `Mach` object capabilities and `BSD` process/credential semantics.

In `Mach` (`osfmk/`), the unit of resource ownership is a `task_t` (wrapping a virtual memory map `vm_map_t`, ledger memory/CPU accounting, and a private IPC capability table `struct ipc_space`), within which one or more `thread_t` execution contexts run [74, 75, 76]. Tasks never address sibling tasks or system daemons by global integer identifiers; all `Mach` IPC traverses unidirectional kernel message queues represented in `osfmk/ipc/ipc_port.h` by `struct ipc_port`, allocated exclusively from the dedicated `ZONE_ID_IPC_PORT` zone (`zone_id_require(ZONE_ID_IPC_PORT, sizeof(struct ipc_port), port)`) [77]:

```c
/* Simplified from xnu/osfmk/ipc/ipc_port.h and osfmk/ipc/ipc_space.h */
struct ipc_port {
    struct ipc_object   ip_object;      /* io_bits, io_references, IOT_*/IKOT_* type */
    struct waitq        ip_waitq;       /* ip_guarded:1, ip_strict_guard:1, ip_bootstrap:1 */
    struct ipc_mqueue   ip_messages;    /* FIFO message queue & imq_seqno */
    union {
        struct ipc_space *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_receiver") ip_receiver;
        struct ipc_port  *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_destination") ip_destination;
    };
    union {
        uintptr_t         ip_kobject;   /* manually PAC-authenticated kernel object */
        struct ipc_port  *XNU_PTRAUTH_SIGNED_PTR("ipc_port.ip_nsrequest") ip_nsrequest;
    };
    mach_vm_address_t   ip_context;     /* 64-bit guard value when ip_strict_guard == 1 */
    mach_port_mscount_t ip_mscount;     /* make-send count */
    mach_port_rights_t  ip_srights;     /* active send-right reference count */
    mach_port_rights_t  ip_sorights;    /* active send-once-right count */
};
```

Notice the layered defensive invariants baked directly into `struct ipc_port` and `struct ipc_space` on `arm64e` kernels [76, 77, 78]. First, critical internal pointers (`ip_receiver`, `ip_destination`, `ip_nsrequest`, `ip_pdrequest`, `is_table`, and `is_task`) carry type-specific `XNU_PTRAUTH_SIGNED_PTR` signatures, while `is_policy` inside `struct ipc_space` blends its storage address with `ptrauth_string_discriminator("ipc_space.is_policy")` under `ptrauth_key_process_independent_data`, preventing forged port redirection even under partial memory corruption [76, 77, 79]. Second, `ip_right_delta()` guards `ip_srights` and `ip_sorights` with `os_add_overflow()` checks (`__ipc_right_delta_overflow_panic`) to eliminate reference-count wraparound use-after-frees, while `ip_strict_guard` locks `ip_context` so user-space code cannot overwrite or forge guarded port context pointers [77].

User-space code (`EL0`) never observes raw `ipc_port_t` kernel pointers. Instead, a process holds 32-bit `mach_port_name_t` handles indexing its own task-local `ipc_space.is_table` (managed via Safe Memory Reclamation `SMR_POINTER` lookups and randomized freelist permutation `ipc_space_rand_freelist` seeded from `is_entropy`) [76, 78]. As defined in `osfmk/mach/port.h`, each kernel-assigned `mach_port_name_t` packs a 24-bit table slot index (`MACH_PORT_INDEX(name) = name >> 8`) alongside an 8-bit rolling generation number (`MACH_PORT_GEN(name)`) to catch stale double-deallocation bugs [78]. Each entry records which fundamental `mach_port_right_t` capabilities the task holds, exposed to user space as `MACH_PORT_TYPE_*` bitmasks (`MACH_PORT_TYPE(right) = 1u << (right + 16)`) [78]:

$$\begin{aligned}
\texttt{MACH\_PORT\_TYPE\_SEND} &= \texttt{0x00010000} \quad (\text{right } 0\text{: enqueue messages; } \ge 1 \text{ holders}), \\
\texttt{MACH\_PORT\_TYPE\_RECEIVE} &= \texttt{0x00020000} \quad (\text{right } 1\text{: dequeue messages; unique } 1 \text{ holder}), \\
\texttt{MACH\_PORT\_TYPE\_SEND\_ONCE} &= \texttt{0x00040000} \quad (\text{right } 2\text{: single-use reply capability}), \\
\texttt{MACH\_PORT\_TYPE\_PORT\_SET} &= \texttt{0x00080000} \quad (\text{right } 3\text{: multiplexed receive set}), \\
\texttt{MACH\_PORT\_TYPE\_DEAD\_NAME} &= \texttt{0x00100000} \quad (\text{right } 4\text{: tombstone after port destruction}).
\end{aligned}$$

Because port names are purely task-local indices, an unprivileged process cannot fabricate a capability to a privileged service by guessing an integer; it must either inherit a bootstrap send right via `launchd` lookup or receive a port descriptor (`MACH_MSG_PORT_DESCRIPTOR` in `osfmk/mach/message.h`) transferred explicitly across an existing `mach_msg()` channel [75, 78, 80]. When `XPC` (`libxpc` and `NSXPCConnection`) marshals typed RPC dictionaries over `Mach` ports, `XNU` appends a kernel-generated `mach_msg_audit_trailer_t` (`MACH_RCV_TRAILER_AUDIT`) containing the sender's unforgeable eight-word `audit_token_t` [74, 80]:

$$\text{audit\_token\_t} = (\text{auid},\; \text{euid},\; \text{egid},\; \text{ruid},\; \text{rgid},\; \text{pid},\; \text{asid},\; \text{pidversion})$$

Because `XNU` increments `pidversion` monotonically on every `execve()` image replacement and PID wrap-around, binding authorization checks (`csops_audittoken`, `sandbox_check_by_audit_token`, `TCC`) to `audit_token_t` rather than legacy POSIX `pid_t` defeats classic PID-reuse time-of-check-to-time-of-use (`TOCTOU`) races [74, 75].

![Figure: XNU hybrid architecture pairing the Mach capability-port and audit_token_t microkernel layer with the BSD POSIX process, VFS, and Mandatory Access Control Framework (MACF) policy stack.](diagrams/00b-xnu-mach-bsd-macf-stack.svg)

In the `BSD` layer (`bsd/`), every `Mach` `task_t` links one-to-one with a POSIX `struct proc` (`proc_t`) managing `pid_t`, `kauth_cred_t` (`struct ucred`) credentials, file descriptors, network sockets, and Virtual File System (`VFS`) `vnode_t` nodes [74, 75]. Spanning both `Mach` and `BSD` is the TrustedBSD-derived `Mandatory Access Control Framework` (`MACF`, defined across `security/mac_policy.h` and `security/mac_internal.h` at `MAC_POLICY_OPS_VERSION = 91`) [74, 81, 82]. Rather than scattering ad-hoc security conditionals across syscalls, `XNU` attaches opaque `struct label` slot arrays to credentials, tasks, ports, vnodes, mounts, and sockets, and invokes centralized `MAC_CHECK` macros that iterate over every registered policy module's `struct mac_policy_ops` function-pointer vector [81, 82]:

```c
/* Representative hooks from xnu/security/mac_policy.h (MAC_POLICY_OPS_VERSION 91) */
struct mac_policy_ops {
    mpo_cred_check_label_update_execve_t *mpo_cred_check_label_update_execve;
    mpo_file_check_mmap_t                *mpo_file_check_mmap;
    mpo_iokit_check_open_t               *mpo_iokit_check_open;
    mpo_port_check_service_t             *mpo_port_check_service;
    mpo_proc_check_get_task_t            *mpo_proc_check_get_task;
    mpo_proc_check_run_cs_invalid_t      *mpo_proc_check_run_cs_invalid;
    mpo_vnode_check_exec_t               *mpo_vnode_check_exec;
    mpo_vnode_check_open_t               *mpo_vnode_check_open;
    mpo_vnode_check_signature_t          *mpo_vnode_check_signature;
    /* ... >250 lifecycle and access-control callout slots ... */
};
```

First-party security extensions (`AppleMobileFileIntegrity.kext`, `Sandbox.kext` implementing `Seatbelt` and `SIP`, `Quarantine.kext`, and `EndpointSecurity.kext`) register static `mac_policy_conf` descriptors during early kernel bootstrap, before `XNU` seals its `SECURITY_READ_ONLY_LATE` (`__DATA_CONST`) segments under `KTRR`/`SPTM` [74, 81]. Composition across `MACF` modules is strictly *conjunctive* (deny-overrides): if POSIX discretionary permissions allow `UID 0` (`root`) to open a file or call `task_for_pid()`, yet *any* `mac_policy_ops` callback returns `EPERM` or `EACCES`, `XNU` aborts the operation unconditionally [81, 82].

## Cryptographic Primitives, Image4 ASN.1 DER Grammar, and arm64e Mach-O

Across Secure Boot, code signing, `APFS` encryption, and zero-knowledge cloud protocols, Apple standardizes on public cryptographic constructions accelerated in dedicated silicon blocks [1, 83, 84, 85]. Cryptographic hashing uses `SHA-256` (for 4 KB `CodeDirectory` page hashes and `APFS` `SSV` leaf blocks) and `SHA-384` (for `Image4` manifests, `LocalPolicy` digests, and `SEP` boot measurements) [83, 86]. Bulk data-at-rest confidentiality uses inline hardware `XTS-AES-128` and `XTS-AES-256`, while authenticated key wrapping, enclave-to-sensor buses, and cloud records rely on `AES-256-GCM` (`NIST SP 800-38D`) and `RFC 5869` `HKDF` extract-and-expand derivation [84, 85]:

$$K_{\text{derived}} = \text{HKDF-Expand}\bigl(\text{HKDF-Extract}(\text{salt}, \text{IKM}),\; \text{info},\; L\bigr)$$

where $\text{IKM}$ supplies high-entropy input keying material (such as a `SEP`-derived shared secret or hybrid post-quantum key), $\text{salt}$ provides domain randomness, $\text{info}$ binds canonical protocol/keybag context labels, and $L$ fixes output key byte length [84]. Digital signatures and key agreement employ NIST `P-256` and `P-384` (`ECDSA`/`ECDH`), `RSA-3072`/`4096` in long-lived firmware root CAs, `P-224` for compact 28-byte BLE `Find My` beacons, and hybrid `ML-KEM-768`/`1024` in `iMessage` `PQ3` [1].

Every boot-critical artifact across Apple platforms (`LLB`, `iBoot`, `SEP` firmware, `SPTM`, `TXM`, `BootKC`, `AuxKC`, static and loadable trust caches, `Cryptex1` volumes, Mac `LocalPolicy`, and Private Cloud Compute OS bundles) is authenticated inside one canonical container format: `Image4` (`IMG4`), serialized strictly under `ITU-T X.690` Distinguished Encoding Rules (`ASN.1` `DER`) [86, 87, 88]. Unlike permissive `BER` parsers that accept indefinite-length encodings or non-minimal integer padding (a perennial source of X.509 signature-verification bypasses when a parser and hash engine disagree on field boundaries), `DER` mandates unique, minimal, deterministic byte representations for every tag and length prefix [87]. Formally, an `IMG4` object and its three constituent substructures (`IM4P`, `IM4M`, and `IM4R`) obey the following `ASN.1` `DER` grammar, where property tags use `ASN.1` private/context-constructed classes whose 32-bit tag numbers equal four-character ASCII codes (`4CC`s, such as `'MANB' = 0x4d414e42`) [86, 88]:

```text
IMG4 ::= SEQUENCE {
    magic        IA5String ("IMG4"),
    payload      IM4P,                             -- Universal component binary
    manifest     [0] EXPLICIT IM4M OPTIONAL,       -- Signed per-device ApImg4Ticket
    restoreInfo  [1] EXPLICIT IM4R OPTIONAL        -- Boot-nonce generator seed
}

IM4P ::= SEQUENCE {
    magic        IA5String ("IM4P"),
    type         IA5String,                        -- 4CC: "illb", "ibot", "sepi", "krnl", "sptm", "ltrs"
    description  IA5String,                        -- Build tag, e.g. "iBoot-13822.101.4"
    data         OCTET STRING,                     -- Raw or LZFSE / BVX2 compressed image
    kbag         OCTET STRING OPTIONAL             -- DER SEQUENCE of {kclass(1=prod,2=dev), iv, key}
}

IM4M ::= SEQUENCE {
    magic        IA5String ("IM4M"),
    version      INTEGER (0),
    body         SET { [PRIVATE "MANB"] SEQUENCE {
                     IA5String ("MANB"),
                     SET {
                         [PRIVATE "MANP"] ManifestProperties, -- ECID, CHIP, BORD, CEPO, SDOM, CPRO, CSEC, BNCH
                         [PRIVATE <4CC>]  ObjectProperties    -- Per-image OBJP: DGST (SHA-384), EPRO, ESEC
                     }
                 } },
    signature    OCTET STRING,                     -- RSA-4096 or ECDSA-P384 over DER(body)
    certChain    SEQUENCE OF Certificate           -- Chains to fused Apple Root CA or SEP OIHR
}

IM4R ::= SEQUENCE {
    magic        IA5String ("IM4R"),
    properties   SET { [PRIVATE "BNCN"] SEQUENCE { IA5String ("BNCN"), OCTET STRING (SIZE(8)) } }
}
```

Notice the precise division of labor across `IM4P`, `IM4M`, and `IM4R` [86, 88]. `IM4P` contains the firmware or kernel payload bytes and optional `GID`-wrapped `KBAG` decryption keys (`kclass = 1` for production silicon fuses, `kclass = 2` for internal development fuses), with zero per-user or per-device personalization bytes so identical `.im4p` files stream from global CDNs. `IM4M` (`ApImg4Ticket`) signs the `DER`-encoded `MANB` `SET`, uniting global `MANP` silicon constraints (`ECID`, `CHIP`, `BORD`, `CEPO`, `SDOM`, `CPRO`, `CSEC`, and the 32- or 48-byte `BNCH` boot-nonce hash) with per-component `OBJP` sets pinning each 4CC image's `DGST` (`SHA-384` over `IM4P`), `EPRO` (enforcement production), and `ESEC` (enforcement security mode) booleans [86, 88]. Finally, `IM4R` carries the `BNCN` (Boot Nonce) 8-byte generator seed $g$ committed in NVRAM/`SEP` before restore so `LLB` or `iBoot` can recompute $\text{SHA-384}(g)$ and confirm equality against `MANP.BNCH` [86, 88].

> **Definition.**
> An `Image4` admission gate accepts a component of four-character type $\tau$ if and only if (1) the `IM4M` certificate chain validates to the active hardware trust root (`Apple Root CA` hash in `Boot ROM` or `SEP` `OIHR` for Mac `LocalPolicy`) and `Verify(PK, DER(MANB), signature) = 1`, (2) every silicon attribute in `MANP` (`ECID`, `CHIP`, `BORD`, `SDOM`, `CEPO`, `CPRO`, `CSEC`, and `BNCH` $= H(\texttt{BNCN})$ where anti-replay applies) matches live SoC fuse and nonce registers, and (3) $\text{SHA-384}(\texttt{IM4P}) = \texttt{IM4M.MANB}[\tau].\texttt{DGST}$ [86, 87, 88].

Above the `Image4` boot container, kernel collections and user-space executables use the 64-bit `Mach-O` binary format (`EXTERNAL_HEADERS/mach-o/loader.h`, `MH_MAGIC_64 = 0xfeedfacf`), with prelinked `BootKC` and `AuxKC` images using `MH_FILESET` (`0xc`) to bundle `XNU` and dozens of `IOKit` kexts inside unified segment layouts, and universal `macOS` binaries wrapping `x86_64` and `arm64` slices inside `FAT` headers (`FAT_MAGIC = 0xcafebabe`) [75, 89]. Critically, `CPU_TYPE_ARM64` binaries fork into legacy unauthenticated `CPU_SUBTYPE_ARM64_ALL` (`0`) and `arm64e` (`CPU_SUBTYPE_ARM64E = 2`, carrying capability-versioned upper bits in `cpusubtype`) [79, 89]. Compiling for `arm64e` activates Apple's pointer-authenticated C/C++/Objective-C/Swift ABI (`ptrauth.h`), emitting `QARMA` hardware instructions (`PACIBSP`/`RETAB`, `BLRAA`, `LDRAA`) and `LC_DYLD_CHAINED_FIXUPS` metadata that bind return addresses to stack frames and diversify C++ virtual-method tables (`__AUTH_CONST`) and symbol stubs (`__AUTH_GOT`) by both storage address (`addrDiv = 1`) and 16-bit type-signature hashes [79, 89]. Meanwhile, hardware topology passes from `iBoot` into `XNU` via an immutable flattened Apple `DeviceTree` (`pexpert/pexpert/device_tree.h`, `RealDTEntry` nodes including `pmap-io-ranges` physical `MMIO` permissions) rather than Turing-complete x86 `ACPI` AML bytecode, eliminating firmware-table interpreter code execution during OS startup [32, 90].

## Apple's Four-Tier Threat Taxonomy and Analytical Discipline

Evaluating whether any control in the Apple trust chain holds requires stating *which* adversary occupies *which* vantage point [1, 67, 91]. Throughout all twenty chapters, defenses and failures are measured against four progressively capable adversary tiers.

| Adversary Tier | Assumed Capabilities | Canonical Targets | Primary Defending Boundaries |
|---|---|---|---|
| Tier 1: Opportunistic Remote & Malicious App | Arbitrary web JS/Wasm, untrusted App Store or notarized Mac binaries, social engineering | Browser cookies, `TCC`-gated user files, `login.keychain-db`, passkeys | Gatekeeper/Notarization, `Seatbelt` App Sandbox, `TCC`, `SEP` Data Protection Keychain, WebAuthn origin binding |
| Tier 2: Physical Possession (`BFU` & `AFU`) | Seized or stolen hardware, custom USB `DFU` microcontrollers, shoulder-surfed PIN, NAND desoldering | Offline volume decryption, `AFU` RAM/Class `C` keys, Apple Account hijack, `SecureROM` | `Boot ROM` + `AppleDART`, `SEP` `UID` tangling & counter lockboxes, `BFU` 72h reboot, `USB Restricted Mode`, `Stolen Device Protection` |
| Tier 3: Mercenary Multi-Stage Zero-Click | Million-dollar 0-day chains over `iMessage`, `FaceTime`, or `WebKit` with zero user interaction | Journalists, executives, dissidents; live `AFU` session memory, audio/camera, messages | `BlastDoor`, `BrowserEngineKit` JIT isolation, `PAC`, `SPTM`/`TXM`, `Exclaves`, `A19`/`M5` synchronous `EMTE` (`MIE`), `Lockdown Mode` |
| Tier 4: Compromised or Compelled Cloud / Network | Active WAN interception, breached cloud storage, rogue key directory, or statutory `TCN` compulsion | `iCloud` backups/photos/drive, `IDS` identity keys, `Find My` history, `PCC` AI prompts | `Advanced Data Protection` (`ADP`), `iCloud Keychain` verifiable HSMs, `PQ3` + `KT` Merkle logs, `P-224` rotating beacons, `PCC` `OHTTP` + Transparency Log |

Each tier stresses an orthogonal trust boundary, and conflating tiers produces catastrophic security misjudgments [67]. A Tier 2 physical defense such as `SEP` `UID`-tangled `XTS-AES` storage encryption offers zero resistance once a Tier 3 mercenary zero-click chain lands inside an `After First Unlock` (`AFU`) session where Class `C` file keys are legitimately unsealable over the `SEP` mailbox [1]. Conversely, Tier 3 silicon memory-tagging hardware (`A19`/`M5` `EMTE`) on an endpoint cannot protect cloud-synced backups against a Tier 4 server breach or legal compulsion order unless the user has enabled `Advanced Data Protection` so root wrapping keys remain exclusively inside client `SEP`-backed vaults [1].

Across every tier, rigorous systems analysis demands separating *cryptographic or hardware mechanism validity* from *system-level semantic authorization*. A valid `Image4` `IM4M` signature proves that `TSS` authorized an exact byte sequence for an `ECID`, yet if a downgraded `Cryptex` or entitled `macOS` migration helper (`com.apple.rootless.install.heritable`) executes out of context, attackers wield Apple's own signature against `SIP` unless `Launch Constraints` and separate anti-replay nonces bind *who* may invoke it and *when* [86]. Likewise, holding a `MACH_PORT_TYPE_SEND` capability in `ipc_space` proves possession of a valid `ipc_port` channel, yet any `XPC` daemon that validates mutable `pid_t` rather than the kernel's `audit_token_t` (`pidversion`) or omits `DER` entitlement predicates turns capability routing into local privilege escalation [77, 78, 80]. Even inside custom silicon, `SPTM` (`GL2`) proves that CPU page tables satisfy strict `SPRR` `W^X` frame types, yet if an undocumented GPU debug DMA register (`0x206040000` in *Operation Triangulation*) omits `pmap-io-ranges` fencing, attackers write physical RAM directly underneath CPU virtual memory [32, 72, 90].

Finally, Apple's Security Research Device (`SRD`) program demonstrates how Cupertino institutionalizes external vulnerability discovery without introducing backdoors into retail `CPRO = 1` consumer devices: factory-fused `SRD` iPhones (`CPRO = 0` research policy) mount researcher-signed `Cryptexes` and expose kernel/shell introspection strictly on dedicated hardware units that cannot be reproduced via software on commercial silicon [91]. Holding mechanism validity distinct from end-to-end semantic safety across all four adversary tiers guides the twenty chapters ahead, beginning at processor cold reset in [Chapter 1](01-secure-boot.md).
