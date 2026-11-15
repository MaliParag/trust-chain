# Hardware Monitors and Memory Integrity Enforcement

## Overview

* **Link in the Chain:** Silicon-enforced runtime integrity layer on the Application Processor (`AP`); sits beneath `XNU` (`EL1`) and user space (`EL0`) to prevent memory-corruption vulnerabilities from hijacking control flow, forging executable pages, suppressing camera/microphone privacy indicators, or corrupting adjacent heap allocations.
* **Core Security Invariant:** Physical page-table types and `W^X` invariants are arbitrated exclusively by `SPTM` in Guarded Execution `GL2` (`A15+`/`M2+`), code and data pointers carry cryptographic `QARMA` `PAC` tags (`FPAC` synchronous trap), sensor indicator ledgers run inside `Exclaves`, and on `A19`/`M5` silicon (`Memory Integrity Enforcement`) every tagged dereference must satisfy synchronous `EMTE` equality ($T_{\text{ptr}} = T_{\text{mem}}$) under hardware Tag Confidentiality Enforcement.
* **Platform Matrix:** Unified across `iOS`, `iPadOS`, `macOS`, `watchOS`, `visionOS`, and `Private Cloud Compute` by SoC generation (`PAC` on `A12+`/`M1+`; `SPTM` + `TXM` on `A15+`/`M2+`; `Exclaves` on `A17 Pro+`/`M3+`; synchronous `EMTE` `MIE` on `A19+`/`M5+`), with `macOS` alone permitting `Permissive Security` `CTRR`/monitor relaxation via paired `1TR` ([Chapter 2](02-mac-localpolicy.md)).
* **Trusted Computing Base (TCB):** `ARMv8.3-A` `PAC` `QARMA-64` engine and five key registers, `KTRR`/`CTRR` and `APRR`/`SPRR` silicon registers, `SPTM` (`GL2`), `TXM` (`GL0`), and `Exclaves` `Secure Kernel` (`GL1`) firmwares, typed allocators (`kalloc_type`, `xzone malloc`, `libpas`), `A19`/`M5` `EMTE` Tag RAM and speculative tag-hiding logic, and SoC `pmap-io-ranges` / GPU context isolation.
* **Failure Horizon & Handoff:** Undocumented SoC `MMIO` cache-DMA blocks (`CVE-2023-38606`), unscrubbed `M1` GPU shader register files (`CVE-2026-49269`), speculative `PAC`/`MTE` side channels (`PACMAN`, `TikTag`), and software allocator tag-commit races (`macOS 26.4.1` `M5` race) bypass CPU-only page/tag checks; hands off verified filesystem and code-signing semantics to Part II ([Chapter 5](05-apfs-ssv-dyld.md), [Chapter 6](06-amfi-txm-notarization.md)).

## Threat Model & Design Tension

Across `WebKit`, `ImageIO`, `FontParser`, `CoreAudio`, `IOKit`, and `XNU` itself, tens of millions of lines of C, C++, and Objective-C parse untrusted network streams, media codecs, and `Mach` IPC messages at native speed. Against a Tier 3 mercenary spyware team armed with a single heap buffer overflow or use-after-free (`UAF`) such as `SockPuppet` (`CVE-2019-8605`), classical exploitation followed a repeatable five-stage pipeline: overlap data and pointer fields on the heap to leak `KASLR` slides, corrupt a C++ virtual-method table (`vtable`) or saved link register (`LR`) to pivot into Jump- or Return-Oriented Programming (`JOP`/`ROP`), escalate to an arbitrary `EL1` kernel read/write primitive, overwrite `XNU` page-table descriptors (`TTBR1_EL1`) to inject unsigned `EL1` code, and patch `kauth_cred_t` credentials or `AMFI` flags [160, 161, 162].

Eradicating this pipeline inside a mobile and workstation operating system without regressing battery life or frame pacing presents three steep microarchitectural tensions [2, 162, 163]. First, control-flow integrity (`CFI`) cannot consult slow software shadow stacks when Objective-C message dispatches and C++ virtual calls fire millions of times per second. Second, any page-table defense hosted *inside* `EL1` (`XNU` policing itself) collapses if a single overlooked kernel gadget or peripheral DMA block writes physical RAM directly [19, 164]. Third, even after executable code pages and function pointers are locked down completely, *pure data-only exploitation* (corrupting credentials, `ipc_port` fields, or `dyld` state without ever diverting `PC`) remains viable unless hardware catches spatial and temporal memory errors synchronously on the exact offending load or store [2, 162, 165]. Over a nine-year co-design arc from `A10` (`2016`) through `A19` and `M5` (`2025–2026`), Apple systematically migrated all three defenses into custom silicon.

## Silicon & System Mechanics

### ARMv8.3-A Pointer Authentication (PAC), Discriminator Blending, and FPAC

Shipped by Apple on the `A12 Bionic` (`2018`) ahead of rest-of-industry `ARMv8.3-A` silicon, `Pointer Authentication` (`PAC`) repurposes the unused upper extension bits of 64-bit canonical virtual addresses to carry a cryptographic Message Authentication Code computed via Roberto Avanzi's low-latency tweakable block cipher `QARMA-64` [34, 160, 163, 166]. Hardware maintains five 128-bit secret key registers seeded per process (and separately for the kernel) from the hardware `TRNG` and unreadable from `EL0`: `APIAKey_EL1` and `APIBKey_EL1` for instruction pointers, `APDAKey_EL1` and `APDBKey_EL1` for data pointers, and `APGAKey_EL1` for `PACGA` 32-bit generic struct integrity tags [34, 160, 163]. Signing instructions (`PACIA`, `PACIBSP`, `PACDA`, `PACDB`) compute:

$$\text{PAC}_{K}(p, c) = \text{Trunc}_{b}\Bigl(\text{QARMA-64}_{K}\bigl(\text{addr}(p),\; c\bigr)\Bigr), \qquad c = \bigl(\text{disc}_{16} \ll 48\bigr) \mathbin{|} \bigl(\text{storage\_addr}_{48}\bigr)$$

where $\text{addr}(p)$ is the raw canonical address, $b$ (`11` to `24` bits depending on VA size and `TBI`/`EMTE` tag allocation) is the PAC width, and $c \in \{0,1\}^{64}$ is the *context tweak* [160, 163]. Under Apple's `arm64e` ABI, function prologues sign saved return addresses via `PACIBSP` using the live stack pointer `SP` as $c$, while C++ `vtable` pointers, Objective-C `isa`/method caches, and `XNU` kernel pointers (`ipc_port`, `ipc_space.is_policy`) invoke `ptrauth_blend_discriminator(&ptr, type_hash)`: blending the 48-bit address where the pointer is stored in memory with a 16-bit compile-time hash of its C++/C declaration type prevents an attacker from substituting a validly signed pointer belonging to struct type `B` or copying a valid pointer from offset `+0x10` to `+0x20` (*pointer substitution attacks*) [160, 162, 167].

Early `A12`/`A13` `PAC` implementations obeyed base `ARMv8.3-A` semantics: when an authentication instruction (`AUTIA`, `AUTDA`) detected a corrupted tag, it did *not* trap immediately, instead stripping the tag and flipping a high non-canonical bit (`bit 53`/`54` error code) so a subsequent load or branch would trigger a translation fault [34, 160]. As Brandon Azad (Google Project Zero) proved in 2019 on `iOS 12.1.2`, non-trapping `AUT*` leaked a fatal algebraic oracle when paired with `PAC*` re-signing gadgets (`AUTIA` followed by `PACIZA`, such as `l2tp_domain_module_stop`): because `PACIZA` on an `AUT`-corrupted pointer produced the *true* PAC with a single deterministic bit (`bit 62`) inverted, an attacker with kernel read/write could read back the corrupted output, flip `bit 62`, and forge valid `APIAKey` signatures for arbitrary kernel JOP chains [160, 167]! Starting with `A14` and `M1` (`FEAT_FPAC`), Apple silicon traps *synchronously* inside `AUT*`, `BLRAA`, `RETAB`, and `LDRAA` the instant a tag mismatches, terminating the thread before any downstream instruction can observe a failed authentication result [34, 160].

### From KTRR and PPL to SPTM (GL2) and TXM (GL0)

Cryptographic pointer integrity raises the bar for `JOP`/`ROP`, yet once an attacker acquires an arbitrary kernel read/write primitive in `EL1`, what prevents `XNU` from overwriting its own L3 page-table entries (`PTE`s) to map unsigned shellcode?

Apple's initial silicon countermeasure on `A10` (`2016`) was the `Kernel Text Readonly Region` (`KTRR`, generalized to `Configurable Text Read-only Region` `CTRR` on Macs) paired with `Access Permission Reconfiguration Registers` (`APRR`, extended to `SPRR` on `M1`+) [32, 164, 168]. During boot (`arm_init_sptm.c`), `iBoot` and early `XNU` compute the physical span `[segLOWESTROKC, segHIGHESTROKC]` housing static kernel `__TEXT`, `__DATA_CONST`, and `BootKC` read-only segments and lock that range inside both CPU MMU system registers and the Apple Memory Cache Controller (`AMCC`), causing even MMU-off accesses or rogue fabric writes to fault [164, 168]. Meanwhile, `APRR`/`SPRR` indirection allows `BrowserEngineKit` JIT compilers to flip per-core thread permissions on `MAP_JIT` pages between `RW-` and `R-X` via a single register write (`pthread_jit_write_protect_np`) without global `TLB` shootdowns across sibling CPU cores [43, 164].

On `A12`–`A14` and `M1`, Apple layered the `Page Protection Layer` (`PPL`, `pmap_cs`) atop `APRR`/`SPRR`, isolating page-table write permissions inside a privileged sub-ring embedded *within* the monolithic `XNU` image [164]. Because `PPL` still compiled inside `XNU` and shared broad kernel state, beginning with `A15` and `M2` silicon (`iOS 17+` and `macOS Sonoma`+), Apple replaced `PPL` with the out-of-kernel `Secure Page Table Monitor` (`SPTM`) running in lateral Guarded Execution `GL2`, paired with the `Trusted Execution Monitor` (`TXM`) in `GL0` [35, 36, 168, 169].

![Figure: Evolution from KTRR and in-kernel PPL to the out-of-kernel Secure Page Table Monitor (SPTM in GL2), Trusted Execution Monitor (TXM in GL0), and hardware-isolated Secure Exclaves.](diagrams/04-sptm-txm-guarded-domains.svg)

Dispatched as a standalone `Image4` payload (`sptm`) by `iBoot` prior to `XNU` (`SPTMArgs` in `osfmk/arm64/sptm/sptm.h`), `SPTM` maintains an authoritative physical *Frame Type Table* in `GL2`-exclusive memory (`SPRR` `R--` to `EL1`, `RW-` to `GL2`) classifying every physical RAM frame on the SoC across trust domains (`SPTM`, `XNU`, `TXM`, and `SK`) [35, 169]:

```c
/* Selected GL2 query & invariant interfaces from xnu/osfmk/arm64/sptm/sptm.h */
extern const sptm_bootstrap_args_xnu_t *SPTMArgs;

static inline sptm_frame_type_t sptm_get_frame_type(sptm_paddr_t paddr);
static inline bool sptm_paddr_is_inflight(sptm_paddr_t paddr);
static inline uint16_t sptm_get_page_table_refcnt(sptm_paddr_t table_paddr);

static inline bool sptm_type_is_user_executable(sptm_frame_type_t frame_type) {
    return (frame_type == XNU_USER_EXEC) ||
           (frame_type == XNU_USER_DEBUG) ||
           (frame_type == XNU_USER_JIT);
}
```

As detailed in open-source `XNU` (`osfmk/arm64/sptm/`) and reverse-engineered by Steffin and Classen (`arXiv:2510.09272`), `XNU` at `EL1` holds *zero* write access to CPU page tables, `EL2` Stage-2 hypervisor tables, or `AppleDART` IOMMU root tables (`IOMMU_bootstrap`) [35, 169]. Every physical frame transition must enter `GL2` via `genter` (`0x00201420`) to invoke `sptm_retype()`, which enforces a strict non-bypassable state machine [35, 169]:

![Figure: SPTM (GL2) physical Frame Type Table and deterministic sptm_retype() state-machine invariants across XNU_DEFAULT, XNU_PAGE_TABLE, XNU_USER_EXEC, and Exclave SK domains.](diagrams/04-extra-sptm-frame-retyping.svg)

Before retyping any physical page `paddr` from `old_type` to `new_type`, `SPTM` verifies that the calling domain (`XNU`, `TXM`, or `SK`) possesses retype rights over `old_type`, that `old_type` equals the live Frame Type Table entry, that no concurrent operation is in flight (`sptm_paddr_is_inflight(paddr) == false`), and that all virtual mappings and page-table reference counts (`sptm_get_page_table_refcnt`) have drained to zero followed by hardware `TLB` shootdowns across cores [35, 169]. Consequently, a frame typed `XNU_DEFAULT` (writable kernel heap/stacks) can *never* receive executable permissions, and transitioning a clean page to `XNU_USER_EXEC` requires `TXM` (executing deprivileged in `GL0` with `SVC`s trapped directly to `SPTM` in `GL2` via `HCR_EL2`) to validate its `SHA-256` `CodeDirectory` hash against an `SPTM`-protected trust cache first [36, 169].

Crucially, `SPTM` establishes this authority *before* `XNU` executes its first instruction [168, 169]. At the end of Stage-2 boot, `iBoot` jumps into `SPTM` in `GL2` rather than `XNU` in `EL1`: `SPTM` allocates its private Frame Type Table, classifies `BootKC`, `SPTM`, `TXM`, and `DeviceTree` `pmap-io-ranges` physical pages, locks `SYS_GXF_ENTER_EL1` and `SYS_SPRR_PERM_EL1` across cores, and runs `IOMMU_bootstrap` to take sole ownership of `AppleDART` stream root registers so a compromised `XNU` driver cannot point peripheral DMA at `SPTM` or `XNU_PAGE_TABLE` frames [168, 169]. Only then does `SPTM` pass `const_sptm_args` (`SPTMArgs`) downward into `XNU`'s `arm_init_sptm.c`, where `arm_slide_rebase_and_sign_image()` walks `DYLD_CHAINED_PTR_ARM64E_KERNEL` fixup chains across the `MH_FILESET` `BootKC` to rebase interior pointers and compute `QARMA` `PAC` signatures in place prior to locking `CTRR` [168].

### Secure Exclaves: ExclaveKit, cL4 Secure Kernel, Tightbeam, and EIC

Extending `SPTM` compartmentalization on `A17 Pro`, `M3`, `M4`, and `M5` SoCs, `Secure Exclaves` migrate privacy-critical sensor ledgers and media/biometric pipelines completely outside `XNU` (`osfmk/mach/exclaves.h`) [169, 170, 171]. Booted across two explicit phases (`EXCLAVES_BOOT_STAGE_EXCLAVECORE` and `EXCLAVES_BOOT_STAGE_EXCLAVEKIT`, with a dedicated `/System/ExclaveKit/System/Library/dyld/` shared cache), the Exclave world runs atop a minimal `GL1` microkernel termed the `Secure Kernel` (`SK`, derived from `seL4`/`cL4` formal microkernel lineage and invoking `SPTM` in `GL2` via `HVC`) while isolating individual `ExclaveKit` services and task-attached *conclaves* (`EXCLAVES_R_CONCLAVE`, `EXCLAVES_R_FRAMEBANK`) in `GL0` [71, 169, 171]. `XNU` cannot map or read Exclave physical frames; instead, `XNU` forwards typed RPC buffers (`exclaves_endpoint_call`, `exclaves_inbound_buffer_copyin`, `exclaves_outbound_buffer_copyout`) through `xnuproxy` using Apple's binary `Tightbeam` IPC serialization framework [169, 171].

The flagship security guarantee of `Exclaves` is the *Exclaves Indicator Controller* (`EXCLAVES_R_EIC` in `exclaves.h`) [170, 171]. Historically, if spyware compromised `XNU` (`EL1`) or `WindowServer`/`SpringBoard`, an implant could silently record microphone audio while hiding the orange/green status-bar indicator dot. Under `EXCLAVES_R_EIC`, hardware microphone (`exclaves_audio_buffer_create`) and camera sensor gates are arbitrated inside `Exclaves` in cryptographic lockstep with the Display Coprocessor (`DCP`): as documented in `exclaves.h` (`exclaves_sensor_status_t`), if `EIC` has not verified that visible indicator pixels are actively composited onto the active display at required luminance (or if a `MacBook`/`iPad` lid Hall-effect sensor disconnects the mic in hardware), sensor status remains `EXCLAVES_SENSOR_STATUS_DENIED` (`2`) and `exclaves_audio_buffer_copyout()` returns strictly zeroes (`0x00`) even to a compromised `EL1` `XNU` kernel [170, 171]!

### Typed Allocators and A19/M5 Memory Integrity Enforcement (EMTE)

With `PAC`, `SPTM`, and `TXM` blocking unsigned code injection, Tier 3 exploit chains shifted toward *data-only heap exploitation* (`SockPuppet` `CVE-2019-8605`, *DarkSword* `CVE-2025-43510`) [2, 161, 172]. Apple's first line of defense is software *type isolation* across three segregated allocators: `kalloc_type` in `XNU` (`osfmk/kern/zalloc.h`), `xzone malloc` in user space, and `libpas` (`IsoHeap`/`Gigacage`) in `WebKit` [2, 162, 173, 174]. Rather than placing arbitrary 192-byte structs into one shared `kalloc.192` slab where `SockPuppet`'s dangling `struct ip6_pktopts` could be reallocated by attacker-controlled `OSData` byte arrays or out-of-line `mach_port_ool_t` pointer arrays, `kalloc_type` inspects compile-time field layout signatures (`1` = pointer, `2` = data), banishes pure data buffers (`OSData`) to a separate `data.kalloc` virtual submap, enforces zone checks inside `kfree_type()`, and randomly distributes pointer-bearing types across `kalloc.type0..N` buckets per boot [162, 172, 174].

Page-level type segregation (`16 KB` granules) stops cross-type `UAF`, yet *intra-bucket* `UAF` (reallocating another instance of the same struct type) and linear out-of-bounds buffer overflows between neighboring slots in the same slab require sub-page hardware enforcement [2, 162]. In September 2025, on `A19` / `A19 Pro` (`iPhone 17` and `iPhone Air`) and `M5` silicon, Apple SEAR shipped *Memory Integrity Enforcement (`MIE`)*: an always-on hardware-software co-design uniting typed allocators with `ARMv8.9-A` *Enhanced Memory Tagging Extension (`EMTE`, `FEAT_MTE4`)* across `XNU` and over seventy user-space daemons (plus third-party apps via Xcode's Enhanced Security setting) [2, 175, 176].

![Figure: A19 and M5 Memory Integrity Enforcement (MIE) pipeline combining random 4-bit allocation tags, EMTE speculative tag-confidentiality protections, and zero-latency synchronous hardware traps.](diagrams/04-mie-emte-tag-check.svg)

Under `EMTE`, every 16-byte physical memory granule carries a secret 4-bit allocation tag $T_{\text{mem}} \in \{0,\dots,15\}$ in `SPTM`-protected Tag RAM while pointers carry a 4-bit logical tag $T_{\text{ptr}}$ in bits `[59:56]` [2, 165]. Apple's `MIE` implementation resolves four fatal flaws that plagued earlier commercial `MTE` deployments [2, 175, 177, 178]:

$$\forall \text{ load/store via } p:\quad T_{\text{ptr}}(p) \neq T_{\text{mem}}\bigl(\text{PA}(p)\bigr) \implies \text{Synchronous Trap Prior to Retirement}$$

First, `MIE` runs exclusively in *synchronous (`SYNC`) mode* for both loads and stores, eliminating the multi-instruction asynchronous (`ASYNC`) race window before syscall entry [2]. Second, `xzone` and `kalloc_type` assign distinct random tags to adjacent slots (stopping linear overflows instantly) and retag freed chunks on reuse while excluding the prior tag ($T_{\text{new}} \neq T_{\text{old}}$, catching first-reuse `UAF` deterministically), while `EMTE` (`FEAT_MTE4`) also enforces tag checks when pointers derived from tagged regions attempt out-of-bounds accesses into untagged global/stack memory [2, 175]. Third, `SPTM` locks kernel allocator metadata and Tag RAM against `EL1` tampering, and `XNU` enforces user-space tag checks during kernel `copyin()`/`copyout()` syscalls on an app's behalf [2]. Fourth, Apple's *Tag Confidentiality Enforcement* eliminates speculative tag-probing side channels (`TikTag` `arXiv:2406.08719` and `StickyTags`, which leaked Pixel/Chrome `MTE` tags via speculative execution timing without crashing!) by making speculative execution strictly invariant to tag match/mismatch in silicon, frequently reseeding tag PRNGs, and deploying a near-zero-cost `TDI`-inspired `Spectre V1` confinement scheme requiring $\ge 25$ independent `Spectre V1` gadgets to reach reliable tag disclosure [2, 177, 178, 179].

> **Key idea.**
> Without a crashless speculative oracle (`TikTag` blocked in silicon), a 4-bit synchronous `EMTE` tag is not "merely 4 bits of entropy": an unguided zero-click exploit crashes immediately and noisily on its very first out-of-bounds dereference with probability $\ge \frac{15}{16} = 93.75\%$ (and $1 - (1/16)^k > 99.97\%$ across $k = 3$ heap steps), collapsing multi-million-dollar exploit reliability [2].

## Platform Forks Across Apple OSes

Silicon memory monitors track SoC stepping uniformly across `iOS`, `iPadOS`, `macOS`, `watchOS`, `visionOS`, and `PCC` [2, 35]. An `M5` Mac under `Full Security`, an `A19 Pro` iPhone, and a `PCC` server blade enforce identical `FPAC`, `GL2` `SPTM`, `GL0` `TXM`, `Exclaves` `EIC`, and synchronous `EMTE` (`MIE`) invariants.

Two bounded forks exist solely on `macOS` [7, 9]. First, if a physical owner boots paired `1TR` ([Chapter 2](02-mac-localpolicy.md)) and configures `Permissive Security` with `bputil -c` (`sip2 = true` disabling `CTRR`) or `coih` (`Asahi Linux` `m1n1`), `iBoot` relaxes monitor handoff for that volume group alone so custom kernels can manage native `EL1`/`EL2` page tables; similarly, loading a third-party `AuxKC` disables `use_xnu_restricted` (`XNU_KERNEL_RESTRICTED`) in `arm_init_sptm.c` for legacy driver compatibility [7, 9, 168]. Second, `Rosetta 2` `x86_64` binary translation on `macOS` executes translated x86 guest pointers that lack `arm64e` `PAC` signatures and `[59:56]` `EMTE` pointer tags inside guest state, making native `arm64e` compilation essential for high-assurance `macOS` applications [176].

## In-the-Wild Failures & Architectural Bounds

Real-world attacks and offensive disclosures between 2019 and 2026 demonstrate a profound systems lesson: *CPU pointer and page-table monitors (`PAC`, `PPL`, `SPTM`, `EMTE`) hold inside their modeled state machines, so attackers systematically hunt unmodeled speculation paths, undocumented SoC `MMIO` blocks, unscrubbed accelerator registers, and software allocator races*.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `A12` `AUTIA`+`PACIZA` Signing Gadgets (Azad) | 2019 | `iOS 12` (`A12` `iPhone XS`) | `ARMv8.3-A` `PAC` unforgeability | Non-trapping `AUTIA` left single-bit error code that `PACIZA` inverted (`bit 62`), creating an arbitrary `APIAKey` signing oracle under kernel R/W | Added synchronous `FPAC` hardware fault (`A14`/`M1`+) and eliminated signing gadgets [160, 167] |
| `SockPuppet` (`CVE-2019-8605`, Williamson) | 2019 | `iOS 12.4` / `macOS` | Flat `kalloc.192` zone isolation | Dangling `struct ip6_pktopts` in `in6_pcbdetach()` reallocated with `OSData` and `mach_port_ool_t` arrays for arbitrary R/W | Shipped `kalloc_type` signature bucketing, `data.kalloc` split, and `kfree_type()` [161, 162, 172] |
| `PACMAN` Speculative Oracle (MIT CSAIL) | 2022 | `macOS` / `iOS` (`M1` / `A12`+) | `PAC` tag confidentiality | Speculative execution past `AUTIA` inside transient branch windows leaked valid `PAC` tags via L1 cache timing without faulting | Hardened speculative `FPAC` serialization and layered `SPTM` + `EMTE` [2, 180] |
| `PAC` / `RPAC` ITW Bypasses (`CVE-2022-48618`, `CVE-2025-31201`) | 2022-2025 | `iOS`, `iPadOS`, `macOS` | Kernel / read-only `PAC` state | Logic and state-handling flaws allowed attackers with arbitrary R/W to forge or bypass `PAC`/`RPAC` pointer checks in-the-wild | Patched `PAC`/`RPAC` state signing (`iOS 16.2` / `iOS 18.4.1`) and added `MIE` [181] |
| *Operation Triangulation* (`CVE-2023-38606`) | 2023 | `iOS` (`A12`-`A16`, `< 16.5.1`) | `PPL` physical page-table lock | Undocumented `gfx-asc` CoreSight `UTT` (`0x206040000`) and GPU cache-ECC DMA (`0x206150048`) `MMIO` wrote physical RAM past `PPL` | Fenced `0x206000000-0x206050000` & `0x206110000-0x206400000` in `DeviceTree` `pmap-io-ranges` [19, 182] |
| `TikTag` & `StickyTags` vs. `ARM MTE` | 2024 | `ARMv8.5-A` `MTE` ecosystems | `MTE` 4-bit tag confidentiality | Speculative execution timing differences on tag check leaked 4-bit memory tags in < 4 seconds without triggering faults | `A19`/`M5` `EMTE` Tag Confidentiality Enforcement makes speculation strictly tag-invariant [2, 177, 178] |
| `M5` Kernel Allocator Race (`Calif`) | 2026 | `macOS 26.4.1` (`M5`) | `MIE` (`EMTE`) tag synchronization | Concurrent kernel allocation race opened a brief window between `kalloc` slot handoff and `EMTE` tag enforcement | Serialized allocator tag-commit transitions in `macOS 26.4.2` / `iOS 26.4.2` [183] |
| `M1` GPU Register Residue (`CVE-2026-49269`) | 2026 | `macOS` / `iPadOS` (`M1` GPU) | Cross-process GPU register state | `M1` GPU failed to zero general-purpose compute-shader registers across context switches between distinct sandboxed `Metal` apps | Added shader register-file scrubbing barrier across cross-process GPU dispatches [20] |

### Speculative Oracles (PACMAN, TikTag), GPU Cache-DMA MMIO (CVE-2023-38606), and Register Residue

Three waves of offensive research between 2022 and 2026 prove why `SPTM` and `EMTE` must treat transient microarchitectural pipelines, undocumented `MMIO` decoders, and accelerator register files as first-class parts of the isolation boundary. First, at ISCA 2022, MIT CSAIL researchers (`Ravichandran` et al.) disclosed `PACMAN` on Apple `M1` silicon, demonstrating how speculative execution could brute-force 16-bit kernel `PAC` tags without triggering a single visible kernel panic [180]. Under `FPAC`, retiring a failed `AUTIA` traps immediately; however, when an attacker trained the CPU branch predictor to enter a wrong-path speculative window executing `AUTIA` followed by a pointer dereference (`LDR`), a wrong `PAC` guess stalled at an invalid non-canonical translation while the *single valid* 16-bit `PAC` tag translated cleanly and perturbed L1 data-cache / `TLB` replacement state before the mispredicted branch squashed the architectural fault [180]! That exact speculative-oracle lesson directly shaped Apple's `A19`/`M5` `EMTE` Tag Confidentiality Enforcement after `TikTag` (`arXiv:2406.08719`) and `StickyTags` (2024) used analogous speculative load timing to leak 4-bit `ARMv8.5-A` `MTE` tags on non-Apple mobile CPUs in under four seconds: by ensuring tag comparison outcomes never alter speculative cache fills or execution latency, `A19`/`M5` silicon denies attackers any crashless tag-testing oracle [2, 177, 178].

Second, in December 2023 at 37C3, Kaspersky GReAT researchers (`Larin`, `Bezvershenko`, `Kucherin`) dissecting the four-zero-day *Operation Triangulation* `iMessage` chain (`CVE-2023-41990` `ADJUST` TrueType font RCE $\to$ `CVE-2023-32434` `mach_make_memory_entry` integer overflow granting user-space physical memory mapping $\to$ `CVE-2023-38606`) uncovered how the attackers bypassed `PPL` on `A12`–`A16` iPhones without touching a single `PPL` gate [19]. After waking the `gfx-asc` GPU co-processor via power-manager `MMIO` (`0x23B700408` on `A16`) and halting its core via Apple's proprietary CoreSight `UTT` debug-wrap register at `0x206040000` (`ml_dbgwrap_halt_cpu`), the exploit wrote target physical addresses, 64-byte payloads, and two 10-bit S-box digests into completely undocumented `MMIO` registers at `0x206140008`, `0x206140108`, `0x206150040`, and `0x206150048` [19]. As Hector Martin (`marcan`) subsequently identified in January 2024, those "hashes" were hardware Hamming Error-Correcting Codes (`ECC`) for an unadvertised direct-to-cache hardware injection port that wrote physical cache lines directly past CPU `APRR`/`PPL` checks (mitigated by Apple fencing `0x206000000–0x206050000` and `0x206110000–0x206400000` inside `DeviceTree` `pmap-io-ranges` and `SPTM` I/O frame tables) [19, 169, 182].

Third, in June 2026, `CVE-2026-49269` exposed a complementary non-CPU isolation gap on `M1` GPUs: although `AppleDART` cleanly isolated GPU *memory pages* across processes, the `M1` GPU did not scrub its internal compute-shader general-purpose register file between `Metal` dispatches from separate sandboxed apps, allowing an unprivileged reader shader to recover a victim app's 128-bit cryptographic secret verbatim from residual shader registers [20]. Likewise, Calif's May 2026 kernel exploit on `macOS 26.4.1` (`M5`) showed that even with synchronous `EMTE` silicon active, a software race condition during concurrent kernel allocator tag assignment could briefly expose an untagged/mismatched window for data-only escalation prior to `26.4.2` [183]. Silicon memory safety is only as airtight as the `MMIO` tables, register scrubs, and allocator state machines surrounding it.

## Verification & Forensic Artifacts

On an Apple Silicon Mac, query `sysctl` to verify active `ARMv8.3-A` `PAC`, synchronous `FPAC`, and `A19`/`M5` `EMTE` (`FEAT_MTE` / `FEAT_MTE4`) silicon capabilities [2, 34, 160]:

```bash
sysctl hw.optional.arm.FEAT_PAuth hw.optional.arm.FEAT_PAuth2 hw.optional.arm.FEAT_FPAC
sysctl hw.optional.arm.FEAT_MTE hw.optional.arm.FEAT_MTE4 2>/dev/null || true
```

Representative output (`FEAT_MTE` and `FEAT_MTE4` report `1` on `M5`/`A19`+ `MIE` hardware):

```text
hw.optional.arm.FEAT_PAuth: 1
hw.optional.arm.FEAT_PAuth2: 1
hw.optional.arm.FEAT_FPAC: 1
```

Verify `Exclaves` runtime availability and confirm that critical system daemons execute as pointer-authenticated `arm64e` Mach-O slices [160, 171]:

```bash
sysctl kern.exclaves_status 2>/dev/null || true
file /usr/libexec/securityd /System/Library/CoreServices/Finder.app/Contents/MacOS/Finder
```

Expected output:

```text
kern.exclaves_status: 1
/usr/libexec/securityd: Mach-O 64-bit executable arm64e
/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder: Mach-O 64-bit executable arm64e
```

When triaging `.ips` JSON crash reports under `/Library/Logs/DiagnosticReports` (or inside an `iOS` `sysdiagnose`), both synchronous `FPAC` pointer traps (`ESR_EL1` `EC = 0x1C`) and `MIE` `EMTE` synchronous tag-check faults (`ESR_EL1` `DFSC = 0b010001` tag check fault) emit deterministic crash telemetry [2, 34, 160]:

```bash
grep -E '"exception"|"subtype"|"esr"' /Library/Logs/DiagnosticReports/*.ips 2>/dev/null | head -n 4
```

Part I has traced how Apple Silicon boots from immutable mask `Boot ROM` ([Chapter 1](01-secure-boot.md)), scopes `macOS` openness inside `1TR` `LocalPolicy` ([Chapter 2](02-mac-localpolicy.md)), isolates `UID` key custody inside `SEP` ([Chapter 3](03-secure-enclave.md)), and enforces `GL2` `SPTM`, `Exclaves`, and synchronous `EMTE` memory safety ([Chapter 4](04-silicon-memory-safety.md)). Part II now ascends into `XNU` and user space, beginning in [Chapter 5](05-apfs-ssv-dyld.md) with how the root filesystem (`APFS` `SSV`), `Cryptexes`, and `dyld4` shared cache inherit that silicon trust.
