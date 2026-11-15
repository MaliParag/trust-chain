# Hardware Arm MTE and Hardened Heap Allocation in Production

## Overview

* **Link in the Chain:** Hardware-assisted spatial and temporal memory-safety enforcement layer; pairs the `Scudo` hardened heap allocator with `ARMv8.5-A`/`ARMv9` Memory Tagging Extension (`MTE`) 4-bit pointer and memory-granule tags in production.
* **Core Security Invariant:** Every 16-byte allocation granule in `MTE`-enabled heap/stack regions carries a 4-bit physical tag $T_{\text{mem}} \in \{1, \dots, 15\}$, and every CPU load/store compares pointer bits `[59:56]` ($T_{\text{ptr}}$) against $T_{\text{mem}}$, raising a hardware tag-check fault whenever $T_{\text{ptr}} \ne T_{\text{mem}}$ due to out-of-bounds access or post-`free()` re-tagging.
* **Ecosystem Enforcement Tier:** Available on `ARMv9` `MTE`-capable silicon (`Google Pixel 8` / `Tensor G3` and newer, selected flagship `Arm` cores) across both `GREEN` stock OS (opt-in per-app, system daemons, `bootloader` upgrade-on-fault, and always-on under `Advanced Protection Mode`) and `YELLOW` `GrapheneOS` (default synchronous `MTE` enforced broadly across system and installed packages); independent of `ORANGE` lock state.
* **Trusted Computing Base (TCB):** `ARMv8.5-A`/`ARMv9` CPU `MTE` tag-comparison logic and physical Tag RAM carveout ($\approx 3.125\%$ of DRAM), `GKI` `EL1` tag-management context switching (`SCTLR_EL1.TCF0`, `GCR_EL1`), `Bionic` `libc` + LLVM `Scudo` hardened allocator, and `debuggerd` tombstone / bootloader one-shot telemetry.
* **Seam & Handoff:** Turns probabilistic C/C++ heap overflows and use-after-frees into immediate `SIGSEGV` (`SEGV_MTESERR` / `SEGV_MTEAERR`) crashes with `15/16` ($93.75\%$) single-shot detection probability; closes Part II and hands application-level `UID`, `WebView`, and `Binder` sandboxing to Part III ([Chapter 9](09-uid-zygote-binder.md)).

## Threat Model & Ecosystem Constraint

While [Chapter 7](07-treble-gki-rust.md) showed how Rust eliminates memory-safety bugs in *newly written* AOSP daemons, hundreds of millions of lines of mission-critical C and C++ code remain active on every Android phone: the Chromium `Blink` DOM and `Skia`/`ANGLE` graphics engines inside `WebView` and Chrome, complex third-party native game/AR SDKs (`Unity`, `Unreal`, `JNI` libraries), legacy media/image codecs (`libwebp`, `libavc`, `libhevc`), and system C++ frameworks [65, 67]. Across Google's Threat Analysis Group (`TAG`) and Project Zero zero-day tracking, memory corruption (specifically heap buffer overflows and temporal Use-After-Free `UAF` bugs) inside C/C++ native libraries accounts for the overwhelming majority of initial remote code-execution footholds on smartphones [67, 142].

Prior to hardware support, software-only sanitizers such as `AddressSanitizer` (`ASan`) and `HWASan` caught spatial and temporal heap bugs reliably during CI testing, yet imposed $2\times$ CPU slowdowns and $2\times\text{ to }3\times$ RAM overhead, disqualifying them completely from shipping on retail consumer handsets [64, 66]. Traditional hardened allocators (`jemalloc` hardening or early `Scudo` without `MTE`) added randomized free lists and CRC-checked chunk headers, stopping classic `unlink()` metadata attacks while remaining blind when a dangling `UAF` pointer overwrote application object fields inside a recycled heap slot of the same size class [65].

Shipping fine-grained spatial and temporal memory safety *in production on battery-powered consumer phones* imposed severe engineering budgets: less than `3% to 5%` DRAM overhead for tag metadata, low single-digit CPU overhead on latency-sensitive UI threads, backward binary compatibility with unmodified precompiled NDK `.so` libraries, and deterministic crash containment against multi-attempt attackers [64, 65, 67].

## Architecture & AOSP Implementation

### `ARMv8.5-A` / `ARMv9` Memory Tagging Extension (`MTE`) Lock-and-Key Mechanics

Introduced in the `ARMv8.5-A` specification and mandated across modern `ARMv9-A` Cortex-X/A cores (deployed commercially first on Google Pixel 8 `Tensor G3` in late 2023 and expanded across Pixel 9/10+ and flagship `ARMv9` SoCs [67]), `Arm MTE` implements architectural lock-and-key memory coloring directly inside the CPU core and memory controller [5, 64].

`MTE` exploits AArch64's existing *Top-Byte-Ignore* (`TBI`, `TCR_EL1.TBI0 = 1`) feature, under which the MMU ignores bits `[63:56]` during virtual-to-physical page translation. `MTE` repurposes bits `[59:56]` of every 64-bit virtual pointer as a 4-bit *Logical Address Tag* (`key`, $T_{\text{ptr}} \in \{0, 1, \dots, 15\}$), while partitioning physical memory (for pages mapped with the `PROT_MTE` `mmap()` attribute) into 16-byte *Allocation Granules*, each associated with a 4-bit *Physical Allocation Tag* (`lock`, $T_{\text{mem}} \in \{0, 1, \dots, 15\}$) stored inside a dedicated hardware carveout in DRAM ($4\text{ bits}$ per $128\text{ bits} = 1/32 = 3.125\%$ physical RAM overhead, cached inside on-chip CPU Tag Caches) [64].

![Figure: ARMv8.5-A Memory Tagging Extension (MTE) 4-bit pointer logical tag vs. 16-byte physical granule allocation tag check.](diagrams/08-mte-pointer-granule-check.svg)

Dedicated unprivileged ARM64 instructions manage tags at single-cycle throughput [5, 64]: `IRG Xd, Xn, Xm` (*Insert Random Tag*) draws a non-zero 4-bit pseudorandom tag from hardware `GCR_EL1` LFSR/TRNG state while excluding forbidden tag masks in `Xm` (so adjacent chunks never receive identical tags!); `ADDG` / `SUBG` adjust pointer offsets and tags; and `STG`, `ST2G`, `STZG` (*Store Allocation Tag and Zero*) write the 4-bit lock tag into Tag RAM across $16\text{-byte}$ or $32\text{-byte}$ granules simultaneously with zeroing heap memory.

On every load (`LDR`) or store (`STR`) targeting `PROT_MTE` memory via a register other than untagged `SP`-relative stack accesses where configured, hardware compares $T_{\text{ptr}} \stackrel{?}{=} T_{\text{mem}}$. When $T_{\text{ptr}} \ne T_{\text{mem}}$, CPU behavior is governed per-thread by `SCTLR_EL1.TCF0` across three hardware modes [64, 66, 69]. Under *Synchronous Mode* (`SYNC`), the CPU halts the offending instruction *precisely before* any memory write commits or invalid read value enters architectural registers, delivering an immediate synchronous Data Abort to `EL1`, which delivers `SIGSEGV` (`si_code = SEGV_MTESERR`) with the exact faulting address and program counter; because no corrupt store ever reaches RAM, `SYNC` mode functions as an active exploit-prevention barrier at roughly `~2% to 6%` CPU cost depending on workload memory intensity [66, 67]. Under *Asynchronous Mode* (`ASYNC`), to achieve near-zero (`< 1%`) CPU pipeline stall on out-of-order cores, the CPU allows the speculative/retired load or store to complete and asynchronously sets a sticky fault bit in `TFSR_EL1` (*Tag Fault Status Register*); on the very next kernel entry (syscall, timer tick, interrupt, or context switch), `GKI` checks `TFSR_EL1 != 0` and terminates the process with `SIGSEGV` (`SEGV_MTEAERR`) [64, 66]. Under *Asymmetric Mode* (`ASYMM`, `ARMv8.7-A`/`ARMv9.2-A`), hardware enforces precise synchronous traps on memory *reads* (`LDR`) while using fast asynchronous reporting on memory *writes* (`STR`) [66, 69]. As Google Project Zero analyzed in detail ("The Story of MTE Asymmetry" [69]), security-critical surfaces must prefer pure `SYNC` over `ASYNC` or `ASYMM` against active exploits: under `ASYNC` (or an asynchronous write in `ASYMM`), a race thread on a second CPU core can consume a corrupted heap write in the microsecond window *before* the faulting thread hits its next syscall check, whereas pure `SYNC` closes that race window to zero nanoseconds.

### The `Scudo` Hardened Allocator (`Bionic` `libc`)

Since Android 11 (`API 30`), AOSP's `Bionic` C library uses LLVM's `Scudo` (`compiler-rt/lib/scudo/standalone`) as the universal native `malloc()` / `free()` / `operator new` allocator across system daemons and applications, engineered from day one to drive `Arm MTE` [65, 66].

Even on older `ARMv8.0` chips lacking `MTE`, `Scudo` enforces four software defenses [65]: *size-class isolation with shuffled allocation batches* (allocating chunks in randomized order within memory regions so heap layouts are unpredictable), *16-byte checksummed chunk headers* (`CRC32` computed using hardware `ARMv8` CRC instructions over a per-process secret cookie, chunk address, size, and state, catching header overwrites, double-`free()`, and invalid pointers immediately), *guard pages* surrounding Secondary (large) `mmap` allocations, and *thread/global Quarantine queues* holding recently `free()`d chunks out of immediate reuse to disrupt deterministic `UAF` slot reclamation [65].

![Figure: Scudo hardened allocator and hardware Arm MTE lifecycle catching spatial overflows and temporal use-after-free bugs.](diagrams/08-scudo-mte-lifecycle.svg)

On `ARMv9` `MTE` silicon, `Scudo` activates full hardware memory coloring automatically whenever the process runs with `MTE` enabled [65, 66]. For *spatial isolation* with zero-byte redzones, unlike `ASan` (which wastes `16 to 32 bytes` of dead redzone padding between allocations), `Scudo` packs `16-byte`-aligned allocations tightly and uses `IRG`'s exclude mask (`Xm = (1 << prev_tag) | (1 << next_tag)`) so adjacent heap chunks are guaranteed deterministically ($100\%$ probability!) to hold distinct 4-bit tags $T_i \ne T_{i+1}$; any linear buffer overflow or underflow of $1\text{ to }16$ bytes into an adjacent chunk faults with $100\%$ certainty [65, 66]. For *temporal `UAF` detection*, the instant `free(ptr)` executes, `Scudo` generates a fresh random tag $T_{\text{new}} \ne T_{\text{old}}$ (or reserves a dedicated `0` quarantine tag) and executes `STZG` across the freed chunk before placing it in quarantine. Any lingering dangling pointer `ptr` still carries $T_{\text{old}}$ in bits `[59:56]`: dereferencing `*ptr` fails $T_{\text{old}} \ne T_{\text{new}}$ immediately, and `debuggerd` records a rich `MTE` Tombstone containing the exact allocation `backtrace` and `free()` `backtrace` from `Scudo`'s ring buffer [65, 66].

### Production Deployment: Manifest Opt-In, Bootloader Escalation, and Advanced Protection

Android exposes three operational mechanisms turning `MTE` into a fleet-wide defensive shield [66, 67, 89]:

First, critical system daemons and network/NFC/Bluetooth services compile with both Heap `MTE` and Stack `MTE` (`-fsanitize=memtag-heap,memtag-stack`), while any application developer can enable `MTE` in production with zero recompilation via `AndroidManifest.xml` (`android:memtagMode="sync"` or `"async"` on `<application>` or individual `<process>` elements) [66].

Second, Pixel 8+ introduced *Bootloader One-Shot / Upgrade-on-Fault Telemetry* (`memtag_once`) [66, 67]: when an `ASYNC` `MTE` check or memory-corruption signal triggers in the field without full `SYNC` mode active, the OS can arm a temporary upgrade so subsequent executions run precise `SYNC` mode to pinpoint and contain active exploitation or capture exact crash telemetry.

Third, enabling Android 16/17 `Advanced Protection Mode` ([Chapter 11](11-accessibility-advanced-protection.md)) or Developer Options *Memory Tagging Extension* turns hardware `MTE` on system-wide across eligible applications (`memtagMode="default"` packages automatically upgrade to hardware `MTE`!), while `GrapheneOS` (`YELLOW` locked Pixel 8/9/10+) goes furthest of all: enabling synchronous Heap `MTE` (`SYNC`) by default across pre-installed system components and user-installed apps out of the box, paired with its own hardened `hardened_malloc` allocator [16, 67, 89]!

## Vendor, OEM, & Custom-OS Boundaries

Hardware `MTE` illustrates a critical silicon supply-chain lesson in *The Android Trust Chain*: *CPU core support (`Cortex-X4` / `Cortex-A720`) does not automatically mean SoC `MTE` availability* [64, 67]! For `MTE` to work at runtime, the SoC vendor (`Google Tensor`, `MediaTek Dimensity 9300+`, `Qualcomm Snapdragon`, `Samsung Exynos`) must wire the DRAM controller, coherent interconnect (`CMN`/`NoC`), Tag Cache, and bootloader `TZ`/`EL3` DRAM carveout (`SCR_EL3.ATA = 1`) to reserve the $3.125\%$ Tag RAM and expose `ID_AA64PFR1_EL1.MTE >= 2` to `EL1`/`EL2` [5, 67].

Google led commercial smartphone adoption by enabling full end-to-end production `MTE` on `Tensor G3` (Pixel 8), `Tensor G4` (Pixel 9), and successor `Tensor` generations, followed by MediaTek on `Dimensity 9300`+ designs, whereas several competing `ARMv9` smartphone SoCs initially fused `MTE` off in early firmware due to Tag-Cache latency or DRAM carveout tuning before progressive `CDD` / `Android 15-16` ecosystem pressure expanded adoption [67].

## Exploit Chains & Structural Limits

Because `MTE` stores a 4-bit tag per granule, its mathematical guarantees and microarchitectural side channels must be analyzed with rigor rather than marketing hype.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Non-Linear Heap Spray (`1/16` Random Collision Bound) | Structural | 4-bit tag entropy ($T \in \{1..15\}$) | Remote JS / media exploit jumping past neighbor chunk | Non-adjacent arbitrary offset or un-excluded tag reuse has $p = 1/15 \approx 6.67\%$ ($1/16 = 6.25\%$) single-guess pass rate | Crash-intolerance: respawn throttling, process death logging, & compounding failure $(1/16)^k$ across multi-step exploits [66, 69] |
| `ASYNC` / `ASYMM` Cross-Thread Race Window (Project Zero) | 2023 | `SCTLR_EL1.TCF0` `ASYNC`/`ASYMM` write deferral | Multi-threaded exploit racing corrupted write before `TFSR_EL1` trap | `ASYNC` writes commit to cache before faulting thread enters kernel | Enforce strict `SYNC` mode on security-critical daemons, `GrapheneOS`, & `Advanced Protection` [66, 69] |
| `TIKTAG` Speculative Execution Tag Oracle (`TIKTAG-v1` / `v2`) | 2024 | Out-of-order CPU branch predictor + prefetcher / store-to-load | Speculatively executing `LDR` inside mispredicted branch and measuring cache timing | Speculative `MTE` mismatch suppresses cache fill without raising architectural `SIGSEGV`, leaking 4-bit tag in $< 4\text{ ms}$ via cache side channel | Browser site isolation / high-res timer coarsening, Chrome `WebGPU`/JIT disable in `Advanced Protection`, & CPU microcode/silicon mitigations [68, 89] |
| Intra-Object Field / Container Confusion (`struct` sub-object bounds) | Structural | C `struct` containing `char buf[32]` followed by `fn_ptr` or `container_of` cast | Overflow within a *single* `malloc()` allocation or type-confused container | All 16-byte granules inside one `malloc()` block share the same allocation tag $T$ | Pair `MTE` with `-fbounds-safety` / `__counted_by`, allocator type isolation, `KCFI` ([Chapter 7](07-treble-gki-rust.md)), and Rust migration [61, 64, 70] |

### Probability Bounds and Speculative Tag Oracles (`TIKTAG`)

Let us formalize both the power and the boundary of 4-bit `MTE` [68, 69]. For a linear buffer overflow crossing into an immediately adjacent `Scudo` heap chunk, `Scudo`'s neighbor-exclusion mask guarantees $T_{\text{adj}} \ne T_{\text{cur}}$, yielding detection probability $P_{\text{detect, linear}} = 1$. For a non-linear out-of-bounds offset or recycled `UAF` slot drawn uniformly over the 15 non-zero tags (or 16 total values), a single blind attacker dereference succeeds with probability at most $p \le \frac{1}{15} \approx 0.0667$ (and if an exploit chain requires $k = 3$ independent blind `UAF`/OOB corruptions to construct an arbitrary R/W primitive, success drops exponentially to $p^3 \le (1/15)^3 \approx 0.0296\%$, while the `99.97%` failure path immediately crashes the process and writes an `MTE` crash tombstone!).

That exponential security bound holds *if and only if every failed guess causes an observable process crash* (no crashless tag oracle!) [68, 69]. In 2024, Juhee Kim et al. demonstrated `TIKTAG` (`TIKTAG-v1` exploiting speculative load-to-load cache prefetch gadgets and `TIKTAG-v2` exploiting store-to-load forwarding differences on Cortex-X2/X3 cores) [68]: when a tagged `LDR` executes *inside a mispredicted conditional branch*, an `ARMv8.5-A` CPU suppresses the architectural `SEGV_MTESERR` exception (because the branch was speculative!), yet still aborts or alters L1/L2 cache line allocation depending on whether $T_{\text{ptr}} == T_{\text{mem}}$! Inside a JIT-compiled JavaScript environment (such as V8 with high-resolution `SharedArrayBuffer` timers), an attacker could probe all 16 candidate tags speculatively without crashing the renderer and leak the valid 4-bit tag before issuing the architectural exploit write [68].

Look how Android's layered defense-in-depth responds to `TIKTAG` across Part II and Part III: `Advanced Protection Mode` ([Chapter 11](11-accessibility-advanced-protection.md)) disables V8 JavaScript JIT compilation and `WebGPU` on untrusted sites (removing the fast speculative gadget compiler needed to mount `TIKTAG` from web content!) [89], while even if an attacker somehow bypassed `MTE` inside a `WebView` or Chrome renderer, that renderer runs inside a zero-permission `u0_i*` `isolatedProcess` sandbox ([Chapter 9](09-uid-zygote-binder.md)) blocked by `seccomp-BPF` and `SELinux` ([Chapter 6](06-selinux-seccomp.md)), with high-value keys locked inside `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) and `StrongBox` ([Chapter 3](03-trustzone-strongbox.md)). Part III now ascends into userspace to examine how Android builds that application sandbox, IPC capability fabric, APK signing chain, UI protection, file encryption, and biometric/passkey stack.

## Inspecting via ADB, Fastboot, & Attestation

Check whether the handset's CPU and bootloader expose hardware `Arm MTE` (`mte` in `/proc/cpuinfo` `Features`, alongside `arm64.memtag` bootctl / system properties):

```bash
adb shell grep -m 1 'Features' /proc/cpuinfo | tr ' ' '\n' | grep -E '^mte|^paca|^bti'
adb shell getprop | grep -iE 'memtag|mte' | head -n 8
```

Inspect whether a specific running process (such as `nfc`, `bluetooth`, or an opted-in app) has active `PROT_MTE` tagged heap mappings (`mt` flag inside `/proc/<pid>/smaps` `VmFlags` where readable on debuggable processes):

```bash
adb shell dumpsys meminfo com.android.nfc | head -n 12
```

On `MTE`-capable Pixel devices (`Tensor G3`+), query the bootloader `boot_control` / `memtag` status property indicating whether system-wide or one-shot `MTE` mode is armed across reboots:

```bash
adb shell getprop ro.arm64.memtag.bootctl_supported
adb shell getprop arm64.memtag.bootctl
```
