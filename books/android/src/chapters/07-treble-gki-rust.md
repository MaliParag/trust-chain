# Project Treble HALs, Generic Kernel Image, KCFI, and Kernel Rust

## Overview

* **Link in the Chain:** Structural compartmentalization, kernel ABI unification, and memory-safety engineering layer; splits vendor BSP code out of privileged framework processes and hardens `EL1`/`EL0` binaries against control-flow hijacking and memory corruption.
* **Core Security Invariant:** Vendor hardware abstractions execute in isolated `/vendor` `Binder` daemons with zero network capability across versioned `VINTF` Stable `AIDL` contracts; every Android 12+ launch device boots a Google-signed `Generic Kernel Image` (`GKI` 2.0) core governed by `STG` `KMI` symbol verification and compiled with Clang `KCFI` and `x18` `Shadow Call Stack` (`SCS`); and safe Rust eliminates spatial and temporal memory bugs at compile time across newly authored AOSP daemons and `GKI` drivers.
* **Ecosystem Enforcement Tier:** Enforced identically in `GREEN` and `YELLOW` locked states via `AVB` `vbmeta` / `boot.img` signatures and `CTS`/`VTS` (`VtsGenericBootImageTest` verifies Google `GKI` certification); `ORANGE` unlocked state permits replacing `boot.img` with custom debug kernels at the cost of verified boot state.
* **Trusted Computing Base (TCB):** Google-built `GKI` `vmlinux` (`boot.img`) and signed protected `GKI` modules (`system_dlkm`), `STG`-verified `KMI` symbol lists (`abi.stg`), vendor loadable kernel modules (`vendor_boot` / `vendor_dlkm`), Clang `KCFI` + `SCS` passes, `KFENCE` fleet sampler, `rustc` safe abstractions (`drivers/android/binder/`), and `VINTF` `AIDL` IPC stubs.
* **Seam & Handoff:** Compresses core kernel patch lag and drives memory-safety CVEs from `76%` of Android vulnerabilities in 2019 down below `20%` by 2025, while leaving legacy C/C++ userspace codecs and out-of-tree vendor `.ko` GPU/ISP drivers to be defended at runtime by hardware `Arm MTE` and `Scudo` in [Chapter 8](08-arm-mte-scudo.md).

## Threat Model & Ecosystem Constraint

In July 2015, Joshua Drake's disclosure of the *Stagefright* remote code-execution vulnerabilities (`CVE-2015-1538` and siblings inside `frameworks/av/media/libstagefright`) exposed two existential architectural flaws in first-decade Android [2, 12, 242]:

First, *monolithic in-process vendor HAL coupling maximized blast radius*. Through Android 6.0 (`Marshmallow`), a single privileged `mediaserver` daemon (`UID 1013`) parsed untrusted MP4, MKV, and MP3 byte streams from MMS messages and web pages while simultaneously holding `camera`, `audio`, `inet`, `bluetooth`, `drm`, and GPU/ISP `/dev` group memberships, and loading proprietary SoC vendor C/C++ shared libraries (`/system/lib64/hw/*.so` and OpenMAX `libstagefrighthw.so`) directly into its own address space via `dlopen()` [12, 238]. When an unchecked 32-bit integer multiplication in `SampleTable::setSampleToChunkParams()` (`CVE-2015-1538` [242]) under-allocated a heap buffer inside `mediaserver`, a single malformed MMS video granted the remote attacker immediate access to the microphone, camera, and wide kernel driver `ioctl` surfaces, while ABI coupling between framework C++ internals and `dlopen()`ed vendor `.so` blobs prevented Google from shipping OS updates until every SoC vendor recompiled their proprietary HALs [12, 243].

Second, *four-tier Linux kernel fork fragmentation paralyzed upstream security patching*. Unlike server or desktop Linux distributions that boot upstream `kernel.org` releases directly, pre-GKI Android kernels descended through a four-stage fork cascade [10, 13]: upstream Linux Long-Term Support (`LTS`, such as `4.4` or `4.14`) forked into Google's Android Common Kernel (`ACK`), which forked into massive SoC vendor Board Support Package (`BSP`) trees (`CodeAurora` / `CLO`, where out-of-tree vendor modifications routinely swelled to *50 percent of total kernel code*!), which forked yet again into per-OEM and per-handset trees for display panels, chargers, and camera sensors [13]. Backporting a single upstream slab UAF fix across hundreds of diverged handset kernels delayed `LTS` adoption by up to `18 months`, even though Pixel telemetry proved that `90%` of kernel vulnerabilities cited in the Android Security Bulletin (`ASB`) were *already fixed* on devices keeping current with upstream `LTS` [13, 43]!

Eliminating in-process HAL blast radius, collapsing the 18-month kernel patch gap, and drying up the underlying C/C++ memory-corruption supply required four coordinated engineering transformations across Android 7 through Android 17: media/HAL process disaggregation (`Project Treble`), the `Generic Kernel Image` (`GKI` 2.0), forward- and backward-edge Control-Flow Integrity (`KCFI` and `SCS`), and industrial-scale migration of new systems code to *Rust* [12, 13, 32, 244, 245].

## Architecture & AOSP Implementation

### Post-*Stagefright* De-Privileging and `Project Treble` (`VNDK`, `HIDL`, and Unified Stable `AIDL`)

Android's structural compartmentalization began in Android 7.0 (`Nougat`) by shattering `mediaserver` along strict least-privilege boundaries (`frameworks/av/media/`) [238] and generalized across the entire hardware stack in Android 8.0 (`Oreo`) under `Project Treble` [12].

![Figure: De-privileging media and hardware stacks from monolithic pre-Treble mediaserver to Mainline sandboxes and Binderized Treble AIDL HALs.](diagrams/07-extra-mediaserver-to-hal-isolation.svg)

Trace how Android 7.0+ dismantled the *Stagefright* attack path (`source.android.com/docs/core/media/framework-hardening`) [81, 238]. Monolithic `mediaserver` was split into six isolated processes: `media.extractor` (container demuxers such as `MPEG4Extractor` and `MatroskaExtractor`), `media.codec` / `media.swcodec` (software/hardware video decoders, packaged since Android 10 inside an updatable `Project Mainline` `APEX` [81]), `mediadrmserver` (`Widevine` / `OEMCrypto` decryption passing cross-process `native_handle_t` secure buffer file descriptors via `Parcel::writeNativeHandle()`), `audioserver`, `cameraserver`, and a stripped `mediaserver` coordinator [238]. Crucially, `media.extractor` holds *zero* open file descriptors to storage, *zero* `/dev` hardware nodes, and *zero* network permissions: it cannot even `open()` the MP4 file it parses, instead reading byte ranges over a restricted `Binder` `IDataSource` pipe beneath a tight `minijail` `seccomp-BPF` allowlist ([Chapter 6](06-selinux-seccomp.md)) [72, 238]!

`Project Treble` extended that exact out-of-process isolation rule across every SoC hardware abstraction on the phone [12, 243, 246]. Save for a tiny, Google-enumerated allowlist of latency-critical Same-Process `SP-HAL` rendering libraries (`vulkan.${driver}.so`, `libGLESv2_${driver}.so`, and `android.hardware.graphics.mapper`, which map exclusively into client Linker Namespaces `android_create_namespace()` linked only against stable `LL-NDK` `libc`/`liblog`/`libnativewindow` and `VNDK-SP` libraries [243]), framework processes (`system_server`, `cameraserver`, `audioserver`) are *prohibited from `dlopen()`ing vendor `.so` libraries* [12, 243]. Instead, every hardware subsystem (`Camera`, `Audio`, `Codec2`, `Sensors`, `Gnss`, `Biometrics`, `KeyMint`, `Weaver`, `Wi-Fi`, `IRadio`) executes inside its own `/vendor/bin/hw/*` daemon under a dedicated Linux `UID` (`AID_CAMERA`, `AID_AUDIO`, `AID_BLUETOOTH`), confined inside a per-HAL `SELinux` domain (`hal_camera_default`, `hal_sensors_default`) stripped of `AF_INET` network sockets and `CAP_SYS_ADMIN` [12, 24].

Notice how `Treble`'s IPC and library layers matured between Android 8 and Android 16 [12, 73, 243, 246, 247]: Android 8.0 initially introduced `HIDL` (`Hardware Interface Definition Language`) communicating over `/dev/hwbinder` (`hwservicemanager`), alongside `/dev/vndbinder` (`vndservicemanager`) for vendor-to-vendor `AIDL` IPC and `VNDK` `APEX` snapshots (`/apex/com.android.vndk.v*`) on `/system` [73, 243]. Starting in Android 10-11 and completed across Android 14-16, AOSP unified framework and HAL IPC onto *Stable `AIDL`* (`stability: "vintf"` in `Android.bp`) directly over `/dev/binder`, deprecated `/dev/vndbinder` (eliminating duplicate service managers and thread pools [73, 247]), and in Android 15 deprecated the `VNDK` `APEX` (`ro.vndk.version`) so vendor partitions bundle their own self-contained library copies cleanly [243]! Every Stable `AIDL` HAL (`hardware/interfaces/*`) uses strictly typed *structured parcelables* whose frozen wire definitions and SHA-256 API hashes live under `aidl_api/<module>/<version>/`, generating type-safe stubs across C++, NDK, Java, and *Rust* backends (`backend.rust.enabled: true`) [246]. Both `/system` and `/vendor` publish machine-readable XML *Vendor Interface (`VINTF`)* manifests and compatibility matrices verified by `libvintf` at build, OTA install, and `VTS` certification, guaranteeing that a clean Google Generic System Image (`GSI`) boots atop any compliant OEM `/vendor` partition without recompiling a single HAL [11, 12, 248].

### `Generic Kernel Image` (`GKI` 2.0): `STG` KMI Enforcement, Vendor Hooks, and Out-of-Tree `.ko` Boundaries

While `Project Treble` decoupled `/system` from `/vendor` in `EL0` userspace, SoC kernel forks continued to bottleneck `EL1` security updates until `GKI 2.0` became mandatory for all devices launching with Android 12 (`Linux 5.10`) and newer (`android13-5.15`, `android14-6.1`, `android15-6.6`, `android16-6.12`) [13, 249].

![Figure: Project Treble VINTF Stable AIDL process split and Generic Kernel Image (GKI 2.0) frozen KMI module architecture.](diagrams/07-treble-gki-split.svg)

Under `GKI 2.0`, partners are forbidden from modifying core kernel subsystems (`mm/`, `sched/`, `fs/`, `net/`, `security/`, `io_uring/`, `drivers/android/binder/`, `arch/arm64/kvm/hyp/nvhe/`) [13, 250]. Google compiles the canonical `aarch64` `GKI` `vmlinux` (`boot.img`) and signed *Protected GKI Modules* (`system_dlkm`, authenticated with Google's ephemeral kernel build-time key pair so the module loader grants them access to non-KMI internal kernel symbols while refusing vendor overrides, alongside *Unprotected GKI Modules* when partners temporarily require newer upstream features post-freeze [251]) from a single `gki_defconfig` using a hermetic `Kleaf`/Bazel build and pinned AOSP LLVM Clang toolchain [13, 249]. During certification, `VTS` (`VtsGenericBootImageTest`) verifies cryptographically that the handset's `boot.img` carries Google's embedded `GKI` release certificate [11, 13]. All SoC and OEM hardware drivers (clocks, interconnect, `UFS` storage, camera ISPs, `Mali`/`Adreno` GPUs, Wi-Fi/PCIe) load exclusively as unsigned out-of-tree `.ko` *Vendor Modules* from `AVB`/`dm-verity`-protected `vendor_boot` (early boot `initramfs` modules required to mount storage) and `vendor_dlkm` partitions, which the kernel module loader admits *only* if every unresolved external symbol appears on the frozen `KMI` allowlist [23, 249, 251].

Maintaining a frozen binary *Kernel Module Interface (`KMI`)* across years of upstream `LTS` security backports (something upstream Linux explicitly declines to do) relies on three tight mechanisms [249, 250, 252, 253]:

First, *explicit Partner Symbol Lists and `TRIM_UNUSED_KSYMS`*: out of `30,000+` `EXPORT_SYMBOL_GPL` functions in Linux, `GKI` exposes *only* the union of symbols declared in partner symbol lists (`gki/aarch64/symbols/*`) [252]. `CONFIG_TRIM_UNUSED_KSYMS` strips every non-listed internal symbol from the module export table, so unsigned vendor `.ko` modules attempting to resolve internal `mm` or `cred` symbols fail `insmod` immediately [249, 251, 252].

Second, *continuous `STG` (`Symbol-Type Graph`) ABI equivalence verification*: AOSP's `STG` engine (`external/stg`, generating `gki/aarch64/abi.stg` and replacing legacy `libabigail` XML in Android 14+ [252, 253]) extracts the complete transitive graph of function signatures, nested `struct`/`union`/`enum` byte sizes, member bit offsets, and `MODVERSIONS` symbol CRCs from `vmlinux`. On every Gerrit commit to a frozen `ACK` branch, `STG` diffs the built binary graph against the committed `abi.stg` and blocks the patch (`Lint-1`) if a single exported struct shifts by even 1 byte (for instance adding an `int` inside `struct mm_struct` shifts downstream offsets and alters thousands of transitive symbol CRCs!) [252, 253]. To let upstream security patches add state to hot kernel structs (`task_struct`, `mm_struct`, `inode`, `file`) after `KMI` freeze without breaking `.ko` binary offsets, `GKI` pre-allocates `u64` padding slots via `ANDROID_KABI_RESERVE(n)` (consumed via `ANDROID_KABI_USE(n, type field)` during security backports) alongside `ANDROID_VENDOR_DATA(n)` and `ANDROID_OEM_DATA(n)` (for partner module private state, with OEMs strictly forbidden from colliding with SoC `ANDROID_VENDOR_DATA` slots) [250, 252]:

```c
/* Illustrative GKI KMI-preserving struct reservation & vendor hook pattern */
#include <linux/android_kabi.h>
#include <linux/android_vendor.h>
#include <trace/hooks/sched.h>

/* Inside a KMI-monitored core kernel struct (e.g. include/linux/sched.h): */
struct task_struct_gki_tail {
    ANDROID_KABI_RESERVE(1);       /* Reserved u64 for future LTS security backports */
    ANDROID_VENDOR_DATA_ARRAY(1, 4); /* Per-task u64[4] scratchpad for SoC .ko modules */
    ANDROID_OEM_DATA(1);           /* Separate u64 slot reserved for handset OEM .ko */
};

/* Invoked in kernel/exit.c without modifying core scheduler logic: */
trace_android_vh_sched_exit(tsk);  /* Dispatches registered SoC tracepoint callback  */
```

Third, *Tracepoint Vendor Hooks (`trace_android_vh_*` and `trace_android_rvh_*`)*: where SoC vendors previously hacked custom scheduler, thermal, or memory-reclaim heuristics directly into `kernel/sched/core.c`, `GKI` exposes typed tracepoint hooks (`DECLARE_HOOK(android_vh_*, ...)` for normal detachable hooks and `DECLARE_RESTRICTED_HOOK(android_rvh_*, ...)` for non-atomic or offline-CPU scheduler paths where attached modules are permanently pinned against unloading) in `include/trace/hooks/` [250].

Yet note the critical security seam inside `EL1` [43, 44, 251]: although vendor `.ko` modules (`mali_kbase.ko`, `msm_kgsl.ko`) cannot modify `vmlinux` source files, once loaded into `EL1` kernel virtual memory they execute at *the exact same `EL1` CPU exception level and share the same Stage-1 kernel page tables* as `vmlinux`! A heap UAF inside `mali_kbase.ko` still grants full `EL1` arbitrary read/write over core `GKI` structures unless isolated by `EL2` `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) [4, 43].

### Forward/Backward Control-Flow Integrity (`KCFI` & `x18` `SCS`) and Fleet Sanitizers (`KFENCE` / `KASAN`)

To harden both core `GKI` `vmlinux` and every loaded vendor `.ko` module against C memory corruption, `gki_defconfig` mandates Clang Link-Time Optimization (`CONFIG_LTO_CLANG_THIN`), forward-edge Clang Kernel Control Flow Integrity (`CONFIG_CFI_CLANG` / `-fsanitize=kcfi`), backward-edge `Shadow Call Stack` (`CONFIG_SHADOW_CALL_STACK` / `-fsanitize=shadow-call-stack`), zero-initialization of stack automatics (`-ftrivial-auto-var-init=zero` [254]), and `KFENCE` fleet sampling [32, 255, 256, 257].

![Figure: Comparison of Rust memory safety, Clang KCFI, Shadow Call Stack, and ARM Pointer Authentication across AOSP and GKI.](diagrams/07-kcfi-scs-rust-defense.svg)

On the *forward edge*, `KCFI` (`kernel/cfi.c`, upstreamed in Linux 6.1 by Sami Tolvanen [32, 256]) replaces earlier jump-table `CFI` with zero-indirection inline prototype hashing. Clang computes a 32-bit `xxHash` digest over each address-taken C function's canonical parameter and return types, emitting that 32-bit constant into read-only/execute-only `.text` four bytes prior to the function entry (`[target - 4]`) [32, 256]:

```c
/* ARM64 assembly sequence emitted by Clang -fsanitize=kcfi before indirect BLR x8 */
ldur  w16, [x8, #-4]          /* Load 32-bit prototype hash stored at fn_entry - 4 */
mov   w17, #0x4a1f            /* Lower 16 bits of expected call-site type hash     */
movk  w17, #0x9c32, lsl #16   /* Upper 16 bits of expected call-site type hash     */
cmp   w16, w17
b.eq  .Lcall_ok
brk   #0x8220                 /* Immediate EL1 KCFI trap encoded with reg operands */
.Lcall_ok:
blr   x8
```

Because `CONFIG_STRICT_KERNEL_RWX` marks kernel `.text` strictly non-writable and `ARMv8.5-A` Branch Target Identification (`BTI`) restricts indirect jumps to `BTI C` landing pads, corrupting a function pointer in `struct file_operations` or `struct timer_list` cannot pivot control to mid-instruction ROP gadgets or `commit_creds()`, restricting calls strictly to functions sharing the exact static C prototype [32, 241, 256].

On the *backward edge*, `Shadow Call Stack` (`SCS`, `clang.llvm.org/docs/ShadowCallStack.html`) outperforms traditional stack canaries (`-fstack-protector-strong`, which can be leaked via info-disclosure bugs or hopped over by non-linear indexed writes!) by reserving AArch64 platform register `x18` (`-ffixed-x18` across *every* `GKI` kernel file, vendor `.ko` module, and `Bionic` userspace library) as a dedicated `SCSReg` pointer to a separate, guard-page-surrounded shadow stack holding *only* 64-bit `x30` (`LR`) return addresses (`str x30, [x18], #8` in non-leaf prologues; `ldr x30, [x18, #-8]!` in epilogues) [32, 255]. Because `x18` is never spilled to the normal `sp` data stack (and `Bionic`'s `setjmp.S` stores only the aligned low offset bits of `x18` inside `jmp_buf`), even an arbitrary linear stack smash or heap info-leak cannot locate or overwrite the shadow stack, complemented on `ARMv8.3-A+` silicon by cryptographic Pointer Authentication (`PACIASP` / `AUTIASP`) [32, 255].

Alongside exploit mitigations, Android pairs pre-release `KASAN` (`CONFIG_KASAN_SW_TAGS` and `MTE`-backed `CONFIG_KASAN_HW_TAGS` [258, 259]) with always-on production *Kernel Electric-Fence (`KFENCE`, `CONFIG_KFENCE`)* [257]. `KFENCE` carves out just `2 MiB` of RAM (`255` 4 KiB object pages interleaved with unmapped `PAGE_SIZE` guard pages) and uses a periodic timer (`kfence.sample_interval`) to route sampled `kmalloc` / `kmem_cache_alloc` allocations onto page boundaries adjacent to an unmapped guard page (with pattern redzones on the opposite side) [257]. At virtually `0%` CPU cost, millions of hours of fleet uptime turn silent vendor `.ko` out-of-bounds reads, UAFs, and double-frees into immediate page-fault crash reports carrying full allocation and deallocation stack traces [257]!

### Memory-Safe Rust Across AOSP Daemons and the `GKI` Kernel

Control-flow integrity and sampling sanitizers contain or surface C/C++ bugs; *memory-safe Rust* prevents spatial and temporal memory corruption from compiling in the first place [34, 35, 244, 245]. Following Google's *Rule of Two* (no component may simultaneously process untrusted inputs, be written in an unsafe language, and run with high privilege [189]), Android 12+ integrated `rustc` directly into Soong (`Android.bp`) and `Kleaf` kernel builds, focusing strategically on *newly written and actively modified native code* (where vulnerability telemetry shows bugs are overwhelmingly introduced!) [244, 245].

Look at the breadth of high-exposure AOSP and `GKI` subsystems now running production Rust [34, 186, 207, 245, 260, 261, 262, 263, 264]: in cryptographic and virtualization roots, `keystore2` ([Chapter 4](04-keymint-weaver-throttling.md)), `pvmfw`, `virtmgr`, and `crosvm` ([Chapter 5](05-pkvm-avf-microdroid.md)) are 100 percent Rust; in zero-click network and proximity stacks, Android's `DNS-over-HTTP/3` resolver (`quiche` inside the `DnsResolver` Mainline `APEX` [262]), the Ultra-Wideband (`UWB`) UCI protocol stack (`packages/modules/Uwb` [261]), Bluetooth `Gabeldorsche` (`GD`) Rust modules and Play Services *Nearby Presence* [245, 260], NFC parsers, MLS RCS encryption, and Chromium's PNG, JSON, and web-font parsers (`Skia`/`Fontations`) shipped in Rust [245]; and in `EL1` kernel space, `android16-6.12` became Android's first production `GKI` kernel shipping `CONFIG_RUST=y` with Google's upstreamed *Rust `Binder` driver* (`drivers/android/binder/`, [Chapter 9](09-uid-zygote-binder.md) [77, 245, 264, 265]), alongside the joint Google, Arm, and Collabora *`Tyr`* memory-safe Rust DRM kernel driver for Arm Mali `CSF` GPUs [245, 263]! Notice *why* rewriting `Binder` in Rust mattered so much architecturally [77, 264]: C `drivers/android/binder.c` suffered years of subtle UAFs (`CVE-2019-2215`, `CVE-2022-20421`, `CVE-2023-20938`) because threads had to manually drop `binder_proc` inner spinlocks before acquiring `binder_node` locks while juggling raw pointers and split strong/weak integer reference counts; in `drivers/android/binder/` (`rust_binder`), `rustc`'s borrow checker, `Pin<&mut SpinLock<T>>` lock-protected fields, and typed `Arc<Node>` / `ListArc` intrusive list wrappers verify at compile time that no mutable field can be touched without holding its guarding lock and no `Thread` or `Node` struct can ever outlive an `epoll` wait-queue registration!

Google's six-year longitudinal vulnerability study (Vander Stoep & Rebert 2024 [244]; Vander Stoep Nov 2025 [245]) delivered landmark empirical proof across the entire systems security discipline: as annual net lines of new first-party Rust in AOSP surpassed new C++ additions in 2024-2025 (reaching `~5 million` lines of platform Rust), the share of Android security vulnerabilities caused by memory-safety defects plummeted from `76%` in 2019 to `24%` in 2024 and *below `20%` in 2025* (versus the `70%` industry norm) [244, 245]! Across five years and 5 MLOC of Rust, Android recorded *zero* exploited Rust memory-safety bugs and just a single near-miss `unsafe`-block flaw (`CVE-2025-48530`, mitigated by `Scudo` and fixed pre-release), yielding a measured Rust vulnerability density of `0.2 per MLOC` compared to `~1,000 per MLOC` in historical C/C++: a *1,000-fold reduction in memory-safety vulnerability density*, accompanied by `25%` faster code reviews and a `4x` lower change rollback rate [245]!

## Vendor, OEM, & Custom-OS Boundaries

Despite `Treble` and `GKI 2.0`, two multi-vendor structural gaps persist at the OEM and SoC boundary [13, 43, 44]. First, *Google Requirements Freeze (`GRF`)* permits SoC vendors to freeze `/vendor` software and launch `KMI` kernel branches (`android13-5.15` or `android14-6.1`) across multiple chipset-reuse years while `/system` upgrades to Android 16; while `GKI` ensures monthly `LTS` security fixes still flow into `vmlinux` on those frozen `KMI` branches, new upstream architectural hardenings (such as Linux `6.12` Rust drivers) arrive only when SoC BSPs move to newer `KMI` baselines [13, 245].

Second, vendor `DLKM` `.ko` drivers (`mali_kbase.ko`, `msm_kgsl.ko`, vendor Wi-Fi/NPU drivers) remain overwhelmingly written in C by SoC teams and distributed via quarterly vendor bulletins rather than Google's monthly `GKI` `boot.img` [43, 44]. As Project Zero's *Mind the Gap* investigation documented [43], fixes for exploited Arm Mali GPU UAFs (`CVE-2022-38181`, `CVE-2023-4211`) took months after Arm's source advisory to ship inside OEM `/vendor` OTA updates, directly motivating the `Tyr` Rust GPU driver initiative [263] and `GrapheneOS`'s rapid Pixel firmware integration and aggressive GPU/malloc hardening [20].

## Exploit Chains & Structural Limits

Every generation of `Treble` and `GKI` defenses retired an entire class of trivial Android exploits while funneling elite commercial spyware chains toward out-of-tree C `.ko` GPU drivers and pure data-only `EL1` corruption.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| *Stagefright* MP4 RCE (`CVE-2015-1538`) | 2015 | Monolithic `mediaserver` (`UID 1013` + camera/audio/net) | Zero-click MMS or web MP4 `stsc` atom integer overflow | `SampleTable::setSampleToChunkParams` 32-bit multiply wrap in over-privileged daemon | Split into zero-FD `media.extractor` + `minijail` `seccomp` + `Mainline` `APEX` + `Treble` HALs [81, 238, 242] |
| Pre-Treble In-Process Vendor HAL Bugs | 2015-2017 | `system_server` & `cameraserver` `dlopen()` `.so` plugins | Crafted camera metadata or sensor payload | Proprietary vendor C++ `.so` ran inside framework UID and blocked OS updates | `Project Treble` Binderized Stable `AIDL` HALs + `SP-HAL` linker namespaces [12, 243, 246] |
| *Bad Binder* Fork-Lag Zero-Day (`CVE-2019-2215`) | 2019 | Downstream OEM `4.4`/`4.9` kernel fork (`binder.c`) | Local `untrusted_app` or Chrome renderer `epoll` UAF | Upstream `syzkaller` fix took 20 months to propagate across fragmented downstream forks | `GKI 2.0` single signed `vmlinux` + upstream Rust `Binder` rewrite (`6.12`) [13, 77, 218, 264] |
| *Arm Mali* GPU Patch-Gap Chains (`CVE-2022-38181` / `CVE-2023-4211`) | 2022-2023 | Vendor `mali_kbase.ko` running in `EL1` | Unprivileged `untrusted_app` `/dev/mali0` JIT/TLB `ioctl` | Out-of-tree C `.ko` GPU memory alias/UAF lagged months between Arm fix and OEM OTA | Faster OEM `vendor_dlkm` servicing + `Tyr` Rust Mali DRM driver transition [43, 245, 263] |
| *Qualcomm Adreno* `KGSL` Chains (`CVE-2023-33106` / `CVE-2024-23380`) | 2023-2024 | Vendor `msm_kgsl.ko` in `EL1` | Malicious app `/dev/kgsl-3d0` shared-page mapping `ioctl` | Out-of-tree GPU DMA/IOMMU page-mapping flaws granting physical RAM R/W | `KGSL` page-pool isolation + `pKVM` Stage-2 SMMUv3 IOMMU protection ([Chapter 5](05-pkvm-avf-microdroid.md)) [4, 44] |
| Prototype-Compatible `KCFI` & Data-Only Kernel Exploits (Maar et al.) | 2024 | `GKI` `EL1` `struct cred`, PTEs, & same-type callbacks | Slab UAF or OOB write in C kernel subsystem or `.ko` | `KCFI` checks static C function types only; `SCS` ignores non-control data writes to `cred->uid` | Hardware `CONFIG_KASAN_HW_TAGS` (`Arm MTE`, [Chapter 8](08-arm-mte-scudo.md)) + Rust driver migration [241, 245, 259] |
| `KFENCE` Live Fleet OOB/UAF Catches | 2021-2026 | `GKI` & `vendor_dlkm` `kmalloc` slabs | Production edge-case driver paths missed by lab fuzzing | Rare hardware-state races unexercised in QEMU/`syzkaller` CI | Always-on `CONFIG_KFENCE` 2 MiB guard-page fleet sampling in `GKI` [257] |
| Unsafe Rust Near-Miss (`CVE-2025-48530`) | 2025 | Platform `unsafe` Rust FFI/buffer boundary | Pre-release internal audit / fuzzing | Unsound invariant inside explicit `unsafe` Rust block (1st across 5 MLOC!) | Caught pre-release + contained at runtime by `Scudo` hardened allocator ([Chapter 8](08-arm-mte-scudo.md)) [245, 266] |

### Why Control-Flow Integrity Cannot Substitute for Spatial and Temporal Memory Safety

Lukas Maar et al.'s USENIX Security 2024 evaluation of `GKI` kernels [241] crystallizes why `KCFI` and `x18` `Shadow Call Stack`, essential as they are, cannot be the final line of defense for legacy C/C++ code. Once an attacker exploits a spatial heap overflow or temporal Use-After-Free (`UAF`) in a C driver or native codec to construct an *arbitrary read/write primitive* (for instance corrupting `pipe_buffer->page` or GPU page-table entries), the exploit never needs to call a mismatched function pointer (`KCFI`) or corrupt a saved return address (`SCS`)! Overwriting `task_struct->cred` or browser DOM permission flags executes 100 percent legitimate control-flow edges over corrupted data [241].

> **Key takeaway.**
> Rust extinguishes spatial and temporal bugs at compile time for *new* code (driving memory-safety CVEs below 20 percent of Android's total), while hundreds of millions of lines of *existing* C/C++ in Chromium, codecs, NDK libraries, and vendor `.ko` modules require catching the very first invalid pointer dereference in silicon before an arbitrary read/write primitive can ever be assembled. [Chapter 8](08-arm-mte-scudo.md) dissects how `ARMv8.5-A`/`ARMv9-A` Memory Tagging Extension (`MTE`) and `Scudo` enforce that lock-and-key check in production.

## Inspecting via ADB, Fastboot, & Attestation

Verify the running `GKI 2.0` kernel release (`KMI` branch format `<lts>-android<ver>-<kmi_gen>`) and device launch / `VINTF` API level:

```bash
adb shell uname -r
adb shell getprop ro.board.api_level
adb shell getprop ro.product.first_api_level
```

Inspect active `GKI` compile-time mitigations (`CONFIG_CFI_CLANG`, `CONFIG_SHADOW_CALL_STACK`, `CONFIG_KFENCE`, `CONFIG_RUST`) and enumerate loaded out-of-tree `.ko` modules:

```bash
adb shell zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(CFI_CLANG|SHADOW_CALL_STACK|KFENCE|RUST)='
adb shell lsmod | head -n 8
```

Confirm post-*Stagefright* media process disaggregation (`media.extractor`, `media.swcodec`, `cameraserver`, `audioserver`) and Binderized `/vendor/bin/hw/*` `Treble` HAL daemons running in isolated `SELinux` domains:

```bash
adb shell ps -AZ | grep -E 'media\.(extractor|swcodec)|cameraserver|audioserver' | head -n 6
adb shell ps -AZ | grep '/vendor/bin/hw/' | head -n 6
```

