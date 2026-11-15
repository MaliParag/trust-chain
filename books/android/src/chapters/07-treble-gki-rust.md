# Project Treble HALs, Generic Kernel Image, KCFI, and Kernel Rust

## Overview

* **Link in the Chain:** Structural compartmentalization, kernel ABI unification, and memory-safety engineering layer; splits vendor BSP code out of privileged framework processes and hardens `EL1`/`EL0` binaries against control-flow hijacking and memory corruption.
* **Core Security Invariant:** Vendor hardware abstractions execute in isolated `/vendor` `Binder` processes across versioned `VINTF` `AIDL` contracts; every Android 12+ launch device runs a Google-signed `Generic Kernel Image` (`GKI`) core compiled with Clang `KCFI` and `Shadow Call Stack` (`SCS`); and safe Rust eliminates spatial and temporal memory bugs at compile time across newly authored AOSP daemons and kernel subsystems.
* **Ecosystem Enforcement Tier:** Enforced identically in `GREEN` and `YELLOW` locked states via `AVB` `vbmeta` / `boot.img` signatures and `CTS`/`VTS` (`GKI` certification checks exact Google kernel build signatures); `ORANGE` unlocked state allows replacing `boot.img` with custom debug kernels at the cost of verified boot state.
* **Trusted Computing Base (TCB):** Google-built `GKI` `vmlinux` (`boot.img`), frozen Kernel Module Interface (`KMI`) symbol list, vendor loadable kernel modules (`vendor_boot` / `vendor_dlkm`), LLVM/Clang `KCFI` + `SCS` compiler passes, `rustc` safe abstractions (`kernel/` crate), and `VINTF` `AIDL` Binder IPC stubs.
* **Seam & Handoff:** Compresses core kernel update lag and shrinks C/C++ memory-safety CVEs from 76% to ~24% of platform vulnerabilities, while leaving legacy C/C++ userspace codecs and vendor `.ko` drivers to be defended at runtime by hardware `Arm MTE` and `Scudo` in [Chapter 8](08-arm-mte-scudo.md).

## Threat Model & Ecosystem Constraint

In July 2015, the *Stagefright* remote code-execution vulnerabilities (`libstagefright` MPEG-4 integer/heap overflows reachable via MMS/browser video) exposed two catastrophic structural defects in first-decade Android architecture [4, 57]:

First, *in-process vendor HAL coupling*: in Android 7.x and earlier, `mediaserver`, `cameraserver`, `audioserver`, and `system_server` loaded proprietary SoC vendor C/C++ shared libraries (`/system/lib64/hw/*.so`) directly into their own privileged address spaces via `dlopen()`. A single heap overflow inside a vendor camera ISP library or hardware H.264 decoder immediately handed the attacker all permissions, `UID`s, and `/dev` file descriptors of the entire framework service, AND prevented Google from updating `/system` across Android releases until the SoC vendor (`Qualcomm`, `MediaTek`, `Samsung`) recompiled every proprietary `.so` against changed internal AOSP C++ headers [57].

Second, *multi-tier Linux kernel fork fragmentation*: unlike desktop Linux distributions that boot upstream `kernel.org` releases directly, Android kernels historically passed through a four-stage fork cascade [58, 141]. Upstream Linux LTS (`4.14` or `4.19`) was forked into the Android Common Kernel (`ACK`), which was forked by several million lines of out-of-tree SoC Board Support Package (`BSP`) code (`CodeAurora` / `CLO`), which was forked *again* by each OEM (`Samsung`, `Xiaomi`, `Motorola`, `OnePlus`) for per-handset camera, charger, and display drivers! Merging a single upstream Linux kernel UAF patch down all four forks routinely took three to nine months, leaving millions of devices exposed to publicly disclosed "n-day" kernel exploits [58, 138].

Solving both structural failures simultaneously, while systematically eliminating C/C++ memory corruption inside the code that remained, required three multi-year engineering initiatives: `Project Treble`, the `Generic Kernel Image` (`GKI` 2.0), and pairing Clang `KCFI`/`SCS` with *Rust* across AOSP and the Linux kernel [57, 58, 59, 60].

## Architecture & AOSP Implementation

### `Project Treble`: Binderized `AIDL` HALs and `VINTF` Isolation

Introduced in Android 8.0 (`Oreo`) and refined around *Stable `AIDL`* in Android 11 through Android 16, `Project Treble` severed `/system` from `/vendor` both ABI-wise and process-wise [57]. Instead of `dlopen()`ing vendor `.so` plugins inside `system_server` (save for a tiny, strictly stateless allowlist of Same-Process `SP-HAL`s such as OpenGL ES / Vulkan user-mode shader drivers that must map into the rendering app's own unprivileged sandbox!), every hardware subsystem (`Camera`, `Audio`, `Bluetooth`, `KeyMint`, `Weaver`, `Sensors`, `Gnss`, `Radio` `IRadio`) executes as an *independent userspace daemon* (`/vendor/bin/hw/android.hardware.*-service`) communicating with `/system` exclusively over kernel `/dev/binder` (`vndbinder` for vendor-to-vendor IPC, `/dev/binder` for framework-to-vendor Stable `AIDL` IPC) [57, 73].

![Figure: Project Treble VINTF Stable AIDL process split and Generic Kernel Image (GKI 2.0) frozen KMI module architecture.](diagrams/07-treble-gki-split.svg)

Observe the dual security and servicing payoff [50, 57]. First, *fault and exploit containment*: each Binderized HAL daemon runs under a dedicated low-privilege Linux `UID` (`AID_CAMERA`, `AID_BLUETOOTH`, `AID_NFC`) and its own tight `SELinux` domain (`hal_camera_default`, `hal_bluetooth_default`) ([Chapter 6](06-selinux-seccomp.md)). Compromising a vendor Bluetooth HAL no longer grants camera, microphone, or storage access; compromising a camera HAL grants access only to `/dev/video*` ISP nodes already owned by the camera pipeline, forcing an attacker to find a separate `EL1` kernel bug to escape the HAL sandbox! Second, *cryptographically tested ABI stability (`VINTF` + `VTS`)*: `/system` and `/vendor` declare their exact provided and required `AIDL` interface versions inside XML `VINTF` (`Vendor Interface`) manifests, and `VTS` verifies that any Google Generic System Image (`GSI`) boots and passes conformance directly atop the untouched `/vendor` partition [3, 57]. Vendor binaries may link only against stable `LL-NDK` (`libc`, `libm`, `liblog`) or frozen `VNDK`/`APEX` libraries, never private framework C++ symbols.

### The `Generic Kernel Image` (`GKI` 2.0) and Frozen `KMI`

`Project Treble` solved userspace fragmentation, leaving `EL1` kernel forks as the major remaining bottleneck. Starting with Android 12 (Linux `5.10`) and mandatory across Android 13-16 (`5.15`, `6.1`, `6.6`, `6.12`), `GKI 2.0` extended the `Treble` split directly into `Ring 0` [58].

Under `GKI 2.0`, OEMs and SoC vendors are *prohibited from modifying core Linux kernel source code (`mm/`, `sched/`, `fs/`, `net/`, `security/`, `drivers/android/binder`, `arch/arm64/kvm/hyp/nvhe`)*. Instead, Google builds and cryptographically signs the canonical `ARM64` `GKI` `boot.img` containing the monolithic core `vmlinux` directly from the upstream-tracked Android Common Kernel (`ACK`) [58]! All SoC-specific and board-specific drivers (`SoC` clocks, pin controllers, `UFS` host controllers, `Mali`/`Adreno` GPUs, camera ISPs, Wi-Fi/PCIe drivers) must be compiled as *out-of-tree Loadable Kernel Modules (`.ko`)* packaged inside `vendor_boot` (`initramfs` early boot modules) and `vendor_dlkm` / `system_dlkm` (`dm-verity`-verified read-only partitions, preventing arbitrary `.ko` loading from mutable `/data`) [22, 58].

To keep Google's signed `boot.img` binary-compatible with Qualcomm's or MediaTek's `.ko` modules across years of monthly security updates, `GKI` freezes a strict *Kernel Module Interface (`KMI`)* per kernel branch (e.g., `android15-6.6`) [58]. Specifically, `abi_gki_aarch64.stg` (`STG`, Symbol-Type Graph) tracks the exact binary layout (`sizeof`, field offsets, function prototypes, and `CRC` `MODVERSIONS`) of every `EXPORT_SYMBOL_GPL` symbol on the approved `KMI` symbol list; continuous integration rejects any patch that breaks struct ABI, using pre-reserved `ANDROID_VENDOR_DATA(n)` padding fields when upstream security fixes require adding struct members. Non-allowlisted internal kernel symbols are stripped from module visibility (`TRIM_UNUSED_KSYMS`), preventing vendor `.ko` modules from reaching into internal `mm` or `cred` globals. During `VTS` (`VtsGenericBootImageTest`), certification verifies cryptographically that the handset's running `boot.img` kernel carries Google's official `GKI` signature [3, 58]. When an upstream `netfilter`, `pipe`, `futex`, or `Binder` zero-day is patched, Google ships a newly signed `GKI` `boot.img` ready for immediate deployment across every Android 14/15/16 OEM handset on that `KMI` branch without touching a single line of vendor BSP code.

### `KCFI` and `Shadow Call Stack` (`SCS`) in `GKI` and Userspace

Because millions of lines of existing Linux kernel and userspace C code remain in service, `GKI` compiles all kernel and vendor `.ko` code with LLVM/Clang Link-Time Optimization (`CONFIG_LTO_CLANG_THIN`), Clang Kernel Control Flow Integrity (`CONFIG_CFI_CLANG` / `KCFI`), and `ARM64` `Shadow Call Stack` (`CONFIG_SHADOW_CALL_STACK`) (paired on `ARMv8.3+` hardware with Pointer Authentication `PACIASP`/`AUTIASP` and Branch Target Identification `BTI`) [59].

![Figure: Comparison of Rust memory safety, Clang KCFI, Shadow Call Stack, and ARM Pointer Authentication across AOSP and GKI.](diagrams/07-kcfi-scs-rust-defense.svg)

`KCFI` (`kernel/cfi.c`, upstreamed in Linux 6.1 by Sami Tolvanen) hardens *forward-edge* indirect calls (`BLR x8` through C function pointers in `struct file_operations`, `struct net_proto_family`, or `sk_buff` destructors) [59]. At compile time, Clang hashes each target function's canonical C prototype into a deterministic 32-bit type ID $T_{\text{fn}}$ and emits that 32-bit constant immediately *before* the function's entry instruction in `.text` (`fn_addr - 4`). Before every indirect call `(*fn_ptr)(...)`, Clang emits an inline load and comparison:

```c
/* Conceptual ARM64 KCFI inline check emitted before BLR x8 */
ldr   w16, [x8, #-4]          /* Load 32-bit type hash preceding target fn */
movk  w17, #EXPECTED_TYPE_ID  /* Expected prototype hash at call site */
cmp   w16, w17
b.eq  1f
brk   #0x8220                 /* Immediate kernel panic / oops on mismatch! */
1: blr x8
```

Because `.text` is mapped strictly Execute-Only / Read-Only (`CONFIG_STRICT_KERNEL_RWX`), an attacker with a heap UAF overwriting `file->f_op` can no longer pivot `BLR x8` to arbitrary ROP stack-pivot gadgets (`xchg`/`mov sp`) or `commit_creds()`, restricting indirect calls strictly to legitimate entry points of functions sharing the exact C type signature [59, 63].

Complementing `KCFI` on the *backward edge* (function `RET` instructions), `Shadow Call Stack` (`SCS`) reserves general-purpose ARM64 register `x18` (forbidden from general use via `-ffixed-x18` across both `GKI` and `Bionic` userspace!) as a dedicated pointer to a hidden, guard-page-isolated shadow stack storing *only* 64-bit return addresses (`str x30, [x18], #8` in function prologues; `ldr x30, [x18, #-8]!` in epilogues) [59]. Overwriting a traditional stack buffer on `sp` corrupts local stack variables without touching `x18`, neutralizing classic stack-smashing Return-Oriented Programming (`ROP`).

### Memory-Safe Rust Across AOSP and the Kernel

Mitigations like `KCFI` and `SCS` raise exploit development cost; memory-safe languages eliminate the spatial and temporal vulnerability class at its root. Beginning in Android 12 (`API 31`), Google made *Rust* a first-class supported systems language in AOSP alongside C and C++, targeting high-exposure parsers, privileged daemons, and wireless stacks first [60, 61]. Across privileged security and virtualization infrastructure, `keystore2` ([Chapter 4](04-keymint-weaver-throttling.md)), `pvmfw`, `virtmgr`, and `crosvm` (`AVF`, [Chapter 5](05-pkvm-avf-microdroid.md)) were written 100 percent in Rust [42, 45, 60]. Across zero-click wireless and network parsers, Android's Bluetooth stack (`btservices` Rust modules), Ultra-Wideband (`UWB` UCI stack), `DNS-over-HTTP/3` (`quiche` inside the `resolv` Mainline `APEX`), and NFC components moved to Rust [60, 61]. Inside kernel subsystems (`Rust for Linux` in `GKI`), Google's kernel team rewrote the complex Linux kernel `Binder` driver in Rust (`drivers/android/binder_rust`, [Chapter 9](09-uid-zygote-binder.md)), eliminating the manual C reference-counting and lock-ordering hazards responsible for notorious in-the-wild zero-days like `CVE-2019-2215`, alongside Rust abstractions for `ashmem` and firmware loaders [62, 75].

Google's published multi-year vulnerability telemetry across AOSP proved the empirical result with remarkable clarity [60, 61]: as the share of new native code written in memory-safe Rust exceeded new C/C++ additions, the proportion of Android security vulnerabilities caused by memory-safety bugs fell from `76%` in 2019 to `24%` in 2024, dropping *below* industry averages for the first time in Android's history, with near-zero memory-safety CVEs across tens of millions of lines of production Rust in AOSP [61]!

## Vendor, OEM, & Custom-OS Boundaries

While `GKI 2.0` unifies `vmlinux`, a crucial boundary remains inside `vendor_dlkm` (`vendor_boot` and `/vendor/lib/modules/*.ko`) [58, 138]. Although `GKI` forces vendor `.ko` modules to compile with Clang `KCFI` and `SCS` (otherwise the kernel module loader rejects them for missing `.kcfi_traps` / `x18` ABI compatibility!), those vendor GPU (`mali_kbase.ko`, `msm_kgsl.ko`), ISP, NPU, and Wi-Fi modules are still overwhelmingly written in C/C++ by SoC vendors rather than Google [138, 139].

Moreover, devices upgraded from pre-Android-12 launch baselines ("launch kernel exemptions" under `GRF`, Google Requirements Freeze, which lets SoC vendors freeze vendor software on a chip platform for 3 years while `/system` upgrades) may run older `KMI` branches (`5.10` or `5.15`) alongside newer Android 15/16 `/system` frameworks, a deliberate pragmatic trade-off in `Treble` that keeps OEMs shipping OS updates while concentrating residual `Ring 0` risk inside vendor `.ko` modules [57, 58].

## Exploit Chains & Structural Limits

Adversaries adapting to `Treble`, `GKI`, `KCFI`, and `SCS` shifted away from simple ROP/JOP control-flow hijacking toward *data-only kernel attacks* and bugs inside third-party C/C++ vendor `.ko` drivers.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Pre-Treble *Stagefright* (`CVE-2015-1538` et al.) | 2015 | Monolithic `mediaserver` (`UID 1013` + camera/audio/system groups) | Remote MMS / web MP4 integer overflow | Media extractors + vendor codecs ran inside one privileged daemon without `seccomp` or `Treble` split | Split `media.extractor` into restricted `seccomp` sandbox + `Mainline` `APEX` + Binderized `Treble` HALs [25, 54, 57] |
| Pre-GKI Downstream Fork N-Days (`CVE-2019-2215` `Bad Binder`) | 2019 | OEM kernel fork lagging upstream Linux fix | Local `untrusted_app` UAF in `binder_poll` | Fix existed in upstream Linux for 20 months before landing across downstream Android kernel forks | `GKI 2.0` unified kernel + `Rust Binder` rewrite eliminating manual C refcounting [58, 74, 75] |
| Type-Confused `KCFI` Gadget / Data-Only Attacks (USENIX '24) | 2023-2024 | `GKI` `EL1` kernel data structures (`struct cred`, page tables) | Heap UAF / OOB write inside C vendor `.ko` driver | `KCFI` & `SCS` protect *code pointers*, not non-control data (`cred->uid`, `selinux_state`, PTEs) corrupted via arbitrary R/W | Eliminate initial UAF/OOB primitive via Rust drivers and hardware `Arm MTE` ([Chapter 8](08-arm-mte-scudo.md)) [61, 63] |
| Vendor `DLKM` GPU Driver Bugs (`Mali` / `Adreno`) | 2022-2025 | `/vendor/lib/modules/*.ko` running in `EL1` | Reachable `/dev/mali0` or `/dev/kgsl-3d0` `ioctl` | Loadable `.ko` modules still share `EL1` Ring 0 address space with `GKI` `vmlinux` | Isolate workloads in `EL2` `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) + transition new drivers to Rust [44, 62] |

### Why Control-Flow Integrity Cannot Substitute for Memory Safety

Lukas Maar et al.'s systematic evaluation of modern Android kernels [63] highlights the exact theoretical ceiling of `KCFI` and `SCS`: once an attacker converts a spatial buffer overflow or temporal Use-After-Free (`UAF`) in a C driver into a page-table or slab *arbitrary read/write primitive* (for instance via `pipe_buffer` page references or GPU MMU page-table manipulation), the attacker never needs to corrupt a single function pointer (`KCFI`) or return address (`SCS`)! Overwriting `current->cred->euid = 0` and `selinux_state.enforcing = 0` uses 100 percent legitimate kernel instructions operating on corrupted heap data [63].

> **Key idea.**
> Stopping data-only exploitation in legacy C/C++ libraries, browsers, and drivers that have not yet been rewritten in Rust requires catching the *very first out-of-bounds or use-after-free memory dereference in hardware* before heap corruption can be weaponized into an arbitrary read/write primitive. That is the exact mission of `ARMv8.5-A`/`ARMv9` Memory Tagging Extension (`MTE`) and the `Scudo` hardened allocator in [Chapter 8](08-arm-mte-scudo.md).

## Inspecting via ADB, Fastboot, & Attestation

Verify that the handset is running a certified `GKI 2.0` kernel (`uname -r` reports the exact `KMI` generation such as `6.1.xx-android14-11-...` or `6.6.xx-android15-8-...`) and check the Vendor NDK / Treble `VINTF` API level:

```bash
adb shell uname -r
adb shell getprop ro.vndk.version
adb shell getprop ro.product.first_api_level
```

Confirm active kernel mitigations (`CONFIG_CFI_CLANG=y`, `CONFIG_SHADOW_CALL_STACK=y`, `CONFIG_RUST=y` where enabled) from `/proc/config.gz` on devices exposing kernel build config, or inspect loaded `vendor_dlkm` `.ko` modules:

```bash
adb shell zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_CFI_CLANG|CONFIG_SHADOW_CALL_STACK|CONFIG_KVM'
adb shell lsmod | head -n 10
```

Inspect Binderized `Project Treble` HAL services running inside isolated `/vendor/bin/hw/*` processes under distinct `UID`s and `hal_*` `SELinux` domains:

```bash
adb shell ps -AZ | grep '/vendor/bin/hw/' | head -n 10
```
