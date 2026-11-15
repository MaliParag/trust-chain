# Multi-Vendor Chain Breaks: GPUs, Basebands, Trustlets, and the Patch Gap

## Overview

* **Link in the Chain:** Full-system adversarial synthesis and supply-chain finale; dissects how real-world commercial spyware (*Cytrox Predator*, *NSO Pegasus*) and zero-click chains route around Android's hardened AOSP core through third-party silicon drivers, cellular basebands, and the multi-hop OEM patch gap.
* **Core Security Invariant:** A multi-vendor trust chain is bounded by its least-isolated, slowest-patched component sharing `EL1` kernel memory or un-IOMMU'd DMA access: even flawless `AVB`, `SELinux`, and `Rust` daemons fail when a reachable C/C++ GPU `.ko` driver or over-the-air cellular modem parser remains unpatched months after an upstream git commit becomes public.
* **Ecosystem Enforcement Tier:** Highlights the starkest operational divergence across the Android ecosystem: Pixel (`GREEN`) and `GrapheneOS` (`YELLOW`, adding synchronous `Arm MTE`, disabled V8 JIT, 2G/VoLTE hardening, and zero-day-lag monthly ASB shipping) close upstream N-days within days, whereas long-tail third-party OEM/carrier `GREEN` models frequently suffer `60 to 180+ day` patch gaps, and `ORANGE` unlocked builds forfeit boot-integrity eviction across reboots.
* **Trusted Computing Base (TCB):** Every component granted `EL1` kernel residence or unmediated bus access on a commercial handset: vendor GPU drivers (`Arm Mali` `mali_kbase.ko`, `Qualcomm Adreno` `msm_kgsl.ko`), cellular baseband RTOS (`Samsung Shannon`, `Qualcomm Hexagon`, `MediaTek`), `SMMUv3` PCIe/shared-memory IOMMUs, and the four-hop Silicon $\to$ AOSP $\to$ OEM $\to$ Carrier OTA pipeline.
* **Seam & Handoff:** Synthesizes all twenty chapters into an actionable architectural roadmap: shrinking `EL1` via `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) and `Rust` drivers ([Chapter 7](07-treble-gki-rust.md)), catching C bugs via `SYNC` `Arm MTE` ([Chapter 8](08-arm-mte-scudo.md)), locking high-risk surfaces via `Advanced Protection` ([Chapter 11](11-accessibility-advanced-protection.md)), preserving E2EE `Intrusion Logs` ([Chapter 14](14-play-protect-intrusion-logging.md)), and eliminating the multi-vendor patch gap.

## Threat Model & Ecosystem Constraint

Across twenty chapters, we have watched Android systematically shut down entire classes of historical exploitation: `AVB 2.0` and `dm-verity` killed persistent `/system` rootkits ([Chapter 1](01-bootrom-avb-vbmeta.md) and [Chapter 2](02-antirollback-verity-apex.md)); `StrongBox` `Titan M2` and `Weaver` stopped offline PIN brute-forcing ([Chapter 3](03-trustzone-strongbox.md) and [Chapter 4](04-keymint-weaver-throttling.md)); `SELinux` `neverallow` rules and `seccomp-BPF` caged `UID 0` daemons and blocked `io_uring` ([Chapter 6](06-selinux-seccomp.md)); Rust eliminated memory-safety CVEs in `keystore2`, `pvmfw`, `UWB`, and `Binder` ([Chapter 7](07-treble-gki-rust.md)); `isolatedProcess` `u0_i*` sandboxes jailed `WebView` and Chrome renderers ([Chapter 9](09-uid-zygote-binder.md)); and `RKP` ended factory keybox extraction on modern chips ([Chapter 15](15-key-attestation-rkp.md)).

How, then, do commercial surveillance vendors (*Cytrox / Intellexa* authoring *Predator*, *NSO Group* authoring *Pegasus*, *Candiru*, *Variston*) and state-backed APTs tracked by Google's Threat Analysis Group (`TAG`), Google Project Zero, Amnesty International Security Lab, and Citizen Lab still build reliable remote spyware chains against Android targets [4, 136, 137, 138, 140, 142]?

Look at Google Project Zero's multi-year datasets of in-the-wild 0-day and n-day Android exploits [138, 142]: *attackers stopped fighting Google's hardened AOSP Rust/framework core almost entirely, and converged on three multi-vendor supply-chain seams*. First are *reachable third-party GPU kernel drivers* (`Arm Mali` and `Qualcomm Adreno`): because `Vulkan` and `OpenGL ES` require ultra-low-latency buffer submission from every app and browser GPU process, `SELinux` *must* allow `untrusted_app` (and Chrome's GPU broker) to open `/dev/mali0` or `/dev/kgsl-3d0` and issue complex shared-memory and page-table `ioctl`s directly into vendor C code running in `EL1` Ring 0 [138, 139]! Second are *zero-click over-the-air cellular baseband processors* (`Samsung Exynos`/`Shannon` VoLTE and Wi-Fi Calling): every smartphone contains a second, proprietary real-time operating system running on the cellular modem DSP/ARM core that parses untrusted `SIP`/`SDP` (`VoLTE`), `ASN.1` RRC, and SMS frames directly off the radio tower, requiring *zero user clicks* and operating completely outside the Linux kernel's `SELinux`, `KCFI`, and `Arm MTE` protections [137]! Third is *the structural multi-vendor "patch gap"*: when Arm, Qualcomm, or Linux kernel maintainers commit a security fix to a public git repository or ship a source drop to dozens of OEM licensees, `3 to 7 months` routinely elapse before downstream OEMs and carriers ship that binary `.ko` update to end-user handsets, turning public upstream patches into free zero-effort exploit blueprints ("n-days functioning as 0-days") [138, 141]!

## Architecture & AOSP Implementation

*(In this Finale chapter, tracing architecture means tracing how complete, real-world multi-stage exploit chains traverse the exact AOSP, driver, and baseband interfaces built across Parts I through IV, and why each defensive boundary either holds or gives way.)*

### Kill Chain I: One-Click Browser Renderer $\to$ GPU Kernel Driver (`Cytrox Predator` & `Mali`/`Adreno`)

Examine the canonical commercial spyware architecture dissected by Google `TAG` and Project Zero in *Cytrox Predator* campaigns (`CVE-2021-38000` + `CVE-2021-37973`/`37976` + kernel escape; and 2022-2024 chains pairing Chrome V8 bugs with `Arm Mali` `CVE-2022-38181` / `CVE-2023-4211` or `Qualcomm Adreno` `CVE-2024-23380`) [136, 138, 139]:

![Figure: Multi-vendor spyware kill chains traversing zero-click VoLTE basebands or one-click browser renderers into reachable Mali/Adreno GPU kernel drivers while evading AVB persistence.](diagrams/20-predator-baseband-gpu-chain.svg)

In *Stage 1* (Initial Delivery and Renderer RCE), the target receives a spear-phishing WhatsApp/SMS one-time link (or silent HTTP redirect on an unencrypted `http://` captive/ISP link!). Inside Chrome's `u0_i*` `isolated_app` renderer ([Chapter 9](09-uid-zygote-binder.md)), a V8 JavaScript TurboFan JIT type-confusion bug grants arbitrary read/write inside the renderer's `EL0` address space. Notice that at this stage, *Android's sandbox holds*: the `u0_i*` renderer cannot read a single file, cannot open a socket, and is blocked by `seccomp-BPF` ([Chapter 6](06-selinux-seccomp.md)) from almost every syscall!

In *Stage 2* (Renderer-to-Broker / App Pivot), rather than attacking the Linux kernel directly from `isolated_app` (which cannot even open `/dev/mali0`!), the exploit attacks Chrome's Mojo IPC interface into the privileged Chrome Browser/GPU process (`u0_a*` `untrusted_app` domain), *which does hold open file descriptors to `/dev/mali0` (`Arm Mali`) or `/dev/kgsl-3d0` (`Qualcomm Adreno`)* [72, 138, 139]!

In *Stage 3* (Escaping into `EL1` via Vendor GPU Page Tables, `CVE-2023-4211` & `CVE-2024-23380`), observe why GPU kernel drivers (`mali_kbase.ko` and `msm_kgsl.ko`) are an exploit developer's dream target [138, 139]. Modern GPUs possess their own hardware Memory Management Units (`GPU MMU`) translating GPU Virtual Addresses (`GPU VA`) into host Physical Addresses (`PA`), so userspace Vulkan/GLES drivers constantly ask `mali_kbase.ko` (`KBASE_IOCTL_MEM_ALLOC`, `MEM_COMMIT`, `MEM_JIT_INIT`, `TLSTREAM`) or `msm_kgsl.ko` (`IOCTL_KGSL_GPUMEM_ALLOC_ID` / `SPARSE_PHYS`) to map, shrink, alias, and unmap physical pages shared between CPU and GPU. In `Arm Mali` `CVE-2022-38181` and `CVE-2023-4211`, race conditions and premature page freeing in `mali_kbase` memory-region tracking returned physical pages back to the Linux kernel's global `buddy` page allocator *while stale writable entries remained live inside the GPU MMU page tables* [138]! Think through the devastating consequence of a *stale GPU PTE*: when Linux reallocates those freed physical frames as `EL1` CPU page-table pages (`PTE`s) or `struct cred` / `pipe_buffer` slabs, the attacker submits a legitimate GPU compute shader from userspace that *writes directly via the GPU into physical RAM*, overwriting the CPU's own page tables or `task_struct->cred` *without executing a single corrupted C pointer inside `EL1` CPU code*, bypassing `KASLR`, `Shadow Call Stack`, and `KCFI` ([Chapter 7](07-treble-gki-rust.md)) in one stroke [63, 138, 139]!

In *Stage 4* (Post-Exploitation Under `AVB`: Living in RAM), with arbitrary physical and kernel R/W, the implant zeroes `selinux_state.enforcing = 0` in `EL1` RAM ([Chapter 6](06-selinux-seccomp.md)) and spawns an in-memory collection daemon reading `AFU`-unlocked `CE` SQLite databases (`/data/data/org.thoughtcrime.securesms` Signal, WhatsApp, microphone, location) [136, 140]. Crucially, *the implant never touches `/system`, `/vendor`, or `boot`*, because modifying a single byte on verified partitions would trip `AVB 2.0` `dm-verity` `VERITY_MODE_RESTART` ([Chapter 2](02-antirollback-verity-apex.md)) and burn the USD 5,000,000 operation! When the target reboots their phone, the implant vanishes completely, leaving forensic traces only inside pre-sealed cloud `Intrusion Logging` from [Chapter 14](14-play-protect-intrusion-logging.md).

### Kill Chain II: Zero-Click Cellular Baseband RCE (`Exynos` / `Shannon` `CVE-2023-24033`)

Even more chilling than a one-click browser link is a *zero-click over-the-air cellular baseband compromise* requiring *only the victim's phone number* [137]! In March 2023, Google Project Zero's Natalie Silvanovich disclosed eighteen vulnerabilities (including four Internet-to-Baseband zero-click RCEs led by `CVE-2023-24033`) in Samsung's `Exynos` / `Shannon` cellular modems (deployed across Samsung Galaxy S22, A-series, and Google Pixel 6 / Pixel 7 handsets) [137]:

When `VoLTE` (*Voice over LTE*) or `Wi-Fi Calling` (`VoWiFi`) is enabled, carrier IMS networks route Session Initiation Protocol (`SIP`) call-setup packets containing *Session Description Protocol* (`SDP`) media-codec offers straight into the baseband processor *before* the phone even rings or displays an incoming-call UI! Inside `Shannon`'s proprietary C parser, `SDP` format-attribute (`fmtp`) codec strings copied network-supplied attributes into fixed-size stack/heap buffers without bounds checking (`CVE-2023-24033`) [137]. An attacker knowing only the target's MSISDN phone number could transmit a malformed `SIP INVITE` that silently hijacked the baseband RTOS without waking the screen!

What stands between a compromised cellular baseband and the main Android `EL1` application processor? Hardware `SMMUv3` (`System MMU` / `IOMMU`) DMA isolation! On older poorly partitioned boards where the modem had unrestricted PCIe/AXI bus-master DMA over all of DRAM, baseband RCE immediately meant full Linux kernel R/W. On modern Pixel (`Tensor`) and flagship architectures, strict `SMMUv3` stream tables confine the cellular modem exclusively to its dedicated IPC shared-memory ring buffer (`pktproc` / `shmem`), forcing an attacker who compromises the baseband to *still* chain a second zero-day bug inside the Linux kernel's IPC packet parser (though the compromised baseband alone can already intercept cellular voice/SMS traffic and baseband GPS!), and explaining why Google and `GrapheneOS` also began rolling out Clang bounds-checking, sanitizers, and 2G/VoLTE baseband exploit mitigations directly into modem firmware builds [16, 89, 137].

## Vendor, OEM, & Custom-OS Boundaries

### The Structural Multi-Vendor Patch Gap

Why did `Arm Mali` `CVE-2022-38181` and `CVE-2023-4211` compromise users *months after Arm had already fixed both bugs* [138]? Trace the four-hop supply-chain latency documented by Project Zero's *"Mind the Gap"* investigation [138, 141]:

![Figure: The four-hop multi-vendor Android patch gap turning public upstream git fixes into multi-month in-the-wild N-day exploit windows.](diagrams/20-multivendor-patch-gap.svg)

At *Hop 1* (Day 0), Arm or Qualcomm discovers or receives a GPU driver bug report, patches their reference driver (`r40p0` / `CLO` public git), and publishes release notes or source code, immediately alerting commercial spyware brokers who run automated binary/source diffing pipelines over every upstream commit [138, 142]! At *Hop 2* (+30 to 60 days), the SoC vendor packages monthly BSP releases for dozens of OEMs. At *Hop 3* (+60 to 120 days), Google coordinates the CVE inside the monthly Android Security Bulletin (`ASB`) and ships Pixel updates on Day 1 of the bulletin (`GrapheneOS` merges and ships that exact ASB within 24-48 hours as well [16]). Yet at *Hop 4* (+90 to 210+ days), downstream OEMs maintaining fifty distinct mid-range handset SKUs across global carriers delay integrating updated `vendor_dlkm` (`mali_kbase.ko`) or modem firmware blobs, leaving hundreds of millions of phones reporting an older `ro.vendor.build.security_patch` totally exposed to weaponized n-day chains [138, 141]!

## Exploit Chains & Structural Limits

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| *Cytrox Predator* Full Chains (`CVE-2021-38000` + Chrome + Kernel) | 2021-2023 | Intent/Chrome V8 $\to$ `EL1` kernel privilege escalation | 1-click SMS/WhatsApp link or ISP HTTP injection | Chained browser JIT RCE with unpatched downstream kernel driver UAFs | `Advanced Protection` (`HTTPS-First` + V8 JIT disable + `Arm MTE`) + `GKI 2.0` rapid kernel updates [58, 89, 136] |
| `Arm Mali` GPU Patch-Gap Chains (`CVE-2022-38181`, `CVE-2023-4211`) | 2022-2024 | `/dev/mali0` `mali_kbase.ko` GPU MMU pages | Reachable GPU `ioctl` from compromised app / Chrome GPU process | Freed physical pages retained stale writable GPU MMU PTEs + multi-month OEM patch lag | Patch `mali_kbase`, tighten `SELinux` `allowxperm`, & migrate GPU drivers toward Rust (`Tyr` / Panthor) [53, 62, 138] |
| `Qualcomm Adreno` `KGSL` Exploit (`CVE-2024-23380` / `CVE-2023-33106`) | 2023-2024 | `/dev/kgsl-3d0` `msm_kgsl.ko` in `EL1` | Shader / sparse-memory `ioctl` integer overflow / UAF | Complex C memory-mapping logic inside reachable Ring 0 `.ko` driver | ASB `vendor` patch-level enforcement in `STRONG` attestation + `KGSL` isolation [116, 139] |
| `Exynos` / `Shannon` 0-Click VoLTE Baseband RCE (`CVE-2023-24033`) | 2023 | Cellular baseband RTOS `SIP`/`SDP` parser | Over-the-air `VoLTE` / `VoWiFi` call setup packet (0 clicks) | Unbounded C string/attribute copy in modem `SDP` `fmtp` parser | Strict `SMMUv3` modem DMA confinement, compiler bounds checks in modem FW, & Wi-Fi Calling / 2G controls [89, 137] |

### Closing Synthesis: Why the Chain Holds and How Defenders Win

Step back and view all twenty chapters of *The Android Trust Chain* as a single engineering equation. Fifteen years ago, compromising an Android handset took a single 200-line exploit (`RageAgainstTheCage` or a `v1` APK bug) authored by one hobbyist over a weekend, yielding permanent `/system` root persistence forever. Today, compromising a hardened modern Android 16/17 handset (`Pixel` or `GrapheneOS` running locked `AVB 2.0` + `Titan M2` `StrongBox` + `pKVM` + synchronous `Arm MTE` + `Advanced Protection Mode` + `Intrusion Logging`) requires chaining three to four distinct zero-day exploits across renderer, Mojo broker, and `SMMU`/kernel boundaries without tripping a single `15/16` `MTE` tag fault, vanishes completely on the next `72-hour` (or nightly) reboot because `dm-verity` forbids persistence, cannot unseal `BFU` storage against `Titan M2` `Weaver`, and leaves tamper-evident forensic tracks sealed inside end-to-end encrypted cloud `Intrusion Logs` [1, 4, 67, 89, 106].

> **Key idea.**
> Security in a multi-vendor operating system is never a static state; it is the ongoing compression of the Trusted Computing Base and the patch gap. Every subsystem migrating from C to Rust (`keystore2`, `Binder`, `pvmfw`, and next-generation `Panthor`/`Tyr` Rust GPU drivers [61, 62]), every workload moving out of `EL1` and `TrustZone` into `EL2` `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)), every `ARMv9` handset enabling synchronous `MTE` ([Chapter 8](08-arm-mte-scudo.md)), and every `Mainline` `APEX` + `GKI` update bypassing carrier delay pushes the cost of compromise out of reach of mass crimeware and steadily narrows the window left to elite adversaries.

For architects, defenders, and relying parties operating atop Android today, four concrete operational imperatives summarize this volume: verify *both* `ro.build.version.security_patch` and `ro.vendor.build.security_patch` / `bootPatchlevel` via direct hardware `Key Attestation` (`RKP`) ([Chapter 15](15-key-attestation-rkp.md)) so stale vendor `.ko` drivers cannot hide behind updated `/system` UI numbers; turn on `Advanced Protection Mode` ([Chapter 11](11-accessibility-advanced-protection.md)) or deploy `GrapheneOS` (`YELLOW` custom `AVB` root with `SYNC` `MTE` and hardware USB lock) for every executive, journalist, developer, and high-risk principal; reboot regularly (or enforce automated inactivity reboots) to evict ephemeral in-memory implants back to `BFU` ([Chapter 12](12-fbe-usb-theft-protection.md)); and design every AI, enterprise, and cloud service around explicit hardware-attested capabilities (`AppFunctions`, `Passkeys`, `Titan` vaults, and `Titanium Intelligence Enclaves`) rather than ambient trust.

## Inspecting via ADB, Fastboot, & Attestation

Audit the exact split between the *Core OS Security Patch Level* (`/system` + `GKI`) and the *Vendor BSP Security Patch Level* (`/vendor` GPU `.ko` drivers, `TrustZone` TAs, and baseband firmware!) on any handset; a multi-month lag in `ro.vendor.build.security_patch` directly measures that handset's multi-vendor patch gap:

```bash
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.vendor.build.security_patch
adb shell getprop ro.boot.vbmeta.digest
adb shell getprop gsm.version.baseband
```

Inspect which GPU kernel driver (`/dev/mali0` `Arm Mali` vs. `/dev/kgsl-3d0` `Qualcomm Adreno` vs. `PowerVR`) is exposed on the handset and check its `SELinux` device label (`gpu_device`):

```bash
adb shell ls -lZ /dev/mali* /dev/kgsl* /dev/dri/* 2>/dev/null
```

Check `SMMU` / `IOMMU` hardware translation groups protecting system DRAM against peripheral and cellular baseband DMA on devices exposing `/sys/kernel/iommu_groups`:

```bash
adb shell ls /sys/kernel/iommu_groups 2>/dev/null | wc -l
```
