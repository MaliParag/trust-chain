# Protected KVM and the Android Virtualization Framework

## Overview

* **Link in the Chain:** Normal World `EL2` hypervisor isolation boundary; de-privileges both the host `EL1` Android Linux kernel and legacy `S-EL1` `TrustZone` stacks by running confidential workloads inside hardware-isolated Protected Virtual Machines (`pVMs`).
* **Core Security Invariant:** Once the host `EL1` kernel donates physical memory frames to a Protected VM via `pKVM` hypercalls, `EL2` Stage-2 page tables and `SMMUv3` IOMMU tables unmap those frames from the host's address space, ensuring a compromised host Linux kernel can neither read nor modify `pVM` memory or `DICE` secrets.
* **Ecosystem Enforcement Tier:** Supported identically in `GREEN` and `YELLOW` locked states with `pvmfw` chaining `OpenProfile for DICE` `CDI_Attest` and `CDI_Seal` roots from verified boot; operates in `ORANGE` unlocked state with degraded `UNVERIFIED` `DICE` mode bits so remote verifiers distinguish unlocked hosts.
* **Trusted Computing Base (TCB):** SoC Boot ROM and early bootloader `DICE` chain, `EL2` `pKVM` hypervisor (`arch/arm64/kvm/hyp/nvhe`), `SMMUv3` Stage-2 hypervisor driver, Rust `pvmfw` (`packages/modules/Virtualization/guest/pvmfw`), and inside each `pVM` its verified `Microdroid` kernel and signed payload `APEX`/`APK`.
* **Seam & Handoff:** Removes the multi-million-line host Linux kernel from the confidentiality `TCB` of isolated compilation, DRM, ML, and OEM security services; leaves host `EL1`/`EL0` mandatory access control and syscall attack-surface reduction to [Chapter 6](06-selinux-seccomp.md).

## Threat Model & Ecosystem Constraint

Parts I's hardware anchors ([Chapter 3](03-trustzone-strongbox.md) and [Chapter 4](04-keymint-weaver-throttling.md)) leave a glaring architectural gap for rich, stateful security workloads. Modern smartphones routinely execute tasks that process high-value code or secrets far too complex to fit inside a discrete `StrongBox` microcontroller over `SPI`, yet far too sensitive to expose to a compromised host Linux kernel: compiling `ART` system server and boot-classpath bytecode (`Isolated Compilation`), decoding studio-grade DRM media streams, running biometric liveness or on-device machine-learning models, and executing proprietary OEM security agents [43, 44].

For a decade, SoC vendors and OEMs stuffed those workloads into `Arm TrustZone` (`S-EL1`/`S-EL0`). As [Chapter 3](03-trustzone-strongbox.md) documented, that choice backfired across the ecosystem: every third-party C trustlet added to `S-EL0` widened the attack surface against the single shared `TEE` that held `KeyMint` and `Gatekeeper` secrets, while each SoC vendor (`Qualcomm QTEE`, `Trustonic Kinibi`, `Samsung Teegris`, `Trusty`) shipped incompatible proprietary `TEE` SDKs that could not be updated via `Project Mainline` [30, 32, 43]. Conversely, running those workloads in Normal World `EL0` processes left every page of their virtual memory mapped inside the host `EL1` Linux kernel's linear physical map (`physmap`), where any GPU or USB kernel vulnerability (`Ring 0` arbitrary read/write) could dump or patch them trivially.

Android 13 (`API 33`) through Android 16 resolved both halves of that dilemma simultaneously by introducing the `Android Virtualization Framework` (`AVF`) backed by `Protected KVM` (`pKVM`) in Normal World `EL2` [43, 44]. Under `pKVM`'s threat model, *the entire host Android Linux kernel (`EL1`) and all host `UID 0` userspace daemons are treated as untrusted for the confidentiality and integrity of Protected VMs*, while the host retains responsibility only for CPU scheduling, memory allocation, and untrusted `VirtIO` transport queues (meaning a compromised host can deny liveness by refusing to schedule a `vCPU`, but cannot inspect or forge `pVM` state) [43, 44, 48].

## Architecture & AOSP Implementation

### Early-Boot De-Privileging and `EL2` Stage-2 Page Ownership

On standard enterprise Linux servers (`ARMv8.1+` Virtualization Host Extensions, `VHE`), KVM runs the entire monolithic host Linux kernel directly at `EL2` (`HCR_EL2.E2H = 1`) for performance, placing every device driver and filesystem inside the hypervisor `TCB`. On a mobile SoC carrying millions of lines of third-party driver code, running Linux at `EL2` would defeat virtualization-based security before boot even finished [44].

`pKVM` (`arch/arm64/kvm/hyp/nvhe/`, upstreamed into mainline Linux by Google and Arm kernel engineers) inverts KVM's privilege hierarchy using ARM64's non-VHE split mode [44]. At kernel startup, Linux enters at `EL2`, initializes minimal boot CPU tables, allocates a physically contiguous hypervisor memory pool (`hyp_mem_base`), loads the compact, self-contained `nvhe` hypervisor object (`kvm_nvhe.o`, only a few thousand lines of auditable C/Rust-interfacing code with zero module loader, zero network stack, and zero userspace syscall surface), and invokes `kvm_hyp_enable_protection()` *before* mounting `/data`, loading untrusted third-party kernel modules, or spawning userspace [44, 48].

![Figure: Protected KVM (pKVM) Stage-2 page-ownership architecture stripping host EL1 Linux access to donated Protected VM frames.](diagrams/05-pkvm-stage2-deprivation.svg)

That one-way initialization step drops the host Linux kernel permanently down to `EL1` and activates a *Host Stage-2 MMU translation table* (`VTTBR_EL2`) underneath the host kernel itself! Initially, `pKVM` maps normal DRAM as `OWNED` by the host in an identity-mapped Stage-2 table, while marking `pKVM`'s own `.text`, `.rodata`, stack, and page-ownership metadata (`hyp_vmemmap`, an array of `struct hyp_page` tracking every $4\text{ KiB}$ physical frame on the SoC) inaccessible (`PROT_NONE`) to `EL1` [44, 48].

Every physical page frame $p$ in `hyp_vmemmap` carries an explicit finite-state ownership tag inside `pKVM` [44, 48]:

$$\text{state}(p) \in \{\texttt{PKVM\_NOPAGE}, \; \texttt{PKVM\_ID\_HOST}, \; \texttt{PKVM\_ID\_HYP}, \; \texttt{PKVM\_ID\_FFA}, \; \texttt{PKVM\_ID\_GUEST}(v), \; \texttt{PKVM\_SHARED}\}$$

When `virtmgr` in host userspace launches a Protected VM $v$ (`crosvm` virtual machine monitor), the host `EL1` kernel allocates anonymous physical frames and invokes explicit `HVC` hypercalls (`__pkvm_host_donate_guest`) asking `EL2` to transfer ownership of frame $p$ from `PKVM_ID_HOST` to `PKVM_ID_GUEST(v)`. Inside `EL2`, `pKVM` atomically verifies under spinlock that $p$ is currently exclusively `PKVM_ID_HOST` (neither shared nor pinned elsewhere), *unmaps $p$ completely from the Host Stage-2 page table and issues TLB invalidation (`TLBI IPAS2E1IS`)*, zeroes or measures $p$ as required before mapping it into Guest $v$'s Stage-2 page table, and updates `hyp_vmemmap[p]` [44, 48]. If a compromised host `EL1` kernel subsequently attempts to dereference `phys_to_virt(p)` to spy on the `pVM`, the ARM64 MMU raises an immediate Stage-2 Permission/Translation Fault into `EL2`, killing the rogue host access! Conversely, for `VirtIO` network or block ring buffers that *must* exchange ciphertext with `crosvm`, the guest explicitly invokes `pkvm_guest_share_host` on designated bounce-buffer pages (`swiotlb`), ensuring only untrusted I/O buffers ever become visible to `EL1` [43, 44].

Critically, CPU Stage-2 tables alone would fail if a compromised host `EL1` kernel programmed a GPU, display controller, or USB DMA engine to read `pVM` physical addresses directly over the SoC interconnect. `pKVM` closes that DMA hole by taking exclusive `EL2` ownership of the SoC's `Arm SMMUv3` (`System MMU`) controller hardware registers and Stage-2 stream tables, ensuring peripheral DMA engines see the exact same stripped physical view as host `EL1` CPU cores [43, 44]. When a `pVM` terminates (`__pkvm_reclaim_page`), `pKVM` scrubs every reclaimed $4\text{ KiB}$ frame to all-zeros in `EL2` *before* restoring `PKVM_ID_HOST` permissions in the Host Stage-2 table, guaranteeing zero post-mortem secret leakage back to host Linux [44].

### `pvmfw` and `OpenProfile for DICE` Layered Attestation

Isolating a VM's memory from the host kernel is meaningless if the host kernel (which loads the VM's initial RAM image via `crosvm`) simply boots a backdoored guest image inside the `pVM`! How can a Protected VM know its own identity, keep persistent sealed secrets across reboots, and prove to remote servers or `KeyMint` what code is running inside it when the host `EL1` loader is untrusted?

Android solves guest bootstrap trust through two components shipped via the `com.android.virt` Mainline `APEX`: `pvmfw` (`Protected VM Firmware`, written from scratch in memory-safe `no_std` *Rust* inside `packages/modules/Virtualization/guest/pvmfw`) and the Trusted Computing Group's `OpenProfile for DICE` (`Device Identifier Composition Engine`, implemented in `open-dice`) [45, 47].

![Figure: Protected VM Firmware (pvmfw) and OpenProfile for DICE layered CDI_Attest and CDI_Seal derivation pipeline.](diagrams/05-pvmfw-dice-chain.svg)

Trace the exact cryptographic handoff from silicon reset into a running `pVM` [45, 47]:

At Layer 0, SoC `Boot ROM` reads the immutable per-chip 256-bit `Unique Device Secret` (`UDS`) from hardware fuses, hashes the next bootloader stage, derives Layer 1 Compound Device Identifiers (`CDI_Attest` and `CDI_Seal`) via `HKDF-SHA512`, and permanently latches hardware `UDS` readout off before jumping out of ROM. At `ABL` ([Chapter 1](01-bootrom-avb-vbmeta.md)), the bootloader loads the signed `pvmfw.img` partition into a dedicated physical carveout region, verifies its `AvbHashDescriptor` inside `vbmeta`, derives `pvmfw`'s DICE `CDI` pair and `CBOR`/`COSE_Sign1` Boot Certificate Chain (`BCC`), writes that `BCC` bundle into `pvmfw`'s reserved memory, and hands control to Linux, where early `pKVM` initialization immediately unmaps `pvmfw`'s physical carveout from Host `EL1` Stage-2 [45]!

Whenever the host later spawns any Protected VM $v$, `pKVM` refuses to start Guest `vCPU 0` at a host-chosen entry point. Instead, `pKVM` unconditionally copies the pristine `pvmfw` image and its secret `DICE` handover page from `EL2`-protected memory into the base of Guest $v$'s private Stage-2 address space and boots Guest `vCPU 0` inside `pvmfw` first [45]. Running inside the already-isolated `pVM`, Rust `pvmfw` inspects the guest kernel (`Microdroid`) and guest `instance.img` / `APEX` / `APK` descriptors passed by `crosvm`, verifies their `AVB` signatures, extracts the payload signer's public key $K_{\text{signer}}$, exact code hash $H_{\text{code}}$, security version $V_{\text{svn}}$, and debug mode flag $M$, and executes a new `OpenProfile for DICE` derivation step [45, 47]:

$$\text{CDI}_{\text{Attest}}^{(n+1)} = \text{HKDF-SHA512}\bigl(\text{CDI}_{\text{Attest}}^{(n)}, \; H_{\text{code}} \parallel H_{\text{cfg}} \parallel K_{\text{signer}} \parallel M\bigr)$$

$$\text{CDI}_{\text{Seal}}^{(n+1)} = \text{HKDF-SHA512}\bigl(\text{CDI}_{\text{Seal}}^{(n)}, \; K_{\text{signer}} \parallel M \parallel V_{\text{svn}}\bigr)$$

Notice the crucial asymmetry between those two equations [47]: `CDI_Attest` mixes the *exact binary hash* $H_{\text{code}}$, changing on every single build so remote `RKP` / attestation verifiers ([Chapter 15](15-key-attestation-rkp.md)) know the exact `Microdroid` and payload revision executing; `CDI_Seal` mixes the *authority public key* $K_{\text{signer}}$ (plus anti-rollback floor $V_{\text{svn}}$) rather than $H_{\text{code}}$, remaining stable across legitimate signed updates from the same developer so the `pVM` can decrypt its own persistent `instance.img` state across Mainline upgrades while locking out every other `pVM` and every tampered payload! Finally, `pvmfw` appends a new `COSE_Sign1` leaf certificate to the `BCC`, *explicitly zeroizes its own parent `CDI`s from `pVM` RAM*, unmaps itself, and jumps into the verified guest kernel [45].

### `Microdroid` and Production `AVF` Workloads

Although `AVF` can boot raw bare-metal binaries inside a `pVM`, writing complex applications without dynamic linking, `Binder`, or `APEX` support is error-prone. AOSP therefore provides `Microdroid` (`packages/modules/Virtualization/microdroid`), a stripped-down, read-only miniature Android OS (~tens of megabytes) containing a `GKI`-derived minimal Linux kernel, `init`, `servicemanager` (`Binder` over `vsock` to the host app!), `apexd`, and `apkverity` (`dm-verity`/`fs-verity` verifying the host app's `.apk` and `.apex` mounts over `VirtIO-blk` without trusting the host block server!) [46].

Since Android 14 through Android 16, `AVF` + `Microdroid` powers multiple production security boundaries: *Isolated Compilation* (`composd`, compiling boot-classpath/system-server `odex` artifacts after Mainline `ART` updates inside a `pVM` and signing them with a `DICE`-sealed key so a transiently compromised host cannot plant trojanized `ART` native code across reboots), OEM camera/biometric/DRM trustlet replacements migrating out of `S-EL1` `TrustZone`, and isolated on-device AI / enterprise workloads [43, 46].

## Vendor, OEM, & Custom-OS Boundaries

Bringing `pKVM` across a multi-vendor ARM64 ecosystem required closing a major silicon-firmware conflict: historically, Qualcomm, MediaTek, and Samsung firmwares either held `EL2` inside proprietary hypervisors (`Qualcomm Gunyah` or Samsung `RKP`/`UH` hypervisor) and dropped Linux directly into `EL1` at boot (making standard KVM impossible!), or lacked `SMMUv3` Stage-2 support for peripheral DMA isolation [43, 44].

On Google Pixel handsets (`Tensor G2`/`G3`/`G4`+ on Pixel 7 through Pixel 10+), `ABL` hands `EL2` directly to the open-source `GKI` Linux kernel, running upstream AOSP `pKVM` natively in both `GREEN` stock OS and `YELLOW` `GrapheneOS` builds [16, 43]. To accommodate SoC vendors shipping alternate `EL2` hypervisors (such as `Qualcomm Gunyah` on Snapdragon 8 Gen 2/3/Elite), AOSP abstracted the `AVF` hypervisor backend (`VirtualizationService` + `crosvm` hypervisor-agnostic `pvmfw` ABI) while progressively tightening `CDD` / `VTS` requirements (`android.software.virtualization_framework`) on Android 15/16+ flagship chipsets so `pvmfw` `DICE` handover, memory isolation from host `EL1`, and `RKP` VM attestation ([Chapter 15](15-key-attestation-rkp.md)) behave uniformly across vendors [2, 43, 45].

## Exploit Chains & Structural Limits

Because `pKVM` shrinks the hypervisor `TCB` to a small, formally analyzed `EL2` codebase (`SeKVM`/`pKVM` formal verification lineage [48]) paired with Rust `pvmfw` and Rust `VirtualizationService`/`crosvm`, vulnerabilities found to date have largely come from proactive Google Project Zero audits of hypercall state machines and shared-memory edge cases rather than sprawling driver subsystems.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| `pKVM` Page State / Donation Races (`CVE-2023-21255` & PZ Audits) | 2023 | `EL2` `pKVM` `mm`/`mem_protect.c` hypercalls | Compromised host `EL1` invoking concurrent `HVC` page-share/donate calls | Subtle state-transition accounting flaws in early `hyp_vmemmap` host-to-guest sharing routines | Patched in `GKI` LTS; formal state-machine invariants enforced across `hyp_page` refcounts [48, 49] |
| Missing `SMMU` DMA Coverage on Pre-`AVF` Boards | 2022-2023 | Peripheral DMA engines (`GPU` / `ISP`) | Compromised host `EL1` programming un-IOMMU'd DMA master | SoCs lacking `EL2`-controlled `SMMUv3` Stage-2 stream tables could bypass CPU Stage-2 via bus DMA | `AVF` Protected VM support gated strictly on hardware `SMMU`/MPU DMA isolation in `VTS` [3, 43] |
| VirtIO Untrusted Host I/O Injection (`VirtIO-blk` / `vsock`) | Structural | Guest `Microdroid` `VirtIO` front-end drivers | Compromised host `crosvm` mutating shared `swiotlb` ring descriptors | Host controls shared bounce buffers and scheduling timing | `Microdroid` wraps `VirtIO-blk` in `dm-verity`/`fs-verity`, uses `swiotlb` copy-in validation, & Rust `VirtIO` parsers [46, 49] |
| Host Denial-of-Service & Timing Side Channels | Structural | Host `EL1` `vCPU` scheduler & shared LLC | Compromised host `EL1` starving `vCPU`s or probing shared CPU caches | `pKVM` delegates scheduling to host Linux for battery/thermal efficiency | `pKVM` guarantees confidentiality & integrity, not availability against a dead-host `EL1` DoS [43, 44] |

### What `pKVM` Solves and What Remains in Host `EL1`

`pKVM` and `AVF` represent one of the cleanest architectural inversions in modern OS design: without adding a single trustlet to `TrustZone`, Android carved out an attested, `DICE`-rooted confidential computing tier directly in Normal World `EL2` that survives complete compromise of the host Linux kernel [44, 45].

> **Key idea.**
> `TrustZone` (`S-EL1`), `StrongBox` (`Titan M2`), and `pKVM` (`EL2`) form complementary points in the hardware design space: `StrongBox` owns physical fault/glitch resistance and `Weaver` timers; `TrustZone` owns low-latency SoC sensor/display secure paths; and `pKVM` owns large, memory-safe, `Mainline`-updatable confidential VMs (`Microdroid`) without bloating `S-EL1`.

Of course, `99%` of standard Android user interfaces, `system_server` Binder services, camera stacks, and third-party apps still execute atop the host `EL1` Linux kernel rather than inside separate virtual machines. Preventing an untrusted app from compromising host `EL1` or neighboring processes in the first place is the job of universal enforcing `SELinux`, `CTS` `neverallow` rules, and `seccomp-BPF`, examined in [Chapter 6](06-selinux-seccomp.md).

## Inspecting via ADB, Fastboot, & Attestation

Check whether the device supports the `Android Virtualization Framework` (`AVF`) and Protected VMs (`hypervisor.protected_vm.supported = 1`), alongside active `pKVM` / hypervisor boot properties:

```bash
adb shell pm list features | grep -i virtualization
adb shell getprop ro.boot.hypervisor.version
adb shell getprop ro.boot.hypervisor.protected_vm.supported
```

Inspect the `com.android.virt` Mainline `APEX` mount hosting `virtmgr`, `crosvm`, `Microdroid` images, and Isolated Compilation (`composd`) binaries:

```bash
adb shell ls -l /apex/com.android.virt/bin
adb shell ls -lh /apex/com.android.virt/etc/fs
```

Verify whether the `pvmfw` partition is verified inside `vbmeta` and inspect running `virtmgr` SELinux confinement (`u:r:virtualizationservice:s0` / `virtualizationmanager`):

```bash
adb shell getprop | grep -iE 'pvmfw|hypervisor'
adb shell ps -AZ | grep -iE 'virtmgr|crosvm'
```
