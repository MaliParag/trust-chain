# Protected KVM and the Android Virtualization Framework

## Overview

* **Link in the Chain:** Normal World `EL2` hypervisor isolation boundary; de-privileges both the host `EL1` Android Linux kernel and legacy `S-EL1` `TrustZone` stacks by executing confidential workloads inside hardware-isolated Protected Virtual Machines (`pVMs`).
* **Core Security Invariant:** Once the host `EL1` kernel donates physical frames to a Protected VM or to `EL2` via `pKVM` hypercalls, `EL2` `Stage-2` translation tables (`host_mmu`), `hyp_vmemmap` ownership state, and `SMMUv3` stream tables strip host CPU and peripheral DMA access, ensuring a compromised host Linux kernel can neither read nor tamper with `pVM` memory or `DICE` secrets.
* **Ecosystem Enforcement Tier:** Enforced identically in `GREEN` and `YELLOW` locked states with `pvmfw` chaining `OpenProfile for DICE` `CDI_Attest` and `CDI_Seal` roots (`mode = normal`) and `Secretkeeper` rollback protection; operates in `ORANGE` unlocked state with degraded non-normal `DICE` mode bits visible to every local and remote verifier.
* **Trusted Computing Base (TCB):** SoC `Boot ROM` and `ABL` `DICE` handover, `EL2` `pKVM` monitor (`arch/arm64/kvm/hyp/nvhe`, or certified vendor hypervisor), `EL2` `SMMUv3` driver, `no_std` Rust `pvmfw` (`packages/modules/Virtualization/guest/pvmfw`), `Rialto` `RKP VM`, `Secretkeeper`, and inside each `pVM` its verified `Microdroid` kernel and signed `APK`/`APEX` payload.
* **Seam & Handoff:** Excludes the multi-million-line host Linux kernel from the confidentiality and integrity `TCB` of isolated security services (`Trusty VM`, `RKP VM`, DRM, biometrics, and private AI); leaves host `EL1`/`EL0` mandatory access control and syscall filtering for standard Android apps to [Chapter 6](06-selinux-seccomp.md).

## Threat Model & Ecosystem Constraint

Part I's hardware anchors ([Chapter 3](03-trustzone-strongbox.md) and [Chapter 4](04-keymint-weaver-throttling.md)) leave a stark architectural gap whenever Android needs to isolate *rich, stateful, megabyte-scale workloads*. Modern handsets routinely execute tasks that handle sensitive code, keys, or user data far too large and dynamic to run over `SPI` inside a discrete `Titan M2` microcontroller, yet far too critical to leave exposed inside host Linux memory: remote attestation `Service VMs` (`RKP VM`), migrating `TrustZone` applets (`Trusty VM`), studio-grade media DRM pipelines, biometric template matchers, enterprise security enclaves, and confidential on-device machine-learning inference [3, 4, 184, 202].

For nearly a decade, SoC vendors and OEMs forced those workloads into `Arm TrustZone` (`S-EL1`/`S-EL0`). As [Chapter 3](03-trustzone-strongbox.md) demonstrated, that pattern failed across three dimensions simultaneously [3, 14, 164]: every third-party C parser loaded into `S-EL0` widened the attack surface against the single shared `TEE` protecting `KeyMint` and `Gatekeeper`; each chipset vendor (`Qualcomm QTEE`, `Samsung TEEGRIS`, `Trustonic Kinibi`, `Google Trusty`, `OP-TEE`) maintained incompatible proprietary `TEE` SDKs and ELF loaders; and OEM firmware lag meant `S-EL0` vulnerabilities could not be patched uniformly across the ecosystem via `Project Mainline` [3, 10, 81]. Conversely, running those workloads as ordinary Normal World `EL0` processes left every physical page of their address space mapped inside the host `EL1` Linux kernel's linear map (`physmap`), where a single GPU or USB kernel bug (`Ring 0` arbitrary read/write) could dump or modify them trivially.

Introduced in Android 13 (`API 33`) and expanded across Android 14 through Android 16 via the `com.android.virt` Mainline `APEX`, the `Android Virtualization Framework` (`AVF`) backed by Will Deacon, Quentin Perret, and Fuad Tabba's `Protected KVM` (`pKVM`) resolves this dilemma by moving *beneath* the host Linux kernel into Normal World `EL2` [3, 4, 55, 203]. Under `pKVM`'s threat model, *the entire host Android Linux kernel (`EL1`), all vendor loadable kernel modules, and all host `UID 0` daemons (including the `crosvm` Virtual Machine Monitor) are untrusted for the confidentiality and integrity of Protected VMs* [3, 4]. Host Linux retains authority solely over resource allocation (CPU `vCPU` scheduling, physical frame selection prior to donation, and untrusted `VirtIO` ciphertext/ring transport), meaning a compromised host `EL1` kernel can deny *availability* by starving `vCPU` threads, but cannot read, modify, or roll back `pVM` state [4, 55, 101].

## Architecture & AOSP Implementation

### Early-Boot De-Privileging (`__pkvm_prot_finalize`) and Host Stage-2 Wrapping

On conventional enterprise ARM64 servers (`ARMv8.1+` Virtualization Host Extensions, `VHE`), Linux sets `HCR_EL2.E2H = 1` and executes the entire monolithic host kernel directly at `EL2` to avoid trap overhead, placing tens of millions of lines of drivers inside the hypervisor `TCB` [50]. On a smartphone SoC running complex out-of-tree GPU, ISP, and Wi-Fi modules, `VHE` would forfeit virtualization-based security before boot even completed [4].

`pKVM` (`arch/arm64/kvm/hyp/nvhe/` [4, 55]) exploits ARM64's split *non-VHE* (`nVHE`, `HCR_EL2.E2H = 0`) mode to invert the relationship between host OS and hypervisor. Compiled inside the Google-signed `GKI` `boot.img` binary (guaranteeing atomic kernel-hypervisor pairing via `AVB` in [Chapter 1](01-bootrom-avb-vbmeta.md)), the `EL2` monitor resides in dedicated `.hyp.text` and `.hyp.data..ro_after_init` ELF sections (`kvm_nvhe.o`) stripped of module loaders, filesystems, networking stacks, and userspace syscall surfaces [3, 4]. During early kernel startup, while `boot.img` is still pristine and *before* `/data` mounts or untrusted vendor kernel modules (`vendor_dlkm`) load, Linux enters at `EL2`, carves out physically contiguous hypervisor memory pools (`hyp_s1_pgtable_pages()`, `host_s2_pgtable_pages()`, `hyp_vmemmap_pages()`, and `hyp_ffa_proxy_pages()` in `arch/arm64/include/asm/kvm_pkvm.h`), initializes `host_mmu` via `kvm_host_prepare_stage2()`, and executes the irreversible `kvm_hyp_enable_protection()` hypercall (`__pkvm_prot_finalize()` in `mem_protect.c`) [4, 55]:

```c
/* Simplified from Linux arch/arm64/kvm/hyp/nvhe/mem_protect.c */
int __pkvm_prot_finalize(void) {
  struct kvm_s2_mmu *mmu = &host_mmu.arch.mmu;
  struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
  if (params->hcr_el2 & HCR_EL2_VM) return -EPERM;   /* One-way latch! */
  params->vttbr = kvm_get_vttbr(mmu);
  params->vtcr  = mmu->vtcr;
  params->hcr_el2 |= HCR_EL2_VM;                     /* Enable Host Stage-2! */
  kvm_flush_dcache_to_poc(params, sizeof(*params));
  write_sysreg_hcr(params->hcr_el2);
  __load_stage2(mmu);
  __tlbi(vmalls12e1); dsb(nsh); isb();
  return 0;
}
```

At that exact `isb()` barrier, the host Android Linux kernel drops permanently to `EL1` inside `VMID 0` underneath an active `EL2`-controlled `Stage-2` MMU (`VTTBR_EL2` pointing to `host_mmu.pgt`, configured with `KVM_PGTABLE_S2_IDMAP` so host `IPA == PA` with large block mappings for low TLB pressure) [3, 55]! Simultaneously, `pKVM` unmaps its own `.hyp.text`, stacks, page-table pools, `pvmfw` physical carveout, and `hyp_vmemmap` metadata array from `host_mmu.pgt`. Any subsequent attempt by a compromised `EL1` kernel to read or overwrite `EL2` memory traps immediately into `EL2`'s `handle_host_mem_abort()`, which calls `host_inject_mem_abort()` (setting `ESR_ELx_S1PTW` in the synthesized `EL1` Data/Instruction Abort) and kills the rogue host access [55]!

![Figure: Protected KVM (pKVM) Stage-2 page-ownership architecture stripping host EL1 Linux access to donated Protected VM frames.](diagrams/05-pkvm-stage2-deprivation.svg)

### The `hyp_vmemmap` Page-Ownership State Machine (`mem_protect.c`)

How does `pKVM` guarantee mathematically (verified mechanically with Cambridge's `Isla` ARMv8-A relaxed-memory semantics and `CN`/`Coq` proofs [204, 205]) that two mutually distrusting components can never hold conflicting mappings to the same physical RAM page? Inside `arch/arm64/kvm/hyp/include/nvhe/memory.h` and `mem_protect.c` [55], `EL2` maintains a protected linear array `hyp_vmemmap` indexed by physical frame number (`PFN`), storing a compact 8-byte `struct hyp_page` (`BUILD_BUG_ON(sizeof(struct hyp_page) != sizeof(u64))`) alongside 2 software ownership bits (`KVM_PGTABLE_PROT_SW0 | SW1`) inside every Guest `Stage-2` leaf PTE [55]:

```c
/* Exact 8-byte per-PFN ownership record (arch/arm64/kvm/hyp/include/nvhe/memory.h) */
struct hyp_page {
  u16      refcount;                /* Buddy/pool pin count under hyp_pool::lock */
  u8       order;                   /* Allocation order */
  unsigned __host_state     : 4;    /* Guarded by host_mmu.lock (0 = OWNED) */
  unsigned __hyp_state_comp : 4;    /* Complemented: 0 ^ 0x3 = PKVM_NOPAGE! */
  u32      host_share_guest_count;  /* Active guest share reference counter */
};
```

Notice the clever zero-initialization invariant in `memory.h` [55]: because the BSS-allocated `hyp_vmemmap` array starts zeroed at boot, storing `PKVM_PAGE_OWNED = 0` directly in `__host_state` while storing the *XOR complement* (`state ^ 0b11`) in `__hyp_state_comp` causes a single `memset(0)` to initialize all of DRAM to `host_state = PKVM_PAGE_OWNED` (`0`) and `hyp_state = PKVM_NOPAGE` (`0 ^ 3 = 3`) instantaneously without iterating millions of frames! From the perspective of each component $c \in \{\texttt{PKVM\_ID\_HOST}, \; \texttt{PKVM\_ID\_HYP}, \; \texttt{PKVM\_ID\_GUEST}(v)\}$ (which also defines `mem_protect.c`'s strict deadlock-free spinlock acquisition hierarchy `host_mmu.lock` $\to$ `pkvm_pgd_lock` $\to$ `vm->lock`!), every $4\text{ KiB}$ frame occupies one of five states in `enum pkvm_page_state` [55]:

$$\text{state}_c(p) \in \bigl\{\texttt{PKVM\_PAGE\_OWNED}\;(00_2), \; \texttt{PKVM\_PAGE\_SHARED\_OWNED}\;(01_2), \; \texttt{PKVM\_PAGE\_SHARED\_BORROWED}\;(10_2), \; \texttt{PKVM\_NOPAGE}\;(11_2), \; \texttt{PKVM\_POISON}\bigr\}$$

![Figure: pKVM hyp_vmemmap and Stage-2 page ownership state machine in arch/arm64/kvm/hyp/nvhe/mem_protect.c.](diagrams/05-extra-hyp-vmemmap-state-machine.svg)

Trace how `mem_protect.c` polices the lifecycle of a Protected VM (`struct pkvm_hyp_vm` in `pkvm.h` [203]) across hypercalls [55]:

First, *exclusive memory donation (`__pkvm_host_donate_guest` & `__pkvm_host_donate_hyp`)*: after ` __pkvm_prot_finalize()`, normal RAM starts with `host_state = PKVM_PAGE_OWNED` and `hyp_state = guest_state = PKVM_NOPAGE`. When host `crosvm` (`packages/modules/Virtualization` / `crosvm` [206]) allocates guest RAM or `EL2` metadata pages, host `EL1` invokes `__pkvm_host_donate_guest(pfn, gfn, vcpu)` [55]. Under both `host_mmu.lock` and `vm->lock`, `EL2` checks `pfn_range_is_valid()` and `check_range_allowed_memory()`, verifies `host_state == PKVM_PAGE_OWNED` and `guest_state(ipa) == PKVM_NOPAGE`, *splits any host hugepage block (`host_stage2_force_pte_cb`) and replaces the Host Stage-2 leaf PTE with an invalid annotated descriptor (`KVM_HOST_INVALID_PTE_TYPE_DONATION` encoding `PKVM_ID_GUEST`, the 16-bit VM `handle`, and 40-bit `gfn`)*, flushes Host Stage-2 TLBs (`TLBI IPAS2E1IS`), sets `host_state = PKVM_NOPAGE`, zeroes or measures the page, and maps `ipa -> phys` into `vm->pgt` as `PKVM_PAGE_OWNED` [55]! From that cycle onward, `EL1` `root` reading `phys_to_virt(pfn << 12)` faults synchronously into `EL2`.

Second, *controlled VirtIO bounce sharing (`__pkvm_guest_share_host`), `MMIO_GUARD`, and `HCR_EL2` sanitization*: because `crosvm`'s VirtIO backends run in untrusted host userspace, a Protected VM never shares arbitrary kernel memory with the host [3, 206]. Instead, the guest allocates fixed `swiotlb` bounce pages and issues SMCCC hypercall `MEM_SHARE` (`0xc6000003` $\to$ `__pkvm_guest_share_host()`), transitioning only those explicit bounce pages to `guest = PKVM_PAGE_SHARED_OWNED` and `host = PKVM_PAGE_SHARED_BORROWED` until revoked by `MEM_UNSHARE` (`0xc6000004`) [55, 131]. Likewise, `pKVM` strips untrusted host `HCR_EL2` trap bits (`PKVM_HCR_EL2_HOST_PVM` permits only `HCR_EL2_VSE` in `pkvm.h` [203] so host `EL1` cannot trap guest system registers!) and enforces `MMIO_GUARD` (`0xc6000005`..`0xc6000008` [3, 131]): any guest Stage-2 translation fault outside regions explicitly enrolled via `MMIO_GUARD_MAP` is treated as fatal rather than forwarding faulting register contents to `crosvm`.

Third, *DMA (`SMMUv3`), `TrustZone` (`FF-A`), and zero-scrubbed teardown*: to block peripheral DMA attacks from a compromised host kernel, `pKVM` owns `Arm SMMUv3` `Stage-2` stream tables in `EL2` (`drivers/iommu/arm/arm-smmu-v3/pkvm/` [63, 65]) so GPUs, USB controllers, and modems see the exact same unmapped `PKVM_NOPAGE` holes as host CPUs. Equally critical, `pKVM` traps *all* host `SMC` instructions at `EL2` (`HCR_EL2.TSC = 1`), proxying `PSCI` CPU-online entry points (so waking cores always install `host_mmu` before entering `EL1`!) and inspecting `Arm FF-A` (`ARM DEN 0077` [58]) `FFA_MEM_SHARE` / `FFA_MEM_LEND` descriptors (`__pkvm_host_share_ffa` [55]) so a malicious host cannot ask `TrustZone` (`S-EL1`) to read or overwrite a `pVM`'s physical pages as a confused deputy [3]! Finally, when a `pVM` exits (`__pkvm_reclaim_dying_guest_page`) or relinquishes balloon pages (`__pkvm_guest_relinquish_to_host`), `EL2` zeroes all $4096$ bytes and cleans data caches to the Point of Coherency (`clean_dcache_guest_page`) *before* restoring `PKVM_ID_HOST` in `host_mmu.pgt` [55].

### `pvmfw`, `OpenProfile for DICE`, and `Secretkeeper` Rollback Sealing

Memory isolation from host `EL1` would be useless if untrusted `crosvm` could simply load a trojanized kernel into the `pVM` and steal its persistent secrets! Android solves `pVM` bootstrap trust and stateful sealing through three components: `pvmfw` (`packages/modules/Virtualization/guest/pvmfw`, written in memory-safe `no_std` *Rust* [131, 207]), the `Android Profile for DICE` (`open-dice` `"android.14"`, `"android.15"`, and `"android.16"` CBOR/COSE profiles [33, 100]), and `Secretkeeper` (`system/secretkeeper` [101]).

![Figure: Protected VM Firmware (pvmfw) and OpenProfile for DICE layered CDI_Attest and CDI_Seal derivation pipeline.](diagrams/05-pvmfw-dice-chain.svg)

Follow the hardware-to-guest `DICE` chain step by step [33, 100, 131, 207]:

At silicon reset, SoC `Boot ROM` reads the chip's immutable 256-bit `Unique Device Secret` (`UDS`) from OTP fuses, measures the next loader stage, derives Layer-1 Compound Device Identifiers (`CDI_Attest` and `CDI_Seal`), and locks `UDS` hardware readout before exiting ROM. At `ABL` ([Chapter 1](01-bootrom-avb-vbmeta.md)), the bootloader verifies the `pvmfw.img` partition via `AVB`, copies `pvmfw.bin` into a dedicated `no-map` physical carveout (`compatible = "linux,pkvm-guest-firmware-memory"`), and appends at the next $4\text{ KiB}$ boundary the `pvmfw` Configuration Header (`Magic = 0x666d7670`, version `1.0`..`1.3` [131]). Inside that header, `Entry 0` holds the `PvmfwDiceHandover` CBOR map (`{1: CDI_Attest_32B, 2: CDI_Seal_32B, 3: DiceCertChain}`), while `Entry 3` (`VM Reference DT`, v1.2+) pins trusted device-tree constants such as the hardware `Secretkeeper` public key and verified `/vendor` hashtree digest [131]! Early `pKVM` initialization immediately unmaps this entire `pvmfw` physical carveout from Host `EL1` Stage-2.

Whenever `crosvm` launches *any* Protected VM, `pKVM` ignores the host's requested entry PC, copies `pvmfw.bin` and its secret configuration blob into the base of the `pVM` (`0x7fc0_0000`), and starts `vCPU 0` inside `pvmfw` [131]. Executing inside the isolated `pVM`, Rust `pvmfw` parses the untrusted guest Device Tree (`x0`) against its `VM Reference DT`, invokes `libavb` (via safe Rust wrappers) to verify the appended `AVB` footer on the guest kernel (`Microdroid` bootloader/kernel at `/config/kernel-address`) and ramdisk (`/chosen/linux,initrd-start`), obtains hardware entropy via `SMCCC` `TRNG_RND` (`ARM DEN 0098` [166]), and derives the guest's child `DICE` identifiers [33, 100, 131]:

$$\text{CDI}_{\text{Attest}}^{(n+1)} = \text{HKDF}\bigl(\text{CDI}_{\text{Attest}}^{(n)}, \; H_{\text{code}} \parallel H_{\text{cfg}} \parallel H_{\text{auth}} \parallel \text{mode}\bigr)$$

$$\text{CDI}_{\text{Seal}}^{(n+1)} = \text{HKDF}\bigl(\text{CDI}_{\text{Seal}}^{(n)}, \; H_{\text{auth}} \parallel \text{mode} \parallel V_{\text{svn}}\bigr)$$

Look at the elegant duality between those two derivations [33, 100]: `CDI_Attest` incorporates the *exact code digest* $H_{\text{code}}$, rotating on every single build so remote `RKP` verifiers ([Chapter 15](15-key-attestation-rkp.md)) inspect the exact `COSE_Sign1` (`Ed25519` or `ECDSA P-256`/`P-384`) CBOR `DiceCertChain` (including Android DICE keys `-70002` component name and `-70005` monotonic security version, mandatory in `"android.16"` [100]); meanwhile, `CDI_Seal` incorporates the *signer authority hash* $H_{\text{auth}}$, allowing a `pVM` to keep its sealed secrets across legitimate Mainline updates from the same signer!

Even better, Android 15+ closed the stateful rollback problem on `instance.img` via `Secretkeeper` (`system/secretkeeper/README.md` [101]). Because `instance.img` sits as an encrypted VirtIO file on host `/data`, a compromised host OS could snapshot an older `instance.img` and replay it after a `pVM` security patch. With `Secretkeeper`, the `pVM` establishes an encrypted, `DICE`-authenticated `AuthGraph` key-exchange session (`IAuthGraphKeyExchange.aidl`) directly through the untrusted host into the `Secretkeeper` TA inside `TrustZone`/`StrongBox` (authenticated against the public key pinned in `pvmfw`'s `VM Reference DT`!), storing a 32-byte per-VM secret in `RPMB`/secure storage gated by a declarative `DicePolicy` that demands `security_version >= latest_seen` [101, 131]. Finally, `pvmfw` zeroizes its parent `CDI`s, writes the child `DICE` handover into a `no-map` `"google,open-dice"` node (`0x7fe0_0000`), unmaps itself, and branches into the verified guest [131].

### `Microdroid`, `AuthFS`, `RKP VM`, `CompOS`, and `Trusty VM`

Above `pvmfw`, AOSP ships two complementary guest execution models inside `/apex/com.android.virt` [49, 202]. For minimal, single-purpose platform enclaves, the *Service VM* (`packages/modules/Virtualization/docs/service_vm.md` [202]) boots `Rialto`, a tiny bare-metal Rust kernel built atop `libvmbase`, running the singleton `RKP VM` (`-70006` marker in Android DICE [100]) that validates sibling `pVM` `DICE` chains for remote attestation ([Chapter 15](15-key-attestation-rkp.md)).

For richer application and OEM workloads, AOSP provides `Microdroid` (`packages/modules/Virtualization/microdroid` [49]): a stripped-down, Bionic-based miniature Android OS mounting its `super.img` over `dm-verity`, activating requested Mainline `APEX` modules over virtual block devices via `apexd`, mounting the caller's host `APK` read-only via `zipfuse` + `dm-verity`/`apkverity` (verifying host-supplied blocks cryptographically inside the `pVM`!), exposing `Binder` RPC over `virtio-vsock`, and exchanging individual files with the untrusted host through `AuthFS` (`packages/modules/Virtualization/authfs` [49, 208]), a FUSE filesystem backed by `fd_server` that enforces on-access `fs-verity` `SHA-256` Merkle trees over both read-only inputs and read-write outputs!

Production `AVF` workloads illustrate rapid architectural evolution across Android 13 through Android 16 [3, 184, 209]. Android 13 and 14 pioneered `AVF` in production with *Isolated Compilation* (`CompOS` [209]), running `dex2oat`/`odrefresh` inside a `Microdroid` `pVM` over `AuthFS` after Mainline `ART` updates and signing output artifacts so `odsign` could trust pre-reboot compilation without stalling boot; as background pre-reboot `dexopt` in `ART` Service (`artd`) matured in Android 15+, `CompOS` was deprecated and streamlined out in favor of broader, long-lived `AVF` workloads: `Trusty VM` (running `Google Trusty` TAs such as `KeyMint` and `Widevine`/OEM applets inside `EL2`-isolated `pKVM` VMs rather than `S-EL1` `TrustZone` [184]), `RKP VM` [202], confidential on-device ML models, and isolated Linux terminal/container environments.

## Vendor, OEM, & Custom-OS Boundaries

Deploying `AVF` across a multi-vendor ARM64 ecosystem required bridging a longstanding firmware divide: while Google Pixel bootloaders (`Tensor G2` through `Tensor G5` on Pixel 7 through Pixel 10+) launch the `GKI` kernel directly in `EL2`, enabling upstream AOSP `pKVM` natively on both `GREEN` stock Pixel OS and `YELLOW` `GrapheneOS` [3, 20], Qualcomm Snapdragon (`SM8550`/`SM8650`/`SM8750`+) and selected Samsung/MediaTek BSPs historically retained `EL2` inside vendor Type-1 hypervisors such as `Qualcomm Gunyah` (`hyp.mbn` [60]), booting host Linux at `EL1`.

| Isolation Architecture | Monitor Location & Size | Host `EL1` Linux Trust | Peripheral DMA Fencing | Servicing & Update Channel | Workload Sweet Spot |
|---|---|---|---|---|---|
| Standard Cloud KVM (`VHE`) [50] | Monolithic Linux at `EL2` (`10M+` LoC) | Fully trusted (`EL2 == Host`) | Host-managed `SMMUv3` | Host OS kernel update | Cloud VMs trusting the host hypervisor OS |
| Android `pKVM` (`nVHE` `AVF`) [4, 55] | Split `kvm_nvhe.o` at `EL2` (`~10K` LoC) + Rust `pvmfw` | Untrusted (`VMID 0` under `host_mmu` Stage-2) | `EL2`-owned `SMMUv3` Stage-2 driver [65] | `GKI` `boot.img` + `com.android.virt` Mainline `APEX` | `Microdroid`, `RKP VM`, `Trusty VM`, DRM, AI [3, 184] |
| Vendor Type-1 (`Gunyah` `AVF`) [60] | Proprietary `hyp.mbn` at `EL2` + Rust `pvmfw` | Untrusted (`EL1` HLOS VM) | Vendor hypervisor `SMMU` Stage-2 | Vendor firmware OTA (`hyp.mbn`) + Mainline `pvmfw`/guest | Snapdragon `AVF` `pVM`s & OEM isolated VMs |
| `Arm TrustZone` (`S-EL1`) [47, 57] | `BL31` (`EL3`) + `TEE` OS (`S-EL1`) | Untrusted (`SCR_EL3.NS=1` barred by `TZASC`) | `TZASC` (`TZC-400`) Secure bus bit [56] | Vendor OTA (`tz.mbn` / `Trusty`) | Low-latency SoC `KeyMint`, `ConfirmationUI`, `Secretkeeper` |
| `ARMv9 RME` (`CCA` Realms) [48, 59] | `EL3` `GPT` + `RMM` at `R-EL2` | Untrusted (barred by `GPTBR_EL3` `Realm PAS`) | `SMMUv3.2+` `RME` Granule Protection Checks | `TF-A` / `RMM` firmware + `AVF` guest `APEX` | Next-gen `ARMv9` confidential compute isolated from both Host & `S-EL1` |

To unify security guarantees across `pKVM`, `Gunyah`, and emerging `ARMv9` `RME` silicon without fragmenting application developers, AOSP designed `VirtualizationService`, `crosvm` (which isolates each emulated `VirtIO` device inside its own jailed, `seccomp`-filtered Rust child process on the host [206]), and `pvmfw` (`SMCCC` vendor hypercall discovery in `pvmfw` [131]) around a hypervisor-agnostic Protected VM contract. Simultaneously, Android 15 and Android 16+ tightened `CDD` and `VTS` gates (`android.software.virtualization_framework`, `hwtrust` `DICE` chain compliance verifying CBOR/COSE `"android.15"`/`"android.16"` certificates [100], `RKP VM` remote attestation [202], and `VtsSecretkeeperTargetTest` [101]) so confidential workloads enjoy identical memory isolation, `DICE` sealing, and rollback resistance across flagship silicon vendors [3, 9].

## Exploit Chains & Structural Limits

Because `pKVM` shrinks the `EL2` codebase to a few thousand lines of formally modeled C (`SeKVM`/`Isla`/`CN` proofs [204, 205]) paired with memory-safe Rust (`pvmfw`, `Rialto`, `VirtualizationService`, `crosvm`, `AuthFS`, and `Secretkeeper`), vulnerabilities discovered to date center on subtle range/integer edge cases in `mem_protect.c` hypercalls and architectural VirtIO/SMMU boundaries rather than sprawling driver heaps.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| `EL1` EFI Wrapper Shadow-Stack Logic Error (`CVE-2023-21102`) | 2023 | Host `EL1` `efi-rt-wrapper.S` kernel boundary | Local `EL1` control-flow pivot targeting shadow call stack | Logic flaw in `__efi_rt_asm_wrapper` bypassed `SCS` on host `EL1`, underscoring why `pKVM` treats host `EL1` as untrusted | Patched in May 2023 ASB; even full `EL1` `SCS`/`KCFI` bypass cannot read `EL2`-unmapped `pVM` pages [4, 55] |
| `pKVM` `mem_protect.c` Misplaced Access Check (`CVE-2023-21264`) | 2023 | `EL2` `arch/arm64/kvm/hyp/nvhe/mem_protect.c` | Compromised `EL1` / guest invoking crafted `HVC` transition | Memory access validation check placed in the wrong order allowed unauthorized hypervisor memory access | Patched in August 2023 ASB; tightened `check_range_allowed_memory` & `CN` formal invariants [205, 210, 211] |
| Missing `SMMUv3` Stage-2 Coverage on Early Boards | 2022-2023 | Non-CPU DMA masters (`GPU`, `ISP`, `USB`) | Compromised host `EL1` programming un-fenced peripheral DMA | Boards lacking `EL2`-owned `SMMUv3` `Stage-2` stream tables allowed bus DMA to read `pVM` physical RAM | `AVF` Protected VM flag (`ro.boot.hypervisor.protected_vm.supported`) strictly requires `EL2` IOMMU fencing in `VTS` [3, 65] |
| Host `SMC` / `FF-A` Confused-Deputy `TrustZone` Read | Architectural | `EL1` $\to$ `EL3`/`S-EL1` shared-memory `SMC` | Compromised host passing donated `pVM` PA in `TrustZone` `SMC` | Without `EL2` `SMC` trapping, `S-EL1` (`NS` bus access permitted) could read/clobber `pVM` RAM on the host's behalf | `pKVM` sets `HCR_EL2.TSC = 1` and proxies `FF-A` descriptors (`__pkvm_host_share_ffa`) against `hyp_vmemmap` [3, 55, 58] |
| `pKVM` `mem_protect.c` Integer Overflow OOB Write (`CVE-2025-48637`) | 2025 | `EL2` `arch/arm64/kvm/hyp/nvhe/mem_protect.c` | Local privileged caller passing crafted page-range counts | Integer overflow in range calculation across `mem_protect.c` functions caused `EL2` out-of-bounds write | Patched in December 2025 ASB using overflow-safe `pfn_range_is_valid()` arithmetic [55, 212] |
| `mem_protect.c` Relinquish & Range OOB Writes (`CVE-2026-0032`, `CVE-2026-59046`) | 2026 | `EL2` `mem_protect.c` (`__pkvm_guest_relinquish_to_host`) | Malicious guest / host invoking page-relinquish hypercalls | Improper input validation and logic errors in page-relinquish paths enabled `EL2` out-of-bounds write / DoS | Patched in 2026 ASB (`GKI` Mainline kernel updates) with strict `GFN`/`PFN` state bounds [55, 213] |
| Untrusted Host `VirtIO` Ring & `instance.img` Replay | Structural | Guest `VirtIO` front-end & host-backed virtual disks | Compromised host mutating `swiotlb` rings or replaying old `instance.img` | Host owns `crosvm` device backends and `/data` backing files | `swiotlb` copy-in validation, `MMIO_GUARD`, `dm-verity`/`AuthFS` Merkle checks, & `Secretkeeper` rollback policy [101, 131, 208] |
| Host `vCPU` Starvation & LLC Cache Timing | Structural | Host `EL1` scheduler & shared Last-Level Cache | Compromised host refusing `KVM_RUN` or probing shared CPU caches | `pKVM` delegates scheduling to host Linux for mobile battery/thermal efficiency | `pKVM` guarantees confidentiality & integrity, not availability against a dead-host `EL1` DoS [3, 4] |

### Complementary Roles of `StrongBox`, `TrustZone`, and `pKVM`

`pKVM` and `AVF` accomplish one of the cleanest privilege inversions in modern operating-system architecture: without adding a single C trustlet to `TrustZone`, Android carved out a dynamically instantiated, `DICE`-attested, `Secretkeeper`-sealed confidential computing tier in Normal World `EL2` that survives complete `Ring 0` compromise of the host Linux kernel [4, 101, 131].

> **Key idea.**
> `StrongBox` (`Titan M2` / `Knox Vault`), `TrustZone` (`S-EL1`), and `pKVM` (`EL2`) occupy orthogonal, non-redundant points in Android's hardware security lattice: `StrongBox` defeats physical silicon glitching and `NAND` mirroring via off-die `Weaver` flash; `TrustZone` anchors low-latency SoC display/sensor paths and `Secretkeeper` storage; and `pKVM` scales memory-safe, Mainline-updatable confidential VMs (`Microdroid`, `RKP VM`, `Trusty VM`) without re-bloating `S-EL1`.

Still, the overwhelming majority of interactive Android user interfaces, `system_server` `Binder` services, camera pipelines, and third-party apps execute directly atop the host `EL1` `GKI` Linux kernel rather than inside separate virtual machines. Stopping an untrusted application or media payload from compromising host `EL1` or neighboring apps in the first place is the mission of universal enforcing `SELinux`, `CTS` `neverallow` gates, and `seccomp-BPF`, examined next in [Chapter 6](06-selinux-seccomp.md).

## Inspecting via ADB, Fastboot, & Attestation

Check whether the handset advertises `AVF` support (`android.software.virtualization_framework`) and Protected VM isolation (`ro.boot.hypervisor.protected_vm.supported = 1` / `kvm-arm.mode=protected`):

```bash
adb shell pm list features | grep -i virtualization
adb shell getprop ro.boot.hypervisor.version
adb shell getprop ro.boot.hypervisor.protected_vm.supported
adb shell getprop ro.boot.hypervisor.vm.supported
```

Inspect the mounted `com.android.virt` Mainline `APEX` containing Rust `virtmgr`, `crosvm`, `fd_server` (`AuthFS`), and `Microdroid` `super`/`vbmeta` guest images:

```bash
adb shell ls -l /apex/com.android.virt/bin
adb shell ls -lh /apex/com.android.virt/etc/fs
```

Confirm `pvmfw` Verified Boot partition measurement, `Secretkeeper` HAL availability, and `SELinux` confinement of any active `virtmgr` or `crosvm` processes:

```bash
adb shell service list | grep -iE 'secretkeeper|virtualization'
adb shell getprop | grep -iE 'pvmfw|hypervisor' | head -n 8
adb shell ps -AZ | grep -iE 'virtmgr|crosvm|rialto'
```
