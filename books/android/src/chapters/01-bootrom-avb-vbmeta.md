# SoC Boot ROM, Bootloader Lock States, and AVB 2.0 VBMeta

## Overview

* **Link in the Chain:** Immutable pre-OS root of trust; executes from mask ROM at CPU power-on reset to authenticate vendor bootloader stages and evaluate the signed `Android Verified Boot 2.0` (`AVB`) `vbmeta` partition graph before transferring control to the Linux kernel.
* **Core Security Invariant:** Execution advances from mask ROM through Secondary/Applications Bootloaders (`XBL`/`ABL`) into `boot` and `init_boot` if and only if each stage's cryptographic signature chains cleanly to an OTP-fused OEM root key (`GREEN`) or an enrolled user root key (`YELLOW`), while any transition between `Locked` and `Unlocked` (`ORANGE`) states forces unconditional cryptographic erasure of `userdata`.
* **Ecosystem Enforcement Tier:** Mandatory `CDD` Section 9.10 enforcement in `GREEN` (stock OEM root) and `YELLOW` (`avb_custom_key` sovereign root such as `GrapheneOS`, reporting `KM_VERIFIED_BOOT_SELF_SIGNED`); intentionally bypassed in `ORANGE` (unlocked developer state, reporting `KM_VERIFIED_BOOT_UNVERIFIED` and unsealing zero `GREEN`-bound keys); halted at pre-OS screen in `RED`.
* **Trusted Computing Base (TCB):** On-die SoC `Boot ROM` (`PBL`), One-Time Programmable (`OTP` / `QFPROM`) root public-key hash fuses, early SRAM vendor bootloaders (`SBL1`/`XBL`, `BL2`, `BL31` `EL3` monitor, `ABL`), `libavb` descriptor and RSA/SHA-256 parsers, and the `FRP` (`Factory Reset Protection`) hardware-gated unlock bit.
* **Seam & Handoff:** Delivers an authenticated kernel image, ramdisk, and verified `vbmeta` root digest plus immutable boot-state measurements (`verifiedBootKey`, `deviceLocked`, `verifiedBootState`, `verifiedBootHash`) into `KeyMint` and `DICE` before `EL1` starts; hands runtime block-level `dm-verity`, anti-rollback `RPMB` floors, and `APEX` verification to [Chapter 2](02-antirollback-verity-apex.md).

## Threat Model & Ecosystem Constraint

Every runtime boundary examined later in this book, from universal enforcing `SELinux` ([Chapter 6](06-selinux-seccomp.md)) and `EL2` `pKVM` Stage-2 memory ownership ([Chapter 5](05-pkvm-avf-microdroid.md)) to `File-Based Encryption` ([Chapter 12](12-fbe-usb-theft-protection.md)), assumes that the kernel binary, early ramdisk, and hypervisor stub loaded from Universal Flash Storage (`UFS`) have not been altered prior to CPU execution. On a mobile handset, flash storage sits directly in the path of two distinct adversaries: a persistent local attacker who briefly achieves `Ring 0` execution and attempts to implant a surviving bootkit onto `boot` or `system`, and a physical adversary (thief, border agent, or supply-chain interdictor) who connects the powered-off phone to USB `fastboot`, Emergency Download Mode (`EDL`), or direct flash-chip probes [13, 14, 17].

Solving pre-OS integrity on Android is substantially harder than on single-vendor smartphones for two structural reasons. First, early Android versions (`Android 4.4` through `Android 7.x`) verified `boot` and `system` independently through OEM-bespoke bootloader extensions, creating severe ecosystem fragmentation whenever `Project Treble` ([Chapter 7](07-treble-gki-rust.md)) split Android across `/system`, `/vendor`, `/product`, `/system_ext`, `/odm`, `boot`, `vendor_boot`, and `init_boot` partitions [13, 57]. Updating `/system` independently of `/vendor` without breaking atomic multi-partition signature verification required a unified, open-source cryptographic metadata format (`AVB 2.0` `VBMeta`) simple enough to run inside constrained C bootloaders lacking heap complex allocators or ASN.1 X.509 stacks [13].

Second, Android serves simultaneously as a locked consumer appliance for billions of non-technical users and as an open developer and custom-OS platform (`AOSP`, `GrapheneOS`, `LineageOS`) where device owners possess the explicit right to unlock the bootloader and flash custom kernels [14, 15, 16]. Permitting bootloader unlocking without allowing a physical thief to flash a backdoored `boot.img` and read the victim's existing encrypted files forced Android to couple its lock-state machine tightly to both mandatory `userdata` destruction and `Factory Reset Protection` (`FRP`) [15].

## Architecture & AOSP Implementation

### SoC Boot ROM (`PBL`) and One-Time Programmable Fuses

Unlike PC motherboards that fetch initial UEFI `SEC` instructions over an external SPI flash bus vulnerable to clip-on programmers, mobile ARM64 SoCs anchor execution inside on-die mask-programmed silicon (`Boot ROM`, termed the Primary Bootloader or `PBL` on Qualcomm Snapdragon, `BL0`/`ROM` on Google Tensor and Samsung Exynos, and `BROM` on MediaTek Dimensity) [14, 17, 20]. Because mask ROM is etched photolithographically during wafer fabrication, its instructions are physically immutable. At power-on reset, CPU core zero begins executing `Boot ROM` at `EL3` using internal on-die SRAM before external LPDDR DRAM controllers are trained.

To authenticate the first mutable bootloader stage stored on external `UFS` or `eMMC` flash, `Boot ROM` reads a cryptographic public-key digest permanently blown during factory provisioning into One-Time Programmable (`OTP`) silicon eFuses (such as Qualcomm `QFPROM` `OEM_PK_HASH` paired with `OEM_SECURE_BOOT_ENABLE` and OEM Hardware ID / Model ID fuses) [17, 18]. Let $H_{\text{OTP}} = \text{SHA-384}(K_{\text{OEM\_root}})$ or $\text{SHA-256}(K_{\text{OEM\_root}})$ denote the fused root digest. `Boot ROM` loads the signed Secondary or eXtensible Bootloader (`XBL_SEC` / `SBL1` on Qualcomm; `BL1`/`BL2` on Tensor/Exynos) into internal SRAM, hashes the embedded root X.509/RSA public key against $H_{\text{OTP}}$, verifies the image signature and anti-rollback fuse version, and only then initializes DRAM and chains verification across `EL3` Secure Monitor firmware (`BL31` / `TZ`), Secure World `TEE` OS (`QTEE` / `Trusty`), and the Normal World Applications Bootloader (`ABL`, often UEFI-based `LinuxLoader` or `Little Kernel` `LK` / `U-Boot`) running at `EL1` or `EL2` [14, 18].

### The Bootloader Lock State Lattice and Mandatory Wipe Gate

Once execution reaches the Applications Bootloader (`ABL`), `Android Verified Boot` evaluates device lock policy and partition signatures according to the four-state machine mandated by `CDD` Section 9.10 and AOSP's Verified Boot specification [2, 14].

![Figure: Android Verified Boot 2.0 lock and verification state matrix across GREEN, YELLOW, ORANGE, and RED states.](diagrams/01-bootloader-lock-states.svg)

In the factory default `LOCKED` configuration, if every boot partition chains cleanly to the OEM root public key hardcoded inside the verified `ABL` binary, the device boots silently in the `GREEN` state (`KM_VERIFIED_BOOT_VERIFIED`). If the bootloader is `LOCKED` and `ABL` supports user-provisioned roots via the `avb_custom_key` partition, verifying the partition graph against that custom public key transitions the device into the `YELLOW` state (`KM_VERIFIED_BOOT_SELF_SIGNED`), displaying a short pre-OS notice showing the truncated `SHA-256` fingerprint of the enrolled custom key before continuing boot with full cryptographic enforcement [14, 16]. Conversely, if the bootloader is `LOCKED` and any partition fails hash, signature, or rollback verification on the active A/B slot (and no valid fallback slot remains), `ABL` halts in the `RED` state (`KM_VERIFIED_BOOT_FAILED`), refusing OS entry altogether [14].

When a developer or owner unlocks the bootloader (`fastboot flashing unlock`), the device enters the `ORANGE` state (`KM_VERIFIED_BOOT_UNVERIFIED`), displaying an unskippable boot warning and bypassing `AVB` partition signature enforcement so custom `boot.img` builds can run [14, 15]. Two hardware-anchored gates prevent a physical attacker from abusing `ORANGE` to steal data from a `GREEN` or `YELLOW` phone [15]:

First, any state transition $\text{Locked} \to \text{Unlocked}$ or $\text{Unlocked} \to \text{Locked}$ requires explicit physical confirmation on the handset's hardware volume/power buttons and executes an unconditional wipe of `userdata` and `metadata` (destroying the hardware-wrapped filesystem master keys before fastboot regains control). Even if a bug in `ABL`'s wipe routine failed to erase `UFS` blocks, [Chapter 4](04-keymint-weaver-throttling.md) shows that `ABL` sends `deviceLocked = false` and `verifiedBootState = UNVERIFIED` over a one-way early-boot mailbox to `KeyMint`/`StrongBox` prior to booting Linux, causing hardware key derivation to produce a completely different root key and rendering prior encrypted `userdata` cryptographically undecipherable [15, 36].

Second, even destructive unlocking is gated by two persistent flags stored in a hardware-write-protected partition (`frp` / `persistent_data_block`) or `RPMB`: the userspace Developer Options toggle (`sys.oem_unlock_allowed`, mirrored into the last byte of the `FRP` partition) and carrier lock policy [15]. Inside a booted Android session, flipping *OEM Unlocking* in Settings requires authenticating with the owner's Lock Screen Knowledge Factor (`LSKF`). While the handset sits locked at the lock screen or in `fastboot`, the `oem_unlock_allowed` bit remains `0`, causing `ABL` to reject `fastboot flashing unlock` with `FAILED (remote: 'Flashing Unlock is not allowed')` [15].

### AVB 2.0 and the `AvbVBMetaImageHeader` Binary Format

Rather than scattering detached PKCS#7 ASN.1 signatures across a dozen partitions, `AVB 2.0` (`external/avb/libavb` in AOSP) concentrates verification around a compact, big-endian 256-byte C header (`AvbVBMetaImageHeader`) stored at the start of the dedicated `vbmeta` partition (`vbmeta_a` / `vbmeta_b` on A/B devices) [13]. Avoiding X.509 DER parsers inside `ABL` eliminates an entire class of pre-OS memory-corruption bugs that historically plagued PC UEFI and mobile bootloaders:

```c
/* Simplified from AOSP external/avb/libavb/avb_vbmeta_image.h */
typedef struct AvbVBMetaImageHeader {
  uint8_t  magic[4];                        /* "AVB0" */
  uint32_t required_libavb_version_major;   /* 1 */
  uint32_t required_libavb_version_minor;
  uint64_t authentication_data_block_size;  /* Hash + RSA signature */
  uint64_t auxiliary_data_block_size;       /* Descriptors + Public Key */
  uint32_t algorithm_type;                  /* e.g. SHA256_RSA4096 (2) */
  uint64_t hash_offset;
  uint64_t hash_size;
  uint64_t signature_offset;
  uint64_t signature_size;
  uint64_t public_key_offset;
  uint64_t public_key_size;
  uint64_t descriptors_offset;
  uint64_t descriptors_size;
  uint64_t rollback_index;                  /* Monotonic anti-rollback floor */
  uint32_t flags;                           /* AVB_VBMETA_IMAGE_FLAGS_* */
  uint8_t  release_string[48];
  uint8_t  reserved[80];
} AVB_ATTR_PACKED AvbVBMetaImageHeader;
```

Immediately following this 256-byte header sit two contiguous variable-length blocks whose bounds are checked strictly with overflow-safe arithmetic inside `avb_vbmeta_image_verify()` [13]. The *Authentication Data Block* holds only raw cryptographic outputs: $\text{Hash} = \text{SHA-256}(\text{Header} \parallel \text{AuxiliaryBlock})$ and $\text{Sig} = \text{Sign}_{K_{\text{priv}}}(\text{Hash})$. The *Auxiliary Data Block* contains the serialized RSA public key (`AvbRSAPublicKeyHeader`, precomputed with Montgomery parameter $n_0' = -n^{-1} \bmod 2^{32}$ and $R^2 \bmod n$ so `libavb` performs fast modular exponentiation without division or Bignum heap allocation) alongside a packed array of typed `AvbDescriptor` records [13].

![Figure: AVB 2.0 root VBMeta structure and delegated hash, hashtree, and chained partition descriptors.](diagrams/01-avb-vbmeta-descriptor-chain.svg)

Three descriptor types connect `vbmeta` to every executable byte on the device [13]:

First, `AvbHashDescriptor` covers comparatively small partitions loaded completely into RAM before OS entry (`boot`, `init_boot`, `vendor_boot`, `dtbo`, `pvmfw`). `ABL` reads the entire partition from flash, prepends the descriptor's random salt, computes `SHA-256` (or `SHA-512`), and verifies exact equality with the digest inside `vbmeta` before jumping to the kernel entry point.

Second, `AvbHashtreeDescriptor` covers multi-gigabyte read-only filesystems (`system`, `vendor`, `product`, `system_ext`, `odm`) that would take seconds to hash linearly at boot. Instead of reading all of `/system` in `ABL`, `vbmeta` authenticates only the 32-byte `dm-verity` Merkle root digest, salt, block sizes, and Reed-Solomon Forward Error Correction (`FEC`) offsets, passing them via kernel command-line / `bootconfig` parameters so Linux verifies individual $4\text{ KiB}$ blocks lazily on demand ([Chapter 2](02-antirollback-verity-apex.md)) [13, 22].

Third, `AvbChainPartitionDescriptor` solves multi-party signing under `Project Treble` [13, 57]. In the root `vbmeta` signed by the OEM, an `AvbChainPartitionDescriptor` for `vbmeta_system` records the target partition name, an independent `rollback_index_location` slot $s \ge 1$, and Google's public signing key $K_{\text{GSI}}$. During `avb_slot_verify()`, `libavb` reads `vbmeta_system_a`, verifies its signature against $K_{\text{GSI}}$, checks its independent rollback index against hardware slot $s$, and processes its nested `AvbHashtreeDescriptor`s for `system` and `system_ext`. Google or an enterprise builder can thus ship a newly signed `system.img` + `vbmeta_system.img` update without ever holding the OEM's root `vbmeta` private key. Finally, `libavb` computes the composite *Verified Boot Hash* (`ro.boot.vbmeta.digest`), defined as the `SHA-256` over the concatenated verified `VBMeta` structs across the root and all chained partitions, sealing the exact software cohort into `KeyMint`'s `RootOfTrust` [13, 110].

## Vendor, OEM, & Custom-OS Boundaries

While `libavb` standardizes `VBMeta` verification across AOSP, everything *beneath* `libavb` (`Boot ROM`, `EDL` recovery modes, fuse blowing, and custom-key enrollment) remains governed by SoC vendor silicon and OEM manufacturing discipline [16, 17, 20].

On Google Pixel handsets (`Tensor` silicon paired with `Titan M2`), `ABL` implements full first-class support for sovereign custom Verified Boot roots: an owner unlocks the bootloader (`ORANGE`), flashes a custom OS build (`GrapheneOS`), flashes their own `RSA-4096` public key to the `avb_custom_key` virtual partition (`fastboot flash avb_custom_key pkmd.bin`), and re-locks the bootloader (`fastboot flashing lock`) [16]. Re-locking forces a fresh wipe and boots in `YELLOW` (`deviceLocked = true`, `verifiedBootState = SELF_SIGNED`), binding `Titan M2` `Weaver` slots and `KeyMint` keys to the custom `verifiedBootKey` digest so a physical attacker with USB access faces the exact same locked bootloader, disabled `fastboot` flashing commands, and hardware-verified `dm-verity` partitions as on stock Pixel OS [16]. By contrast, most Samsung, Xiaomi, and carrier-locked North American Qualcomm OEMs either omit `avb_custom_key` support in `ABL` (forcing custom ROM users to remain permanently in `ORANGE` with Verified Boot disabled), permanently blow a `Knox Warranty Bit` eFuse (`0x0` $\to$ `0x1`) upon first unlock that irreversibly disables `Knox Vault` enterprise containers [34], or disable `OEM Unlocking` completely at the carrier SKU level.

A sharper vendor divergence sits inside SoC Emergency Download (`EDL`) recovery protocols built directly into immutable `Boot ROM` (`PBL`) for factory brick recovery [17, 20]. On Qualcomm SoCs, grounding board test points or issuing an `edl` reboot enters `PBL`'s USB `Sahara` protocol (`USB VID:PID 05C6:9008`), which accepts an ELF "programmer" binary (`prog_ufs_firehose_*.elf`) uploaded over USB into SRAM to read or write raw `UFS` flash LUNs via XML `Firehose` commands [17]. Properly fused devices require that `Firehose` programmer to carry a valid OEM `RSA` signature chaining to the same `QFPROM` `OEM_PK_HASH` fuse as normal boot, with anti-rollback version fuses preventing old programmers from running. Whenever an OEM reuses a single root signing key across device generations without incrementing programmer anti-rollback fuses, a single leaked factory `Firehose` programmer turns `Boot ROM` itself into an arbitrary flash-read/write oracle bypassing `ABL` lock states entirely [17].

## Exploit Chains & Structural Limits

Real-world pre-OS compromises never invert `RSA-4096` or `SHA-256`; they exploit leaked factory programmers, integer/parser bugs inside vendor `XBL`/`ABL` loaders, improper `fastboot` command gating, or unblown OEM fuses.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| OnePlus / Moto Fastboot Bypasses (CVE-2017-5626, CVE-2016-8462) | 2016-2017 | OEM `ABL` (`LK` / `aboot`) | Physical USB `fastboot oem` vendor commands on locked device | Proprietary OEM `fastboot` handlers disabled `dm-verity` or flashed `boot`/`modemst` RAM buffers without checking `is_unlocked` | Remove debug `fastboot oem` commands; gate all state mutations on `deviceLocked` [15, 19] |
| Qualcomm Leaked `Firehose` EDL Programmers | 2017-2019 | SoC `PBL` `Sahara` / `Firehose` SRAM loader | Physical USB `05C6:9008` `EDL` mode | OEM-signed factory `Firehose` ELF programmers leaked without per-model `HW_ID` or anti-rollback fuse revocation, granting raw UFS R/W | Bind programmers to per-device `HW_ID`/`OEM_ID`, VIP command hashing, and `QFPROM` anti-rollback fuses (`FBE` still protects `BFU` data) [17] |
| MediaTek `kamakiri` (CVE-2020-0069) | 2020 | MediaTek `BROM` USB Download Mode | Physical USB control transfer to on-die `Boot ROM` | Missing bounds check in `BROM` USB DMA control-transfer handler allowed SRAM overwrite and arbitrary unsigned `preloader` execution | Fixed in newer silicon mask steppings; requires disabling `BROM` USB entry via eFuse (`SLA`/`DAA`) [20] |
| Qualcomm `XBL` UEFI Verification Bypass (CVE-2021-1931) | 2021 | Qualcomm `XBL` pre-`ABL` loader | Physical/local flash write of crafted ELF/UEFI image | Improper ELF segment/hash-table validation in `XBL` allowed modified code segments to pass signature verification before `ABL` ran | Patch `XBL` image loader and increment `QFPROM` bootloader anti-rollback fuse [18] |

### Anatomy of `Firehose` Leaks and `Boot ROM` Immutability

Roee Hay's analysis of Qualcomm `EDL` programmers demonstrated why `Boot ROM` recovery interfaces represent a permanent structural tension in SoC design [17]. Because `PBL` is etched in mask ROM, a bug in `PBL` itself (such as MediaTek `CVE-2020-0069` `kamakiri` [20]) cannot be patched via firmware OTA on deployed handsets unless silicon fuses exist to disable USB `BROM` entry completely prior to `USB` enumeration. Even when `PBL`'s `RSA` verifier is bug-free, leaked OEM-signed `Firehose` programmers execute at `EL3`/`EL1` in SRAM before `ABL` or `AVB` runs, allowing a physical attacker to overwrite `boot` or dump raw `userdata` ciphertext [17]. Against a `Firehose` read/write attack, `AVB` alone cannot stop raw flash modification (though `RED` state will catch tampered `boot` if `ABL` runs normally); the decisive backstop for user confidentiality in that scenario is `File-Based Encryption` in the `Before First Unlock` (`BFU`) state ([Chapter 12](12-fbe-usb-theft-protection.md)) backed by discrete `StrongBox` `Weaver` silicon ([Chapter 3](03-trustzone-strongbox.md) and [Chapter 4](04-keymint-weaver-throttling.md)), because raw `UFS` dumps yield only `AES-256-XTS` ciphertext whose unsealing key resides off-flash inside `Titan M2` or `Knox Vault` [33, 91].

> **Warning.**
> Bootloader lock state (`GREEN` or `YELLOW`) guarantees code authenticity at boot, not secrecy against hardware flash readers on its own, and conversely an `ORANGE` unlocked bootloader does not merely skip `boot.img` verification: it permanently alters the `RootOfTrust` input fed into `KeyMint` at every boot, preventing `GREEN`-sealed keys from unsealing and marking every hardware attestation certificate `unverified` [14, 110].

Even on a tightly fused `GREEN` device with zero `fastboot` or `EDL` flaws, two structural questions remain open at the moment `ABL` jumps into the Linux kernel. First, what stops an attacker with raw flash access from replacing `vbmeta_a` and `boot_a` with *genuinely OEM-signed* older partitions from two years ago containing known `Ring 0` vulnerabilities? Second, because `ABL` verified only the 32-byte Merkle root of `/system` rather than reading gigabytes of blocks at boot, how does the running kernel detect or heal tampered flash blocks at runtime, and how can Google patch userspace modules without waiting months for OEM `vbmeta` re-signing? [Chapter 2](02-antirollback-verity-apex.md) answers both questions.

## Inspecting via ADB, Fastboot, & Attestation

On any running Android handset with `adb` debugging enabled, inspect the active `AVB` lock state, verified boot color, `VBMeta` composite `SHA-256` digest, and bootloader version exported by `init` from `bootconfig` / kernel command-line properties:

```bash
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.vbmeta.digest
adb shell getprop ro.bootloader
```

On a stock locked handset, `ro.boot.vbmeta.device_state` returns `locked` and `ro.boot.verifiedbootstate` returns `green` (or `yellow` on a locked `GrapheneOS` install using `avb_custom_key`). You can also confirm whether the userspace *OEM Unlocking* gate (`FRP` unlock bit) is currently barred against `fastboot flashing unlock`:

```bash
adb shell getprop sys.oem_unlock_allowed
adb shell getprop ro.oem_unlock_supported
```

When auditing an extracted factory image or custom build offline on a workstation, AOSP's `avbtool` inspects the exact `AvbVBMetaImageHeader`, algorithm, rollback index, and chained/hashtree descriptors inside `vbmeta.img` and verifies the full descriptor chain:

```bash
avbtool info_image --image vbmeta.img
avbtool verify_image --image vbmeta.img --follow_chain_partitions
```

Finally, from the pre-OS `fastboot` interface (`adb reboot bootloader`), query lock status, active A/B slot, and unlocked vulnerability flags without modifying device state:

```bash
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar secure
```
