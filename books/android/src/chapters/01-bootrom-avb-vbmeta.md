# SoC Boot ROM, Bootloader Lock States, and AVB 2.0 VBMeta

## Overview

* **Link in the Chain:** Immutable pre-OS silicon root of trust; executes from on-die mask ROM at CPU power-on reset to authenticate vendor bootloader pipelines (`PBL` to `XBL` to `ABL` or `BL0` to `BL1`/`BL2` to `ABL`) and verify the signed `Android Verified Boot 2.0` (`AVB`) `vbmeta` partition graph before transferring control to the Linux kernel.
* **Core Security Invariant:** Execution advances from mask ROM through vendor bootloaders into `boot`, `init_boot`, `vendor_boot`, and `pvmfw` if and only if every stage's cryptographic signature chains cleanly to an OTP-fused OEM root key (`GREEN`) or an enrolled owner key (`YELLOW`), while any transition between `Locked` and `Unlocked` (`ORANGE`) forces unconditional erasure of `userdata` and `metadata`.
* **Ecosystem Enforcement Tier:** Mandatory `CDD` Section 9.10 enforcement in `GREEN` (`KM_VERIFIED_BOOT_VERIFIED`) and `YELLOW` (`avb_custom_key` sovereign root such as `GrapheneOS`, reporting `KM_VERIFIED_BOOT_SELF_SIGNED`); bypassed in `ORANGE` (`KM_VERIFIED_BOOT_UNVERIFIED`, altering `KeyMint` `RootOfTrust` derivation so zero `GREEN`/`YELLOW` keys unseal); halted pre-OS in `RED`.
* **Trusted Computing Base (TCB):** On-die SoC `Boot ROM` (`PBL` / `BL0` / `BROM`), One-Time Programmable (`OTP` / `QFPROM`) public-key hash and `SEC_BOOT` fuses, SRAM/DRAM vendor bootloaders (`XBL`/`SBL1`, `BL1`/`BL2`, `BL31` `EL3` monitor, `ABL`), `libavb` (`external/avb`), and the `FRP` (`persistent_data_block`) unlock gate.
* **Seam & Handoff:** Delivers an authenticated kernel image, generic ramdisk, verified `dm-verity` root descriptors, and immutable one-way boot measurements (`verifiedBootKey`, `deviceLocked`, `verifiedBootState`, `verifiedBootHash`) into `KeyMint` and `DICE` before `EL1` starts; hands runtime `RPMB` rollback floors, `dm-verity` `FEC`, `fs-verity`, and `APEX` Mainline mounts to [Chapter 2](02-antirollback-verity-apex.md).

## Threat Model & Ecosystem Constraint

Every runtime security invariant analyzed later in this book, from universal enforcing `SELinux` ([Chapter 6](06-selinux-seccomp.md)) and `EL2` `pKVM` Stage-2 memory isolation ([Chapter 5](05-pkvm-avf-microdroid.md)) to `File-Based Encryption` ([Chapter 12](12-fbe-usb-theft-protection.md)), rests on a foundational precondition: the kernel binary, early `init` ramdisk, device-tree overlays, and hypervisor stub loaded from Universal Flash Storage (`UFS`) must not have been modified prior to CPU execution. On a smartphone, non-volatile `UFS` flash sits directly in the crosshairs of two distinct adversaries [19, 22, 105]. The first is a *post-exploitation persistence adversary*: an exploit chain that briefly achieves `EL1` kernel read/write execution via a GPU or VFS vulnerability and attempts to overwrite `boot_a` or `vbmeta_a` so its implant survives device reboot. The second is a *physical interdiction or forensic adversary*: a thief, border inspector, or lab technician who connects the handset over USB-C to `fastboot`, triggers SoC Emergency Download Mode (`EDL`), or solders directly onto board test points to dump DRAM or flash unsigned boot images [105, 106, 118].

Designing pre-OS verification across the Android ecosystem is substantially harder than on single-vendor smartphones for two structural reasons. First, Android's modularization under `Project Treble` ([Chapter 7](07-treble-gki-rust.md)) and `GKI 2.0` decomposed the monolithic firmware image into a fleet of independently built partitions: `boot` (housing the Google-signed Generic Kernel Image), `init_boot` (generic `init` ramdisk), `vendor_boot` and `vendor_dlkm` (SoC kernel modules and first-stage ramdisk), `dtbo`, `pvmfw`, and dynamic `liblp` logical partitions (`system`, `system_ext`, `product`, `vendor`, `odm`) packed inside the `super` partition [12, 13, 119, 120]. Early Android releases (`Android 4.4` through `7.x`) verified `boot` and `system` using ad-hoc X.509/ASN.1 extensions bolted onto vendor bootloaders, creating severe parser attack surfaces and preventing `/system` from updating independently of `/vendor`. Android 8.0+ therefore needed a single, self-contained, zero-ASN.1 binary verification format (`AVB 2.0` `VBMeta`) small and deterministic enough to execute inside bare-metal C or Rust bootloaders with zero dynamic heap complexity [22, 88, 121].

Second, Android serves simultaneously as a sealed consumer vault for billions of users and as an open computing platform where hardware owners retain the right to unlock the bootloader and run sovereign operating systems (`AOSP`, `GrapheneOS`, `LineageOS`) [19, 20, 122]. Supporting `fastboot flashing unlock` without handing every physical phone snatcher a trivial lockscreen bypass forced Android to couple bootloader lock transitions mathematically to hardware key derivation, mandatory cryptographic storage destruction, and `Factory Reset Protection` (`FRP`) [28, 122, 123].

## Architecture & AOSP Implementation

### Multi-Vendor Silicon Boot Pipelines and OTP Fuse Anchors

Unlike x86 PC motherboards that fetch reset-vector instructions over an external SPI flash bus vulnerable to clip-on logic probes, mobile ARM64 SoCs anchor CPU reset inside on-die, photolithographically etched mask ROM (`Boot ROM`) [19, 124, 125]. At cold power-on reset, application CPU core zero wakes in `EL3` (`SCR_EL3.NS = 0`), disables external interrupts, maps internal on-die SRAM (because external LPDDR5X DRAM controllers have not yet been trained), and executes immutable mask ROM instructions. Because mask ROM cannot be altered after wafer fabrication, per-OEM cryptographic trust is bound through One-Time Programmable (`OTP`) silicon eFuse arrays blown permanently on the factory line [105, 124].

While every Android SoC converges at AOSP's `libavb` before booting Linux, pre-`ABL` stage nomenclature and binary formats divide across two dominant silicon lineages [51, 124, 125]:

| Boot Stage / Property | Qualcomm Snapdragon (`PBL` $\to$ `XBL` $\to$ `ABL`) | Google Tensor / Samsung Exynos (`BL0` $\to$ `BL1`/`BL2` $\to$ `ABL`) | Execution Level & Memory | Primary Security Responsibility |
|---|---|---|---|---|
| Stage 0: Mask ROM | `PBL` (Primary Bootloader) [124] | `BL0` / `iROM` (`BROM` on MediaTek) [125, 126] | `EL3` in on-die SRAM | Reads `OTP`/`QFPROM` root key hash & `SEC_BOOT` fuses; verifies Stage 1 |
| Silicon Root Fuses | `QFPROM`: `OEM_PK_HASH` (`SHA-384`), `SEC_BOOT`, `OEM_ID`, `ANTI_ROLLBACK` [124] | `OTP` bank: `ROT_PK_HASH`, `SECURE_BOOT_EN`, monotonic `SW_REV` bitmasks [125] | Hardware eFuse latches | Pins OEM root CA digest; disables JTAG/SWD debug; gates `EDL`/USB recovery |
| Stage 1/2: Early Loader | `XBL_SEC` + `XBL` (eXtensible Bootloader; `SBL1` on older chips) [124, 127] | `BL1` (chip init / monotonic monitor) $\to$ `BL2` + `PBL` [51, 125] | `EL3` / `S-EL1` SRAM $\to$ LPDDR | Trains LPDDR DRAM; configures initial `TZASC` carveouts; verifies `EL3` & `TEE` |
| Stage 3: Secure World | `QSEE` / `QTEE` (`tz.mbn`) + `AOP`/`DEVCFG` + optional `Gunyah` (`hyp.mbn`) [60, 124] | `BL31` (`EL3` monitor) + `BL32` (`Trusty` on Tensor; `TEEGRIS` on Exynos) [57, 125] | `EL3` + `S-EL1` (+ `EL2` if vendor hyp) | Establishes `SMC` runtime monitor, `TEE` OS, and `DICE` `UDS` $\to$ `CDI` derivation |
| Stage 4: App Bootloader | `ABL` (`LinuxLoader.efi` EDK2 UEFI app; transitioning toward Rust `GBL`) [121, 124] | `ABL` (`Little Kernel`-derived Pixel loader / `sboot`; Rust `GBL` path) [121, 125] | Normal World `EL2` or `EL1` | Implements `fastboot`, lock-state policy, `libavb` `vbmeta` verification, & `KeyMint` latch |

Trace the Qualcomm Snapdragon boot sequence first [124, 127]. Upon reset, `PBL` reads `QFPROM` fuses containing `OEM_PK_HASH` (the `SHA-384` or `SHA-256` digest of the OEM's root X.509 certificate), `OEM_SECURE_BOOT_ENABLE`, `OEM_ID`, `MODEL_ID`, and hardware anti-rollback bitmasks. `PBL` loads the ELF-formatted `XBL` image from the dedicated `UFS` Boot LUN (`LUN 1` or `LUN 2`) into on-die SRAM, parses its Qualcomm Hash Table Segment (`MI_BOOT_IMG_HDR`), verifies the X.509 attestation certificate chain up to `OEM_PK_HASH` while checking `OU` fields for `OEM_ID`/`SW_ID` binding, and validates every ELF program segment hash before branching to `XBL_SEC` [124, 127]. `XBL` initializes PMIC rails and LPDDR DRAM, activates `TZASC` memory firewalls, loads `tz.mbn` (`EL3` monitor and `QTEE` `S-EL1` kernel) and `hyp.mbn` (`EL2`), and finally authenticates and launches the Normal World `abl.elf` (`LinuxLoader.efi`), an EDK2 UEFI application that houses `fastboot` and AOSP `libavb` [124].

On Google Tensor (`GS101` through `Tensor G4`/`G5`) and Samsung Exynos platforms, the pipeline follows an Arm Trusted Firmware-inspired `BL0` $\to$ `BL1` $\to$ `BL2` $\to$ `BL31`/`BL32` $\to$ `ABL` cascade stored on `UFS` boot LUNs [51, 125]. Immutable `BL0` ROM verifies signed `BL1` against fused OTP root keys; `BL1` authenticates `BL2`, which brings up LPDDR DRAM and verifies `BL31` (`EL3` Secure Monitor), `BL32` (`Google Trusty` LK microkernel on Pixel, paired over `SPI` with discrete `Titan M2` [26, 57]), and Normal World `ABL` running at `EL2` so `ABL` can eventually hand `EL2` directly to the `GKI` Linux kernel for `pKVM` initialization ([Chapter 5](05-pkvm-avf-microdroid.md)) [4, 125]. Across both ecosystems, Google's AOSP `Generic Bootloader` (`GBL`, `bootable/libbootloader` [121]) increasingly replaces bespoke C/UEFI `ABL` code with a unified, memory-safe *Rust* EFI application implementing `libavb`, `DICE`, A/B slot selection, and `fastboot` parsing from one audited codebase.

### Bootloader Lock States, `avb_custom_key`, and `FRP` Unlock Gating

Once vendor stages launch `ABL`, `Android Verified Boot` enforces the four-color state machine defined by `CDD` Section 9.10 (`GREEN`, `YELLOW`, `ORANGE`, and `RED`) [9, 19].

![Figure: Android Verified Boot 2.0 lock and verification state matrix across GREEN, YELLOW, ORANGE, and RED states.](diagrams/01-bootloader-lock-states.svg)

When the device is `LOCKED` and the root `vbmeta` partition verifies against the OEM public key compiled into `ABL`, `ABL` boots silently in `GREEN` (`KM_VERIFIED_BOOT_VERIFIED`) [19]. When the device is `LOCKED` and `ABL` implements custom root-of-trust enrollment via `avb_custom_key` (`fastboot flash avb_custom_key pkmd.bin`), verifying `vbmeta` against that enrolled key boots in `YELLOW` (`KM_VERIFIED_BOOT_SELF_SIGNED`), pausing briefly to display the custom public key's `SHA-256` fingerprint before enforcing identical `dm-verity`, rollback, and `StrongBox` hardware protections [19, 20]. If `ABL` is `LOCKED` and verification fails on all bootable A/B slots, execution halts unconditionally in `RED` (`KM_VERIFIED_BOOT_FAILED`) [19].

Conversely, if the owner unlocks the bootloader (`fastboot flashing unlock`), the handset enters `ORANGE` (`KM_VERIFIED_BOOT_UNVERIFIED`), displaying a mandatory warning banner and skipping `vbmeta` enforcement so custom kernels can execute [19, 122]. Three interlocking hardware and storage gates prevent a physical attacker from exploiting `ORANGE` to extract data from a stolen `GREEN` or `YELLOW` device [28, 122, 123, 128]:

First, any state transition (`Locked` to `Unlocked` or `Unlocked` to `Locked`) requires physical confirmation via hardware Volume/Power buttons wired directly to the bootloader and triggers immediate cryptographic erasure of `userdata` and `metadata` before `fastboot` accepts flashing commands [122]. Second, as [Chapter 4](04-keymint-weaver-throttling.md) details, before jumping to Linux, `ABL` transmits a one-time early-boot RPC (`SetBootParams`) to `KeyMint` (`TEE` and `StrongBox` `Titan M2`), latching `KM_TAG_ROOT_OF_TRUST`:

$$\text{RootOfTrust} = \bigl(\texttt{verifiedBootKey}, \; \texttt{deviceLocked}, \; \texttt{verifiedBootState}, \; \texttt{verifiedBootHash}\bigr)$$

Because `KeyMint` mixes `RootOfTrust` directly into its hardware Key Encryption Key (`KEK`) derivation and locks `SetBootParams` until the next hardware reset, booting in `ORANGE` (`deviceLocked = false`, `verifiedBootState = UNVERIFIED`) produces an orthogonal `KEK` incapable of unwrapping any key blob sealed under `GREEN` or `YELLOW`, while simultaneously recording `UNVERIFIED` inside every hardware attestation certificate ([Chapter 15](15-key-attestation-rkp.md)) [19, 28, 29]. Third, to block `AFU` cold-boot RAM extraction attacks (`CVE-2024-29745` [106]), modern Pixel and `GrapheneOS` bootloaders scrub leftover Normal World LPDDR DRAM upon entering `fastboot` or rebooting from an unclean reset [106, 128].

What stops a thief from simply wiping a stolen phone via `fastboot flashing unlock` and reselling it? `Factory Reset Protection` (`FRP`) stores a dedicated persistent block (`/dev/block/by-name/frp`, managed in userspace by `frameworks/base/services/core/java/com/android/server/pdb/PersistentDataBlockService.java`) protected against untrusted writes [122, 123]. The `frp` partition stores two critical artifacts: an encrypted Google account / enterprise credential digest checked during SetupWizard after an untrusted recovery wipe, and at the *final byte* of the partition, the single-byte `oem_unlock_ability` flag (`0x00` by default; `0x01` only when the authenticated owner enters their valid `LSKF` PIN inside `Settings` $\to$ `Developer options` $\to$ `OEM unlocking`) [122, 123]. When `oem_unlock_ability == 0x00` (or when `Titan M2` `Weaver` / `RPMB` latches `unlock_ability = 0`), `ABL` refuses `fastboot flashing unlock` outright.

### `AvbVBMetaImageHeader` Binary Layout and Descriptor Verification

To eradicate pre-OS ASN.1/X.509 parser vulnerabilities, `AVB 2.0` (`external/avb/libavb/` in AOSP) encodes all partition verification metadata inside a flat, network-byte-order (big-endian) binary structure headed by the 256-byte `AvbVBMetaImageHeader` (`external/avb/libavb/avb_vbmeta_image.h`) [22, 88]:

```c
/* Exact byte offsets from AOSP external/avb/libavb/avb_vbmeta_image.h */
typedef struct AvbVBMetaImageHeader {
  uint8_t  magic[4];                        /*   0: "AVB0" */
  uint32_t required_libavb_version_major;   /*   4: 1 */
  uint32_t required_libavb_version_minor;   /*   8: feature floor (e.g. 0..3) */
  uint64_t authentication_data_block_size;  /*  12: 64-byte aligned */
  uint64_t auxiliary_data_block_size;       /*  20: 64-byte aligned */
  uint32_t algorithm_type;                  /*  28: e.g. SHA256_RSA4096 (2) */
  uint64_t hash_offset;                     /*  32: offset in Auth block */
  uint64_t hash_size;                       /*  40: 32 (SHA-256) or 64 (SHA-512) */
  uint64_t signature_offset;                /*  48: offset in Auth block */
  uint64_t signature_size;                  /*  56: 256 (RSA2048) / 512 (RSA4096) */
  uint64_t public_key_offset;               /*  64: offset in Aux block */
  uint64_t public_key_size;                 /*  72: AvbRSAPublicKeyHeader + n + rr */
  uint64_t public_key_metadata_offset;      /*  80: optional pkmd (avb_custom_key) */
  uint64_t public_key_metadata_size;        /*  88: 0 if unused */
  uint64_t descriptors_offset;              /*  96: packed AvbDescriptor array */
  uint64_t descriptors_size;                /* 104: total descriptor byte length */
  uint64_t rollback_index;                  /* 112: monotonic anti-rollback floor */
  uint32_t flags;                           /* 120: HASHTREE / VERIFICATION flags */
  uint32_t rollback_index_location;         /* 124: 0 for root vbmeta */
  uint8_t  release_string[48];              /* 128: NUL-terminated avbtool stamp */
  uint8_t  reserved[80];                    /* 176..255: must be zero */
} AVB_ATTR_PACKED AvbVBMetaImageHeader;
```

Immediately following byte `255` sit two 64-byte-aligned variable blocks verified in strict cryptographic-first order inside `avb_vbmeta_image_verify()` (`external/avb/libavb/avb_vbmeta_image.c`) [88, 129]. Before `libavb` trusts or dereferences *any* descriptor inside the Auxiliary Data Block, it validates integer addition bounds via `avb_safe_add()`, hashes the 256-byte `AvbVBMetaImageHeader` concatenated directly with the entire `Auxiliary Data Block` (skipping the `Authentication Data Block` in between!), verifies that the resulting `SHA-256` or `SHA-512` digest matches `AuthBlock[hash_offset]`, and verifies the PKCS#1 v1.5 RSA-2048 or RSA-4096 signature at `AuthBlock[signature_offset]` against the serialized `AvbRSAPublicKeyHeader` at `AuxBlock[public_key_offset]` [88, 129].

Even the public key format reflects bootloader minimalism: `AvbRSAPublicKeyHeader` stores `key_num_bits`, precomputed Montgomery constant $n_0' = -n^{-1} \bmod 2^{32}$, modulus $n$, and $R^2 \bmod n$ ($R = 2^{\text{bits}}$), enabling `avb_rsa_verify()` (`avb_rsa.c`) to compute $s^{65537} \bmod n$ in fixed stack buffers with zero Bignum heap allocations and zero division instructions [22, 129]. Once the RSA signature succeeds, `ABL` invokes its board callback `validate_vbmeta_public_key()` (or `validate_public_key_for_partition()`) to confirm whether the signing key matches the hardcoded OEM root (`GREEN`) or the `avb_custom_key` partition (`YELLOW`) [19, 129].

![Figure: AvbVBMetaImageHeader binary layout, Authentication and Auxiliary blocks, and delegated descriptor verification graph.](diagrams/01-extra-vbmeta-binary-layout.svg)

Only after cryptographic authentication completes does `avb_slot_verify()` (`avb_slot_verify.c` [129]) walk the packed array of `AvbDescriptor` records (`tag` + `num_bytes_following`, 8-byte aligned) inside `AuxBlock[descriptors_offset]` [130]:

First, `AvbHashDescriptor` (`tag = 2`, `avb_hash_descriptor.h`) authenticates entire partitions loaded into RAM prior to OS entry: `boot` (Boot Image Header v3/v4 containing the `GKI` kernel), `init_boot` (generic `init` ramdisk split out in Android 13+), `vendor_boot`, `dtbo`, and `pvmfw` [119, 130, 131]. For partitions without a dedicated `vbmeta` entry (or dynamic partitions), an `AvbFooter` (`"AVBf"`, 64 bytes placed at the very end of the partition) points backward to an appended `VBMeta` blob. `libavb` loads `image_size` bytes from the active slot (`boot_a`), hashes `salt || image_bytes` under `hash_algorithm` (`sha256` or `sha512`), and demands bit-for-bit equality with the descriptor's expected digest before allowing execution [129, 130].

Second, `AvbHashtreeDescriptor` (`tag = 1`, `avb_hashtree_descriptor.h`) covers multi-gigabyte read-only filesystems (`system`, `vendor`, `product`, `system_ext`, `odm`, resolved via `liblp` logical-partition extents inside `super` [120]) without stalling boot [130]. The descriptor authenticates `image_size`, `tree_offset`, `tree_size`, `data_block_size` ($4096$), `fec_num_roots` ($2$), `fec_offset`, `salt`, and the 32-byte `root_digest`, which `ABL` exports to the kernel via `bootconfig` / command-line substitutions so Linux `init` mounts each filesystem over `dm-verity` ([Chapter 2](02-antirollback-verity-apex.md)) [23, 119, 130].

Third, `AvbChainPartitionDescriptor` (`tag = 4`, `avb_chain_partition_descriptor.h`) enables `Project Treble` key delegation [12, 22, 130]. Inside the OEM-signed root `vbmeta`, a chain descriptor specifies `partition_name` (such as `vbmeta_system` or `vbmeta_vendor`), a dedicated `rollback_index_location` $s \in \{1, \dots, 31\}$, and the delegated authority's `public_key` bytes (for example Google's GSI/system key). `avb_slot_verify()` recursively loads `vbmeta_system_a`, verifies its `AvbVBMetaImageHeader` against that exact delegated public key (disallowing further nested chaining to bound stack depth!), checks `vbmeta_system`'s `rollback_index` against hardware slot $s$, and collects its child `AvbHashtreeDescriptor`s [129, 130].

![Figure: AVB 2.0 root VBMeta structure and delegated hash, hashtree, and chained partition descriptors.](diagrams/01-avb-vbmeta-descriptor-chain.svg)

Fourth, `AvbKernelCmdlineDescriptor` (`tag = 3`, `avb_kernel_cmdline_descriptor.h`) carries signed kernel command-line fragments gated by `flags`: fragments marked `AVB_KERNEL_CMDLINE_FLAGS_USE_ONLY_IF_HASHTREE_NOT_DISABLED` (`1 << 0`) activate normal `androidboot.veritymode=enforcing` parameters, whereas developer `userdebug` `fastboot --disable-verity` (`ORANGE` state setting `AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED` in `vbmeta.flags`) switches cleanly to `USE_ONLY_IF_HASHTREE_DISABLED` (`1 << 1`) [88, 130]. Finally, `avb_slot_verify_data_calculate_vbmeta_digest()` computes `verifiedBootHash` (`ro.boot.vbmeta.digest`) as the `SHA-256` across the concatenated verified `VBMeta` images in traversal order, binding every partition's exact cryptographic state into a single 32-byte measurement [22, 129].

## Vendor, OEM, & Custom-OS Boundaries

While `libavb` unifies `VBMeta` parsing across AOSP, everything *beneath* `libavb` (`Boot ROM` USB protocols, fuse provisioning, `fastboot` vendor commands, and `YELLOW` custom-key support) diverges sharply across OEMs [20, 105, 132, 133].

Google Pixel devices (`Tensor` + `Titan M2`) treat sovereign custom OS installation as a first-class architectural tier [20, 128]. An owner enables `OEM unlocking` in Settings, runs `fastboot flashing unlock` (`ORANGE`), installs `GrapheneOS`, flashes their release `avb_custom_key` (`pkmd.bin`), and runs `fastboot flashing lock`. Re-locking wipes `userdata`, latches `Titan M2` into `YELLOW` (`deviceLocked = true`, `verifiedBootState = SELF_SIGNED`, `verifiedBootKey = SHA-256(custom_pubkey)`), disables all `fastboot` flash/boot commands while locked, and enforces full `AVB`, `dm-verity` `FEC`, `Weaver` PIN throttling, and `Auditor` hardware attestation (`StrongBox` ECDSA pairing pinned to the `GrapheneOS` verified boot hash) [20, 128]. Conversely, most Samsung, Xiaomi, Motorola, and North American carrier-locked devices omit `avb_custom_key` support in `ABL` (stranding custom ROM users in `ORANGE`), or on Samsung Galaxy devices permanently blow a physical `Knox Warranty Bit` eFuse (`0x0` to `0x1`) on the very first unlock, irreversibly disabling `Knox Vault` enterprise workspaces even if stock firmware is later re-flashed [27].

A far more dangerous vendor boundary lies inside SoC Emergency Download (`EDL`) recovery protocols etched into mask `Boot ROM` for factory board bring-up and unbricking [105, 126]. On Qualcomm Snapdragon SoCs, shorting PCB test points, using a deep-flash cable, or corrupting `XBL` causes `PBL` to enumerate over USB as `05C6:9008` speaking Qualcomm's binary `Sahara` protocol [105]. `Sahara` accepts a signed ELF programmer (`prog_ufs_firehose_*.elf`) into SRAM; once authenticated against `QFPROM` `OEM_PK_HASH`, that programmer speaks an XML protocol (`Firehose`) capable of issuing raw `<read>` and `<program>` sector commands directly to any `UFS` LUN, completely beneath `ABL` lock states and `FRP` [105]! Properly engineered OEMs (`Google`, `Samsung`, modern `Sony`/`Xiaomi`) bind `Firehose` programmers to per-model `OEM_ID`/`MODEL_ID` fuses, increment programmer anti-rollback fuses, or enforce `VIP` (`Validated Image Programming`) chaining that restricts XML writes to factory-authenticated digest tables. When OEMs instead sign unrestricted `Firehose` programmers under a shared root key without fuse revocation, a single factory leak grants permanent physical flash R/W across entire product lines [105].

## Exploit Chains & Structural Limits

Real-world pre-OS compromises never break `RSA-4096` or `SHA-256`; they target residual debug `fastboot oem` commands, `fastboot` parser memory corruption, uninitialized DRAM across warm reboots, or leaked `Boot ROM` programmers.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Nexus 6 / Pixel `fastboot oem sha1sum` (`CVE-2016-8462`) | 2016 | OEM `ABL` `fastboot` handler | Physical USB `fastboot` after warm reset | Debug command computed `SHA-1` over arbitrary physical DRAM ranges, allowing byte-by-byte brute-force recovery of lingering RAM secrets | Remove memory-oracle `fastboot oem` commands; scrub DRAM on reset [134, 135] |
| Motorola `initroot` (`CVE-2016-10277`) | 2017 | Motorola `aboot` (`LK` `ABL`) | Physical USB `fastboot utag` config injection | Untrusted `initrd` address/size `utag` overrode verified `boot.img` ramdisk load address on locked bootloaders, granting `EL0` `init` root | Verify ramdisk exclusively via `AvbHashDescriptor`; ban untrusted `bootargs`/`utag` overrides [136] |
| OnePlus 3/3T Hidden Unlock & Verity Bypass (`CVE-2017-5626`, `CVE-2017-5624`) | 2017 | OxygenOS `aboot` (`ABL`) | Physical USB `fastboot oem 4F500301` & `disable_dm_verity` | Undocumented OEM `fastboot` commands unlocked the bootloader without `FRP` check or `userdata` wipe and disabled `dm-verity` while `GREEN` | Strip factory backdoors; `CDD` 9.10 + `VTS` lock/wipe compliance [122, 132] |
| Leaked Qualcomm `Firehose` `EDL` Programmers | 2017-2020 | SoC `PBL` `Sahara` / `Firehose` SRAM loader | Physical USB `05C6:9008` `EDL` mode | OEM-signed unrestricted `Firehose` ELF binaries leaked without `MODEL_ID` isolation or `QFPROM` rollback revocation, granting raw UFS R/W | Enforce `VIP` programmer digest tables, per-model fuse IDs, and `BFU` `StrongBox` `FBE` [105] |
| MediaTek `kamakiri` (`CVE-2020-0069`) | 2020 | MediaTek on-die `BROM` USB stack | Physical USB DMA control transfer in `BROM` mode | Unbounded length in `BROM` USB control-transfer DMA handler overwrote SRAM return pointers to run unsigned `preloader` code | Fixed in new silicon mask steppings; blow `SLA`/`DAA` eFuses to gate `BROM` USB [126] |
| Snapdragon `fastboot` Buffer Overflow (`CVE-2021-1931`) | 2021 | Qualcomm `ABL` `LinuxLoader` `fastboot` | Physical USB crafted `fastboot` packet length | Improper buffer-length and integer-bounds validation during `fastboot` command handling triggered pre-OS buffer overflow | Bounds-check `fastboot` buffers in `ABL`, increment `QFPROM` rollback fuse, migrate toward Rust `GBL` [121, 127, 137] |
| Unisoc Bootloader Stack Overflow (`CVE-2022-20210`) | 2022 | Unisoc `u-boot` `fastboot` parser | Physical USB oversized `fastboot` flash/download arg | Unchecked string/length copy on locked `fastboot` interface corrupted bootloader stack to bypass `AVB` verification | Patch `u-boot` `fastboot` bounds and restrict commands when `deviceLocked == true` [133] |
| Pixel `fastboot` `AFU` DRAM Disclosure (`CVE-2024-29745`, CISA KEV) | 2024 | Google Pixel `ABL` `fastboot` firmware | Physical forensic reboot from `AFU` into `fastboot` | Uninitialized memory handling in `fastboot` firmware exposed residual physical DRAM pages from the prior unlocked Android session over USB | Patch `ABL` buffer zeroing (April 2024 Pixel Bulletin) + full DRAM zeroization on bootloader entry [106, 128] |
| Android `ABL` `draw_surface_image` Overflow (`CVE-2025-36907`) | 2025 | `ABL` UI surface renderer (`abl/android/lib/draw/draw.c`) | Physical USB `fastboot` image payload on unlocked loader | Missing dimension/allocation bounds check in `draw_surface_image()` caused pre-OS heap out-of-bounds write | Harden `ABL` integer overflow checks and adopt memory-safe Rust `GBL` [121, 138] |

### Anatomy of Physical `fastboot` Zero-Days and `EDL` Boundaries

Two lessons stand out from this decade of pre-OS exploitation [105, 106, 118, 136, 139]. First, USB `fastboot` and recovery USB gadget stacks (`CVE-2021-39685` [139]) run *before* standard userspace `SELinux`, `Scudo`, or `Arm MTE` sandboxes exist, yet parse untrusted USB control transfers and command packets directly from physical attackers! In `CVE-2016-10277` (`initroot`), Motorola's locked bootloader faithfully verified `boot.img` via RSA, then allowed an unauthenticated `fastboot oem config fsg-id` `utag` parameter to redirect the Linux kernel's `initramfs` physical start address to an attacker-uploaded scratch buffer in RAM [136]. Seven years later, commercial forensic extractors exploited `CVE-2024-29745` on seized `After First Unlock` (`AFU`) Pixels by forcing a warm reset into `fastboot` and reading uninitialized bootloader heap/buffer regions over USB to recover lingering `AFU` filesystem keys from DRAM [106, 128]. Modern bootloaders therefore follow two strict rules: while `deviceLocked == true`, `fastboot` must reject almost every data-upload and vendor subcommand prior to allocation, and `ABL` must unconditionally scrub DRAM on reset so warm-reboot remnants vanish before USB enumerates [118, 128].

Second, even an unpatchable `Boot ROM` bug (`CVE-2020-0069`) or leaked `Firehose` programmer [105, 126] hits a hard cryptographic wall if the device was powered off (`Before First Unlock`, `BFU`) and seals keys inside discrete `StrongBox` silicon ([Chapter 3](03-trustzone-strongbox.md) and [Chapter 4](04-keymint-weaver-throttling.md)). Dumping 100 percent of `UFS` flash via `Firehose` yields only `AES-256-XTS` ciphertext whose `Weaver`-throttled unwrapping secret lives inside `Titan M2` or `Knox Vault` on a separate chip that `PBL` cannot read [26, 27, 92].

> **Warning.**
> Verified Boot (`GREEN` or `YELLOW`) guarantees code authenticity at boot, not physical flash secrecy by itself; conversely, unlocking into `ORANGE` does far more than skip `boot.img` signature checks: it flips `deviceLocked = false` inside `KeyMint`'s latched `RootOfTrust` on every boot, rendering prior `GREEN`/`YELLOW` keys undecipherable and marking every hardware attestation certificate `UNVERIFIED` [19, 28, 29].

Even on a tightly fused `GREEN` handset with zero `fastboot` or `EDL` flaws, two critical gaps remain at the exact instruction where `ABL` jumps to the Linux kernel. First, what stops an adversary with flash access from overwriting `vbmeta_a` and `boot_a` with *genuinely OEM-signed* older images from last year containing a known `EL1` kernel vulnerability? Second, because `ABL` verified only the 32-byte `AvbHashtreeDescriptor` root of `/system` rather than reading four gigabytes of flash at boot, how does the running kernel detect or heal tampered flash blocks at runtime while still allowing Google to push modular security patches via Play? [Chapter 2](02-antirollback-verity-apex.md) answers both questions.

## Inspecting via ADB, Fastboot, & Attestation

On any booted Android device with `adb` enabled, query the hardware-latched `AVB` lock state, verified boot color (`green`, `yellow`, or `orange`), composite `VBMeta` `SHA-256` digest, and bootloader revision exported by `init` from `bootconfig`:

```bash
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.vbmeta.digest
adb shell getprop ro.bootloader
```

Confirm whether the userspace *OEM Unlocking* gate (`FRP` unlock byte managed by `PersistentDataBlockService`) currently blocks `fastboot flashing unlock`, and inspect active `vbmeta` size and hash algorithm properties:

```bash
adb shell getprop sys.oem_unlock_allowed
adb shell getprop ro.oem_unlock_supported
adb shell getprop ro.boot.vbmeta.hash_alg
adb shell getprop ro.boot.vbmeta.size
```

Offline against an extracted factory image or custom OS build, use AOSP's `avbtool` to dump the 256-byte `AvbVBMetaImageHeader`, rollback index, `AvbHashDescriptor`s, `AvbHashtreeDescriptor`s, and `AvbChainPartitionDescriptor`s and verify the complete signature graph:

```bash
avbtool info_image --image vbmeta.img
avbtool verify_image --image vbmeta.img --follow_chain_partitions
avbtool calculate_vbmeta_digest --image vbmeta.img
```

From the pre-OS `fastboot` interface (`adb reboot bootloader`), inspect hardware lock status, active A/B slot, and fused secure-boot enforcement without altering device state:

```bash
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar secure
```
