# Anti-Rollback Indexes, dm-verity, fs-verity, and APEX Mainline

## Overview

* **Link in the Chain:** Temporal and runtime storage-integrity layer; extends [Chapter 1](01-bootrom-avb-vbmeta.md)'s boot-time `VBMeta` signature check forward across time (blocking signed partition downgrades) and across every runtime block and modular `APEX` read inside the running Linux kernel.
* **Core Security Invariant:** A signed `VBMeta` or `APEX` image is admitted only if its `rollback_index` satisfies $\text{index}_{\text{image}} \ge \text{floor}_{\text{RPMB}}$, and the kernel admits a $4\text{ KiB}$ read-only filesystem page into the page cache if and only if its salted `SHA-256` Merkle path (directly or after Reed-Solomon `FEC` parity repair) matches the `vbmeta`-authenticated root digest.
* **Ecosystem Enforcement Tier:** Enforced identically in `GREEN` and `YELLOW` locked states (`VERITY_MODE_RESTART` + `RPMB` hardware rollback counters); disabled or non-enforcing in `ORANGE` unlocked state (`fastboot --disable-verity`) where persistent `RPMB` counters are deliberately decoupled or frozen so developers can test older builds.
* **Trusted Computing Base (TCB):** `UFS`/`eMMC` `Replay Protected Memory Block` (`RPMB`) authenticated via `HMAC-SHA256` keyed in `TEE`/`StrongBox`, bootloader `libavb` slot rollback logic, Linux `drivers/md/dm-verity*` and Reed-Solomon `dm-verity-fec.c`, VFS `fs/verity/`, and userspace `system/apex/apexd`.
* **Seam & Handoff:** Guarantees immutable, downgrade-resistant OS and Mainline module code from flash to kernel page cache, but cannot by itself protect mutable cryptographic keys or throttle passcodes; hands isolated hardware secret execution to `TrustZone` and `StrongBox` in [Chapter 3](03-trustzone-strongbox.md).

## Threat Model & Ecosystem Constraint

Cryptographic signatures are timeless unless explicitly anchored to monotonic state. Suppose an OEM signs `boot.img` and `vbmeta.img` in January 2024 using its fused production key $K_{\text{OEM}}$, discovers a critical `EL1` privilege-escalation vulnerability in March 2024, and ships a patched build signed under the exact same fused key $K_{\text{OEM}}$ (because `Boot ROM` OTP fuses cannot be rotated in the field). Without hardware rollback protection, a physical adversary or privileged flash writer can overwrite the `boot` and `vbmeta` partitions with the genuine January 2024 images, pass every `RSA-4096` and `SHA-256` check in [Chapter 1](01-bootrom-avb-vbmeta.md) with `GREEN` status, and re-exploit the patched kernel vulnerability at will [13, 21].

A second threat arises *after* the bootloader exits. As established in [Chapter 1](01-bootrom-avb-vbmeta.md), `ABL` cannot pause boot for ten seconds to hash four gigabytes of `/system`, `/vendor`, and `/product` blocks linearly from `UFS` flash. Nor can one-time boot hashing defend against a dual-ported flash interposer or runtime block-device write that flips instructions on `/system` *after* Linux mounts the root filesystem [22, 23]. At the same time, consumer flash storage suffers rare, non-malicious cosmic-ray and charge-leakage bit flips over multi-year device lifetimes: if a single natural bit-rot error in an unused wallpaper or font file permanently bricked a locked phone into `RED` state, OEMs would pressure Android to weaken verification from fatal halt to silent `EIO` errors that attackers could abuse as partial bypasses [23].

Finally, even perfect immutable `/system` partitions create an ecosystem servicing dilemma. Historically, fixing a memory-corruption bug in Android's media extractor, `Conscrypt` TLS library, or `ART` runtime required rebuilding `/system`, re-computing the `dm-verity` Merkle tree, signing a full OEM OTA, and waiting months for SoC, OEM, and carrier certification [25, 27]. Android needed a way for Google to deliver cryptographically verified, rollback-protected binary updates to core OS components directly over Google Play while keeping those updates just as tamper-evident at block level as read-only partitions.

## Architecture & AOSP Implementation

### Hardware Anti-Rollback Indexes and `RPMB` Monotonic Storage

`AVB 2.0` defeats signed-image downgrade attacks by embedding a 64-bit unsigned `rollback_index` inside `AvbVBMetaImageHeader` (for root `vbmeta` at slot `0` and each chained partition such as `vbmeta_system` at slot $s \in \{1, \dots, 31\}$) and comparing that value against tamper-resistant non-volatile counters stored inside the flash chip's `Replay Protected Memory Block` (`RPMB`) or `StrongBox` NVM [13, 21, 26]. Defined by JEDEC `UFS` (`JESD220`) and `eMMC` (`JESD84`) standards, `RPMB` is a dedicated hardware partition inside the storage controller provisioned once at factory manufacture with a 256-bit shared secret key $K_{\text{RPMB}}$ known exclusively to the `UFS` controller and the SoC's `TrustZone` TEE (or discrete `StrongBox`) [26]. Every `RPMB` write frame carries an `HMAC-SHA256` computed under $K_{\text{RPMB}}$ over both the payload and a strictly monotonic 32-bit hardware write counter maintained internally by the `UFS` silicon; neither a compromised Normal World Linux kernel nor an external physical chip-off programmer can forge an `RPMB` decrement or replay an older `RPMB` frame [21, 26].

During `avb_slot_verify()`, for every rollback slot $i$ referenced by `vbmeta` and its `AvbChainPartitionDescriptor` children, `ABL` reads `stored_rollback_index[i]` via an `SMC` into the `TEE`/`StrongBox` `AVB` trustlet and enforces the admission inequality [13, 21]:

$$\text{image\_rollback\_index}[i] \ge \text{stored\_rollback\_index}[i]$$

If any partition carries a lower index than the stored floor, `libavb` rejects that A/B boot slot with `AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX`. Crucially, on A/B seamless-update devices (`boot_control` HAL), an OTA update writes new images to the inactive slot (say `slot b`) whose `rollback_index` exceeds `stored_rollback_index[i]`, yet `ABL` does *not* immediately ratchet the `RPMB` floor on the very first experimental boot of `slot b`: if `slot b` crashes before `update_engine` marks the slot `successful`, the device must still be able to fall back cleanly to `slot a` without bricking itself! Only once userspace confirms `markBootSuccessful()` does the bootloader/HAL permanently advance $\text{stored\_rollback\_index}[i] \leftarrow \text{image\_rollback\_index}[i]$ in `RPMB`, permanently sealing the door against the older `slot a` revision [21].

### Runtime Block Authentication: `dm-verity` and Reed-Solomon `FEC`

To verify multi-gigabyte read-only partitions (`EROFS` or `ext4`) with negligible boot latency, Android configures the Linux kernel's device-mapper `dm-verity` target (`drivers/md/dm-verity-target.c`) between the virtual filesystem and the underlying `/dev/block/by-name/system_a` `UFS` partition [22, 23]. At build time, `avbtool add_hashtree_footer` slices a partition of $N$ data blocks (each $B = 4096$ bytes) into leaf digests $h_{0,j} = \text{SHA-256}(\text{salt} \parallel \text{block}_j)$, packs $4096 / 32 = 128$ digests into each $4\text{ KiB}$ level-1 hash block, and recurses upward through $\lceil \log_{128} N \rceil$ levels until a single 32-byte root digest $R$ remains, which is signed inside `AvbHashtreeDescriptor` [13, 22]. For a $4\text{ GiB}$ `/system` image ($N = 2^{20}$ blocks), $\lceil \log_{128} 2^{20} \rceil = 3$ tree levels add less than $33\text{ MiB}$ ($\approx 0.8\%$) of hash metadata, and verifying any uncached $4\text{ KiB}$ page requires at most three intermediate hash-block checks (almost all already resident in the kernel page cache).

![Figure: Runtime block verification via dm-verity SHA-256 Merkle tree and Reed-Solomon Forward Error Correction.](diagrams/02-dm-verity-merkle-fec.svg)

What happens when $\text{SHA-256}(\text{salt} \parallel \text{block}_j)$ fails to match its authenticated parent digest? Early Android releases faced an ugly trade-off between `DM_VERITY_MODE_EIO` (returning an I/O error to the calling process while leaving the potentially compromised OS running) and `DM_VERITY_MODE_RESTART` (immediately rebooting the kernel and marking the partition corrupt). Android 7.0+ solved that trade-off cleanly by appending Reed-Solomon Forward Error Correction (`FEC`, `drivers/md/dm-verity-fec.c`) parity data to the end of every verified partition [22, 23].

Specifically, `avbtool` interleaves partition data and hash blocks across $\text{RS}(M = 255, K = 253)$ codewords over the Galois field $\text{GF}(2^8)$, appending $M - K = 2$ parity bytes per 253 data bytes ($\approx 0.8\%$ storage overhead) interleaved across distant physical flash erase blocks so a localized multi-page NAND media defect distributes at most one symbol error per Reed-Solomon codeword, allowing deterministic correction of up to $\lfloor (M - K)/2 \rfloor = 1$ corrupted byte per interleaved stripe (spanning several consecutive corrupted $4\text{ KiB}$ flash blocks on disk) [22, 23]. When `dm-verity` detects a hash mismatch on $\text{block}_j$, it invokes `fec_decode_rs8()` to reconstruct candidate repaired bytes and *re-computes* $\text{SHA-256}(\text{salt} \parallel \widehat{\text{block}}_j)$ against the signed Merkle tree. Random physical bit-rot heals transparently; an intentional multi-block malicious patch exceeds Reed-Solomon parity distance, fails the re-hash check, and safely triggers `VERITY_MODE_RESTART` into `RED` or A/B fallback [23].

### File-Granular Authentication with `fs-verity`

While `dm-verity` protects whole read-only block partitions, Android also stores security-sensitive read-only files (such as streamed `APK`s under Signature Scheme `v4` in [Chapter 10](10-apk-signing-scoped-storage.md), system certificates, and on-device ML artifacts) inside the mutable `/data` (`f2fs` / `ext4`) filesystem where block locations change dynamically [24, 81]. Linux's `fs-verity` (`fs/verity/`, upstreamed by Google engineers in Linux 5.4) brings `dm-verity`'s lazy Merkle-tree model up to the VFS inode layer [24].

Once a file is written completely to `/data`, enabling `FS_IOC_ENABLE_VERITY` marks the inode immutable at the VFS layer, builds a hidden per-file `SHA-256` $4\text{ KiB}$ Merkle tree stored past EOF in filesystem metadata, and computes a canonical `fsverity_formatted_digest` (`"FSVerity" || digest_algorithm || digest_size || merkle_root`). Whenever any process `mmap()`s or `read()`s a page from that inode, the filesystem's readpage path verifies the $4\text{ KiB}$ page against the inode's Merkle tree before marking the page `PG_uptodate`. Coupled with a PKCS#7 or `APK v4` signature over the `fs-verity` root digest verified inside the kernel keyring or `PackageManager`, `fs-verity` guarantees that even a privileged userspace bug with write access to `/data` directories cannot silently overwrite bytes inside an `fs-verity`-enabled file [24, 81].

### `Project Mainline` and Signed `APEX` Containers

Armed with `AVB`, `dm-verity`, and rollback floors, Android 10+ introduced the Android Pony EXpress (`APEX`) container format (`system/apex/`) to decouple security updates of core OS components from OEM firmware schedules (`Project Mainline`) [25, 27]. An `.apex` file is simultaneously a valid signed Android package and a miniature Verified Boot partition!

![Figure: Project Mainline APEX two-layer signature verification, anti-rollback enforcement, and dm-verity loopback mount pipeline.](diagrams/02-apex-mainline-mount-pipeline.svg)

Structurally, an `.apex` archive contains four files inside an uncompressed ZIP wrapper: `apex_manifest.pb` (Protobuf module name and version code), `AndroidManifest.xml` (allowing delivery through standard Google Play infrastructure), `apex_pubkey` (the module's dedicated `AVB` RSA public key), and `apex_payload.img` (a read-only `ext4` or `EROFS` filesystem image carrying an embedded `AvbFooter` and signed `AvbVBMetaImageHeader` at its end) [25]. Pre-installed baseline versions of every Mainline module (`com.android.art`, `com.android.conscrypt`, `com.android.resolv`, `com.android.media.swcodec`, `com.android.btservices`, `com.android.uwb`, `com.android.rkpd`, `com.android.virt`) reside on `/system/apex` (already protected by `/system`'s `dm-verity` tree).

When Google ships an out-of-band security patch via Google Play system updates, `PackageManager` stages the new `.apex` into `/data/apex/active` after verifying two independent cryptographic layers [25]: first, the outer ZIP's `APK Signature Scheme v3` signature must chain to the exact certificate of the factory-installed module on `/system/apex`; second, `apexd` (`system/apex/apexd/`) verifies `apex_payload.img`'s internal `VBMeta` signature against `apex_pubkey`, checks that `apex_manifest.pb`'s version satisfies anti-rollback constraints (including `KeyMint` `BOOT_PATCHLEVEL` / module version floors), attaches `/data/apex/active/*.apex` to a `/dev/block/loopN` block device, instantiates a live kernel `dm-verity` device over `apex_payload.img`'s `AvbHashtreeDescriptor`, and bind-mounts the verified filesystem read-only at `/apex/<module_name>@<version>` before `Zygote` starts [25, 27]. Even though the `.apex` file sits physically on mutable `/data`, altering a single byte of `/data/apex/active` on disk causes `dm-verity` to fault on page-in, forcing fallback to the immutable factory `/system/apex` baseline.

## Vendor, OEM, & Custom-OS Boundaries

Although `dm-verity` and `APEX` mechanics live in open-source AOSP and `GKI`, two crucial boundaries divide device tiers across the ecosystem [2, 16, 25]. First, `Project Mainline` automatic binary delivery through Play relies on Google signed module keys trusted inside GMS-certified builds (`GREEN`). Open-source AOSP derivatives such as `GrapheneOS` (`YELLOW`) build all `APEX` modules directly from source using their own release signing keys and deliver full atomic OS A/B updates rather than accepting third-party closed binary `APEX` pushes from Play, thereby keeping 100 percent of `/system` and `/apex` reproducible under a single sovereign root of trust [16].

Second, `RPMB` anti-rollback enforcement exhibits subtle hardware seams on lower-tier OEM boards. While `UFS` `RPMB` protects OS `VBMeta` slots (`vbmeta`, `vbmeta_system`), early-stage silicon bootloaders (`PBL` $\to$ `XBL` $\to$ `TZ`) rely on physical SoC OTP fuse arrays (`QFPROM` anti-rollback bitmasks) because `UFS` and `TEE` `RPMB` drivers are not yet initialized when `Boot ROM` runs in SRAM [18, 21]. Because physical SoC fuses have finite bit budgets (often 32 to 64 monotonic version steps across a chip's lifetime), OEMs frequently increment `RPMB` `AVB` rollback counters on every monthly Android Security Bulletin while incrementing hardware `QFPROM` fuse rows only after major `XBL` or `TrustZone` CVEs, leaving brief windows where pre-`ABL` loaders from a recent prior month remain loadable over `EDL` if physical access exists [17, 18].

## Exploit Chains & Structural Limits

Attacks against Android's persistence and anti-downgrade layer target misconfigured OEM `dm-verity` modes, `RPMB` initialization races, or `apexd` staging logic prior to `dm-verity` activation.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Legacy `VERITY_MODE_LOGGING` / `EIO` OEM Builds | 2015-2017 | Kernel `dm-verity` configuration | Post-exploit Ring 0 flash write or physical chip edit | Early OEMs shipped `eio` or `logging` mode instead of `restart` out of fear of NAND bit-rot bootloops, letting tampered blocks fail open or partially | Mandatory `CDD` Section 9.10 `FEC` + strict `VERITY_MODE_RESTART` tested by `CTS` [2, 23] |
| Unprovisioned / Test-Key `RPMB` Boards | 2017-2020 | `UFS`/`eMMC` `RPMB` provisioning in ODM factory | Physical flash replay of older `RPMB` counter sector | ODMs failed to program per-device random `RPMB` HMAC keys or bound `RPMB` keys to static test seeds | `VTS` KeyMint/Gatekeeper/AVB rollback tests and `RKP` silicon identity checks [3, 21] |
| Pre-Fuse `XBL`/`TZ` Trustlet Downgrade (`CVE-2019-10574` chains) | 2019-2021 | Pre-`ABL` firmware (`XBL` / `QSEE` trustlets) | Local root writing older OEM-signed trustlet `.mdt`/`.b00` files to `/vendor/firmware` or boot LUNs | OEMs patched vulnerable trustlets without blowing corresponding `QFPROM` hardware anti-rollback fuse bits | Blow SoC anti-rollback fuses on security fixes; enforce `/vendor` `dm-verity` over firmware blobs [18, 31] |
| Staging TOCTOU in Early `apexd` (`CVE-2020-0096` era) | 2020-2021 | Userspace `apexd` / `PackageManager` staging | Local privileged (`system`) write inside `/data/apex` | Symlink/race windows between outer signature verification and `dm-verity` loop binding before `SELinux` tightening | `SELinux` `apexd` `neverallow` write blocks + atomic hardlink/loop verification in `apexd` [25, 52] |

### Structural Limits of Verified Read-Only Partitions

`AVB 2.0`, `RPMB` rollback counters, `dm-verity`, `fs-verity`, and `APEX` achieve an extraordinary systems property: on a locked `GREEN` or `YELLOW` modern handset, *persistent file-based rootkits on `/system`, `/vendor`, `boot`, and `/apex` are functionally extinct* [4, 140]. Even when a nation-state commercial spyware chain ([Chapter 20](20-multivendor-spyware-chains.md)) achieves full `EL1` kernel read/write execution, modifying a single block of `/system` on `UFS` flash will fail Reed-Solomon `FEC` and trip `VERITY_MODE_RESTART` on reboot.

> **Key idea.**
> Verified Boot and `dm-verity` force modern mobile implants to become *ephemeral in-memory residents* or *mutable-data re-triggers* (hiding inside unverified `/data` application databases or re-infecting over browser/messaging exploits after every reboot), transforming a simple reboot into an effective eviction primitive against Ring 0 persistence [96, 140].

Yet immutable code partitions cannot protect secrets that must change at runtime: user encryption keys, FIDO2 passkeys, biometric authentication tokens, and attestation signing keys cannot live in public read-only `EROFS` images, nor can the Linux kernel in `EL1` hold them safely in normal DRAM if a GPU or USB driver bug compromises `Ring 0`. Protecting mutable secrets requires hardware isolated from `EL1` altogether, bringing us to `Arm TrustZone` TEEs and discrete `StrongBox` security processors in [Chapter 3](03-trustzone-strongbox.md).

## Inspecting via ADB, Fastboot, & Attestation

Verify active `dm-verity` enforcement mode (`enforcing` corresponds to `VERITY_MODE_RESTART`) and check mounted `dm-*` device-mapper targets backing `/` (`system`), `/vendor`, `/product`, and active `APEX` loopback mounts:

```bash
adb shell getprop ro.boot.veritymode
adb shell getprop partition.system.verified
adb shell mount | grep -E ' / | /vendor | /apex/' | head -n 6
```

List currently active `Project Mainline` `APEX` modules, comparing factory `/system/apex` baselines (`isFactory: true`) against Play-updated `/data/apex/active` revisions (`versionCode` / `36xxxxxxx`):

```bash
adb shell cmd package list packages --apex-only --show-versioncode | head -n 8
adb shell ls -l /data/apex/active
```

Inspect `AVB` rollback indexes and `dm-verity` Reed-Solomon `FEC` parameters (`num_roots: 2`, `SHA256`, salt, and root digest) embedded inside a local `system.img` or extracted `.apex` payload using `avbtool`:

```bash
avbtool info_image --image system.img
avbtool print_partition_digests --image vbmeta.img
```

To check whether an `APK` or file on `/data/app` has kernel `fs-verity` enabled at the VFS layer (`FS_VERITY_FL`), query package verification state via `dumpsys`:

```bash
adb shell dumpsys package com.android.chrome | grep -iE 'signatures|verity|versionCode' | head -n 6
```
