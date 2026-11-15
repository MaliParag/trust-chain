# APFS Signed System Volume, Cryptexes, and Shared Cache Trust

## Overview

* **Link in the Chain:** First file-system and dynamic-linking layer above `iBoot` ([Chapter 1](01-secure-boot.md)) and `SPTM` ([Chapter 4](04-silicon-memory-safety.md)); extends hardware boot verification across every 4 KB operating-system file block, rapid security patch image, and pre-linked shared library mapped into user space.
* **Core Security Invariant:** `XNU` mounts the root system namespace (`/`) strictly from a read-only `APFS` snapshot whose cryptographic Merkle tree root matches the `Image4` `IM4M` seal hash verified at boot, verifies every faulted system block on page-in, and maps a single `ASLR`-slid `dyld` shared cache authenticated with `PAC` and `TPRO` read-only protections.
* **Platform Matrix:** Unified `APFS` `Signed System Volume` (`SSV`), `Cryptex1` grafting, and `dyld4` shared-cache architecture across `iOS` (`15+`), `iPadOS`, `macOS` (`Big Sur 11+`), `watchOS`, `visionOS`, and `Private Cloud Compute`; `macOS` alone permits owner-authorized `csrutil authenticated-root disable` inside `1TR` `Reduced`/`Permissive Security` ([Chapter 2](02-mac-localpolicy.md)).
* **Trusted Computing Base (TCB):** `APFS` `fs_tree` and extent-hash Merkle verification inside `apfs.kext`, the `Image4` `SSV` and `Cryptex1` manifests (`TSS` or `LocalPolicy`), `dyld` (`dyld4` `PrebuiltLoader` and shared-cache builder), and `TPRO`/`APRR` hardware read-only memory protection for linker state.
* **Failure Horizon & Handoff:** Prevents persistent disk modification of OS binaries even under `EL1` kernel compromise, but cannot stop in-memory corruption of `dyld` writable loader state during process startup (`CVE-2026-20700`) or malicious code residing on the unsealed `Data` volume; hands off per-process code-signing and entitlement enforcement to `AMFI` and `TXM` ([Chapter 6](06-amfi-txm-notarization.md)).

## Threat Model & Design Tension

Cryptographically verifying the `XNU` kernel image at boot (`BootKC`, [Chapter 1](01-secure-boot.md)) leaves a massive persistence gap if the root filesystem mounted at `/` remains a mutable block volume. Over ninety-five percent of an operating system's privileged logic lives outside the kernel binary inside user-space daemons (`launchd`, `securityd`, `tccd`, `imagent`), system frameworks (`Security.framework`, `CoreGraphics`, `WebKit`), `PAM` modules, and configuration plists. Historically, on both `OS X` (`Rootless` / `SIP`) and early `iOS`, system files lived on a standard read-write or software-protected filesystem guarded only by runtime `MACF` access checks (`SF_RESTRICTED`) and per-binary code signatures. Whenever an attacker achieved a temporary kernel write primitive (or offline storage access without encryption), modifying a configuration file or replacing an unhashed resource on the root partition yielded silent persistence across reboots; conversely, checking individual X.509 signatures on tens of thousands of separate system files imposed launch overhead without detecting deleted files, downgraded system libraries, or tampered metadata.

Converting the entire multi-gigabyte operating system into a single cryptographically sealed, read-only Merkle tree (`Signed System Volume`, or `SSV`) solves rootkit persistence completely, yet immediately collides with three operational requirements [55, 56, 57]. First, UNIX expectations assume paths under `/` mix immutable binaries (`/usr/bin`) with mutable user and daemon state (`/Users`, `/Library`, `/private/var`). Second, rebuilding and re-downloading a 12 GB sealed OS snapshot every time Apple ships an urgent `WebKit` or `dyld` zero-day fix (`Rapid Security Response` / Background Security Improvement) would delay fleet patching by days. Third, linking 2,500+ system dynamic libraries separately at every `execve()` would burn tens of milliseconds and hundreds of megabytes of dirty page tables per app unless pre-linked into a shared cache whose internal pointers remain trustworthy across every process [58, 62].

## Silicon & System Mechanics

### APFS Volume-Group Split, Firmlinks, and the SSV Merkle Tree

Beginning with `macOS Catalina` and `Big Sur` (and unified onto `iOS 15` and later), Apple partitioned the operating system inside a single `APFS` container into an asymmetric *Volume Group* [55, 56, 60]. The `System` volume holds purely immutable Apple-supplied operating-system binaries, frameworks, and resources; the sibling `Data` volume (mounted at `/System/Volumes/Data` on `macOS` and `/private/var` on `iOS`) holds all mutable user files, installed applications, system databases, and logs. To preserve POSIX path compatibility without union-mount performance penalties, `APFS` introduces *bi-directional firmlinks* (`apfs_firmlink` entries listed in `/usr/share/firmlinks`): transparent VFS directory bridges connecting fixed paths on the read-only `System` volume (such as `/Users`, `/Library`, and `/Applications`) to their corresponding directories on the writable `Data` volume [55, 60].

Crucially, the booted `macOS` or `iOS` kernel *never mounts the live `System` volume B-tree directly* [56]. During OS installation or software update, an out-of-band ramdisk / updater constructs the clean `System` volume, captures an immutable `APFS` point-in-time snapshot, and computes a cryptographic Merkle hash tree (`SHA-256` / `SHA-384`) bottom-up across the entire snapshot [55, 56].

![Figure: APFS Signed System Volume (SSV) Merkle hash seal anchoring read-only catalog metadata and 4 KB file extents to the Image4 IM4M root digest alongside Personalized Cryptex1 grafts.](diagrams/05-apfs-ssv-cryptex-tree.svg)

In an `SSV`-sealed `APFS` snapshot, every 4 KB physical data block $B_j$ of every system file has its cryptographic digest recorded inside an *extent-hash tree*, while every file-system catalog record (inode permissions, `UID`/`GID`, symlink targets, firmlinks, and extended attributes) is hashed up through internal `fs_tree` B-tree nodes until collapsing into a single 384-bit root digest: the *APFS Seal Hash* ($H_{\text{seal}}$) [55, 56]:

$$H_{\text{seal}} = \text{MerkleRoot}_{\text{SHA-384}}\bigl(\text{Catalog B-Tree} \;\cup\; \{H(B_0), H(B_1), \dots, H(B_{m-1})\}\bigr)$$

During the `TSS` personalization handshake ([Chapter 1](01-secure-boot.md)), Apple's signing authority verifies that $H_{\text{seal}}$ matches the exact published Apple OS build and embeds $H_{\text{seal}}$ inside the device-personalized `Image4` `IM4M` manifest stored on `Preboot` [27, 56]. At boot, `iBoot` validates `IM4M` against `Boot ROM` (or `SEP` `OIHR` `LocalPolicy`) and hands the authenticated $H_{\text{seal}}$ directly to `XNU` and `apfs.kext`. When `apfs_vfsop_mount()` mounts `/` from the sealed snapshot, `apfs.kext` checks the snapshot superblock root against $H_{\text{seal}}$; subsequently, on *every single 4 KB VFS page-in* from NVMe flash, `APFS` hashes the incoming disk block and verifies its Merkle branch up to cached verified parent nodes before placing the page into the unified buffer cache [56, 61].

> **Key idea.**
> Under `APFS` `SSV`, even a live `EL1` kernel exploit that achieves raw NVMe controller write access cannot establish persistent rootkit survival on `/`: modifying a single bit of `/sbin/launchd` on flash causes the next cold boot's Merkle page-in verification to fail against the `Image4`-pinned $H_{\text{seal}}$, triggering an immediate kernel panic (`apfs_seal_broken`) or forcing recovery restoration [56].

### Cryptexes and Rapid Security Updates

Sealing `/` inside an immutable Merkle tree creates an acute servicing puzzle: how can Apple patch a zero-day inside `Safari` / `WebKit`, update Neural Engine compiler weights, or ship developer symbol tools without re-downloading and re-sealing the entire multi-gigabyte `System` snapshot? Apple solved this with *Cryptexes* (*Cryptographic Extensions*, specifically `Cryptex1` OS, `Safari`, and `SystemContent` bundles) [57, 61].

A `Cryptex` is a standalone, read-only disk image containing an `SSV`-style hashed `APFS` filesystem packaged as an `Image4` payload (`IM4P`) paired with its own `TSS`-personalized `IM4M` manifest (`Cryptex1` ticket bound to the chip's `ECID` and a dedicated Cryptex nonce) [57, 61]. At boot (or dynamically for developer disk images), `iBoot` and `libauthinstall` / `cryptexd` verify the `Cryptex` `IM4M` chaining to Apple's Root CA, register its companion dynamic trust cache with `TXM` ([Chapter 6](06-amfi-txm-notarization.md)), and *graft* (`mount_apfs` graft point) the verified `Cryptex` subtree directly onto designated mount slots in the system namespace (such as `/System/Cryptexes/OS` and `/System/Cryptexes/App`, symlinked/firmlinked into `/System/Library/PrelinkedKernels` or `dyld` shared-cache search paths) [57].

This `Cryptex` mechanism powers *Rapid Security Responses* (`RSR`, evolved in `iOS 26` and `macOS Tahoe 26` into *Background Security Improvements*) [57]. When Apple releases an out-of-band `WebKit` or `dyld` security patch, the device downloads only a compact delta `Cryptex` (~80 to 250 MB) containing the rebuilt `dyld_shared_cache` and patched frameworks, personalizes its `IM4M` ticket via `TSS`, and grafts it over the base OS build on quick reboot, delivering cryptographic `Image4` immutability at browser-extension update speed [57].

### dyld4, PrebuiltLoaders, and Shared Cache Trust

Once `XNU` validates a `Mach-O` executable's entry header during `execve()`, kernel space does not link dynamic libraries itself; instead, `XNU` maps the user-space Dynamic Link Editor (`/usr/lib/dyld`) into the fledgling process and transfers `EL0` execution to `_dyld_start` [58, 62]. Because nearly every process links hundreds of system frameworks (`libSystem.B.dylib`, `CoreFoundation`, `Foundation`, `UIKit`/`AppKit`, `Security`), reading and relocating individual `.dylib` files from disk per launch would be prohibitive. Instead, Apple pre-links over 2,500 system libraries into a single multi-gigabyte `dyld_shared_cache` file residing on the sealed `SSV` (or active `OS` `Cryptex`) [58, 62].

![Figure: dyld4 shared-cache mapping, single-boot ASLR slide, PrebuiltLoader validation, TPRO read-only state sealing, and the CVE-2026-20700 writable-state corruption boundary.](diagrams/05-dyld-shared-cache-trust.svg)

At early boot, `launchd` invokes a privileged shared-region syscall (`shared_region_check_np` / `map_with_linking`) causing `XNU` to choose a single random `ASLR` slide offset for the shared cache for that boot cycle [58]. Read-only `__TEXT` segments map clean and shared across all user processes; writable `__DATA_CONST` and Global Offset Table (`__AUTH_GOT` / `__AUTH_CONST`) pages containing cross-library pointers are rebased and signed with process-independent or shared-region `PAC` keys (`APDAKey` / shared diversifiers) upon fault-in (`vm_shared_region_slide_page`) so processes cannot tamper with sibling processes' library code [47, 58].

Modern `dyld4` (`iOS 15+` / `macOS Monterey+`) splits execution into an ahead-of-time *Closure / PrebuiltLoader* model and a runtime *JustInTimeLoader* fallback [58, 62]. For platform binaries and cached apps, `dyld4` precomputes a compact binary `PrebuiltLoaderSet` recording exact symbol bindings, dependency graphs, and fixup targets so startup performs zero Mach-O export-trie parsing. During `_dyld_start`, `dyld4` allocates internal runtime state (`RuntimeState`, `Allocator` pools) inside pages guarded by *Thread-Local Permission Restriction* (`TPRO`, an `APRR`/`SPRR` hardware permission index closely related to JIT isolation): while `dyld` actively loads a library (`dlopen()`) or applies initial fixups, the executing thread switches its core-local `TPRO` register to `RW-`, mutates `RuntimeState` and `__DATA_CONST`, and immediately flips `TPRO` back to `R--` before invoking untrusted library initializers or `main()` [5, 58, 62].

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, `watchOS`, and `visionOS`, the `dyld_shared_cache` is built offline by Apple inside Cupertino's build pipeline and baked directly into the sealed `SSV` image (or `Cryptex1` update); on-device software *never* rebuilds the shared cache locally, and `System` `SSV` sealing cannot be disabled [1, 56, 58]. Historically on `macOS` (`10.15` and earlier), `update_dyld_shared_cache` rebuilt the cache locally on the user's Mac, a privileged, fragile step eliminated in `macOS Big Sur` when Apple moved Macs onto pre-built `SSV`-sealed `dyld` caches matching `iOS` [60].

Today, `macOS` forks from `iOS` in only two carefully bounded ways [30, 56, 58]. First, third-party `macOS` apps frequently bundle their own private `.dylib` and `.framework` files outside the system shared cache, causing `dyld4` to exercise its runtime `JustInTimeLoader` path (`dlopen()` of notarized developer frameworks subject to Library Validation, [Chapter 6](06-amfi-txm-notarization.md)) far more heavily than locked `iOS` binaries. Second, if a developer explicitly enters `1TR` ([Chapter 2](02-mac-localpolicy.md)), switches a test volume to `Reduced` or `Permissive Security`, disables `SIP`, and runs `csrutil authenticated-root disable`, `LocalPolicy` permits mounting an unsealed `APFS` snapshot (`mount -uw` followed by `bless --mount ... --create-snapshot`), trading cryptographic `SSV` protection for custom system-framework experimentation on that volume alone [30, 32, 56].

## In-the-Wild Failures & Architectural Bounds

While `APFS` `SSV` eliminated persistent `/` disk modification in the wild (forcing macOS and iOS malware alike onto mutable `Data`-volume persistence (`LaunchAgents` on `macOS`, or non-persistent zero-click re-exploitation on `iOS`)) attackers shifted upward into `Cryptex` downgrade races and in-memory `dyld` state corruption (`CVE-2026-20700`).

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Rootless` Data-Volume Migration Pivot | 2020-2026 | `macOS` (`11`+) | Persistence after `SSV` sealed `/` | Because `/` became cryptographically read-only, commodity and APT implants pivoted to `/Library/LaunchDaemons`, user `LaunchAgents`, and `TCC`-abusing scripts on `Data` | Added `Background Task Management` (`BTM`) login-item notifications and `Launch Constraints` [56, 65, 89] |
| `Cryptex1` Nonce / Downgrade Pinning | 2022-2023 | `iOS` / `iPadOS` (`16`) | `WebKit` / `dyld` `Cryptex` version binding | Mismatched or unpinned `Cryptex1` tickets risked pairing a newer base kernel with an older vulnerable `Safari`/`dyld` graft | Enforced separate `Cryptex1` `TSS` nonces and strict `OS`/`Cryptex` epoch pairing [27, 57, 61] |
| `dyld` Env / `LC_LOAD_DYLIB` Hijacks | 2015-2024 | `macOS` | `dyld` search path & `DYLD_INSERT_LIBRARIES` | Unhardened third-party Mach-O binaries lacking `CS_RUNTIME` or Library Validation loaded attacker dylibs via `@rpath` or `DYLD_*` env vars | Mandatory Hardened Runtime (`CS_RUNTIME`) for Apple Notarization ([Chapter 6](06-amfi-txm-notarization.md)) [66, 70] |
| `CVE-2026-20700` (*DarkSword* `dyld` 0-Day) | 2026 | `iOS`, `iPadOS`, `macOS`, `watchOS`, `visionOS` (`< 26.3`) | `dyld` internal memory state integrity | Improper state management inside `dyld` allowed an attacker holding a process memory-write primitive to corrupt loader state and hijack arbitrary code execution | Patched `dyld` state synchronization in `iOS 26.3` / `18.7.5` & `macOS Tahoe 26.3`; reinforced by `MIE` (`EMTE`) on `A19`/`M5` [5, 59, 79] |

### CVE-2026-20700: Why dyld Is the Ultimate In-Process Escalation Target

In February and March 2026, Apple (`HT`/`26.3` advisories) and Google Threat Intelligence Group (`GTIG`, alongside iVerify and Lookout) disclosed `CVE-2026-20700`: an actively exploited zero-day memory-corruption vulnerability in `dyld` affecting `iOS`, `iPadOS`, `macOS Tahoe`, `watchOS`, `tvOS`, and `visionOS` prior to version `26.3` (and `iOS 18.7.5` / `macOS 15.7.4`), deployed inside the multi-actor *DarkSword* iOS exploit chain [59, 79]. Why would a sophisticated exploit chain that already achieved arbitrary memory read/write inside a process via `JavaScriptCore` (`CVE-2025-43529`) or a system daemon (`mediaplaybackd` via `CVE-2025-43510`) need a *separate* zero-day specifically inside `dyld`?

Under `PAC`, `SPTM`, `TXM`, and `TPRO`, an arbitrary heap read/write primitive inside an `arm64e` process no longer grants trivial arbitrary code execution! Executable pages are immutable in `SPTM` (`W^X`), `JIT` pages do not exist outside entitled browser engines, return addresses and `vtable` pointers carry unforgeable `PAC` signatures, and `__DATA_CONST` / `dyld` `RuntimeState` are write-locked behind `TPRO` except during transient `dyld` state transitions [5, 47, 58]. `dyld`, however, inherently possesses valid `PAC`-signing gadgets and legitimate authority to flip `TPRO` writable, bind symbols, and invoke initializer functions (`_ModInitFuncs`). Because `CVE-2026-20700` stemmed from improper state validation inside `dyld` when memory write access already existed, corrupting unguarded or unsynchronized `dyld` transition state tricked `dyld` itself into signing and dispatching attacker-controlled execution paths cleanly under valid `PAC` semantics [59, 79].

## Verification & Forensic Artifacts

Inspect the `APFS` Volume Group layout, active `Signed System Volume` (`SSV`) seal flag (`Sealed: Yes`), and mounted read-only `com.apple.os.update-*` boot snapshot on `macOS` using `diskutil` and `mount` [55, 56]:

```bash
diskutil apfs list | grep -E 'APFS Volume Disk|Name:|Role:|Sealed:|Snapshot' | head -n 12
mount | grep ' / '
```

Representative output on a sealed `macOS` host (`read-only`, `sealed`, mounted from an immutable snapshot rather than raw `disk3s1`):

```text
    Name:                      Macintosh HD (Case-insensitive)
    Role:                      System
    Sealed:                    Yes
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```

Inspect active `Cryptex` grafts (`OS` and `App` / `Safari`) mounted over `/System/Cryptexes` to verify rapid security patch state [57]:

```bash
mount | grep '/System/Cryptexes'
ls -la /System/Cryptexes/OS/System/Library/dyld/ 2>/dev/null | head -n 5
```

Representative output showing verified read-only `Cryptex` mounts hosting the active `dyld_shared_cache`:

```text
/dev/disk4s1 on /System/Cryptexes/App (apfs, sealed, local, read-only, nobrowse)
/dev/disk5s1 on /System/Cryptexes/OS (apfs, sealed, local, read-only, nobrowse)
```

Confirm the active `dyld_shared_cache` architecture (`arm64e`) and version loaded into the current process space:

```bash
ls -lh /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e* 2>/dev/null | head -n 3
```

Sealing `/` via `APFS` `SSV` guarantees that system files on disk match Apple's published release bit for bit, yet user space constantly executes binaries off the *mutable* `Data` volume (`/Applications`, downloaded tools, App Store apps). [Chapter 6](06-amfi-txm-notarization.md) traces how `AMFI`, `TXM` trust caches, `DER` entitlements, `Launch Constraints`, and `Notarization` govern every executable page faulted from any volume.
