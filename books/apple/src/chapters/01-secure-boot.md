# Immutable Boot ROM, iBoot, and Image4 Personalization

## Overview

* **Link in the Chain:** Hardware reset anchor of the Apple trust chain; executes directly from mask silicon (`Boot ROM`) at cold power-on to authenticate `LLB`, `iBoot`, co-processor firmwares, and the `XNU` `BootKC` kernel collection before any mutable operating-system instruction runs.
* **Core Security Invariant:** Boot stage $k$ transfers execution to stage $k+1$ if and only if stage $k+1$'s `Image4` payload (`IM4P`) matches the `SHA-384` digest inside a valid `ASN.1` `DER` manifest (`IM4M`) signed by the silicon-fused Apple Root CA (or delegated `LocalPolicy` root) whose `ECID`, `CHIP`, `CEPO`, and anti-replay `BNCH` nonce match the live hardware registers of this exact SoC.
* **Platform Matrix:** Unified across `iOS`, `iPadOS`, `watchOS`, `visionOS`, `Private Cloud Compute`, and `macOS` under `Full Security`; `macOS` alone permits owner-authorized `LocalPolicy` relaxation via `1TR` ([Chapter 2](02-mac-localpolicy.md)), while `PCC` extends the chain into public Transparency Logs ([Chapter 19](19-private-cloud-compute.md)).
* **Trusted Computing Base (TCB):** Mask `Boot ROM` (`SecureROM`) code and fused Apple Root CA public-key hash, on-die SRAM, the `USB` Device Firmware Upgrade (`DFU`) stack, early `AppleDART` IOMMU initialization, `SEP` random-nonce generation, and Apple's `Tatsu Signing Server` (`TSS`) infrastructure.
* **Failure Horizon & Handoff:** Cannot be patched in the field if mask `Boot ROM` contains parser, USB DMA, or `AppleDART` configuration bugs (`checkm8`, `usbliter8`); hands off an authenticated kernel and firmware state to `macOS` `LocalPolicy` ([Chapter 2](02-mac-localpolicy.md)), `SEP` key custody ([Chapter 3](03-secure-enclave.md)), and `SPTM`/`EMTE` runtime monitors ([Chapter 4](04-silicon-memory-safety.md)).

## Threat Model & Design Tension

Every higher-level security guarantee in an operating system rests on an unstated temporal assumption: that no adversary ran code on the application processor before the kernel initialized its page tables, sandboxes, and code-signing monitors. On open PC architectures, early firmware resides on a socketed or board-soldered SPI flash chip governed by mutable `UEFI` variables (`PK`, `KEK`, `db`, and `dbx`). When Microsoft or a Linux vendor discovers a memory-corruption bug inside a signed `UEFI` bootloader, revoking that binary requires pushing its `SHA-256` hash into finite NVRAM `dbx` storage across hundreds of millions of machines. Any attacker with local administrator or physical EFI System Partition write access on an unupdated host (or before fleet-wide `dbx` enforcement lands) can drop the legitimately signed old bootloader onto disk and exploit it to neutralize kernel integrity, a structural weakness exploited repeatedly by `BlackLotus` (`CVE-2022-21894`) and `Bitpixie` (`CVE-2023-21563`).

Apple's boot architecture was designed from early `iPhone` generations to eliminate both mutable SPI flash roots and denylist-based downgrade races [1, 19]. Against a Tier 2 physical adversary holding a stolen or seized device (capable of interposing custom USB microcontrollers in recovery modes, flashing arbitrary bytes onto NVMe/NOR boot partitions, replaying captured update manifests, or attaching high-speed Thunderbolt/PCIe DMA hardware) the boot chain must uphold three simultaneous properties. First, the initial verification code and root public key must be physically unmodifiable even by `UID 0` kernel exploits or hardware programmers. Second, firmware images signed by Apple for version $v$ must become cryptographically unbootable on individual devices once the user updates to version $v+1$ and Apple closes the signing window for $v$, without storing a growing denylist of revoked hashes on the device. Third, recovery over USB when storage is corrupted (`DFU` mode) must remain functional for factory servicing and bricked consumer devices without exposing unauthenticated execution primitives.

Balancing an immutable silicon reset path against live USB recovery creates a permanent engineering tension. Anything etched into mask `Boot ROM` during chip fabrication is immune to persistent rootkits, yet any memory-safety or DMA-configuration flaw inside that same ROM (`limera1n`, `checkm8`, `usbliter8`) becomes permanent for the physical lifetime of every chip taped out from that mask [21, 23, 24].

## Silicon & System Mechanics

### Mask Boot ROM and the Multi-Stage Bootstrap

When power stabilizes on an Apple Silicon SoC (`A`-series, `M`-series, or `S`-series) and the Power Management Unit (`PMU`) releases the primary Application Processor (`AP`) cluster from reset, execution begins at the architectural reset vector mapped directly to on-die read-only memory: `Boot ROM`, known internally in `iBoot` source trees as `SecureROM` [1, 19]. Fabricated as lithographic metal/via masks inside the silicon die itself, `Boot ROM` contains two foundational assets: the minimal bootstrap code (including `ASN.1` `DER` `Image4` parsers, cryptographic verification routines, storage/SPI drivers, and the USB `DFU` stack) and the cryptographic hash of the Apple Root CA public key [19]. Neither asset resides in rewritable flash; neither can be altered by firmware updates, JTAG without factory demotion fuses, or kernel exploits.

Because external LPDDR DRAM has not yet undergone memory-controller training at reset, `Boot ROM` executes entirely inside fast on-die Static RAM (`SRAM`), configuring stack protection, hardware `Pointer Authentication` (`PAC` on `A13` and `M1` onward, with `A12` `SecureROM` predating ROM-level `PAC` activation), and initial `MMU` `W^X` page mappings [19, 23]. `Boot ROM` inspects chip fuse registers reporting the 64-bit Exclusive Chip ID (`ECID`), SoC `CHIP` and `BORD` identifiers, Certificate Epoch (`CEPO`), Production Status (`CPRO`), and Security Mode (`CSEC`) [20]. On normal boot, `Boot ROM` reads the first mutable firmware stage (the Low-Level Bootloader (`LLB`), stored in dedicated NOR SPI flash on Macs or an early NVMe/`ANS` boot partition on mobile devices) into internal `SRAM` and verifies its `Image4` container [19, 29].

![Figure: Apple Silicon Secure Boot pipeline from immutable Boot ROM through LLB, iBoot, SPTM/TXM, and XNU, anchored by per-device Image4 (IM4P, IM4M, and IM4R) verification.](diagrams/01-secure-boot-image4-chain.svg)

Once `Boot ROM` validates `LLB`, it maps `LLB` executable, scrubs sensitive ROM workspace, locks ROM-only hardware registers (such as chip demotion or fuse-override latches), and jumps to `LLB` [19]. `LLB` performs low-level clock, voltage, and LPDDR DRAM controller training, checks battery/thermal thresholds, locates the main second-stage bootloader (`iBoot`, four-character tag `ibot`) on storage, and verifies `iBoot`'s `Image4` manifest in freshly trained DRAM before transferring control [19, 29]. If `Boot ROM` cannot locate or validate `LLB` (or if the user asserts the hardware button chord for Device Firmware Upgrade) `Boot ROM` falls back directly to `DFU` mode over USB without touching mutable flash, waiting for a host computer to stream a signed recovery `iBSS`/`iBEC` bootstrap image verified under the exact same `Image4` rules [19, 26].

### Early AppleDART Configuration and Peripheral Fencing

As soon as `iBoot` initializes DRAM and prepares to wake storage (`ANS`), display (`DCP`), USB, and PCIe buses, untrusted peripheral firmware enters the threat surface. If a Thunderbolt adapter, PCIe NVMe controller, or Synopsys USB controller could issue arbitrary physical memory writes while `iBoot` unpacks the kernel collection, peripheral DMA could overwrite verified code *after* `Image4` signature validation (`TOCTOU`).

To close that window, `iBoot` configures `AppleDART` (Device Address Resolution Table) and `SART` I/O MMU hardware units across peripheral buses prior to loading peripheral firmwares or enabling bus-mastering (`BME`) [16, 28]. Each `AppleDART` enforces hardware stream-ID isolation, mapping device-visible I/O virtual addresses (`IOVA`) exclusively to scratch DMA buffers carved outside `iBoot`'s own code, heap, page tables, and `BootKC` staging regions [28]. Beginning with `A14` and `M1` generations, Apple pushed `AppleDART` enforcement even earlier into `SecureROM` itself for the USB `DFU` controller after `checkm8` demonstrated the peril of unconstrained USB DMA state in pre-boot SRAM [21, 23, 28].

### Image4 Verification and TSS Per-ECID Personalization

Rather than signing monolithic firmware binaries valid on every iPhone or Mac in the world, Apple separates universal code (`IM4P`) from per-device authorization (`IM4M`) via the `Tatsu Signing Server` (`TSS`) personalization protocol [20, 27]. During an iOS restore, OTA update, or macOS `Full Security` installation, the update agent queries the target device for its hardware identity dictionary (`ApECID`, `ApChipID`, `ApBoardID`, `ApSecurityDomain`) alongside two fresh cryptographic nonces: an Application Processor boot nonce (`ApNonce`, tag `BNCH`) and a Secure Enclave boot nonce (`SepNonce`, tag `snon`) [27].

Crucially, `ApNonce` is not chosen freely by untrusted user-space software. Instead, `SEP` generates a high-entropy random seed (commonly termed the *generator* $g \in \{0,1\}^{64}$ or hardware nonce slot), stores $g$ in protected NVRAM/`SEP` state, and exposes only its one-way cryptographic commitment to the update client [20, 27]:

$$N_{\text{AP}} = \text{SHA-384}(g) \quad (\text{or } \text{SHA-256}(g) \text{ on older } \texttt{A7}\text{-}\texttt{A9}\text{ silicon})$$

The update host sends `ECID`, $N_{\text{AP}}$, `SepNonce`, and the `SHA-384` digests of every component in the target release's `BuildManifest.plist` (`LLB`, `iBoot`, `SEP` firmware `sepi`, `SPTM`, `TXM`, static trust cache, `BootKC`/`krnl`, and the `APFS` `SSV` root hash) over HTTPS to Apple's `TSS` cluster [27]. `TSS` checks an authoritative server-side policy table: is this exact OS build currently approved for signing on this `CHIP`/`BORD` model? Only if the signing window is open does `TSS` mint and sign a bespoke `IM4M` manifest (`ApTicket`) embedding the caller's exact `ECID`, hardware attributes, `BNCH` $= N_{\text{AP}}$, and component `SHA-384` map [19, 27].

![Figure: Per-device TSS firmware personalization sequence binding BuildManifest digests to the chip's unique 64-bit ECID and SEP-derived ApNonce to defeat fleet-wide downgrade replay.](diagrams/01-tss-apnonce-personalization.svg)

At boot time, `Boot ROM` and `iBoot` enforce both identity binding and anti-replay freshness:

$$\text{Verify}_{\text{PK}_{\text{AppleRoot}}}(\texttt{IM4M}) = 1 \;\land\; \texttt{IM4M.ECID} = \text{Fuse}_{\text{ECID}} \;\land\; \text{SHA-384}(\texttt{IM4P}) = \texttt{IM4M}[\text{tag}].\text{digest}$$

For restore/OTA-staged boots where `BNCH` enforcement is active, `LLB`/`iBoot` reads the stored generator $g$, recomputes $\text{SHA-384}(g)$, verifies equality against `IM4M.MANP.BNCH`, and rotates or invalidates the ephemeral nonce on restore so a previously captured `SHSH`/`IM4M` blob from iOS $v$ cannot be replayed once `SEP`/NVRAM rolls $g$ and `TSS` closes signing for $v$ [27]. Furthermore, if Apple ever discovers a severe vulnerability inside an early firmware stage (`LLB` or `iBoot`) requiring irrevocable hardware advancement, bumping the Certificate Epoch (`CEPO`) check in newer tickets or blowing one-time fuse latches blocks older epochs unconditionally [20].

> **Key idea.**
> x86 `UEFI` Secure Boot asks *"Is this signed bootloader on the local revocation denylist (`dbx`)?"*, failing open against every unrevoked historical binary. Apple `TSS` personalization asks *"Did Apple's live signing server explicitly bind this build to this chip's `ECID` and fresh `ApNonce` during an active signing window?"*, turning fleet-wide downgrade revocation into a single server-side policy toggle in Cupertino [19, 27].

### Kernel Collection Load and Handoff

Once `iBoot` is running in DRAM, it authenticates and loads companion `Image4` firmwares for `SEP` (`sepi`), `AOP`, neural/graphics controllers, `SPTM` (`sptm`), `TXM` (`txm`), and the static OS trust cache (`ltrs`), locking physical memory regions before starting the `Boot Kernel Collection` (`BootKC` on `macOS`, or the prelinked `kernelcache` on `iOS`) [19, 29, 49]. Before jumping to `XNU`'s `_start` entry point at `EL1` (and initializing `SPTM` in `GL2`), `iBoot` populates the read-only `DeviceTree` and `boot_args` structure with hardware topology, memory maps, random `KASLR` slide entropy derived from the hardware RNG, and the verified `Image4` manifest pointer so `APFS` can subsequently anchor the `Signed System Volume` (`SSV`) root hash without re-trusting disk metadata [29, 56]. If *any* required `Image4` signature or digest fails at `LLB` or `iBoot`, the bootloader refuses to fall back to an unsigned shell; instead, it forces entry into Recovery Mode (`iBEC`/ paired `1TR`) to request a fresh `TSS`-personalized restore [19, 29].

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, `watchOS`, and `visionOS`, the boot chain enforces `Full Security` with zero user-configurable toggles: `CPRO` and `CSEC` fuses are blown at manufacture, `TSS` personalization is mandatory for every OS install, and no local interface exists to enroll a user root key or boot an unsigned kernel [1, 19]. `watchOS` tightens physical attack surface further on recent `Apple Watch` models by eliminating exposed external USB data pads on consumer bands altogether, routing diagnostics over authenticated wireless recovery channels [1].

Two deliberate forks branch from this common `Boot ROM` $\to$ `iBoot` spine. First, on Apple Silicon Macs (`M1` through `M5`), `Boot ROM` and `LLB` remain 100% identical in rigor to `iPhone`, enforcing Apple Root CA `Image4` signatures unconditionally so no third-party bootkit can infect Stage 0 or Stage 1 [29]. However, `iBoot` on `macOS` checks whether a `SEP`-signed `LocalPolicy` (`lpnh`) chained from paired One True Recovery (`1TR`) authorizes `Reduced Security` or `Permissive Security` for a specific `APFS` volume group, the exact architectural fork dissected in [Chapter 2](02-mac-localpolicy.md) [29, 30]. Second, on `Private Cloud Compute` (`PCC`) server nodes, Apple removes local recovery persistence entirely: `PCC` blades boot statelessly over the data-center network using `Image4` manifests that must simultaneously validate against `Boot ROM` *and* appear in a public cryptographic Transparency Log audited by client devices ([Chapter 19](19-private-cloud-compute.md)) [2].

## In-the-Wild Failures & Architectural Bounds

Because `RSA-4096`/`ECDSA-P384` and `SHA-384` have never been cryptographically broken, every real-world compromise of Apple's boot chain has targeted implementation bugs inside immutable `Boot ROM` USB/image parsers, missing `AppleDART` DMA fences in `SecureROM`, or saved-generator replay windows prior to `SEP` keybag migration.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `limera1n` (`geohot`) | 2010 | `iOS` (`A4` `S5L8930X`) | `Boot ROM` `DFU` USB control path | Heap buffer overflow in `DFU` `cc_clear` length handling overwrote stack return address in SRAM | Fixed in `A5` mask ROM revision [24] |
| `SHAtter` | 2010 | `iOS` (`A4` `S5L8930X`) | `Boot ROM` `IMG3` `AES` `GID` engine | Unchecked `DFU` state reset allowed misusing ROM `GID` decryption oracle and `SHA-1` buffer length | Replaced `IMG3` with canonical `DER` `Image4` and isolated `GID` access [20, 25] |
| `checkm8` (`CVE-2019-8900`) | 2019 | `iOS`, `iPadOS`, `watchOS`, `tvOS`, `T2` (`A5`-`A11`, `S1P`-`S3`) | `SecureROM` USB `DFU` lifecycle | Heap use-after-free when incomplete USB control transfer (`0xA1, 1`) freed `io_buffer` while global state pointer survived across USB reset | Unpatchable on `A5`-`A11`; fixed pointer clearing in `A12` ROM and hardened `SEP` (`HT211843`) [21, 22] |
| `SHSH2` Generator Replay | 2016-2022 | `iOS` / `iPadOS` (with kernel R/W) | `TSS` `ApNonce` anti-replay | Existing kernel exploit wrote known `com.apple.System.boot-nonce` generator to NVRAM to replay previously saved `IM4M` tickets | Bound `Cryptex1` nonces and tightened `SEP` firmware compatibility across downgrades [27, 61] |
| `usbliter8` (Paradigm Shift) | 2026 | `iOS`, `iPadOS`, `watchOS` (`A12`, `S4`/`S5`, `A13`) | `SecureROM` Synopsys USB DMA & `AppleDART` | Synopsys USB controller decrements Setup DMA pointer by 24 B on 4th packet while accepting short 4 B writes (12 B backward SRAM underflow) with `SecureROM` USB `AppleDART` in bypass mode | Unpatchable in `A12`/`A13` mask ROM; `A14+` configures `AppleDART` inside `SecureROM` to block out-of-bounds USB DMA [23, 28] |

### Unpatchable Mask-ROM Defects: checkm8 and usbliter8

Two landmark hardware vulnerabilities nine and sixteen years into the `iPhone` lineage illustrate why mask-ROM immutability is a double-edged sword. In September 2019, `axi0mX` disclosed `checkm8` (`CVE-2019-8900`), a use-after-free in `SecureROM`'s USB `DFU` stack spanning seven generations of silicon from `A5` (`iPhone 4S`) through `A11` (`iPhone X` and the Intel Mac `T2` security chip) [21]. During `DFU` setup, a `DFU_DNLOAD` USB control transfer with `wLength > 0` allocated a global `io_buffer` on the SRAM heap. If the host left the data phase incomplete and triggered a bus reset into `DFU` re-initialization, `usb_core_stop()` freed `io_buffer` *without* nulling the global state structure's pointer. Subsequent USB descriptors reallocated that heap chunk with attacker-crafted fake task/callback metadata, yielding arbitrary `EL1`/`EL3` code execution inside `SecureROM` over a USB cable [21].

Apple fixed the dangling pointer in `A12` (`iPhone XS`) mask silicon, and for seven years `A12` and `A13` `SecureROM` withstood public scrutiny, with `A13` further adding hardware `PAC` return-address signing inside ROM [23]. Yet in June 2026, researchers at Paradigm Shift disclosed `usbliter8`, breaking `A12`, `S4`/`S5`, and `A13` `SecureROM` in under two seconds via an `RP2350` USB microcontroller attached to a device in `DFU` mode [23]. Rather than a software allocator bug, `usbliter8` combined a hardware state-machine quirk in the Synopsys DesignWare USB 2.0 controller with a missing `AppleDART` fence inside `SecureROM`. Specifically, the Synopsys controller buffers up to three 8-byte USB Setup packets via DMA ($3 \times 8 = 24\text{ B}$) and resets its internal DMA write pointer on the fourth Setup packet by subtracting a fixed $24\text{ bytes}$; however, when fed undersized 4-byte Setup packets ($3 \times 4 = 12\text{ B}$), the controller advances its pointer by $+12\text{ B}$ and then subtracts $24\text{ B}$, stepping the hardware DMA write pointer *backward* through SRAM by $\Delta = 12 - 24 = -12\text{ bytes}$ per cycle [23].

On `A11`, the ROM driver rewrote the DMA base register after every packet; on `A14` and all `M`-series silicon, `SecureROM` programs the USB `AppleDART` IOMMU strictly so an underflowing DMA pointer faults harmlessly at the buffer boundary [23, 28]. On `A12`, `S4`/`S5`, and `A13` alone, `SecureROM` left the USB `AppleDART` in bypass mode. On `A12` (lacking ROM `PAC`), stepping backward across SRAM overwrote a saved link register (`LR`) on the adjacent USB task stack; on `A13` (where `PAC` guards saved `LR`s), Paradigm Shift chained heap/task-state corruption to overwrite an unauthenticated USB interrupt-handler pointer in `.bss`, achieving `EL1` execution inside `SecureROM` to demote SoC debug flags or boot unsigned `iBoot` images [23].

> **Warning.**
> Neither `checkm8` nor `usbliter8` grants persistent untethered bootkits (because `Boot ROM` resets clean on every power cycle) nor automatic decryption of `Before First Unlock` (`BFU`) user data, because `SEP` runs its own independent `SEPROM` and keeps the silicon `UID` key locked behind hardware anti-replay passcode counters ([Chapter 3](03-secure-enclave.md)) [21, 23, 37]. However, on a seized device where the user later enters a passcode or where an `SEP` vulnerability coexists (as `Blackbird` showed on `A10` [22, 44]), ROM-level control completely bypasses `iBoot`, `SPTM`, `SSV`, and kernel code signing for that boot session.

## Verification & Forensic Artifacts

On an Apple Silicon Mac, inspect the live `DeviceTree` firmware properties populated by `iBoot` to confirm `SecureROM` / `iBoot` generation, hardware `AppleDART` presence, and active `AppleSecureBoot` enforcement without modifying system state [29, 32]:

```bash
ioreg -l -p IODeviceTree | grep -E '"secure-boot"|"firmware-version"|"chip-epoch"' | head -n 6
bputil -d | grep -E 'Security Mode|Boot Policy|coih'
```

Representative output on a Mac running `Full Security`:

```text
    |   "firmware-version" = <"iBoot-13822.101.4">
    |   "chip-epoch" = <01>
Security Mode                 : Full (1)
```

Verify that peripheral buses sit behind active `AppleDART` I/O MMU instances in the live `IOKit` registry [16, 28]:

```bash
ioreg -c AppleDART -r -d 1 | grep -E '\+-o AppleDART|"mapper- present"|"iommu"' | head -n 6
```

Representative output confirming dedicated per-controller `AppleDART` translation units:

```text
+-o dart-usb0@382f8000  <class AppleDART, id 0x100000214, registered>
+-o dart-apcie0@68008000  <class AppleDART, id 0x10000023a, registered>
+-o dart-ans2@7bcc4000  <class AppleDART, id 0x100000251, registered>
```

Inspect the personalized `Image4` `IM4M` manifest (`ApTicket`) staged on the `Preboot` volume for the booted `APFS` volume group using `openssl asn1parse` to observe the canonical `DER` `IM4M`, `MANB`, `MANP`, and `BNCH` tags [11, 20]:

```bash
MANIFEST=$(ls /System/Volumes/Preboot/*/boot/*/System/Library/Caches/apticket.der 2>/dev/null | head -n 1)
openssl asn1parse -inform DER -in "$MANIFEST" | head -n 10
```

Representative `ASN.1` `DER` structure showing the `IM4M` header and signed `MANB` body:

```text
    0:d=0  hl=4 l=3942 cons: SEQUENCE
    4:d=1  hl=2 l=   4 prim: IA5STRING         :IM4M
   10:d=1  hl=2 l=   1 prim: INTEGER           :00
   13:d=1  hl=4 l=2618 cons: SET
   17:d=2  hl=4 l=2614 cons: cont [ 1129074242 ]
   23:d=3  hl=2 l=   4 prim: IA5STRING         :MANB
```

On `iOS` and `iPadOS` devices under physical forensic triage, `DFU`-mode exploitation leaves volatile USB product-string markers (such as `PWND:[checkm8]` or `PWND: [usbliter8]` while tethered [21, 23]) and disappears on cold reboot, whereas legitimate boot firmware build strings (`iBoot-...`) and `ECID` values are recorded inside captured `sysdiagnose` archives (`ioreg.txt` and `SystemVersion.plist`). With the shared `Boot ROM` and `Image4` substrate established, [Chapter 2](02-mac-localpolicy.md) examines how Apple Silicon Macs reconcile this locked hardware boot pipeline with owner-authorized custom kernels and security downgrades.
