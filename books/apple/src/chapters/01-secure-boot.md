# Immutable Boot ROM, iBoot, and Image4 Personalization

## Overview

* **Link in the Chain:** Hardware reset anchor of the Apple trust chain; executes directly from mask silicon (`Boot ROM`) at cold power-on to authenticate `LLB` (`iBootStage1`), `iBoot` (`iBootStage2`), co-processor firmwares, and the `XNU` `BootKC` kernel collection before any mutable operating-system instruction runs.
* **Core Security Invariant:** Boot stage $k$ transfers execution to stage $k+1$ if and only if stage $k+1$'s `Image4` payload (`IM4P`) matches the `SHA-384` digest inside a canonical `ASN.1` `DER` manifest (`IM4M`) signed by the silicon-fused Apple Root CA (or delegated `LocalPolicy` root) whose `ECID`, `CHIP`, `BORD`, `SDOM`, `CEPO`, and anti-replay `BNCH` nonce match live SoC fuse and generator registers.
* **Platform Matrix:** Unified across `iOS`, `iPadOS`, `watchOS`, `visionOS`, `Private Cloud Compute`, and `macOS` under `Full Security`; `macOS` alone permits owner-authorized `LocalPolicy` relaxation via paired `1TR` ([Chapter 2](02-mac-localpolicy.md)), while `PCC` extends boot measurements into public Transparency Logs ([Chapter 19](19-private-cloud-compute.md)).
* **Trusted Computing Base (TCB):** Mask `Boot ROM` (`SecureROM`) code and silicon-fused Apple Root CA public-key hash, on-die SRAM, the `USB` Device Firmware Upgrade (`DFU`) 1.1 state machine, early `AppleDART` and `SART` DMA initialization, `SEP` random-nonce generation, and Apple's `Tatsu Signing Server` (`TSS`) infrastructure.
* **Failure Horizon & Handoff:** Cannot be patched in the field if mask `Boot ROM` contains USB `DFU` lifecycle bugs, `AppleDART` bypass windows, or `SEPROM` register truncations (`checkm8`, `Blackbird`, `usbliter8`); hands off an authenticated kernel and firmware state to `macOS` `LocalPolicy` ([Chapter 2](02-mac-localpolicy.md)), `SEP` key custody ([Chapter 3](03-secure-enclave.md)), and `SPTM`/`EMTE` runtime monitors ([Chapter 4](04-silicon-memory-safety.md)).

## Threat Model & Design Tension

Every runtime defense inside an operating system assumes no adversary ran code on the application processor or peripheral buses before the kernel initialized its page tables, sandboxes, and code-signing monitors. On modular x86 PCs, early firmware resides on an external SPI flash chip governed by mutable `UEFI` variables (`PK`, `KEK`, `db`, `dbx`) and historically allowed add-in cards to execute PCIe Option ROMs prior to OS load [92, 93]. Revoking a vulnerable signed `UEFI` bootloader requires distributing its digest into finite NVRAM `dbx` denylists across millions of hosts; an attacker with EFI System Partition write access on an unupdated host can stage the old signed loader to subvert ring-0 integrity before OS startup.

Apple's boot chain eliminates mutable flash roots, peripheral Option ROM execution, and denylist downgrade races simultaneously [29, 31, 33]. Against a Tier 2 physical adversary holding a seized device (attaching custom USB microcontrollers in recovery modes, reflashing NOR/NVMe sectors, replaying captured manifests, or plugging bus-mastering Thunderbolt hardware into external ports), Stage 0 and Stage 1 enforce three invariants: reset code and the root public key live in immutable silicon masks beyond `UID 0` or programmer reach; firmware for version $v$ becomes cryptographically unbootable on a chip once updated to $v+1$ after Apple closes signing for $v$ [31]; and USB `DFU` recovery unbricks wiped storage without exposing unauthenticated execution [29, 94].

Reconciling mask-ROM immutability with USB recovery creates a permanent design tension: code etched into `Boot ROM` resists persistent bootkits (`Thunderstrike`), yet any memory-safety or DMA defect inside that mask (`limera1n`, `checkm8`, `usbliter8`) remains frozen across every SoC fabricated from that stepping [17, 18, 95].

## Silicon & System Mechanics

### SecureROM, Boot-Interface Descriptors, and Fuse Configuration Tags

When supply rails stabilize on an Apple Silicon SoC and the Power Management Unit (`PMU`) releases the boot Application Processor (`AP`) core from reset, architectural execution begins at the hardwired reset vector mapped directly to on-die mask read-only memory: `Boot ROM`, named `SecureROM` throughout Apple's `iBoot` source codebase [29, 96]. Fabricated as immutable metal/via layers inside the SoC die, `SecureROM` embeds minimal `AArch64` bootstrap routines, a deterministic `ASN.1` `DER` `Image4` verifier, `SHA-384` and `RSA-4096`/`ECDSA-P384` routines, block/SPI storage drivers, a minimal USB 2.0 Device Firmware Upgrade (`DFU`) device stack, and the cryptographic `SHA-384` hash of the Apple Root CA public key [29, 30]. Because external LPDDR DRAM requires complex PHY training before storing data reliably, `SecureROM` executes exclusively out of fast on-die Static RAM (`SRAM`), immediately mapping SRAM regions with strict `W^X` (`XN` on stack, heap, and download buffers) MMU attributes and initializing `Pointer Authentication` (`PAC` `APIAKey` seeded from the hardware `TRNG` on `A13` and `M1` onward) [18, 29, 97].

During early hardware bring-up, `SecureROM` reads one-time-programmable silicon eFuses and configuration latches that define the chip's permanent cryptographic identity and debug posture, exporting them both to its internal `Image4` evaluator and to USB recovery descriptors (`SRNM` / non-sensitive status strings) [30, 96, 98]. Specifically, `SecureROM` inspects the 64-bit per-die Exclusive Chip ID (`ECID`), the 16-bit SoC `CHIP` identifier (for instance, `0x8103` for `M1` or `0x8140` for `A18`), the board configuration `BORD`, the Security Domain (`SDOM`, `0x01` for Apple consumer silicon), the minimum Certificate Epoch (`CEPO`, preventing pre-epoch root/intermediate certificates from validating newer silicon), Production Status (`CPRO` / `EPRO`, `1` on fused retail units, `0` on factory pre-production prototypes), Security Mode (`CSEC` / `ESEC`, `1` enforcing secure boot), and the Chip Platform / Demotion register (`CPFM` and `DEM`) [30, 96]. On internal Apple debug prototypes (or temporarily in RAM when a researcher already holds a `SecureROM` exploit), setting the hardware Demotion bit (`DEM`) suppresses `EPRO` production enforcement while simultaneously instructing the hardware `AES` engine to disable production `GID` keys and switch to development `KBAG` slots (`kclass = 2`), ensuring that demoting a chip to attach JTAG/SWD never leaks production `GID`-encrypted firmware secrets [30, 88, 96].

To locate the first mutable bootloader stage, `SecureROM` iterates through a compiled-in array of *boot-interface descriptors* determined by board strap pins [29, 96]. On mobile devices (`iOS`, `iPadOS`, `watchOS`, `visionOS`), `SecureROM` probes the internal `ANS` NVMe/flash boot namespace; on Apple Silicon Macs, `SecureROM` reads dedicated boot NOR SPI flash [7, 96]. From the first responsive boot interface, `SecureROM` loads the Low-Level Bootloader (`LLB`, compiled from the `iBoot` codebase as `iBootStage1` with four-character `IM4P` tag `illb`) into an `SRAM` staging carveout and runs full `Image4` verification [7, 29, 96].

![Figure: Apple Silicon Secure Boot pipeline from immutable Boot ROM through LLB, iBoot, SPTM/TXM, and XNU, anchored by per-device Image4 (IM4P, IM4M, and IM4R) verification.](diagrams/01-secure-boot-image4-chain.svg)

If `LLB` passes verification, `SecureROM` enforces three irreversible one-way hardware transitions before branching to `LLB` [29, 96, 97]. First, `SecureROM` writes a hardware lock bit disabling `SecureROM`'s own memory-mapped window (or unmapping sensitive ROM routines) and locking the `DEM` demotion latch until the next cold reset. Second, if `LLB` or subsequent stages are not permitted to invoke `SecureROM`'s `GID` key slot directly on older steppings (or if a stage fails validation), `SecureROM` writes the `AES` key-disable register to block unauthorized `GID` oracle calls [96, 99]. Third, `SecureROM` zeroes its `SRAM` stack and cryptographic scratchpad before jumping to `LLB`. If every boot-interface descriptor fails to yield a valid `illb` container (or if the user asserts the hardware `DFU` button chord at cold reset), `SecureROM` enables the Synopsys USB controller in `DFU` mode and waits for a host restore client (`Finder`, `Apple Configurator`, or `idevicerestore` via `libirecovery`) to stream a signed recovery first-stage loader (`iBSS`, also built from `iBoot`) verified under identical `Image4` rules [29, 94, 98].

### LLB to iBootStage2 and Memory-Safe iBoot Hardening

Running inside `SRAM`, `LLB` (`iBootStage1`) brings up PMIC rails, trains external LPDDR DRAM, initializes `ANS` NVMe via `SART`, evaluates Mac `LocalPolicy` or `Preboot`/NOR directories, and loads `iBoot` (`iBootStage2`, tag `ibot`, or recovery `iBEC`) into DRAM [7, 29, 96]. Because `iBootStage2` parses `APFS` `Preboot` containers, `DeviceTree` overlays, display splash planes, USB/Thunderbolt recovery transports, and `Image4` manifests (`sepi`, `sptm`, `txm`, `BootKC`), Apple `SEAR` hardened `iBoot` with systematic memory-safety defenses [97]: dynamic allocations are segregated into type-aware heap zones flanked by unmapped guard pages, compiler bounds checks wrap pointer and slice arithmetic, heap chunk headers carry boot-random integrity secrets (`heap_panic` on mismatch), indirect pointers use `ARMv8.3-A` `PAC` (`FPAC` on `A14`/`M1`+), and strict `W^X` bars writable executable mappings [97].

### Pre-Boot AppleDART and SART Fencing vs. Option ROM and DMA Attacks

To appreciate Apple Silicon's pre-boot peripheral fencing, consider how Intel Macs failed against Thunderbolt devices between 2014 and 2019. In `Thunderstrike` (`CVE-2014-4498`), Trammell Hudson showed that Intel Mac `EFI 1.10` executed unsigned PCIe Option ROMs off Thunderbolt adapters *before* firmware passwords or OS boot checks while leaving `BIOS_CNTL` SPI flash unlocked across EFI updates, allowing a Thunderbolt dongle to flash a permanent bootkit [92]. Eight months later, `Thunderstrike 2` (`CVE-2015-3707` et al.) demonstrated wormable Option ROM reflashing from `UID 0` and unlocked `TSEGMB` DMA into `SMRAM` [93]. Even with Intel `VT-d` enabled, Ulf Frisk's `PCILeech` and the NDSS 2019 `Thunderclap` study by Markettos et al. showed that late IOMMU setup, 4 KB sub-page buffer sharing, and untrusted PCIe `ATS` leaked kernel RAM over DMA [100, 101].

Apple Silicon eliminates Option ROM execution and pre-boot peripheral DMA structurally [7, 33, 68, 69]. Neither `SecureROM`, `LLB`, nor `iBoot` includes any UEFI `DXE` or PCIe Option ROM loader: external Thunderbolt/PCIe peripherals never supply host code [7, 33]. External PCIe root ports reset with Bus Master Enable (`BME`) cleared, dropping upstream DMA packets until `AppleDART` (`dart-apcie*`) enables `TRANSLATE_ENABLE = 1` with `SP_START`/`SP_END` sub-page bounds [33, 68]. Internal `ANS` NVMe controllers sit behind `SART` (`drivers/soc/apple/sart.c`), exposing only `iBoot`'s staging buffers while shielding bootloader code and manifests [33, 69], and `A14`/`M1`+ mask ROMs enable `dart-usb*` inside `SecureROM` itself [18, 33].

### The Image4 Verification Graph and TSS Per-ECID Personalization

At every stage boundary (`SecureROM` $\to$ `LLB`, `LLB` $\to$ `iBoot`, and `iBoot` $\to$ `{sepi, sptm, txm, ltrs, krnl}`), admission reduces to evaluating the canonical `ASN.1` `DER` `Image4` verification graph introduced in [Foundations](00b-foundations.md) [29, 30, 86, 88].

![Figure: Image4 (IMG4) ASN.1 DER verification graph uniting universal IM4P firmware payloads, TSS-signed IM4M manifests (MANB, MANP, and OBJP), and IM4R BNCN anti-replay nonces.](diagrams/01-extra-image4-der-tree.svg)

Separating universal `IM4P` binaries from tiny (~4 KB) `ECID`-bound `IM4M` manifests (`ApImg4Ticket`) enables Apple's `Tatsu Signing Server` (`TSS`) personalization protocol to defeat fleet-wide downgrade attacks without local `dbx` revocation lists [30, 31, 98]. During an `iOS`/`visionOS` restore, OTA update, or `macOS` `Full Security` install, the update agent queries the target device for its silicon identity (`ApECID`, `ApChipID`, `ApBoardID`, `ApSecurityDomain`) together with two hardware-backed single-use commitments: an Application Processor boot nonce (`ApNonce`, `MANP` tag `BNCH`) and a Secure Enclave boot nonce (`SepNonce`, tag `snon`) [31, 98].

Crucially, `ApNonce` is never transmitted in raw seed form during normal updates. Instead, `SEP` (or `iBoot` backed by `SEP` secure storage) generates a random 64-bit *generator* seed $g \in \{0,1\}^{64}$ (`BNCN` inside `IM4R` / NVRAM `com.apple.System.boot-nonce`), seals $g$ inside non-volatile state, and exports only its one-way `SHA-384` (or `SHA-256` on older `A7`–`A9` chips) hash to the restore client [30, 31, 86]:

$$N_{\text{AP}} = \text{SHA-384}(g), \qquad \texttt{IM4R.BNCN} = g, \qquad \texttt{IM4M.MANP.BNCH} = N_{\text{AP}}$$

The restore client transmits `ECID`, $N_{\text{AP}}$, `SepNonce`, and the `SHA-384` component digests from the release's `BuildManifest.plist` over HTTPS to Apple's `TSS` signing authority [31, 98]. `TSS` consults its live signing-policy matrix: if Apple has closed the signing window for that older `iBoot` or `XNU` build after patching a vulnerability, `TSS` refuses to sign the manifest, rendering old `.ipsw` archives uninstallable worldwide within seconds of policy cutover [31]. Only for actively signed builds does `TSS` return an `IM4M` signed under Apple's Secure Boot CA chaining to the silicon-fused Apple Root CA [29, 31].

![Figure: Per-device TSS firmware personalization sequence binding BuildManifest digests to the chip's unique 64-bit ECID and SEP-derived ApNonce to defeat fleet-wide downgrade replay.](diagrams/01-tss-apnonce-personalization.svg)

At boot, `SecureROM`, `LLB`, and `iBoot` evaluate the four-part conjunction over the `DER`-encoded `MANB` body [29, 30, 31]:

$$\text{Verify}_{\text{PK}_{\text{Root}}}(\texttt{IM4M}) = 1 \;\land\; \texttt{MANP}_{\text{hw}} = \text{Fuses}_{\text{SoC}} \;\land\; \text{SHA-384}(g_{\text{stored}}) = \texttt{MANP.BNCH} \;\land\; \text{SHA-384}(\texttt{IM4P}) = \texttt{OBJP}[\tau].\texttt{DGST}$$

On restore or OTA installation, `SEP` rolls $g_{\text{stored}} \to g'_{\text{fresh}}$, permanently invalidating every historical `IM4M` ticket previously captured for `ECID` (`SHSH` blobs) unless an attacker *already* holds an active kernel/NVRAM write exploit capable of overwriting `com.apple.System.boot-nonce` back to the saved generator $g$ *and* the target `sepOS` firmware (`sepi`) remains cryptographically and structurally compatible with the current on-disk `SEP` anti-replay state [31, 102]. Should an early firmware flaw ever demand irrevocable hardware advancement across reboots, bumping `CEPO` (Certificate Epoch) or blowing SoC epoch fuses blocks pre-epoch signatures unconditionally [30, 96].

> **Key idea.**
> x86 `UEFI` Secure Boot asks *"Is this signed bootloader listed on the local revocation denylist (`dbx`)?"*, failing open for every unrevoked historical binary. Apple `TSS` personalization asks *"Did Apple's live signing server explicitly bind this exact build to this chip's 64-bit `ECID` and current `SEP` `ApNonce` while the signing window was open?"*, turning global downgrade revocation into an atomic server-side policy switch [29, 31].

### Kernel Collection Handoff and DeviceTree Sealing

Once `iBootStage2` executes in DRAM, it validates and dispatches companion `Image4` payloads for `SEP` (`sepi`, staged in `RAM` for `SEPROM` to verify independently), `AOP` and `RTKit` peripheral firmwares, `SPTM` (`sptm`), `TXM` (`txm`), the base OS static trust cache (`ltrs`), and the `MH_FILESET` `Boot Kernel Collection` (`BootKC` / `krnl`) [7, 29, 89]. Before transferring CPU control to `SPTM` (`GL2`) and `XNU`'s `_start` (`EL1`), `iBoot` populates the flattened `DeviceTree` (`SecureDT`, including `pmap-io-ranges` physical `MMIO` allowlists and `AppleDART` topology), injects `TRNG`-derived `KASLR` slide entropy into `boot_args`, locks `KTRR`/`CTRR` physical read-only memory ranges, and hands the authenticated `IM4M` pointer to `XNU` so `apfs.kext` can anchor the `Signed System Volume` (`SSV`) root hash without trusting mutable disk superblocks [7, 90]. Any signature or digest failure at `LLB` or `iBoot` scrubs staging memory and traps directly into Recovery Mode (`iBEC` or paired `1TR`) [7, 29].

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, `watchOS`, and `visionOS`, Secure Boot operates exclusively in `Full Security` [29, 31]. Factory fuses permanently lock `CPRO = 1` and `CSEC = 1`, `TSS` personalization is mandatory for every restore and OTA update, and zero user-facing mechanisms exist to enroll a custom root key or relax signature checks. Recent `Apple Watch` generations narrow physical Tier 2 exposure further by removing consumer-accessible external USB data pads, performing recovery restores over authenticated wireless diagnostics transports [94].

Two intentional architectural forks branch above `LLB` while preserving 100% identical `Boot ROM` and `LLB` silicon verification. First, on Apple Silicon Macs (`M1` through `M5`), `Boot ROM` and `LLB` still enforce Apple Root CA signatures unconditionally (guaranteeing no third-party bootkit ever runs in Stage 0 or Stage 1), but `LLB` and `iBoot` inspect the per-volume-group `LocalPolicy` (`IM4M` signed by the Mac's own `SEP` `OIHR` key inside paired One True Recovery `1TR`) to permit owner-authorized `Reduced Security` or `Permissive Security` (`CustomOS` `coih` images such as Asahi Linux `m1n1`), dissected in [Chapter 2](02-mac-localpolicy.md) [7, 8]. Second, on `Private Cloud Compute` (`PCC`) server nodes, Apple eliminates persistent local boot storage and recovery downgrades altogether: `PCC` nodes boot statelessly from ramdisks whose `Image4` manifests must validate against `Boot ROM` *and* match an append-only cryptographic Transparency Log audited by client devices ([Chapter 19](19-private-cloud-compute.md)).

## In-the-Wild Failures & Architectural Bounds

Because `RSA-4096`, `ECDSA-P384`, and `SHA-384` remain unbroken, every real-world compromise of Apple's pre-OS boot pipeline has exploited memory-corruption bugs in `Boot ROM`'s USB `DFU` stack, missing `AppleDART` DMA protections inside `SecureROM`, `SEPROM` MMIO register width truncations, or saved-nonce replay windows.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `limera1n` (`geohot`) | 2010 | `iOS` (`A4` `S5L8930X`) | `Boot ROM` `DFU` USB heap | Unchecked length in `DFU` download buffer handling overflowed SRAM heap metadata to overwrite saved `LR` | Fixed bounds validation in `A5` mask ROM [95] |
| `SHAtter` (`pod2g` / Chronic Dev) | 2010 | `iOS` (`A4` `S5L8930X`) | `Boot ROM` `IMG3` `SHA-1` & `GID` | Unchecked `DFU` reset state allowed abusing ROM `SHA-1`/DMA length to gain execution with `GID` active | Replaced custom `IMG3` with canonical `ASN.1` `DER` `Image4` and gated `GID` key slots [30, 88, 99] |
| `Thunderstrike` & `Thunderstrike 2` (`CVE-2014-4498`, `CVE-2015-3707`) | 2014-2015 | Intel `OS X` Macs | Pre-boot Thunderbolt Option ROM & SPI flash | `EFI 1.10` executed unsigned Thunderbolt PCIe Option ROMs and left `BIOS_CNTL` SPI flash / `TSEGMB` SMRAM unlocked | Eliminated Option ROM execution and external mutable BIOS flash on Apple Silicon; enforced `AppleDART` [33, 92, 93] |
| `Thunderclap` & `PCILeech` Pre-Boot DMA | 2016-2019 | Intel `macOS` (`VT-d`) | PCIe / Thunderbolt IOMMU isolation | Sub-page 4 KB IOMMU sharing and late/permissive descriptor parsing leaked adjacent kernel RAM over DMA | Per-stream `AppleDART` `SP_START`/`SP_END` sub-page bounds and `BME = 0` at reset [33, 68, 100, 101] |
| `checkm8` (`CVE-2019-8900`, `axi0mX`) | 2019 | `iOS`, `iPadOS`, `watchOS`, `tvOS`, `T2` (`A5`-`A11`, `S1P`-`S3`) | `SecureROM` USB `DFU` 1.1 lifecycle | Incomplete `DFU_DNLOAD` followed by `DFU_CLR_STATUS` / reset freed `io_buffer` while global `ep0` pointer remained live (`UAF`) | Unpatchable on `A5`-`A11`; nulled global pointer in `A12` ROM, added `PAC` (`A13`) and `DART` (`A14`) [17, 103, 104, 105] |
| `hardbird` (`A7`) & `Blackbird` (`A8`-`A10`, `T2`) | 2020 | `iOS`, `iPadOS`, `bridgeOS` (`A7`-`A10`, `T2`) | `SEPROM` `TZ0` memory isolation & `SEP` `GID` | `SEPROM` read 64-bit `TZ0` MMIO (`0x200000480`) as 32-bit and shifted left 12 bits, dropping bits $\ge 20$ while `AMCC` honored them | Locked `TZ0` earlier in `iBoot` (`HT211843`), fixed 64-bit `TZ0` checks (`A12+`), added `SEP` `CMAC` memory integrity [102, 106, 107, 108, 109] |
| `SHSH2` Generator Nonce Replay | 2016-2022 | `iOS` / `iPadOS` (with kernel R/W) | `TSS` `ApNonce` (`BNCH`) freshness | Kernel write primitive overwrote NVRAM `boot-nonce` generator $g$ to match saved historical `ApImg4Ticket` blobs | Added independent `Cryptex1` nonces and strict `SEP` anti-replay version coupling [31, 98] |
| `usbliter8` (Paradigm Shift) | 2026 | `iOS`, `iPadOS`, `watchOS` (`A12`, `S4`/`S5`, `A13`) | `SecureROM` `DWC2` USB DMA & `AppleDART` | Synopsys `DWC2` Setup DMA subtracts 24 B after four 4 B short Setup packets (`-12 B` SRAM underflow) with USB `DART` in bypass mode | Unpatchable in `A12`/`A13` mask ROM; `A14+`/`M1+` enables USB `AppleDART` inside `SecureROM` [18, 33, 68, 110] |

### Inside checkm8 (CVE-2019-8900), PongoOS, and the Blackbird SEP GID Boundary

Disclosed by `axi0mX` in September 2019, `checkm8` (`CVE-2019-8900`, `VU#941987`) compromised `SecureROM` across seven generations of Apple silicon (`A5` through `A11`, `S1P`–`S3`, and the `T2` co-processor) by exploiting a subtle mismatch between the USB `DFU` 1.1 control-transfer state machine and `SecureROM`'s global endpoint-0 data-phase pointers [17, 103, 104, 105, 111]. When `SecureROM` initializes `DFU` (`usb_dfu_init()`), it allocates an SRAM heap chunk (`0x800` bytes) named `io_buffer` to stage incoming firmware chunks. When the host sends a `DFU_DNLOAD` (`bmRequestType = 0x21`, `bRequest = 1`) Setup packet advertising `wLength <= 0x800`, `handle_interface_request()` validates the length and copies `io_buffer`'s address into the USB core's global `ep0_data_phase_buffer` pointer (`ep0_data_phase_length = wLength`) [103, 105]. Under normal USB 2.0 `DFU` operation (`DFU_GETSTATUS` `0xA1, 3` polling until completion), receiving all `wLength` bytes zeroes `ep0_data_phase_buffer` cleanly [105, 111].

However, `axi0mX` observed what happens when a USB host initiates `DFU_DNLOAD` (`wLength > 0`), deliberately withholds or stalls the data stage so `ep0_data_phase_rcvd < ep0_data_phase_length`, and immediately forces `DFU` teardown via `DFU_CLRSTATUS` (`0x21, 4`) followed by a USB bus reset [17, 103, 105, 112]. `usb_dfu_exit()` dutifully calls `free(io_buffer)` and re-enters a fresh `DFU` cycle, yet the abort path *forgot to clear `ep0_data_phase_buffer`*! To prevent the next `usb_dfu_init()` from reallocating the new `io_buffer` right back into the same chunk, `checkm8` on `A9X`–`A11` exploited a companion memory leak: stalling `EP0` while queueing requests whose lengths required 64-byte zero-length packet (`ZLP`) terminators leaked `usb_device_io_request` structs across `DFU` resets, sculpting a deterministic SRAM heap hole [103, 105]. Subsequent standard USB control transfers wrote directly through the dangling `ep0_data_phase_buffer` pointer into a live `usb_device_io_request` struct, overwriting its `next` link and `callback` function pointer; issuing one final USB reset walked the cancelled I/O queue and jumped straight into attacker shellcode at the highest privilege level (`EL1`/`EL3`), bootstrapping the `checkra1n` jailbreak and its open-source pre-XNU execution environment `PongoOS` [17, 105, 113].

Because `checkm8` hijacked `SecureROM` *before* ROM locked out the `AP` hardware `AES` `GID` key, researchers gained a live decryption oracle for `AP` `KBAG`-encrypted `iBoot` firmwares on `A5`–`A11`, accelerating public `Darwin` security research [17, 113]. Crucially, however, `AP` `SecureROM` compromise did *not* expose the `Secure Enclave`'s separate `SEP` `GID` key or `UID`-tangled user passcodes! Breaching `SEP` firmware (`sepi`) on `A8`–`A10` and `T2` required a second independent silicon/ROM vulnerability: `Blackbird`, discovered independently in August 2020 by `windknown` (Pangu Lab) and `littlelailo` (following `Proteas`'s `A7` `hardbird` `TZ0` channel-selector bug) [102, 107, 108, 109]. During boot, the `AP` programs the physical base and end addresses of `SEP`'s encrypted DRAM carveout (`TZ0`) into 64-bit MMIO registers (`0x200000480`–`0x200000484`) inside the Apple Memory Cache Controller (`AMCC`). While `AMCC` hardware decoded upper address bits past bit `20`, `SEPROM` on `A8`–`A10` and `T2` mistakenly read the register as a `uint32_t` and executed `addr << 12` (truncating bits `[31:20]`)! By setting bit `21` from `PongoOS` before `TZ0` locked, an attacker caused `AMCC` to guard a decoy physical range while `SEPROM` executed out of unprotected DRAM readable and writable by the `AP`, unlocking `SEP` `GID` decryption and custom keybag control on `A10` (`HT211843` hardened `iBoot` `TZ0` locking for software exploits, while `A11`+ `SEP` memory integrity trees and `A12`+ 64-bit `SEPROM` bounds permanently closed the bug) [102, 106, 107, 108].

### usbliter8 (2026): Synopsys USB DMA Underflow vs. SecureROM AppleDART

Apple fixed the `checkm8` dangling pointer in `A12` (`iPhone XS`) mask silicon (`A12`–`A13` retained a latent non-exploitable remnant lacking the `ZLP` leak, while `A13` added ROM `PAC`), and for nearly seven years post-`A11` `SecureROM` remained unbroken [17, 18]. In June 2026, however, Paradigm Shift researchers disclosed `usbliter8`, achieving arbitrary `EL1` `SecureROM` execution in under two seconds on `A12`, `S4`/`S5`, and `A13` chips using an external `RP2350` USB controller [18]. Rather than a software heap bug, `usbliter8` exploited a hardware state-machine invariant inside the Synopsys DesignWare (`DWC2`) USB 2.0 device controller paired with an unconfigured `SecureROM` `AppleDART` [18, 33, 110].

Specifically, the Synopsys `DWC2` endpoint-0 engine buffers up to three consecutive 8-byte USB Setup packets via hardware DMA ($3 \times 8 = 24\text{ B}$) and resets its internal DMA write pointer on the fourth back-to-back Setup packet by subtracting a hardcoded $24\text{ bytes}$ [18, 110]. When an attacker microcontroller transmits non-compliant *4-byte* Setup packets instead ($3 \times 4 = 12\text{ B}$), the controller advances its internal pointer by $+12\text{ B}$ and then subtracts $24\text{ B}$, stepping its physical DMA write cursor *backward* through `SecureROM` SRAM by $\Delta = 12 - 24 = -12\text{ bytes}$ per four-packet cycle [18]:

$$\text{DMA\_Ptr}_{k+1} = \text{DMA\_Ptr}_{k} + 3 \times 4 - 24 = \text{DMA\_Ptr}_{k} - 12\text{ bytes}$$

On `A11`, the older ROM driver reloaded the DMA base address register after every packet; on `A14` (`iPhone 12`) and every `M1`–`M5` SoC, `SecureROM` enables `TRANSLATE_ENABLE = 1` on `dart-usb*` (`AppleDART`) before turning on USB `DFU`, causing the backward-stepping `IOVA` to hit an unmapped guard boundary and fault harmlessly inside `DART` (`R_ERROR.WRITE_FAULT`) [18, 33, 68]. On `A12`, `S4`/`S5`, and `A13` alone, `SecureROM` left `dart-usb` in `BYPASS_DART = 1` mode! Stepping backward across SRAM overwrote saved stack link registers on `A12` (pre-ROM `PAC`) and corrupted unauthenticated `.bss` USB interrupt-handler pointers on `A13` (bypassing ROM `PAC`), proving why `AppleDART` must fence even mask-ROM recovery peripherals from instruction zero [18, 33].

> **Warning.**
> Neither `checkm8` nor `usbliter8` yields persistent untethered bootkits (because mask `Boot ROM` resets clean when power cycles) nor offline `Before First Unlock` (`BFU`) data extraction on modern `SEP` silicon, because `SEP` executes its own `SEPROM` and gates the unreadable silicon `UID` key behind hardware counter lockboxes ([Chapter 3](03-secure-enclave.md)) [12, 17, 18]. Yet during a tethered session where a user subsequently enters a passcode (or if an `AFU` device is warm-rebooted/compromised), ROM control neutralizes `iBoot`, `SPTM`, `SSV`, and kernel code signing completely for that boot.

## Verification & Forensic Artifacts

On an Apple Silicon Mac, query the read-only `IODeviceTree` plane populated by `iBoot` and `bputil -d` to inspect active `iBoot` build version, silicon `chip-epoch` (`CEPO`), and `Full Security` enforcement without altering boot state [7, 90, 114]:

```bash
ioreg -l -p IODeviceTree | grep -E '"secure-boot"|"firmware-version"|"chip-epoch"' | head -n 6
bputil -d | grep -E 'Security Mode|Boot Policy|nsih'
```

Representative output on a Mac booted under `Full Security`:

```text
    |   "firmware-version" = <"iBoot-13822.101.4">
    |   "chip-epoch" = <01>
Security Mode                 : Full (1)
```

Verify that USB, PCIe/Thunderbolt, and `ANS` NVMe buses sit behind dedicated `AppleDART` and `SART` hardware units in the live `IOKit` registry [33, 68, 69]:

```bash
ioreg -c AppleDART -r -d 1 | grep -E '\+-o dart-' | head -n 6
ioreg -l -p IODeviceTree | grep -E 'sart' | head -n 4
```

Representative output confirming per-controller `AppleDART` and `SART` isolation blocks:

```text
+-o dart-usb0@382f8000  <class AppleDART, id 0x100000214, registered>
+-o dart-apcie0@68008000  <class AppleDART, id 0x10000023a, registered>
+-o dart-ans2@7bcc4000  <class AppleDART, id 0x100000251, registered>
```

Decode the personalized `Image4` `IM4M` manifest (`apticket.der`) staged on `/System/Volumes/Preboot` using `openssl asn1parse` to inspect its canonical `ITU-T X.690` `DER` `IM4M`, `MANB`, and `MANP` tags [30, 86, 88]:

```bash
MANIFEST=$(ls /System/Volumes/Preboot/*/boot/*/System/Library/Caches/apticket.der 2>/dev/null | head -n 1)
openssl asn1parse -inform DER -in "$MANIFEST" | head -n 10
```

Representative `ASN.1` `DER` header showing the 4-byte `IM4M` magic and private-tag `MANB` (`0x4d414e42` = `1296125506` / context tag) set:

```text
    0:d=0  hl=4 l=3942 cons: SEQUENCE
    4:d=1  hl=2 l=   4 prim: IA5STRING         :IM4M
   10:d=1  hl=2 l=   1 prim: INTEGER           :00
   13:d=1  hl=4 l=2618 cons: SET
   17:d=2  hl=4 l=2614 cons: priv [ 1296125506 ]
   23:d=3  hl=2 l=   4 prim: IA5STRING         :MANB
```

During physical forensic triage of `iOS` and `watchOS` hardware, active tethered `DFU` exploitation exposes modified USB product strings (`PWND:[checkm8]` or `PWND:[usbliter8]`) while vanishing on cold power-off, whereas legitimate `iBoot` build tags and `ECID` identifiers persist inside `sysdiagnose` (`ioreg.txt`) logs [17, 18, 98]. With the locked `Boot ROM` and `Image4` substrate established, [Chapter 2](02-mac-localpolicy.md) examines how Apple Silicon Macs reconcile this immutable hardware root with owner-authorized custom kernels and per-volume security downgrades.
