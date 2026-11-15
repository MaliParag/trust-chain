# Secure Boot

## Overview

* **Role in the Chain:** First cryptographic admission gate in the Windows boot path; executes inside UEFI Driver Execution Environment (DXE) firmware to authenticate pre-OS binaries before transferring control to the Windows Boot Manager (`bootmgfw.efi`) and operating-system loader (`winload.efi`).
* **Core Security Invariant:** Firmware executes a PE/COFF image via `LoadImage()` if and only if its Authenticode digest or signing certificate chain is absent from the forbidden signatures database (`dbx`) and present in the authorized signatures database (`db`), after which Trusted Boot enforces kernel-mode signature policy across the loader-to-kernel boundary.
* **Trusted Computing Base (TCB):** Pre-UEFI silicon verification roots where provisioned and fused for enforcement (Intel Boot Guard or AMD Platform Secure Boot), SPI flash hosting SEC/PEI/DXE firmware volumes, NVRAM storing authenticated UEFI variables (`PK`, `KEK`, `db`, `dbx`), and the private keys held by the platform OEM and Microsoft.
* **Primary Failure Modes:** Chain-loading legitimately signed but vulnerable boot managers prior to `dbx` or SVN revocation (CVE-2022-21894 Baton Drop / BlackLotus, CVE-2023-24932), memory corruption in pre-verifier DXE parsers (LogoFAIL), leaked or test Platform Keys in production firmware (PKfail), and soft-reboot or recovery downgrades that expose unsealed secrets in physical memory (Bitpixie, WinRE).
* **Handoff:** Delivers a signature-verified execution path through `bootmgfw.efi`, `winload.efi`, `ntoskrnl.exe`, and the Early Launch Anti-Malware (ELAM) driver; delegates tamper-evident boot recording, hardware secret sealing, remote attestation, hypervisor isolation, and runtime code integrity to subsequent chapters.

## Core Engineering Problem & Threat Model

Operating-system security controls cannot defend themselves if an adversary executes code before the operating system exists. Under the legacy IBM PC BIOS architecture, CPU reset vectored execution into 16-bit real mode, ran power-on self-test routines, read sector zero (the 512-byte Master Boot Record) of the active disk into physical memory at `0000:7C00`, and checked only that the final two bytes at offset 510 equaled `0x55AA` [1]. That two-byte signature was a media-format marker, not a cryptographic proof of origin or integrity. Any code occupying sector zero ran unconditionally with complete hardware privilege.

As 64-bit Windows introduced Kernel-Mode Code Signing (KMCS) and Driver Signature Enforcement (DSE) beginning with Windows Vista [2], pre-OS execution became the decisive bypass vector. Bootkits including BootRoot (hooking real-mode `INT 13h` disk reads in 2005) [3], Vbootkit (2007) [4], Mebroot (2007) [5], and TDL-4 (infecting over 4.5 million systems in early 2011) [6] overwrote the MBR or Volume Boot Record to intercept `winload` and patch `ntoskrnl.exe` in memory, disabling DSE before kernel signature verification initialized. In September 2011, Mebromi pushed persistence one layer deeper into motherboard SPI flash, using the legitimate Award `CBROM.EXE` firmware-assembly tool to inject a malicious module into the BIOS ROM so the firmware itself reinfected the MBR on every boot [7]. Because firmware updates and boot sectors lacked hardware-anchored signature verification, OS-enforced ring-0 defenses rested on an untrusted substrate.

The modern boot threat model assumes an adversary with local administrative privileges (capable of mounting the FAT32 EFI System Partition, writing Boot Configuration Data, or invoking UEFI runtime variable services), unattended physical access, or local network adjacency for Preboot Execution Environment (PXE) recovery. Against this adversary, the platform must prevent unapproved pre-OS code execution, block unauthorized weakening of boot configuration flags, and maintain continuous cryptographic verification from processor reset through kernel initialization.

## Architectural Deep Dive

### The UEFI Platform Initialization Pipeline and Silicon Roots

Windows Hardware Compatibility Program (WHCP) requirements mandate Unified Extensible Firmware Interface (UEFI) version 2.3.1C or later with legacy Compatibility Support Module (CSM) emulation disabled on modern Secure Boot systems [8, 9]. Internally, platform firmware executes the UEFI Platform Initialization (PI) specification as a four-stage bootstrap pipeline [10]. Execution begins in the Security (`SEC`) phase directly from SPI flash at the CPU reset vector; because main DRAM is not yet initialized, `SEC` configures processor cache as temporary flat memory (Cache-as-RAM) to establish the initial root of execution. Control then advances to Pre-EFI Initialization (`PEI`), which initializes the memory controller, trains physical DRAM, dispatches Pre-EFI Initialization Modules (`PEIMs`), and records discovered hardware topology inside Hand-Off Blocks (`HOBs`).

Once main memory is available, `PEI` hands off to the Driver Execution Environment (`DXE`), loading several megabytes of system firmware that host PCIe and NVMe bus drivers, file-system drivers, network stacks, graphical human-interface parsers, UEFI runtime services, and the `LoadImage()` Authenticode verifier. After `DXE` driver dispatch completes, Boot Device Selection (`BDS`) evaluates NVRAM boot policy variables (`BootNext`, `BootOrder`, `Boot####`), locates the target EFI binary on the EFI System Partition (`ESP`) or network interface, and invokes `LoadImage()` followed by `StartImage()` to transfer execution to the operating-system boot manager [10].

![Figure: UEFI Platform Initialization. SEC and PEI establish early firmware state, DXE hosts the Secure Boot LoadImage() verifier, and BDS reads BootOrder; where provisioned in fuses, Intel Boot Guard / AMD Hardware Validated Boot verifies initial firmware below SEC.](diagrams/16-secure-boot-firmware-pipeline.svg)

Crucially, the base UEFI PI specification does not mandate cryptographic verification between `SEC`, `PEI`, and `DXE` Firmware Volumes (`FVs`). If an attacker modifies the `DXE` volume in SPI flash, as the LoJax UEFI rootkit demonstrated in the wild in 2018 [11], a compromised `DXE` dispatcher can patch out `LoadImage()` before any bootloader signature check runs. Enterprise x86 silicon closes this pre-UEFI gap by anchoring verification below `SEC` in immutable hardware fuses. On Intel platforms beginning with 4th-generation Core (Haswell) silicon, Intel Boot Guard intercepts reset in CPU microcode and loads an Intel-signed Authenticated Code Module (`ACM`) into internal SRAM before releasing x86 execution [11, 12]; in Verified Boot enforcement mode, the `ACM` validates the OEM Key Manifest and Initial Boot Block (`IBB`) against an OEM public-key hash permanently blown into chipset Field Programmable Fuses (`FPFs`), after which the verified `IBB` must chain cryptographic verification across subsequent `PEI` and `DXE` Firmware Volumes (the OEM Boot Block, or `OBB`) prior to dispatch. AMD platforms enforce an analogous boundary through AMD Platform Secure Boot (`PSB`) executing on the on-die AMD Platform Security Processor (`PSP`, also termed the AMD Secure Processor), an isolated ARM core that initializes ahead of the main x86 cores [13, 14]; when `PSB` fuses are blown and locked, the `PSP` validates the OEM root signing key against on-die OTP fuses and authenticates the BIOS directory and initial x86 firmware image in SPI flash before releasing the host CPU from reset [13].

Both silicon mechanisms remain conditional on OEM manufacturing discipline. If an OEM ships Boot Guard in Profile 0 (disabled) or measurement-only mode, fails to chain verification from the `IBB` across `OBB` and `DXE` volumes, or leaves AMD `PSB` fuses unblown in production [13], SPI flash modification beneath `DXE` remains viable despite UEFI Secure Boot reporting enabled.

### Authenticated Variables and the Trust Hierarchy

UEFI Secure Boot policy resides in non-volatile RAM (NVRAM) inside authenticated UEFI variables protected with the `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute [9]. Any boot-service or runtime call to `SetVariable()` targeting these databases must supply a PKCS#7 signature computed over the variable name, vendor GUID, attributes, monotonic timestamp, and new payload, chaining to an authorized parent key in a two-tier administrative hierarchy. At the apex sits the single Platform Key (`PK`), normally held by the OEM to establish platform ownership. When `PK` is unpopulated, firmware operates in *Setup Mode* and Secure Boot enforcement remains inactive; enrolling `PK` transitions the platform into *User Mode*, with UEFI 2.5 and later adding *Audit Mode* and *Deployed Mode* to tighten state transitions [9]. A valid `PK` signature can update `PK`, `KEK`, `db`, or `dbx`, or clear `PK` to return the machine to Setup Mode. Beneath `PK`, the Key Exchange Key (`KEK`) holds an `EFI_SIGNATURE_LIST` of X.509 certificates authorized to sign updates to `db` and `dbx`. Windows-certified x86 PCs enroll both an OEM `KEK` and the Microsoft Corporation KEK CA (across its 2011 and 2023 generations), allowing Microsoft to deliver `db` and `dbx` updates through Windows Update without per-OEM re-signing [9, 15].

Those administrative keys govern the two signature databases evaluated during image loading. The authorized Signature Database (`db`) forms the allowlist of `EFI_SIGNATURE_LIST` structures permitting execution, populated with X.509 issuing certificates (`EFI_CERT_X509_GUID`) or individual PE/COFF Authenticode SHA-256 digests (`EFI_CERT_SHA256_GUID`). Overriding `db` unconditionally is the Forbidden Signatures Database (`dbx`), whose entries record revoked PE/COFF SHA-256 image digests (`EFI_CERT_SHA256_GUID`), revoked X.509 certificates (`EFI_CERT_X509_GUID`), and To-Be-Signed (`TBS`) certificate SHA-256 hashes paired with revocation timestamps (`EFI_CERT_X509_SHA256_GUID`) [9, 15]. Across all four variables, WHCP mandates a minimum cryptographic floor of RSA-2048 keys with SHA-256 digests [9], and canonical variable payloads for the Windows ecosystem are published in Microsoft's `secureboot_objects` repository [15].

### The LoadImage() Verification Protocol

During DXE and BDS, every third-party PCIe Option ROM, UEFI driver, UEFI shell utility, and OS bootloader loaded from external media or flash passes through the `EFI_BOOT_SERVICES.LoadImage()` security architectural protocol. First, firmware parses the PE/COFF headers and computes the image's SHA-256 Authenticode digest, omitting three regions per the Microsoft PE format specification: the Optional Header `CheckSum` field, the Certificate Table entry in the Optional Header Data Directories, and the trailing Attribute Certificate Table (`WIN_CERTIFICATE`) containing the PKCS#7 signature [16]. Before consulting any allowlist, `LoadImage()` evaluates the revocation database (`dbx`): if the computed Authenticode digest matches any `EFI_CERT_SHA256_GUID` entry in `dbx`, loading aborts immediately with `EFI_SECURITY_VIOLATION`, and as firmware extracts all embedded Authenticode signatures (supporting dual-signed binaries), any candidate signing chain whose certificate or TBS hash matches `dbx` is likewise rejected. Only after surviving both denylist gates does `LoadImage()` consult `db`, admitting the image if its digest matches an `EFI_CERT_SHA256_GUID` entry or if at least one non-revoked Authenticode signature chains cleanly to an `EFI_CERT_X509_GUID` authority in `db`. Every unsigned or unchained image fails by default with `EFI_SECURITY_VIOLATION`, causing BDS to advance to the next boot option or enter firmware recovery.

![Figure: The LoadImage() decision tree. The unconditional dbx (denylist) checks run first, so a hash in dbx cannot be rescued by also appearing in db.](diagrams/16-secure-boot-loadimage-decision.svg)

### Ecosystem Certificate Authorities and Expiration Semantics

Although UEFI Secure Boot is architecturally vendor-agnostic, commercial x86 PCs ship with Microsoft-rooted authorities pre-enrolled in `db` so retail installation media and add-in PCIe cards work out of the box [9, 17, 18]. Historically, two 2011 issuing authorities anchored this ecosystem: `Microsoft Windows Production PCA 2011` (carrying X.509 `notAfter` date October 19, 2026) signed first-party Windows boot components (`bootmgfw.efi`, `bootmgr.efi`, `winload.efi`, `winresume.efi`, and `memtest.efi`) [18], while `Microsoft Corporation UEFI CA 2011` (`notAfter` June 27, 2026) signed third-party UEFI ecosystem binaries including hardware-vendor Option ROMs, firmware updaters, and Linux `shim.efi` first-stage bootloaders [18]. Ahead of those fifteen-year expirations, Microsoft introduced `Windows UEFI CA 2023` and `Microsoft UEFI CA 2023` under KB5025885 and KB5062710 as successor authorities for first-party Windows bootloaders and third-party UEFI code, respectively [15, 18, 19].

> **Warning.**
> Standard UEFI `LoadImage()` implementations do not enforce X.509 `notAfter` expiration dates against wall-clock time when verifying bootloaders (avoiding fleet-wide unbootable states when CMOS batteries fail or certificates age) [18]. Passing the June and October 2026 expiration dates does *not* cause firmware to reject 2011-signed vulnerable bootloaders; old binaries remain bootable forever until explicitly revoked in `dbx` or blocked by Boot Manager Security Version Numbers. Conversely, machines that lack `Windows UEFI CA 2023` in `db` cannot boot newly signed Windows recovery media or post-transition boot managers [18, 19].

Non-Windows operating systems integrate with this third-party CA through `shim.efi`, signed by the Microsoft UEFI CA [17, 20]. At boot, `shim.efi` exposes an independent Machine Owner Key (`MokList`) NVRAM store and verifies distribution-signed second-stage loaders (`grubx64.efi` or unified kernel images) without requiring Microsoft signatures on each distribution kernel build.

### Trusted Boot: Extending Verification Across the Kernel Boundary

UEFI Secure Boot's jurisdiction ends the instant `bootmgfw.efi` begins executing. Windows *Trusted Boot* extends cryptographic enforcement from `bootmgfw.efi` into ring 0 across a continuous chain of loader and kernel handoffs [21, 22]. Before loading the operating system, `bootmgfw.efi` parses the Boot Configuration Data (`BCD`) store on the ESP; whenever UEFI reports `SecureBoot = 1`, `bootmgfw.efi` and `winload.efi` engage a security policy gate that strips or refuses integrity-weakening BCD elements, including `testsigning`, `nointegritychecks`, `debug` (kernel debugging), and raw physical memory truncation flags. On hibernate resume (ACPI S4), `bootmgfw.efi` invokes `winresume.efi` instead, which cryptographically validates `hiberfil.sys` so an offline attacker cannot tamper with saved kernel memory on disk.

Because kernel-mode `ci.dll` is not yet running during OS load, `winload.efi` embeds a standalone code-integrity engine inside the shared `bootlib` library [23]. Reverse engineering of `winload.efi` traces the loader verification path (`OslLoadDrivers` → `OslLoadImage` → `LdrpLoadImage` → `BlImgLoadPEImageEx` → `ImgpLoadPEImage` → `ImgpValidateImageHash`), which validates the Authenticode signatures and catalog hashes of `ntoskrnl.exe`, `hal.dll`, `ci.dll`, the Early Launch Anti-Malware (`ELAM`) driver, and every `SERVICE_BOOT_START` driver prior to transferring CPU control [23]. When `winload.efi` calls `ExitBootServices()` and jumps to `KiSystemStartup` in `ntoskrnl.exe`, it passes a `LOADER_PARAMETER_BLOCK` containing `LOADER_PARAMETER_EXTENSION` (`LPE`) [24]. Fields added in modern Windows 11 releases (`CodeIntegrityData` and `CodeIntegrityDataSize`) serialize the active System Integrity Policy (`SiPolicy.p7b`), boot-driver validation verdicts, and revocation state across the loader-to-kernel boundary so policy cannot be dropped during initialization [24, 25].

Once `ntoskrnl.exe` initializes, kernel-mode `ci.dll` consumes that `LPE` state and hooks image-load notifications to enforce KMCS and active Code Integrity policies on all subsequent ring-0 loads [2]. Before any third-party boot-start driver executes, however, the kernel initializes the Microsoft-signed `ELAM` driver (registered under the `Early-Launch` group) first [26, 27]. Through `IoRegisterBootDriverCallback`, `ELAM` inspects the hashes and certificates of every remaining boot-start driver against an anti-malware signature hive in the registry and returns a `BDCB_CLASSIFICATION` verdict (`BdCbClassificationKnownGoodImage`, `BdCbClassificationKnownBadImage`, `BdCbClassificationUnknownImage`, or `BdCbClassificationKnownBadImageBootCritical`) [27, 28]. Under default policy, the kernel blocks `KnownBadImage` drivers outright while permitting boot-critical storage drivers needed to avoid an unbootable crash.

## Attack Catalog & Gap Analysis

No public attack has broken the RSA-2048 or SHA-256 primitives underlying UEFI Secure Boot. Real-world compromises cluster instead around disabled enforcement, vulnerable signed Microsoft bootloaders left unrevoked in `dbx`, memory-corrupting DXE parsers below `LoadImage()`, leaked IBV Platform Keys, and soft-reboot state retention.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| ESPecter | 2021 | Unverified `bootmgfw.efi` execution from ESP | Secure Boot disabled; administrative ESP write | Patches `bootmgfw.efi` on FAT32 ESP to hook `winload.efi` and disable Driver Signature Enforcement in memory | Enable UEFI Secure Boot enforcement [29] |
| FinSpy UEFI | 2021 | Unverified `bootmgfw.efi` replacement on ESP | Secure Boot disabled; administrative ESP write | Replaces `bootmgfw.efi` with trojanized loader staging ring-0 hooks and user-mode payload injection into `winlogon.exe` | Enable UEFI Secure Boot enforcement [30] |
| BlackLotus / Baton Drop (CVE-2022-21894) | 2022-2023 | BCD memory-map integrity in signed `bootmgfw.efi` | Local administrator access to ESP | Drops legitimate old Microsoft-signed `bootmgfw.efi`; abuses BCD `truncatememory` to evict persistent security structures and disable HVCI, BitLocker, and Defender | Apply KB5025885 `dbx` / SVN revocations and rotate to Windows UEFI CA 2023 [19, 31, 32, 33, 34] |
| Boot Manager Bypass (CVE-2023-24932) | 2023 | Cohort persistence of vulnerable signed Windows boot managers | Local administrator or physical ESP access | Replaces patched ESP bootloader with unrevoked 2011-PCA-signed vulnerable `bootmgfw.efi` revisions to re-enable pre-OS arbitrary code execution | Complete KB5025885 staged enrollment (`Windows UEFI CA 2023` + PCA 2011 revocation) [19, 35] |
| Bitpixie (CVE-2023-21563) | 2022-2024 | BitLocker VMK confidentiality across PXE soft reboot | Unattended physical/LAN access; TPM-only BitLocker | Forces PXE soft reboot into downgraded signed `bootmgfw.efi` under unchanged `PCR[7]` authority; extracts unscrubbed VMK from DRAM | Require pre-boot factor (`TPMAndPIN`); apply KB5025885 boot-manager revocations [19, 36, 37, 38] |
| LogoFAIL (CVE-2023-39539 et al.) | 2023 | DXE execution integrity prior to `LoadImage()` | ESP or NVRAM write access to OEM boot logo | Triggers heap/integer overflows in AMI, Insyde, and Phoenix DXE image parsers (BMP, GIF, JPEG, PCX, TGA) before BDS runs | Apply OEM UEFI capsule updates fixing IBV `HiiImage` decoders [39, 40] |
| WinRE Bypass (CVE-2024-20666) | 2024 | Windows Recovery Environment BitLocker boundary | Physical access to WinRE recovery boot | Abuses unpatched boot/recovery binaries on the local WinRE partition to bypass BitLocker drive encryption | Service on-disk WinRE (`winre.wim`) via KB5034957 and update `dbx` [41, 42, 43] |
| PKfail (BRLY-2024-005 / CVE-2024-0762) | 2024 | Root Platform Key (`PK`) authenticity | Local administrator access to `SetVariable()` | Signs arbitrary `KEK`, `db`, and `dbx` updates using leaked AMI reference test private keys (`DO NOT TRUST`) shipped in production firmware | Apply OEM firmware update provisioning a unique OEM-generated `PK` [44] |

### Unenforced Firmware Gates: ESPecter and FinSpy

The EFI System Partition is an unencrypted FAT32 volume accessible to any ring-3 administrator via `mountvol`. In 2021, ESET documented ESPecter [29] and Kaspersky documented FinSpy's UEFI bootkit [30], both of which replaced or hooked `\EFI\Microsoft\Boot\bootmgfw.efi` on victim machines where Secure Boot was disabled. ESPecter patched `winload.efi` in transit to neutralize `ci.dll` DSE checks and load an unsigned kernel driver; FinSpy chained hooks down into `winlogon.exe`. Neither malware family bypassed `LoadImage()` cryptography; both exploited fleet misconfigurations where UEFI booted without Secure Boot active, proving that KMCS and ELAM provide zero protection when the firmware root is permissive.

### Signed-but-Vulnerable Bootloaders: Baton Drop, BlackLotus, and CVE-2023-24932

BlackLotus (sold on underground forums in late 2022 and dissected by ESET in March 2023) became the first publicly documented in-the-wild UEFI bootkit capable of defeating fully enabled UEFI Secure Boot on patched Windows 11 systems [31, 33, 34]. Rather than forging signatures, BlackLotus brought its own authentic, Microsoft-signed copies of older `bootmgfw.efi`, `hvloader.efi`, and `winload.efi` onto the ESP and invoked CVE-2022-21894 (*Baton Drop*) [31, 32].

![Figure: The BlackLotus exploit chain. Every enforced step accepts a Microsoft-signed binary; Baton Drop (CVE-2022-21894) then disables HVCI, BitLocker, and Defender from below the trusted-boot horizon.](diagrams/16-secure-boot-blacklotus-chain.svg)

Under Secure Boot, `bootmgfw.efi` is supposed to block BCD options that corrupt security state. However, affected builds prior to January 2022 honored `BCDE_LIBRARY_TYPE_TRUNCATE_PHYSICAL_MEMORY` (`truncatememory`) even when Secure Boot was enforcing [32]. By truncating physical memory addresses right where `bootmgr` stored persistent serialized security descriptors, an attacker caused the loader to drop its enforced integrity context while keeping code execution inside a validly signed Microsoft binary. BlackLotus used this primitive to deploy a self-enrolled MOK/custom loader path, patch kernel memory to disable Hypervisor-Protected Code Integrity (HVCI), BitLocker, and Microsoft Defender Antivirus, and load an unsigned ring-0 HTTP backdoor [31, 33].

Although Microsoft patched the `truncatememory` bug in January 2022, it did not immediately add the vulnerable binaries' hashes to `dbx` for fear of breaking unupdated recovery drives and installation media. As Martin Smolar of ESET noted in March 2023, exploitation remained viable because the affected, validly signed binaries had still not been added to the UEFI revocation list [31]. Microsoft subsequently tracked this architectural rollback exposure under CVE-2023-24932 and launched KB5025885: a multi-year revocation and CA-rotation program required to retire the entire cohort of vulnerable 2011-PCA-signed Windows boot managers [19, 35].

### Downgrade State Leakage: Bitpixie (CVE-2023-21563) and WinRE (CVE-2024-20666)

Bitpixie (discovered in 2022 and weaponized publicly at 38C3 in December 2024) demonstrated how unrevoked bootloaders break adjacent cryptographic subsystems without executing unsigned code in UEFI [36, 37, 38]. On modern Windows fleets, TPM-only BitLocker seals the Volume Master Key (VMK) primarily to `PCR[7]` (which records Secure Boot policy and signing authority, not the exact hash of `bootmgfw.efi` in `PCR[4]`) and caps `PCR[11]` after OS handoff [37].

An attacker with physical LAN and keyboard access modifies an on-disk or PXE BCD configuration to trigger a soft reboot into network PXE recovery using a downgraded, validly signed `bootmgfw.efi`. Because the downgraded boot manager chains to the identical Microsoft Production PCA 2011, `PCR[7]` matches the sealed policy and the TPM unseals the BitLocker VMK into RAM. Due to CVE-2023-21563, the older boot manager failed to scrub the unsealed VMK from physical DRAM before initiating a soft reboot into a signed Linux `shim` or WinPE image over PXE, allowing the attacker to dump DRAM and decrypt the drive [36, 37]. CVE-2024-20666 exposed a related operational gap in on-disk Windows Recovery Environment (`winre.wim`) partitions: cumulative OS updates patched `\Windows\Boot\EFI\bootmgfw.efi` on the main volume while leaving stale recovery binaries inside the hidden WinRE partition unless explicitly serviced via KB5034957 [41, 42, 43].

### Pre-Verifier Firmware Compromise: LogoFAIL

LogoFAIL (disclosed by Binarly in December 2023 across CVE-2023-39539, CVE-2023-40238, CVE-2023-5058, and related advisories) targeted the UEFI PI layer *beneath* `LoadImage()` [39, 40]. Reference firmware from all three major Independent BIOS Vendors (AMI, Insyde, and Phoenix) included `HiiImage` decoders for BMP, GIF, JPEG, PCX, and TGA formats inside DXE to render customizable OEM splash screens early in boot.

Because OEM update capsules, vendor customization partitions, or writable ESP logo files feed untrusted image bytes into these DXE parsers before BDS invokes `LoadImage()`, classic heap buffer overflows and integer multiplications granted arbitrary ring-0 execution inside the DXE environment itself [40]. Once running inside DXE, an attacker can overwrite `gBS->LoadImage` function pointers or inject arbitrary certificates into runtime variables (demonstrated by Binarly chaining CVE-2023-40238 to bypass Secure Boot end to end) [39].

### Supply-Chain Root Compromise: PKfail

Disclosed by Binarly in July 2024 (`BRLY-2024-005` / `CVE-2024-0762`), PKfail revealed that over 800 device models across major server and client OEMs shipped in production with an AMI reference test Platform Key (`CN=DO NOT TRUST - AMI Test PK`) whose private key had leaked years earlier [44]. Because `PK` sits at the apex of the UEFI variable hierarchy, any local administrator on an affected host can sign authenticated `SetVariable()` payloads with the known private key to append attacker certificates to `db`, purge `dbx` revocations, or clear `PK` entirely without physical presence or BIOS setup interaction [44]. Every cryptographic check in `LoadImage()` functioned as specified, yet the trust anchor itself was shared and compromised in the firmware supply chain.

## Theoretical Limits & Structural Invariants

### The Verifier-of-Verifiers Regress and Fuse Permanence

A software verifier cannot establish its own integrity. `LoadImage()` trusts the DXE core; DXE depends on PEI and SEC; SEC depends on SPI flash contents unless hardware silicon (Intel Boot Guard or AMD PSB) authenticates the initial firmware block before releasing the CPU [10, 12, 13]. Termination in hardware OTP fuses solves flash modification at the cost of key agility: once an OEM blows its public key hash into chipset FPFs or PSP fuses, a leaked OEM firmware-signing key cannot be revoked or rotated in the field without replacing the motherboard [11, 13]. Conversely, if an OEM fails to blow enforcement fuses or omits chained verification between the IBB and DXE volumes, Secure Boot rests on mutable flash.

### Decoupling Cryptographic Validity from Authorization Policy

Secure Boot illustrates a foundational law that recurs across every layer of the Windows trust chain: cryptographic signature validity is distinct from authorization safety.

When `LoadImage()` evaluates `bootmgfw.efi`, an Authenticode signature chaining to `Microsoft Windows Production PCA 2011` proves only a historical provenance statement: *at some point between 2011 and 2026, Microsoft's build pipeline signed this byte sequence.* It does not prove that the binary lacks memory-truncation bugs (CVE-2022-21894), scrubs cryptographic secrets across reboots (CVE-2023-21563), or belongs on the current machine's boot path. Whenever an architecture equates `"validly signed by trusted CA K"` with `"authorized to execute unconditionally"`, every historical vulnerability ever signed by `K` remains an active bypass weapon until revocation reaches every verifier.

### The NVRAM dbx Capacity Ceiling and Cohort Revocation

Closing the gap between *patched* and *revoked* collides directly with physical flash hardware constraints. Authenticated UEFI variables share a small SPI flash NVRAM partition, with total `dbx` capacity on commodity x86 motherboards commonly bounded around 32 KB [17]. Each SHA-256 `EFI_SIGNATURE_DATA` entry consumes 48 bytes (16-byte owner GUID plus 32-byte digest); a single ecosystem vulnerability such as the 2020 GRUB2 *BootHole* disclosure consumed roughly 10 KB of `dbx` space in one update [17]. Moreover, aggressive NVRAM writes risk flash wear, variable-store fragmentation, or catastrophic bricking if power is lost mid-commit or if an active recovery partition relies on a newly denylisted binary [19].

Because fifteen years of cumulative Windows builds, ISO installers, PXE images, and OEM recovery partitions produced thousands of distinct 2011-signed `bootmgfw.efi` hashes, individual hash denylisting in `dbx` cannot scale. On the first-party Windows path, KB5025885 bypasses per-hash exhaustion through authority rotation paired with Boot-Manager Security Version Numbers (`SVNs`): Microsoft enrolls `Windows UEFI CA 2023` and `Microsoft Corporation KEK 2K CA 2023` into NVRAM, updates the on-disk and WinRE boot managers to 2023-signed binaries carrying enforced `SVNs`, and only then revokes the entire `Microsoft Windows Production PCA 2011` certificate inside `dbx` [15, 18, 19, 886]. In 2026, this transition shifted from proactive hardening to an operational cliff as the original fifteen-year 2011 roots reached expiration (`Microsoft Corporation KEK CA 2011` on June 24, 2026, `Microsoft Corporation UEFI CA 2011` on June 27, 2026, and `Microsoft Windows Production PCA 2011` in October 2026) [886]. While existing bootloaders remain bootable across firmware that ignores post-issuance expiry, any endpoint that fails to complete the 2023 `KEK` and `db` migration loses the ability to authenticate future `dbx` revocation updates signed under the 2023 hierarchy, freezing its boot-revocation floor against future bootkits [886].

Across the third-party UEFI ecosystem, Linux `shim` solves the same NVRAM capacity bound through generation-metadata revocation rather than certificate rotation. Under Secure Boot Advanced Targeting (`SBAT`), build pipelines embed component generation numbers inside a `.sbat` PE section, and `shim` compares those metadata records at boot against a compact `SbatLevel` UEFI variable so entire vulnerable bootloader generations can be rejected in a few dozen bytes without consuming `dbx` hash slots [17].

### Admission Control Without Attestable State

Even when properly provisioned, patched, and updated with current `dbx` revocations, Secure Boot and Trusted Boot are purely local admission gates. They enforce a boolean execution decision at load time (`EFI_SUCCESS` vs. `EFI_SECURITY_VIOLATION`) and leave no cryptographic proof of which firmware version, option ROM, `dbx` revision, or bootloader actually executed. If a physical attacker disables Secure Boot in UEFI setup, or if LogoFAIL subverts DXE below `LoadImage()`, the booted operating system cannot prove its integrity to a local disk-encryption key or a remote enterprise verifier by consulting Secure Boot variables alone. Recording an unforgeable execution transcript requires a separate hardware measurement and attestation rail.

## Inspecting and Verifying on a Running System

Operational verification of Secure Boot requires checking firmware enforcement state, inspecting enrolled NVRAM certificates for CA rotation and supply-chain test keys, verifying KB5025885 servicing status, and confirming ELAM kernel policy. All `SecureBoot` module queries require administrative privileges [45].

### Checking Firmware Secure Boot Enforcement

Query the UEFI `SecureBoot` state variable via the native PowerShell cmdlet [45]:

```powershell
Confirm-SecureBootUEFI
```

Expected output on an enforcing UEFI system:

```text
True
```

A return value of `False` indicates UEFI mode with Secure Boot disabled (or in Setup/Audit Mode). On legacy BIOS systems (or VMs configured as Generation 1), the cmdlet throws `System.PlatformNotSupportedException` (`Cmdlet not supported on this platform`); in an unelevated shell, it throws `System.UnauthorizedAccessException`. Note that `Get-SecureBootPolicy` queries an optional platform configuration policy variable (used primarily on locked-down S-mode or specialized devices) and returns `Secure Boot policy is not enabled on this machine` on standard x86 enterprise installations even when `Confirm-SecureBootUEFI` is `True` [45].

### Auditing PK and db for CA 2023 Enrollment and PKfail Exposure

Inspect the raw `EFI_SIGNATURE_LIST` byte arrays in `db`, `dbx`, and `PK` to verify enrollment of `Windows UEFI CA 2023` and ensure the firmware does not trust leaked IBV test keys (`PKfail`) [15, 18, 44, 45]:

```powershell
[Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes) -match 'Windows UEFI CA 2023'
[Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI PK).Bytes) -match 'DO NOT TRUST|DO NOT SHIP'
(Get-SecureBootUEFI dbx).Bytes.Length
```

Expected output on a healthy, transitioned system:

```text
True
False
11596
```

The first line confirms `Windows UEFI CA 2023` is present in NVRAM `db`; the second confirms `PK` does not match known AMI/IBV test-key subject strings (`False` is safe; `True` indicates PKfail vulnerability); the third confirms `dbx` is populated and reports its current NVRAM byte footprint.

### Verifying KB5025885 Servicing and Revocation State

Windows tracks automated Secure Boot certificate and boot-manager servicing under the `SecureBoot\Servicing` registry key, while staged pending update bitmasks are written to the `AvailableUpdates` `REG_DWORD` value under `Control\SecureBoot` [19]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing' |
    Select-Object UEFICA2023Status, UEFICA2023Error, WindowsUEFICA2023Capable
Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
```

Expected output on a fully updated host:

```text
UEFICA2023Status UEFICA2023Error WindowsUEFICA2023Capable
---------------- --------------- ------------------------
Updated                                                 2
0
```

When servicing completes cleanly across reboots via the `\Microsoft\Windows\PI\Secure-Boot-Update` scheduled task, `UEFICA2023Status` reports `Updated`, `UEFICA2023Error` is absent, and `AvailableUpdates` returns `0` (as staged bitmask flags such as `0x40`, `0x100`, or `0x5944` are cleared as each step applies) [19].

### Checking Early Launch Anti-Malware Driver Policy

Inspect the Group Policy registry value governing how `ntoskrnl.exe` enforces ELAM `BDCB_CLASSIFICATION` verdicts on boot-start drivers [26, 28]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -ErrorAction SilentlyContinue
```

Expected output when explicitly configured via Group Policy (*Boot-Start Driver Initialization Policy*):

```text
DriverLoadPolicy : 3
```

If the `Policies\EarlyLaunch` key or `DriverLoadPolicy` value is absent (nothing returned), the kernel enforces the built-in default (`3`: initialize *Good*, *Unknown*, and *BadButCritical*; block *KnownBad*). Hardened environments set `8` (*Good only*) or `1` (*Good and Unknown*), whereas `7` (*All*) disables blocking of known-malicious boot drivers.

## Summary & Handoff

Secure Boot and Trusted Boot solve the unauthenticated sector-zero problem by requiring every UEFI boot application, OS loader, kernel image, and boot-start driver to chain cryptographically to NVRAM policy authorities before execution. Yet fifteen years of operational deployment demonstrate that cryptographic signature checks are bounded by lifecycle management: pre-verifier DXE bugs (LogoFAIL), leaked OEM/IBV keys (PKfail), and the multi-year latency between patching a vulnerable bootloader and revoking it across constrained `dbx` flash (BlackLotus, CVE-2023-24932, Bitpixie) define where firmware admission control fails.

Because Secure Boot only blocks unapproved binaries at load time, every stateful guarantee above the firmware gate depends on downstream layers of the architecture. Hardware-isolated registers and non-exportable keys required to record platform state reside in [The TPM (Chapter 2)](01-tpm.md), while eliminating exposed inter-chip buses and OEM firmware update lag motivates [Pluton (Chapter 3)](02-pluton.md). Measuring every firmware and bootloader stage into PCRs across static and dynamic roots of trust and sealing BitLocker keys against downgrade paths belong to [Measured Boot (Chapter 4)](03-measured-boot.md), paired with off-box cryptographic verification in [Attestation (Chapter 5)](04-attestation.md). Once `ExitBootServices()` completes, protecting kernel memory and credentials against vulnerable signed drivers requires [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md), while evaluating `SiPolicy`, catalog signatures, HVCI, and WDAC rules across user and kernel mode continues in [Code Integrity and Application Control (Chapter 7)](06-code-integrity.md).
