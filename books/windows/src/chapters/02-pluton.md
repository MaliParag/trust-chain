# Pluton

## Overview

* **Role in the Chain:** On-die hardware root of trust and security processor integrated directly into the client CPU SoC; implements TPM 2.0 storage and reporting services without an external motherboard bus while introducing an OS-delivered firmware update channel.
* **Core Security Invariant:** Host-to-TPM traffic never traverses off-package board traces, hardware-isolated keys protected by Secure Hardware Cryptography Key (SHACK) remain unreadable even to Pluton runtime firmware, and post-boot processor firmware can be authenticated and updated directly by Microsoft via Windows Update.
* **Trusted Computing Base (TCB):** The on-die Pluton silicon IP block and FIPS-validated immutable Boot ROM, Secure Hardware Cryptography Key (SHACK) engines, Microsoft-signed Pluton firmware, Microsoft's firmware-signing PKI and Windows Update delivery pipeline, and the silicon foundry/packaging supply chain.
* **Primary Failure Modes:** Logic or memory-safety defects in shared TCG reference code paths (such as CVE-2025-2884), OEM firmware configurations leaving Pluton disabled or falling back to shared chipset fTPMs, version skew between SPI-resident pre-OS firmware and OS-loaded runtime firmware, and single-signer authority concentration.
* **Handoff:** Anchors tamper-resistant PCR storage and non-exportable keys inside the CPU package for [Measured Boot (Chapter 4)](03-measured-boot.md) and [Attestation (Chapter 5)](04-attestation.md); leaves boot measurement orchestration, remote quote appraisal, and post-unseal VTL1 memory isolation to downstream chapters.

## Core Engineering Problem & Threat Model

[Chapter 2](01-tpm.md) established three empirical failure classes across traditional Windows TPM deployments: discrete TPMs expose plaintext `TPM2_Unseal` responses to passive logic analyzers on motherboard LPC and SPI traces [75, 76], chipset firmware TPMs share broad execution environments susceptible to timing side channels and physical voltage glitching [77, 78], and both depend on multi-tier vendor-to-OEM UEFI capsule pipelines that leave known firmware vulnerabilities unpatched for months or years. Fixing the protocol specification could not fix physical board topology or OEM servicing latency.

Microsoft's architectural response evolved across three prior internal hardware generations before reaching Windows PCs: the Xbox One SoC (2013), which co-located a Microsoft-signed security processor on the AMD processor die to resist physical console hardware attacks [98]; Microsoft Research's *Seven Properties of Highly Secure Devices* (MSR-TR-2017-16, 2017), which formalized *renewable security* through online firmware servicing as a mandatory root-of-trust requirement [99]; and Azure Sphere (2018-2020), which licensed the named *Pluton* security subsystem onto third-party silicon backed by cloud-delivered updates [100, 101, 102]. Announced for Windows PCs alongside AMD, Intel, and Qualcomm on November 17, 2020 [98] and first shipped in AMD Ryzen 6000 mobile processors in early 2022 [103, 104], Pluton brings that integrated model to the Windows 11 client ecosystem [79].

The Pluton threat model assumes an adversary with physical possession of a stolen or unattended laptop (capable of probing motherboard buses and power rails), local administrative or ring-0 kernel execution attempting to extract keys or exploit TPM command parsers, and rapid weaponization of newly disclosed firmware vulnerabilities faster than OEM BIOS update cycles. Against this threat model, Pluton eliminates external TPM wiring, isolates security services into a dedicated SoC block, migrates newer firmware foundations to memory-safe Rust, and routes runtime firmware patches directly through Windows Update [79, 98].

## Architectural Deep Dive

### On-Die SoC Integration and Dedicated Isolation

Unlike a discrete TPM wired across external Low Pin Count (`LPC`), `SPI`, or `I2C` traces, Pluton is synthesized directly onto the host application processor die as a dedicated hardware security subsystem (termed the Hardware Security Processor, or `HSP`, in AMD SoC documentation) [79, 98, 105]. Microsoft integrates Pluton across all three client silicon ecosystems: AMD Ryzen 6000, 7000, 8000, 9000, and Ryzen AI series processors; Intel Core Ultra 200V series, Core Ultra Series 3, and Core Series 3 processors; and Qualcomm Snapdragon 8cx Gen 3 and Snapdragon X series processors powering Copilot+ PCs and Microsoft Surface hardware [79].

On the host side, Pluton exposes a standard TCG TPM 2.0 Command Response Buffer (`CRB`) memory-mapped I/O (`MMIO`) interface [80, 106]. Because communication between the x86/ARM application cores and the Pluton subsystem occurs entirely across internal on-die interconnect fabrics, no off-package pins carry unsealed BitLocker keys or authorization traffic [98]. Because the transport adheres to the open TCG CRB specification, both Windows (`tpm.sys` and TPM Base Services) and non-Windows kernels (Linux 6.3 and later via `tpm_crb` [106, 107]) interact with Pluton using standard `TPM2_*` command structures without proprietary OS APIs.

Architecturally, Pluton also separates TPM execution from general-purpose platform management coprocessors [79]. On AMD platforms, Pluton resides in its own dedicated hardware block rather than running as a TrustZone applet inside the shared AMD Platform Security Processor (`PSP`) alongside memory-encryption setup and SMM helpers, narrowing the shared-TEE blast radius exploited by `faulTPM` when Pluton is configured as the active system TPM [78, 105].

### Platform Operating Modes and OEM Firmware Routing

Shipping silicon that *contains* a Pluton IP block does not guarantee that Windows uses Pluton as its active TPM. OEMs configure platform routing in UEFI firmware across three distinct operating modes [79, 80]. In *Pluton as TPM 2.0* mode, firmware exposes Pluton's TCG CRB interface as the system's sole active TPM (`ManufacturerIdTxt = MSFT`), binding BitLocker, Measured Boot, Windows Hello, and Credential Guard directly to Pluton [80]. In *co-resident security processor* mode, firmware enumerates Pluton as a Windows Plug-and-Play device (`Microsoft Pluton Security Processor`) for platform services and Windows Update firmware management while routing the system TPM 2.0 interface to a traditional discrete TPM chip, for example to satisfy legacy Common Criteria EAL4+ procurement mandates [80]. In *disabled or chipset fTPM fallback* mode, firmware hides or gates Pluton altogether and exposes Intel PTT or AMD PSP fTPM instead [105, 108].

Reverse engineering of commercial AMD Ryzen 6000 UEFI images by Matthew Garrett in 2022 documented two distinct disable mechanisms in platform firmware [105]: a high-level UEFI setup toggle that suppresses OS ACPI/CRB communication channels without powering down the underlying block, and a lower-level AMD PSP directory entry (`0xB`, bit 36) soft fuse that gates the HSP clock, disables the HSP core, and blocks PSP-to-HSP mailbox commands. Because commercial OEMs adopted divergent launch defaults (with Microsoft Surface and Snapdragon X enabling Pluton by default, Lenovo shipping early Ryzen 6000 ThinkPads with Pluton disabled by default, and Dell declining Pluton enablement on commercial lines [79, 108, 109]), enterprise defenders must verify active TPM routing rather than inferring protection from CPU model numbers.

![Figure: Physical packaging and bus topology across three TPM realizations: discrete dTPM chips over exposed SPI/LPC motherboard traces, chipset/PSP firmware fTPMs, and on-die Microsoft Pluton communicating over internal SoC fabric via Command Response Buffer (CRB) with SHACK key isolation.](diagrams/tpm-vs-pluton-topology.svg)

### SHACK and the Transition to Rust Firmware

Pluton extends key protection one ring deeper than standard TCG `fixedTPM` semantics through Secure Hardware Cryptography Key (SHACK) technology [98]. In conventional microcontroller or firmware TPMs, runtime firmware executing inside the coprocessor loads raw symmetric or asymmetric key bytes into internal SRAM during cryptographic routines; a memory-disclosure vulnerability inside TPM firmware can therefore expose key material. SHACK isolates critical hardware keys inside dedicated cryptographic engines on the Pluton block such that keys can be exercised by firmware requests without the raw key bits ever becoming readable to Pluton's own runtime software [98].

At the software layer, Pluton's boot root is anchored in an on-die Boot ROM carrying FIPS 140-3 Level 2 cryptographic module validation (CMVP Certificate #4880) [110]. Above that immutable ROM, Pluton's runtime firmware has matured across two distinct engineering generations. Disassembly of first-generation 2022 Ryzen 6000 firmware images revealed a 32-bit ARM binary incorporating substantial portions of the C-based TCG TPM 2.0 reference library [105]. To eliminate spatial and temporal memory-safety defects such as buffer overflows, use-after-free bugs, and uninitialized reads inside high-privilege security firmware, Microsoft transitioned 2024 and newer AMD and Intel Pluton platforms onto a memory-safe, Rust-based firmware foundation [79].

### Dual-Phase Boot and Windows Update Servicing

Pluton operationalizes *renewable security* by splitting firmware delivery across early hardware initialization and operating-system startup [79]:

![Figure: Pluton boot and update, architectural shape. The shape is generic to on-die RoT designs; specific protocol bytes between Pluton and Windows Update are not on the public record.](diagrams/02-pluton-boot-update.svg)

At power-on reset, Pluton's immutable on-die Boot ROM cryptographically verifies and loads a base Pluton firmware image stored in motherboard SPI flash, anchored against hardware anti-rollback version counters to service pre-OS UEFI Measured Boot (`PCR[0..7]`) and early BitLocker `TPM2_Unseal` calls. Once Windows 11 starts, the operating system checks whether Windows Update has staged a newer, Microsoft-signed Pluton firmware package on disk and dynamically loads that updated image into Pluton during OS initialization, superseding the older SPI-resident build for all runtime operations [79]. Separate OEM UEFI capsule updates (also distributable through Windows Update) subsequently advance the SPI-resident early-boot image so pre-OS execution converges onto the patched baseline [79].

This dual-channel architecture decouples urgent runtime TPM vulnerability remediation from slow OEM per-model BIOS qualification cycles while preserving deterministic pre-OS boot availability.

## Attack Catalog & Gap Analysis

As of 2026, no public attack has extracted SHACK-protected keys or bypassed Pluton's on-die Boot ROM signature verification. Instead, documented risks center on shared TCG reference-code defects, OEM firmware disablement or fallback misconfigurations, integrated-TPM side-channel surfaces, and architectural boundaries that Pluton was never designed to cover.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| OEM fTPM / dTPM Fallback Drift | 2022-2026 | Assumed on-die Pluton protection on supported CPUs | OEM SKU shipping Pluton disabled (e.g., PSP `0xB` bit 36 or BIOS toggle) | Forces platform back onto AMD PSP fTPM (`faulTPM` exposure) or discrete LPC/SPI TPM (bus-sniffing exposure) despite Pluton-capable CPU | Audit `Get-Tpm` (`MSFT`) + PnP `SecurityDevices`; enable Pluton in UEFI setup [80, 105, 108] |
| Post-Unseal DRAM Extraction (Bitpixie / DMA) | 2022-2024 | BitLocker VMK confidentiality after `TPM2_Unseal` | PXE soft-reboot downgrade (`CVE-2023-21563`) or pre-auth DMA without IOMMU | Extracts plaintext VMK from host DRAM *after* Pluton legitimately unseals it across the on-die CRB interface | Enforce `TPMAndPIN`, KB5025885 revocations, and Kernel DMA Protection [19, 36, 67, 111] |
| iTPM Timing Observation (`TPMScan`) | 2024 | Constant-time uniformity across TPM 2.0 implementations | Local high-resolution command-timing measurement | Empirical CHES 2024 test suite across 78 TPM 2.0 versions (including Pluton iTPMs) probing command latency and nonce behaviors | Maintain current Windows Update Pluton firmware and Rust-based 2024+ builds [79, 112, 113] |
| TCG Reference OOB Read (CVE-2025-2884 / VU#282450) | 2025 | Bounds safety in `CryptHmacSign` TPM 2.0 command handler | Authenticated local access to vulnerable reference-derived TPM interface | Triggers out-of-bounds memory read causing information disclosure or TPM denial of service in TCG v1.83 reference derivatives | Deliver patched TPM firmware via Windows Update (Pluton) or OEM UEFI capsules [79, 114, 115, 116] |
| Pre-OS SPI vs. OS-Load Version Skew | Architectural | Pre-OS Pluton firmware currency prior to Windows startup | Unupdated SPI flash capsule paired with newer OS-loaded Pluton image | Targets early-boot SPI-resident Pluton firmware during pre-OS window before Windows startup loads the newer OS-delivered image | Apply UEFI firmware capsules alongside Windows Update OS packages [79] |

### Reference-Code Lineage and Patch Dwell Time: CVE-2025-2884

Disclosed in June 2025 under CERT/CC `VU#282450` and TCG advisory `VRT0009`, CVE-2025-2884 is an out-of-bounds read in `CryptHmacSign` within the official TCG TPM 2.0 reference implementation (Revision 01.83), enabling an authenticated local attacker to disclose internal memory or crash TPM service [114, 115, 116]. Because the TCG reference codebase underpins virtually the entire TPM 2.0 ecosystem, the single upstream flaw propagated simultaneously into Intel TPM products (`INTEL-SA-01209`), Siemens industrial systems (`SSA-628843`), `libtpms` virtual TPMs (`CVE-2025-49133`), and reference-derived firmware lines [117, 118, 119, 120].

![Figure: CVE-2025-2884 propagation: a single bug in the TCG TPM 2.0 reference code reaches Intel TPM products, Siemens product TPMs, libtpms, and any reference-derived firmware that retained the affected code path. Garrett 2022 makes Pluton a plausible lineage concern, not a proved affected product. The patch paths differ; the underlying defect class is the same.](diagrams/02-pluton-cve-propagation.svg)

Although no public advisory confirmed that shipping Pluton builds exposed the vulnerable `CryptHmacSign` path, Garrett's 2022 finding of TCG reference code inside early ARM Pluton firmware illustrates why on-die placement does not immunize a processor against logic or memory bugs [105]. What Pluton changes is remediation dwell time: whereas fixing a reference-code bug on discrete TPMs or chipset fTPMs requires waiting quarters for chip vendors and OEMs to ship per-laptop BIOS capsules, Pluton allows Microsoft to compile, sign, and deploy a runtime firmware fix directly to endpoints on the monthly Windows Update cadence, while 2024+ Rust foundations eliminate entire classes of C out-of-bounds reads structurally [79].

### Fleet Enablement Drift and Soft-Fuse Traps

The most common real-world failure of Pluton protections in enterprise fleets is silent non-enablement. Because OEMs decide per SKU whether Pluton is active, co-resident, or disabled in BIOS [80, 108], asset inventories filtered purely on CPU generation (such as "all Ryzen 7000 or Core Ultra laptops") routinely misclassify endpoints running `AMD` PSP fTPM or discrete `IFX`/`NTC` chips as Pluton-backed. Furthermore, because the UEFI setup toggle and PSP directory `0xB` bit 36 soft fuse behave differently across board revisions [105], administrators must verify both the Plug-and-Play device state and the active `TPM_PT_MANUFACTURER` identifier (`MSFT`) inside the running OS.

### Integrated Side-Channel Audits and Pre-OS Servicing Gaps

Placing a security processor on the main CPU die removes physical probe pins but places the subsystem closer to shared package power delivery and high-bandwidth host interfaces. The CHES 2024 `TPMScan` study evaluated 78 TPM 2.0 firmware versions across six vendors, explicitly including Pluton-based integrated TPMs alongside Intel, AMD, Infineon, STMicroelectronics, and Nuvoton implementations, demonstrating how automated black-box timing harnesses continuously audit modern iTPMs for scalar-multiplication and command-timing leaks [112, 113]. Additionally, defenders must account for Pluton's split boot lifecycle: because Windows Update dynamically loads updated Pluton firmware *during Windows startup*, pre-OS TPM operations (such as early UEFI `PCR` extensions and `bootmgfw.efi` BitLocker unsealing) execute on the SPI-resident Pluton image until a UEFI capsule advances flash storage [79].

## Theoretical Limits & Structural Invariants

### On-Die Storage Root Does Not Protect Post-Unseal Host RAM

Pluton inherits the fundamental boundary of every passive TPM 2.0 implementation: it is a Root of Trust for Storage and Reporting, not an active monitor of host x86/ARM memory ([Chapter 2](01-tpm.md)). Eliminating the external LPC/SPI bus ensures a physical attacker cannot clip a logic analyzer onto motherboard traces during `TPM2_Unseal` [75, 98]. However, the instant Pluton returns the unsealed BitLocker Volume Master Key over the internal CRB MMIO window into host DRAM, that key resides in normal VTL0 memory. If a vulnerable signed bootloader leaves the VMK unscrubbed across a soft reboot (`Bitpixie`, [Chapter 1](16-secure-boot.md)) [36] or a malicious Thunderbolt peripheral reads DRAM without IOMMU remapping [111], Pluton cannot intervene. Protecting secrets *after* release requires hypervisor-enforced VTL1 memory isolation ([Chapter 6](05-secure-kernel.md), [Chapter 12](08-credential-guard.md)).

### Single-Signer Revocation Impossibility and Sovereign Governance

Pluton's fastest security feature is simultaneously its hardest governance constraint. Stated formally, when an on-die security processor authenticates firmware exclusively against a single vendor root anchored in immutable mask ROM, that signing authority cannot be revoked, rotated to an independent party, or co-constrained without replacing the physical CPU.

This trade-off is structural rather than cryptographic. While multi-party threshold signatures and transparency logs exist in network protocols [121], Pluton optimizes for zero-touch, fleet-wide patch velocity under Microsoft's signing authority [79, 98]. Consequently, organizations bound by sovereign hardware mandates (such as European government fleets referencing German BSI Common Criteria `PP-0084` discrete-TPM profiles [122] or navigating EU Cyber Resilience Act supply-chain governance [123]) face an explicit procurement choice: accept centralized Microsoft firmware authority in exchange for on-die bus elimination and Windows Update speed, or retain certified discrete TPMs paired with mandatory pre-boot PINs and offline UEFI capsule management [80, 108].

### Decoupling Firmware Signature Validity from Supply-Chain and Runtime Trust

Just as bootloader signatures prove provenance rather than runtime safety, cryptographic verification of a Pluton firmware image proves only that Microsoft's signing key endorsed that binary; it does not attest to pre-provisioning wafer fabrication, foundry integration, or motherboard assembly integrity prior to fuse programming, nor does it attest to peripheral firmware on PCIe, NVMe, or network controllers (where component attestation standards such as DMTF SPDM 1.3 remain server-focused rather than deployed Windows client gates [124]). Likewise, a genuine Pluton quote or key signature proves hardware residence on the SoC, never whether the user-mode session invoking `CNG` has been hijacked at runtime.

## Inspecting and Verifying on a Running System

Operational verification on a Windows 11 endpoint must confirm three distinct facts: whether Pluton hardware is enumerated by Plug and Play, whether Pluton is actually selected as the active TPM (`MSFT`), and that `MSFT` is running on bare metal rather than a hypervisor virtual TPM.

### Verifying Active Pluton-as-TPM vs. Virtual TPM Ambiguity

Query the active TPM manufacturer string alongside the host computer model to distinguish physical Pluton silicon from a Hyper-V or Azure Trusted Launch `vTPM` (both of which report `ManufacturerIdTxt = MSFT`) [79, 80, 125]:

```powershell
Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerIdTxt, ManufacturerVersion
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model
```

Expected output on physical Pluton-as-TPM hardware:

```text
TpmPresent TpmReady ManufacturerIdTxt ManufacturerVersion
---------- -------- ----------------- -------------------
      True     True MSFT              1.38.2504.0

Manufacturer           Model
------------           -----
Microsoft Corporation  Surface Laptop 7th Edition
```

If `Model` reports `Virtual Machine` while `ManufacturerIdTxt` reports `MSFT`, the system is backed by a host-emulated `vTPM`, not physical Pluton silicon. Conversely, if a Ryzen 6000+ or Core Ultra laptop reports `AMD` or `INTC`, Pluton is either disabled in UEFI setup or superseded by the chipset fTPM [105, 108].

### Enumerating Co-Resident Security Devices via Plug and Play

Inspect the `SecurityDevices` device class to detect whether Pluton is enumerated in co-resident mode alongside a discrete TPM or active as the primary processor [79, 80]:

```powershell
Get-PnpDevice -Class SecurityDevices | Select-Object Status, FriendlyName, InstanceId
```

Expected output when Pluton is enumerated and healthy:

```text
Status FriendlyName                        InstanceId
------ ------------                        ----------
OK     Microsoft Pluton Security Processor ACPI\MSFT0200\...
OK     Trusted Platform Module 2.0         ACPI\MSFT0101\...
```

Presence of `Microsoft Pluton Security Processor` with `Status = OK` confirms OS visibility for Windows Update firmware servicing even on SKUs where an OEM routes `Trusted Platform Module 2.0` to a discrete vendor (`IFX`, `NTC`, `STM `).

### Checking Active Pluton Driver and Firmware Package Version

Inspect the installed Windows driver package version bound to the Pluton Plug-and-Play node to verify Windows Update servicing currency [79]:

```powershell
Get-PnpDevice -Class SecurityDevices -FriendlyName '*Pluton*' |
    Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_DriverVersion','DEVPKEY_Device_FirmwareVersion' |
    Select-Object KeyName, Data
```

Expected output format on a serviced endpoint:

```text
KeyName                        Data
-------                        ----
DEVPKEY_Device_DriverVersion   10.0.26100.3912
DEVPKEY_Device_FirmwareVersion 1.38.2504.0
```

Comparing `DEVPKEY_Device_DriverVersion` and `ManufacturerVersion` across fleet baselines identifies endpoints pending reboot or blocked from receiving OS-loaded Pluton updates.

## Summary & Handoff

Microsoft Pluton resolves the physical and operational vulnerabilities exposed across discrete and shared-TEE TPMs between 2019 and 2024: moving the cryptoprocessor onto the CPU die eliminates sniffable LPC/SPI traces, isolating it from general platform management engines narrows fault-injection blast radius, adopting Rust on modern x86 platforms hardens memory safety, and loading signed updates through Windows Update compresses vulnerability dwell time. In exchange, Pluton concentrates irreversible firmware-signing authority in Microsoft and leaves host memory post-unseal outside its boundary.

With the hardware root anchored directly on the SoC, the trust chain advances from key storage to recording and proving what the platform executes. Extending deterministic hashes of firmware, bootloaders, and OS policies into static (`PCR[0..7]`) and dynamic (`PCR[17..22]`) registers to protect BitLocker secrets is owned by [Measured Boot (Chapter 4)](03-measured-boot.md). Turning those Pluton or TPM PCR states and TCG event logs into cryptographically signed `TPM2_Quote` claims verified by cloud control planes belongs to [Attestation (Chapter 5)](04-attestation.md), while protecting unsealed keys, kernel code pages, and credentials once they cross out of the Pluton boundary into host RAM requires [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md).
