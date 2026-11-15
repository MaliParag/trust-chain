# Measured Boot

## Overview

* **Role in the Chain:** Cryptographic recording and local sealing layer bridging platform reset to kernel initialization; hashes every firmware, Secure Boot policy, bootloader, and early-driver stage into TPM Platform Configuration Registers (PCRs) alongside a replayable Windows Boot Configuration Log (`WBCL`).
* **Core Security Invariant:** Each boot stage measures the code and configuration of its successor into append-only PCR banks *before* transferring execution (`SRTM`), or re-anchors execution from a hardware-enforced CPU late launch at TPM Locality 4 (`DRTM` / Secure Launch), ensuring any alteration to measured inputs deterministically changes final PCR digests.
* **Trusted Computing Base (TCB):** For SRTM, the silicon/firmware Core Root of Trust for Measurement (`CRTM`) and every intermediate loader measuring its successor prior to execution; for DRTM, CPU late-launch microcode (`GETSEC[SENTER]` / `SKINIT`), the vendor-signed launch module (`SINIT ACM` / `SLB`), the IOMMU, and SMM isolation (`STM` / SMM Supervisor).
* **Primary Failure Modes:** Reproducing seal-time `PCR[7]` + `PCR[11]` digests with an unrevoked vulnerable boot manager to extract BitLocker keys across soft reboot (`Bitpixie`, CVE-2023-21563), uncontained SMM handlers subverting early DRTM launches, retail firmware omitting mandatory `PCR[7]` debug measurements, and verifiers consuming unsigned `WBCL` logs without cryptographic PCR replay.
* **Handoff:** Produces live hardware PCR digests (enforcing local BitLocker `TPM2_Unseal` policies) and the merged `WBCL` event transcript; delegates off-box cryptographic quoting, `EK`/`AK` identity binding, and remote health verdicts to [Attestation (Chapter 5)](04-attestation.md).

## Core Engineering Problem & Threat Model

Signature verification alone (`Secure Boot`, [Chapter 1](16-secure-boot.md)) answers only a binary admission question at load time: *was this image signed by a trusted authority absent from `dbx`?* Once `ExitBootServices()` completes, admission gates leave behind no tamper-evident record of *which* UEFI revision, PCIe Option ROM, BCD configuration, or signed bootloader build actually ran. Neither a local secret (such as a BitLocker Volume Master Key) nor a remote enterprise gateway can distinguish a clean, current boot from a machine where Secure Boot was toggled off in BIOS setup or downgraded to an older validly signed binary unless every boot transition is cryptographically recorded into hardware registers that the OS cannot rewind ([Chapter 2](01-tpm.md), [Chapter 3](02-pluton.md)).

William Arbaugh, David Farber, and Jonathan Smith formulated the inductive bootstrap model in their 1997 *AEGIS* architecture [126]: beginning from a minimal immutable root (`L0`), each initialization layer verifies its successor prior to execution. Because an in-RAM BIOS check could not prove its transcript to an external observer or protect secrets offline, the Trusted Computing Group paired inductive measurement with hardware PCRs in the PC Client Specific Implementation (`PCSI`) for TPM 1.2 and modernized it for multi-bank hash agility in the TCG PC Client Platform Firmware Profile (`PFP`) for TPM 2.0 [57, 58, 127]. Windows 8 integrated this pipeline natively with *Measured Boot* and the Windows Boot Configuration Log (`WBCL`), and Windows 10 version 1809 added hardware late launch via *System Guard Secure Launch* [21, 128, 129, 130].

The Measured Boot threat model assumes an adversary with physical access to a stolen or unattended endpoint, LAN PXE boot reachability, or local administrative privileges capable of swapping ESP bootloaders, toggling BCD flags, or forging user-mode log files. Against this adversary, Measured Boot does *not* block execution; instead, it guarantees that any deviation in measured code or configuration alters the hardware PCR state so sealed secrets remain locked and remote verifiers detect tampering.

## Architectural Deep Dive

### Static Root of Trust for Measurement (SRTM) and Windows PCR Allocation

Under the Static Root of Trust for Measurement (`SRTM`), measurement begins at CPU reset inside the Core Root of Trust for Measurement (`CRTM`): immutable boot block code anchored by Intel Boot Guard, AMD Platform Secure Boot, or firmware backed by Pluton ([Chapter 1](16-secure-boot.md), [Chapter 3](02-pluton.md)) [130]. Before jumping to general UEFI initialization, the CRTM hashes its own version (`EV_S_CRTM_VERSION`), code (`EV_S_CRTM_CONTENTS`), and POST firmware volumes (`EV_POST_CODE`, `EV_EFI_PLATFORM_FIRMWARE_BLOB`) into `PCR[0]` [129]. Each subsequent stage measures its successor before transferring CPU control:

![Figure: The linear SRTM measurement chain. Each stage measures its successor and extends a PCR before handing off: CRTM→PCR[0], PEI/DXE→PCR[1–3], BDS→PCR[7] (Secure Boot policy) and PCR[4] (bootmgfw.efi), Windows boot→PCR[12–14]. PCR[11] is reserved for the BitLocker seal and carries no boot-code measurement, and the kernel's EV_SEPARATOR freezes the Windows OS PCRs (firmware having already closed PCR[0–7]).](diagrams/03-measured-boot-srtm-chain.svg)

Per the TCG PC Client PFP and Microsoft's `Tbsi_Get_TCG_Log` specification [127, 129], the 24 registers in each active TPM 2.0 bank (canonically SHA-256) partition cleanly across firmware, Windows boot, and dynamic late launch:

| PCR Index | Measuring Component | Recorded Measurements on Windows |
|---|---|---|
| `PCR[0]` | CRTM, SEC, PEI | Core UEFI firmware version (`EV_S_CRTM_VERSION`) and main SPI firmware volumes |
| `PCR[1]` | PEI / DXE | Host platform configuration, SMBIOS tables, CPU microcode, UEFI setup variables |
| `PCR[2]` | DXE | Pluggable third-party UEFI drivers and PCIe Option ROM code (`EV_EFI_BOOT_SERVICES_DRIVER`) |
| `PCR[3]` | DXE | Option ROM and UEFI driver configuration data |
| `PCR[4]` | UEFI BDS | Authenticode PE image digest of `bootmgfw.efi` (`EV_EFI_BOOT_SERVICES_APPLICATION`) and boot attempts |
| `PCR[5]` | UEFI BDS | GPT partition table, `BootOrder`/`Boot####` variables (`EV_EFI_VARIABLE_BOOT`), `ExitBootServices` transitions |
| `PCR[6]` | Firmware / OEM | Platform manufacturer-specific host state and wake transitions |
| `PCR[7]` | DXE / BDS | Secure Boot policy: `SecureBoot`, `PK`, `KEK`, `db`, `dbx` (`EV_EFI_VARIABLE_DRIVER_CONFIG`), matched signer (`EV_EFI_VARIABLE_AUTHORITY`), and pre-OS debugger state (`EV_EFI_ACTION`) [131] |
| `PCR[8..10]` | Unused by Windows | Left unextended by Windows (`0x00...00`); used by GRUB/IMA on Linux |
| `PCR[11]` | `bootmgfw.efi` | BitLocker access-control PCR: extended to cap unseal access once the OS volume key is released |
| `PCR[12]` | `bootmgfw.efi` / `winload.efi` | Windows boot-application configuration, BCD store elements, and boot-debug flags (`WBCL`) |
| `PCR[13]` | `winload.efi` | Boot module digests (`ntoskrnl.exe`, `hal.dll`, boot-start drivers), ELAM policy hash, ELAM driver digest, and per-driver ELAM verdicts |
| `PCR[14]` | `winload.efi` | Code-signing authorities validating Windows boot components |
| `PCR[16]`, `PCR[23]` | Debug / App | Resettable debug (`PCR[16]`) and application-specific (`PCR[23]`) registers |
| `PCR[17..22]` | CPU Locality 4 + MLE | DRTM / System Guard Secure Launch: `SINIT ACM` / `SLB` (`PCR[17]`), Hyper-V + Secure Kernel MLE (`PCR[18]`), and dynamic OS state [12, 128] |

Two subtle encoding rules govern `PCR[4]` and `PCR[7]` operationally. Just like UEFI `LoadImage()`, BDS extends the PE/COFF Authenticode digest of `bootmgfw.efi` (excluding header checksum and signature table) into `PCR[4]`, followed by `EV_SEPARATOR` events (`0x00000004` over `0x00000000` or error value `0x00000001`) across `PCR[0..7]` to close the firmware measurement window [16, 129]. In `PCR[7]`, firmware does not hash raw `dbx` bytes alone; each `EV_EFI_VARIABLE_DRIVER_CONFIG` event hashes a serialized `UEFI_VARIABLE_DATA` structure containing `(VariableName GUID, UnicodeLength, VariableDataSize, UnicodeName, VariableData)` [129, 131]. Any Windows Update expanding `dbx` (such as KB5025885) therefore shifts `PCR[7]` deterministically, and TCG specifications likewise mandate that firmware offering a pre-OS UEFI debugger extend an `EV_EFI_ACTION` string into `PCR[7]` prior to enabling debug access [131]. On the Windows side, practitioners must also avoid conflating `PCR[11]` with OS code hashes: `ntoskrnl.exe`, boot-critical drivers, and ELAM verdicts extend into `PCR[13]` (with BCD configuration in `PCR[12]` and signing authorities in `PCR[14]`), whereas `PCR[11]` acts strictly as BitLocker's state-machine gate [129].

### Crypto-Agile Event Logs (`TCG_PCR_EVENT2`) and the WBCL Pipeline

Because `TPM2_PCR_Extend` compresses an arbitrarily long measurement sequence into a fixed 32-byte SHA-256 value, a verifier cannot invert a PCR digest to enumerate what ran. Firmware and Windows therefore maintain a companion plaintext event transcript in host RAM [129, 132]. To remain parseable by legacy TPM 1.2 readers while advertising multi-bank TPM 2.0 layouts, the very first entry in a PFP event log is formatted as a legacy `TCG_PCR_EVENT` of type `EV_NO_ACTION` (`PCRIndex = 0`, zero SHA-1 digest) whose payload is a `TCG_EfiSpecIDEventStruct` beginning with the 16-byte ASCII signature `"Spec ID Event03\0"` and enumerating active `TPM_ALG_ID` digest sizes [129]. Every subsequent firmware and OS measurement appends a crypto-agile `TCG_PCR_EVENT2` structure containing `PCRIndex`, `EventType`, `TPML_DIGEST_VALUES` (holding `Count` `TPMT_HA` bank-specific digests of the measured entity), and variable-length `Event` metadata describing the component, such as a file path, variable GUID, or `WBCL` `EV_EVENT_TAG` TLV payload [129].

Across the firmware-to-OS transition, UEFI callers invoke `EFI_TCG2_PROTOCOL.HashLogExtendEvent` to hash data, append a `TCG_PCR_EVENT2` record, and extend the TPM atomically [132]. Measurements occurring after `GetEventLog` and prior to `ExitBootServices()` are captured in the UEFI `EFI_TCG2_FINAL_EVENTS_TABLE` ACPI/EFI configuration table. `winload.efi` then appends its `WBCL` records (`PCR[11..14]`), emits OS `EV_SEPARATOR` markers, and passes the unified buffer to `ntoskrnl.exe`. At runtime, `Tbs.sys` archives binary logs per boot under `C:\Windows\Logs\MeasuredBoot\` and serves the active transcript via the Win32 `Tbsi_Get_TCG_Log` and `Tbsi_Get_TCG_Log_Ex` APIs [129, 133].

### BitLocker Sealing Profiles (`0x880` vs. Legacy Fallbacks)

BitLocker converts Measured Boot PCRs into local data-at-rest enforcement without needing a network verifier [53, 67]. When BitLocker initializes on an OS volume, it seals the Volume Master Key (`VMK`) to the TPM Storage Root Key under a `TPM2_PolicyPCR` digest computed over a selected Platform Validation Profile.

![Figure: BitLocker seal vs unseal. At seal time TPM2_PolicyPCR derives the sealed VMK policy from the selected PCRs; every boot rebuilds the policy session and TPM2_Unseal releases the VMK only when the live PCR digest matches the sealed policy, otherwise the 48-digit recovery path. The default UEFI profile 0x880 binds PCR[7] and PCR[11].](diagrams/03-measured-boot-seal-unseal.svg)

When Windows detects active UEFI Secure Boot with compliant `EV_EFI_VARIABLE_AUTHORITY` support, BitLocker selects the default native UEFI profile binding the `VMK` exclusively to `PCR[7]` (Secure Boot policy and authority) and `PCR[11]` (BitLocker access control), represented by bitmask `0x0880` [67, 134]. Because `PCR[0..4]` are excluded from that bitmask, routine OEM BIOS updates, Option ROM swaps, and cumulative `bootmgfw.efi` patches do *not* trigger 48-digit BitLocker recovery prompts; only modifications to Secure Boot keys or revocations (`PK`, `KEK`, `db`, `dbx`) or disabling Secure Boot alter `PCR[7]` and block unsealing. Once `bootmgfw.efi` unseals the `VMK` and hands off to `winload.efi`, it extends `PCR[11]` from `0` to a non-zero cap so later code in the same boot cycle cannot call `TPM2_Unseal` again [37]. By contrast, when Secure Boot is disabled or unsupported, BitLocker falls back to code-hash PCRs (`PCR[0, 2, 4, 11]` under bitmask `0x0815` on UEFI without `PCR[7]` binding, or `PCR[0, 2, 4, 8, 9, 10, 11]` on legacy BIOS), where every firmware flash or bootloader update invalidates the seal unless BitLocker is suspended prior to reboot [134].

Administrators customize the UEFI PCR selection via MDM (`BitLocker/SystemDrivesConfigureTPMPCRProfile`) or Group Policy (*Configure TPM platform validation profile for native UEFI firmware configurations*, stored as per-PCR `REG_DWORD` entries under `HKLM\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI`). Modifying Group Policy alone does not update an existing TPM blob; BitLocker must re-seal its TPM protector (`manage-bde -protectors`) to bind the new `policyDigest` [134, 135].

### Dynamic Root of Trust for Measurement (DRTM) and System Guard Secure Launch

While `PCR[7]` + `PCR[11]` suffices for local BitLocker sealing, remote enterprise attestation confronts a combinatorial wall under SRTM: thousands of OEMs, motherboard models, UEFI versions, and peripheral Option ROMs produce millions of legitimate `PCR[0..6]` digests, making strict fleet-wide SRTM allowlists operationally unmanageable and vulnerable to DXE/SMM bugs early in boot [130].

Introduced in Windows 10 version 1809 and central to Microsoft's Secured-core PC baseline, System Guard Secure Launch solves SRTM allowlist explosion using hardware Dynamic Root of Trust for Measurement (`DRTM`) [128, 130, 136]:

![Figure: Two measurement planes: SRTM fills PCR[0–7, 11–14] from reset as a large, OEM-diverse anchor; at late launch winload's Secure Kernel Loader issues SENTER/SKINIT, the CPU resets PCR[17–22] and re-roots into the ACM/SLB (PCR[17]) and the MLE (PCR[18]), a smaller and less OEM-diverse anchor.](diagrams/03-measured-boot-srtm-vs-drtm.svg)

1. **Untrusted Early Boot:** Platform firmware executes normal UEFI PI and SRTM (`PCR[0..7]`) to load `bootmgfw.efi` and `winload.efi`.
2. **Atomic CPU Late Launch (Locality 4):** Inside `winload.efi`, the Secure Kernel Loader (`SKL`) prepares DMA protections and executes `GETSEC[SENTER]` (Intel `TXT`) or `SKINIT` (AMD `SVM`), halting application processors, masking interrupts, asserting hardware TPM Locality 4, and resetting `PCR[17..22]` from `0xFF...FF` to `0x00...00` [12, 128].
3. **Anchor and `MLE` Extension:** Intel microcode authenticates the vendor-signed `SINIT ACM` and Launch Control Policy into `PCR[17]` (while AMD `SKINIT` hashes the `SLB` into `PCR[17]`), then measures and enters the Measured Launch Environment (`MLE`), extending Hyper-V, the Secure Kernel (`PCR[18]`), and launch configuration (`PCR[19..20]`) [12, 128, 130].
4. **SMM Containment Activation:** The launch engages an Intel SMI Transfer Monitor (`STM`) or AMD/Microsoft SMM Supervisor to confine Ring -2 System Management Interrupts (`SMIs`) beneath hypervisor page-table oversight [128, 136, 137].

That fourth step closes a critical architectural loophole: because `SMIs` operate outside normal OS page tables, unconstrained firmware handlers could otherwise read or patch VTL1 or kernel memory immediately after `SENTER` or `SKINIT` completes [137]. Furthermore, because `PCR[17..22]` depend solely on CPU-vendor launch modules and Microsoft's hypervisor and Secure Kernel binaries rather than OEM UEFI drivers, a remote verifier can validate `PCR[17..22]` against a compact, vendor-universal allowlist while retaining `PCR[0..14]` alongside it for forensic visibility [130].

## Attack Catalog & Gap Analysis

Measured Boot failures never invert SHA-256; instead, attackers exploit the semantic gap between *signer-authority PCRs* (`PCR[7]`) and *code-version safety*, tamper with unconstrained hardware modes (`SMM`), omit specification-mandated firmware events, relay challenges to external TPMs, or spoof unsigned event logs against naive verifiers.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Cuckoo Relay Attack (Parno) | 2008 | Binding of PCR measurements to the physical target chassis | Malware execution on target; network relay to attacker-owned TPM | Proxies verifier's `TPM2_Quote` nonce from compromised unmeasured host to an attacker-controlled clean TPM and returns valid signed quote | Enroll and pin hardware `EK` certificate to device identity out-of-band (Autopilot / WHfB) ([Chapter 5](04-attestation.md)) [138, 139] |
| TXT SMM Bypass (Rutkowska & Wojtczuk) | 2009 | Post-`GETSEC[SENTER]` DRTM Measured Launch Environment integrity | Pre-launch compromise of motherboard System Management RAM (`SMRAM`) | Triggers SMI after `SENTER` completes; unconstrained Ring -2 SMM handler overwrites measured hypervisor/MLE in RAM without altering `PCR[17..18]` | Enforce SMM sandboxing via Intel STM or Secured-core SMM Supervisor + IOMMU [128, 136, 137] |
| Bitpixie (CVE-2023-21563) | 2022-2024 | TPM-only BitLocker (`0x880` `PCR[7,11]` seal) confidentiality | Physical LAN + keyboard access; unrevoked 2011-signed `bootmgfw.efi` | Boots downgraded signed `bootmgfw.efi` via BCD/PXE matching `PCR[7]` + `PCR[11]`; triggers PXE soft reboot without platform reset and dumps `-FVE-FS-` VMK from RAM | Require `TPMAndPIN`; apply KB5025885 `dbx` revocations (accepting planned `PCR[7]` reseal) [36, 37, 38, 140, 141] |
| Unmeasured UEFI Debugger (`EV_EFI_ACTION` gap) | 2023 | `PCR[7]` completeness over firmware debug interfaces | Retail UEFI firmware exposing pre-OS hardware/USB debug without PFP compliance | Attaches firmware debugger to modify boot memory while firmware omits mandatory `EV_EFI_ACTION` extension into `PCR[7]`, allowing `0x880` VMK unseal | OEM firmware patches enforcing TCG PFP §6.4 `EV_EFI_ACTION` extension; enable `TPMAndPIN` [131] |
| Unsigned WBCL Log Spoofing | Architectural | Authenticity of `TCG_PCR_EVENT2` component descriptions | Compromised pre-OS stage or ring-0 `Tbs.sys` log interception | Extends true malicious digest into hardware PCRs (or alters RAM buffer) while writing benign module names into unsigned `WBCL` for naive auditors | Always recompute PCR digests from `WBCL` entries and verify exact match against `AK`-signed `TPM2_Quote` ([Chapter 5](04-attestation.md)) [129] |

### Policy-Replay Downgrades and the Break-Fix Loop: Bitpixie (CVE-2023-21563)

Discovered by `Rairii` in August 2022 and demonstrated publicly at 38C3 by Thomas Lambertz (Neodyme) alongside SySS research in 2024 [36, 37, 141, 142], *Bitpixie* (`CVE-2023-21563`) is the canonical exploitation of Windows' default `0x880` (`PCR[7]` + `PCR[11]`) TPM-only BitLocker profile.

![Figure: The bitpixie (CVE-2023-21563) VMK-leak flow. A normal unseal leaves the VMK in RAM; the attacker downgrades to an older but still-signed boot manager whose default-profile PCR[7] and PCR[11] still satisfy the seal, triggers a PXE soft reboot that returns control without a platform reset (RAM uncleared, no fresh BitLocker policy challenge), then PXE-boots Linux and scavenges the -FVE-FS- marker from memory.](diagrams/03-measured-boot-bitpixie-leak.svg)

An attacker with physical Ethernet and keyboard access stages a network boot server supplying a modified BCD and an older, pre-November-2022 `bootmgfw.efi` validly signed by `Microsoft Windows Production PCA 2011`. Because `PCR[4]` (which changes when `bootmgfw.efi` is swapped) is excluded from the default `0x880` UEFI profile, and because the downgraded binary chains to the exact same `db` authority with Secure Boot enabled, live `PCR[7]` and `PCR[11]` values match the victim's seal-time `policyDigest` bit for bit [37]. The TPM therefore executes `TPM2_Unseal` normally and places the plaintext `VMK` into DRAM.

Before `winload.efi` can cap `PCR[11]` or scrub transient boot buffers, the modified BCD triggers a legacy PXE *soft reboot* inside the vulnerable `bootmgfw.efi` [36, 37]. Execution transfers over PXE to a signed Linux `shim` and kernel image without issuing a hardware platform reset, leaving physical DRAM contents intact. Once booted, the Linux environment scans physical RAM for the BitLocker Full Volume Encryption pool tag (`-FVE-FS-`), extracts the raw `VMK` in seconds, and mounts the encrypted NTFS volume [36, 37].

Closing Bitpixie exposed a painful operational feedback loop across enterprise fleets [140]: revoking vulnerable boot managers requires updating `dbx` (KB5025885), which alters `EV_EFI_VARIABLE_DRIVER_CONFIG` for `dbx`, which changes `PCR[7]`, which immediately triggers 48-digit BitLocker recovery prompts on every `0x880`-sealed machine whose protection was not suspended across the update.

### Subverting DRTM From Ring -2 and PCIe DMA: SMM, WSMT, and Secured-core PC

When Intel introduced `GETSEC[SENTER]` in 2007, early DRTM threat models assumed resetting `PCR[17..22]` at Locality 4 bypassed all motherboard firmware bugs. At Black Hat DC 2009, Joanna Rutkowska and Rafal Wojtczuk proved otherwise [137]: if an attacker compromised BIOS/SMM prior to `SENTER`, `SMRAM` remained active across the late launch. Triggering a System Management Interrupt (`SMI`) immediately after `SENTER` measured a clean `MLE` into `PCR[18]` allowed Ring -2 SMM code to overwrite the running hypervisor in DRAM while `PCR[17..18]` continued reporting a pristine digest.

Similarly, PCIe, Thunderbolt, and M.2 bus-mastering peripherals (`PCILeech` FPGA interposers [887]) can issue Direct Memory Access (`DMA`) reads and writes straight to physical DRAM without consulting CPU page tables or extending any `PCR`. To close both side doors beneath the OS, Microsoft's Secured-core PC specification pairs System Guard Secure Launch (`DRTM`) with mandatory SMM isolation and IOMMU DMA remapping [889]. Firmware publishes the ACPI Windows SMM Security Mitigations Table (`WSMT`) certifying that `SMM` communication buffers are validated against arbitrary guest physical memory pointers (`FIXED_COMM_BUFFERS` and `COMM_BUFFER_NESTED_PTR_PROTECTION`), while `SMM Supervisor` or `Intel STM` confines Ring -2 handlers inside page-table sandboxes isolated from `VTL1` memory [128, 136, 888]. Simultaneously, firmware enables `Intel VT-d` or `AMD-Vi` `IOMMU` remapping (`Kernel DMA Protection`) from early UEFI handoff through OS runtime, blocking external PCIe, Thunderbolt, and USB4 devices from reading `BitLocker` keys or `VBS` pages unless explicitly mapped per buffer by an authorized driver [111, 887, 889].

### Missing Firmware Measurements and Cuckoo/Log Forgery

Two specification-boundary gaps affect audit and remote verification pipelines. First, forensic research cataloged retail UEFI implementations that exposed pre-boot debugging capabilities without extending the TCG-mandated `EV_EFI_ACTION` debugger event into `PCR[7]`, blinding `0x880` policies to hardware debug attachment [131]. Second, both the Cuckoo relay attack (Bryan Parno, 2008 [138], where malware on an unmeasured host forwards nonce challenges to an external clean TPM) and unsigned WBCL spoofing exploit verifiers that fail to validate cryptographic bindings end to end: `WBCL` binary logs in `C:\Windows\Logs\MeasuredBoot` are unauthenticated byte streams until replayed hash-by-hash against a `TPM2_Quote` signed by an `EK`-bound `AK` ([Chapter 5](04-attestation.md)) [129, 138].

## Theoretical Limits & Structural Invariants

### Axiomatic Trust in the Initial Measurer

Inductive hash chains prove every transition $k \to k+1$ for $k \ge 0$, yet stage $0$ (`CRTM` for SRTM, or CPU microcode + `SINIT ACM`/`SLB` for DRTM) measures itself axiomatically [12, 126]. If SPI flash lacks hardware Boot Guard/PSB enforcement ([Chapter 1](16-secure-boot.md)) or the TPM itself is extracted via voltage fault injection ([Chapter 2](01-tpm.md)), a subverted stage $0$ can extend the expected hash of a benign binary into `PCR[0]` while executing malicious code in RAM. Measurement records history faithfully only down to the hardware root that initiates it.

### Decoupling Measurement Equality from Policy Safety ("A Hash Is Not a Good Hash")

Across every layer of the trust chain, a PCR digest encodes cryptographic identity or state equality, never software safety.

> **Key idea.**
> Measured Boot is reporting infrastructure, not policy infrastructure. During `TPM2_Unseal`, the TPM verifies only whether current PCRs equal the `policyDigest` recorded when the secret was sealed. If a secret is sealed exclusively to *authority* registers (`PCR[7]`) rather than *code* registers (`PCR[4]`), any vulnerable historical binary signed by that authority satisfies the seal; even if sealed to `PCR[4]`, sealing on an already-vulnerable build preserves access for that build forever. Deciding whether a measured hash is *acceptable today* requires an external, continuously updated appraisal policy ([Chapter 5](04-attestation.md)).

### The Availability-vs.-Granularity Trade-Off in Sealing

Every local sealing architecture faces an irreducible tension between downgrade surface and fleet availability. Coarse authority sealing (`PCR[7]` + `PCR[11]`) survives routine UEFI capsule updates and monthly OS patches without user disruption, yet trusts every unrevoked binary signed by enrolled `db` CAs and therefore requires `TPMAndPIN` (`TPM2_PolicyAuthValue`) to defend unattended physical machines against `Bitpixie`-class downgrades [36, 67]. Conversely, fine code-hash sealing (`PCR[0, 2, 4, 7, 11]`) rejects bootloader downgrades immediately because swapping `bootmgfw.efi` alters `PCR[4]`, at the operational cost of converting every un-suspended BIOS update, Option ROM change, or cumulative bootloader patch into a 48-digit recovery lockout [134].

## Inspecting and Verifying on a Running System

Operational verification covers collecting raw SRTM/DRTM event logs, auditing active BitLocker PCR validation profiles and protectors, and confirming System Guard Secure Launch (`DRTM`) execution.

### Collecting SRTM and DRTM Measured Boot Logs (`WBCL`)

Archive the binary `TCG_PCR_EVENT2` logs archived by `Tbs.sys` using `tpmtool` or enumerate per-boot `.log` files directly (elevated PowerShell) [129, 133]:

```powershell
New-Item -ItemType Directory -Path 'C:\Temp\TpmLogs' -Force | Out-Null
tpmtool gatherlogs 'C:\Temp\TpmLogs'
Get-ChildItem 'C:\Windows\Logs\MeasuredBoot\*.log' | Sort-Object LastWriteTime | Select-Object -Last 3 Name, Length
```

Expected output format:

```text
Name                        Length
----                        ------
0000000041-0000000000.log    84216
0000000042-0000000000.log    84392
0000000042-0000000001.log    19408
```

`tpmtool gatherlogs` writes `SRTMBoot.dat` (and `DRTMBoot.dat` when Secure Launch is active) alongside decoded XML/text summaries; in `C:\Windows\Logs\MeasuredBoot\`, the prefix tracks the boot count and `-0000000000.log` vs. `-0000000001.log` tracks initial boot vs. hibernate/DRTM sequences [129, 133].

### Auditing BitLocker Protectors and UEFI PCR Validation Policy

Inspect active volume protectors via `manage-bde` and check whether Group Policy overrides the default `PCR[7, 11]` (`0x880`) native UEFI validation profile [67, 134, 135]:

```powershell
manage-bde -protectors -get C:
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\FVE\OSPlatformValidation_UEFI' -ErrorAction SilentlyContinue
```

Expected `manage-bde` output excerpt on a `TPMAndPIN` UEFI machine:

```text
    TPM And PIN:
      ID: {B4E19C20-...}
      PCR Validation Profile:
        7, 11 (Uses Secure Boot for integrity validation)
```

If `PCR Validation Profile` displays `0, 2, 4, 11`, the volume is sealed without Secure Boot `PCR[7]` authority binding and will enter BitLocker recovery on firmware updates unless suspended (`Suspend-BitLocker -MountPoint 'C:' -RebootCount 1`) and re-sealed after enabling UEFI Secure Boot [67, 134].

### Verifying System Guard Secure Launch (DRTM) Runtime Status

Query the `Win32_DeviceGuard` WMI/CIM class to verify whether DRTM (`System Guard Secure Launch`, service ID `3`) is both configured and actively running on the current boot [128]:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object SecurityServicesConfigured, SecurityServicesRunning
```

Expected output when Credential Guard (`1`), HVCI (`2`), and System Guard Secure Launch (`3`) are active:

```text
SecurityServicesConfigured SecurityServicesRunning
-------------------------- -----------------------
{1, 2, 3}                  {1, 2, 3}
```

Presence of `3` in `SecurityServicesRunning` confirms `winload.efi` executed `GETSEC[SENTER]` or `SKINIT` on this boot, resetting and populating `PCR[17..22]` under SMM protection [128].

## Summary & Handoff

Measured Boot complements Secure Boot's load-time signature gate with an indelible, hash-chained history of platform initialization. By recording firmware and policy state into `PCR[0..7]`, isolating BitLocker access control in `PCR[11]` from Windows loader transcripts in `PCR[12..14]`, and collapsing OEM firmware variance via Locality-4 CPU late launch (`PCR[17..22]` under System Guard Secure Launch), Windows turns platform startup into deterministic cryptographic state. Yet measurement alone is purely local reporting: unsigned `WBCL` logs can be spoofed in RAM, and `TPM2_Unseal` validates only static profile equality rather than vulnerability status (`Bitpixie`).

Turning local PCRs and `WBCL` transcripts into off-box trust and runtime isolation requires two subsequent architectural links. Binding `Attestation Keys` to hardware `Endorsement Keys`, signing nonce-fresh `TPM2_Quote` structures, replaying `WBCL` logs on cloud verifiers, and issuing Conditional Access health claims belong to [Attestation (Chapter 5)](04-attestation.md), while enforcing the VTL1 execution boundary launched inside the `PCR[18]` Measured Launch Environment to protect kernel code integrity and credentials at runtime is owned by [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md).
