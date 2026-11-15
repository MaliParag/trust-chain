# The TPM

## Overview

* **Role in the Chain:** Hardware root of trust for storage and reporting; provides isolated cryptographic key residence, append-only Platform Configuration Registers (PCRs), policy-gated secret sealing, and signed state quotes beneath the operating system.
* **Core Security Invariant:** Private keys generated or imported with non-exportable attributes (`fixedTPM`, `fixedParent`) never leave the TPM boundary in plaintext, and sealed data objects (`TPM2_Unseal`) are released if and only if live PCR digests and authorization session predicates satisfy the object's immutable `policyDigest`.
* **Trusted Computing Base (TCB):** The discrete TPM silicon or firmware-TPM execution environment (Intel CSME or AMD ASP/PSP), the Core Root of Trust for Measurement (CRTM) supplying initial measurements, internal primary seeds and NVRAM lockout counters, and the silicon vendor's Endorsement Key (EK) certificate authority.
* **Primary Failure Modes:** Passive logic-analyzer interception of unencrypted secrets on discrete LPC/SPI buses at release (Andzakovic, WithSecure, SCRT), microarchitectural or execution-time side channels leaking ECDSA keys (TPM-Fail), physical voltage fault injection dumping internal firmware-TPM state (faulTPM), and flawed vendor key-generation firmware (ROCA).
* **Handoff:** Supplies four foundational primitives (`Measure`, `Extend`, `Seal`, `Quote`) and hardware-bound key handles to higher layers; leaves on-die bus elimination and OS-delivered firmware servicing to [Pluton (Chapter 3)](02-pluton.md), boot-log assembly to [Measured Boot (Chapter 4)](03-measured-boot.md), remote verification to [Attestation (Chapter 5)](04-attestation.md), and post-unseal memory isolation to [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md).

## Core Engineering Problem & Threat Model

Software-only secret storage fails under two routine adversarial conditions: offline disk extraction and ring-0 kernel compromise. Early Windows cryptographic subsystems, including NT 4.0 LSA secrets [46] and Windows 2000 Data Protection API (DPAPI) and Encrypting File System (EFS) keys [47, 48], wrapped user and machine secrets using keys derived from logon credentials or local system material. Regardless of key-derivation depth, the unwrapping key ultimately resided in operating-system memory or on the same nonvolatile volume as the ciphertext. An attacker who obtained `SYSTEM` privileges dumped the keys from kernel or LSASS memory; an attacker who stole a powered-off laptop imaged the drive and attacked the wrapping hierarchy offline without hardware rate limiting.

To sever secret storage from operating-system memory, industry vendors formed the Trusted Computing Platform Alliance in 1999 (reorganized as the Trusted Computing Group, or TCG) and shipped TPM 1.1b and TPM 1.2 across commercial PCs between 2003 and 2014 [49, 50, 51]. Paired with Windows Vista BitLocker in 2007 [52, 53], TPM 1.2 established non-exportable RSA-2048 keys and PCR-sealed volume keys, yet hard-coded SHA-1 and RSA-2048 directly into command structures and register widths [51]. Once NIST deprecated SHA-1 signatures in 2011 [54] and practical SHA-1 collisions materialized in 2017 [55], TPM 1.2 could not adopt stronger hashes without breaking its wire specification, while its single Storage Root Key (SRK) coupled administrative storage resets to device identity. TCG replaced the architecture in April 2014 with the algorithm-agile TPM 2.0 Library Specification (standardized as ISO/IEC 11889:2015) [56, 57, 58]. Microsoft mandated TPM 2.0 enabled by default for Windows OEM hardware certification in July 2016 [59] and enforced it as an operating-system installation baseline with Windows 11 in 2021 [60, 61].

The TPM threat model assumes an adversary who may possess physical access to a powered-off or booting chassis, administrative or kernel-level code execution inside the host operating system, or network reachability to services relying on TPM-backed keys. Against this adversary, the TPM must prevent offline bulk guessing via hardware anti-hammering, refuse key export even when `ntoskrnl.exe` is fully compromised, and withhold boot-sealed secrets whenever pre-OS code deviates from expected measurements [62]. Conversely, the TPM is explicitly a *passive* slave device: it neither monitors host DRAM nor verifies whether the operating system requesting an operation has been subverted after boot.

## Architectural Deep Dive

### Algorithm Agility and Multi-Bank PCRs

TPM 2.0 decouples protocol data structures from fixed cryptographic primitives by tagging every digest, key object, and signature scheme with a normative `TPM_ALG_ID` identifier [57]. Rather than exposing a single fixed-width register file, TPM 2.0 organizes Platform Configuration Registers into parallel *PCR banks*, one bank per active hash algorithm. Per the TCG PC Client Platform TPM Profile (PTP), compliant implementations expose 24 registers (`PCR[0..23]`) per bank and support at minimum SHA-256 alongside legacy SHA-1 (with newer silicon adding SHA-384 and SHA-512 banks) [62, 63].

Software cannot write arbitrary values into a PCR. Host code modifies a register exclusively through `TPM2_PCR_Extend`, which folds an incoming digest $m$ into the existing register state for each selected bank hash $H$:

$$\mathrm{PCR}[i]_{\text{new}} = H\bigl(\mathrm{PCR}[i]_{\text{old}} \,\Vert\, m\bigr)$$

Because cryptographic hash functions resist preimage and second-preimage attacks, the final register value commits uniquely to the exact sequence of digests extended since reset [37, 57]. Under the PC Client profile, the 24 registers divide into three bands governed by hardware reset and locality semantics [12, 63]. Static Root of Trust registers (`PCR[0..15]`) initialize to zero only at platform power-on or cold reset and cannot be reset during runtime; firmware and boot loaders extend `PCR[0..7]` across UEFI initialization and Secure Boot handoff, while operating-system components extend `PCR[8..15]`, including `PCR[11]` for BitLocker access control. Dynamic Root of Trust registers (`PCR[17..22]`) initialize to all ones (`0xFF...FF`) at power-on and reset to zero *only* via hardware-asserted TPM Locality 4 during an atomic CPU late-launch instruction (`GETSEC[SENTER]` on Intel TXT or `SKINIT` on AMD), as examined in [Chapter 4](03-measured-boot.md) [12]. Finally, `PCR[16]` and `PCR[23]` serve as software-resettable debug and application registers for testing and user-space instrumentation, and are never used to seal production OS secrets.

### Four Hierarchies, Primary Seeds, and Key Provenance

TPM 1.x anchored all protected storage beneath a single Storage Root Key (`SRK`) created during ownership provisioning, while relying on an external Privacy CA to certify an Attestation Identity Key (`AIK`) against the permanent Endorsement Key (`EK`) [51]. Clearing the `SRK` destroyed every child key simultaneously.

![Figure: TPM 1.x key hierarchy. A single Storage Root Key roots every child key, while the Attestation Identity Key is an independent RSA signing key whose binding to the chip is certified by a Privacy CA over the EK.](diagrams/01-tpm-1x-hierarchy.svg)

TPM 2.0 replaces that single-root tree with four isolated hierarchies, separating platform firmware control, hardware identity, OS storage, and ephemeral sessions [57, 64]. The Platform Hierarchy (`TPM_RH_PLATFORM`) is governed by early platform firmware via `platformAuth` and `platformPolicy` and rooted in the Platform Primary Seed (`PPS`), which persists across operating-system reinstallations unless regenerated by UEFI firmware. Alongside it, the Endorsement Hierarchy (`TPM_RH_ENDORSEMENT`) is seeded at silicon manufacture by the immutable Endorsement Primary Seed (`EPS`), rooting the device's Endorsement Key (`EK`) and its vendor-signed X.509 EK certificate chaining to the TPM manufacturer's root CA [64, 65]. Day-to-day OS secrets live instead under the Storage Hierarchy (`TPM_RH_OWNER`), controlled by `ownerAuth` and rooted in the Storage Primary Seed (`SPS`); executing `TPM2_Clear` regenerates the `SPS` to destroy all OS-created storage keys in one atomic operation while leaving the `EPS` and `EK` hardware identity untouched [64]. Finally, the Null Hierarchy (`TPM_RH_NULL`) derives from an ephemeral seed regenerated on every TPM reset, binding transient session keys and non-persistent objects guaranteed to vanish on power loss.

![Figure: TPM 2.0's four hierarchies (Platform, Endorsement, Storage, and Null) each rooted in its own primary seed, with primary keys deterministically re-derived via TPM2_CreatePrimary.](diagrams/01-tpm-2x-hierarchies.svg)

Because internal TPM NVRAM is small (typically 16 to 64 KB), ordinary child keys (such as Windows Hello user keys or BitLocker protectors) do not consume persistent on-chip NVRAM slots. Instead, `TPM2_CreatePrimary` deterministically derives a Storage Root Key from the `SPS` and a canonical public template; child keys are generated inside the TPM (`TPM2_Create`) with attributes such as `fixedTPM | fixedParent | sensitiveDataOrigin`, symmetrically encrypted and integrity-protected under their parent key, and returned to Windows as opaque wrapped blobs stored on the NTFS file system. When Windows needs a signature or decryption, the TPM Base Services (`TBS`) daemon loads the wrapped blob into volatile TPM RAM via `TPM2_Load`, executes `TPM2_Sign` or `TPM2_Unseal` inside the boundary, and flushes the transient handle [62, 64].

For remote reporting, the `EK` is restricted from signing arbitrary data directly (preventing cross-service hardware tracking). Instead, Windows generates a restricted signing Attestation Key (`AK`, historically `AIK`) and binds it to the genuine `EK` via `TPM2_MakeCredential` and `TPM2_ActivateCredential` [64, 65]. Because `TPM2_ActivateCredential` requires decrypting a challenge under the `EK` and verifying that the target `AK` resides inside the *same* TPM (`fixedTPM`), a verifier gains cryptographic proof that quotes signed by the `AK` originate from authentic TPM silicon without exposing the `EK` as a global signing identifier ([Chapter 5](04-attestation.md)).

### Enhanced Authorization (EA) and Dictionary-Attack Protection

TPM 2.0 governs object usage through Enhanced Authorization (`EA`) policy sessions [57, 64]. Every TPM object carries an immutable 32-byte (for SHA-256) `policyDigest` in its public area, computed at creation time by chaining required authorization commands. To exercise the object later, the host opens a policy session (`TPM2_StartAuthSession` with `TPM_SE_POLICY`) whose running `sessionDigest` begins at zero and advances through composable policy assertion commands. Calling `TPM2_PolicyPCR` folds the live digests of a caller-specified PCR selection bitmask into `sessionDigest`; if any selected PCR differs by even a single bit from the state expected at seal time, `sessionDigest` diverges from `policyDigest` and `TPM2_Unseal` aborts with `TPM_RC_POLICY_FAIL`. Interactive or pre-boot secrets bind into the same hash chain via `TPM2_PolicyAuthValue` and `TPM2_PolicySecret`, which require proof of knowledge of a PIN, password, or object `authValue`. To avoid brittle resealing across legitimate software updates, `TPM2_PolicyAuthorize` and `TPM2_PolicySigned` allow an external signing authority to approve updated PCR policies dynamically, while `TPM2_PolicyCommandCode` and `TPM2_PolicyLocality` restrict *which* specific TPM command or *which* hardware locality (such as Locality 4 versus Locality 0) may invoke the key [57, 64].

When an object incorporates a user PIN or password (`userWithAuth` or `TPM2_PolicyAuthValue` without `noDA`), failed authorization attempts increment a nonvolatile dictionary-attack counter (`LockoutCount`) inside the TPM [57, 66]. Once `LockoutCount` reaches `LockoutMax` (for example, 31 failures under standard Windows provisioning), the TPM enters dictionary-attack lockout and refuses further authorization attempts until `LockoutHealTime` elapses per counter decrement across active power cycles [66].

Optionally, `TPM2_StartAuthSession` supports HMAC-authenticated and CFB-encrypted command/response sessions (*parameter encryption*), encrypting the first sized parameter crossing the physical bus between host CPU and TPM [57, 64]. Whether the host OS actually enables parameter encryption on a given call path determines whether unsealed secrets cross motherboard traces in plaintext.

### Windows Integration and the Four Implementation Classes

Inside Windows, user-mode and kernel-mode callers rarely construct raw `TPM2_*` byte streams directly. `tpm.sys` drives the hardware Tis/FIFO or Command Response Buffer (`CRB`) MMIO interface; TPM Base Services (`TBS`) multiplexes contexts and command queues across processes; and Cryptography API: Next Generation (`CNG`) exposes the `Microsoft Platform Crypto Provider`, letting applications hold standard `NCRYPT_KEY_HANDLE` references backed by non-exportable TPM keys [48, 62]. Through this stack, four core operations (`Measure`, `Extend`, `Seal`, `Quote`) anchor platform security across the operating system. BitLocker Drive Encryption seals the Volume Master Key (`VMK`) under a `TPM2_PolicyPCR` profile, canonically binding `PCR[7]` and `PCR[11]` when UEFI Secure Boot is active and optionally adding `TPM2_PolicyAuthValue` for `TPMAndPIN` ([Chapter 4](03-measured-boot.md)) [53, 67]. Measured Boot and Device Health Attestation extend boot components into PCR banks and sign `TPM2_Quote` structures with an `AK` for remote health evaluation ([Chapter 4](03-measured-boot.md), [Chapter 5](04-attestation.md)) [68], while Credential Guard and VBS protect VTL1 isolated secret-sealing keys against offline disk extraction ([Chapter 6](05-secure-kernel.md), [Chapter 12](08-credential-guard.md)) [69]. At the identity layer, Windows Hello for Business, DPAPI-NG, and Virtual Smart Cards store per-user asymmetric credentials, enterprise certificate keys verified via TPM key attestation, and domain protection keys behind hardware anti-hammering ([Chapter 17](12-hello.md)) [65, 70, 71].

Hardware vendors deliver this identical TCG 2.0 command surface across distinct physical realizations whose physical and microarchitectural attack surfaces differ sharply [62, 72, 73, 74]:

| Dimension | Discrete TPM (dTPM) | Firmware TPM: Intel PTT | Firmware TPM: AMD fTPM | Virtual TPM (vTPM) |
|---|---|---|---|---|
| Execution Boundary | Dedicated external microcontroller (Infineon, STMicro, Nuvoton) | Firmware applet inside Intel CSME (PCH or SoC die) [72] | Firmware applet inside AMD ASP/PSP (ARM core on SoC) [73] | Host hypervisor process / isolated memory [74] |
| Host Interconnect | External PCB traces (LPC, SPI, or I2C) | Internal on-package/on-die fabric (CRB MMIO) | Internal on-die mailbox / CRB MMIO | Hypervisor VMBus / virtual CRB |
| Shared TCB Surface | Dedicated TPM ROM/flash only | Shared with full Intel Management Engine stack | Shared with AMD PSP boot, SEV, and SMM helpers | Host hypervisor and cloud control plane |
| Servicing Channel | Vendor TPM firmware updater / OEM capsule | OEM UEFI BIOS capsule | OEM UEFI BIOS capsule | Cloud host / hypervisor servicing |
| Dominant Exposure | Passive LPC/SPI bus sniffing of plaintext `Unseal` [75, 76] | Shared-TEE timing side channels (TPM-Fail) [77] | PSP voltage fault injection (faulTPM) [78] | Host hypervisor compromise ([Chapter 22](29-confidential-vms.md)) |

*(A fifth realization, Microsoft Pluton, integrates a dedicated security processor block directly onto the CPU die with Windows-Update-delivered firmware; [Chapter 3](02-pluton.md) analyzes Pluton's architecture and trade-offs in full [79, 80].)*

## Attack Catalog & Gap Analysis

Attacks against deployed Windows TPMs have never broken SHA-256 or correctly generated RSA-2048/ECDSA keys mathematically. Instead, adversaries have exploited flawed vendor prime generation, unencrypted motherboard buses during `TPM2_Unseal`, shared-coprocessor timing leaks, and physical voltage glitching.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| ROCA (CVE-2017-15361) | 2017 | Non-recoverability of on-chip RSA private keys | Public RSA key (`EK` or child key) from affected Infineon firmware | Exploits structured prime generation in Infineon RSALib (`1.02.013`) to factor RSA-2048 keys via Coppersmith's method | Apply Infineon TPM firmware update (`ADV170012`) and regenerate all TPM-resident RSA keys [81, 82, 83] |
| LPC Bus Sniffing (`lpc_sniffer_tpm`) | 2019-2024 | Confidentiality of VMK crossing discrete TPM bus | Chassis physical access; TPM-only BitLocker; LPC dTPM | Taps 33 MHz `LAD[0..3]`/`LCLK`/`LFRAME#` pins with logic analyzer or $40 FPGA to read plaintext `TPM2_Unseal` response | Enforce pre-boot PIN (`TPMAndPIN`) or migrate to on-die TPM without external bus [67, 75, 84, 85, 86] |
| TPM-Fail (CVE-2019-11090 / CVE-2019-16863) | 2019 | Constant-time isolation of ECDSA signing keys | Local execution (or fast network timing oracle) | Measures secret-dependent ECDSA scalar-multiplication timing variations in Intel PTT and STMicro ST33 to recover private keys via lattice reduction | Apply Intel CSME and STMicro TPM firmware updates enforcing constant-time scalar math [77, 87, 88, 89] |
| SPI Bus Sniffing | 2020-2024 | Confidentiality of VMK crossing SPI discrete TPM | Chassis physical access; TPM-only BitLocker; SPI dTPM | Probes `MOSI`/`MISO`/`CLK`/`CS#` lines on M.2/motherboard SPI traces during boot to capture unencrypted BitLocker VMK bytes | Enforce pre-boot PIN (`TPMAndPIN`) or startup key; eliminate external discrete bus [67, 76] |
| faulTPM (CVE-2023-20592) | 2023 | Complete internal state and seed isolation on AMD fTPM | Physical motherboard access (~2-3 hours) to AMD SVI2/voltage rail | Injects timed voltage glitches into AMD PSP during fTPM NVRAM/seed operations to exfiltrate primary seeds, sealed blobs, and lockout state | Apply AMD AGESA/PSP firmware mitigations; treat low-entropy PINs as offline-crackable post-extraction [78, 90] |

![Figure: Three generations of TPM attack, 2019–2024. LPC/SPI bus sniffing, the TPM-Fail timing side channel, and the faulTPM voltage glitch; each generation invalidates the reassurance the previous one reached for.](diagrams/01-tpm-attack-timeline.svg)

### Vendor Cryptographic Firmware Flaws: ROCA (CVE-2017-15361)

A hardware boundary is only as sound as the closed-source cryptographic library burned into its ROM. In October 2017, researchers at Masaryk University disclosed *Return of Coppersmith's Attack* (ROCA, CVE-2017-15361) affecting Infineon's `RSALib` across millions of discrete TPM 1.2 and TPM 2.0 chips [81, 82]. To accelerate prime generation on slow microcontrollers, Infineon constructed primes of the form $p = k \cdot M + (65537^a \bmod M)$ for a fixed primorial $M$. That algebraic structure drastically shrank entropy and enabled practical factorization of RSA-1024 and RSA-2048 keys from the public modulus alone [81]. Because non-exportability prevents defenders from inspecting private keys, remediation under Microsoft Security Advisory `ADV170012` required flashing updated Infineon firmware via OEM capsules, clearing the TPM, and re-creating every affected BitLocker, Windows Hello, and virtual smart card key [83].

### Plaintext Release Over External Buses: LPC and SPI Sniffing

In March 2019, Denis Andzakovic demonstrated that TPM-only BitLocker on discrete TPM 1.2 and TPM 2.0 laptops could be defeated non-destructively in minutes using a logic analyzer or a low-cost Lattice iCE40 FPGA attached to exposed Low Pin Count (`LPC`) headers (`LCLK`, `LFRAME#`, `LAD[0..3]`) [75, 84]. Subsequent work by WithSecure extended passive capture to Serial Peripheral Interface (`SPI`) discrete TPMs [76], and SCRT operationalized rapid pogo-pin extraction across commercial enterprise laptops from major OEMs [85, 86].

The architectural gap lies not inside the TPM silicon, which performed `TPM2_PolicyPCR` verification faithfully, but at the host-to-TPM transport layer. Although the TPM 2.0 specification supports encrypted response sessions (`CFB` parameter encryption), Windows `bootmgfw.efi` does not establish an encrypted bus session when issuing `TPM2_Unseal` during pre-OS boot. Consequently, on TPM-only configurations, the unsealed 256-bit BitLocker VMK crosses motherboard copper traces in cleartext before any user logs on [75, 76]. Adding a pre-boot PIN (`TPMAndPIN`) prevents an attacker with a stolen, powered-off laptop from triggering `TPM2_Unseal` at all [67], though SCRT demonstrated in 2024 that if an adversary can covertly implant a sniffer ("evil maid") and wait for a legitimate user to enter the PIN, parameter-unencrypted bus traffic still exposes secret material in transit [86].

### Shared-TEE Timing Side Channels: TPM-Fail (CVE-2019-11090, CVE-2019-16863)

Moving the TPM off an external PCB bus into chipset firmware (Intel Platform Trust Technology inside CSME) eliminated physical wire sniffing, only to expose microarchitectural and timing channels. In November 2019, Moghimi et al. disclosed *TPM-Fail* (USENIX Security 2020), demonstrating secret-dependent execution latency during ECDSA nonce generation and scalar multiplication in both Intel PTT (`CVE-2019-11090`) and STMicroelectronics' Common Criteria EAL4+ / FIPS 140-2 certified `ST33TPHF2ESPI` discrete TPM (`CVE-2019-16863`) [77, 87, 88, 89].

By collecting ~1,200 to ~40,000 signature timestamps from an unprivileged local process (or across a low-latency network against a TPM-backed IPsec/VPN endpoint), attackers used lattice reduction to reconstruct the full 256-bit ECDSA private key in 4 to 20 minutes locally [77]. TPM-Fail proved two structural lessons: eliminating physical pins does not eliminate software-observable side channels, and formal hardware security certifications (FIPS 140-2 and CC EAL4+) do not guarantee constant-time cryptographic implementations.

### Physical Fault Injection on Shared Coprocessors: faulTPM (CVE-2023-20592)

In April 2023, Jacob et al. published *faulTPM*, targeting AMD's firmware TPM executing inside the on-die AMD Platform Security Processor (`PSP`) [78, 90]. Unlike a dedicated discrete security IC hardened with active voltage meshes, light sensors, and dual-rail logic, the AMD PSP shares SoC power delivery rails regulated over the Serial VID Interface (`SVI2`) bus.

By injecting precisely timed voltage glitches onto the PSP power rail over two to three hours of physical motherboard access, the researchers corrupted memory-copy bounds checks and cryptographic comparisons inside the PSP bootloader and fTPM trusted application [78]. The exploit extracted the *entire internal fTPM state*, including primary hierarchy seeds, NVRAM indices, wrapping keys, and sealed blobs. Crucially, once internal fTPM state is extracted to an attacker's workstation, hardware `LockoutCount` anti-hammering ceases to exist: `TPMAndPIN` protection degrades to offline brute-force cracking of the user's PIN on GPUs, making a 6-digit numeric PIN recoverable in milliseconds [78].

## Theoretical Limits & Structural Invariants

### Storage and Reporting Root vs. Execution Root

A TPM is a Root of Trust for Storage (RTS) and a Root of Trust for Reporting (RTR); it is *never* a Root of Trust for Measurement (RTM) or Execution [57, 64]. Because the TPM sits passively on a command/response register interface, it cannot verify whether the digest passed to `TPM2_PCR_Extend` honestly represents the code about to run. Every static measurement chain depends unconditionally on the initial firmware CRTM measuring itself and the next stage before relinquishing CPU control ([Chapter 4](03-measured-boot.md)). If SPI flash or SMM compromises the CRTM (or if an attacker resets dynamic PCRs only via hardware-enforced CPU late launch), the TPM faithfully extends whatever digest arrives over MMIO.

### The Point-of-Release Boundary

Hardware non-exportability protects keys *used* inside the TPM (`TPM2_Sign`, `TPM2_RSA_Decrypt`), where private material never leaves the boundary. By contrast, *sealed data blobs* (`TPM2_Unseal`, used for symmetric bulk-encryption keys like the BitLocker VMK because a low-throughput TPM cannot AES-XTS-encrypt gigabytes of NVMe I/O inline) must cross into host DRAM to key the OS storage stack.

> **Key idea.**
> For sealed symmetric keys, the TPM's security invariant terminates at the instant of `TPM2_Unseal`. Against offline disk theft and pre-OS boot tampering, PCR sealing withholds the key; against passive bus taps during boot (`TPM`-only) or a runtime-compromised ring-0 kernel after boot, the unsealed key already resides outside the TPM TCB [67]. Protecting secrets *after* release requires hypervisor memory isolation ([Chapter 6](05-secure-kernel.md), [Chapter 12](08-credential-guard.md)).

### Decoupling Key Residence from Resource Authorization

Cryptographic proof that a key resides inside a genuine TPM must never be conflated with authorization to access enterprise resources. In Windows TPM Key Attestation [65] and DPAPI-NG (`NCryptProtectSecret`) [71, 91], the TPM proves a *hardware-residence predicate*: key $K$ is non-exportable inside a chip whose `EK` chains to a trusted silicon manufacturer CA.

Authorization policy lives in a separate plane: Active Directory Certificate Services (ADCS) templates, Entra Conditional Access rules, or DPAPI-NG protection descriptors (`SID`, `SDDL`, `CERTIFICATE`) [65, 91]. If malware compromises a user's session in ring 3, it cannot export the user's TPM-bound key to another workstation, *but* it can instruct `CNG` / `TBS` on the infected host to sign arbitrary challenges or unprotect secrets as that user in place. Furthermore, trusting vendor EK CAs introduces fleet-wide supply-chain coupling: a compromised or mis-issuing TPM manufacturer CA could mint synthetic EK certificates indistinguishable from physical silicon during remote key enrollment [65].

### Cryptographic Agility vs. Hardware Buffer Ceilings

Although TPM 2.0's `TPM_ALG_ID` tagging was explicitly engineered for cryptographic transitions, migrating hardware TPMs to NIST's finalized post-quantum standards (ML-KEM in FIPS 203, ML-DSA in FIPS 204, and SLH-DSA in FIPS 205 [92, 93, 94, 95]) exposes physical silicon ceilings rather than wire-format rigidity. Current TCG PC Client profiles (`TPM_PT_MAX_COMMAND_SIZE`, `TPM_PT_MAX_RESPONSE_SIZE`, and `TPM_PT_NV_BUFFER_MAX`) size internal SRAM command/response buffers around 1 to 4 KB and total NVRAM around tens of kilobytes [63, 96], whereas lattice and hash-based public keys and signatures span several kilobytes to tens of kilobytes. Supporting native post-quantum `EK`s, `AK`s, and `TPM2_Quote` signatures across Windows [97] requires normative TCG PQC profile extensions, command-buffer fragmentation, and firmware or silicon updates, making field-updatable on-die security processors architecturally decisive ([Chapter 3](02-pluton.md)).

## Inspecting and Verifying on a Running System

Administrative inspection on Windows verifies four properties: TPM initialization and lockout health, hardware manufacturer and firmware revision (to assess `ROCA`, `TPM-Fail`, or `faulTPM` patch levels), Endorsement Key certificate provenance, and BitLocker protector configuration.

### Querying TPM Readiness, Manufacturer, and Anti-Hammering State

Inspect the operating system's view of the active TPM via the `TrustedPlatformModule` PowerShell module (elevated) [66]:

```powershell
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmOwned, ManufacturerIdTxt,
    ManufacturerVersion, LockoutCount, LockoutMax, LockoutHealTime
```

Expected output format on a provisioned Windows 11 system:

```text
TpmPresent          : True
TpmReady            : True
TpmOwned            : True
ManufacturerIdTxt   : INTC
ManufacturerVersion : 600.18.0.0
LockoutCount        : 0
LockoutMax          : 31
LockoutHealTime     : 10 minutes
```

`ManufacturerIdTxt` (`IFX` for Infineon, `STM ` for STMicroelectronics, `NTC` for Nuvoton, `INTC` for Intel PTT, `AMD` for AMD fTPM, `MSFT` for Pluton or Hyper-V vTPM) and `ManufacturerVersion` identify the exact realization and firmware revision. Non-zero `LockoutCount` values indicate failed dictionary-attack authorization attempts against TPM-protected PINs or keys [66].

### Verifying TPM 2.0 Specification Level and Functional Readiness

Query TPM Base Services device metadata using the built-in `tpmtool` utility:

```powershell
tpmtool getdeviceinformation
```

Expected output format:

```text
-TPM Present: True
-TPM Version: 2.0
-TPM Specification Version: 1.38
-Ready For Storage: True
-Ready For Attestation: True
```

`Ready For Storage` confirms the Storage Primary Seed (`SPS`) and SRK template are provisioned for CNG/BitLocker; `Ready For Attestation` confirms `EK` and `AK` prerequisites are intact for Measured Boot quotes ([Chapter 5](04-attestation.md)). Note that inside a virtual machine (such as Azure Trusted Launch), `Get-Tpm` and `tpmtool` report `True` against a hypervisor-emulated `vTPM` [74].

### Inspecting Endorsement Key Certificate Provenance

Retrieve the hardware Endorsement Key public digest and manufacturer certificate chain [65]:

```powershell
Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 |
    Select-Object IsPresent, PublicKeyHash, ManufacturerCertificates
```

Expected output format:

```text
IsPresent                : True
PublicKeyHash            : 4a9e8b1c...
ManufacturerCertificates : {[Subject] CN=TPM_EK_Cert... [Issuer] CN=Vendor TPM EK Intermediate CA...}
```

An empty `ManufacturerCertificates` array (common on unprovisioned vTPMs or cleared OEM boards lacking NVRAM EK certs) prevents strict EK-pinned certificate enrollment or hardware attestation until retrieved from the vendor provisioning service.

### Auditing BitLocker TPM Protectors and Servicing Suspension

Verify whether the OS volume relies on `TPM`-only sealing (exposed to passive dTPM bus sniffing) or enforces a pre-boot factor (`TpmPin` / `TpmStartupKey`) [53, 67]:

```powershell
(Get-BitLockerVolume -MountPoint 'C:').KeyProtector |
    Select-Object KeyProtectorType, KeyProtectorId
```

Expected output on a hardened laptop enforcing TPM+PIN with escrowed recovery:

```text
KeyProtectorType  KeyProtectorId
----------------  --------------
TpmPin            {A1B2C3D4-...}
RecoveryPassword  {E5F6A7B8-...}
```

Before applying a UEFI BIOS or TPM firmware update that alters `PCR[0]` or `PCR[7]`, suspend BitLocker protection for one reboot (`Suspend-BitLocker -MountPoint 'C:' -RebootCount 1`) after verifying `RecoveryPassword` escrow in Entra ID or Active Directory so Windows automatically re-binds to the updated PCR state on restart.

## Summary & Handoff

TPM 2.0 provides modern Windows with an algorithm-agile hardware vault: non-exportable asymmetric keys rooted in four separated primary seeds, append-only multi-bank PCRs, composable `policyDigest` authorization predicates, and nonvolatile dictionary-attack lockout. Yet empirical attacks from 2017 through 2024 demonstrate that standardizing the `TPM2_*` command interface does not standardize physical resilience: discrete chips leak unsealed keys across unencrypted LPC/SPI traces, chipset firmware TPMs suffer timing leaks and voltage fault injection across shared coprocessors, and passive silicon cannot defend keys once released into host RAM.

From this hardware foundation, four downstream layers address what a standalone TPM 2.0 chip cannot solve alone. Moving the cryptoprocessor directly onto the CPU die inside a dedicated hardware block updated through Windows Update eliminates exposed motherboard traces and OEM servicing lag in [Pluton (Chapter 3)](02-pluton.md). Orchestrating static (`PCR[0..7]`) and dynamic (`PCR[17..22]`) boot measurements, TCG event logs, and BitLocker sealing profiles belongs to [Measured Boot (Chapter 4)](03-measured-boot.md), while binding `AK` identities to `EK` certificates and validating signed `TPM2_Quote` payloads in cloud control planes is the domain of [Attestation (Chapter 5)](04-attestation.md). Finally, isolating unwrapped secrets and kernel code integrity away from a compromised VTL0 operating system after `TPM2_Unseal` is enforced by [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md) and [Credential Guard and LSASS Isolation (Chapter 12)](08-credential-guard.md).
