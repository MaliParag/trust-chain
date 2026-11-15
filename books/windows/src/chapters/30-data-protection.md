# Data Protection and Local Secret Custody

## Overview

* **Role in the Chain:** Bridges host authorization ([Windows Access Control](25-access-control.md), Chapter 10) and hardware roots of trust ([The TPM](01-tpm.md), Chapter 2; [Measured Boot](03-measured-boot.md), Chapter 4) to persistent storage, governing how Windows encrypts full volumes at rest (`BitLocker`), isolates asymmetric private keys in `VTL1` (`CNG KeyIso`), and protects per-user application secrets (`DPAPI`, `DPAPI-NG`, `App-Bound Encryption`, and `VBS Enclaves`).
* **Core Security Invariant:** Volume ciphertext on powered-off storage media cannot be decrypted without reconstructing the `Volume Master Key` (`VMK`) through an authorized protector (`TPM 2.0` `PCR`-sealed blob, pre-boot `PIN`, or recovery key), and private keys or enclaved user stores marked `VBS`-isolated cannot be exported as raw key material from `VTL0` user or kernel memory.
* **Trusted Computing Base (TCB):** `fvevol.sys` and `bootmgr` (`BitLocker`), the `TPM 2.0` / `Pluton` sealing engine, `lsass.exe` and `LsaIso.exe` (`KeyIso` and `DPAPI` `MasterKey` custody), Active Directory domain controllers holding the `[MS-BKRP]` domain backup key, and `VTL1` `VBS Enclave` runtimes (`vertdll.dll`) for enclave-bound stores.
* **Primary Failure Modes:** Broken firmware implementations in hardware self-encrypting drives (`TCG Opal`), `Windows Recovery Environment` (`WinRE`) partition-relocation and pre-OS `BootExecute` bypasses (`CVE-2022-41099`, `CVE-2024-20666`), same-user `DPAPI` decryption by commodity infostealers, domain-wide offline `DPAPI` decryption via stolen `[MS-BKRP]` domain backup keys, and `TPM`-only unattended unlock combined with physical bus or `DMA` access.
* **Handoff:** Protects volume sectors at rest and local application key containers, while delegating protection of active domain authentication hashes (`NTOWF`) and `Kerberos` `TGT` session keys inside `lsass.exe` to [Credential Guard and LSASS Isolation](08-credential-guard.md) (Chapter 12).

## Core Engineering Problem & Threat Model

Operating-system access control ([Chapter 10](25-access-control.md)) exists only while `ntoskrnl.exe` is running to mediate `NtCreateFile` and `SeAccessCheck`. The moment a laptop is powered down, booted from external media, or imaged over `NVMe`, `NTFS` discretionary access control lists (`DACLs`) become passive metadata inside unencrypted sectors. Conversely, once the operating system boots and a user signs in, hundreds of user-mode components, including browsers, cloud sync clients, mail profiles, Wi-Fi supplicants, and certificate stores, must persist authentication cookies, refresh tokens, and private keys on disk without prompting the user for a passphrase on every process start.

Windows therefore confronts two distinct data-custody problems separated by a sharp lifecycle boundary. The first is *offline volume confidentiality* from pre-boot power-on through operating-system mount: protecting the entire `NTFS` or `ReFS` block device against physical theft, raw disk imaging, or unauthorized boot modifications while preserving unattended reboot capability for servers and managed endpoints. The second is *online secret custody* during post-logon runtime: allowing authorized processes to exercise persistent symmetric secrets and asymmetric private keys while bounding what a same-user infostealer, an elevated local `SYSTEM` attacker, or a compromised domain controller can extract and replay on another machine.

Conflating these two layers produces recurring enterprise failures. Organizations routinely deploy `BitLocker` assuming it protects browser session cookies against post-phishing malware, when `fvevol.sys` transparently decrypts every sector for any running process once the volume is mounted [879]. Conversely, developers call `CryptProtectData` (`DPAPI`) assuming user-scoped encryption isolates secrets from other processes in the same logon session, when `DPAPI` by design treats the interactive user `SID` (not the calling executable) as the security boundary [877]. When [Credential Guard](08-credential-guard.md) (Chapter 12) closed plaintext `NTOWF` extraction inside `lsass.exe`, offensive tradecraft pivoted directly into `DPAPI` `MasterKeys`, browser cookie databases, and software-backed `CNG` key containers.

## Architectural Deep Dive

### BitLocker Key Hierarchy and XTS-AES Sector Encryption

`BitLocker Drive Encryption` decouples volume re-keying from protector rotation through a three-tier key hierarchy enforced by `bootmgr` during pre-OS initialization and by the filter driver `fvevol.sys` situated between the file system (`ntfs.sys`) and the volume manager (`volmgr.sys`) [879]:

![Figure: BitLocker three-tier key hierarchy and hardware-encryption bypass seam](diagrams/30-bitlocker-key-hierarchy.svg)

At the bottom of that hierarchy, the 128-bit or 256-bit Full Volume Encryption Key (`FVEK`) encrypts and decrypts raw disk sectors inline inside `fvevol.sys`, defaulting since Windows 10 version 1511 to `XTS-AES` rather than legacy `AES-CBC` with the `Elephant` diffuser [879]. Rather than storing the `FVEK` directly under user credentials, BitLocker wraps the `FVEK` under a 256-bit Volume Master Key (`VMK`) using `AES-CCM` authenticated encryption across three redundant `-FVE-FS-` metadata headers on the volume, so rotating a compromised PIN or rolling a recovery password re-wraps only the 32-byte `VMK` in milliseconds without re-encrypting terabytes of sector data [879]. Above the `VMK` sit one or more independent key protectors: `TPM`-only sealing (`TPM2_Seal` bound to `PCR[7, 11]` on `UEFI`, analyzed in [Chapter 4](03-measured-boot.md)), `TPM + PIN` (mixing a 6-to-20 character pre-boot secret with `TPM` anti-hammering dictionary lockout), an external USB startup key (`.BEK`), and the 48-digit numeric recovery password whose eight 6-digit groups encode 128 bits of entropy with each group divisible by 11 as a typographical checksum [879].

At the sector cipher layer (`IEEE P1619` / `NIST SP 800-38E`), `XTS-AES` splits a 256-bit or 512-bit key into $(K_1, K_2)$ and encrypts each 16-byte cipher block $j$ inside sector $i$ (where $i$ serves as the byte-offset or sector-number tweak) according to:

$$T = E_{K_2}(i) \otimes \alpha^j, \qquad C_j = E_{K_1}(P_j \oplus T) \oplus T$$

Here $\otimes$ denotes polynomial multiplication in $\mathrm{GF}(2^{128})$ modulo $x^{128} + x^7 + x^2 + x + 1$. Because `XTS-AES` is a narrow-block tweakable mode without per-sector authentication tags, flipping ciphertext bits corrupts only the corresponding 16-byte plaintext block rather than authenticating integrity across the sector, trading ciphertext expansion for wire-speed random I/O [879].

Before 2019, Windows automatically delegated encryption to drive firmware whenever an `NVMe` or `SATA` solid-state drive advertised `TCG Opal` / `IEEE 1667` (`eDrive`) hardware encryption. In *Self-Encrypting Deception* (2019), Meijer and van Woudenberg reverse-engineered major `TCG Opal` SSD controllers and proved that multiple vendors failed to bind the Media Encryption Key (`MEK`) cryptographically to the user password: an attacker with physical `SATA`/`NVMe` access or JTAG debug pins could patch controller firmware to bypass authentication check routines and read plaintext NAND flash directly [880]. Following `ADV190023`, Microsoft changed Windows to enforce software `fvevol.sys` encryption by default even when `Opal` hardware is present [881].

### DPAPI and DPAPI-NG: User-Bound Secret Custody and Domain Backup

Whereas `BitLocker` protects offline volumes, the Windows `Data Protection API` (`DPAPI`, exposed via `CryptProtectData` and `CryptUnprotectData` in `crypt32.dll` routing over `LSASS` `LRPC` to `dpapisrv.dll`) protects arbitrary byte blobs for applications running on an online OS [877].

`DPAPI` never encrypts application data directly under the user's password; otherwise, every password change would orphan encrypted files unless all files on disk were located and re-encrypted. Instead, `DPAPI` maintains rotating 512-bit random `MasterKeys` stored in `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` and rolled every 90 days [877]. On disk, each `MasterKey` file is encrypted under a symmetric key derived via `PBKDF2-HMAC-SHA1` or `SHA512` from `SHA1(UTF-16LE(password))` (or, for domain accounts, from the user's `NTOWF` credential material cached by `LSASS`), combined with a per-file random salt and the user's `SID`. When an application calls `CryptProtectData(plaintext, optionalEntropy)`, `LSASS` unwraps the active `MasterKey` in memory and derives a per-blob encryption and `HMAC` key from the `MasterKey`, a fresh 128-bit random salt recorded in the `DPAPI` blob header, and any caller-supplied `optionalEntropy`.

In an enterprise environment, however, an administrative password reset invalidates the user's password-derived key. Domain-joined workstations solve that recovery problem by additionally encrypting every user `MasterKey` under the Active Directory domain controller's asymmetric 2048-bit RSA `Domain DPAPI Backup Key`, stored as `G$BCKUPKEY_*` secret objects in `AD` [878]. Legitimate password recovery invokes the `BackuprKey` RPC protocol (`[MS-BKRP]`) against a domain controller to unwrap historical `MasterKeys`; offensively, any attacker who extracts the domain backup private key via `DCSync` can decrypt *every* domain user's `DPAPI` blobs across the entire forest offline without knowing a single user password.

To eliminate `MasterKey` file management for cross-machine scenarios, Windows 8 introduced `CNG DPAPI` (`DPAPI-NG`, `NCryptProtectSecret` / `NCryptUnprotectSecret`), which encrypts secrets directly to declarative protection descriptors such as `SID=S-1-5-21-...` or `LOCAL=user` resolved via Active Directory `Group Key Distribution Service` (`GKDS`, `[MS-GKDI]`) without persisting per-host `MasterKey` files [71, 91]. This mechanism underpins `Windows LAPS` encrypted password blobs and modern `PFX` export protection ([Chapter 15](31-enterprise-pki.md)).

### VTL1 CNG KeyIso, Browser App-Bound Encryption, and Recall VBS Enclaves

Because classic `DPAPI` treats every process running under the user's `SID` as equally authorized, three progressively stronger isolation mechanisms narrow runtime secret exposure on modern Windows.

![Figure: Local secret custody split: user-context DPAPI versus VTL1 KeyIso, App-Bound Encryption, and VBS Enclaves](diagrams/30-dpapi-keyiso-custody.svg)

At the cryptographic key layer, `CNG Key Isolation` (`KeyIso`) hosts asymmetric keys created via `Cryptography API: Next Generation` (`CNG`, `ncrypt.dll`) under the `Microsoft Software Key Storage Provider` inside `lsass.exe`, handing client processes only an opaque `NCRYPT_KEY_HANDLE` rather than raw private key bytes [883]. When `Virtualization-Based Security` ([Chapter 6](05-secure-kernel.md)) is active and a key is generated or imported without export permissions (`NCRYPT_ALLOW_EXPORT_FLAG` omitted), `VBS Key Isolation` wraps the private key under a `VTL1` `LsaIso.exe` trustlet key and performs all private-key signing and decryption exclusively inside `VTL1` memory [883]. Even a local `SYSTEM` or Ring-0 `VTL0` attacker cannot extract the raw private key bytes, reducing key theft to an in-session signing oracle while the host remains compromised.

For symmetric application databases such as browser session stores, Chrome and Microsoft Edge introduced `App-Bound Encryption` in 2024 to counter commodity infostealers (`Lumma`, `RedLine`, `Stealc`) that run as the unprivileged logged-in user and invoke `CryptUnprotectData` against the `AES-256-GCM` key protecting Chromium `Cookies` and `Login Data` SQLite databases [884]. Under `App-Bound Encryption`, an elevated `SYSTEM` COM service (`elevation_service.exe` exposing `IElevator`) verifies the calling executable's path and code signature before unwrapping a `SYSTEM`-scoped `DPAPI` layer chained to a user-scoped `DPAPI` layer, binding the validated caller identity inside the ciphertext blob. Unprivileged user-mode malware running outside the browser directory can no longer decrypt browser secrets directly; an attacker must either inject into the genuine signed browser binary (risking `PPL`, code-integrity, or `ETW` injection telemetry) or escalate to `SYSTEM` first [884].

The strictest local custody tier emerged from Microsoft's redesign of Copilot+ `Windows Recall`. When `Recall` was first previewed in May 2024, storing semantic screen-activity snapshots in a local SQLite database guarded only by standard `DPAPI` and file ACLs meant that any same-user infostealer or elevated administrative process could harvest historical screen contents. Microsoft suspended the rollout and rebuilt `Recall` around a `VTL1` `VBS Enclave`, an Isolated User Mode enclave instantiated via `CreateEnclave(ENCLAVE_TYPE_VBS)` and verified by `skci.dll` [885].

![Figure: Copilot+ Recall VBS Enclave and Windows Hello ESS presence-gated decryption](diagrams/30-recall-enclave-gate.svg)

Under the hardened `Recall` architecture, captured screen frames and the `UKP` vector/SQLite index are encrypted with per-user keys sealed to the `TPM 2.0` and isolated inside a `VTL1` `VBS Enclave` [885]. Releasing or querying decrypted index contents requires a live `Windows Hello Enhanced Sign-in Security` (`ESS`) biometric or `PIN` authorization ceremony evaluated in `VTL1` ([Chapter 17](12-hello.md)), rate-limited by hardware anti-hammering counters. Neither an offline disk clone nor a silent background infostealer running under the user's `SID` can bulk-decrypt `Recall` history without interactive user verification [885].

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Cold Boot & DMA `FVEK` Extraction (`PCILeech`) | 2008-2025 | Mounted `BitLocker` `FVEK` in `VTL0` DRAM | Physical access to sleeping/locked PC | Chills DRAM to retain remanence across reset or reads `fvevol.sys` key pool via unguarded PCIe/Thunderbolt `DMA` [887] | Enable `Kernel DMA Protection` (`IOMMU`), hibernate instead of sleep, and enforce `TPM + PIN` |
| `TCG Opal` Self-Encrypting SSD Bypass | 2018-2019 | Hardware SED `MEK` / password decoupling | Physical drive access (`SATA`/`NVMe`/debug) | Exploits drive firmware where `MEK` is not cryptographically derived from user passphrase (`Self-Encrypting Deception`) [880] | Enforce software `BitLocker` via Group Policy (`Configure use of hardware-based encryption = Disabled`) [881] |
| `WinRE` Partition & `BootExecute` Bypasses (`CVE-2022-41099`, `CVE-2024-20666`) | 2022-2026 | `BitLocker` pre-OS / recovery transition | Physical disk access on `TPM`-only host | Boots older `WinRE` image or abuses unauthenticated recovery `BootExecute` / `reagentc` state to access unlocked volume [41, 882] | Refresh `WinRE` partition (`KB5034441`+), apply `DBX` revocations, and require pre-boot `TPM + PIN` |
| Same-User `DPAPI` Infostealers (`Mimikatz` `dpapi::`, `SharpDPAPI`) | 2014-present | Application secret isolation within user session | Code execution as target interactive user | Calls `CryptUnprotectData` in user session (or injects into browser to abuse `IElevator`) to dump cookies and tokens [877, 884] | Move high-value keys into `VTL1` `KeyIso` / `VBS Enclaves`; enforce `WDAC` and `Token Protection` (`PoP`) |
| Domain `DPAPI` Backup Key Theft (`lsadump::backupkeys`) | 2015-present | Forest-wide user `DPAPI` confidentiality | Domain Admin / `DCSync` read on DC secrets | Extracts `G$BCKUPKEY_PREFERRED` RSA key (`[MS-BKRP]`) from AD to decrypt any user's `MasterKeys` offline [878] | Treat `G$BCKUPKEY_*` access as Tier-0 breach; audit DC `4662` secret reads and isolate Tier-0 admin hosts |
| `CNG KeyIso` ALPC Memory Corruption (`CVE-2023-28229`) | 2023 | Low-privilege / sandbox to `SYSTEM` (`lsass.exe`) | Local execution reaching `KeyIso` RPC endpoint | Triggers out-of-bounds write in `KeyIso` `LRPC` server hosted inside `VTL0` `lsass.exe` [307, 308] | Apply MSRC security updates; isolate raw key material inside `VTL1` `LsaIso.exe` via `VBS Key Isolation` [883] |

### Gap Analysis: Why TPM-Only BitLocker Fails Against Physical Possession

Enterprises frequently deploy `BitLocker` in `TPM`-only mode (`PCR[7, 11]`) so laptops reboot unattended during overnight maintenance windows. That choice is sound against opportunistic theft where an attacker removes the `NVMe` SSD or boots a live USB image (`PCR[7]` or `PCR[11]` diverges and the `TPM` refuses `TPM2_Unseal`), yet it leaves an intrinsic architectural seam: during a normal unattended boot of the genuine signed Windows OS up to the `Winlogon` lock screen, the `TPM` *must* succeed at `TPM2_Unseal` and hand the `VMK` to `bootmgr`, which unwraps the `FVEK` into `fvevol.sys` kernel memory [36, 879].

At the `Winlogon` screen on a `TPM`-only device, the volume is already mounted and decrypted in `DRAM`. Every physical bypass class disclosed between 2019 and 2026 exploits that exact mounted state without breaking `AES` or the `TPM` itself. Passive `SPI` or `LPC` bus sniffing ([Chapter 2](01-tpm.md)) captures the 32-byte `VMK` on discrete motherboard `TPM` traces at the instant `bootmgr` executes `TPM2_Unseal` [36]. Soft-reboot and `WinRE` lifecycle seams (`CVE-2022-41099`, `CVE-2023-21563`, `CVE-2024-20666`) trick an unrevoked signed boot or recovery path into unsealing the `VMK` under valid `PCR[7, 11]` measurements and retaining volume access across a recovery shell or soft transition [38, 41, 882]. Direct Memory Access tools such as `PCILeech` read `fvevol.sys` pool structures directly over an unguarded PCIe or Thunderbolt slot whenever `Kernel DMA Protection` (`IOMMU`) is absent or disabled [111, 887].

Adding a pre-boot `PIN` (`TPM + PIN`) shifts the cryptographic invariant from *"did an untampered Windows boot loader start?"* to *"did the human owner authorize key release at the firmware prompt?"* For high-risk travel laptops and Tier-0 administrative workstations (`PAWs`), `TPM + PIN` combined with `Microsoft Pluton` (closing bus sniffing) and `Kernel DMA Protection` closes all three physical classes simultaneously.

### Gap Analysis: The Same-User DPAPI Fallacy and Domain Backup Asymmetry

Application developers routinely treat `DPAPI` as a local hardware vault, yet architecturally `DPAPI` is a *user-roaming convenience cipher* rather than a process-isolation boundary. Because `DPAPI` enforces zero process binding by default, any binary executing under `Alice`'s `Medium-IL` token holds identical authority to invoke `CryptUnprotectData` over `LRPC` to `lsass.exe` unless per-blob `optionalEntropy` is hidden elsewhere (which merely relocates the key-storage problem) or an out-of-process broker such as `IElevator` or a `VBS Enclave` verifies caller code identity [877, 884]. Even `IElevator` (`App-Bound Encryption`) remains exposed once an attacker reaches `SYSTEM` privilege or injects code into a signed browser process before `Code Integrity Guard` (`CIG`) or `PPL` blocks injection [884].

A second structural gap arises from permanent forest-wide escrow under `[MS-BKRP]`. Unlike `TPM`-sealed keys, domain `DPAPI` `MasterKeys` intentionally embed an asymmetric escrow blob (`Domain Backup Key`) that Active Directory almost never rotates automatically [878]. If an adversary compromises Active Directory once and extracts `G$BCKUPKEY_*`, that single 2048-bit RSA private key permanently compromises historical and future domain-joined `DPAPI` `MasterKeys` until an administrator explicitly regenerates the domain backup key and rotates every user's `MasterKey`. Secrets that must survive both same-user malware and domain escrow must bind private keys inside non-exportable `TPM` (`PCP`) containers or `VTL1` `KeyIso` and `VBS Enclaves` [883, 885].

> **Key idea.**
> `BitLocker` protects data across power-off boundaries while `fvevol.sys` exposes mounted sectors to every running process; `DPAPI` protects secrets across user `SIDs` while exposing `CryptUnprotectData` to every process in the active user session and escrowing `MasterKeys` to Active Directory. Surviving both same-user malware and domain compromise requires moving secret *execution* across a hardware or `VTL1` boundary (`KeyIso` or `VBS Enclaves`) rather than wrapping files in `VTL0`.

## Theoretical Limits & Structural Invariants

### Unattended Reboot vs. Physical Possession

Any full-disk encryption system that boots unattended to a network-reachable operating-system login prompt without human input *must* store every secret needed to reconstruct the `FVEK` inside the physical chassis, partitioned solely between storage media and the platform cryptoprocessor. Against a physical adversary capable of probing internal interconnects, inducing `DRAM` or cache leaks, or exploiting pre-authentication OS recovery bugs, unattended `TPM`-only unlock can verify *boot-code integrity* up to `Winlogon` but cannot prove *operator authorization*.

### Narrow-Block Malleability and Ambient User Custody

Two further structural bounds constrain sector ciphers and user-scoped secret vaults. At the block layer, because `XTS-AES` preserves a 1:1 sector size without per-sector `MAC` tags or Merkle trees, an offline attacker with raw disk write access can malleate 16-byte ciphertext blocks or roll back encrypted sectors to an earlier snapshot (`evil maid` ciphertext rollback) without `fvevol.sys` detecting tampering; integrity must be supplied above the block device at the filesystem or application layer, or via `Measured Boot` across early boot partitions [879]. At the application layer, under Norman Hardy's *Confused Deputy* principle [363], encrypting application secrets to the user's ambient `SID` (`DPAPI`) collapses the security of high-assurance credentials down to the weakest unsandboxed binary that user runs. True per-application secret custody requires pairing unforgeable caller code identity (`skci.dll` signing levels or `VBS Enclave` `AuthorId` and `ImageId` sealing) with hardware-isolated key execution in `VTL1` or the `TPM`.

## Inspecting and Verifying on a Running System

### Inspect BitLocker Encryption Method, Protectors, and Software Enforcement

Verify that the OS volume uses `XtsAes256` (or `XtsAes128`) software encryption rather than legacy `Opal` hardware encryption, and enumerate active `VMK` key protectors [879, 881]:

```powershell
Get-BitLockerVolume -MountPoint $env:SystemDrive |
  Select-Object MountPoint, VolumeStatus, EncryptionMethod, KeyProtector
```

Expected output on a hardened endpoint (`TpmPin` + `RecoveryPassword`, active `XtsAes256`):

```text
MountPoint VolumeStatus   EncryptionMethod KeyProtector
---------- ------------   ---------------- ------------
C:         FullyEncrypted XtsAes256        {TpmPin, RecoveryPassword}
```

Confirm via `manage-bde` whether encryption is performed in software by `fvevol.sys` rather than delegated to drive firmware:

```powershell
manage-bde -status $env:SystemDrive | Select-String "Conversion Status|Encryption Method|Key Protectors" -Context 0,2
```

### Verify VBS Key Isolation (`KeyIso` + `LsaIso.exe`) and Kernel DMA Protection

Confirm that `VBS` and `LsaIso.exe` are running so non-exportable `CNG` keys are isolated inside `VTL1`, and check `Kernel DMA Protection` state against physical `PCIe`/`Thunderbolt` `DMA` extraction [111, 883]:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
```

Query system information flags for `Kernel DMA Protection` (`1` indicates active `IOMMU` boot/runtime `DMA` remapping):

```powershell
Get-Process -Name LsaIso -ErrorAction SilentlyContinue | Select-Object Name, Id
```

### Enumerate CNG Key Storage Providers and Non-Exportable Machine Keys

List registered `CNG` Key Storage Providers (`Microsoft Platform Crypto Provider` for `TPM`-bound keys and `Microsoft Software Key Storage Provider` for `KeyIso` / `VBS`-isolated keys) and inspect machine key containers [883]:

```powershell
certutil -csplist | Select-String "Provider Name"
```

```powershell
certutil -key -csp "Microsoft Platform Crypto Provider"
```

## Summary & Handoff

`BitLocker`, `DPAPI`, `CNG KeyIso`, and `VBS Enclaves` form the persistent data-custody layer of Windows: `BitLocker` (`fvevol.sys` + `TPM2_Seal`) protects offline storage media against physical removal, `DPAPI` and `DPAPI-NG` manage rotating user and group secrets with Active Directory recovery, and `VTL1` `KeyIso` alongside `Recall`-class `VBS Enclaves` prevent raw key or sensitive index extraction from `VTL0` memory. Yet whenever secrets remain accessible to `VTL0` `lsass.exe` or same-user processes without `VTL1` isolation, post-exploitation tools extract them directly from memory.

With persistent disk and local secret custody established, the next link isolates the operating system's highest-value active domain authentication secrets inside `lsass.exe` itself. [Credential Guard and LSASS Isolation](08-credential-guard.md) (Chapter 12) examines how Windows relocates `NTOWF` password hashes, `Kerberos` `AES` keys, and `TGT` session keys out of `VTL0` `lsass.exe` into `VTL1` `LsaIso.exe`, while [Pass-the-Hash to Pass-the-PRT](11-pth-prt.md) (Chapter 16) and [Continuous Access Evaluation](14-cae.md) (Chapter 20) extend hardware-bound proof-of-possession and real-time revocation to cloud refresh and session tokens so stolen browser artifacts cannot be replayed off-host.
