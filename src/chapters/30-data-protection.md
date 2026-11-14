# Data Protection and Local Secret Custody

## Overview

* **Role in the Chain:** Bridges host authorization ([Windows Access Control](25-access-control.md), Chapter 10) and hardware roots of trust ([The TPM](01-tpm.md), Chapter 2; [Measured Boot](03-measured-boot.md), Chapter 4) to persistent storage, governing how Windows encrypts full volumes at rest (`BitLocker`), isolates asymmetric private keys in `VTL1` (`CNG KeyIso`), and protects per-user application secrets (`DPAPI`, `DPAPI-NG`, `App-Bound Encryption`, and `VBS Enclaves`).
* **Core Security Invariant:** Volume ciphertext on powered-off storage media cannot be decrypted without reconstructing the `Volume Master Key` (`VMK`) through an authorized protector (`TPM 2.0` `PCR`-sealed blob, pre-boot `PIN`, or recovery key), and private keys or enclaved user stores marked `VBS`-isolated cannot be exported as raw key material from `VTL0` user or kernel memory.
* **Trusted Computing Base (TCB):** `fvevol.sys` and `bootmgr` (`BitLocker`), the `TPM 2.0` / `Pluton` sealing engine, `lsass.exe` and `LsaIso.exe` (`KeyIso` and `DPAPI` `MasterKey` custody), Active Directory domain controllers holding the `[MS-BKRP]` domain backup key, and `VTL1` `VBS Enclave` runtimes (`vertdll.dll`) for enclave-bound stores.
* **Primary Failure Modes:** Broken firmware implementations in hardware self-encrypting drives (`TCG Opal`), `Windows Recovery Environment` (`WinRE`) partition-relocation and pre-OS `BootExecute` bypasses (`CVE-2022-41099`, `CVE-2024-20666`), same-user `DPAPI` decryption by commodity infostealers, domain-wide offline `DPAPI` decryption via stolen `[MS-BKRP]` domain backup keys, and `TPM`-only unattended unlock combined with physical bus or `DMA` access.
* **Handoff:** Protects volume sectors at rest and local application key containers, while delegating protection of active domain authentication hashes (`NTOWF`) and `Kerberos` `TGT` session keys inside `lsass.exe` to [Credential Guard and LSASS Isolation](08-credential-guard.md) (Chapter 12).

## Core Engineering Problem & Threat Model

Operating-system access control ([Chapter 10](25-access-control.md)) exists only while `ntoskrnl.exe` is running to mediate `NtCreateFile` and `SeAccessCheck`. The moment a laptop is powered down, booted from external media, or imaged over `NVMe`, `NTFS` discretionary access control lists (`DACLs`) become passive metadata inside unencrypted sectors. Conversely, once the operating system boots and a user signs in, hundreds of user-mode components, including browsers, cloud sync clients, mail profiles, Wi-Fi supplicants, and certificate stores, must persist authentication cookies, refresh tokens, and private keys on disk without prompting the user for a passphrase on every process start.

Windows therefore faces two distinct data-custody problems separated by a sharp lifecycle boundary:

1. **Offline Volume Confidentiality (Pre-Boot to OS Mount):** Protect the entire `NTFS`/`ReFS` block device against physical theft, disk imaging, or unauthorized boot modifications, while preserving unattended reboot capability for servers and managed endpoints.
2. **Online Secret Custody (Post-Logon Runtime):** Allow authorized processes to use persistent symmetric secrets and asymmetric private keys while bounding what a same-user infostealer, an elevated local `SYSTEM` attacker, or a compromised domain controller can extract and replay on another machine.

Conflating these two layers produces recurring enterprise failures. Organizations routinely deploy `BitLocker` assuming it protects browser session cookies against post-phishing malware, when `fvevol.sys` transparently decrypts every sector for any running process once the volume is mounted [879]. Conversely, developers call `CryptProtectData` (`DPAPI`) assuming user-scoped encryption isolates secrets from other processes in the same logon session, when `DPAPI` by design treats the interactive user `SID` (not the calling executable) as the security boundary [877]. When [Credential Guard](08-credential-guard.md) (Chapter 12) closed plaintext `NTOWF` extraction inside `lsass.exe`, offensive tradecraft pivoted directly into `DPAPI` `MasterKeys`, browser cookie databases, and software-backed `CNG` key containers.

## Architectural Deep Dive

### BitLocker Key Hierarchy and XTS-AES Sector Encryption

`BitLocker Drive Encryption` decouples volume re-keying from protector rotation through a three-tier key hierarchy enforced by `bootmgr` during pre-OS initialization and by the filter driver `fvevol.sys` situated between the file system (`ntfs.sys`) and the volume manager (`volmgr.sys`) [879]:

![BitLocker three-tier key hierarchy and hardware-encryption bypass seam](diagrams/30-bitlocker-key-hierarchy.svg)

1. **Full Volume Encryption Key (`FVEK`, 128-bit or 256-bit):** Encrypts raw disk sectors inline. Since Windows 10 version 1511, new volumes default to `XTS-AES` (`IEEE P1619` / `NIST SP 800-38E`) rather than legacy `AES-CBC` with `Elephant` diffuser [879]. Under `XTS-AES`, a 256-bit or 512-bit key $(K_1, K_2)$ encrypts each 16-byte cipher block $j$ inside sector $i$ (where $i$ is the byte offset or sector number tweak) as:
   $$T = E_{K_2}(i) \otimes \alpha^j, \qquad C_j = E_{K_1}(P_j \oplus T) \oplus T$$
   where $\otimes$ denotes multiplication in $\mathrm{GF}(2^{128})$ modulo $x^{128} + x^7 + x^2 + x + 1$. Because `XTS-AES` is a narrow-block tweakable mode without authentication tags, flipping ciphertext bits corrupts only the corresponding 16-byte plaintext block rather than authenticating integrity across the sector, trading ciphertext expansion for wire-speed random I/O.
2. **Volume Master Key (`VMK`, 256-bit):** Wraps the `FVEK` inside the on-disk `-FVE-FS-` metadata header using `AES-CCM` (`authenticated encryption`), which appears in three redundant metadata copies across the volume. Rotating a compromised PIN or rolling a recovery password re-wraps only the 32-byte `VMK` in milliseconds without re-encrypting terabytes of sector data [879].
3. **Key Protectors:** Wrap the `VMK` under one or more independent unlock paths: `TPM`-only (`TPM2_Seal` bound to `PCR[7, 11]` on `UEFI`, as analyzed in [Chapter 4](03-measured-boot.md)), `TPM + PIN` (stretching a 6-to-20 character pre-boot secret mixed with `TPM` anti-hammering dictionary lockout), external USB startup key (`.BEK`), or the 48-digit numeric recovery password (eight 6-digit groups encoding 128 bits of entropy, where each group is divisible by 11 as a typographical checksum) [879].

Before 2019, Windows automatically delegated encryption to drive firmware whenever an `NVMe` or `SATA` solid-state drive advertised `TCG Opal` / `IEEE 1667` (`eDrive`) hardware encryption. In *Self-Encrypting Deception* (2019), Meijer and van Woudenberg reverse-engineered major `TCG Opal` SSD controllers and proved that multiple vendors failed to bind the Media Encryption Key (`MEK`) cryptographically to the user password: an attacker with physical `SATA`/`NVMe` access or JTAG debug pins could patch controller firmware to bypass authentication check routines and read plaintext NAND flash directly [880]. Following `ADV190023`, Microsoft changed Windows to enforce software `fvevol.sys` encryption by default even when `Opal` hardware is present [881].

### DPAPI and DPAPI-NG: User-Bound Secret Custody and Domain Backup

Whereas `BitLocker` protects offline volumes, the Windows `Data Protection API` (`DPAPI`, exposed via `CryptProtectData` and `CryptUnprotectData` in `crypt32.dll` routing over `LSASS` `LRPC` to `dpapisrv.dll`) protects arbitrary byte blobs for applications running on an online OS [877].

`DPAPI` never encrypts application data directly under the user's password; otherwise, every password change would orphan encrypted files unless all files on disk were located and re-encrypted. Instead, `DPAPI` maintains rotating 512-bit random `MasterKeys` stored in `%APPDATA%\Microsoft\Protect\<SID>\<GUID>` (rotated every 90 days) [877]:

1. **Local MasterKey Protection:** On disk, each `MasterKey` file is encrypted with a symmetric key derived via `PBKDF2-HMAC-SHA1` / `SHA512` from `SHA1(UTF-16LE(password))` (or for domain accounts, the user's `NTOWF` credential material cached by `LSASS`) salted with a per-file random salt and user `SID`.
2. **Per-Blob Derivation:** When an application calls `CryptProtectData(plaintext, optionalEntropy)`, `LSASS` unwraps the active `MasterKey` in memory and derives a per-blob encryption and `HMAC` key combining the `MasterKey`, a fresh 128-bit random salt stored in the `DPAPI` blob header, and any caller-supplied `optionalEntropy`.
3. **Active Directory Domain Backup (`[MS-BKRP]`):** Because an enterprise password reset by an administrator invalidates the user's password-derived key, domain-joined workstations additionally encrypt every user `MasterKey` under the Active Directory domain controller's asymmetric 2048-bit RSA `Domain DPAPI Backup Key` (`G$BCKUPKEY_*` secret objects in `AD`) [878]. Legitimate password recovery invokes `BackuprKey` RPC (`[MS-BKRP]`) against a DC to unwrap old `MasterKeys`; offensively, any attacker who extracts the domain backup private key via `DCSync` can decrypt *every* domain user's `DPAPI` blobs across the entire forest offline without knowing a single user password.

To eliminate `MasterKey` file management for cross-machine scenarios, Windows 8 introduced `CNG DPAPI` (`DPAPI-NG`, `NCryptProtectSecret` / `NCryptUnprotectSecret`), which encrypts secrets directly to declarative protection descriptors such as `SID=S-1-5-21-...` or `LOCAL=user` resolved via Active Directory `Group Key Distribution Service` (`GKDS`, `[MS-GKDI]`) without persisting per-host `MasterKey` files [71, 91]. This mechanism underpins `Windows LAPS` encrypted password blobs and modern `PFX` export protection ([Chapter 15](31-enterprise-pki.md)).

### VTL1 CNG KeyIso, Browser App-Bound Encryption, and Recall VBS Enclaves

Because classic `DPAPI` treats every process running under the user's `SID` as equally authorized, three progressively stronger isolation mechanisms narrow runtime secret exposure on modern Windows:

![Local secret custody split: user-context DPAPI versus VTL1 KeyIso, App-Bound Encryption, and VBS Enclaves](diagrams/30-dpapi-keyiso-custody.svg)

* **CNG Key Isolation (`KeyIso`) and VBS Key Isolation (`LsaIso.exe`):** Asymmetric keys created via `Cryptography API: Next Generation` (`CNG`, `ncrypt.dll`) under the `Microsoft Software Key Storage Provider` execute inside the `KeyIso` service (`lsass.exe`) so client processes hold only an `NCRYPT_KEY_HANDLE` rather than raw private key bytes [883]. When `Virtualization-Based Security` ([Chapter 6](05-secure-kernel.md)) is active and a key is generated or imported without export flags (`NCRYPT_ALLOW_EXPORT_FLAG` omitted), `VBS Key Isolation` wraps the private key under a `VTL1` `LsaIso.exe` trustlet key and performs private-key signing and decryption exclusively inside `VTL1` memory [883]. Even a local `SYSTEM` or Ring-0 `VTL0` attacker cannot extract the raw private key bytes, reducing theft to an in-session signing oracle while the host remains compromised.
* **Browser `App-Bound Encryption` (`IElevator` COM Service):** Commodity infostealers (`Lumma`, `RedLine`, `Stealc`) routinely run as the unprivileged logged-in user and call `CryptUnprotectData` to unwrap the `AES-256-GCM` key protecting Chromium `Cookies` and `Login Data` SQLite databases. In 2024, Chrome and Microsoft Edge introduced `App-Bound Encryption` [884]: an elevated `SYSTEM` COM service (`elevation_service.exe` exposing `IElevator`) verifies the caller's executable path and code signature before unwrapping a `SYSTEM`-scoped `DPAPI` layer chained to a user-scoped `DPAPI` layer, encoding the validated caller identity inside the ciphertext blob. Unprivileged user-mode malware outside the browser directory can no longer call `CryptUnprotectData` directly; attackers must either inject into the genuine browser binary (triggering `PPL`/code-integrity or `ETW` injection telemetry) or escalate to `SYSTEM` first [884].
* **Copilot+ `Recall` and Presence-Gated `VBS Enclaves`:** When Microsoft previewed `Windows Recall` in May 2024, storing semantic screen-activity snapshots in a local SQLite database protected only by standard `DPAPI`/file ACLs meant any same-user infostealer or elevated admin process could read a user's historical screen contents. Microsoft suspended the rollout and re-architected `Recall` around a `VTL1` `VBS Enclave` (`IUM` enclave loaded via `CreateEnclave(ENCLAVE_TYPE_VBS)` and verified by `skci.dll`) [885]:

![Copilot+ Recall VBS Enclave and Windows Hello ESS presence-gated decryption](diagrams/30-recall-enclave-gate.svg)

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

At the `Winlogon` screen on a `TPM`-only device, the volume is already mounted and decrypted in `DRAM`. Every physical bypass class from 2019 to 2026 exploits that exact invariant without breaking `AES` or the `TPM`:

* **Passive SPI/LPC Bus Sniffing ([Chapter 2](01-tpm.md)):** Captures the 32-byte `VMK` on discrete motherboard `TPM` traces at the instant `bootmgr` calls `TPM2_Unseal` [36].
* **Soft-Reboot & `WinRE` Lifecycle Seams (`CVE-2022-41099`, `CVE-2023-21563`, `CVE-2024-20666`):** Tricks an unrevoked signed boot/recovery path into unsealing the `VMK` under valid `PCR[7, 11]` state and retaining access across a recovery shell or soft transition [38, 41, 882].
* **Direct Memory Access (`PCILeech`):** Reads `fvevol.sys` pool structures directly over an unguarded PCIe slot if `Kernel DMA Protection` (`IOMMU`) is absent or disabled [111, 887].

Adding a pre-boot `PIN` (`TPM + PIN`) shifts the cryptographic invariant from *"did an untampered Windows boot loader start?"* to *"did the human owner authorize key release at the firmware prompt?"* For high-risk travel laptops and Tier-0 administrative workstations (`PAWs`), `TPM + PIN` combined with `Microsoft Pluton` (closing bus sniffing) and `Kernel DMA Protection` closes all three physical classes simultaneously.

### Gap Analysis: The Same-User DPAPI Fallacy and Domain Backup Asymmetry

Application developers routinely treat `DPAPI` as a local hardware vault. Architecturally, `DPAPI` is a *user-roaming convenience cipher*, not a process-isolation boundary:

1. **Zero Process Binding by Default:** Any binary running under `Alice`'s Medium-IL token has identical authority to invoke `CryptUnprotectData` over `LRPC` to `lsass.exe` unless per-blob `optionalEntropy` is hidden elsewhere (which merely moves the key-storage problem) or an out-of-process broker like `IElevator` / `VBS Enclaves` enforces caller code identity [877, 884]. Even `IElevator` (`App-Bound Encryption`) remains vulnerable once an attacker achieves `SYSTEM` privilege or injects code into a signed browser process before `Code Integrity Guard` (`CIG`) or `PPL` blocks injection [884].
2. **Permanent Forest-Wide Escrow (`[MS-BKRP]`):** Unlike `TPM`-sealed keys, domain `DPAPI` `MasterKeys` intentionally embed an asymmetric escrow blob (`Domain Backup Key`) that Active Directory almost never rotates automatically [878]. If an adversary compromises Active Directory once and extracts `G$BCKUPKEY_*`, that single 2048-bit RSA key permanently compromises historical and future domain-joined `DPAPI` `MasterKeys` until every user's `MasterKey` is rotated after explicitly regenerating the domain backup key. Secrets that must survive both same-user malware and domain escrow must bind private keys inside non-exportable `TPM` (`PCP`) or `VTL1` `KeyIso` / `VBS Enclaves` [883, 885].

> **Key idea.**
> `BitLocker` protects data across power-off boundaries while `fvevol.sys` exposes mounted sectors to every running process; `DPAPI` protects secrets across user `SIDs` while exposing `CryptUnprotectData` to every process in the active user session and escrowing `MasterKeys` to Active Directory. Surviving both same-user malware and domain compromise requires moving secret *execution* across a hardware or `VTL1` boundary (`KeyIso` or `VBS Enclaves`) rather than wrapping files in `VTL0`.

## Theoretical Limits & Structural Invariants

* **Unattended Reboot vs. Physical Possession Impossibility:** Any full-disk encryption system that boots to a network-reachable OS login prompt without human input *must* store every secret required to reconstruct the `FVEK` inside the physical chassis (split between storage media and the `TPM`). Against a physical adversary capable of probing internal interconnects, inducing `DRAM`/cache leaks, or exploiting pre-auth OS vulnerabilities, unattended `TPM`-only unlock can verify *boot-code integrity* but cannot prove *operator authorization*.
* **Narrow-Block Disk Encryption Cannot Provide Replay-Safe Integrity:** Because `XTS-AES` preserves 1:1 sector size without per-sector `MAC` tags or Merkle trees, an offline attacker with raw disk write access can malleate ciphertext 16-byte blocks or roll back encrypted sectors to an earlier snapshot (`evil maid` ciphertext rollback) without `fvevol.sys` detecting modification at the block layer; integrity must be enforced at the filesystem/application layer or via `Measured Boot` over early boot partitions [879].
* **Ambient User Authority vs. Per-App Key Custody:** Under Norman Hardy's *Confused Deputy* principle [363], encrypting all application secrets to the user's ambient `SID` (`DPAPI`) collapses the security of high-assurance credentials down to the weakest un-sandboxed binary the user executes. True per-application secret custody requires both unforgeable caller identity (`skci.dll` signing levels / `VBS Enclave` `AuthorId` + `ImageId` sealing) and hardware-isolated key execution (`VTL1` / `TPM`).

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

With persistent disk and local secret custody established, the next link isolates the operating system's highest-value active domain authentication secrets inside `lsass.exe` itself:

* **Isolating Domain Authentication Secrets in `VTL1`:** Moving `NTOWF` password hashes, `Kerberos` `AES` keys, and `TGT` session keys out of `VTL0` `lsass.exe` into `LsaIso.exe` belongs to [Credential Guard and LSASS Isolation](08-credential-guard.md) (Chapter 12).
* **Binding Cloud Sessions to Hardware Keys:** Requiring `TPM`/enclave proof-of-possession on cloud refresh and access tokens so stolen browser cookies cannot be replayed off-host belongs to [Pass-the-Hash to Pass-the-PRT](11-pth-prt.md) (Chapter 16) and [Continuous Access Evaluation](14-cae.md) (Chapter 20).
