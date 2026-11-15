# UEFI, shim, Machine Owner Keys, and SBAT Revocation

## Overview

* **Link in the Chain:** First cryptographic admission gate on x86_64 and ARM64 UEFI platforms; authenticates pre-OS Linux bootloaders against firmware NVRAM trust stores before transferring execution to a second-stage loader (`GRUB2`, `systemd-boot`) or Unified Kernel Image (`UKI`).
* **Core Security Invariant:** Firmware `LoadImage()` executes an initial EFI binary only if its PE/COFF Authenticode digest and signing chain are absent from `dbx` and chain to `db`; subsequently, `shim.efi` admits a second-stage PE image only if its `.sbat` component generations satisfy `SbatLevel`, its digest/signer is absent from `dbx` and `MokListX`, and its Authenticode signature chains to `db`, `shim`'s embedded vendor certificate, or `MokList`.
* **Deployment Profile Matrix:** Mutable enterprise distributions (`RHEL`, `Ubuntu`, `Debian`, `SUSE`) deploy Microsoft-signed `shim.efi` chaining to vendor-signed `grubx64.efi` with `MokManager` enabled for out-of-tree `DKMS` modules; immutable appliances and `Talos` / `Bottlerocket` builds either chain `shim.efi` directly to a signed `UKI` or enroll custom OEM/fleet `PK`/`KEK`/`db` keys with Microsoft third-party CAs removed; cloud VMs rely on hypervisor-provisioned OVMF NVRAM templates.
* **Trusted Computing Base (TCB):** Silicon reset roots where fused (`Intel Boot Guard`, `AMD Platform Secure Boot`), SPI flash hosting UEFI `SEC`/`PEI`/`DXE`/`BDS` volumes, NVRAM authenticated variables (`PK`, `KEK`, `db`, `dbx`) and boot-services-only `SbatLevel`/`MokList`, Microsoft UEFI CA signing infrastructure, `shim.efi`, and the distribution's bootloader signing HSM.
* **Integration Seam & Handoff:** Hands off an Authenticode- and `SBAT`-verified bootloader or `vmlinuz` entry point plus runtime-readable `MokListRT` key mirrors; leaves `initramfs` and kernel command-line binding to [Chapter 2](02-uki-systemd-pcrlock.md) and post-boot Ring 0 lockdown to [Chapter 5](05-kernel-lockdown-modules.md).

## Problem Statement & Threat Model

Operating-system access controls, mandatory access control policies, and kernel memory mitigations cannot defend themselves if an adversary executes arbitrary instructions in Ring 0 before the Linux kernel initializes. Under legacy PC BIOS boot, CPU reset jumped into 16-bit real mode, initialized DRAM, read the first 512-byte sector (Master Boot Record) of the boot drive to physical address `0x7C00`, verified only the two-byte `0x55AA` magic trailer, and transferred control unconditionally [1]. Any attacker who gained transient root privileges or brief physical access to an unencrypted boot sector could overwrite Stage 1 or Stage 1.5 of `GRUB` to hook kernel decompression in memory while concealing the modification from userspace utilities.

Unified Extensible Firmware Interface (`UEFI`) Secure Boot (`UEFI` Specification Section 32 [1]) replaced unauthenticated sector jumping with cryptographic verification of Portable Executable (`PE/COFF`) boot applications against authenticated NVRAM variables (`PK`, `KEK`, `db`, `dbx`). On commercial x86_64 hardware, however, Secure Boot immediately collided with the organizational structure of open-source software. Commodity motherboards leave the factory with Microsoft's Platform/Key-Exchange ecosystem pre-enrolled in `KEK` and `db` (`Microsoft Windows Production PCA 2011` / `Windows UEFI CA 2023` for Windows, and `Microsoft Corporation UEFI CA 2011` / `Microsoft UEFI CA 2023` for third-party UEFI drivers, PCIe Option ROMs, and non-Windows bootloaders) [1, 15, 16]. Hundreds of independent Linux distributions, enterprise rebuilds, corporate fleet teams, and individual kernel developers compile custom kernels daily, plus out-of-tree kernel modules (`NVIDIA` GPU drivers, `ZFS`, custom network ASICs) via `DKMS`. Routing every distribution kernel release and every developer's local `make bzImage` through Microsoft's central hardware-dev-center signing portal was operationally impossible, yet asking mainstream laptop users to wipe factory UEFI keys in firmware setup would break Windows dual-boot and brick systems whose PCIe GPU or NVMe Option ROMs are signed solely by the Microsoft third-party UEFI CA [11, 16].

The Linux ecosystem therefore faced a three-part engineering problem under an adversary model encompassing local root compromise (mounting the `FAT32` EFI System Partition at `/boot/efi` and invoking `efivarfs` writes), unattended physical access, and rogue network boot servers (`PXE` / `UEFI HTTP Boot`). First, Linux needed a compact, auditable first-stage UEFI bridge signed once by the Microsoft third-party UEFI CA that could delegate trust cleanly to each distribution's own signing authority *and* allow machine owners with physical console presence to enroll local keys without disabling Secure Boot. Second, when a vulnerability was discovered in shared upstream bootloader code such as `GNU GRUB2`, the ecosystem needed a revocation mechanism that would not exhaust constrained 32-to-64 KiB motherboard SPI flash NVRAM by enumerating thousands of per-distro binary SHA-256 hashes [12, 13]. Third, the handoff from `shim` to `GRUB2` and `vmlinuz` had to block interpreter, dynamic-module, and parser escapes inside the pre-OS environment itself.

## Kernel & Userspace Mechanics

### UEFI Platform Initialization, Silicon Anchors, and Authenticated Variables

Before a single byte of Linux code executes, platform firmware runs the four-phase UEFI Platform Initialization (`PI`) pipeline from motherboard SPI flash: Security (`SEC`), Pre-EFI Initialization (`PEI`), Driver Execution Environment (`DXE`), and Boot Device Selection (`BDS`) [1]. Because `LoadImage()` signature enforcement lives inside `DXE`, UEFI Secure Boot assumes `SEC`, `PEI`, and `DXE` firmware volumes in SPI flash have not been modified. Enterprise servers and modern client systems anchor those pre-UEFI stages in immutable silicon fuses via `Intel Boot Guard` (which verifies an Authenticated Code Module and the OEM Initial Boot Block against Field Programmable Fuses before releasing x86 cores) or `AMD Platform Secure Boot` (`PSB`, verified on the on-die AMD Secure Processor) [1, 18].

Within `DXE`, Secure Boot policy is governed by four authenticated NVRAM variables carrying the `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute (`PK`, `KEK`, `db`, `dbx`) [1]. Any call to `SetVariable()` mutating these stores must wrap the new `EFI_SIGNATURE_LIST` payload inside a `EFI_VARIABLE_AUTHENTICATION_2` descriptor signed via PKCS#7 with a strictly monotonic `EFI_TIME` timestamp by an authority higher in the hierarchy (`PK` signs `KEK`; `PK` or `KEK` signs `db` and `dbx`). During `BDS`, `LoadImage()` computes the target binary's PE/COFF Authenticode SHA-256 digest (skipping the PE Optional Header `CheckSum`, the Certificate Table directory entry, and the trailing `WIN_CERTIFICATE` PKCS#7 blob [8]) and enforces denylist precedence: if the binary hash or any certificate in its signing chain matches `dbx`, loading aborts immediately with `EFI_SECURITY_VIOLATION`; otherwise, `LoadImage()` admits the image only if its hash or signing chain matches an entry in `db` [1].

### `shim.efi`, `SHIM_LOCK`, and the `MokList` / `MokListRT` Split

To bridge Microsoft's `Microsoft Corporation UEFI CA` in `db` to independent Linux distributions, Red Hat and the Linux community created `shim` (`shimx64.efi` on x86_64, `shimaa64.efi` on ARM64), a deliberately minimal UEFI application containing a stripped Cryptlib/OpenSSL X.509 verifier, PE loader, and embedded vendor certificate (`vendor_cert` / `vendor_db`) [11, 16]. Microsoft's review board audits each distribution's `shim` build (verifying reproducible build provenance, embedded HSM-backed CA policy, and current `SBAT` metadata [16]) and signs `shim.efi` under the Microsoft third-party UEFI CA.

![Figure: UEFI Secure Boot trust delegation from firmware dbx/db through Microsoft-signed shim.efi, boot-services-only MokList mirrored to MokListRT, and second-stage GRUB2 or UKI loading into the Linux kernel.](diagrams/01-shim-mok-trust-chain.svg)

When UEFI `BDS` invokes `shim.efi`, `shim` cannot rely on firmware `LoadImage()` alone to verify `grubx64.efi` or `vmlinuz`, because firmware `db` knows nothing about Fedora's, Ubuntu's, or Debian's signing keys. Instead, `shim` implements its own PE Authenticode verifier (`verify_buffer()`) and installs a UEFI protocol GUID (`SHIM_LOCK_GUID`, `605dab50-e046-4300-abb6-3dd810dd8b23`) exposing a function pointer `shim_lock->Verify(buffer, size)` to downstream loaders [11, 17]. Simultaneously, modern `shim` (`v15.8+`) hooks or overrides the UEFI Boot Services security architectural protocol so any nested `LoadImage()` call issued by `systemd-boot` or `GRUB2` transparently routes through `shim`'s expanded trust and revocation checks [11].

How does `shim` allow local administrators or developers to sign custom kernels and `DKMS` modules without possessing an `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` `KEK` private key? Through Machine Owner Keys (`MOK`), engineered around a crucial UEFI variable attribute asymmetry [11, 50]:

```c
/* Simplified UEFI variable attribute split enforced by shim (shim.c / mok.c) */
#define MOK_NV_ATTR  (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define MOK_RT_ATTR  (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)
```

Notice the absence of `EFI_VARIABLE_RUNTIME_ACCESS` on the persistent `MokList`, `MokListX` (MOK denylist), and `SbatLevel` variables! Once the Linux kernel invokes `ExitBootServices()`, UEFI firmware completely hides every variable lacking `RUNTIME_ACCESS` from the running operating system (`efivarfs` under `/sys/firmware/efi/efivars` cannot read or write `MokList` or `SbatLevel`) [1, 11]. Consequently, an attacker who achieves `UID 0` in Linux userspace *cannot* directly append a rogue X.509 certificate into `MokList`. Instead, userspace `mokutil --import key.der` writes a staging variable `MokNew` (which *does* carry `RUNTIME_ACCESS` alongside an SHA-256 salted password hash). On the next reboot, `shim` runs *before* `ExitBootServices()`, detects `MokNew`, and launches `MokManager.efi` (`mmx64.efi`) on the local UEFI console, requiring a human at the keyboard to prove physical presence by typing the enrollment password before `MokManager` copies the certificate into boot-services-only `MokList` [11]. Before handing off to the OS, `shim` copies `MokList` and `MokListX` into *volatile* (non-`NON_VOLATILE`) runtime-readable mirror variables named `MokListRT` and `MokListXRT`. During kernel boot, `certs/load_uefi.c` reads `MokListRT` to populate the `.machine` keyring ([Chapter 5](05-kernel-lockdown-modules.md)), while any runtime write attempt to `MokListRT` either fails or vanishes harmlessly on reboot [50].

### `GRUB2` Verifiers, `BootHole`, and `.sbat` Generation Revocation

Once `shim` authenticates `grubx64.efi`, `GRUB2` itself becomes an active operating environment containing filesystem drivers (`ext2`, `xfs`, `btrfs`, `fat`), network stacks (`tftp`, `http`), font and image decoders, and a Turing-complete shell interpreter parsing `/boot/grub/grub.cfg` [13, 17]. If `GRUB2` loaded arbitrary unsigned `insmod` modules or jumped to unsigned kernels when `SecureBoot = 1`, `GRUB2` would act as a universal Secure Boot bypass. Modern `GRUB2` (`2.06+`) therefore activates its internal `grub_verifier` framework (`grub-core/commands/efi/shim_lock.c`), locking down dangerous commands (`iorw`, `memrw`, custom `acpi` table injection, legacy unverified `linux16`), forbidding unsigned dynamic `GRUB` modules (baking required modules into the signed monolithic `grubx64.efi` core image), and passing every kernel image read by the `linux` command back through `shim_lock->Verify()` [17].

In July 2020, Eclypsium researchers disclosed `BootHole` (`CVE-2020-10713`), exposing a catastrophic flaw in that model [13]. An integer overflow in `grub_script_yyparse()` while parsing crafted tokens in the unauthenticated text file `grub.cfg` triggered a heap buffer overflow inside `grubx64.efi` *before* `GRUB2` ever called `shim_lock` to verify `vmlinuz`. Any attacker with root access to modify `/boot/efi/EFI/<distro>/grub.cfg` gained arbitrary Ring 0 pre-OS code execution under active Secure Boot. Worse, `BootHole` revealed a structural crisis in UEFI revocation [12, 13]. Because every Linux distribution, point release, and derivative compiled its own `grubx64.efi` signed by its own vendor sub-CA, hundreds of distinct vulnerable Microsoft-chained `shim` and vendor-signed `GRUB2` binaries existed in the wild. Revoking every distribution's CA in UEFI `dbx` would invalidate existing retail install ISOs, while adding 200+ 32-byte `EFI_CERT_SHA256_GUID` digests (each consuming 48 bytes in `EFI_SIGNATURE_DATA`) consumed nearly a third of the entire 32 KiB NVRAM `dbx` budget available on many motherboards [12].

![Figure: Why hash-based UEFI dbx revocation failed to scale during BootHole (CVE-2020-10713) and how SBAT (.sbat PE metadata compared against the boot-services-only SbatLevel variable) achieves constant-space generation revocation.](diagrams/01-sbat-vs-dbx-revocation.svg)

To eliminate $O(N_{\text{binaries}})$ NVRAM bloat permanently, Linux and Microsoft co-designed `UEFI Secure Boot Advanced Targeting` (`SBAT`) [12]. Every Secure-Boot-signed PE binary (`shim`, `GRUB2`, `systemd-boot`, `UKI`, `fwupd`) now embeds an Authenticode-covered `.sbat` PE section formatted as UTF-8 CSV records declaring its upstream component lineage and monotonically increasing *security generation* integers [12]:

```text
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.12,https://www.gnu.org/software/grub/
grub.fedora,3,The Fedora Project,grub2,2.12-10.fc41,https://fedoraproject.org/
```

Correspondingly, `shim` maintains a boot-services-only non-volatile variable `SbatLevel` (mirrored to `SbatLevelRT` for OS inspection) holding minimal generation floors such as `sbat,1,2024010900\nshim,4\ngrub,4\n` (under 100 bytes total!) [12]. Formally, let $C(B) = \{(c_i, g_i)\}$ denote the set of `(component_name, generation)` pairs inside binary $B$'s `.sbat` section, and let $R = \{(c_j, g^{\min}_j)\}$ denote the floors recorded in `SbatLevel`. During `verify_buffer()`, `shim` enforces the predicate:

$$\operatorname{SBAT\_Valid}(B, R) \iff C(B) \neq \emptyset \;\land\; \forall (c, g) \in C(B),\; \forall (c, g^{\min}) \in R:\; g \ge g^{\min}$$

If a candidate binary lacks a `.sbat` section altogether or declares `grub,3` when `SbatLevel` demands `grub,4`, `shim` rejects it immediately with `EFI_SECURITY_VIOLATION` across *every* vendor simultaneously, using fewer than twenty bytes of flash storage [12]. When `shim` itself runs, it automatically ratchets `SbatLevel` forward to its compiled-in conservative baseline (`SbatPolicy = Automatic`) whenever the on-flash timestamp is older, while updates delivered via `fwupd` or OS updates advance `SbatLevel` to the latest revocation epoch without touching `dbx` unless an ancient pre-SBAT (`shim <= 15.2`) binary itself requires hash revocation.

## Distro, Immutable-OS, & Cloud Trade-Offs

Across mutable enterprise distributions (`RHEL 9/10`, `Ubuntu 22.04/24.04 LTS`, `Debian 12/13`, `SUSE`), the standard `shim` $\to$ `GRUB2` $\to$ `vmlinuz` chain optimizes for hardware compatibility and dual-boot coexistence with Windows on retail OEM firmware [11, 15]. Leaving `MokManager` available allows enterprise operators to sign proprietary third-party `.ko` modules (`NVIDIA`, EDR kernel sensors) under an organization-owned MOK key without disabling Secure Boot, at the cost of keeping `GRUB2`'s 300,000-line parser stack inside the pre-OS TCB and leaving `grub.cfg` plus locally built `initramfs` images outside Authenticode coverage unless paired with UKIs ([Chapter 2](02-uki-systemd-pcrlock.md)).

Immutable container operating systems (`Talos Linux`, `Bottlerocket`, `Flatcar`, and UKI-configured `Fedora CoreOS`) aggressively prune this surface [10, 34, 35]. By eliminating `GRUB2` completely in favor of `systemd-boot` (roughly one-tenth the code size, possessing no script interpreter, no filesystem drivers beyond UEFI's own `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`, and no network stack) or invoking a signed `UKI` directly from `shim.efi` (or directly from UEFI `BDS`), immutable builds strip complex parsers out of Ring 0 boot services [19, 34]. On dedicated bare-metal appliances and hyperscale cloud instances (`AWS Nitro` UEFI, `GCP Shielded VMs`, `Azure Trusted Launch`), platform owners frequently go one step further: replacing Microsoft's `PK`, `KEK`, and `db` entirely with fleet-specific X.509 keys via `systemd-boot` auto-enrollment (`loader/keys/auto/*.auth`) or `sbctl` [1, 20]. Enrolling a custom `PK` and omitting `Microsoft Corporation UEFI CA` eliminates exposure to third-party UEFI bootloader or Option ROM vulnerabilities across the rest of the PC ecosystem, provided no physical PCIe card on a bare-metal server requires Option ROM execution signed by Microsoft's third-party CA [16].

## Seam Failures, CVEs, & Structural Bounds

Real-world Linux Secure Boot failures demonstrate how parser complexity inside pre-OS loaders, subtle UEFI variable-persistence bugs, and cross-OS revocation coordination break otherwise sound Authenticode cryptography.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| BootHole (`CVE-2020-10713`) | 2020 | `GRUB2` `grub.cfg` parser | Untrusted `grub.cfg` cannot subvert signed `grubx64.efi` | Integer overflow in `grub_script_yyparse` triggers heap corruption and arbitrary pre-OS code execution | Patch `GRUB2` allocator bounds and introduce `.sbat` / `SbatLevel` generation revocation [12, 13] |
| Font / Image Bugs (`CVE-2022-2601`, `CVE-2021-3695`) | 2022 | `GRUB2` `pf2` font & PNG decoders | Graphical boot theme assets on ESP are benign data | Crafted `.pf2` `glyf` font or PNG dimensions overflow `grub_malloc` buffers inside `DXE` privilege | Harden `GRUB2` theme parsers, bump `grub,3` / `grub,4` `SBAT`, or remove `GRUB2` via `UKI` [12, 17] |
| `shim` HTTP Boot RCE (`CVE-2023-40547`) | 2023-2024 | `shim.efi` `httpboot.c` | Network HTTP headers parsed prior to signature check are bounded | MitM / rogue PXE HTTP server returns chunked response exceeding `rx_buf`, achieving pre-verifier RCE | Patch `shim 15.8`, add old `shim` hashes to `dbx`, and advance `shim,4` `SBAT` floor [14] |
| PKfail (`CVE-2024-0762` / `BRLY-2024-005`) | 2024 | OEM / IBV UEFI `PK` provisioning | Production motherboards ship unique secret OEM Platform Keys | Hundreds of models shipped leaked AMI test `PK` ("DO NOT TRUST"), letting local root sign arbitrary `db`/`dbx` updates | Flash OEM UEFI capsule provisioning a hardware-vendor-unique `PK` [18] |
| Windows / Linux `SBAT` Dual-Boot Lockout (`KB5041595`) | 2024 | Shared `SbatLevel` NVRAM across dual-boot OSes | Windows Update only applies `SBAT` bumps to single-boot machines | August 2024 Windows update wrote `shim,4` / `grub,3` into `SbatLevel`, blocking older Linux ISOs and `Ubuntu`/`Mint` `shim 15.7` setups | Upgrade distro `shim >= 15.8`, or reset `SbatPolicy` (`mokutil --set-sbat-policy delete`) before re-applying [15] |

Two structural lessons stand out across this failure history. First, *any parser executing before cryptographic verification inherits adversarial inputs directly*. In `CVE-2023-40547` (scored CVSS 9.8 by MSRC [14]), `shim.efi`'s HTTP boot client parsed remote HTTP response headers to download the next-stage image *before* `verify_buffer()` could check its signature; an adjacent network attacker or compromised DHCP relay gained Ring 0 execution inside a genuine Microsoft-signed `shim` binary, forcing an emergency `dbx` hash revocation because `shim` is the root evaluator of `SbatLevel` and cannot revoke itself via `SBAT` when `shim` is the first binary loaded by firmware [12, 14]. Second, the August 2024 `KB5041595` incident underscored that `UEFI` NVRAM is a *shared global state bus* across every OS on a disk: when Windows Update wrote an updated `SbatLevel` floor intended to close `CVE-2022-2601` (`shim` < `15.8`), dual-boot workstations running older Linux distributions or stale live-recovery USB sticks hit immediate `Verifying shim SBAT data failed: Security Policy Violation` aborts at `BDS` [15]. Finally, UEFI Secure Boot and `SBAT` possess an explicit theoretical ceiling: they authenticate *executable code entry*, not unmeasured configuration files, `initramfs` archives, or post-boot memory writes. Closing the `initramfs` and command-line gap requires binding all early-boot inputs into a single signed `Unified Kernel Image` paired with `TPM 2.0` PCR policies ([Chapter 2](02-uki-systemd-pcrlock.md)).

## Inspecting on a Live Linux Host

Verify whether UEFI Secure Boot is currently active in `User` / `Deployed` mode and inspect `shim`'s MOK enforcement state via `mokutil` and `bootctl`:

```bash
mokutil --sb-state
bootctl status 2>/dev/null | head -n 18
```

Inspect the certificates currently enrolled in firmware `db`, the count of revoked `dbx` hashes/certificates, and any local Machine Owner Keys mirrored into `MokListRT`:

```bash
mokutil --db | grep -E "Subject:|Issuer:" | head -n 10
mokutil --dbx | grep -c "SHA-256"
mokutil --list-enrolled | grep -E "Subject:|Valid"
```

Read the active `SBAT` revocation floor from the runtime mirror variable `SbatLevelRT` and inspect the `.sbat` metadata compiled into the installed `shim` or `GRUB2` EFI binary:

```bash
mokutil --list-sbat-revocations
objcopy -O binary --only-section=.sbat /boot/efi/EFI/*/shimx64.efi /dev/stdout 2>/dev/null
```

Check whether the platform `PK` carries a test/placeholder subject (`PKfail` `DO NOT TRUST` indicator):

```bash
mokutil --pk | grep -E "Subject:|Issuer:"
```
