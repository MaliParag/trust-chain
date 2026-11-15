# Unified Kernel Images, systemd-stub, and TPM2 PCR Policies

## Overview

* **Link in the Chain:** Bridges pre-OS UEFI/shim signature verification ([Chapter 1](01-uefi-shim-sbat.md)) to early userspace (`initrd`) and unattended `LUKS2` disk decryption ([Chapter 3](03-luks2-verity.md)), sealing the classic unsigned-`initramfs` and mutable-command-line gap.
* **Core Security Invariant:** Firmware and `shim` authenticate a single Portable Executable (`UKI`) encompassing `systemd-stub`, `vmlinuz`, `.initrd`, and `.cmdline`, while `systemd-stub` and `systemd-pcrphase` extend cryptographic digests and boot-phase barriers into `TPM 2.0` `PCR[11]` so sealed disk secrets unseal exclusively to vendor-signed images inside the `enter-initrd` window and under `systemd-pcrlock`-authorized platform measurements.
* **Deployment Profile Matrix:** Traditional mutable distros still default to host-generated unsigned `/boot/initramfs-*.img` CPIO archives (with optional `UKI` opt-in on Fedora/RHEL 9.4+/Ubuntu 24.04+); immutable OSes (`Talos`, `Flatcar`, `UKI`-profile `CoreOS`) ship vendor-signed UKIs exclusively; Confidential VMs (`SEV-SNP` / `TDX` in [Chapter 18](18-confidential-vms-svsm.md)) measure UKIs into hardware launch digests or `COCONUT-SVSM` `vTPM` `PCR[11]`.
* **Trusted Computing Base (TCB):** UEFI firmware and `TPM 2.0` (discrete chip, firmware `fTPM`, or `SVSM` `vTPM`), `systemd-stub`, `ukify` / vendor PCR policy signing keys (`.pcrpkey`), `systemd-pcrlock` NV-index pin and event-log parser, and early `initrd` unlock units (`systemd-cryptsetup`).
* **Integration Seam & Handoff:** Delivers an Authenticode-verified kernel, immutable command line (`roothash=`, `lockdown=integrity`),verified `initrd`, and phase-locked `TPM 2.0` volume key to [Chapter 3](03-luks2-verity.md), leaving block/file Merkle verification and post-pivot runtime execution enforcement to [Chapters 3](03-luks2-verity.md) and [4](04-ima-ipe-keylime.md).

## Problem Statement & Threat Model

For over a decade after mainstream Linux distributions enabled `UEFI Secure Boot`, a glaring architectural hole split early boot directly in half [10]. Even when `UEFI`, `shim.efi`, and `GRUB2` verified the compressed kernel image (`/boot/vmlinuz-*`) cleanly, `GRUB2` next loaded two completely unauthenticated artifacts from the unencrypted `/boot` or `ESP` partition: the kernel command line (`cmdline` inside `grub.cfg`) and the initial RAM filesystem (`initramfs-*.img`) [10, 19]. Why did distributions leave `initramfs` unsigned? Because tools such as `dracut`, `mkinitramfs`, and `mkinitcpio` assembled `initramfs` *locally on every end-user machine* during `apt` or `dnf` kernel post-install hooks, baking host-specific `/etc/crypttab`, `/etc/mdadm.conf`, storage drivers, and microcode into a bespoke CPIO archive that the upstream distribution's offline HSM could obviously never sign [10].

Under an offline physical attacker ("Evil Maid") or a transient boot-partition tamper model, that unauthenticated `initramfs` destroys both verified boot and full-disk encryption simultaneously [10, 27]. Inside Linux's boot sequence, the kernel unpacks `initramfs` into an initial `rootfs` in RAM and executes `/init` as `UID 0` *before* unlocking the encrypted `LUKS2` root volume. An attacker who steals or accesses a powered-off laptop in a hotel room for sixty seconds mounts the unencrypted `/boot` partition, unpacks `initramfs`, inserts a five-line keylogger hook into `systemd-ask-password` or `cryptsetup` (exfiltrating the user's passphrase or decrypted volume master key on the subsequent boot), repacks the CPIO archive, and powers the laptop off. On reboot, UEFI reports `SecureBoot = 1`, `shim` and `GRUB2` verify `vmlinuz`, and the trojanized `initramfs` runs with full Ring 3 root authority while the kernel command line remains equally exposed to injected parameters such as `init=/bin/sh` or `systemd.debug_shell=1` [10, 20].

Attempts to paper over that seam by sealing `LUKS2` decryption keys directly to static `TPM 2.0` PCR hashes (`PCR[0,2,4,7,9]`) via legacy scripts (`clevis` raw PCR pins or manual `tpm2_createpolicy`) created two opposite failures [22, 23, 25]. First, if `PCR[9]` (`initrd` measurement) or `PCR[4]` (bootloader/kernel digest) was omitted so routine `apt upgrade` kernel updates would not lock the machine out of its disk, then an Evil Maid attacker could swap in an older signed Ubuntu LiveCD kernel + arbitrary `initramfs`, satisfy `PCR[7]` (same Secure Boot CA!), unseal the `LUKS2` key automatically into RAM, and read the entire disk without knowing any passphrase [10, 24]. Second, if `PCR[4]` and `PCR[9]` *were* pinned statically, every routine security update to `vmlinuz`, `shim`, or `fwupd` UEFI firmware invalidated the static PCR digest and threw headless servers or remote laptops into emergency recovery prompts. Closing the early-boot chasm required unifying the kernel, `initrd`, and command line into a single vendor-signable binary *and* replacing static PCR hash pinning with signed `TPM 2.0` authorization policies plus phase barriers so unsealed keys vanish from TPM reachability before untrusted userspace ever starts [19, 20, 22, 23].

## Kernel & Userspace Mechanics

### Unified Kernel Images (`UKI`) and `systemd-stub`

Standardized by the UAPI Group [19] and built via `ukify(1)` [26], a `Unified Kernel Image` (`UKI`) eliminates split `/boot` artifacts by linking a small UEFI boot stub (`systemd-stub`, `linuxx64.efi.stub` [20]) together with the kernel, universal `initrd`, kernel command line, OS release metadata, `.sbat` revocation metadata, and `TPM 2.0` policy public keys into a single `PE/COFF` executable stored directly in `/EFI/Linux/<id>.efi` on the EFI System Partition:

![Figure: Internal PE/COFF section layout of an Authenticode-signed Unified Kernel Image (UKI) and how systemd-stub extends section digests and monotonic boot-phase barriers into TPM 2.0 PCR[11].](diagrams/02-uki-pe-sections-pcr11.svg)

Because PE Authenticode covers every declared PE section header and payload in one signature, `UEFI` `LoadImage()` and `shim.efi` verify `.linux` (`vmlinuz`), `.initrd` (a host-generic CPIO archive discovering partitions dynamically via GPT type UUIDs [31]), `.cmdline` (for example `roothash=... lockdown=integrity`), `.osrel`, `.uname`, `.sbat`, and `.pcrpkey` atomically before `systemd-stub` executes its first instruction [19, 20]. When `SecureBoot` is enabled in firmware, `systemd-stub` strictly ignores external UEFI `LoadOptions` command-line arguments passed by `BDS` or `GRUB2`, ensuring an attacker with NVRAM or ESP access cannot append `rd.break` or `init=/bin/sh` [20]. Where legitimately signed host-specific kernel flags or devicetree blobs are needed without rebuilding the vendor `UKI`, `systemd-stub` (`v254+`) scans `/EFI/Linux/<id>.efi.extra.d/*.addon.efi` for small PE *UKI Addons* carrying `.cmdline` or `.dtb` sections and verifies their Authenticode signatures against UEFI `db`/`shim` before merging them and measuring them into `PCR[12]` [20].

To hand the embedded `.initrd` CPIO buffer to `vmlinuz` cleanly without writing temporary files to the untrusted FAT32 ESP, `systemd-stub` installs an in-memory UEFI `EFI_LOAD_FILE2_PROTOCOL` instance attached to the `LINUX_EFI_INITRD_MEDIA_GUID` (`5568e427-68fc-4f3d-ac74-ca555231cc68`) device path and jumps into the kernel's native EFI handover entry point (`efi_pe_entry`) [20]. Inside early kernel startup (`drivers/firmware/efi/libstub/`), Linux locates `LINUX_EFI_INITRD_MEDIA_GUID`, reads the verified `.initrd` bytes directly from RAM, and measures them into `PCR[9]` prior to `ExitBootServices()` [21].

### `PCR[11]` Section Measurements and Phase-Locked Secret Windows

Before jumping into `.linux`, `systemd-stub` performs a deterministic measurement sweep across every payload section in canonical alphabetical order (`.cmdline`, `.dtb`, `.initrd`, `.linux`, `.osrel`, `.pcrpkey`, `.profile`, `.sbat`, `.splash`, `.uname`), extending both the section name and the section's `SHA-256` payload digest into `TPM 2.0` `PCR[11]` [20, 21, 22]. Crucially, `PCR[11]` does not stop changing once the kernel boots! Instead, `systemd-pcrphase.service` treats `PCR[11]` as a *cryptographic state-machine clock*, extending ASCII phase-transition strings at well-defined milestones along the `systemd` boot dependency graph [20, 22]:

$$\begin{aligned}
\text{PCR}[11]_{\text{stub}} &= \operatorname{ExtendChain}\!\left(0^{256},\; (\text{`.cmdline`}, \dots, \text{`.uname`})\right) \\
\text{PCR}[11]_{\text{initrd}} &= \operatorname{SHA-256}\!\left(\text{PCR}[11]_{\text{stub}} \;\parallel\; \operatorname{SHA-256}(\texttt{"enter-initrd"})\right) \\
\text{PCR}[11]_{\text{root}} &= \operatorname{SHA-256}\!\left(\text{PCR}[11]_{\text{initrd}} \;\parallel\; \operatorname{SHA-256}(\texttt{"leave-initrd"})\right)
\end{aligned}$$

Followed in userspace by `"sysinit"`, `"ready"` (multi-user target reached), and `"shutdown"` [21, 22]. Consider what happens when `systemd-cryptenroll` seals the root `LUKS2` volume key specifically to the $\text{PCR}[11]_{\text{initrd}}$ digest (`enter-initrd` phase)! During `initrd` execution, `PCR[11]` equals $\text{PCR}[11]_{\text{initrd}}$, so `systemd-cryptsetup` can unseal the `LUKS2` master key from the `TPM 2.0`, unlock `/dev/mapper/root`, and zero its userspace buffer. Before `initrd` pivots (`systemctl switch-root`) into the main OS root filesystem where network daemons, containers, or user sessions run, `systemd-pcrphase-initrd.service` extends `"leave-initrd"` into `PCR[11]` [20, 22]. Because `TPM2_PCR_Extend` is cryptographically one-way, *no process in the booted operating system, not even a compromised `UID 0` daemon or Ring 0 exploit after boot, can ever coax the `TPM 2.0` into re-unsealing the `enter-initrd`-bound `LUKS2` keyslot again until the next clean hardware reboot* [2, 22]. Similarly, host-service secrets managed by `systemd-creds` ([Chapter 12](12-keyrings-systemd-creds.md)) can bind to `sysinit` so early storage helpers and late multi-user workloads sit in cryptographically disjoint TPM unseal windows.

### Signed Policies (`TPM2_PolicyAuthorize`) and `systemd-pcrlock`

How does a distribution update its `UKI` weekly without invalidating every user's `PCR[11]`-sealed `LUKS2` header? At `ukify build` time, `systemd-measure sign` pre-calculates the exact $\text{PCR}[11]$ value for each boot phase (`enter-initrd`, `sysinit`, `ready`) across `SHA-256` PCR banks, constructs the corresponding `TPM2_PolicyPCR` trial policy digest $P_{\text{phase}}$, and signs $P_{\text{phase}}$ using the vendor's RSA-2048 or ECDSA P-256 PCR policy private key $SK_{\text{pcr}}$ [22, 26]. The public half $PK_{\text{pcr}}$ sits inside the `UKI`'s `.pcrpkey` section, while the JSON array of per-phase signatures sits inside `.pcrsig` [19, 22]. When the user initially runs `systemd-cryptenroll --tpm2-device=auto --tpm2-public-key-pcrs=11`, the `LUKS2` TPM2 token embeds a `TPM2_PolicyAuthorize` policy pinned to $\operatorname{Name}(PK_{\text{pcr}})$ rather than any fixed PCR hash. Every future `UKI` signed by $SK_{\text{pcr}}$ supplies a fresh `.pcrsig` satisfying `TPM2_PolicyAuthorize` automatically!

![Figure: Combining vendor-signed PCR[11] policies (.pcrpkey/.pcrsig via TPM2_PolicyAuthorize) with local systemd-pcrlock NV-pinned PolicyOR event-log predictions to prevent both Evil-Maid downgrades and upgrade lockouts.](diagrams/02-pcrlock-signed-policy.svg)

Yet relying on vendor-signed `PCR[11]` *alone* creates a subtle fleet-wide vulnerability: if a distribution signs a single generic `UKI` booted by millions of machines, any attacker with physical access to Victim Machine A could boot *that same valid vendor-signed `UKI`* from a USB stick with custom firmware settings or attach Victim A's NVMe drive to Attacker Machine B unless the `LUKS2` policy *also* binds local machine identity and firmware/Secure-Boot state (`PCR[0..7]`) [23, 24]! Introduced in `systemd v255`, `systemd-pcrlock(8)` resolves the tension between host-specific `PCR[0..7]` binding and firmware/boot-order fragility [23]. Instead of blindly reading current raw PCR register values, `systemd-pcrlock` parses the fine-grained binary TCG Event Log (`/sys/kernel/security/tpm0/binary_bios_measurements`) into discrete component records (`000-firmware-code`, `240-secureboot-policy`, `400-secureboot-separator`, `600-gpt`, `700-action-efi-exit-boot-services`) and stores authorized variants in `/var/lib/systemd/pcrlock.d/*.pcrlock` [23]. Before a firmware capsule update (`fwupd`) or bootloader update lands on disk, `pcrlock` registers *both* the currently running component measurement and the incoming update's predicted measurement, evaluates the Cartesian product of valid component paths, folds them into hierarchical 8-branch `TPM2_PolicyOR` Merkle trees, and authorizes the new root policy inside a local `TPM 2.0` Non-Volatile (`NV`) index (`TPM2_PolicyAuthorizeNV`) protected by a PIN or monotonic generation counter [23]. Thus, the host unlocks seamlessly whether an update succeeds or rolls back, while immediately blocking downgrade to unapproved older `UKI` generations or foreign hardware.

### `systemd-cryptenroll` vs. `Clevis`

Historically, enterprise Linux servers automated unattended disk unlocking via `Clevis` (`clevis-luks-bind`), supporting either Network-Bound Disk Encryption (`Tang`, using an elliptic-curve McCallum-Relyea key exchange where a local on-LAN `Tang` server blinds and unblinds a secret point without learning the client's `LUKS` key) or a `tpm2` JWE pin [25]. While `Tang` remains valuable on legacy TPM-less rack servers inside physically guarded data centers, `Clevis`'s `tpm2` pin binds static `TPM2_PolicyPCR` digests (`-p '{"pcr_ids":"7"}'`) without `PCR[11]` phase barriers or `pcrlock` variant trees, forcing administrators either to bind `PCR[7]` alone (vulnerable to booting a signed Fedora/Ubuntu live ISO to extract the key!) or suffer reboot lockouts on updates [24, 25]. Modern deployments standardize on `systemd-cryptenroll(1)`, which natively composes signed `PCR[11]` `UKI` policies, `systemd-pcrlock` local NV policies, optional pre-boot `TPM2` PIN verification (`--tpm2-with-pin=yes`, protected against brute force by hardware `TPM 2.0` Dictionary Attack lockout counters), or `FIDO2` `hmac-secret` hardware tokens (`--fido2-device=auto`) directly inside `LUKS2` JSON token metadata [24, 27].

## Distro, Immutable-OS, & Cloud Trade-Offs

Transitioning from locally built `initramfs` archives to vendor-signed `UKI` binaries forces distributions to build a *universal* ("host-independent") `initrd` containing standard storage, filesystem, `TPM2`, and `dm-crypt`/`dm-verity` drivers, discovering root and `/usr` partitions automatically via UAPI Discoverable Partitions GPT type GUIDs rather than hardcoded `/etc/fstab` UUIDs [10, 19, 31]. Immutable distributions (`Talos Linux`, `Flatcar`, `Bottlerocket`) embraced universal `UKI` images early because their root trees are uniform across fleets [34, 35]. General-purpose distributions (`Fedora 40+` Cloud/Variants, `RHEL 9.4+` `kernel-uki-virt`, `Ubuntu 24.04+` Secure Boot UKI flavors, `Arch Linux` `mkinitcpio`/`ukify`) now offer either vendor-signed `UKI` packages (often ~60-110 MiB per `.efi` image, requiring larger `>= 1-2 GiB` EFI System Partitions!) or locally assembled UKIs signed by an operator-enrolled `MOK` / custom `db` key plus a locally held `PCR[11]` signing key [19, 26]. In public-cloud Virtual Machines (`AWS Nitro`, `Azure Trusted Launch`, `GCP Shielded VM`), virtual `TPM 2.0` state resides in hypervisor-managed storage, making `UKI` + `PCR[11]` an effective defense against guest OS persistent bootkits and offline snapshot tampering, whereas removing the cloud provider itself from the `vTPM` TCB requires Confidential VMs running `COCONUT-SVSM` in `VMPL0` ([Chapter 18](18-confidential-vms-svsm.md)) [143].

## Seam Failures, CVEs, & Structural Bounds

Even with `TPM 2.0` sealing and `UKI` packaging, real-world bypasses cluster around omitting `initrd`/phase PCRs, discrete SPI/LPC bus sniffing on client laptops, and unencrypted swap or debug shells inside `initrd`.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| Unauthenticated `initramfs` Evil Maid | 2012-2024 | Classic `GRUB2` + `/boot` CPIO | `UEFI Secure Boot` verifies the entire pre-LUKS boot chain | Offline attacker injects passphrase logger into unsigned `/boot/initramfs-*.img` | Replace split `vmlinuz`+`initrd` with Authenticode-signed `UKI` [10, 19] |
| `PCR[7]`-Only Live-ISO Unseal Bypass | 2021-2024 | `Clevis` / naive `tpm2` `PCR[7]` binding | Sealing `LUKS2` solely to `PCR[7]` proves the host OS booted | Attacker boots signed distro Live USB under identical `db` CA (`PCR[7]` unchanged) and invokes `TPM2_Unseal` | Bind signed `PCR[11]` (`enter-initrd` phase) + `systemd-pcrlock` + `PCR[15]` [22, 23, 24] |
| Discrete `TPM 2.0` SPI/LPC Bus Sniffing (`tpm-genie` / `faulTPM`) | 2018-2024 | Motherboard unencrypted `SPI`/`eSPI` bus | `TPM2_Unseal` response travels privately to CPU | Passive logic analyzer (~$50) probes discrete TPM pins during unattended `TPM`-only boot to read plaintext `LUKS2` key | Enable salted/encrypted `TPM2` parameter sessions (`CONFIG_TCG_TPM2_HMAC`, Linux 6.10+) and require pre-boot `--tpm2-with-pin=yes` [2, 24] |
| Emergency `initrd` Shell Breakout (`CVE-2016-4484` class) | 2016-2023 | `dracut` / `initramfs-tools` error handlers | Failed root mount safely drops to rescue prompt | Repeated invalid input or simulated disk timeout drops attacker into unauthenticated `UID 0` `initrd` shell while `PCR[11]` is still in `enter-initrd` | Set `rd.shell=0 rd.emergency=fail` inside signed `UKI` `.cmdline` [19, 20] |
| Rollback of Vendor-Signed `UKI` | 2023 | `TPM2_PolicyAuthorize` without NV counter | Old `SK_pcr`-signed `UKI` versions become unbootable after patching | Attacker swaps vulnerable old vendor-signed `UKI` + matching `.pcrsig` onto ESP | Pair `.pcrsig` with `SBAT` bumps and `systemd-pcrlock` `TPM2_PolicyAuthorizeNV` local generation pin [12, 23] |

> **Warning.**
> Hardware `TPM 2.0` parameter encryption (`CONFIG_TCG_TPM2_HMAC` in Linux 6.10+ and `systemd` encrypted HMAC sessions) encrypts the unsealed secret in transit across the physical `SPI`/`LPC` bus between the discrete TPM and host DRAM, defeating passive logic-analyzer sniffing. However, unattended TPM-only unlocking (`--tpm2-with-pin=no`) still deposits the decrypted `LUKS2` volume key into DRAM automatically at power-on, remaining exposed to physical cold-boot attacks, rogue `PCIe`/`Thunderbolt` DMA if IOMMU pre-boot protection fails, or active CPU interposers unless gated by an interactive `TPM2` PIN or `FIDO2` token [2, 24].

## Inspecting on a Live Linux Host

Inspect the PE/COFF sections of an installed Unified Kernel Image (or verify stub status via `ukify` / `objdump`) and check `bootctl` stub measurements:

```bash
ukify inspect /boot/efi/EFI/Linux/*.efi 2>/dev/null || objdump -h /boot/efi/EFI/Linux/*.efi 2>/dev/null
systemd-analyze pcrs 0 4 7 9 11 12 15
```

Examine the fine-grained `TPM 2.0` TCG event-log components parsed by `systemd-pcrlock` and list active `pcrlock` policy rules:

```bash
/usr/lib/systemd/systemd-pcrlock log-components 2>/dev/null | head -n 20
/usr/lib/systemd/systemd-pcrlock list-components 2>/dev/null | head -n 16
```

Verify which keyslots and `TPM 2.0` / `FIDO2` tokens (`systemd-tpm2`, `pcrlock`, `pcr11`) are enrolled inside a `LUKS2` block device header without touching volume keys:

```bash
# Replace /dev/nvme0n1p3 with your LUKS2 partition from lsblk -f
cryptsetup luksDump /dev/nvme0n1p3 2>/dev/null | head -n 40
```

Pre-calculate expected `PCR[11]` phase digests for a `UKI` binary using `systemd-measure`:

```bash
/usr/lib/systemd/systemd-measure calculate --linux=/boot/vmlinuz-$(uname -r) 2>/dev/null | head -n 12
```
