# Kernel Lockdown, Signed Modules, and kexec Gates

## Overview

* **Link in the Chain:** First post-boot Ring 0 defense in Part II; prevents a compromised or malicious `UID 0` userspace process from overwriting running kernel memory, loading unsigned `.ko` rootkits, or soft-rebooting into an unverified kernel to bypass Part I's verified boot chain.
* **Core Security Invariant:** Under `lockdown=integrity`, no userspace process (even holding all 41 POSIX capabilities) may modify running Ring 0 code or data structures except via cryptographically verified interfaces (`MODULE_SIG_FORCE` PKCS#7 modules and `kexec_file_load` PE/PKCS#7 kernels); under `lockdown=confidentiality`, userspace is additionally barred from reading arbitrary Ring 0 memory.
* **Deployment Profile Matrix:** Mainstream distros (`Fedora`, `RHEL`, `Ubuntu`, `Debian`) automatically activate `lockdown=integrity` whenever UEFI `SecureBoot = 1` while leaving `DKMS` MOK enrollment available; immutable OSes (`Talos`, `Bottlerocket`) compile monolithic or strictly `MODULE_SIG_FORCE` kernels under `lockdown=confidentiality` with legacy `kexec_load` disabled; cloud VMs frequently run `lockdown=none` unless Secure Boot is enabled in OVMF.
* **Trusted Computing Base (TCB):** Linux kernel `security/lockdown/` LSM, `kernel/module/signing.c` PKCS#7 ASN.1/X.509 parser, `.builtin_trusted_keys`, `.secondary_trusted_keys`, `.machine`, and `.blacklist` keyrings, `kexec_file_load` PE/PKCS#7 verifier, and every private key trusted to sign `.ko` modules (including any locally generated `DKMS` MOK key).
* **Integration Seam & Handoff:** Carves a formal privilege boundary between userspace `UID 0` and hardware Ring 0 across administrative APIs; leaves protection against in-kernel memory-corruption exploits (`UAF`, `ROP`) to [Chapter 6](06-kernel-memory-rust.md) and fine-grained VFS/IPC mandatory access control to [Chapter 7](07-stacked-lsms-landlock.md).

## Problem Statement & Threat Model

Throughout the first four decades of Unix and Linux history, `UID 0` (`root`) and Ring 0 (supervisor kernel mode) were treated as a single undivided trust domain [44, 49]. System administrators loaded unsigned device drivers on the fly with `insmod`, poked hardware registers directly through `/dev/mem` and `/dev/port`, overrode broken motherboard `ACPI` bytecode from userspace, inspected live kernel structures via `/dev/kcore`, and fast-rebooted into newly compiled kernels via `kexec_load(2)`. That design made perfect sense when the physical owner, the `root` administrator, and the ultimate arbiter of platform trust were all the same person sitting at a trusted workstation.

The introduction of `UEFI Secure Boot` ([Chapter 1](01-uefi-shim-sbat.md)), `TPM 2.0` `PCR[11]` phase sealing ([Chapter 2](02-uki-systemd-pcrlock.md)), `dm-verity` immutable `/usr` partitions ([Chapter 3](03-luks2-verity.md)), and remote `Keylime` attestation ([Chapter 4](04-ima-ipe-keylime.md)) shattered that equivalence [44, 49]. If `UID 0` remains synonymous with arbitrary Ring 0 code execution, then any remote root vulnerability in a network daemon or container escape instantly neutralizes Secure Boot without touching SPI flash or the EFI System Partition: the attacker simply runs `insmod rootkit.ko`, maps physical RAM via `/dev/mem` to patch out `SELinux` and `IPE`, or calls `kexec_load(2)` to soft-boot an unsigned kernel while keeping hardware `PCR[0..7]` intact! Worse, on dual-boot machines or enterprise fleets, an attacker with Linux `UID 0` could abuse kernel-level raw EFI or PCIe DMA access to subvert firmware and sibling operating systems [44].

The threat model of this chapter assumes an adversary who has *already achieved full `UID 0` (`root`) execution in Linux userspace* with a full POSIX capability set (`CapEff = 0x1ffffffffff`), whether through a `SUID` escalation, a misconfigured `sudo` rule, or a compromised privileged container. Against an omnipotent `UID 0` adversary, the kernel must defend two nested invariants: *Ring 0 integrity* (preventing `UID 0` from injecting unsigned executable code or mutating kernel data structures) and *Ring 0 confidentiality* (preventing `UID 0` from extracting cryptographic secrets such as `dm-crypt` volume master keys, kernel module signing keys, or confidential-guest memory resident inside the kernel address space) [44, 49].

## Kernel & Userspace Mechanics

### The `lockdown` LSM Lattice: `integrity` vs. `confidentiality`

Merged into mainline Linux 5.4 after seven years of contentious upstream debate (`security/lockdown/lockdown.c` [44, 49]), `Kernel Lockdown` implements a dedicated early-initialized Linux Security Module governed by a monotonic three-tier ordinal variable `kernel_locked_down`:

```c
enum lockdown_reason {
    LOCKDOWN_NONE = 0,
    LOCKDOWN_MODULE_SIGNATURE,
    LOCKDOWN_DEV_MEM,
    LOCKDOWN_KEXEC,
    LOCKDOWN_HIBERNATION,
    LOCKDOWN_PCI_ACCESS,
    LOCKDOWN_IOPORT,
    LOCKDOWN_MSR,
    LOCKDOWN_ACPI_TABLES,
    /* ... */
    LOCKDOWN_INTEGRITY_MAX,
    LOCKDOWN_KCORE,
    LOCKDOWN_KPROBES,
    LOCKDOWN_BPF_READ_KERNEL,
    LOCKDOWN_PERF,
    LOCKDOWN_TRACEFS,
    LOCKDOWN_CONFIDENTIALITY_MAX,
};
```

Across dozens of sensitive kernel subsystems, privileged entry points invoke `security_locked_down(reason)`. If `kernel_locked_down >= reason`, the hook logs a rate-limited audit notice (`Lockdown: <comm>: <reason> is restricted; see man kernel_lockdown.7`) and returns `-EPERM` unconditionally, overriding `capable(CAP_SYS_ADMIN)` and `capable(CAP_SYS_RAWIO)` [44]. Once raised via the kernel command line (`lockdown=integrity` or `lockdown=confidentiality`), via UEFI Secure Boot detection (`CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y`), or dynamically at runtime by writing to `/sys/kernel/security/lockdown`, `kernel_locked_down` can *only move upward* (`none` $\to$ `integrity` $\to$ `confidentiality`), never downward until hardware reset [44].

![Figure: How Linux Kernel Lockdown partitions UID 0 userspace away from Ring 0 across integrity mode (blocking raw memory, port/MSR/PCI writes, unsigned modules, and legacy kexec_load) and confidentiality mode (blocking kernel memory extraction via kcore, kprobes, and raw eBPF reads).](diagrams/05-uid0-ring0-lockdown-boundary.svg)

Examining the exact gates below `LOCKDOWN_INTEGRITY_MAX` reveals just how many backdoors legacy Unix left open between `UID 0` and Ring 0 [44, 48]. In `integrity` mode, the kernel blocks `/dev/mem`, `/dev/kmem`, and `/dev/port` openings; denies x86 `iopl(2)` and `ioperm(2)` raw I/O port instructions; blocks raw `PCI` BAR `mmap()` and config-space writes through `/sys/bus/pci` (which otherwise allow `UID 0` to program a NVMe or network card's bus-mastering DMA engine to overwrite physical kernel text when IOMMU allows or is reconfigured); blocks raw CPU Model-Specific Register writes (`/dev/cpu/*/msr`, preventing `UID 0` from repointing `IA32_LSTAR` syscall entry to user memory!); forbids custom `ACPI` DSDT/SSDT bytecode overrides from `initrd` or `debugfs` (`ACPI` AML bytecode runs inside the kernel's AML interpreter with arbitrary physical SystemMemory OperationRegion write access [48]); disables unverified swap hibernation (`swsusp`, because an offline or `UID 0` attacker can edit the swap partition's saved kernel image on disk prior to resume); disables dangerous kernel command-line hardware overrides (`memmap=`, `iomem=relaxed`); and mandates cryptographic verification on all loadable kernel modules and `kexec` transitions [44].

Escalating to `lockdown=confidentiality` adds read-side barriers above `LOCKDOWN_INTEGRITY_MAX` [44, 49]: `/proc/kcore` (an ELF core alias of live physical kernel RAM) is disabled; arbitrary `kprobes` and `ftrace` direct register inspection are blocked; `eBPF` helpers capable of reading arbitrary kernel addresses (`bpf_probe_read_kernel`, `bpf_probe_read_kernel_str` [77]) are rejected at load time unless restricted to safe BTF typed pointers; raw `debugfs` and `tracefs` interfaces are closed; and `perf_event_open` raw kernel instruction/register sampling is scrubbed so `UID 0` cannot siphon `LUKS2` master keys or signing secrets out of Ring 0 slab caches [44].

### Signed Kernel Modules (`PKCS#7`) and the System Keyring Hierarchy

Unlike macOS or modern appliances that disable dynamic kernel extensions outright, enterprise and workstation Linux relies heavily on loadable `.ko` ELF relocatable modules (`drivers/`, `fs/`, netfilter modules). When `CONFIG_MODULE_SIG_FORCE=y` is compiled in or `lockdown=integrity` is active, `init_module(2)` and `finit_module(2)` invoke `mod_verify_sig()` in `kernel/module/signing.c` before the kernel ELF loader ever parses a single section header of the `.ko` buffer (`elen` bytes) [45]! That ordering is critical: ELF relocation parsing in C is complex and untrusted, whereas stripping the trailing 28-byte `~Module signature appended~\n` magic marker, reading the 12-byte `struct module_signature` descriptor (`id_type = PKEY_ID_PKCS7`), and passing the raw module body plus detached `CMS`/`PKCS#7` (`SHA-256` or `SHA-512` + `RSA`/`ECDSA`/`EdDSA`) signature into `verify_pkcs7_signature()` ensures corrupted or unsigned `.ko` files fail with `-EKEYREJECTED` or `-ENOKEY` prior to ELF parsing [45].

![Figure: The Linux kernel trust keyring hierarchy (.platform, .machine, .builtin_trusted_keys, .secondary_trusted_keys, and .blacklist) governing PKCS#7 module loading and kexec_file_load verification.](diagrams/05-module-sig-kexec-pipeline.svg)

Which X.509 certificates does `verify_pkcs7_signature()` trust? Early Linux designs tossed every UEFI certificate into a single keyring, inadvertently allowing third-party UEFI bootloader keys to sign Ring 0 kernel drivers. Modern Linux (`certs/system_keyring.c` and `certs/load_uefi.c` [46, 50]) enforces a strict four-ring separation checked first against the unconditional `.blacklist` denylist keyring (populated at boot from UEFI `dbx` and `MokListXRT`):

First, `.builtin_trusted_keys` holds X.509 certificates compiled directly into read-only `vmlinux` `.rodata` at kernel build time: typically the distribution's ephemeral *per-build autogenerated signing key* (whose private half is destroyed immediately after `rpmbuild`/`dpkg-buildpackage` signs that exact kernel build's in-tree `.ko` modules, making key theft impossible!) plus the distribution's offline Secure Boot root CA [45, 46]. Second, `.secondary_trusted_keys` serves as the active runtime verification ring for `finit_module` and `kexec_file_load`; new certificates can be linked into `.secondary_trusted_keys` at runtime *only* if signed by an existing CA in `.builtin_trusted_keys` or `.machine` (`restrict_link_by_builtin_and_secondary_trusted`) [46]. Third, `.platform` imports UEFI `db` certificates solely for verifying `kexec_file_load` PE kernels and `IPE`/`dm-verity` policies, *without* automatically trusting third-party Microsoft UEFI CA certificates to load arbitrary `.ko` kernel modules [46, 50]. Fourth, `.machine` imports operator-enrolled `MokListRT` keys ([Chapter 1](01-uefi-shim-sbat.md)) and links into `.secondary_trusted_keys` when configured (`CONFIG_INTEGRITY_MACHINE_KEYRING`), enabling enterprise IT or workstation owners to sign out-of-tree `DKMS` modules while keeping firmware `db` separated [50].

### `kexec_load(2)` vs. `kexec_file_load(2)`

Linux supports rebooting directly from a running kernel into a new kernel in ~100 milliseconds without cycling through motherboard POST or UEFI `DXE` (`kexec`, heavily used for `kdump` crash-kernel capture and fast fleet upgrades) [47]. Originally, `kexec_load(2)` accepted an array of raw memory segments (`struct kexec_segment`) prepared entirely in userspace by `/sbin/kexec`: the running kernel had zero visibility into whether those raw pages came from a signed `vmlinuz` or a malicious rootkit buffer! Under `lockdown=integrity`, `kexec_load(2)` is unconditionally denied with `-EPERM` [44, 47]. Instead, callers must invoke `kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char *cmdline, unsigned long flags)` [47]: the kernel itself reads the PE `bzImage` or `UKI` from `kernel_fd` inside Ring 0, verifies its PE Authenticode or PKCS#7 signature against `.builtin_trusted_keys`, `.secondary_trusted_keys`, and `.platform` (checking `.blacklist` revocations first), carries forward the `IMA` measurement buffer (`CONFIG_IMA_KEXEC`) so `PCR[10]` attestation stays continuous, and only then stages the transition [41, 47].

## Distro, Immutable-OS, & Cloud Trade-Offs

Mutable distributions (`Ubuntu`, `Fedora`, `RHEL`) automatically enable `lockdown=integrity` under Secure Boot (leaving `confidentiality` opt-in so root administrators can still run `bpftrace` and `perf` production diagnostics) and integrate `DKMS` with `shim` `MOK`: on first install of `nvidia-driver` or `zfs-dkms`, `dkms` generates a local RSA keypair on disk (`/var/lib/shim-signed/mok/MOK.priv` on Ubuntu/Debian or `/etc/pki/akmods/private/private_key.priv` on Fedora/RPMFusion) and prompts for `MokManager` enrollment on reboot [50]. Wait: pause and trace that threat seam! While `MOK` requires physical console presence *once* during enrollment, leaving the unencrypted `MOK.priv` private key sitting in `/var/lib/` (readable by `UID 0`!) means any subsequent `UID 0` attacker on a `DKMS`-enabled workstation can simply sign `rootkit.ko` using `/var/lib/shim-signed/mok/MOK.priv` and load it cleanly through `MODULE_SIG_FORCE` and `lockdown=integrity` [50]!

Hardened servers and immutable OSes close the `DKMS` private-key loophole completely. `Talos Linux` sets `CONFIG_MODULES=n` or ships exclusively build-time ephemeral-key-signed modules with zero on-host private keys, enforces `lockdown=confidentiality`, disables `kexec` altogether (`CONFIG_KEXEC_CORE=n` or `sysctl kernel.kexec_load_disabled=1`), and sets `module.sig_enforce=1` inside the signed `UKI` `.cmdline` [34, 44, 45]. Where enterprise fleets do require custom `.ko` modules (`NVIDIA` data-center GPUs), signing is performed off-host inside an offline CI Hardware Security Module (`HSM` / `PKCS#11` `sign-file`) whose public cert resides in `.machine`, never storing signing private keys on target hosts [45, 50].

## Seam Failures, CVEs, & Structural Bounds

Real-world bypasses of post-boot kernel integrity exploit forgotten raw-hardware interfaces, locally stored `DKMS` signing keys, vulnerable vendor-signed `.ko` modules ("Bring Your Own Vulnerable Driver" on Linux), and `ASN.1`/`PKCS#7` parser bugs inside Ring 0.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `ACPI` `custom_method` / Initrd Table Override | 2017-2020 | `drivers/acpi/` AML interpreter | `ACPI` tables supply passive hardware topology data | `UID 0` injects crafted AML `SystemMemory` OperationRegion writing directly over `kernel_locked_down` in physical RAM | Block `acpi_rsdp`, initrd ACPI upgrades, and `custom_method` under `lockdown=integrity` [44, 48] |
| Local `DKMS` `MOK.priv` Key Theft | 2018-2025 | Distro `dkms` / `akmods` host key storage | `MODULE_SIG_FORCE` blocks `UID 0` from loading custom rootkits | Post-compromise `UID 0` reads `/var/lib/shim-signed/mok/MOK.priv`, runs `sign-file sha256`, and calls `finit_module()` | Sign out-of-tree modules in off-host CI HSMs or wrap host `DKMS` keys inside `TPM 2.0` (`tpm2-pkcs11`) [45, 50, 103] |
| `PKCS#7` / `X.509` Parser Bugs (`CVE-2016-2053`, `CVE-2023-39191` class) | 2016-2023 | Kernel ASN.1 BER decoder (`lib/asn1_decoder.c`) | Signature verifier rejects malformed `.ko` blobs safely | Malformed ASN.1 tags in unauthenticated module trailer trigger Ring 0 parser bugs *during* signature verification | Fuzz/harden kernel ASN.1 state machine and gate `finit_module` behind `CAP_SYS_MODULE` + `IPE` [38, 45] |
| Linux BYOVD / Vulnerable Signed `.ko` Modules | 2022-2025 | Out-of-tree vendor `.ko` (`ioctl` / `/proc` debug) | Valid vendor PKCS#7 signature implies safe Ring 0 code | Attacker loads older vendor-signed diagnostics `.ko` exposing arbitrary physical R/W `ioctl` and overwrites `cred` | Use ephemeral per-kernel build keys (old `.ko` cannot load on new kernel!) and `.blacklist` hash revocations [45, 46] |
| `io_uring` / `eBPF` Kernel Memory Extraction under `integrity` | 2021-2024 | `lockdown=integrity` without `confidentiality` | `integrity` mode protects kernel-resident secrets from `UID 0` | `UID 0` attaches `kprobe` or `bpf_probe_read_kernel` to `dm-crypt` functions and dumps live `LUKS2` master keys | Escalate servers holding high-value keys to `lockdown=confidentiality` [44, 49] |

Notice a striking architectural advantage Linux enjoys over Windows on Row 4 (*Bring Your Own Vulnerable Driver*): whereas Windows's central WHQL CA signs third-party `.sys` drivers that remain loadable across multiple OS builds until added to the Vulnerable Driver Blocklist, in-tree Linux distro modules are signed by a *throwaway key generated fresh for each kernel build* (`CONFIG_MODULE_SIG_ALL=y`) whose private half is deleted at compile end [45]! Consequently, an attacker cannot take a vulnerable in-tree `.ko` from `linux-6.1.0-10` and load it onto `linux-6.12.0-25` because `6.12`'s `.builtin_trusted_keys` does not contain `6.1`'s ephemeral key. Only long-lived CA keys enrolled in `.machine` or `.secondary_trusted_keys` create cross-version BYOVD risk, reinforcing why long-lived module CAs must be tightly audited. Even with `lockdown=confidentiality` and ephemeral module keys active, however, `Lockdown` assumes the *already-running* kernel code has no exploitable memory-corruption bugs: defending Ring 0 when a reachable syscall or driver contains a Use-After-Free or buffer overflow belongs to [Chapter 6](06-kernel-memory-rust.md).

## Inspecting on a Live Linux Host

Check the current `Kernel Lockdown` state (`[none]`, `[integrity]`, or `[confidentiality]`) and whether one-shot `kexec` or module loading has been permanently locked via `sysctl`:

```bash
cat /sys/kernel/security/lockdown 2>/dev/null; echo
sysctl kernel.modules_disabled kernel.kexec_load_disabled 2>/dev/null
```

Verify kernel compile-time module signature enforcement (`CONFIG_MODULE_SIG_FORCE`) and Lockdown Secure Boot integration in `/boot/config-*` or `/proc/config.gz`:

```bash
grep -E "CONFIG_(MODULE_SIG|LOCK_DOWN_KERNEL)" /boot/config-$(uname -r) 2>/dev/null
cat /sys/module/module/parameters/sig_enforce 2>/dev/null
```

List the X.509 certificates currently loaded into `.builtin_trusted_keys`, `.secondary_trusted_keys`, `.platform`, `.machine`, and `.blacklist` via `/proc/keys` or `keyctl`:

```bash
# Viewing system keyrings in /proc/keys requires root / run0
grep -E "^\S+.*(\.builtin|\.secondary|\.platform|\.machine|\.blacklist)" /proc/keys 2>/dev/null
```

Inspect the appended `PKCS#7` signature metadata on any installed `.ko` kernel module using `modinfo`:

```bash
modinfo $(find /lib/modules/$(uname -r) -name "*.ko*" 2>/dev/null | head -n 1) 2>/dev/null | grep -E "^sig_|^signer"
```
