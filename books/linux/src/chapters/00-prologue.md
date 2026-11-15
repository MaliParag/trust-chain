# Prologue

## Composable Mechanisms and the Seam Between Them

Inspect a classic enterprise Linux server running `UEFI Secure Boot`, and ask what cryptographic guarantee actually holds between firmware `LoadImage()` and the moment `sshd` accepts its first connection. On a traditionally configured distribution, `UEFI` verifies Microsoft-signed `shim.efi`, `shim` verifies the vendor's `GRUB2` and `vmlinuz` kernel image, and verification stops cold: `GRUB2` loads an unauthenticated `initramfs` CPIO archive off an unencrypted `/boot` partition, executes shell scripts inside it as `UID 0`, and pivots into a mutable root filesystem [1]. Every individual component functions as documented, yet an attacker with offline disk access drops a two-line hook into `initramfs` and captures the `LUKS` passphrase at the next reboot without touching Secure Boot keys.

*The Linux Trust Chain* is about how modern Linux closes those integration seams from reset vector to multi-tenant cloud silicon, and why assembling a coherent chain out of independent open-source subsystems creates failure modes fundamentally different from Windows or Apple platforms.

### From Mutable Distros to Image-Based Verified Systems

Modern Linux engineering (`systemd` `Unified Kernel Images`, `SBAT`, `dm-verity`, `IMA`, `Landlock`, and `COCONUT-SVSM`) systematically replaces ad-hoc boot scripts and mutable root filesystems with measured, signed artifacts [1, 2, 3]. Packing the kernel, kernel command line, `initrd`, and `.sbat` metadata into a single Authenticode-signed PE binary (`UKI`) lets `UEFI` verify the entire pre-userspace payload in one pass while `systemd-stub` binds phase-specific `TPM 2.0` policies (`PCR[11]` signed policies via `systemd-pcrlock`) so secrets unseal only to authorized boot phases [1]. Above block storage, `dm-verity` pins immutable `/usr` trees to a root Merkle hash, while stacked Linux Security Modules (`SELinux`, `AppArmor`, and unprivileged `Landlock`) plus `Kernel Lockdown` prevent even `UID 0` from mutating running Ring 0 code [2].

### Shared-Kernel Density and Supply-Chain Trust

At the cloud and container layer, Linux carries a unique burden: millions of untrusted multi-tenant containers and AI jobs share host kernels guarded by `namespaces`, `cgroups v2`, and `seccomp-BPF` syscall filters. Whenever an attacker triggers a kernel memory bug in `io_uring`, `netfilter`, or the `eBPF` verifier (`Dirty Pipe`), `user_namespaces` amplify unprivileged container code into host Ring 0 compromise, motivating hardware/user-space boundaries such as `Firecracker`, `Kata Containers`, and `gVisor`. And as the March 2024 `XZ Utils` (`CVE-2024-3094`) backdoor proved [4], even an intact hardware and kernel chain snaps if a patient adversary subverts maintainer trust upstream and injects pre-authentication `RSA` hooks into `sshd` via build-time test blobs.
