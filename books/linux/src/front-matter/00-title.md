# The Linux Trust Chain

## From UEFI, Unified Kernel Images, and dm-verity Through LSMs, eBPF, and Containers to Confidential Cloud

**Parag Mali**

---

Unlike Windows or Apple platforms, Linux has no single vendor root key, no monolithic userland, and no single deployment shape: the same kernel family powers developer laptops, immutable `ostree` / `systemd-sysext` appliances, hyperscale `Kubernetes` nodes, and `AMD SEV-SNP` / `Intel TDX` confidential cloud guests. Historically, that modularity left a gaping hole right across early boot: `UEFI` verified `shim` and `vmlinuz`, while an unencrypted, unsigned `initramfs` and mutable `/etc` allowed physical or root-fs attackers to hijack execution before userspace ever started [1]. Modern Linux closes that gap through a composable chain: `SBAT` generation revocations, signed `Unified Kernel Images` (`UKIs`) measured into `TPM 2.0` `PCR[11]` (`systemd-stub` / `systemd-pcrlock`), `LUKS2` + `dm-verity` and `fs-verity` Merkle trees, `Kernel Lockdown` and stacked `Linux Security Modules` (`SELinux`, `AppArmor`, `Landlock`) [2], `eBPF` verifier mediation, `user_namespaces` + `seccomp-BPF` / microVM sandboxes, `SPIFFE`/`SPIRE` workload attestation, and `COCONUT-SVSM` paravisors [3].

### Planned Architecture of Volume III

| Section | Chapters | Scope |
|---|---|---|
| Opening | [Prologue](../chapters/00-prologue.md) | Why composable open-source primitives create extraordinary flexibility alongside acute integration-seam fragility |
| Part I · Verified Boot & Immutable Root | Chapters 1 to 4 (In Preparation) | 1. `UEFI`, `shim`, `MOK`, and `SBAT` Revocation (`BootHole`) · 2. Closing the Initramfs Gap: `Unified Kernel Images` (`UKI`), `systemd-stub`, and `systemd-pcrlock` (`TPM 2.0` `PCR[11]`) · 3. Block and File Integrity: `LUKS2`, `dm-verity` Merkle Trees, and `fs-verity` · 4. Runtime Measurement and Appraisal: `IMA` / `EVM` and `Keylime` Remote Attestation |
| Part II · Kernel Integrity, LSMs, & eBPF | Chapters 5 to 8 (In Preparation) | 5. `Kernel Lockdown` (`integrity` vs. `confidentiality`), Signed Modules, and `kexec` Gates · 6. Kernel Memory Defenses: `KASLR`, `KCFI` / `FineIBT`, `KFENCE`, and Rust-for-Linux · 7. Stacked Linux Security Modules: `SELinux`, `AppArmor`, and Unprivileged `Landlock` · 8. The `eBPF` Verifier Dual Edge: `LSM-BPF` Security Enforcement (`Tetragon`/`Falco`) vs. Verifier Escape Primitives |
| Part III · Userspace Privilege & Credentials | Chapters 9 to 12 (In Preparation) | 9. `POSIX` Capabilities, Ambient Sets, and the `user_namespaces` Attack Surface · 10. Privilege Brokers: `sudo`, `Polkit`, `systemd` Service Sandboxing, and `D-Bus` · 11. Kernel Keyrings (`keyctl`), `systemd-creds`, and `TPM2` PKCS#11 Custody · 12. Pluggable Authentication (`PAM`), `SSSD` / Kerberos, SSH Certificates, and `pam_u2f` Passkeys |
| Part IV · Containers, Workloads, & Cloud Silicon | Chapters 13 to 15 (In Preparation) | 13. Why Containers Are Not VMs: `namespaces`, `cgroups v2`, `seccomp-BPF`, and `io_uring` / `Dirty Pipe` Escapes · 14. Sandboxed Runtimes and MicroVMs: `gVisor`, `Firecracker`, and `Kata Containers` · 15. `SPIFFE`/`SPIRE` Workload Identity and Linux Confidential VMs (`COCONUT-SVSM`, `SEV-SNP`, and `TDX`) |
| Finale | Chapter 16 (In Preparation) | 16. Upstream Supply-Chain Compromise: The `XZ Utils` (`liblzma` / `CVE-2024-3094`) `sshd` Backdoor and Reproducible Distro Trust |

Begin with the [Prologue](../chapters/00-prologue.md) or review [References](../back-matter/70-references.md).
