# Index

## A

- `ACPI` table override lockdown: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `add_key(2)` / `keyctl(2)` kernel keyrings: [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `AEAD` disk authentication (`dm-integrity`): [**Ch. 3**](../chapters/03-luks2-verity.md)
- AI coding agent sandboxing: [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- Ambient capabilities (`CapAmb`): [**Ch. 9**](../chapters/09-capabilities-userns.md), [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `AMD Platform Secure Boot` (`PSB`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `AMD SEV-SNP` (`RMP`, `VMPL0..3`, `VCEK`): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 18**](../chapters/18-confidential-vms-svsm.md), [**Ch. 19**](../chapters/19-confidential-containers.md)
- `AppArmor` (`DFA` path mediation & `userns` gate): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `Argon2id` (`RFC 9106` KDF in `LUKS2`): [**Ch. 3**](../chapters/03-luks2-verity.md)
- `Arm CCA` (`RME`, `Realms`, `GPT`): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)
- `AT_SECURE` dynamic-linker environment scrubbing: [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `Attestation Agent` (`AA`, `CoCo`): [**Ch. 19**](../chapters/19-confidential-containers.md)
- `auditd` netlink backlog limits vs. `eBPF`: [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- Authenticode (`PE/COFF` verification): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 1**](../chapters/01-uefi-shim-sbat.md), [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)

## B

- `Baron Samedit` (`sudo` `CVE-2021-3156`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `Binder` Rust driver (`drivers/android/binder/`): [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `.blacklist` kernel keyring (`dbx` / `MokListX`): [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `BootHole` (`GRUB2` `CVE-2020-10713`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `Bottlerocket` immutable container OS: [**Ch. 3**](../chapters/03-luks2-verity.md), [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md)
- `bpf_probe_write_user` offensive abuse: [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `Bubblewrap` (`bwrap` unprivileged sandbox): [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `.builtin_trusted_keys` keyring: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)

## C

- Capabilities (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`): [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `CET` (Intel Control-flow Enforcement Technology Shadow Stack & IBT): [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `cgroups v2` unified hierarchy & `CVE-2022-0492`: [**Ch. 14**](../chapters/14-containers-escapes.md)
- `Clevis` & `Tang` vs. `systemd-cryptenroll`: [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- `CLONE_NEWUSER` (unprivileged user namespaces): [**Ch. 9**](../chapters/09-capabilities-userns.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `close_range(2)` descriptor hygiene: [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `Cloud Hypervisor` Rust VMM: [**Ch. 15**](../chapters/15-gvisor-microvms.md)
- `COCONUT-SVSM` (`VMPL0` Rust paravisor & `vTPM`): [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)
- `composefs` (`EROFS` + `fs-verity`): [**Ch. 3**](../chapters/03-luks2-verity.md)
- `Confidential Containers` (`CoCo`): [**Ch. 19**](../chapters/19-confidential-containers.md)
- `Confidential Data Hub` (`CDH`): [**Ch. 19**](../chapters/19-confidential-containers.md)
- `cosign` (`Sigstore` verification): [**Ch. 19**](../chapters/19-confidential-containers.md), [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- Credential-injecting reverse proxies: [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `CVE-2016-0728` (keyring refcount overflow): [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `CVE-2019-5736` (`runc` `/proc/self/exe` escape): [**Ch. 14**](../chapters/14-containers-escapes.md)
- `CVE-2020-8835` (`eBPF` 32-bit bounds LPE): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `CVE-2020-10713` (`BootHole` `GRUB2`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `CVE-2021-3156` (`sudo` `Baron Samedit`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `CVE-2021-3490` (`eBPF` `ALU32` `tnum` LPE): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `CVE-2021-3560` (`Polkit` D-Bus UID race): [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `CVE-2021-4034` (`PwnKit` `pkexec`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `CVE-2022-0492` (`cgroup` v1 `release_agent` escape): [**Ch. 14**](../chapters/14-containers-escapes.md)
- `CVE-2022-0847` (`Dirty Pipe`): [**Ch. 6**](../chapters/06-kernel-memory-rust.md), [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `CVE-2022-4543` (`EntryBleed` `KASLR` side channel): [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `CVE-2023-0386` (`OverlayFS` `userns` SUID copy-up): [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `CVE-2023-2163` (`eBPF` register pruning LPE): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `CVE-2023-38408` (forwarded `ssh-agent` PKCS#11 RCE): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `CVE-2023-4911` (`Looney Tunables` `glibc` `ld.so`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `CVE-2023-40547` (`shim` HTTP boot RCE): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `CVE-2024-0762` (`PKfail` untrusted Platform Key): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `CVE-2024-1086` (`Flipping Pages` `nf_tables` LPE): [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `CVE-2024-3094` (`XZ Utils` / `liblzma` backdoor): [**Prologue**](../chapters/00-prologue.md), [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `CVE-2024-6387` (`regreSSHion` OpenSSH RCE): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `CVE-2024-21626` (`Leaky Vessels` `runc` FD escape): [**Ch. 14**](../chapters/14-containers-escapes.md)
- `CVE-2024-25742` (`WeSee` `SEV-SNP` `#VC` injection): [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)
- `CVE-2025-32463` (`sudo` `chroot` `nsswitch.conf` LPE): [**Ch. 10**](../chapters/10-suid-to-run0.md)

## D

- `D-Bus` (`dbus-broker` & `SO_PEERCRED`): [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `Dirty Pipe` (`CVE-2022-0847`): [**Ch. 9**](../chapters/09-capabilities-userns.md)
- Discoverable Partitions Specification (`DPS`): [**Ch. 3**](../chapters/03-luks2-verity.md)
- `DKMS` MOK private-key risks: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `dlopen()` transitive library decoupling in `libsystemd`: [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `dm-crypt` (`AES-XTS` malleability vs. `AEAD`): [**Ch. 3**](../chapters/03-luks2-verity.md)
- `dm-integrity` journaled authentication tags: [**Ch. 3**](../chapters/03-luks2-verity.md)
- `dm-verity` block Merkle trees: [**Foundations**](../chapters/00b-foundations.md), [**Ch. 3**](../chapters/03-luks2-verity.md), [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `DynamicUser=yes` (`systemd.exec`): [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)

## E

- `eBPF` verifier, `LSM-BPF`, and escapes: [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `EntryBleed` (`CVE-2022-4543`): [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `EVM` (Extended Verification Module): [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)

## F

- `Falco` & `Tracee` ring-buffer telemetry: [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `Fedora CoreOS` & `Flatcar Container Linux`: [**Ch. 3**](../chapters/03-luks2-verity.md)
- `FIDO2` SSH resident keys (`sk-ssh-ed25519@openssh.com`): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `FineIBT` forward-edge CFI: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `Firecracker` KVM micro-VM & `jailer`: [**Ch. 15**](../chapters/15-gvisor-microvms.md), [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `fs-verity` per-file Merkle trees: [**Foundations**](../chapters/00b-foundations.md), [**Ch. 3**](../chapters/03-luks2-verity.md), [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `Fulcio` short-lived OIDC code-signing CA: [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)

## G

- `.git/hooks` & `.git/config` read-only sandbox carveouts: [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `GNOME Keyring` (`org.freedesktop.secrets`) D-Bus exposure: [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `GNU_IFUNC` (`STT_GNU_IFUNC` resolver hijack): [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `GRUB2` `shim_lock` verifier & `BootHole`: [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `gVisor` (`runsc`, `Sentry`, `systrap`, `Gofer`): [**Ch. 15**](../chapters/15-gvisor-microvms.md), [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)

## I

- `IETF RATS` (`RFC 9334` attestation architecture): [**Ch. 4**](../chapters/04-ima-ipe-keylime.md), [**Ch. 19**](../chapters/19-confidential-containers.md)
- `IMA` & `IMA-appraisal` (`PCR[10]`, `security.ima`): [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `IMDSv2` (`169.254.169.254` `PUT` token & `IP TTL = 1`): [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)
- Indirect Prompt Injection (`XPIA`): [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `Initdata` (`Confidential Containers` pod policy): [**Ch. 19**](../chapters/19-confidential-containers.md)
- `initramfs` unsigned gap: [**Prologue**](../chapters/00-prologue.md), [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- `in-toto` supply-chain attestations: [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `Intel Boot Guard`: [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `Intel TDX` (`SEAM`, `MKTME`, `S-EPT`, `#VE`): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 18**](../chapters/18-confidential-vms-svsm.md), [**Ch. 19**](../chapters/19-confidential-containers.md)
- `io_uring` exploit surface & `io_uring_disabled`: [**Ch. 9**](../chapters/09-capabilities-userns.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `IPE` (Integrity Policy Enforcement LSM, Linux 6.12+): [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)

## K

- `KASLR` & `FGKASLR`: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `Kata Containers` (`3.x` micro-VMs & `CoCo`): [**Ch. 15**](../chapters/15-gvisor-microvms.md), [**Ch. 19**](../chapters/19-confidential-containers.md)
- `KCFI` (`CONFIG_CFI_CLANG`): [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- Kernel Keyrings (`@t`, `@p`, `@s`, `@u`, `Possessor` permissions): [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `Kernel Lockdown` (`integrity` vs. `confidentiality`): [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `kexec_file_load(2)` vs. `kexec_load(2)`: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `Keylime` remote attestation: [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `KFENCE` guard-page sampling: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- Kubernetes Bound ServiceAccount OIDC Projections: [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)

## L

- `Landlock` (`ABI v1` through `v7` unprivileged sandboxing): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `Leaky Vessels` (`runc` `CVE-2024-21626`): [**Ch. 14**](../chapters/14-containers-escapes.md)
- `libkrun` (`krunvm` embedded VMM): [**Ch. 15**](../chapters/15-gvisor-microvms.md)
- `Looney Tunables` (`glibc` `CVE-2023-4911`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `LSM` hook stacking (`lsm_blob_sizes`): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md)
- `LSM-BPF` (`KRSI` / `Tetragon`): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `LUKS2` (`Argon2id`, tokens, `dm-integrity`): [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md), [**Ch. 3**](../chapters/03-luks2-verity.md)

## M

- `.machine` & `.platform` keyrings: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- Machine Owner Keys (`MokList`, `MokListRT`, `MokManager`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md), [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `memfd_create` (`F_SEAL_WRITE` in `runc`): [**Ch. 14**](../chapters/14-containers-escapes.md)
- `memfd_secret(2)` direct-map unmapping: [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- Merkle hash trees ($O(\log N)$ verification): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 3**](../chapters/03-luks2-verity.md)
- `Model Context Protocol` (`MCP`) server isolation: [**Ch. 17**](../chapters/17-ai-agent-sandboxes.md)
- `MODULE_SIG_FORCE` (`PKCS#7` signed `.ko` modules): [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- Multi-Category Security (`MCS` / `sVirt`): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 14**](../chapters/14-containers-escapes.md)

## N

- Namespaces (`mnt`, `pid`, `net`, `ipc`, `uts`, `user`, `cgroup`, `time`): [**Ch. 9**](../chapters/09-capabilities-userns.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `nf_tables` `CVE-2024-1086` (`Flipping Pages`): [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `NoNewPrivileges` (`PR_SET_NO_NEW_PRIVS`): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 10**](../chapters/10-suid-to-run0.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `NVIDIA` Confidential GPUs (`H100`/`B200` `SPDM`): [**Ch. 18**](../chapters/18-confidential-vms-svsm.md), [**Ch. 19**](../chapters/19-confidential-containers.md)

## O

- `ocicrypt` encrypted container layers: [**Ch. 19**](../chapters/19-confidential-containers.md)
- `openat2(2)` (`RESOLVE_IN_ROOT`, `RESOLVE_NO_MAGICLINKS`): [**Ch. 14**](../chapters/14-containers-escapes.md)
- OpenSSH User & Host Certificates & `9.8` `sshd-session` split: [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `OverlayFS` `CVE-2023-0386`: [**Ch. 9**](../chapters/09-capabilities-userns.md)

## P

- `PAM` (`auth`, `account`, `session`, `password` stacks): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `PCR[10]` (`IMA` runtime log): [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `PCR[11]` (`UKI` section & boot-phase binding): [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- `pidfd` (`pidfd_open`, `SO_PEERPIDFD`, `SCM_PIDFD`): [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)
- `pivot_root(2)` vs. `chroot(2)`: [**Ch. 14**](../chapters/14-containers-escapes.md)
- `PKfail` (`CVE-2024-0762`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `Polkit` (`pkexec` `PwnKit` & `CVE-2021-3560`): [**Ch. 10**](../chapters/10-suid-to-run0.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `ProtectSystem=strict` (`systemd.exec`): [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)

## R

- `ramfs` non-swappable credential delivery: [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `RANDOM_KMALLOC_CACHES`: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `RA-TLS` (Remote-Attested TLS): [**Ch. 19**](../chapters/19-confidential-containers.md)
- `regreSSHion` (`CVE-2024-6387`): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `Rekor` transparency log (`Sigstore`): [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- Reproducible Builds (`SOURCE_DATE_EPOCH`): [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `run0` & `run0 --empower` (`systemd`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `runc` container escapes: [**Ch. 14**](../chapters/14-containers-escapes.md)
- `Rust-for-Linux` safe driver abstractions: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)

## S

- `SBAT` (`.sbat` & `SbatLevel` generation revocation): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `seccomp-BPF` & `SECCOMP_RET_USER_NOTIF`: [**Foundations**](../chapters/00b-foundations.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `.secondary_trusted_keys` keyring: [**Ch. 5**](../chapters/05-kernel-lockdown-modules.md)
- `SELinux` (`FLASK`, `AVC`, Type Enforcement, `MCS`): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md)
- `shim.efi` & `SHIM_LOCK`: [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `Sigstore` (`cosign`, `Fulcio`, `Rekor`): [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `SLAB_FREELIST_HARDENED` & `SLAB_VIRTUAL`: [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `SLSA` (`v1.0` Build Level 3 provenance): [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
- `SMEP`, `SMAP`, `PXN`, & `PAN`: [**Foundations**](../chapters/00b-foundations.md), [**Ch. 6**](../chapters/06-kernel-memory-rust.md)
- `SO_PEERCRED` UNIX socket authentication: [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)
- `SPDM` Confidential GPU attestation: [**Ch. 18**](../chapters/18-confidential-vms-svsm.md), [**Ch. 19**](../chapters/19-confidential-containers.md)
- `SPIFFE` & `SPIRE` (`X.509-SVID` workload mTLS): [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)
- `SSH` agent-forwarding risks & `ProxyJump`: [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `SSSD` (Kerberos, Active Directory, & Entra OIDC): [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `struct cred` (RCU task credentials): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 6**](../chapters/06-kernel-memory-rust.md), [**Ch. 9**](../chapters/09-capabilities-userns.md)
- `sudo` vulnerabilities (`CVE-2021-3156`, `CVE-2025-32463`): [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `SUID` (`S_ISUID`) architectural hazards: [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `SWIOTLB` confidential DMA bounce buffers: [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)
- `SystemCallFilter=` & `SystemCallArchitectures=native`: [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `systemd-creds` (`LoadCredentialEncrypted=`): [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `systemd-cryptenroll`: [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md), [**Ch. 3**](../chapters/03-luks2-verity.md)
- `systemd-measure` & `systemd-pcrlock`: [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- `systemd-stub` (`PCR[11]` measurement): [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- `systemd-sysext` & `systemd-confext`: [**Ch. 3**](../chapters/03-luks2-verity.md)

## T

- `Talos Linux` immutable OS: [**Ch. 3**](../chapters/03-luks2-verity.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 13**](../chapters/13-pam-ssh-fido2.md)
- `Tetragon` (`LSM-BPF` inline enforcement): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `TIOCSTI` terminal injection (`dev.tty.legacy_tiocsti`): [**Ch. 7**](../chapters/07-stacked-lsms-landlock.md), [**Ch. 10**](../chapters/10-suid-to-run0.md)
- `tnum` (tristate numbers in `eBPF` verifier): [**Ch. 8**](../chapters/08-ebpf-dual-edge.md)
- `TOCTOU` (Time-of-Check to Time-of-Use in VFS/syscalls/IPC): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 4**](../chapters/04-ima-ipe-keylime.md), [**Ch. 8**](../chapters/08-ebpf-dual-edge.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md), [**Ch. 14**](../chapters/14-containers-escapes.md)
- `TPM 2.0` (`PCR` algebra, `PolicyAuthorize`, parameter encryption): [**Foundations**](../chapters/00b-foundations.md), [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md), [**Ch. 4**](../chapters/04-ima-ipe-keylime.md)
- `tpm2-pkcs11` hardware-bound TLS/SSH keys: [**Ch. 12**](../chapters/12-keyrings-systemd-creds.md)
- `Trustee` (`KBS` confidential key broker): [**Ch. 19**](../chapters/19-confidential-containers.md)

## U

- `UEFI` (`PK`, `KEK`, `db`, `dbx`, `LoadImage()`): [**Ch. 1**](../chapters/01-uefi-shim-sbat.md)
- `ukify(1)` & Unified Kernel Images (`UKI`): [**Ch. 2**](../chapters/02-uki-systemd-pcrlock.md)
- User namespaces (`CLONE_NEWUSER`): [**Ch. 9**](../chapters/09-capabilities-userns.md)

## V

- `Varlink` brokerless IPC: [**Ch. 10**](../chapters/10-suid-to-run0.md), [**Ch. 11**](../chapters/11-systemd-dbus-sandboxing.md)
- `#VC` & `#VE` confidential hypervisor traps: [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)
- Virtual File System (`VFS` `inode`, `dentry`, `file`): [**Foundations**](../chapters/00b-foundations.md)
- `virtio-fs` (`virtiofsd`): [**Ch. 15**](../chapters/15-gvisor-microvms.md)
- `VMGENID` snapshot CSPRNG reseeding: [**Ch. 15**](../chapters/15-gvisor-microvms.md)

## W

- `WeSee` (`CVE-2024-25742` `#VC` injection): [**Ch. 18**](../chapters/18-confidential-vms-svsm.md)

## X

- `X.509-SVID` (`SPIFFE` workload identity): [**Ch. 16**](../chapters/16-workload-identity-spiffe.md)
- `XZ Utils` (`liblzma` `CVE-2024-3094` backdoor): [**Prologue**](../chapters/00-prologue.md), [**Ch. 20**](../chapters/20-xz-supply-chain-provenance.md)
