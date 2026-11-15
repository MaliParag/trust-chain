# References

1. UEFI Forum. *Unified Extensible Firmware Interface (UEFI) Specification, Version 2.10* (2022). <https://uefi.org/specifications>
2. Trusted Computing Group (TCG). *TPM 2.0 Library Specification, Family "2.0", Level 00, Revision 01.83* (2024). <https://trustedcomputinggroup.org/resource/tpm-library-specification/>
3. Intel Corporation. *Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3: System Programming Guide* (2025). <https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html>
4. Arm Limited. *Arm Architecture Reference Manual for A-profile Architecture (DDI 0487)* (2025). <https://developer.arm.com/documentation/ddi0487/latest/>
5. Linux Kernel Documentation. *Credentials in Linux (`Documentation/security/credentials.rst`)* (2025). <https://docs.kernel.org/security/credentials.html>
6. Linux Kernel Documentation. *Overview of the Linux Virtual File System (`Documentation/filesystems/vfs.rst`)* (2025). <https://docs.kernel.org/filesystems/vfs.html>
7. Chris Wright, Crispin Cowan, Stephen Smalley, James Morris, and Greg Kroah-Hartman. *Linux Security Modules: General Security Support for the Linux Kernel*, Proceedings of the 11th USENIX Security Symposium (2002). <https://www.usenix.org/legacy/events/sec02/wright.html>
8. Microsoft Corporation. *Windows Authenticode Portable Executable Signature Format and PE Format Specification* (2024). <https://learn.microsoft.com/en-us/windows/win32/debug/pe-format>
9. Trusted Computing Group (TCG). *TCG PC Client Platform Firmware Profile Specification, Version 1.06* (2023). <https://trustedcomputinggroup.org/resource/pc-client-specific-platform-firmware-profile-specification/>
10. Lennart Poettering. *Fitting Everything Together: Verifiable OS Images, Boot, and Storage on Linux* (2022). <https://0pointer.net/blog/fitting-everything-together.html>
11. Red Hat Bootloader Team (`rhboot`). *shim: First-Stage UEFI Bootloader, Machine Owner Key (MOK) Protocol, and MokManager* (2025). <https://github.com/rhboot/shim>
12. Red Hat Bootloader Team (`rhboot`). *UEFI Secure Boot Advanced Targeting (SBAT) Specification (`SBAT.md`)* (2024). <https://github.com/rhboot/shim/blob/main/SBAT.md>
13. Jesse Michael and Mickey Shkatov (Eclypsium Research). *There's a Hole in the Boot: GRUB2 Buffer Overflow Leading to Secure Boot Bypass (BootHole, CVE-2020-10713)* (2020). <https://eclypsium.com/blog/theres-a-hole-in-the-boot/>
14. Bill Demirkapi (Microsoft Security Response Center). *Avoid Confusion When Fixing Security Bugs: Remote Code Execution in shim HTTP Boot (CVE-2023-40547)* (2024). <https://msrc.microsoft.com/blog/2024/01/avoid-confusion-when-fixing-security-bugs-cve-2023-40547/>
15. Microsoft Corporation. *August 2024 Windows Security Update (KB5041595): Applying Secure Boot Advanced Targeting (SBAT) Revocations and Dual-Boot Impact* (2024). <https://support.microsoft.com/en-us/topic/august-13-2024-kb5041595-os-builds-22621-4037-and-22631-4037-546610c5-591f-445b-8d5c-5d8194b4d204>
16. Microsoft Corporation. *Updated Microsoft UEFI CA Signing Requirements and Third-Party Bootloader Review Process* (2025). <https://techcommunity.microsoft.com/blog/hardwaredevcenter/updated-uefi-signing-requirements/1062916>
17. GNU Project. *GNU GRUB Manual 2.12: UEFI Secure Boot, Shim Lock, and Verifiers Framework* (2024). <https://www.gnu.org/software/grub/manual/grub/grub.html>
18. Binarly Research. *PKfail (BRLY-2024-005 / CVE-2024-0762): Untrusted Platform Keys Undermine Secure Boot on UEFI Ecosystem* (2024). <https://www.binarly.io/blog/pkfail-untrusted-platform-keys-undermine-secure-boot-on-uefi-ecosystem>
19. UAPI Group. *Unified Kernel Image (UKI) Specification* (2025). <https://uapi-group.org/specifications/specs/unified_kernel_image/>
20. systemd Project. *`systemd-stub(7)`: Simple UEFI Kernel Boot Stub and `PCR[11]` Measurement Architecture* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd-stub.html>
21. UAPI Group. *Linux TPM PCR Registry Specification* (2025). <https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/>
22. systemd Project. *`systemd-measure(1)`: Pre-Calculate and Sign Expected `TPM2` `PCR[11]` Values for Unified Kernel Images* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd-measure.html>
23. systemd Project. *`systemd-pcrlock(8)`: Analyze and Predict `TPM2` PCR States and Generate Dynamic Access Policies* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html>
24. systemd Project. *`systemd-cryptenroll(1)`: Enroll PKCS#11, FIDO2, and `TPM2` Devices into LUKS2 Volumes* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html>
25. Latchset Project. *Clevis Pluggable Framework for Automated Decryption (`clevis-luks-bind` and Tang/TPM2 Pins)* (2024). <https://github.com/latchset/clevis>
26. systemd Project. *`ukify(1)`: Combine Kernel, Initrd, Cmdline, and PCR Signatures into a Unified Kernel Image* (2025). <https://www.freedesktop.org/software/systemd/man/latest/ukify.html>
27. Milan Broz and Cryptsetup Project. *LUKS2 On-Disk Format Specification, Version 1.2.0* (2024). <https://gitlab.com/cryptsetup/LUKS2-docs>
28. Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich. *RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications* (IETF, 2021). <https://www.rfc-editor.org/rfc/rfc9106>
29. Linux Kernel Documentation. *`dm-integrity`: Device-Mapper Block-Level Integrity Target (`Documentation/admin-guide/device-mapper/dm-integrity.rst`)* (2025). <https://docs.kernel.org/admin-guide/device-mapper/dm-integrity.html>
30. Linux Kernel Documentation. *`dm-verity`: Device-Mapper Cryptographic Integrity Checking Target (`Documentation/admin-guide/device-mapper/verity.rst`)* (2025). <https://docs.kernel.org/admin-guide/device-mapper/verity.html>
31. UAPI Group. *Discoverable Partitions Specification (DPS)* (2025). <https://uapi-group.org/specifications/specs/discoverable_partitions_specification/>
32. systemd Project. *`systemd-sysext(8)` and `systemd-confext(8)`: Cryptographically Verified System and Configuration Extensions* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd-sysext.html>
33. Linux Kernel Documentation. *`fs-verity`: Read-Only File-Based Authenticity Protection (`Documentation/filesystems/fsverity.rst`)* (2025). <https://docs.kernel.org/filesystems/fsverity.html>
34. Sidero Labs and Amazon Web Services. *Talos Linux Immutable OS Architecture and Bottlerocket Security Features* (2025). <https://www.talos.dev/latest/learn-more/architecture/>
35. Fedora CoreOS and Flatcar Container Linux Projects. *rpm-ostree, Composefs, and Dual-Partition Immutable Provisioning* (2025). <https://docs.fedoraproject.org/en-US/fedora-coreos/>
36. Reiner Sailer, Xiaolan Zhang, Trent Jaeger, and Leendert van Doorn. *Design and Implementation of a TCG-Based Integrity Measurement Architecture*, Proceedings of the 13th USENIX Security Symposium (2004). <https://www.usenix.org/legacy/event/sec04/tech/sailer.html>
37. Linux Kernel Documentation. *Integrity Measurement Architecture (`IMA`) and Extended Verification Module (`EVM`)* (2025). <https://sourceforge.net/p/linux-ima/wiki/Home/>
38. Fan Wu and Deven Bowers (Linux Kernel Documentation). *Integrity Policy Enforcement (`IPE`) Linux Security Module (`Documentation/admin-guide/LSM/ipe.rst`, Linux 6.12+)* (2024-2025). <https://docs.kernel.org/admin-guide/LSM/ipe.html>
39. Jonathan Corbet (LWN.net). *Integrity Policy Enforcement Merged for Linux 6.12* (2024). <https://lwn.net/Articles/979871/>
40. Henk Birkholz, Dave Thaler, Michael Richardson, Ned Smith, and Wei Pan. *RFC 9334: Remote ATtestation procedureS (RATS) Architecture* (IETF, 2023). <https://www.rfc-editor.org/rfc/rfc9334>
41. CNCF Keylime Project. *Keylime Architecture: Scalable `TPM 2.0` Remote Boot Attestation and Runtime `IMA` Monitoring* (2025). <https://keylime.dev/>
42. Linux Kernel Documentation. *IMA Templates and Appraisal Policy Syntax (`Documentation/security/IMA-templates.rst`)* (2025). <https://docs.kernel.org/security/IMA-templates.html>
43. Nabil Schear, Patrick T. Cable II, Thomas M. Moyer, Bryan Richard, and Robert Rudd. *Bootstrapping and Maintaining Trust in the Cloud*, Proceedings of ACSAC (2016). <https://doi.org/10.1145/2991079.2991104>
44. Matthew Garrett and David Howells. *`kernel_lockdown(7)`: Linux Kernel Lockdown Feature (`integrity` and `confidentiality` Modes)*, Linux man-pages (2025). <https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html>
45. Linux Kernel Documentation. *Kernel Module Signing Facility (`Documentation/admin-guide/module-signing.rst`)* (2025). <https://docs.kernel.org/admin-guide/module-signing.html>
46. Linux Kernel Documentation. *System Keyrings: `.builtin_trusted_keys`, `.secondary_trusted_keys`, and `.machine` Keyrings* (2025). <https://docs.kernel.org/security/keys/trusted-encrypted.html>
47. Linux man-pages. *`kexec_load(2)` and `kexec_file_load(2)`: Load a New Kernel for Later Execution* (2025). <https://man7.org/linux/man-pages/man2/kexec_load.2.html>
48. Linux Kernel Documentation. *Upgrading ACPI Tables via Initrd (`Documentation/admin-guide/acpi/initrd_table_override.rst`) and Lockdown Restrictions* (2025). <https://docs.kernel.org/admin-guide/acpi/initrd_table_override.html>
49. Jonathan Corbet (LWN.net). *Lockdown and Kernel Integrity vs. Confidentiality Boundaries* (2019). <https://lwn.net/Articles/796840/>
50. Linux Kernel Documentation. *EFI Variables, MokListRT Import (`certs/load_uefi.c`), and DKMS Signing Considerations* (2025). <https://docs.kernel.org/security/index.html>
51. Kernel Self Protection Project (KSPP, Kees Cook et al.). *Recommended Linux Kernel Hardening Settings and Threat Model* (2025). <https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project>
52. Joao Moreira, Sandro Rigo, Michalis Polychronakis, and Vasileios P. Kemerlis. *FineIBT: Fine-Grain Control-Flow Enforcement with Indirect Branch Tracking* (LWN.net, 2022-2023). <https://lwn.net/Articles/891976/>
53. Sami Tolvanen and Kees Cook. *Kernel Control Flow Integrity (`CONFIG_CFI_CLANG` / KCFI) in Linux 6.1+* (LWN.net, 2022). <https://lwn.net/Articles/898040/>
54. Jann Horn and Matteo Rizzo (Google Security Blog). *Mitigating Kernel Cross-Cache Attacks with `CONFIG_RANDOM_KMALLOC_CACHES` and `SLAB_VIRTUAL`* (2023-2024). <https://security.googleblog.com/2023/09/mitigating-kernel-cross-cache-attacks.html>
55. Linux Kernel Documentation. *Kernel Electric-Fence (`KFENCE`): Low-Overhead Sampling-Based Memory Safety Error Detector (`Documentation/dev-tools/kfence.rst`)* (2025). <https://docs.kernel.org/dev-tools/kfence.html>
56. Miguel Ojeda, Alex Gaynor, Boqun Feng, Wedson Almeida Filho, Alice Ryhl, et al. *Rust for Linux (`Documentation/rust/index.rst`)* (2022-2026). <https://docs.kernel.org/rust/index.html>
57. Jonathan Corbet (LWN.net). *Shadow Stacks and Indirect Branch Tracking (`CET`) in the Linux Kernel* (2023-2025). <https://lwn.net/Articles/940663/>
58. Will Liu (`willsroot`). *EntryBleed: Breaking KASLR under KPTI with Prefetch (`CVE-2022-4543`)* (2022). <https://www.willsroot.io/2022/12/entrybleed.html>
59. Rust for Linux Project. *Safe Rust Abstractions for Mainline Drivers (`Binder`, `DRM`, `PHY`, and Block Subsystems)* (2024-2026). <https://rust-for-linux.com/>
60. Linux Kernel Documentation. *Heap and Stack Zeroing Parameters: `init_on_alloc`, `init_on_free`, and `CONFIG_ZERO_CALL_USED_REGS`* (2025). <https://docs.kernel.org/admin-guide/kernel-parameters.html>
61. Casey Schaufler (Linux Kernel Documentation). *Linux Security Module (`LSM`) Stacking and `lsm_blob_sizes` Infrastructure (`Documentation/security/lsm.rst`)* (2025). <https://docs.kernel.org/security/lsm.html>
62. Stephen Smalley, Chris Vance, and Wayne Salamon. *Implementing SELinux as a Linux Security Module* and *The SELinux Notebook* (2001-2025). <https://github.com/SELinuxProject/selinux-notebook>
63. John Johansen and Canonical Security Team. *AppArmor Technical Documentation: Path Mediation, IPC Mediation, and User Namespace Profiles* (2025). <https://gitlab.com/apparmor/apparmor/-/wikis/Documentation>
64. Mickael Salaun (Linux Kernel Documentation). *Landlock: Unprivileged Sandboxing for Linux (`Documentation/userspace-api/landlock.rst`, ABI v1 through v7)* (2021-2026). <https://docs.kernel.org/userspace-api/landlock.html>
65. Mickael Salaun. *`landlock(7)`: Unprivileged Access-Control Syscalls (`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`)*, Linux man-pages (2025). <https://man7.org/linux/man-pages/man7/landlock.7.html>
66. Landlock Project. *Landlock ABI Evolution: TCP Bind/Connect (v4), Device `ioctl` Filtering (v5), IPC Scoping (v6), and Audit Logging (v7)* (2024-2026). <https://landlock.io/>
67. Robert N. M. Watson. *Exploiting Concurrency Vulnerabilities in System Call Wrappers (Pathname TOCTOU)*, Proceedings of USENIX WOOT (2007). <https://www.usenix.org/legacy/event/woot07/tech/full_papers/watson/watson.pdf>
68. Red Hat Enterprise Linux Documentation. *Multi-Category Security (`MCS`) and `sVirt` / Container `SELinux` Isolation (`container_t` vs. `spc_t`)* (2025). <https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/>
69. Linux Kernel Documentation. *BPF Verifier Architecture and Abstract Interpretation (`Documentation/bpf/verifier.rst`)* (2025). <https://docs.kernel.org/bpf/verifier.html>
70. KP Singh (Linux Kernel Documentation). *BPF Linux Security Module (`LSM-BPF` / KRSI, `Documentation/bpf/prog_lsm.rst`)* (2020-2025). <https://docs.kernel.org/bpf/prog_lsm.html>
71. Cilium Project. *Tetragon: eBPF-Based Security Observability and Synchronous Runtime Enforcement* (2025). <https://tetragon.io/docs/>
72. CNCF Falco and Aqua Tracee Projects. *Asynchronous eBPF Ring-Buffer System Call Telemetry and Detection Architecture* (2025). <https://falco.org/docs/>
73. Linux man-pages. *`auditd(8)` and Kernel Audit Netlink Backlog Drop Behavior (`audit_backlog_limit`)* (2025). <https://man7.org/linux/man-pages/man8/auditd.8.html>
74. Manfred Paul (Zero Day Initiative). *CVE-2020-8835: Linux Kernel Privilege Escalation via Improper eBPF 32-Bit Bounds Tracking* (2020). <https://www.thezdi.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification>
75. Valentina Palmiotti (`chompie`). *Kernel Pwning with eBPF: `CVE-2021-3490` `ALU32` Bitwise Bounds Tracking Defect* (2021). <https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story>
76. Juan Jose Lopez Jaimez and Meador Inge (Google). *CVE-2023-2163: Linux Kernel eBPF Verifier Register Pruning Incorrectness Leading to Arbitrary Read/Write* (2023). <https://nvd.nist.gov/vuln/detail/CVE-2023-2163>
77. Linux man-pages. *`bpf-helpers(7)`: `bpf_probe_write_user`, `bpf_send_signal`, and Kernel Tracing Helper Warnings* (2025). <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>
78. Linux man-pages. *`capabilities(7)`: Overview of Linux Capabilities (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`)* (2025). <https://man7.org/linux/man-pages/man7/capabilities.7.html>
79. Brad Spengler (`grsecurity`). *False Boundaries and Arbitrary Code Execution: Why `CAP_SYS_ADMIN` and Root-Equivalent Capabilities Collapse Privilege Separation* (2012). <https://forums.grsecurity.net/viewtopic.php?f=7&t=2522>
80. Linux man-pages. *`user_namespaces(7)`: Overview of Linux User Namespaces and UID/GID Mappings* (2025). <https://man7.org/linux/man-pages/man7/user_namespaces.7.html>
81. Notselwyn. *Flipping Pages: Analysis of `CVE-2024-1086`, Universal Local Privilege Escalation in `nf_tables` via `CLONE_NEWUSER`* (2024). <https://pwning.tech/nftables/>
82. Wiz Research. *CVE-2023-0386: Linux Kernel `OverlayFS` Setuid Copy-Up Local Privilege Escalation via Unprivileged User Namespaces* (2023). <https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability>
83. Matteo Rizzo (Google Security Blog). *Learnings from kCTF VRP's 42 Linux Kernel Exploits: Restricting `io_uring` Across Production* (2023). <https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html>
84. Max Kellermann. *The Dirty Pipe Vulnerability (`CVE-2022-0847`): Overwriting Arbitrary Read-Only Files via Uninitialized `PIPE_BUF_FLAG_CAN_MERGE`* (2022). <https://dirtypipe.cm4all.com/>
85. Canonical Ubuntu Security Team. *Restricting Unprivileged User Namespaces via AppArmor in Ubuntu 23.10 and 24.04 LTS (`kernel.apparmor_restrict_unprivileged_userns`)* (2024). <https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces>
86. Qualys Threat Research Unit. *CVE-2021-3156: Heap-Based Buffer Overflow in Sudo (Baron Samedit)* (2021). <https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit>
87. Rich Mirch and Sudo Project. *CVE-2025-32463: Sudo `chroot` (`-R`) Arbitrary Shared Library Load via Untrusted `/etc/nsswitch.conf`* (2025). <https://www.sudo.ws/security/advisories/chroot_bug/>
88. Qualys Threat Research Unit. *PwnKit: Local Privilege Escalation Vulnerability in polkit's `pkexec` (`CVE-2021-4034`)* (2022). <https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034>
89. Qualys Threat Research Unit. *Looney Tunables: Local Privilege Escalation in the `glibc` `ld.so` Dynamic Loader (`GLIBC_TUNABLES`, `CVE-2023-4911`)* (2023). <https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so>
90. Linux man-pages. *`TIOCSTI(2const)`: Terminal Input Queue Injection and `dev.tty.legacy_tiocsti` Hardening (Linux 6.2+)* (2025). <https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html>
91. Lennart Poettering. *`run0`: Reinventing `sudo` Without `SUID` in `systemd` v256* (2024). <https://0pointer.net/blog/run0.html>
92. systemd Project. *`run0(1)` and `systemd-run(1)`: Transient Service Privilege Broker and `--empower` Ambient Capability Sessions (`systemd` v256-v259)* (2024-2026). <https://www.freedesktop.org/software/systemd/man/latest/run0.html>
93. Linux Kernel Documentation. *`PR_SET_NO_NEW_PRIVS` (`no_new_privs` Bit, `Documentation/userspace-api/no_new_privs.rst`)* (2025). <https://docs.kernel.org/userspace-api/no_new_privs.html>
94. Linux man-pages. *`ld.so(8)`: Dynamic Linker/Loader and `AT_SECURE` Environment Scrubbing* (2025). <https://man7.org/linux/man-pages/man8/ld.so.8.html>
95. systemd Project. *`systemd.exec(5)`: Execution Environment, Mount Namespace, Seccomp, and `DynamicUser=` Sandboxing Directives* (2025). <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html>
96. Lennart Poettering. *Dynamic Users with systemd (`DynamicUser=yes`)* (2017). <https://0pointer.net/blog/dynamic-users-with-systemd.html>
97. freedesktop.org. *D-Bus Specification: Wire Protocol, Bus Policy, and `SO_PEERCRED` / `SO_PEERPIDFD` Authentication* (2024). <https://dbus.freedesktop.org/doc/dbus-specification.html>
98. Kevin Backhouse (GitHub Security Lab). *Privilege Escalation with Polkit: Getting Root on Linux via D-Bus UID Lookup Race (`CVE-2021-3560`)* (2021). <https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/>
99. Linux man-pages. *`pidfd_open(2)` and `SO_PEERPIDFD`: Race-Free Process File Descriptors in Linux* (2024-2025). <https://man7.org/linux/man-pages/man2/pidfd_open.2.html>
100. Varlink and systemd Project. *Varlink IPC Protocol and Brokerless Point-to-Point UNIX Socket Architecture* (2024-2025). <https://varlink.org/>
101. Linux man-pages. *`keyrings(7)`, `add_key(2)`, and `keyctl(2)`: In-Kernel Key Management and Retention Facility* (2025). <https://man7.org/linux/man-pages/man7/keyrings.7.html>
102. systemd Project. *System and Service Credentials (`systemd-creds(1)`, `LoadCredentialEncrypted=`, `SetCredentialEncrypted=`)* (2025). <https://systemd.io/CREDENTIALS/>
103. `tpm2-software` Project. *`tpm2-pkcs11`: A PKCS#11 Backend for `TPM 2.0` Hardware Keys* (2025). <https://github.com/tpm2-software/tpm2-pkcs11>
104. freedesktop.org. *Secret Service API (`org.freedesktop.secrets`) Specification and Desktop Keyring D-Bus Model* (2024). <https://specifications.freedesktop.org/secret-service-spec/latest/>
105. Jann Horn (Google Project Zero). *Exploiting the Linux Kernel via Keyring Reference Leak (`CVE-2016-0728`)* (2016). <https://googleprojectzero.blogspot.com/2016/01/exploiting-linux-kernel-via-packet.html>
106. Linux man-pages. *`memfd_secret(2)`: Create an Anonymous RAM-Based File Unmapped from Kernel Direct Map* (2025). <https://man7.org/linux/man-pages/man2/memfd_secret.2.html>
107. Linux-PAM Project. *The Linux-PAM System Administrators' Guide (`pam(7)`, Control Flags, and Stack Evaluation)* (2025). <https://github.com/linux-pam/linux-pam>
108. SSSD Project. *System Security Services Daemon (`SSSD`) Architecture: Kerberos, Active Directory, and OIDC Enterprise Identity* (2025). <https://sssd.io/docs/architecture.html>
109. Damien Miller and OpenBSD Project. *OpenSSH `PROTOCOL.certkeys` and `ssh-keygen(1)`: User and Host Certificate Format* (2025). <https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD>
110. OpenBSD Project. *OpenSSH `PROTOCOL.u2f`: `FIDO2` Hardware Authenticator Keys (`sk-ssh-ed25519@openssh.com`, `verify-required`, Resident Keys)* (2025). <https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.u2f?annotate=HEAD>
111. Qualys Threat Research Unit. *regreSSHion: Remote Unauthenticated Code Execution in OpenSSH Server on `glibc` Linux Systems (`CVE-2024-6387`)* (2024). <https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt>
112. Qualys Threat Research Unit. *`CVE-2023-38408`: Remote Code Execution in OpenSSH's Forwarded `ssh-agent` PKCS#11 `dlopen()` Side Effects* (2023). <https://www.qualys.com/2023/07/19/cve-2023-38408/rce-openssh-forwarded-ssh-agent.txt>
113. OpenSSH Project. *OpenSSH 9.8 Release Notes: Privilege Separation Split into `sshd` Listener and `sshd-session` Binary* (2024). <https://www.openssh.com/txt/release-9.8>
114. Open Container Initiative (OCI). *OCI Runtime Specification, Version 1.2.0* (2024). <https://github.com/opencontainers/runtime-spec>
115. Tejun Heo (Linux Kernel Documentation). *Control Group v2 (`Documentation/admin-guide/cgroup-v2.rst`)* (2025). <https://docs.kernel.org/admin-guide/cgroup-v2.html>
116. Linux Kernel Documentation. *Seccomp BPF (`SECure COMPuting with filters`, `Documentation/userspace-api/seccomp_filter.rst`) and `SECCOMP_RET_USER_NOTIF`* (2025). <https://docs.kernel.org/userspace-api/seccomp_filter.html>
117. Aleksa Sarai, Adam Iwaniuk, and Borys Popko. *`CVE-2019-5736`: `runc` Container Breakout via `/proc/self/exe` Host Binary Overwrite* (2019). <https://www.openwall.com/lists/oss-security/2019/02/11/2>
118. Rory McNamara (Snyk Security Labs). *Leaky Vessels (`CVE-2024-21626`): `runc` `WORKDIR` `/proc/self/fd/` File-Descriptor Leak Container Escape* (2024). <https://snyk.io/blog/leaky-vessels-docker-runc-container-breakout-vulnerabilities/>
119. Yuval Avrahami and Felix Wilhelm. *`CVE-2022-0492`: Linux `cgroup` v1 `release_agent` Container Escape via Unscoped `CAP_SYS_ADMIN`* (2022). <https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/>
120. Christian Brauner and Aleksa Sarai. *`openat2(2)`: `RESOLVE_IN_ROOT` and `RESOLVE_BENEATH` Path-Resolution Confinement* (2020-2025). <https://man7.org/linux/man-pages/man2/openat2.2.html>
121. Moby and containerd Projects. *Default `seccomp` System Call Filter Profile for Linux Containers* (2025). <https://docs.docker.com/engine/security/seccomp/>
122. Google gVisor Project. *gVisor Architecture Guide: `Sentry` User-Space Kernel, `systrap` Platform, and `lisafs` `Gofer` File Proxy* (2025). <https://gvisor.dev/docs/architecture_guide/>
123. Alexandru Agache, Marc Brooker, Alexandra Iordache, Anthony Liguori, Rolf Neugebauer, Phil Piwonka, and Diana-Maria Popa (AWS). *Firecracker: Lightweight Virtualization for Serverless Applications*, Proceedings of USENIX NSDI (2020). <https://www.usenix.org/conference/nsdi20/presentation/agache>
124. Kata Containers Project (OpenInfra Foundation). *Kata Containers 3.x Architecture: Rust Runtime, Dragonball / Cloud Hypervisor VMMs, and `virtio-fs`* (2025). <https://katacontainers.io/>
125. Cloud Hypervisor Project. *Cloud Hypervisor: Rust `rust-vmm` KVM Virtual Machine Monitor for Modern Cloud Workloads* (2025). <https://www.cloudhypervisor.org/>
126. Sergio Lopez et al. (`containers/libkrun`). *`libkrun` and `krunvm`: Dynamic Library KVM Micro-VMs with Transparent Socket Impersonation and `virtio-fs`* (2025). <https://github.com/containers/libkrun>
127. Stefan Hajnoczi, Vivek Goyal, Miklos Szeredi, et al. *`virtio-fs`: Shared File System for Virtual Machines* (2020-2025). <https://virtio-fs.gitlab.io/>
128. Kubernetes Documentation. *Bound Service Account Token Volumes, `TokenRequest` API, and Workload Identity Federation* (2025). <https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/>
129. Amazon Web Services. *Configure Instance Metadata Service Version 2 (`IMDSv2`): Session Tokens and `IP TTL = 1` Hop Limit* (2019-2025). <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
130. Amazon Web Services Security Blog. *Defense in Depth: Open Firewalls, Reverse Proxies, and SSRF Vulnerabilities in EC2 Instance Metadata Service* (2019). <https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/>
131. CNCF SPIFFE Project. *Secure Production Identity Framework for Everyone (`SPIFFE`) Specifications: `SPIFFE ID`, `X.509-SVID`, `JWT-SVID`, and Workload API* (2025). <https://spiffe.io/docs/latest/spiffe-about/overview/>
132. CNCF SPIRE Project. *`SPIRE` Concepts: Node Attestation (`x509pop`, `aws_iid`, `tpm_devid`) and Kernel/cgroup/Kubernetes Workload Attestation* (2025). <https://spiffe.io/docs/latest/spire-about/spire-concepts/>
133. Evan Gilman et al. *Solving the Bottom Turtle: A `SPIFFE` and `SPIRE` Book on Zero-Trust Workload Identity* (CNCF, 2020). <https://spiffe.io/book/>
134. Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, and Mario Fritz. *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*, Proceedings of AISec (2023). <https://arxiv.org/abs/2302.12173>
135. Model Context Protocol (`MCP`) Project. *Model Context Protocol Specification and Security Architecture for `stdio` and Remote Tool Servers* (2024-2026). <https://modelcontextprotocol.io/specification/>
136. Containers Project. *`bubblewrap` (`bwrap(1)`): Unprivileged Sandboxing Tool Powered by Linux Namespaces and `seccomp`* (2025). <https://github.com/containers/bubblewrap>
137. GitHub, OpenAI, and Anthropic Engineering Documentation. *Linux Sandboxing (`Landlock`, `Bubblewrap`, Ephemeral VMs) and Credential-Brokering Firewalls for Autonomous Coding Agents* (2025-2026). <https://docs.github.com/en/copilot/concepts/agents/coding-agent>
138. Johann Rehberger (`Embrace The Red`) and Invariant Labs. *MCP Tool Poisoning, `.git/hooks` Persistence, and Secret Exfiltration in Coding Agents* (2024-2025). <https://embracethered.com/blog/>
139. Google Cloud and gVisor Project. *Isolating Untrusted AI Code Execution with `gVisor` and Snapshot-Restored `Firecracker` Micro-VMs* (2025). <https://gvisor.dev/docs/>
140. Advanced Micro Devices (AMD). *AMD `SEV-SNP`: Strengthening VM Isolation with Integrity Protection and More (Reverse Map Table `RMP` and `VMPL0..3`)* (2020-2025). <https://www.amd.com/content/dam/amd/en/documents/epyc-business-docs/white-papers/SEV-SNP-strengthening-vm-isolation-with-integrity-protection-and-more.pdf>
141. Intel Corporation. *Intel Trust Domain Extensions (`Intel TDX`) Module Architecture Specification (`SEAM`, `TDMR`, `#VE`)* (2024-2025). <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html>
142. Arm Limited. *Introducing Arm Confidential Compute Architecture (`Arm CCA`: Realm Management Extension `RME` and `Realms`)* (2023-2025). <https://developer.arm.com/documentation/den0125/latest/>
143. COCONUT-SVSM Project (Joerg Roedel, Tom Lendacky, James Bottomley, Stefano Garzarella, et al.). *Secure VM Service Module (`VMPL0` Open-Source Rust Paravisor and Measured `vTPM` for Confidential Linux)* (2023-2026). <https://github.com/coconut-svsm/svsm>
144. Benedict Schlueter, Supraja Sridhara, Mark Kuhne, Andrin Bertschi, and Shweta Shinde. *WeSee: Using Malicious `#VC` Interrupts to Break AMD SEV-SNP (`CVE-2024-25742`)*, Proceedings of IEEE Symposium on Security and Privacy (2024). <https://arxiv.org/abs/2404.03526>
145. NVIDIA Corporation. *NVIDIA Hopper (`H100`) and Blackwell (`B200`) Confidential Computing Architecture: `SPDM` Attestation and Encrypted PCIe Bounce Buffers* (2024-2025). <https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/>
146. Linux Kernel Documentation. *x86 Confidential Computing Guest Hardening and Untrusted Hypervisor Device Filtering (`Documentation/arch/x86/tdx.rst`)* (2025). <https://docs.kernel.org/arch/x86/tdx.html>
147. CNCF Confidential Containers (`CoCo`) Project. *Confidential Containers Architecture: Enclave-Per-Pod `Kata` Guests, `guest-components`, and Host Threat Model* (2025). <https://confidentialcontainers.org/docs/architecture/>
148. CNCF Confidential Containers (`CoCo`) Project. *`Trustee`: Remote Attestation Verifier, Key Broker Service (`KBS`), and `OPA` Policy Engine* (2025). <https://github.com/confidential-containers/trustee>
149. Containers Project (`ocicrypt`). *Encrypted OCI Container Image Specification and Enclave-Side Layer Decryption* (2025). <https://github.com/containers/ocicrypt>
150. Confidential Containers Project. *Initdata Specification and Confidential Data Hub (`CDH`) for Sealed AI Model Weights* (2025). <https://confidentialcontainers.org/docs/>
151. Microsoft Azure and Red Hat. *Confidential Containers on `AKS` Kata-CC and OpenShift Sandboxed Containers with `SEV-SNP` and `TDX`* (2025). <https://learn.microsoft.com/en-us/azure/aks/deploy-confidential-containers-default-policy>
152. Andres Freund. *Backdoor in Upstream `xz`/`liblzma` Leading to SSH Server Compromise (`CVE-2024-3094`)*, Openwall `oss-security` (2024). <https://www.openwall.com/lists/oss-security/2024/03/29/4>
153. Russ Cox. *Timeline and Technical Anatomy of the `xz` Open-Source Attack (`Jia Tan`, `build-to-host.m4`, `GNU_IFUNC`, and Ed448 Trigger)* (2024). <https://research.swtch.com/xz-timeline>
154. systemd Project. *Decoupling Optional Compression and Crypto Libraries (`liblzma`, `libzstd`, `liblz4`) in `libsystemd` via On-Demand `dlopen()`* (2024). <https://github.com/systemd/systemd/pull/32024>
155. Reproducible Builds Project. *Deterministic Compilation, `SOURCE_DATE_EPOCH`, and Bit-for-Bit Verification of Linux Packages* (2025). <https://reproducible-builds.org/docs/>
156. OpenSSF SLSA Project. *Supply-Chain Levels for Software Artifacts (`SLSA`), Version 1.0 Specification: Build Provenance and Hermetic Builds* (2023-2025). <https://slsa.dev/spec/v1.0/>
157. Zack Newman, John Speed Meyers, and Santiago Torres-Arias. *Sigstore: Software Signing for Everybody (`Fulcio`, `cosign`, and `Rekor` Transparency Logs)*, Proceedings of ACM CCS (2022). <https://dl.acm.org/doi/10.1145/3548606.3559396>
158. CNCF in-toto Project. *`in-toto` Attestation Framework v1.0: Authenticated Software Supply-Chain Metadata* (2024-2025). <https://in-toto.io/>
