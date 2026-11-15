# Glossary

**Abstract Interpretation.** Static program-verification technique implemented inside `kernel/bpf/verifier.c` that simulates all control-flow paths of an `eBPF` program over bounded numeric intervals and tristate bitmasks (`tnum`) to prove memory safety prior to native JIT compilation ([Chapter 8](../chapters/08-ebpf-dual-edge.md)).

**Ambient Capabilities (`CapAmb`).** Per-thread POSIX capability vector introduced in Linux 4.3 (`cred->cap_ambient`) that allows non-root processes to preserve explicitly selected privileges across normal `execve(2)` transitions without requiring `SUID` bits or filesystem `security.capability` extended attributes, automatically cleared whenever a `SUID` or file-capability binary executes ([Chapter 9](../chapters/09-capabilities-userns.md)).

**AMD SEV-SNP (Secure Encrypted Virtualization-Secure Nested Paging).** Hardware confidential-computing architecture on AMD EPYC processors combining per-VM `AES-128-XTS` DRAM encryption managed by an on-die Secure Processor with a silicon-enforced Reverse Map Table (`RMP`) and four intra-guest Virtual Machine Privilege Levels (`VMPL0..3`) ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**AppArmor.** Pathname- and profile-based Linux Security Module (`security/apparmor/`) that compiles per-application filesystem, network, D-Bus, signal, and unprivileged `userns` mediation rules into Deterministic Finite Automata (`DFA`) evaluated on VFS mount/dentry paths ([Chapter 7](../chapters/07-stacked-lsms-landlock.md)).

**Argon2id.** Memory-hard password hashing and key-derivation function standardized in `RFC 9106` and used as the default KDF in `LUKS2` keyslots to resist parallel GPU and ASIC brute-force attacks while defending against cache-timing side channels ([Chapter 3](../chapters/03-luks2-verity.md)).

**Arm CCA (Confidential Compute Architecture).** ARMv9 confidential-computing architecture introducing the Realm Management Extension (`RME`) and EL3-enforced Granule Protection Tables (`GPT`) to isolate dynamically allocated `Realms` from both the Normal-World `EL2` hypervisor and TrustZone Secure World ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**AT_SECURE.** Boolean entry placed in the ELF auxiliary vector (`auxv`) by the Linux kernel across privilege-elevating `execve(2)` transitions (`SUID`, `SGID`, or file capabilities), instructing dynamic linkers such as `glibc` `ld.so` to strip untrusted environment variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`) ([Chapter 10](../chapters/10-suid-to-run0.md)).

**Attestation Key (`AK`).** Restricted signing key (`TPMA_OBJECT_RESTRICTED = 1`) generated inside a `TPM 2.0` and cryptographically bound to the chip's hardware Endorsement Key via `TPM2_MakeCredential` and `TPM2_ActivateCredential` so external verifiers (`Keylime`) can trust `TPM2_Quote` signatures without exposing raw Endorsement keys ([Chapter 4](../chapters/04-ima-ipe-keylime.md)).

**Authenticode (PE/COFF).** Cryptographic code-signing format (`WIN_CERTIFICATE_TYPE_PKCS_SIGNED_DATA`) used across `UEFI` executables (`shim.efi`, `grubx64.efi`, `systemd-boot`, and Unified Kernel Images) to hash Portable Executable sections while excluding checksum and certificate-table header pointers ([Foundations](../chapters/00b-foundations.md), [Chapter 1](../chapters/01-uefi-shim-sbat.md)).

**Bubblewrap (`bwrap`).** Lightweight, unprivileged sandboxing utility (`containers/bubblewrap`) that leverages Linux user, mount, PID, network, and IPC namespaces alongside read-only bind mounts and `PR_SET_NO_NEW_PRIVS` to confine desktop apps (`Flatpak`) and local AI coding agents ([Chapter 17](../chapters/17-ai-agent-sandboxes.md)).

**Capability Bounding Set (`CapBnd`).** Per-thread irreversible ceiling mask in `struct cred` that restricts which filesystem capabilities (`security.capability` $F_P$) a task and all of its descendants can ever acquire across `execve(2)` ([Chapter 9](../chapters/09-capabilities-userns.md)).

**cgroups v2 (Control Groups Version 2).** Unified single-hierarchy Linux kernel subsystem (`/sys/fs/cgroup/`) governing per-service and per-container CPU, memory, swap, I/O, PID-count (`pids.max`), and `eBPF` device-access limits without legacy v1 `release_agent` escape hooks ([Chapter 14](../chapters/14-containers-escapes.md)).

**Cloud Hypervisor.** Memory-safe Virtual Machine Monitor written in Rust atop `rust-vmm` crates for running modern cloud, `Kata Containers`, and `Intel TDX` / `AMD SEV-SNP` workloads over `KVM` with minimal legacy device emulation ([Chapter 15](../chapters/15-gvisor-microvms.md)).

**COCONUT-SVSM (Secure VM Service Module).** Open-source `#![no_std]` Rust paravisor executing at the highest intra-enclave privilege tier (`VMPL0` in `AMD SEV-SNP`) to provide confidential Linux guests (`VMPL1`) with a hardware-measured virtual `TPM 2.0` (`vTPM`) and UEFI variable services isolated from both the host hypervisor and guest Ring 0 ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**composefs.** Verity-backed Linux filesystem composition architecture combining a signed/measured `EROFS` metadata image with a content-addressed backing file store enforced via per-inode `fs-verity` Merkle digests ([Chapter 3](../chapters/03-luks2-verity.md)).

**Confidential Containers (`CoCo`).** CNCF architecture extending `Kata Containers` to run individual Kubernetes Pods inside hardware-encrypted `SEV-SNP` or `Intel TDX` enclave VMs with enclave-side image pulling (`image-rs`), `Initdata` policy binding, and remote `Trustee` key release ([Chapter 19](../chapters/19-confidential-containers.md)).

**Confidential Data Hub (`CDH`).** Rust guest service running inside a `Confidential Containers` pod TEE responsible for unwrapping `ocicrypt` image-layer keys, `LUKS2` scratch keys, and sealed Kubernetes secrets via `Trustee` ([Chapter 19](../chapters/19-confidential-containers.md)).

**Credential-Injecting Reverse Proxy.** Network security broker placed outside an untrusted sandbox or micro-VM that enforces L7 domain, HTTP method, and Git-ref policies before attaching real API `Authorization` headers on outbound TLS connections so the sandbox never holds raw credentials ([Chapter 17](../chapters/17-ai-agent-sandboxes.md)).

**db and dbx (UEFI Signature Databases).** Authenticated non-volatile UEFI NVRAM variables holding `EFI_SIGNATURE_LIST` allowlists (`db`) and unconditional denylists (`dbx`, evaluated prior to `db` in `LoadImage()`) of X.509 certificates and PE/COFF SHA-256 digests ([Chapter 1](../chapters/01-uefi-shim-sbat.md)).

**D-Bus (`dbus-broker` / `dbus-daemon`).** Structured inter-process communication bus on Linux mediating method calls and signals between userspace clients and privileged system daemons over `AF_UNIX` sockets authenticated via `SO_PEERCRED` and `SO_PEERPIDFD` ([Chapter 11](../chapters/11-systemd-dbus-sandboxing.md)).

**Discoverable Partitions Specification (`DPS`).** UAPI Group standard mapping GPT partition type UUIDs to root, `/usr`, `/var`, swap, and `dm-verity` partitions so universal `UKI` images mount storage and enforce A/B updates automatically without a mutable `/etc/fstab` ([Chapter 3](../chapters/03-luks2-verity.md)).

**dm-integrity.** Linux device-mapper target (`drivers/md/dm-integrity.c`) storing per-sector cryptographic authentication tags (`HMAC` or `AEAD`) inside an atomic journaled metadata region to detect offline disk tampering, bit flips, and sector replay beneath `LUKS2` ([Chapter 3](../chapters/03-luks2-verity.md)).

**dm-verity.** Read-only Linux device-mapper target (`drivers/md/dm-verity-target.c`) verifying every demand-paged $4\text{ KiB}$ block read in $O(\log N)$ operations against a precomputed `SHA-256`/`SHA-512` Merkle hash tree anchored to a signed `root_hash` ([Chapter 3](../chapters/03-luks2-verity.md)).

**DynamicUser=yes.** `systemd` service sandboxing directive that allocates an ephemeral `UID`/`GID` (`61184..65519`) exclusively for the runtime lifetime of a unit while enforcing read-only OS mounts, private `/tmp`, and isolated state directories ([Chapter 11](../chapters/11-systemd-dbus-sandboxing.md)).

**eBPF (Extended Berkeley Packet Filter).** In-kernel register virtual machine and verifier subsystem allowing privileged callers to attach statically verified, JIT-compiled bytecode to kernel tracepoints, sockets, cgroups, and `LSM-BPF` security hooks ([Chapter 8](../chapters/08-ebpf-dual-edge.md)).

**EVM (Extended Verification Module).** Linux integrity module (`security/integrity/evm/`) protecting file metadata (`uid`, `gid`, `mode`, inode number, and `security.*` xattrs) against offline disk tampering via `TPM 2.0`-keyed HMACs or asymmetric signatures in `security.evm` ([Chapter 4](../chapters/04-ima-ipe-keylime.md)).

**FIDO2SSH Keys (`sk-ssh-ed25519@openssh.com`).** Hardware-backed OpenSSH key types executing `CTAP2` assertions inside external `FIDO2` authenticators so private scalars never touch host memory and `sshd` can cryptographically mandate physical touch and on-device PIN/biometric verification (`verify-required`) ([Chapter 13](../chapters/13-pam-ssh-fido2.md)).

**FineIBT.** Hybrid x86_64 forward-edge Control-Flow Integrity mechanism in Linux 6.2+ combining hardware `CET` Indirect Branch Tracking (`ENDBR64` landing pads) with callee-side 32-bit C prototype hash verification ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**Firecracker.** Minimalist open-source `KVM` Virtual Machine Monitor written in Rust by AWS (~50k LOC, five `virtio`/serial devices, `< 5 MiB` overhead, jailed via `chroot` + `cgroups v2` + ~35-syscall `seccomp`) for isolating multi-tenant serverless functions and AI sandboxes ([Chapter 15](../chapters/15-gvisor-microvms.md)).

**fs-verity.** Per-file read-only Merkle-tree integrity subsystem (`fs/verity/`) integrated into `ext4`, `btrfs`, and `f2fs` that authenticates demand-paged $4\text{ KiB}$ reads on individual immutable files living inside otherwise writable filesystems ([Chapter 3](../chapters/03-luks2-verity.md)).

**Fulcio.** Free, short-lived OIDC code-signing Certificate Authority in the `Sigstore` ecosystem that binds ephemeral (10-minute) X.509 certificates to verified CI workflow or maintainer OpenID Connect identities instead of static long-lived PGP keys ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**GNU_IFUNC (`STT_GNU_IFUNC`).** ELF dynamic-linker relocation feature in `glibc` allowing a shared library to execute an arbitrary C resolver function during early `ld.so` startup to pick CPU-optimized routines, abused in `XZ Utils` (`CVE-2024-3094`) to hijack `RSA_public_decrypt` inside `sshd` ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**gVisor (`runsc`).** OCI container sandbox runtime developed by Google that intercepts all guest application system calls (`systrap` or `KVM`) and services them inside a memory-safe Go user-space kernel (`Sentry`) paired with an isolated filesystem proxy (`Gofer`) ([Chapter 15](../chapters/15-gvisor-microvms.md)).

**IMA (Integrity Measurement Architecture).** Linux kernel subsystem (`security/integrity/ima/`) that hashes files loaded via `execve`, `mmap(PROT_EXEC)`, or policy hooks, extends runtime measurements into `TPM 2.0` `PCR[10]`, and optionally enforces `security.ima` signatures (`IMA-appraisal`) ([Chapter 4](../chapters/04-ima-ipe-keylime.md)).

**IMDSv2 (Instance Metadata Service Version 2).** Hardened cloud VM metadata protocol on `169.254.169.254` requiring a stateful `HTTP PUT` session-token preflight and defaulting to an `IP TTL = 1` packet hop limit to defeat web `SSRF` and routed container credential theft ([Chapter 16](../chapters/16-workload-identity-spiffe.md)).

**Indirect Prompt Injection (`XPIA`).** Vulnerability class in LLM-integrated agents where adversarial instructions embedded inside untrusted external data (issues, PR diffs, web pages, `MCP` schemas) steer the model into invoking privileged shell, file, or network actions ([Chapter 17](../chapters/17-ai-agent-sandboxes.md)).

**Initdata (`CoCo`).** Launch-time TOML configuration and `OPA` `AgentPolicy` bundle committed into hardware measurement registers (`SEV-SNP` `HOST_DATA` or `Intel TDX` `MRCONFIGID`) to prevent an untrusted Kubernetes `kubelet` from tampering with a Confidential Container's pod behavior ([Chapter 19](../chapters/19-confidential-containers.md)).

**in-toto.** CNCF supply-chain attestation framework defining standardized signed `Statement` and `Predicate` JSON envelopes used to bind `SLSA` build provenance and verification metadata to software artifacts ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**Intel TDX (Trust Domain Extensions).** Hardware confidential-computing architecture on Intel Xeon processors isolating guest Trust Domains (`TDs`) from the host `VMM` via a CPU-attested `SEAM` module, `MKTME` memory encryption + MAC integrity, and private Secure EPT (`S-EPT`) tables ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**IPE (Integrity Policy Enforcement).** Linux Security Module merged in Linux 6.12 (`security/ipe/`) enforcing concise declarative execution and kernel-load rules directly over demand-paged `dm-verity`, `fs-verity`, and `UKI` `boot_verified` cryptographic properties without per-file xattrs ([Chapter 4](../chapters/04-ima-ipe-keylime.md)).

**Kata Containers.** OpenInfra container runtime (`containerd-shim-kata-v2` + `kata-agent`) wrapping Kubernetes Pods inside lightweight hardware-virtualized `KVM` micro-VMs (`Dragonball`, `Cloud Hypervisor`, `Firecracker`, or `QEMU` TEEs) ([Chapter 15](../chapters/15-gvisor-microvms.md), [Chapter 19](../chapters/19-confidential-containers.md)).

**KCFI (`CONFIG_CFI_CLANG`).** Forward-edge Kernel Control-Flow Integrity scheme in `LLVM`/`Clang` that embeds a 32-bit prototype type hash immediately before every valid target function and verifies it inline prior to indirect kernel calls ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**Kernel Keyrings (`keyrings(7)`).** Non-swappable Ring 0 secret and certificate retention subsystem (`add_key`, `keyctl`) scoped across thread (`@t`), process (`@p`), session (`@s`), and user (`@u`) rings with Possessor-centric access control ([Chapter 5](../chapters/05-kernel-lockdown-modules.md), [Chapter 12](../chapters/12-keyrings-systemd-creds.md)).

**Kernel Lockdown (`kernel_lockdown(7)`).** Linux Security Module carving an explicit security boundary between `UID 0` (`root`) and Ring 0 across `integrity` mode (blocking `/dev/mem`, raw PCI/MSR/port writes, unsigned `.ko` modules, and `kexec_load`) and `confidentiality` mode (blocking Ring 0 memory reads) ([Chapter 5](../chapters/05-kernel-lockdown-modules.md)).

**kexec_file_load(2).** Hardened soft-reboot system call accepting open kernel and initrd file descriptors directly into Ring 0 so the running kernel verifies PE/PKCS#7 signatures against system keyrings before staging a reboot, replacing unverified `kexec_load(2)` ([Chapter 5](../chapters/05-kernel-lockdown-modules.md)).

**Keylime.** CNCF remote attestation system implementing `IETF RATS` (`RFC 9334`) for Linux hosts by combining `TPM 2.0` `MakeCredential`/`ActivateCredential` hardware identity binding with continuous nonce-fresh `TPM2_Quote` and `IMA` `PCR[10]` log verification ([Chapter 4](../chapters/04-ima-ipe-keylime.md)).

**KFENCE (Kernel Electric-Fence).** Low-overhead sampling-based memory-safety detector (`mm/kfence/`) deployable in production Linux fleets that places periodic slab allocations beside unmapped MMU guard pages to catch out-of-bounds and use-after-free accesses ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**Landlock.** Stacked Linux Security Module (`security/landlock/`, `ABI v1` through `v7`) enabling any unprivileged process (after `PR_SET_NO_NEW_PRIVS`) to sandbox itself monotonically across filesystem hierarchies, TCP ports, device `ioctl`s, abstract UNIX sockets, and signals ([Chapter 7](../chapters/07-stacked-lsms-landlock.md)).

**LSM-BPF (`BPF_PROG_TYPE_LSM`).** Kernel subsystem (`CONFIG_BPF_LSM`) attaching verified `eBPF` programs directly to `security_*` LSM hooks on pinned kernel objects to achieve synchronous, race-free runtime security enforcement (`Cilium Tetragon`) ([Chapter 8](../chapters/08-ebpf-dual-edge.md)).

**LUKS2 (Linux Unified Key Setup Version 2).** Standard Linux block-encryption on-disk format pairing dual-copy checksummed headers and extensible JSON metadata (`tokens`, `Argon2id` `keyslots`) with `dm-crypt` and optional `dm-integrity` `AEAD` authentication ([Chapter 3](../chapters/03-luks2-verity.md)).

**Machine Owner Key (`MOK`).** Operator-controlled X.509 certificate store (`MokList`, enrolled via `MokManager.efi` with physical console presence and mirrored at boot into runtime-readable `MokListRT`) used by `shim.efi` and the Linux `.machine` keyring to verify custom kernels and modules ([Chapter 1](../chapters/01-uefi-shim-sbat.md), [Chapter 5](../chapters/05-kernel-lockdown-modules.md)).

**memfd_secret(2).** Linux system call allocating anonymous RAM pages that are both locked against swap and completely unmapped from the kernel's own linear direct map to shield user-space cryptographic keys ([Chapter 12](../chapters/12-keyrings-systemd-creds.md)).

**Model Context Protocol (`MCP`).** Open JSON-RPC protocol connecting LLM coding agents and chat hosts to local `stdio` or remote HTTP tool/resource servers, introducing tool-poisoning and cross-server exfiltration boundaries ([Chapter 17](../chapters/17-ai-agent-sandboxes.md)).

**Multi-Category Security (`MCS`).** `SELinux` category-isolation mechanism (`s0:cX,cY`) used by `sVirt` (`Podman`, `CRI-O`, `OpenShift`, `libvirt`) to assign each container or KVM guest a unique category pair that prevents cross-tenant file and process access even under `UID 0` breakouts ([Chapter 7](../chapters/07-stacked-lsms-landlock.md)).

**no_new_privs (`PR_SET_NO_NEW_PRIVS`).** Irreversible per-thread attribute inherited across `fork`, `clone`, and `execve` that forbids any subsequent execution from granting new privileges via `SUID`, `SGID`, or file capabilities; mandatory prerequisite for unprivileged `seccomp-BPF` and `Landlock` ([Chapter 7](../chapters/07-stacked-lsms-landlock.md), [Chapter 10](../chapters/10-suid-to-run0.md)).

**ocicrypt.** OCI container image encryption extension wrapping individual container filesystem layers in `AES-256-GCM` with keys bound to `JWE`/PKCS#7 or remote `Confidential Containers` `Trustee` `KBS` URIs ([Chapter 19](../chapters/19-confidential-containers.md)).

**openat2(2).** Hardened VFS file-opening system call supporting `RESOLVE_IN_ROOT`, `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_MAGICLINKS` flags so container runtimes (`runc`, `crun`) safely traverse untrusted directory trees without `/proc/self/fd` or `..` breakouts ([Chapter 14](../chapters/14-containers-escapes.md)).

**OpenSSH Certificates (`PROTOCOL.certkeys`).** Compact, non-ASN.1 binary SSH certificate format (`ssh-ed25519-cert-v01@openssh.com`) replacing static `authorized_keys` and `TOFU` host prompts with short-lived CA-signed principals and validity windows ([Chapter 13](../chapters/13-pam-ssh-fido2.md)).

**PAM (Pluggable Authentication Modules).** Modular userspace authentication framework (`libpam`, `/etc/pam.d/*`) evaluating ordered `auth`, `account`, `session`, and `password` stacks across local login, `sshd`, and `Polkit` ([Chapter 13](../chapters/13-pam-ssh-fido2.md)).

**PCR (Platform Configuration Register).** Hardware state register inside a `TPM 2.0` (`PCR[0..23]`) mutated exclusively via one-way `TPM2_PCR_Extend` cryptographic hash chaining ($\operatorname{SHA-256}(\text{old} \parallel d)$) to record firmware, `UKI` (`PCR[11]`), and `IMA` (`PCR[10]`) state ([Foundations](../chapters/00b-foundations.md), [Chapter 2](../chapters/02-uki-systemd-pcrlock.md)).

**pidfd (Process File Descriptor).** Unforgeable kernel file handle (`pidfd_open(2)`, `SO_PEERPIDFD`, `SCM_PIDFD`) referencing a specific `struct pid` instance rather than a recyclable numeric PID, eliminating PID-wraparound `TOCTOU` races in `D-Bus`, `Polkit`, `Varlink`, and `SPIRE` ([Chapter 11](../chapters/11-systemd-dbus-sandboxing.md)).

**Rekor.** Append-only, verifiable Merkle-tree transparency log in the `Sigstore` ecosystem recording signed code provenance and ephemeral `Fulcio` certificates so hidden targeted binary signing becomes publicly detectable ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**Reproducible Builds.** Software engineering practice ensuring independent builders compiling an identical Git source tree under a defined toolchain (`SOURCE_DATE_EPOCH`) produce bit-for-bit identical output binaries ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**Reverse Map Table (`RMP`).** Silicon-enforced physical memory ownership table in `AMD SEV-SNP` mapping every $4\text{ KiB}$ System Physical Address to its owning `ASID`, Guest Physical Address, validation state, and `VMPL0..3` permissions ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**run0 (`systemd`).** `SUID`-free privilege-elevation command introduced in `systemd v256` (with `--empower` ambient capability sessions in `v257`–`v259`) that brokers transient clean-room service execution and isolated PTYs through `PID 1` and `Polkit` ([Chapter 10](../chapters/10-suid-to-run0.md)).

**Rust-for-Linux.** Mainline Linux kernel integration (`CONFIG_RUST=y`, `rust/kernel/`) encapsulating raw C subsystem APIs inside small audited `unsafe` abstractions so leaf drivers (`Binder`, `DRM`, `PHY`, `block`) are written in 100% safe, borrow-checked Rust free of UAF and data races ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**SBAT (UEFI Secure Boot Advanced Targeting).** Constant-space bootloader revocation mechanism comparing component generation integers inside a signed PE `.sbat` CSV section against floors stored in the boot-services-only `SbatLevel` UEFI variable ([Chapter 1](../chapters/01-uefi-shim-sbat.md)).

**seccomp-BPF.** Syscall filtering facility (`SECCOMP_SET_MODE_FILTER`) evaluating `cBPF` programs at `SYSCALL` entry over syscall numbers and raw register arguments to shrink reachable Ring 0 attack surface in daemons, containers, and VMMs ([Foundations](../chapters/00b-foundations.md), [Chapter 14](../chapters/14-containers-escapes.md)).

**SELinux (Security-Enhanced Linux).** Label-based Mandatory Access Control LSM (`security/selinux/`) enforcing Flux Advanced Security Kernel (`FLASK`) Type Enforcement, Role-Based Access Control, and Multi-Category Security over persistent `security.selinux` inode extended attributes ([Chapter 7](../chapters/07-stacked-lsms-landlock.md)).

**Shadow Stack (`Intel CET`).** Hardware backward-edge Control-Flow Integrity mechanism storing protected copies of function return addresses on supervisor shadow-stack pages (`CR4.CET`) and raising a `#CP` fault if a `RET` target diverges from the data stack ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**shim (`shim.efi`).** Compact first-stage UEFI bootloader signed by the Microsoft third-party UEFI CA that enforces `SbatLevel` revocations and delegates Secure Boot verification to Linux distribution signing keys and Machine Owner Keys (`MokList`) ([Chapter 1](../chapters/01-uefi-shim-sbat.md)).

**SLAB_VIRTUAL.** Kernel `SLUB` allocator hardening architecture binding virtual slab page addresses permanently to a single `kmem_cache` type so recycled physical DRAM frames can never be exploited for cross-cache Use-After-Free aliasing ([Chapter 6](../chapters/06-kernel-memory-rust.md)).

**SLSA (Supply-Chain Levels for Software Artifacts).** OpenSSF specification (`v1.0`) defining graduated build-integrity tiers (`Build Levels 1..3`) backed by isolated CI control planes emitting authenticated `in-toto` provenance over source commits and build steps ([Chapter 20](../chapters/20-xz-supply-chain-provenance.md)).

**SPDM (Security Protocol and Data Model).** DMTF hardware-authentication protocol used by Confidential Linux VMs to verify `NVIDIA Hopper`/`Blackwell` GPU silicon identity and firmware measurements before establishing encrypted PCIe DMA sessions ([Chapter 18](../chapters/18-confidential-vms-svsm.md)).

**SPIFFE and SPIRE.** CNCF workload-identity standards (`SPIFFE ID`, `X.509-SVID`) and runtime (`SPIRE` Server + Agent) issuing short-lived mTLS certificates by chaining `TPM 2.0` / cloud node attestation into kernel `SO_PEERCRED`/`pidfd` and `cgroups v2` workload attestation ([Chapter 16](../chapters/16-workload-identity-spiffe.md)).

**struct cred.** Immutable, RCU-managed Linux kernel structure (`include/linux/cred.h`) holding a task's real/effective `kuid_t`/`kgid_t`, five 64-bit capability masks, keyrings, user-namespace pointer, and stacked LSM security blob ([Foundations](../chapters/00b-foundations.md)).

**systemd-creds.** `systemd` secret-management subsystem sealing service credentials with `AES-256-GCM` under `TPM 2.0` + host keys (`LoadCredentialEncrypted=`) and delivering plaintext exclusively via per-unit non-swappable `ramfs` mounts ([Chapter 12](../chapters/12-keyrings-systemd-creds.md)).

**systemd-pcrlock.** `TPM 2.0` policy generator in `systemd` (`v255+`) that parses fine-grained TCG event-log components to build `TPM2_PolicyOR` variant trees pinned to an anti-rollback `TPM2` NV index, preventing routine firmware or bootloader updates from causing disk lockouts ([Chapter 2](../chapters/02-uki-systemd-pcrlock.md)).

**systemd-sysext.** Cryptographically verified OS extension mechanism layering signed `dm-verity` `EROFS`/`SquashFS` Discoverable Disk Images cleanly atop an immutable `/usr` tree via read-only `OverlayFS` ([Chapter 3](../chapters/03-luks2-verity.md)).

**TPM2_PolicyAuthorize.** `TPM 2.0` Enhanced Authorization command binding a sealed object's `authPolicy` to a *public signing key* (`.pcrpkey`) rather than a static PCR hash so vendor-signed `UKI` updates (`.pcrsig`) unlock `LUKS2` seamlessly ([Foundations](../chapters/00b-foundations.md), [Chapter 2](../chapters/02-uki-systemd-pcrlock.md)).

**Trustee (`KBS`).** CNCF `Confidential Containers` remote attestation verifier, Reference Value Provider, and Key Broker Service evaluating hardware TEE quotes under `IETF RATS` (`RFC 9334`) before releasing wrapped decryption keys into enclave memory ([Chapter 19](../chapters/19-confidential-containers.md)).

**Unified Kernel Image (`UKI`).** Single Authenticode-signed `PE/COFF` binary (`UAPI Group` specification) bundling `systemd-stub`, `.linux` (`vmlinuz`), `.initrd`, `.cmdline`, `.sbat`, and `.pcrpkey`/`.pcrsig` to eliminate unauthenticated `/boot` `initramfs` and command-line tampering ([Chapter 2](../chapters/02-uki-systemd-pcrlock.md)).

**User Namespaces (`CLONE_NEWUSER`).** Linux namespace isolating UID/GID mappings (`kuid_t` $\leftrightarrow$ `uid_t`) and granting namespace-local capabilities (`ns_capable`) for rootless containers and sandboxes, while historically exposing Ring 0 `CAP_NET_ADMIN` / `OverlayFS` attack surfaces ([Chapter 9](../chapters/09-capabilities-userns.md)).

**Varlink.** Lightweight, brokerless JSON-over-`AF_UNIX` point-to-point IPC protocol adopted across modern `systemd` subsystems (`run0`, `userdb`, `creds`, `pcrlock`) for direct `SO_PEERCRED` + `SO_PEERPIDFD` peer mediation ([Chapter 11](../chapters/11-systemd-dbus-sandboxing.md)).

**virtio-fs (`virtiofsd`).** Shared host-to-VM filesystem protocol transporting `FUSE` requests across `KVM` `virtqueue` rings (now implemented in a sandboxed Rust `virtiofsd` daemon) for `Kata Containers` and `libkrun` micro-VMs ([Chapter 15](../chapters/15-gvisor-microvms.md)).
