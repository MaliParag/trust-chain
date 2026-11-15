# Summary

[Title Page](front-matter/00-title.md)
[Copyright](front-matter/01-copyright.md)
[Preface](front-matter/02-preface.md)
[How to Read This Book](front-matter/03-how-to-read.md)
[Prologue](chapters/00-prologue.md)
[Foundations](chapters/00b-foundations.md)

# Part I: Verified Boot & Immutable Root

- [UEFI, shim, Machine Owner Keys, and SBAT Revocation](chapters/01-uefi-shim-sbat.md)
- [Unified Kernel Images, systemd-stub, and TPM2 PCR Policies](chapters/02-uki-systemd-pcrlock.md)
- [Block and File Integrity: LUKS2, dm-verity, and fs-verity](chapters/03-luks2-verity.md)
- [Runtime Appraisal and Attestation: IMA, IPE, and Keylime](chapters/04-ima-ipe-keylime.md)

# Part II: Kernel Self-Protection & Stacked LSMs

- [Kernel Lockdown, Signed Modules, and kexec Gates](chapters/05-kernel-lockdown-modules.md)
- [Kernel Memory Hardening, Control-Flow Integrity, and Rust](chapters/06-kernel-memory-rust.md)
- [Stacked Linux Security Modules: SELinux, AppArmor, and Landlock](chapters/07-stacked-lsms-landlock.md)

# Interlude: Runtime Visibility & Enforcement

- [The eBPF Dual Edge: Runtime Security Enforcement vs. Verifier Escapes](chapters/08-ebpf-dual-edge.md)

# Part III: Userspace Privilege, Secrets, & Identity

- [POSIX Capabilities and the Unprivileged User Namespace Surface](chapters/09-capabilities-userns.md)
- [Killing SUID: From sudo and Polkit to systemd run0](chapters/10-suid-to-run0.md)
- [Service Sandboxing and D-Bus IPC Mediation](chapters/11-systemd-dbus-sandboxing.md)
- [Local Secret Custody: Kernel Keyrings, systemd-creds, and TPM2 PKCS#11](chapters/12-keyrings-systemd-creds.md)
- [PAM, Hybrid Enterprise Identity, OpenSSH Certificates, and regreSSHion](chapters/13-pam-ssh-fido2.md)

# Part IV: Containers, Agentic AI Sandboxes, & Confidential Cloud

- [Shared-Kernel Containers: Namespaces, cgroups v2, seccomp, and Escapes](chapters/14-containers-escapes.md)
- [De-Privileged Runtimes: gVisor User-Space Kernels and KVM Micro-VMs](chapters/15-gvisor-microvms.md)
- [Cloud Workload Identity: OIDC Projections, IMDSv2, and SPIFFE/SPIRE](chapters/16-workload-identity-spiffe.md)
- [Isolating AI Coding Agents, MCP Servers, and Untrusted Code Execution](chapters/17-ai-agent-sandboxes.md)
- [Confidential VMs and Open Paravisors: SEV-SNP, TDX, and COCONUT-SVSM](chapters/18-confidential-vms-svsm.md)
- [Confidential Containers, Trustee Attestation, and Sealed AI Workloads](chapters/19-confidential-containers.md)

# Finale: Open-Source Supply-Chain Subversion

- [Open-Source Supply-Chain Subversion: XZ Utils, Sigstore, and Reproducible Builds](chapters/20-xz-supply-chain-provenance.md)

---

[References](back-matter/70-references.md)
[Glossary](back-matter/80-glossary.md)
[About This Book](back-matter/85-about.md)
[Colophon](back-matter/90-colophon.md)
[Index](back-matter/95-index.md)
