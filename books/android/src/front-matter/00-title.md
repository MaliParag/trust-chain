# The Android Trust Chain

## From Verified Boot 2.0, StrongBox, and pKVM Through SELinux and Keystore to Play Integrity and Private Compute

**Parag Mali**

---

Android runs atop the Linux kernel, yet inverts nearly every trust assumption of traditional desktop Unix. On Android, there is no shared interactive user account trusted across installed programs: every application receives a distinct Linux `UID` at install time, executes inside a mandatory enforcing `SELinux` domain, communicates exclusively over kernel-mediated `Binder` IPC, and stores secrets under `File-Based Encryption` (`FBE`) backed by `Arm TrustZone` `KeyMint` or a discrete `StrongBox` security chip such as `Google Titan M2` [1, 2]. Beneath userspace, `Android Verified Boot 2.0` (`AVB` `VBMeta` descriptors, rollback indexes, and error-correcting `dm-verity`) seals read-only OS partitions, while the `Android Virtualization Framework` (`AVF` powered by `Protected KVM`, `pKVM`) strips host-kernel memory access away from isolated workloads even if Ring 0 is compromised [2, 3].

### Planned Architecture of Volume IV

| Section | Chapters | Scope |
|---|---|---|
| Opening | [Prologue](../chapters/00-prologue.md) | How Android turned a general-purpose Unix kernel into a mutually distrusting capability-like mobile OS, and why multi-vendor SoC fragmentation remains its Achilles' heel |
| Part I · Silicon, AVB 2.0, & Hardware KeyMint | Chapters 1 to 4 (In Preparation) | 1. SoC Boot ROM, Bootloader Lock States (`Verified` / `Yellow` / `Orange`), and `AVB 2.0` `VBMeta` Chains · 2. Hardware Anti-Rollback Indexes and `dm-verity` + `fs-verity` (`APK` Signature Scheme v4) · 3. `Arm TrustZone` (`OP-TEE` / `Trusty` / `QSEE`) vs. Discrete `StrongBox` (`Titan M2`) · 4. `KeyMint` Authorization Tags: Boot-State, Attestation-ID, and Biometric Weaver Binding |
| Part II · pKVM, SELinux, & Memory Tagging | Chapters 5 to 8 (In Preparation) | 5. De-Privileging the Host Kernel: `Protected KVM` (`pKVM`) and the Android Virtualization Framework (`AVF`) · 6. Universal Enforcing `SELinux` (`neverallow` CTS Gates) and `seccomp-BPF` Zygote Filters · 7. Generic Kernel Image (`GKI`), Vendor HAL Separation (`Treble`), and `KCFI` · 8. Hardware `Arm MTE` (Memory Tagging Extension) in Production against Zero-Day Heap Corruption |
| Part III · App Sandbox, Storage, & Passkeys | Chapters 9 to 12 (In Preparation) | 9. Per-App `UID` Isolation, `Zygote` Forking, and `Binder` IPC Capability Mediation · 10. Runtime Permissions, `Scoped Storage`, and Accessibility-Service Abuse (Banking Malware) · 11. `File-Based Encryption` (`FBE`), Direct Boot (`CE` vs. `DE` Storage), and `Weaver` Throttling · 12. `BiometricPrompt` Class 3 Gates and `Credential Manager` Passkeys + `caBLE` Hybrid Transport |
| Part IV · Remote Attestation & Private AI | Chapters 13 to 15 (In Preparation) | 13. Hardware `Key Attestation` X.509 Extension Chains and Root Provisioning (`RKP`) · 14. `Play Integrity` App/Device Verdicts vs. Root/Frida Spoofing · 15. End-to-End Encrypted Cloud Backup Vaults and Android `Private Compute Core` (`PCC`) |
| Finale | Chapter 16 (In Preparation) | 16. Where the Mobile Chain Snaps: `Mali`/`Adreno` GPU Drivers, Cellular Baseband RCE, `TrustZone` Trustlet Bugs, and Multi-Tier OEM Patch Lag |

Begin with the [Prologue](../chapters/00-prologue.md) or review [References](../back-matter/70-references.md).
