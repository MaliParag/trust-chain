# Summary

[Title Page](front-matter/00-title.md)
[Copyright](front-matter/01-copyright.md)
[Preface](front-matter/02-preface.md)
[How to Read This Book](front-matter/03-how-to-read.md)
[Prologue](chapters/00-prologue.md)
[Foundations](chapters/00b-foundations.md)

# Part I · Silicon, Verified Boot, & Hardware KeyMint

- [SoC Boot ROM, Bootloader Lock States, and AVB 2.0 VBMeta](chapters/01-bootrom-avb-vbmeta.md)
- [Anti-Rollback Indexes, dm-verity, fs-verity, and APEX Mainline](chapters/02-antirollback-verity-apex.md)
- [Arm TrustZone TEEs vs. Discrete StrongBox Security Processors](chapters/03-trustzone-strongbox.md)
- [KeyMint Authorization Tags, Boot Binding, and Weaver Throttling](chapters/04-keymint-weaver-throttling.md)

# Part II · De-Privileging the Kernel: pKVM, SELinux, & Memory Safety

- [Protected KVM and the Android Virtualization Framework](chapters/05-pkvm-avf-microdroid.md)
- [Universal Enforcing SELinux, CTS neverallow Gates, and seccomp-BPF](chapters/06-selinux-seccomp.md)
- [Project Treble HALs, Generic Kernel Image, KCFI, and Kernel Rust](chapters/07-treble-gki-rust.md)
- [Hardware Arm MTE and Hardened Heap Allocation in Production](chapters/08-arm-mte-scudo.md)

# Part III · App Sandbox, Storage, & Local Identity

- [Per-App UID Sandboxing, WebView Isolation, and Binder IPC](chapters/09-uid-zygote-binder.md)
- [APK Signature Schemes, Developer Verification, and Scoped Storage](chapters/10-apk-signing-scoped-storage.md)
- [UI-Layer Bypasses, Banking Trojans, and Advanced Protection Lockdown](chapters/11-accessibility-advanced-protection.md)
- [File-Based Encryption, Physical USB Zero-Days, and Theft Locks](chapters/12-fbe-usb-theft-protection.md)
- [BiometricPrompt Strength Tiers and Credential Manager Passkeys](chapters/13-biometrics-passkeys.md)

# Interlude · Mobile Telemetry & Tamper-Evident Forensics

- [Play Protect, Dynamic Signal Monitoring, and E2EE Intrusion Logging](chapters/14-play-protect-intrusion-logging.md)

# Part IV · Remote Attestation, Enterprise, & Agentic AI

- [Hardware Key Attestation and Remote Key Provisioning](chapters/15-key-attestation-rkp.md)
- [Play Integrity Verdicts vs. Root Hiding and Leaked Keyboxes](chapters/16-play-integrity-keybox-wars.md)
- [Android Enterprise: Work Profiles, COPE, and Zero-Touch](chapters/17-android-enterprise.md)
- [On-Device Agentic AI: AICore, Private Compute Core, and AppFunctions](chapters/18-on-device-agentic-ai.md)
- [E2EE Backup Vaults and Private AI Compute](chapters/19-e2ee-backups-private-ai-compute.md)

# Finale · Where the Multi-Vendor Chain Snaps

- [Multi-Vendor Chain Breaks: GPUs, Basebands, Trustlets, and the Patch Gap](chapters/20-multivendor-spyware-chains.md)

---

[References](back-matter/70-references.md)
[Glossary](back-matter/80-glossary.md)
[About This Book](back-matter/85-about.md)
[Colophon](back-matter/90-colophon.md)
[Index](back-matter/95-index.md)
