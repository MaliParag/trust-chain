# Prologue

## Zero Ambient Trust on a Pocket Supercomputer

Install an untrusted game on a desktop operating system under default settings, and unless explicit sandboxing intervenes, that process runs as your user identity with read access to your documents, SSH keys, and browser profile. Install that same game on Android, and the kernel assigns it an isolated Unix `UID` (`u0_a*`), confines it inside an `untrusted_app` `SELinux` domain enforced by compile-time `neverallow` Compatibility Test Suite (`CTS`) rules, blocks raw filesystem traversal via `Scoped Storage`, and mediates every cross-process call through typed `Binder` transactions [1]. Even `root` (`UID 0`) daemons cannot modify read-only system partitions without tripping `dm-verity` block-level hashes anchored in `Android Verified Boot 2.0` (`AVB`) `VBMeta` descriptors [1].

*The Android Trust Chain* traces how Android constructs that hardware-to-cloud security architecture across billions of multi-vendor ARM devices, and examines the exact hardware, driver, and ecosystem seams where real-world exploit chains still break through.

### De-Privileging Both the App and the Host Kernel

Android's modern evolution reflects two decisive architectural shifts. The first separated vendor SoC churn from core OS servicing (`Project Treble` and the `Generic Kernel Image`), pairing hardware `KeyMint` and discrete `StrongBox` chips (`Titan M2`) with Remote Key Provisioning (`RKP`) so remote relying parties can verify X.509 `Key Attestation` extensions proving a key lives in genuine silicon on a locked `VERIFIED` bootloader at a current patch level [1, 2]. The second recognized that both monolithic Linux kernels and bloated `Arm TrustZone` TEEs (`QSEE`/`Kinibi`) present wide Ring 0 and Secure-EL1 attack surfaces: Android 13+ introduced the `Android Virtualization Framework` (`AVF`) backed by `Protected KVM` (`pKVM` in `EL2`), stripping even the host Android Linux kernel of access to isolated guest frames, paired on modern ARMv9 silicon with synchronous and asynchronous `Memory Tagging Extension` (`MTE`) checks [2, 3].

### The Multi-Vendor Supply-Chain Seam

Where Apple controls every transistor and firmware update end to end, Android's trust chain spans SoC vendors (`Qualcomm`, `MediaTek`, `Samsung`, `Google Tensor`), GPU/modem IP blocks, ODMs, OEMs, and carriers. In-the-wild commercial spyware chains (`Cytrox Predator`, `NSO`, and `cellebrite` physical chains) overwhelmingly target that multi-vendor seam: memory corruption inside third-party `Mali` or `Adreno` GPU kernel drivers, over-the-air `Exynos` or `Shannon` cellular baseband decoders, legacy `TrustZone` trustlet command parsers, and social-engineered `AccessibilityService` grants that read screen contents above the cryptography altogether [4].
