# Glossary

Alphabetical reference across all four parts, the interlude, and the finale of *The Android Trust Chain*.

**ABL (Applications Bootloader).** Final Normal World vendor bootloader stage (`EL1` or `EL2`) that executes `libavb` to verify `vbmeta` descriptors, enforces the `GREEN` / `YELLOW` / `ORANGE` / `RED` lock state machine, latches root-of-trust parameters into `KeyMint`, and transfers execution to the Linux kernel ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md)).

**AccessibilityService.** Assistive Android framework API permitting screen-reader and switch-access services to inspect `AccessibilityNodeInfo` view hierarchies and synthesize UI gestures; heavily abused by Automated Transfer System (`ATS`) banking trojans until gated by `ECM` Restricted Settings and `Advanced Protection Mode` ([Chapter 11](../chapters/11-accessibility-advanced-protection.md)).

**Advanced Protection Mode.** Single-toggle high-risk device lockdown introduced in Android 16 and expanded in Android 17 (`AdvancedProtectionManager`) that atomically blocks sideloading and unverified Accessibility grants, enables `Arm MTE`, disables Chrome V8 JIT and `WebGPU` on untrusted sites, turns off 2G radio, locks USB data while locked, and enables E2EE `Intrusion Logging` ([Chapter 11](../chapters/11-accessibility-advanced-protection.md)).

**AFU (After First Unlock).** Runtime state entered after the user first supplies a valid Lock Screen Knowledge Factor (`LSKF`) post-boot, during which Credential Encrypted (`CE`) `fscrypt` keys remain programmed inside hardware `ICE` keyslots even while the screen is re-locked ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**AICore.** Privileged Android system service hosting on-device `Gemini Nano` foundation models inside the network-less `Private Compute Core` sandbox with ephemeral per-caller context isolation ([Chapter 18](../chapters/18-on-device-agentic-ai.md)).

**AID (Android ID).** Deterministic Linux `UID`/`GID` allocation defined in `android_filesystem_config.h`, assigning static IDs (`1000..2999`) to system daemons, unique `10000..19999` IDs (`u0_a*`) to installed apps, and ephemeral `99000..99999` IDs (`u0_i*`) to isolated processes ([Foundations](../chapters/00b-foundations.md) and [Chapter 9](../chapters/09-uid-zygote-binder.md)).

**AIDL (Android Interface Definition Language).** Typed IPC contract compiler generating marshaling stubs over `/dev/binder`; Stable `AIDL` forms the mandatory `VINTF` boundary between `/system` and `/vendor` HALs as well as `KeyMint` and `RKP` ([Chapter 4](../chapters/04-keymint-weaver-throttling.md) and [Chapter 7](../chapters/07-treble-gki-rust.md)).

**allowxperm.** `SELinux` extended-permission rule filtering the 16-bit `cmd` parameter of `ioctl()` system calls to block untrusted apps from reaching legacy driver debug or profiling subcommands ([Chapter 6](../chapters/06-selinux-seccomp.md)).

**APEX (Android Pony EXpress).** Two-layer signed modular container (`Project Mainline`) pairing an outer `APK v3` signature with an inner `AVB`-signed, `dm-verity`-mounted `apex_payload.img` filesystem to update core OS components via Google Play outside OEM firmware OTAs ([Chapter 2](../chapters/02-antirollback-verity-apex.md)).

**APK Signature Scheme v2 / v3 / v4.** Whole-file binary signing block (`v2`) closing the `Janus` ZIP/DEX gap, extended with cryptographic `SigningCertificateLineage` key rotation (`v3`) and $4\text{ KiB}$ `fs-verity` streaming Merkle trees (`v4`) ([Chapter 10](../chapters/10-apk-signing-scoped-storage.md)).

**AppFunctions.** Typed cross-application capability API introduced in Android 16 (`android.app.appfunctions`) allowing authorized AI agents to invoke developer-declared app operations with structured schema validation rather than screen scraping ([Chapter 18](../chapters/18-on-device-agentic-ai.md)).

**Arm MTE (Memory Tagging Extension).** `ARMv8.5-A`/`ARMv9` hardware memory-safety feature pairing 4-bit pointer tags in address bits `[59:56]` against 4-bit physical allocation tags on 16-byte memory granules to trap spatial overflows and temporal use-after-free bugs in `SYNC`, `ASYNC`, or `ASYMM` modes ([Chapter 8](../chapters/08-arm-mte-scudo.md)).

**Arm TrustZone.** Processor security extension partitioning each physical ARM core and bus transaction (`NS` bit + `TZASC`) between the Normal World (`EL0`-`EL2`) and Secure World (`S-EL0`/`S-EL1` TEEs such as `Trusty`, `QTEE`, and `Kinibi`) via `EL3` `SMC` monitor calls ([Foundations](../chapters/00b-foundations.md) and [Chapter 3](../chapters/03-trustzone-strongbox.md)).

**AuthorizationList.** Structured set of `KeyMint` `KeyParameter` tags (`Tag.aidl`) partitioned into hardware-enforced (`teeEnforced`) and daemon-enforced (`softwareEnforced`) buckets, bound into key-blob AEAD Additional Authenticated Data and attested via X.509 OID `.17` ([Chapter 4](../chapters/04-keymint-weaver-throttling.md) and [Chapter 15](../chapters/15-key-attestation-rkp.md)).

**AVB 2.0 (Android Verified Boot 2.0).** Reference boot-verification architecture (`libavb`) anchoring partition hashes, `dm-verity` Merkle roots, chained partition public keys, and rollback indexes inside a central signed `vbmeta` struct ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md)).

**avb_custom_key.** User-provisionable public-key virtual partition supported on hardware such as Google Pixel, enabling alternate operating systems (`GrapheneOS`) to re-lock the bootloader in `YELLOW` state with full `AVB` and `StrongBox` hardware protection ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md) and [Chapter 16](../chapters/16-play-integrity-keybox-wars.md)).

**AVF (Android Virtualization Framework).** Standard platform subsystem introduced in Android 13 providing `Protected KVM` (`pKVM`), `crosvm`, `pvmfw`, and `Microdroid` to execute confidential workloads isolated from the host Linux kernel ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md)).

**BCC (Boot Certificate Chain).** `CBOR`/`COSE_Sign1` certificate hierarchy constructed across `OpenProfile for DICE` boot stages from silicon `UDS` up to `KeyMint`, `StrongBox`, or `pvmfw` for `Remote Key Provisioning` ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md) and [Chapter 15](../chapters/15-key-attestation-rkp.md)).

**BFU (Before First Unlock).** Cold-boot state prior to initial `LSKF` entry in which only Device Encrypted (`DE`) storage is mounted while Credential Encrypted (`CE`) master keys remain completely absent from DRAM and `ICE` hardware ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**Binder.** In-kernel object-capability inter-process communication driver (`/dev/binder`, rewritten in Rust in modern `GKI`) that translates unforgeable per-process object handles (`flat_binder_object`) and stamps every transaction with `sender_euid` ([Chapter 7](../chapters/07-treble-gki-rust.md) and [Chapter 9](../chapters/09-uid-zygote-binder.md)).

**Biometric Class 3 (Strong).** Highest `CDD` Section 7.3.10 biometric tier requiring `FAR <= 1/50,000`, Spoof Acceptance Rate `SAR <= 7%`, and an isolated hardware sensor-to-`TEE` pipeline; the sole biometric class permitted to mint `HardwareAuthToken`s for `KeyMint` keys ([Chapter 13](../chapters/13-biometrics-passkeys.md)).

**Boot ROM (PBL / BROM).** Photolithographically immutable mask ROM inside the SoC that executes first at power-on reset in `EL3` and verifies the initial mutable bootloader against OTP-fused OEM public-key hashes ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md)).

**caBLE (Cloud-Assisted Bluetooth Low Energy).** `CTAP 2.2` Hybrid Transport protocol combining QR key agreement, mandatory short-range `BLE` physical proximity advertisements, and an end-to-end `Noise` tunnel for cross-device passkey sign-in ([Chapter 13](../chapters/13-biometrics-passkeys.md)).

**CDD (Compatibility Definition Document).** Normative specification defining mandatory security, hardware, and API invariants required of every certified Android device ([Foundations](../chapters/00b-foundations.md)).

**Cloud Key Vault (CKV).** Data-center `Google Titan` Hardware Security Module cohort that wraps Android E2EE Cloud Backup and Passkey Sync recovery keys behind a hardware-enforced ceiling of `<= 10` wrong `LSKF` attempts ([Chapter 13](../chapters/13-biometrics-passkeys.md) and [Chapter 19](../chapters/19-e2ee-backups-private-ai-compute.md)).

**COPE (Corporate-Owned, Personally Enabled).** Android Enterprise deployment mode pairing a company-owned handset enrolled via `Zero-Touch` with an isolated `Work Profile` (`User 10`) while preserving `User 0` personal app and data privacy ([Chapter 17](../chapters/17-android-enterprise.md)).

**Credential Manager.** Unified Android 14+ authentication framework brokering `WebAuthn` passkeys, passwords, and federated credentials across pluggable `CredentialProviderService` vaults ([Chapter 13](../chapters/13-biometrics-passkeys.md)).

**CTS (Compatibility Test Suite).** Automated compliance harness verifying `CDD` adherence, including binary `SELinux` `neverallow` verification (`SELinuxHostTest`) and biometric/KeyMint invariants, prior to GMS licensing ([Foundations](../chapters/00b-foundations.md) and [Chapter 6](../chapters/06-selinux-seccomp.md)).

**Developer Verification (Android).** Ecosystem accountability requirement rolling out in 2026-2027 on certified GMS devices binding both Play-distributed and sideloaded APKs to verified developer identities without reviewing sideloaded app content ([Chapter 10](../chapters/10-apk-signing-scoped-storage.md)).

**DICE (OpenProfile for DICE).** Trusted Computing Group layered cryptographic derivation standard computing `CDI_Attest` (exact code hash) and `CDI_Seal` (authority signer + SVN) across boot stages and Protected VMs ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md) and [Chapter 15](../chapters/15-key-attestation-rkp.md)).

**Direct Boot.** Pre-unlock execution mode introduced alongside `File-Based Encryption` allowing `directBootAware` alarms, telephony, and accessibility components to run from `DE` storage while `CE` user data stays cryptographically locked ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**dm-verity.** Linux device-mapper block-integrity target authenticating $4\text{ KiB}$ read-only partition blocks lazily against a `SHA-256` Merkle tree anchored in `vbmeta`, paired on Android with Reed-Solomon Forward Error Correction (`FEC`) ([Chapter 2](../chapters/02-antirollback-verity-apex.md)).

**Dynamic Signal Monitoring.** On-device behavioral telemetry engine in `Google Play Protect` (Android 16/17 Live Threat Detection) correlating runtime icon hiding, dynamic DEX loading, and permission probing to stop polymorphic droppers ([Chapter 14](../chapters/14-play-protect-intrusion-logging.md)).

**ECM (Enhanced Confirmation Mode / Restricted Settings).** Platform gate introduced in Android 13 and expanded in Android 15 that blocks sideloaded APKs from acquiring `AccessibilityService` or `NotificationListenerService` grants ([Chapter 11](../chapters/11-accessibility-advanced-protection.md)).

**EDL (Emergency Download Mode).** Low-level SoC `Boot ROM` USB recovery interface (such as Qualcomm `Sahara`/`Firehose`); leaked OEM-signed `Firehose` programmers historically granted physical flash read/write access prior to `ABL` ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md)).

**FBE (File-Based Encryption).** Inode-granular filesystem encryption (`fscrypt` v2 using `HKDF-SHA512`, `AES-256-XTS` contents, and `AES-256-CTS` filenames) accelerated inline by `UFS` `ICE` hardware ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**FRP (Factory Reset Protection).** Hardware-backed persistence flag (`frp` partition / `oem_unlock_allowed`) blocking unauthorized `fastboot flashing unlock` or post-theft setup without prior `LSKF` or owner account proof ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md)).

**fs-verity.** Linux VFS read-only file-authentication layer verifying $4\text{ KiB}$ pages on demand against a per-inode Merkle digest stored in filesystem metadata, backing `APK Signature Scheme v4` ([Chapter 2](../chapters/02-antirollback-verity-apex.md) and [Chapter 10](../chapters/10-apk-signing-scoped-storage.md)).

**Gatekeeper.** `TEE`-backed password/PIN verification HAL maintaining HMAC-enrolled handles and `RPMB` failure backoff on devices without discrete `StrongBox` `Weaver` silicon ([Chapter 4](../chapters/04-keymint-weaver-throttling.md)).

**GKI (Generic Kernel Image).** Unified, Google-built and Google-signed `ARM64` core Linux kernel (`boot.img`) exposing a frozen Kernel Module Interface (`KMI`) ABI to vendor `.ko` loadable modules (`vendor_dlkm`) ([Chapter 7](../chapters/07-treble-gki-rust.md)).

**GrapheneOS.** Privacy- and security-hardened open-source Android operating system booting in locked `YELLOW` Verified Boot state (`avb_custom_key`) with default synchronous `Arm MTE`, hardened allocator, USB-C hardware lock, and `Seedvault` backups ([Chapter 1](../chapters/01-bootrom-avb-vbmeta.md), [Chapter 8](../chapters/08-arm-mte-scudo.md), and [Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**HardwareAuthToken.** 69-byte `HMAC-SHA256`-authenticated structure minted inside secure hardware by `Gatekeeper`/`Weaver` or a `Class 3` biometric TA to authorize `USER_SECURE_ID`-gated `KeyMint` operations ([Chapter 4](../chapters/04-keymint-weaver-throttling.md) and [Chapter 13](../chapters/13-biometrics-passkeys.md)).

**ICE (Inline Crypto Engine).** Dedicated cryptographic engine inside the `UFS` storage host controller (`blk-crypto`) encrypting and decrypting file sectors inline via hardware keyslots without exposing raw keys to general DRAM ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**Identity Check.** Android 16/17 anti-theft control requiring live `Class 3` biometric authentication (explicitly disallowing `LSKF` PIN fallback) for critical security and account changes whenever the handset is outside Trusted Places ([Chapter 12](../chapters/12-fbe-usb-theft-protection.md)).

**Intent Redirection.** Application-layer confused-deputy vulnerability in which an exported component extracts an attacker-supplied nested `Intent` and launches it under the victim app's `UID`, leaking internal components or `FileProvider` URIs ([Chapter 9](../chapters/09-uid-zygote-binder.md)).

**Intrusion Logging.** Android 16/17 tamper-evident forensic subsystem sealing USB, network, install, and boot events on-device under the user's E2EE key and streaming ciphertext to an append-only cloud vault immune to post-compromise deletion ([Chapter 14](../chapters/14-play-protect-intrusion-logging.md)).

**isolatedProcess.** Manifest service attribute (`android:isolatedProcess="true"`) spawning zero-permission ephemeral `u0_i*` sandboxes (`WebView` and Chrome renderers) barred from network sockets, storage, and most `Binder` services ([Chapter 9](../chapters/09-uid-zygote-binder.md)).

**Janus (CVE-2017-13156).** Landmark parser-differential vulnerability prepending a malicious `DEX` file ahead of a `v1`-signed ZIP archive, motivating whole-file `APK Signature Scheme v2` enforcement ([Chapter 10](../chapters/10-apk-signing-scoped-storage.md)).

**KCFI (Kernel Control Flow Integrity).** Clang forward-edge mitigation (`CONFIG_CFI_CLANG`) embedding 32-bit prototype type hashes immediately ahead of kernel function entry points and checking them inline before every indirect `BLR` call ([Chapter 7](../chapters/07-treble-gki-rust.md)).

**Key Attestation.** Cryptographic X.509 certificate extension (`OID 1.3.6.1.4.1.11129.2.1.17`) signed by `TEE`/`StrongBox` hardware proving key origin, `teeEnforced` tags, patch levels, and `RootOfTrust` over a fresh challenge nonce ([Chapter 15](../chapters/15-key-attestation-rkp.md)).

**KeyMint.** Versioned Stable `AIDL` hardware cryptographic subsystem (succeeding `Keymaster` in Android 12+) paired with the userspace Rust `keystore2` daemon to enforce `AuthorizationList` tags and boot-bound AEAD key wrapping ([Chapter 4](../chapters/04-keymint-weaver-throttling.md)).

**LSKF (Lock Screen Knowledge Factor).** The human owner's primary PIN, pattern, or alphanumeric password, stretched to unlock `Weaver` slots, unwrap `SyntheticPassword`, and recover `Titan` Cloud Key Vault shares ([Chapter 4](../chapters/04-keymint-weaver-throttling.md) and [Chapter 19](../chapters/19-e2ee-backups-private-ai-compute.md)).

**Microdroid.** Minimal, verified Android-based guest operating system shipped inside the `com.android.virt` `APEX` to host isolated workloads inside `AVF` Protected Virtual Machines ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md)).

**neverallow.** Compile-time negative `SELinux` assertion in AOSP's `system/sepolicy` mechanically audited against compiled OEM binary policies by `CTS` `SELinuxHostTest` to prevent permissive or over-privileged vendor rules ([Chapter 6](../chapters/06-selinux-seccomp.md)).

**Patch Gap.** Multi-month latency across upstream Linux/silicon git commits, SoC BSP drops, Android Security Bulletins, and OEM/carrier OTA rollouts exploited by commercial spyware vendors to weaponize public fixes as n-day chains ([Chapter 20](../chapters/20-multivendor-spyware-chains.md)).

**pKVM (Protected KVM).** Minimal `EL2` hypervisor (`arch/arm64/kvm/hyp/nvhe`) that owns Host and Guest Stage-2 MMU and `SMMUv3` translation tables, unmapping donated Protected VM pages from the untrusted host `EL1` Linux kernel ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md)).

**Play Integrity API.** Google Play's brokered attestation service returning `BASIC`, `DEVICE`, and `STRONG` integrity, licensing, and environment risk verdicts for certified GMS devices ([Chapter 16](../chapters/16-play-integrity-keybox-wars.md)).

**Private AI Compute.** Google's confidential cloud AI architecture terminating end-to-end `HPKE`-encrypted Android prompts inside `DICE`-attested, stateless `Titanium Intelligence Enclaves` (`TIE`) on custom Google TPUs ([Chapter 19](../chapters/19-e2ee-backups-private-ai-compute.md)).

**Private Compute Core (PCC).** `SELinux` network-air-gapped Android sandbox hosting `AICore`, Live Caption, and Smart Reply, permitted external communication strictly via open-source `Private Compute Services` (`Federated Compute`, `PIR`) ([Chapter 18](../chapters/18-on-device-agentic-ai.md)).

**Project Mainline.** Modular system-servicing architecture delivering signed `APEX` and APK updates (`ART`, `Conscrypt`, `MediaProvider`, `rkpd`, `virt`) directly via Google Play without OEM firmware OTAs ([Chapter 2](../chapters/02-antirollback-verity-apex.md)).

**Project Treble.** Architectural separation between `/system` and `/vendor` via versioned, Binderized `VINTF` HAL processes so core OS updates do not depend on recompiling SoC vendor code ([Chapter 7](../chapters/07-treble-gki-rust.md)).

**Protected Confirmation.** Hardware-isolated `WYSIWYS` UI and physical button confirmation flow minting an `HMAC`-authenticated token required before `KeyMint` signs high-stakes transactions ([Chapter 3](../chapters/03-trustzone-strongbox.md)).

**pvmfw (Protected VM Firmware).** Memory-safe `no_std` Rust bootstrap firmware enforced by `pKVM` as the first code inside every Protected VM to verify `Microdroid` payloads and advance `OpenProfile for DICE` `CDI` keys ([Chapter 5](../chapters/05-pkvm-avf-microdroid.md)).

**RKP (Remote Key Provisioning).** Dynamic certificate-provisioning protocol (`IRemotelyProvisionedComponent` + `rkpd`) replacing leak-prone factory keyboxes with short-lived attestation pools anchored in silicon `UDS`/`DICE` chains ([Chapter 15](../chapters/15-key-attestation-rkp.md)).

**RPMB (Replay Protected Memory Block).** Dedicated `HMAC-SHA256`-authenticated partition inside `UFS`/`eMMC` flash enforcing monotonic write counters for `AVB` rollback floors and `Gatekeeper` state ([Chapter 2](../chapters/02-antirollback-verity-apex.md)).

**Scoped Storage.** Filesystem isolation architecture restricting apps to private directories while mediating shared photos and documents through `MediaProvider` FUSE passthrough, EXIF redaction, and the zero-permission Photo Picker ([Chapter 10](../chapters/10-apk-signing-scoped-storage.md)).

**Scudo.** Hardened native heap allocator in `Bionic` `libc` combining randomized chunk slots, `CRC32` headers, quarantine queues, and `Arm MTE` granule tagging ([Chapter 8](../chapters/08-arm-mte-scudo.md)).

**seccomp-BPF.** Kernel syscall filter installed by `Zygote` prior to app execution that traps over `130` unused Linux syscalls (`SIGSYS`) to shrink reachable Ring 0 attack surface ([Chapter 6](../chapters/06-selinux-seccomp.md)).

**Secure Virtual Window.** Isolated `VirtualDisplay` container used by Android 16/17 Gemini UI automation to restrict legacy UI actions to a single opt-in target app with mandatory user takeover before payment or send commits ([Chapter 18](../chapters/18-on-device-agentic-ai.md)).

**Shadow Call Stack (SCS).** Backward-edge control-flow defense reserving ARM64 register `x18` for an isolated return-address stack across `GKI` and userspace to defeat stack-buffer `ROP` attacks ([Chapter 7](../chapters/07-treble-gki-rust.md)).

**StrongBox.** Discrete, physically tamper-resistant security processor (`Google Titan M2` or `Samsung Knox Vault`) with private on-die SRAM/NVM, `TRNG`, side-channel/laser countermeasures, and `Weaver` slots ([Chapter 3](../chapters/03-trustzone-strongbox.md)).

**SyntheticPassword (SP).** Random 256-bit intermediate secret generated by `LockSettingsService` from which `FBE` `CE` keys derive, wrapped behind `LSKF` + `Weaver` + `KeyMint` ([Chapter 4](../chapters/04-keymint-weaver-throttling.md)).

**TIKTAG.** Speculative-execution cache side-channel technique (`2024`) probing 4-bit `Arm MTE` tags inside mispredicted branches without raising architectural `SEGV_MTESERR` crashes ([Chapter 8](../chapters/08-arm-mte-scudo.md)).

**Titanium Intelligence Enclaves (TIE).** Google's hardware-attested confidential cloud boundary spanning `Titan`/`Titanium`-rooted hosts and custom `TPU` accelerators to serve `Private AI Compute` inference ([Chapter 19](../chapters/19-e2ee-backups-private-ai-compute.md)).

**TrickyStore.** Privileged root-spoofing framework intercepting `keystore2` `Binder` replies in `system_server` to forge X.509 `OID .17` leaf certificates using leaked pre-`RKP` OEM factory keyboxes ([Chapter 16](../chapters/16-play-integrity-keybox-wars.md)).

**Weaver.** `StrongBox` hardware secret-throttling HAL storing 128-bit secrets inside private `Titan M2` / `Knox Vault` NVM behind monotonic exponential backoff timers that defeat `NAND mirroring` ([Chapter 4](../chapters/04-keymint-weaver-throttling.md)).

**Work Profile.** Managed corporate secondary user (`userId 10+`) isolated by kernel `UID` arithmetic, `SELinux` `MCS`, `CrossProfileIntentFilter`, and a separate `FBE` master key $K_{\text{CE}, 10}$ ([Chapter 17](../chapters/17-android-enterprise.md)).

**Zero-Touch Enrollment.** Cloud-anchored hardware provisioning service binding corporate-owned Android handsets to enterprise `DPC` supervision across initial setup and every factory reset ([Chapter 17](../chapters/17-android-enterprise.md)).

**Zygote.** Pre-initialized `ART` fork server (`Zygote64`, `WebViewZygote`, `AppZygote`) that specializes new application processes via `COW` memory sharing, `seccomp-BPF` installation, capability dropping, and `SELinux` domain transition ([Chapter 6](../chapters/06-selinux-seccomp.md) and [Chapter 9](../chapters/09-uid-zygote-binder.md)).
