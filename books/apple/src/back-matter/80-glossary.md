# Glossary

**ACME (`Automatic Certificate Management Environment`).** An `IETF` (`RFC 8555`) automated certificate issuance protocol extended by Apple with the `device-attest-01` challenge so enterprise authorities verify `SEP` hardware key residency and OS posture before issuing `mTLS` or `802.1X` X.509 client certificates ([Chapter 12](../chapters/12-sep-app-device-attestation.md)).

**Activation Lock.** An anti-theft mechanism linking a device's hardware `ECID` and `SEP` state to an owner's Apple Account (or `MDM` escrow record) on Apple's activation servers so wiped hardware refuses post-restore activation without authorized credentials ([Chapter 11](../chapters/11-keychain-stolen-device.md)).

**ADE (`Automated Device Enrollment`).** The zero-touch enterprise provisioning mechanism anchored in `Apple Business Manager` that compels `Setup Assistant` at activation time to enroll a corporate-owned device into supervision and non-removable `MDM`/`DDM` management ([Chapter 14](../chapters/14-ddm-platform-sso.md)).

**ADP (`Advanced Data Protection`).** An opt-in `iCloud` security configuration that deletes Apple-held server copies of `CloudKit` service keys across 23+ categories (`Backup`, `Photos`, `Drive`, `Notes`, `Messages`) and rotates wrapping keys exclusively into the user's `SEP`-backed `Octagon` device circle ([Chapter 15](../chapters/15-icloud-hsm-adp.md)).

**AFU (`After First Unlock`).** The runtime device state entered once a user enters their passcode at least one time after cold boot, leaving `Data Protection` Class `C` keys unwrapped for background daemons until reboot or expiration of the 72-hour inactivity timer ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**ACP (`Agent Client Protocol`).** A standardized client-to-coding-agent protocol integrated alongside `MCP` in `Xcode 26` for coordinating autonomous repository analysis and code edits across local or containerized developer environments ([Chapter 18](../chapters/18-agentic-ai-workload-isolation.md)).

**AMFI (`AppleMobileFileIntegrity`).** The `XNU` `MACF` kernel extension (`AMFI.kext`) and companion user-space helper (`amfid`) enforcing `Mach-O` code-signing flags, `DER` entitlements, and provisioning profiles alongside `TXM` ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**AP (`Application Processor`).** The primary cluster of performance and efficiency `ARM64` CPU cores executing `iBoot`, `XNU`, `SPTM`, and user applications, partitioned across the SoC fabric from isolated enclaves such as `SEP` and `R1` ([Foundations](../chapters/00b-foundations.md)).

**APFS (`Apple File System`).** Apple's copy-on-write, snapshot-capable filesystem supporting cryptographic `Signed System Volume` (`SSV`) Merkle trees on the read-only `System` volume and per-file `XTS-AES` Data Protection on the mutable `Data` volume ([Chapter 5](../chapters/05-apfs-ssv-dyld.md), [Chapter 10](../chapters/10-apfs-data-protection.md)).

**ApNonce (`BNCH`).** An ephemeral cryptographic boot nonce seeded by `SEP` (`SHA-384` of a protected generator) and embedded inside `TSS`-signed `Image4` manifests to defeat replay of superseded firmware tickets ([Chapter 1](../chapters/01-secure-boot.md)).

**App Attest (`DCAppAttestService`).** A privacy-preserving `DeviceCheck` primitive issuing anonymous, per-app, per-installation `SEP` hardware attestations and `CBOR` counter assertions without exposing hardware serial numbers across applications ([Chapter 12](../chapters/12-sep-app-device-attestation.md)).

**App Groups.** Provisioned shared container directories authorized via `TXM`-verified `DER` entitlements allowing multiple sandboxed apps or extensions signed under the same developer `TeamID` to exchange files ([Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**App Intents.** Apple's strongly typed Swift schema framework exposing structured, parameter-validated application actions to Siri, Spotlight, and `Apple Intelligence` without raw UI scraping or shell execution ([Chapter 18](../chapters/18-agentic-ai-workload-isolation.md)).

**Apple Containerization.** Apple's open-source Swift framework (`apple/containerization` and `container` CLI) running each `OCI` Linux container or developer agent inside its own dedicated sub-second lightweight virtual machine atop `Virtualization.framework` ([Chapter 18](../chapters/18-agentic-ai-workload-isolation.md)).

**AppleDART (`Device Address Resolution Table`).** Apple Silicon's hardware I/O memory management unit (`IOMMU`) enforcing per-stream physical DMA translation barriers between peripheral controllers (USB, PCIe, Wi-Fi, GPU) and system DRAM ([Foundations](../chapters/00b-foundations.md), [Chapter 1](../chapters/01-secure-boot.md)).

**APRR / SPRR (`Access / System Permission Reconfiguration Registers`).** Custom Apple Silicon MMU indirection registers mapping page-table permission indices to per-core read/write/execute states, powering fast thread-local `JIT` and `TPRO` write locks ([Chapter 4](../chapters/04-silicon-memory-safety.md), [Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**Audit Token (`audit_token_t`).** An unforgeable eight-integer identity structure stamped onto `Mach` IPC message trailers inside `XNU` containing UIDs, GIDs, `pid`, and the monotonic `pidversion` generation counter that defeats POSIX PID-reuse races ([Foundations](../chapters/00b-foundations.md), [Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**AuxKC (`Auxiliary Kernel Collection`).** A locally linked collection of administrator-approved third-party `macOS` kernel extensions (`kexts`) authorized under `1TR` `Reduced Security` by pinning its `SHA-384` digest inside a `SEP`-signed `LocalPolicy` ([Chapter 2](../chapters/02-mac-localpolicy.md)).

**AWDL (`Apple Wireless Direct Link`).** Apple's low-latency peer-to-peer `802.11` Wi-Fi data link (`awdl0`) carrying mutual-TLS `AirDrop`, `Handoff`, and `Universal Clipboard` traffic after Bluetooth Low Energy discovery ([Chapter 13](../chapters/13-accounts-passkeys-continuity.md)).

**BAA (`Basic Attestation Authority`).** A factory-provisioned `SEP` intermediate X.509 certificate chaining to an Apple Attestation Root CA used to certify `OIHR` `LocalPolicy` keys and hardware-attested leaf keys ([Chapter 2](../chapters/02-mac-localpolicy.md), [Chapter 12](../chapters/12-sep-app-device-attestation.md)).

**BFU (`Before First Unlock`).** The maximum-security at-rest device state following cold boot, power loss, or the 72-hour inactivity reboot prior to user passcode entry, during which Class `A`, `B`, and `C` keys remain sealed inside `SEP` and biometrics are disabled ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**BlastDoor.** A tightly sandboxed, stateless Swift airlock service interposed in front of `imagent` (`Messages` and `FaceTime`) to decode untrusted `BPList`, image, and pass payloads without network, file, or `JIT` privileges ([Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**BootKC (`Boot Kernel Collection`).** The prelinked `Mach-O` archive bundling `XNU` and Apple's first-party system kernel extensions verified by `iBoot` via `Image4` before kernel startup ([Chapter 1](../chapters/01-secure-boot.md), [Chapter 2](../chapters/02-mac-localpolicy.md)).

**Boot ROM (`SecureROM`).** Immutable lithographic mask read-only memory inside every Apple Silicon SoC holding the initial reset vector code, USB `DFU` recovery stack, and silicon-fused Apple Root CA public-key hash ([Chapter 1](../chapters/01-secure-boot.md)).

**Bootstrap Token.** A `SEP`-backed cryptographic secret escrowed to an enterprise `MDM` server on supervised Apple Silicon Macs to automate `SecureToken` grants and authorize `SSV` software updates ([Chapter 14](../chapters/14-ddm-platform-sso.md)).

**BrowserEngineKit.** An Apple framework separating web renderers (`WebContent`), `GPU`, and `Networking` extension processes with `APRR` `JIT` isolation for alternative browser engines under the European Union `DMA` ([Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**CDHash (`CodeDirectory Hash`).** The cryptographic digest (`SHA-256`, often truncated to 20 bytes in trust caches) computed over a `Mach-O` binary's `CS_CodeDirectory` structure, uniquely identifying its code pages and `DER` entitlements ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**CloudKit.** Apple's structured cloud storage substrate organizing records into encrypted containers and zones wrapped by per-record, per-zone, and root service keys ([Chapter 15](../chapters/15-icloud-hsm-adp.md)).

**CodeDirectory (`CS_CodeDirectory`).** The core `Mach-O` code-signing data structure holding `SHA-256` hashes for every 4 KB executable page alongside negative special slots for `Info.plist`, resources, and `DER` entitlements ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**Contact Key Verification (`KT`).** An append-only, `VRF`-indexed cryptographic Merkle transparency log paired with continuous on-device self-auditing (`transparencyd`) that detects unauthorized key injection in `iMessage` `IDS` lookups ([Chapter 16](../chapters/16-imessage-pq3-kt.md)).

**CoreTrust.** The `XNU` kernel component (`CoreTrust.kext`) and parsing library responsible for validating Apple X.509 certificate chains, `CMS` signatures, and `DER` provisioning profiles prior to `TXM`/`AMFI` policy checks ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**Cryptex (`Cryptographic Extension`).** An independently signed, `TSS`-personalized `Image4` `APFS` volume grafted onto the sealed system namespace at boot to deliver `Safari`, `dyld`, and Background Security Improvements without re-sealing `/` ([Chapter 5](../chapters/05-apfs-ssv-dyld.md)).

**Data Protection.** Apple's per-file `APFS` cryptographic storage architecture wrapping random 256-bit file keys under `SEP`-managed Class `A`, `B`, `C`, and `D` keys enforced by inline `XTS-AES` hardware ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**Data Vault (`UF_DATAVAULT`).** A kernel-enforced BSD filesystem flag blocking even `UID 0` `root` processes from opening sensitive OS directories (`TCC.db`, Mail, Safari) without matching private Apple entitlements ([Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md), [Chapter 8](../chapters/08-macos-tcc-sysext.md)).

**DDM (`Declarative Device Management`).** Apple's modern fleet-management paradigm (`remotemanagementd`) in which endpoints autonomously evaluate local state predicates over `Activations` and `Configurations` and push proactive `StatusChannel` updates ([Chapter 14](../chapters/14-ddm-platform-sso.md)).

**DER (`Distinguished Encoding Rules`).** The canonical, non-malleable binary subset of `ITU-T X.690` `ASN.1` used by Apple across `Image4` firmware manifests, `Mach-O` slot `-7` entitlements, and `Launch Constraints` ([Foundations](../chapters/00b-foundations.md), [Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**DFU (`Device Firmware Upgrade`).** The emergency USB recovery mode implemented directly inside immutable `Boot ROM`, accepting signed `Image4` bootstrap images when flash bootloaders are corrupted ([Chapter 1](../chapters/01-secure-boot.md)).

**DriverKit.** A `macOS` and M-series `iPadOS` `SystemExtensions` framework relocating USB, PCIe, networking, and audio hardware drivers out of `EL1` `XNU` into sandboxed `EL0` user-space `.dext` processes behind `AppleDART` ([Chapter 8](../chapters/08-macos-tcc-sysext.md)).

**DULT (`Detecting Unwanted Location Trackers`).** The joint Apple and Google `IETF` standard defining cross-platform Bluetooth separated-from-owner beacon flags, trajectory alerts, and chime triggers to deter physical stalking ([Chapter 17](../chapters/17-find-my-anti-tracking.md)).

**dyld (`Dynamic Link Editor`).** User-space `/usr/lib/dyld` (`dyld4`) responsible for mapping the pre-linked `dyld_shared_cache`, validating `PrebuiltLoader` closures, signing `__AUTH_GOT` pointers, and sealing loader state with `TPRO` ([Chapter 5](../chapters/05-apfs-ssv-dyld.md)).

**ECID (`Exclusive Chip ID`).** A factory-fused 64-bit unique identifier burned into every Apple Silicon die and bound into `TSS` `Image4` manifests so firmware tickets cannot move across devices ([Chapter 1](../chapters/01-secure-boot.md)).

**Effaceable Storage.** Dedicated NAND/NOR storage cells lacking wear-leveling retention copies that hold root media wrapping keys (`DKey`, `EMF`, `BAG1`), enabling millisecond cryptographic device obliteration ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**EMTE (`Enhanced Memory Tagging Extension`).** Apple's custom hardware memory-tagging architecture on `A19` and `M5` silicon enforcing zero-latency synchronous 4-bit allocation-tag checks alongside speculative tag-confidentiality protections ([Chapter 4](../chapters/04-silicon-memory-safety.md)).

**EndpointSecurity (`ESF`).** A privileged `macOS` framework (`EndpointSecurity.kext`) delivering deadline-bounded synchronous `AUTH` gates and asynchronous `NOTIFY` audit telemetry to entitled user-space security extensions ([Chapter 9](../chapters/09-esf-xprotect-forensics.md)).

**Exclaves (`Secure Exclaves`).** Tightly coupled hardware-isolated execution environments on `A17 Pro` and `M3`/`M4`/`M5` silicon enforcing camera/microphone privacy indicator pixels independently of `XNU` ([Foundations](../chapters/00b-foundations.md), [Chapter 4](../chapters/04-silicon-memory-safety.md)).

**FileVault.** Full-volume `APFS` `XTS-AES-256` encryption on `macOS` binding `SEP`-managed volume encryption keys to authorized `SecureToken` user credentials and recovery keys ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**Gatekeeper.** The `macOS` execution-admission subsystem (`syspolicyd`) evaluating `com.apple.quarantine` attributes, `Developer ID` signatures, Hardened Runtime flags, `XProtect` rules, and Apple Notarization tickets ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**GID (`Group ID`).** A 256-bit silicon-fused key shared across all dies of an identical SoC model (for example, all `M4` chips) wired to the hardware `AES` engine solely to unwrap obfuscated firmware `KBAG`s ([Chapter 3](../chapters/03-secure-enclave.md)).

**GrandSlam (`GSA`).** Apple's core account authentication protocol executing `RFC 5054` `SRP-6a` zero-knowledge password proofs paired with trusted-device two-factor verification ([Chapter 13](../chapters/13-accounts-passkeys-continuity.md)).

**Guarded Execution (`GL0` - `GL2`).** Apple Silicon's proprietary privilege plane orthogonal to `ARM64` `EL0`-`EL2`, hosting `SPTM` (`GL2`) and `TXM` (`GL0`) outside the `XNU` kernel's write authority ([Foundations](../chapters/00b-foundations.md), [Chapter 4](../chapters/04-silicon-memory-safety.md)).

**iBoot.** Apple's second-stage system bootloader (`ibot`) responsible for configuring `AppleDART` IOMMUs, authenticating co-processor firmwares (`SEP`, `SPTM`, `TXM`), evaluating `LocalPolicy` on Macs, and launching `BootKC` ([Chapter 1](../chapters/01-secure-boot.md)).

**IDS (`Apple Identity Service`).** The global directory infrastructure mapping Apple Account emails and phone numbers to per-device `iMessage` and `FaceTime` cryptographic prekey bundles, audited by `KT` ([Chapter 16](../chapters/16-imessage-pq3-kt.md)).

**Image4 (`IMG4`).** Apple's canonical `ASN.1` `DER` container format uniting an `IM4P` payload, a `TSS`- or `OIHR`-signed `IM4M` manifest, and optional `IM4R` `BNCH` restore nonces ([Foundations](../chapters/00b-foundations.md), [Chapter 1](../chapters/01-secure-boot.md)).

**KTRR / CTRR (`Kernel / Configurable Text Readonly Region`).** Silicon memory-controller range locks initialized by `iBoot` that render static `XNU` executable text physically immutable against both CPU writes and DMA ([Chapter 4](../chapters/04-silicon-memory-safety.md)).

**Launch Constraints.** `ASN.1` `DER` boolean rules evaluated at `posix_spawn`/`execve` restricting a binary's own identity, parent process (`launchd`), and responsible process to block living-off-the-land daemon abuse ([Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**LocalPolicy.** A per-volume-group `Image4` manifest on Apple Silicon Macs signed inside `1TR` by `SEP`'s `OIHR` key recording `Full`, `Reduced`, or `Permissive Security` settings, `SIP` flags, and `AuxKC` hashes ([Chapter 2](../chapters/02-mac-localpolicy.md)).

**Lockdown Mode.** An optional high-assurance surface-reduction profile across `iOS`, `iPadOS`, `macOS`, and `watchOS` that disables `WebKit` `JIT`, blocks risky `BlastDoor` codecs (`JBIG2`/fonts), and cuts locked wired USB data paths ([Chapter 10](../chapters/10-apfs-data-protection.md)).

**MACF (`Mandatory Access Control Framework`).** `XNU`'s TrustedBSD-derived kernel hook layer (`mac_policy_ops`) mediating file, IPC, process, and VM operations across `AMFI`, `Seatbelt`, `Quarantine`, and `EndpointSecurity` ([Foundations](../chapters/00b-foundations.md), [Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**MCP (`Model Context Protocol`).** An open tool-and-context integration protocol adopted in `Xcode 26` and developer CLI agents whose subprocesses inherit host `macOS` `TCC` `responsible_pid` grants unless isolated in micro-VMs ([Chapter 18](../chapters/18-agentic-ai-workload-isolation.md)).

**MDA (`Managed Device Attestation`).** Enterprise device-identity attestation pairing `SEP` posture certificates with `RFC 8555` `ACME` (`device-attest-01`) under `MDM`/`DDM` supervision ([Chapter 12](../chapters/12-sep-app-device-attestation.md)).

**MIE (`Memory Integrity Enforcement`).** Apple's comprehensive hardware-software memory-safety system on `A19` and `M5` silicon combining typed allocators (`kalloc_type`, `xzone`) with always-on synchronous `EMTE` across `XNU` and 70+ daemons ([Chapter 4](../chapters/04-silicon-memory-safety.md)).

**Octagon.** The peer-to-peer cryptographic trust-circle subsystem inside `secd` synchronizing `iCloud Keychain` items, `Passkeys`, and `ADP` service keys across a user's `SEP`-verified devices ([Chapter 15](../chapters/15-icloud-hsm-adp.md)).

**OHTTP (`Oblivious HTTP`).** An `IETF` (`RFC 9458`) privacy relay architecture used by `Private Cloud Compute` so a third-party relay learns the client IP without seeing the prompt while `PCC` decrypts the prompt without seeing the client IP ([Chapter 19](../chapters/19-private-cloud-compute.md)).

**OIHR (`Owner Identity Hardware Root`).** The per-machine asymmetric signing keypair generated inside an Apple Silicon Mac's `SEP` to sign volume-scoped `LocalPolicy` manifests ([Chapter 2](../chapters/02-mac-localpolicy.md)).

**One True Recovery (`1TR`).** The privileged `recoveryOS` environment paired to active System Firmware on Apple Silicon Macs and entered only via a `PMU`-verified cold-boot physical power-button hold ([Chapter 2](../chapters/02-mac-localpolicy.md)).

**Optic ID.** Iris-structure biometric authentication on `Apple Vision Pro` routing near-infrared eye captures through the `R1` co-processor into `SEP` and the Neural Engine ([Chapter 3](../chapters/03-secure-enclave.md), [Chapter 13](../chapters/13-accounts-passkeys-continuity.md)).

**PAC (`Pointer Authentication`).** `ARMv8.3-A` hardware pointer signing (`QARMA` cipher tags in upper address bits diversified by context) protecting return addresses and C++/ObjC function pointers against `ROP`/`JOP` corruption ([Chapter 4](../chapters/04-silicon-memory-safety.md)).

**PCC (`Private Cloud Compute`).** Apple's verifiable cloud AI inference architecture built on stateless, diskless Apple Silicon server blades audited via a public `Image4` Transparency Log and accessed through `OHTTP` relays ([Chapter 19](../chapters/19-private-cloud-compute.md)).

**Platform SSO (`Platform Single Sign-On`).** The `macOS` enterprise identity framework binding `LoginWindow` credentials, OIDC/Entra `PRT` tokens, and Kerberos tickets to non-exportable `SEP` keys ([Chapter 14](../chapters/14-ddm-platform-sso.md)).

**PQ3.** Apple's `Level 3` post-quantum `iMessage` cryptographic protocol uniting `P-256` identity/ratchet keys with `ML-KEM-768` session initialization and periodic `ML-KEM-1024` post-compromise healing ([Chapter 16](../chapters/16-imessage-pq3-kt.md)).

**R1 Co-Processor.** The dedicated real-time sensor-fusion chip inside `Apple Vision Pro` isolating raw infrared eye-tracking camera feeds from untrusted `visionOS` applications until a finger pinch occurs ([Chapter 13](../chapters/13-accounts-passkeys-continuity.md)).

**Seatbelt (`Sandbox.kext`).** Apple's `MACF` mandatory sandboxing engine compiling `SBPL` S-expression profiles into deterministic kernel bytecode enforcing App Sandbox, daemon isolation, and `BlastDoor` containment ([Chapter 7](../chapters/07-ipc-seatbelt-blastdoor.md)).

**SEP (`Secure Enclave Processor`).** The dedicated on-die security processor running `SEPROM` and the `L4`-derived `sepOS` microkernel over encrypted DRAM with hardware-fused `UID`/`GID` `AES` engines and anti-replay counters ([Chapter 3](../chapters/03-secure-enclave.md)).

**SIP (`System Integrity Protection`).** Runtime `macOS` mandatory access controls (`csr_active_config`) restricting even `UID 0` `root` from modifying system paths, attaching debuggers to platform binaries, or loading unapproved kexts ([Chapter 2](../chapters/02-mac-localpolicy.md)).

**SPTM (`Secure Page Table Monitor`).** The minimal root hardware monitor in Guarded Execution `GL2` (`A15+` and `M2+`) owning physical frame types, CPU page tables, `EL2` Stage-2 tables, and `AppleDART` mappings above `XNU` ([Chapter 4](../chapters/04-silicon-memory-safety.md)).

**SSV (`Signed System Volume`).** `APFS`'s cryptographic root-volume seal verifying every 4 KB OS block and catalog node on page-in against a read-only snapshot Merkle root pinned inside `Image4` ([Chapter 5](../chapters/05-apfs-ssv-dyld.md)).

**Stolen Device Protection.** An `iOS` (`17.3+`) anti-theft control stripping passcode fallback in favor of live biometrics plus an unfamiliar-location 1-hour security delay before sensitive account or credential changes ([Chapter 11](../chapters/11-keychain-stolen-device.md)).

**TCC (`Transparency, Consent, and Control`).** The user-privacy subsystem (`tccd` and `TCC.db`) gating access to user folders, camera, microphone, screen recording, and `AppleEvents` via `audit_token_t` and `responsible_pid` attribution ([Chapter 8](../chapters/08-macos-tcc-sysext.md)).

**TSS (`Tatsu Signing Server`).** Apple's live firmware-personalization authority issuing per-`ECID`, `ApNonce`-bound `Image4` `IM4M` tickets only while an OS build's signing window remains open ([Chapter 1](../chapters/01-secure-boot.md)).

**TXM (`Trusted Execution Monitor`).** The guarded code-signing monitor running in `GL0` (`SPTM`-backed silicon) managing static/dynamic trust caches, `CS_CodeDirectory` validation, and `DER` entitlements outside `XNU` write reach ([Chapter 4](../chapters/04-silicon-memory-safety.md), [Chapter 6](../chapters/06-amfi-txm-notarization.md)).

**UID (`Unique ID`).** The per-die 256-bit random cryptographic key fused inside silicon during manufacturing and wired exclusively to hardware `AES` engines inside `SEP`/storage without ever being readable by software or recorded by Apple ([Chapter 3](../chapters/03-secure-enclave.md)).

**XProtect.** `macOS`'s layered built-in antimalware stack combining launch-time `YARA` rules (`XProtect`), scheduled cleanup plugins (`XProtect Remediator`), and kernel-enforced behavioral rules (`Bastion`) ([Chapter 9](../chapters/09-esf-xprotect-forensics.md)).
