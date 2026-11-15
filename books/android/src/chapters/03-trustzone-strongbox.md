# Arm TrustZone TEEs vs. Discrete StrongBox Security Processors

## Overview

* **Link in the Chain:** Hardware secret-isolation and physical tamper-resistance substrate; isolates cryptographic key material, PIN rate-limiting state, and high-assurance confirmation UI outside the Normal World `EL1` Linux kernel.
* **Core Security Invariant:** Private keys generated inside a Trusted Execution Environment (`TEE`) or discrete `StrongBox` security processor never enter Normal World DRAM in plaintext, and `StrongBox` operations additionally resist physical off-die probing, electromagnetic side channels, and voltage or laser fault injection.
* **Ecosystem Enforcement Tier:** Available in both `GREEN` and `YELLOW` locked states with cryptographic key sealing bound to the active verified boot root; accessible in `ORANGE` unlocked state only for newly generated `UNVERIFIED`-bound keys (previously sealed `GREEN`/`YELLOW` keys stay cryptographically inaccessible, and Samsung devices blow the irreversible `Knox` fuse on first unlock).
* **Trusted Computing Base (TCB):** For `TEE`: `EL3` Secure Monitor (`BL31`), `TZASC` DRAM firewall, `S-EL1` OS (`Trusty`, `Qualcomm QTEE`/`QSEE`, `Trustonic Kinibi`, `OP-TEE`), and all co-resident `S-EL0` trustlets; for `StrongBox`: dedicated off-SoC silicon (`Google Titan M2` RISC-V or `Samsung Knox Vault`), private on-die SRAM/NVM, hardware `TRNG`, and narrow `SPI`/mailbox firmware.
* **Seam & Handoff:** Provides physically and logically isolated execution engines (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT` and `SECURITY_LEVEL_STRONGBOX`); hands typed key-usage policy enforcement (`AuthorizationList`), boot-patchlevel sealing, and `Weaver` passcode throttling protocols to [Chapter 4](04-keymint-weaver-throttling.md).

## Threat Model & Ecosystem Constraint

Even with `AVB 2.0` ([Chapter 1](01-bootrom-avb-vbmeta.md)) and `dm-verity` ([Chapter 2](02-antirollback-verity-apex.md)) guaranteeing that the Linux kernel boots from unmodified code, runtime `Ring 0` (`EL1`) memory is never permanently trustworthy. Over the past decade, hundreds of vulnerabilities in GPU shader interfaces, USB gadget parsers, Wi-Fi drivers, and VFS subsystems have granted adversaries arbitrary kernel read and write primitives inside `EL1` [30, 94, 138]. If Android stored `File-Based Encryption` master keys, `Keystore` ECDSA private keys, or Lock Screen Knowledge Factor (`LSKF`) verification secrets inside kernel slab memory, a single kernel exploit or physical cold-boot/DMA extraction would instantaneously compromise every secret on the device and allow offline supercomputer brute-forcing of a six-digit PIN ($10^6$ guesses in milliseconds) [30, 41].

Isolating secrets from `EL1` across a multi-vendor mobile ecosystem encounters two distinct threat classes that pull hardware architecture in opposite directions [6, 33]:

First is the *software Ring 0 adversary*: an attacker executing arbitrary code at `EL1` (and potentially `EL2`) on the main application processor who can invoke arbitrary Secure Monitor Calls (`SMC`), corrupt shared Normal-to-Secure communication buffers (`ION` / `dma-buf`), and attempt to confuse Secure World parsers into overwriting `S-EL1` page tables [30, 31, 32].

Second is the *physical lab adversary*: an intelligence service, forensic laboratory, or well-funded hardware thief with microscope access to the printed circuit board who can desolder and clone external `UFS` flash chips (`NAND mirroring` [41]), attach electromagnetic near-field probes over the SoC package to record Differential Power Analysis (`DPA`) traces during `AES`/`ECDSA` execution, or inject nanosecond voltage drops and focused infrared laser pulses to skip branch instructions inside a PIN-counter check [33, 34]. On-SoC `Arm TrustZone` was originally designed to solve the first problem at near-zero bill-of-materials cost; discrete `StrongBox` silicon (`Titan M2` and `Knox Vault`) was engineered because `TrustZone` repeatedly failed against both expanded software attack surfaces and physical silicon attacks.

## Architecture & AOSP Implementation

### `Arm TrustZone`: `SMC` World Switching, `TZASC`, and `S-EL1` TEEs

Every modern Android SoC implements `Arm TrustZone` (`ARMv8-A`/`ARMv9-A` Security Extension), time-slicing each physical Cortex/Oryon CPU core between Normal World (`SCR_EL3.NS = 1`) and Secure World (`SCR_EL3.NS = 0`) [5, 6]. Normal World kernel drivers cannot jump into Secure World directly; instead, Linux kernel `TEE` client drivers (`drivers/tee/` or `drivers/trusty/`) populate registers `x0` through `x7` according to the Arm `SMC Calling Convention` (`ARM DEN 0028` [28], encoding Fast Calls vs. Yielding Calls, 32/64-bit convention, and Owning Entity Numbers) and execute the `SMC #0` instruction.

Executing `SMC` traps synchronously into the `EL3` Secure Monitor (`BL31`), which saves Normal World general-purpose and system registers into an `EL3` per-CPU context structure, flips `SCR_EL3.NS = 0`, restores the Secure World register file, and executes `ERET` into the `S-EL1` Trusted Operating System [6, 28]. Memory isolation relies on hardware bus tagging: Secure World page tables emit AXI bus transactions with `AxPROT[1] = 0` (`Secure`), whereas Normal World `EL1` and `EL2` always emit `AxPROT[1] = 1` (`Non-Secure`). The SoC's TrustZone Address Space Controller (`TZASC` / `TZC-400`) sits in front of the LPDDR DRAM controller and rejects any `Non-Secure` read, write, or peripheral DMA targeting physical DRAM regions configured as Secure Carveouts at boot [6].

![Figure: Architectural and attack-surface contrast between shared-silicon Arm TrustZone TEEs and discrete StrongBox security processors.](diagrams/03-trustzone-vs-strongbox.svg)

Within `S-EL1`, Android devices run one of four primary `TEE` operating systems [29, 30, 32]: Google's open-source `Trusty` TEE (`trusty/lk`, microkernel-derived from Little Kernel and deployed on Google Tensor Pixels alongside `Titan M2` and selected MediaTek platforms) [29], Qualcomm's proprietary `QTEE` (formerly `QSEE`, microkernel-based on Snapdragon SoCs) [30, 31], `Trustonic Kinibi` (deployed historically on Samsung Exynos and MediaTek chips), or Linaro's open-source `OP-TEE`. User-mode Trusted Applications (`TAs` or trustlets) execute in `S-EL0` address spaces separated by `S-EL1` `Stage-1` MMU tables, communicating with Normal World HAL daemons via shared non-secure memory ring buffers (`virtio` `tipc` in `Trusty` or `QSEECOM`/`SmcInvoke` on Qualcomm) [29, 31].

### Why Bloated `TrustZone` TEEs Repeatedly Broke

In theory, `S-EL1` should have hosted a tiny, formally auditable cryptographic microkernel. In commercial smartphone practice, OEMs and SoC vendors treated `TrustZone` as a convenient dumping ground for every feature needing protection from rooted users [30, 32]: `Widevine` Level 1 and `PlayReady` video DRM parsers handling complex H.264/HEVC subsample metadata, `HDCP 2.x` display authentication, fingerprint image pre-processors, secure camera ISP pipelines, mobile payment applets, and OEM enterprise licensing agents.

As Google Project Zero researcher Gal Beniamini (`CVE-2015-6639`, `CVE-2016-2431` [30]) and later academic fuzzing frameworks such as `Teezz` [32] demonstrated, this architectural bloat inverted `TrustZone`'s security proposition:

First, dozens of `S-EL0` trustlets written in C parsed attacker-controlled shared buffers passed directly from `EL1` over `QSEECOM` without `ASLR` (or with trivial 8-bit `ASLR`), stack canaries, or `W^X` enforcement in early builds [30]. Second, because `S-EL0` trustlets shared a broad `S-EL1` syscall table (and on older Qualcomm SoCs could even map physical Normal World memory or invoke DMA engines unconstrained by Secure `SMMU` contexts), compromising a `Widevine` DRM trustlet escalated into `S-EL1` kernel execution (`CVE-2016-2431`), allowing an attacker with Normal World root to extract hardware-derived `KeyMaster` keys or overwrite Normal World Linux kernel text from above [30, 31]! Third, even a bug-free `TrustZone` OS shares L1/L2/SLC CPU caches (vulnerable to `Prime+Probe` cache-timing leaks across `SMC` switches), shares the SoC's power distribution network (vulnerable to software-observable voltage/frequency fault attacks such as `CLKscrew` and `VoltPillager`), and possesses zero dedicated internal non-volatile flash, forcing it to store rollback-sensitive counters externally on `UFS` `RPMB` [33, 41].

### Discrete `StrongBox`: `Google Titan M2` and `Samsung Knox Vault`

Android 9 (`Pie`) introduced a second, higher hardware assurance tier into `Keystore`/`KeyMint` (`SecurityLevel::STRONGBOX`), realized on flagship handsets via physically discrete or air-gapped tamper-resistant security processors: `Google Titan M` (2018) and RISC-V-based `Google Titan M2` (Pixel 6 through Pixel 10+, co-developed with the open-source `OpenTitan` silicon root-of-trust project) [33], and `Samsung Knox Vault` (introduced on Galaxy S21+ and certified to Common Criteria `EAL5+`/`EAL6+`) [34].

Unlike `TrustZone`, `Titan M2` is a standalone, physically separate microchip mounted on the mainboard and connected to the `Google Tensor` SoC exclusively over a narrow, message-framed Serial Peripheral Interface (`SPI`) bus [33]. Inside the `Titan M2` package sit an custom hardened 32-bit `RISC-V` microcontroller core, dedicated on-die SRAM, private internal embedded flash (`NVM`) that cannot be desoldered or probed externally without decapsulating the die itself, a NIST-compliant physical True Random Number Generator (`TRNG`), and dedicated hardware cryptographic accelerators (`AES`, `SHA-2`/`SHA-3`, `HMAC`, `ECC`/`RSA` bignum engines) [33].

`Titan M2` and `Knox Vault` harden against both software escalation and physical lab attacks through four architectural properties [33, 34]:

First, *minimal fixed-function TCB*: `StrongBox` runs zero `Widevine` DRM codecs, zero video parsers, and zero third-party vendor trustlets. Its RTOS (`Tock`-inspired / dedicated firmware) implements strictly `KeyMint`, `Weaver` 64-slot passcode throttling ([Chapter 4](04-keymint-weaver-throttling.md)), `AVB` boot-state latching, and Insider Attack Resistance (`IAR`).

Second, *Insider Attack Resistance (`IAR`)*: even Google or Samsung cannot silently push a backdoored `StrongBox` firmware update to unlock a targeted user's phone! `Titan M2`'s boot ROM refuses to install or boot updated `StrongBox` firmware over an OTA unless the currently enrolled user enters their valid `LSKF` passcode, cryptographically proving owner consent before key migration occurs [33].

Third, *active silicon side-channel and fault-injection defenses*: derived from the `OpenTitan` hardware security architecture, `Titan M2` incorporates masked cryptographic S-boxes (defeating Differential and Correlation Power Analysis), randomized dummy clock cycles and instruction-timing jitter, redundant dual-core lockstep / shadow instruction counters, voltage/clock glitch detectors, and physical laser-fault sensors that zeroize sensitive key registers within picoseconds if focused light or electromagnetic fault pulses strike the die [33].

Fourth, *private internal NVM*: because `Weaver` retry counters live inside `Titan M2`'s own internal flash rather than external `UFS`, desoldering and re-flashing external storage chips (`NAND mirroring` [41]) has zero effect on the hardware attempt counter.

### `Android Protected Confirmation` (`WYSIWYS` Hardware Signing)

Even when a private key sits securely inside `StrongBox` (`Titan M2`), a compromised host Android OS (`EL1` kernel or `AccessibilityService` trojan in [Chapter 11](11-accessibility-advanced-protection.md)) could display `"Send USD 10 to Alice"` on the normal OLED screen while asking `StrongBox` to sign `"Send USD 10,000 to Eve"` over `SPI`! `Android Protected Confirmation` (`ConfirmationPrompt` API, backed by `IConfirmationUI` HAL and `Tag::TRUSTED_CONFIRMATION_REQUIRED`) closes this What-You-See-Is-What-You-Sign (`WYSIWYS`) gap for high-stakes medical (insulin pump dosing), enterprise, and wire-transfer approvals [35].

![Figure: Android Protected Confirmation hardware-isolated display and physical button approval sequence.](diagrams/03-protected-confirmation-flow.svg)

When an application generates an asymmetric signing key with `setUserConfirmationRequired(true)` and invokes `ConfirmationPrompt.presentPrompt(promptText, extraData)`, control transfers into a hardware-isolated Trusted UI environment (`Trusty` Trusted UI locking display composer planes via `TZASC`/`SMMU`, combined on Pixel devices with direct physical Power/Volume button GPIO routing monitored by `Titan M2`) [33, 35]. Normal World Linux loses ability to draw overlays over the framebuffer or synthesize touch events. Only when the human physically clicks the hardware confirmation button does the secure hardware compute a keyed `HMAC-SHA256` over the exact displayed UTF-8 text:

$$\tau_{\text{confirm}} = \text{HMAC}_{K_{\text{confirm}}}\bigl(\text{"confirmation token"} \parallel \text{CBOR}(\text{promptText}, \text{extraData})\bigr)$$

 Here $K_{\text{confirm}}$ is a symmetric secret shared exclusively between the Trusted UI / `StrongBox` confirmation module and `KeyMint` [35]. When the app subsequently calls `Signature.sign()`, `keystore2` passes $\tau_{\text{confirm}}$ into `KeyMint`, which verifies the `HMAC` and signs the CBOR-formatted `promptText` + `extraData` payload using the non-exportable `CONFIRMATION_REQUIRED` private key. A remote verifier checking both the `Key Attestation` certificate ([Chapter 15](15-key-attestation-rkp.md)) and the ECDSA signature receives mathematical proof that the genuine `StrongBox` hardware rendered that exact text and observed a physical human button press, even if `EL1` Linux was 100 percent owned [35].

## Vendor, OEM, & Custom-OS Boundaries

Support for `TEE` versus discrete `StrongBox` varies sharply by price tier and OEM silicon strategy, governed by `CDD` Section 9.11 [2]. Entry-level and mid-range Qualcomm Snapdragon and MediaTek Dimensity handsets typically implement `IKeyMintDevice` (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`) inside `QTEE`, `Trusty`, or `Kinibi` without a discrete off-die chip, meaning apps calling `setIsStrongBoxBacked(true)` receive `StrongBoxUnavailableException` and must fall back gracefully to `TEE`-backed keys [36].

Flagship Google Pixel (`Pixel 3` onward with `Titan M` / `Titan M2`) and Samsung Galaxy S/Z flagship series (`Knox Vault`) expose two simultaneous `IKeyMintDevice` HAL instances on the device: `/default` (`TrustZone` TEE, offering high-throughput `AES`/`RSA`/`ECDSA` bulk operations) and `/strongbox` (discrete silicon, offering maximum physical tamper resistance at slightly higher `SPI` bus latency, typically $15\text{ to }50\text{ ms}$ per asymmetric operation) [33, 34, 36]. On `GrapheneOS` (`YELLOW` locked Pixel), `Titan M2` operates identically to stock `GREEN` Pixel OS, providing full `StrongBox` `KeyMint`, `Weaver` rate limiting, and `Insider Attack Resistance` without requiring Google Play Services [16].

## Exploit Chains & Structural Limits

Historical vulnerabilities demonstrate vividly why Android shifted high-value secrets from monolithic `S-EL1` `TrustZone` stacks toward discrete `StrongBox` silicon and `EL2` `pKVM` isolation.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Qualcomm `QSEE` `Widevine` + Kernel Escalation (CVE-2015-6639, CVE-2016-2431) | 2015-2016 | `S-EL0` trustlet $\to$ `S-EL1` `QSEE` kernel | Normal World root invoking `QSEECOM` `SMC` buffers | Bounds-check bug in `Widevine` TA + missing pointer validation in `QSEE` syscall let TA overwrite `S-EL1` and extract `KeyMaster` FDE keys | Trustlet privilege reduction, `S-EL0` ASLR/DEP/CFI, and moving PIN throttling into discrete `StrongBox` `Weaver` [30, 33] |
| `CLKscrew` (CVE-2017-5715 / DVFS Faulting) | 2017 | Shared-die `TrustZone` CPU core | Compromised `EL1` kernel manipulating SoC DVFS clock/voltage regulators | Pushing CPU frequency/voltage out of spec induced deterministic bit faults inside `S-EL0` AES/RSA `TrustZone` operations | Dedicated off-SoC `StrongBox` clock/power domains with active glitch sensors (`Titan M2` / `Knox Vault`) [33, 34] |
| Qualcomm `QSEE` `ION` Shared-Buffer Overwrite (CVE-2019-10574, CVE-2019-14040) | 2019 | `QSEE` shared-memory mapper | Crafted `QSEECOM` `ION` scatter-gather descriptors from `EL1` | Improper validation of non-secure vs. secure memory overlaps allowed arbitrary write into Secure World memory | Strict `TZASC` overlap validation in `QTEE` and `SmcInvoke` capability model [31] |
| `Teezz` Multi-Vendor TA Vulnerabilities | 2023 | `QTEE`, `Kinibi`, and `OP-TEE` trustlets | Type-aware fuzzing from Normal World `/dev/qseecom` / `/dev/mobicore` | Complex C TLV serialization mismatches across OEM biometric, DRM, and payment TAs | Restrict `/dev/qseecom` via `SELinux` `neverallow` exclusively to specific HAL domains; migrate TAs to `pKVM` (`AVF`) [32, 43] |

### The Online-Oracle Limit of Any Hardware Security Module

Even a physically impenetrable `Titan M2` `StrongBox` chip obeys a fundamental cryptographic boundary that architects must never overlook: *hardware key isolation prevents key extraction, not online key invocation by an authorized caller that is currently compromised* [4, 36].

> **Warning.**
> If an application creates a `StrongBox` key with `setUserAuthenticationRequired(false)` (`TAG_NO_AUTH_REQUIRED`), a remote exploit running inside that application's UID (or a compromised `EL1` kernel impersonating that UID to `keystore2`) cannot steal the raw ECDSA private scalar $d$ off the phone, *but it can ask `StrongBox` to sign arbitrary challenges for as long as the implant remains active on the device*. Stopping silent background abuse requires binding keys to fresh human gestures (`HardwareAuthToken` or `Protected Confirmation`), which brings us directly to `KeyMint` authorization tags and `Weaver` throttling in [Chapter 4](04-keymint-weaver-throttling.md).

## Inspecting via ADB, Fastboot, & Attestation

Enumerate registered `KeyMint` (or legacy `Keymaster`) HAL instances (`default` TEE vs. `strongbox` discrete chip), `Weaver`, and `Protected Confirmation` services declared in the device's `VINTF` manifest via `lshal` / `service list`:

```bash
adb shell service list | grep -iE 'keymint|weaver|confirmationui'
adb shell getprop | grep -iE 'security.keystore|ro.hardware.keystore|titan|weaver'
```

Verify whether the handset advertises certified `StrongBox` hardware (`android.hardware.strongbox_keystore` feature version, e.g. `40` / `100` / `200` / `300` corresponding to `KeyMint` 1.0-3.0+) and `Android Protected Confirmation` via `pm list features`:

```bash
adb shell pm list features | grep -iE 'strongbox|hardware_keystore|confirmation'
```

On Google Pixel (`Tensor` + `Titan M2`) or Trusty-based devices, inspect non-sensitive `Titan` / `StrongBox` firmware version and `TEE` initialization properties exposed to `dumpstate`:

```bash
adb shell getprop | grep -iE 'ro.boot.hardware|vendor.titan|trusty' | head -n 8
```
