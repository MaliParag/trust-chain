# Play Integrity Verdicts vs. Root Hiding and Leaked Keyboxes

## Overview

* **Link in the Chain:** Ecosystem attestation-broker and anti-tamper battleground layer; aggregates hardware `Key Attestation` ([Chapter 15](15-key-attestation-rkp.md)), `Google Play` app-licensing, and runtime risk telemetry into signed `Play Integrity API` verdicts while defending against `Magisk`, `KernelSU`, and `TrickyStore` keybox spoofing.
* **Core Security Invariant:** On Android 13+ (`API 33`+), passing `MEETS_DEVICE_INTEGRITY` and `MEETS_STRONG_INTEGRITY` requires a valid, unrevoked hardware-backed `Key Attestation` certificate proving `deviceLocked == TRUE` and `verifiedBootState == Verified` (plus recent `OS`/`boot` security patch floors for `STRONG`), defeating purely userspace or kernel-mode property/mount hiding.
* **Ecosystem Enforcement Tier:** Passes `DEVICE` and `STRONG` exclusively on Google-certified (`GMS`) `GREEN` locked stock handsets; *intentionally fails* `DEVICE` and `STRONG` on both `YELLOW` locked custom-OS builds (`GrapheneOS`, because `verifiedBootState == SelfSigned` is not an OEM GMS certified image) and `ORANGE` unlocked/rooted builds.
* **Trusted Computing Base (TCB):** `KeyMint`/`StrongBox` + `RKP` ([Chapter 15](15-key-attestation-rkp.md)), Google Play Services (`com.google.android.gms.unstable` / `DroidGuard` VM), Google Play Integrity cloud verdict signer, `/attestation/status` keybox revocation pipeline, and the relying party's server-side token decryption/verification endpoint.
* **Seam & Handoff:** Explains why `Binder` interception (`TrickyStore`) paired with stolen pre-`RKP` OEM keyboxes briefly spoofed `STRONG` verdicts until `RKP` + mass revocations closed the window, and why sovereign/high-security relying parties should verify direct `Key Attestation` rather than locking out `YELLOW` custom roots; hands enterprise fleet isolation to [Chapter 17](17-android-enterprise.md).

## Threat Model & Ecosystem Constraint

In every chapter up to [Chapter 15](15-key-attestation-rkp.md), the physical human holding the smartphone and the platform defender stood on the same side against external attackers. In mobile gaming (anti-cheat in *PUBG* or *Pokémon GO*), streaming DRM, ride-share driver dispatch (anti-GPS-spoofing click farms), promotional coupon fraud, and certain retail banking apps, *the adversarial model flips*: the *physical owner of the handset* (or a commercial bot-farm operator running racks of 500 modified phones) intentionally unlocks the bootloader (`ORANGE`), roots the kernel, hooks internal app methods via `Zygisk`/`LSPosed`/`Frida`, and tries to convince a remote backend server that their modified phone is an untouched stock `GREEN` consumer handset [116, 119, 120]!

Historically, Google's deprecated `SafetyNet Attestation API` (`2015-2024`) relied heavily on obfuscated userspace telemetry inside `DroidGuard` (`com.google.android.gms.unstable`), scanning `/system/bin/su`, mount tables (`/proc/self/mounts`), `SELinux` status, and `ro.boot.*` system properties, falling back silently to software heuristics whenever hardware attestation threw an exception [116, 120]! That design ignited a decade-long arms race: because `DroidGuard` ran in Normal World `EL0` userspace *atop* an attacker-controlled `EL1` Linux kernel on an `ORANGE` unlocked phone, any signal `EL0` could read, `EL1` (or an injected `Zygote` library) could forge!

At the same time, bundling *hardware boot integrity*, *Google Play Store installation licensing*, and *OEM GMS certification* into a single pass/fail score inside the successor `Play Integrity API` created a profound architectural policy tension across the ecosystem [16, 116]: a security researcher or journalist running `GrapheneOS` on a Pixel 9 Pro with a locked `YELLOW` bootloader, full `AVB 2.0` `dm-verity`, hardware `StrongBox` `Titan M2`, and synchronous `Arm MTE` has *stronger* runtime exploit resistance than almost any stock OEM handset on Earth, yet fails `Play Integrity` `MEETS_DEVICE_INTEGRITY` simply because the OS is signed by `GrapheneOS`'s `avb_custom_key` rather than Google's stock GMS release key!

## Architecture & AOSP Implementation

### The `Play Integrity API`: Standard vs. Classic Requests and the Three Verdict Tiers

Replacing `SafetyNet` completely by 2024-2025, the `Play Integrity API` (`com.google.android.play:integrity`) issues JWE/JWS encrypted and signed JSON verdicts (`AES-256` key-wrapped + `ECDSA` signed on Google's cloud servers, decrypted either on the developer's backend or via `playintegrity.googleapis.com/v1/...:decodeIntegrityToken`) across two request profiles [116]: *Classic Requests* (binding a per-action server `nonce` for high-value one-off mutations, incurring live hardware attestation + network round-trip) and *Standard Requests* (`prepareIntegrityToken()` warming an attested hardware-bound key once, then signing lightweight per-request `requestHash` digests over `(action || payload)` in milliseconds!).

Inside `deviceIntegrity.deviceRecognitionVerdict`, Android 15/16+ (`Play Integrity` 2025 tightened definitions!) evaluates three hierarchical labels [116]. At the base sits `MEETS_BASIC_INTEGRITY`, indicating that the app is running on a physical device passing basic `DroidGuard` anti-emulator and anti-hook checks that may nevertheless have an unlocked `ORANGE` bootloader, rooted kernel, or uncertified custom ROM. Above it sits `MEETS_DEVICE_INTEGRITY`: on all devices running Android 13 (`API 33`) and higher, Google upgraded `MEETS_DEVICE_INTEGRITY` in May 2025 to *strictly require hardware-backed `Key Attestation` proof* (`deviceLocked == TRUE`, `verifiedBootState == Verified`, certified GMS build fingerprint, and no known compromised keybox), closing the legacy loophole where root-hiding modules forced `DroidGuard` to fall back to spoofable Android 12 software `BASIC`-style fingerprint evaluation [116, 119]. At the top sits `MEETS_STRONG_INTEGRITY`, requiring everything in `MEETS_DEVICE_INTEGRITY` (`TEE` or `StrongBox` hardware-backed boot proof) *plus a rolling recent security patch floor* (`OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` within the past 12 months across all partitions!) [116]. Alongside `deviceIntegrity`, the JSON verdict returns `appIntegrity` (`PLAY_RECOGNIZED` vs. `UNRECOGNIZED_VERSION`, proving whether the APK binary matches Play's exact signed distribution), `accountDetails` (`LICENSED`), and `environmentDetails` (`appAccessRiskVerdict` flagging active screen-capture or rogue `AccessibilityService` overlays from [Chapter 11](11-accessibility-advanced-protection.md), plus `playProtectVerdict`) [116]!

### Anatomy of the Root-Hiding Escalation: `Magisk` $\to$ `KernelSU` $\to$ `TrickyStore`

Why did `MagiskHide`, `Zygisk` + `Shamiko`, `PlayIntegrityFix`, `KernelSU`, and finally `TrickyStore` evolve in that exact sequence? Trace each step against the trust chain [117, 118, 119]:

![Figure: Dual-rail escalation timeline comparing root-hiding and keybox-spoofing tools against Android hardware attestation and RKP defenses.](diagrams/16-play-integrity-vs-root-hiding.svg)

Under *Generation 1* (`Magisk` Mount Namespaces, 2016-2020) [117], because `AVB` `dm-verity` ([Chapter 2](02-antirollback-verity-apex.md)) forbade modifying `/system`, `Magisk` patched `boot.img`'s ramdisk (`init`) on an `ORANGE` unlocked bootloader to mount tmpfs/overlayfs masks over `/system/bin` for root apps, while `MagiskHide` entered target banking/`GMS` mount namespaces (`nsenter`) to `umount()` every trace of `magisk` and used `resetprop` (manipulating `init`'s shared-memory `__system_property_area__` directly) to rewrite `ro.boot.verifiedbootstate` from `"orange"` back to `"green"` in userspace RAM! That fooled every naive app calling `getprop`, yet failed the instant `GMS` invoked hardware `Key Attestation` ([Chapter 15](15-key-attestation-rkp.md)), because `ABL` had already latched `ORANGE` into `TrustZone`/`StrongBox` *before* `boot.img` ever ran!

Under *Generation 2* (`Zygisk` + `PlayIntegrityFix`, 2021-2024) [117, 119], root users passed `MEETS_DEVICE_INTEGRITY` for three more years despite `ORANGE` hardware attestation by exploiting `SafetyNet` / pre-2025 `Play Integrity` backward-compatibility fallbacks! `PlayIntegrityFix` injected JNI hooks into `com.google.android.gms.unstable` via `Zygisk`, intercepting `KeyStoreSpi.engineGetCertificateChain()` to throw `ProviderException` / `UnsupportedOperationException` (pretending hardware attestation was broken!) while spoofing `android.os.Build.FINGERPRINT` and `PRODUCT` to an old pre-2018 / Android-8-launched beta device for which Google's server still accepted software-only `DroidGuard` evaluation! When Google's May 2025 `Play Integrity` update eliminated that legacy fallback for all Android 13+ runtimes, `PlayIntegrityFix` fingerprint spoofing died overnight for `DEVICE` and `STRONG` verdicts [116, 119].

Under *Generation 3* (`KernelSU` & `APatch`, 2023-2025) [118], to evade userspace `Zygote` injection detectors (`Zygisk` memory-map anomalies in `/proc/self/maps` spotted by banking SDKs like *LIAPP* or *Promon*), `KernelSU` moved root management entirely out of userspace mount overlays and into a patched `GKI` `boot.img` kernel (`kprobes` / direct kernel compile on `ORANGE` bootloaders). Only UIDs explicitly allowlisted inside the kernel's `ksu` table see `su` behavior on `execve()`/`faccessat()`; to every un-allowlisted banking app, `/proc/mounts`, `Zygote`, and `SELinux` look 100 percent untouched [118]! Yet even `KernelSU` *still* requires flashing a modified `boot.img` on an `ORANGE` unlocked bootloader, so `Titan M2` / `KeyMint` hardware *still* signs `deviceLocked = FALSE` and `verifiedBootState = Unverified`!

Under *Generation 4* (`TrickyStore` + Stolen Pre-`RKP` Keyboxes, 2024-2026) [119], blocked by genuine silicon `KeyMint` reporting `ORANGE`, root-hiding developers attacked the *`Binder` seam above `keystore2`*! Running with `UID 0`/`UID 1000` privilege, `TrickyStore` injects an interceptor into `keystore2` / `system_server` `IKeystoreSecurityLevel` Binder transactions: when `GMS` (`DroidGuard`) or an app requests an attested keypair with `attestationChallenge`, `TrickyStore` generates the key in software, fabricates a fake DER X.509 leaf certificate containing `deviceLocked = TRUE`, `verifiedBootState = Verified`, and fake current `osPatchlevel`/`bootPatchlevel` inside OID `1.3.6.1.4.1.11129.2.1.17`, and *signs that fake leaf certificate in software using a real, stolen pre-`RKP` OEM factory `ECDSA`/`RSA` private keybox XML purchased or leaked from an ODM assembly line* [112, 119]!

Look at why `TrickyStore` temporarily fooled *both* `MEETS_STRONG_INTEGRITY` and direct `Key Attestation` verifiers, and how the platform crushed it [112, 115, 119]. Mathematically, if an ODM leaks a genuine Google-chained intermediate signing private key $sk_{\text{OEM\_batch}}$ into attacker software, any X.509 leaf signed by $sk_{\text{OEM\_batch}}$ is cryptographically indistinguishable from a leaf signed inside that ODM's `TEE` *until $sk_{\text{OEM\_batch}}$'s serial number is added to `/attestation/status`*! Google's telemetry rapidly detects anomalous attestation volume and model mismatches from leaked factory keyboxes ("shadowbans" followed by hard `KEY_COMPROMISE` additions to `https://android.googleapis.com/attestation/status`), burning underground keyboxes in waves while mandatory `RKP`-only provisioning ([Chapter 15](15-key-attestation-rkp.md)) cuts off the upstream supply of extractable factory keyboxes permanently across modern silicon [112, 115, 119]!

### Architectural Choice for Relying Parties: `Play Integrity` vs. Direct `Key Attestation`

Should your backend rely on `Play Integrity` or direct X.509 `Key Attestation` ([Chapter 15](15-key-attestation-rkp.md))? Compare their exact security and ecosystem properties side by side [16, 111, 116, 120]:

![Figure: Relying-party trade-off between brokered Google Play Integrity verdicts and sovereign direct X.509 Key Attestation verification.](diagrams/16-relying-party-verification-choice.svg)

> **Warning.**
> As Ibrahim et al. (*SafetyNOT*, MobiSys 2023 [120]) proved across thousands of production apps, over half of developers using `SafetyNet` / `Play Integrity` made fatal integration errors: validating verdict JWTs *client-side inside the Android app*, omitting user/request-hash binding in `nonce` (allowing attackers to mint one valid token on a cheap clean burner phone and replay it inside automated API scripts!), or hard-blocking `YELLOW` locked `GrapheneOS` users from essential government, transit, or banking services without adding zero security over direct `Key Attestation`.

Use `Play Integrity` when your threat model specifically centers on *Play Store distribution licensing, anti-repackaging, or Play `appAccessRiskVerdict` overlay detection* on commercial GMS apps, always verifying tokens *server-side* with `requestHash = SHA-256(action || params || session_id)` [116, 120]. For high-security authentication, enterprise Zero Trust, government eID, and sovereign banking apps, verify *direct hardware `Key Attestation` (`OID .17`) + ongoing `KeyMint` request signatures* on your own backend, checking `/attestation/status` live, preferring `RKP`-issued `StrongBox` chains, and allowlisting both OEM `GREEN` roots and pinned sovereign `YELLOW` roots (`GrapheneOS`'s published `verifiedBootKey` SHA-256 digest [16])!

## Vendor, OEM, & Custom-OS Boundaries

`Play Integrity` requires proprietary Google Mobile Services (`GMS`) and therefore fails outright on de-Googled China mainland ROMs, Amazon Fire OS, Huawei HarmonyOS/AOSP forks, and default `GrapheneOS` (even when Sandboxed Google Play runs unprivileged on `GrapheneOS`, `Play Integrity` inspects `Key Attestation` `RootOfTrust` and sees `verifiedBootState == SelfSigned`, returning `BASIC` or empty rather than `DEVICE`/`STRONG` [16, 116]). Conversely, direct `Key Attestation` (`KeyStore.getCertificateChain`) is a standard AOSP + `CDD` API available without Play Services across every certified Android 8+ and `GrapheneOS` handset [2, 110].

## Exploit Chains & Structural Limits

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| `MagiskHide` `resetprop` + Mount Unmounting | 2017-2021 | Userspace `getprop` & `/proc/mounts` root checks | Rooted `ORANGE` phone hiding `su` & spoofing `ro.boot.verifiedbootstate=green` | Client SDKs trusted Normal World strings instead of `KeyMint` `RootOfTrust` | Never trust client-side root heuristics; require hardware `Key Attestation` [110, 117, 120] |
| `PlayIntegrityFix` Legacy Fingerprint Downgrade | 2022-2025 | Pre-May-2025 `Play Integrity` Android <13 fallback | `Zygisk` blocking Keystore cert chain + spoofing old `Build.FINGERPRINT` | Backward compatibility permitted software evaluation when hardware attestation errored | May 2025 `Play Integrity` mandate: hardware attestation required for `DEVICE` on Android 13+ [116, 119] |
| `TrickyStore` + Leaked ODM Factory Keybox XML | 2024-2026 | `keystore2` Binder reply in `EL0`/`EL1` | Stolen pre-`RKP` OEM keybox re-signing forged `OID .17` leaf cert in RAM | Compromised factory batch key existed outside silicon `UDS` | Live `/attestation/status` revocation waves + `RKP`-only `StrongBox`/`TEE` cohorts [112, 115, 119] |
| Token Farm Relay ("Real Phone as Signing Oracle") | Ongoing | Unbound `nonce` in `Play Integrity` / `Attestation` | Bot farm proxies server challenge to real untouched USD 80 `GREEN` phone | Attestation proves *some* clean phone signed the nonce, not *which* client holds the HTTP session! | Bind `requestHash` to exact transaction payload + sign requests with the attested `KeyMint` key (`DPoP`/mTLS) [116, 120] |

### From Consumer Fraud Battles to Managed Enterprise Fleets

Remote attestation proves a handset's hardware and boot integrity; in a corporate or government deployment, however, an organization also needs deterministic *policy control, separate corporate storage encryption keys, DLP boundaries, and hardware-locked Zero-Touch provisioning*, often on an employee's personal BYOD handset where corporate IT has zero right to inspect personal photos or chats. [Chapter 17](17-android-enterprise.md) examines `Android Enterprise`.

## Inspecting via ADB, Fastboot, & Attestation

Inspect Google Play Services (`com.google.android.gms` and its isolated `com.google.android.gms.unstable` `DroidGuard` process) alongside active `vbmeta` / patch-level properties evaluated during `MEETS_STRONG_INTEGRITY`:

```bash
adb shell ps -AZ | grep 'com.google.android.gms' | head -n 6
adb shell getprop ro.boot.vbmeta.device_state
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.boot.os_patch_level
```

Verify the device's certified build fingerprint and first shipped API level (`ro.product.first_api_level >= 33` indicates mandatory `RKP` launch baseline under `CDD`!):

```bash
adb shell getprop ro.build.fingerprint
adb shell getprop ro.product.first_api_level
```
