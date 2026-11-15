# KeyMint Authorization Tags, Boot Binding, and Weaver Throttling

## Overview

* **Link in the Chain:** Cryptographic policy enforcement and human-secret rate-limiting bridge; binds `TEE` and `StrongBox` keys ([Chapter 3](03-trustzone-strongbox.md)) to explicit usage tags, Verified Boot state ([Chapter 1](01-bootrom-avb-vbmeta.md)), OS/boot security patch levels, and hardware-throttled passcode tokens.
* **Core Security Invariant:** Hardware `KeyMint` unwraps an encrypted key blob (`AES-256-GCM`) and executes an operation if and only if the requested parameters satisfy every tag in the blob's AEAD-authenticated `AuthorizationList`, the current boot state and patch levels are at or above the blob's sealed floor, and any `USER_SECURE_ID` requirement is satisfied by an `HMAC`-verified `HardwareAuthToken`.
* **Ecosystem Enforcement Tier:** Full hardware key binding and `Weaver`/`Gatekeeper` rate limiting in `GREEN` and `YELLOW` locked states; transitioning to `ORANGE` unlocked state alters the hardware Key Encryption Key (`KEK`) derivation input (`deviceLocked = false`), rendering previously sealed `GREEN`/`YELLOW` key blobs permanently undecipherable.
* **Trusted Computing Base (TCB):** `IKeyMintDevice` `TEE`/`StrongBox` implementation, early-boot bootloader-to-`KeyMint` root-of-trust latch, `IWeaver` `StrongBox` slot NVM or `IGatekeeper` + `RPMB`, `SyntheticPassword` derivation in `LockSettingsService`, and the userspace Rust `keystore2` daemon (`system/security/keystore2`).
* **Seam & Handoff:** Turns raw silicon isolation into fine-grained, boot-bound, brute-force-resistant cryptographic keys for `File-Based Encryption` ([Chapter 12](12-fbe-usb-theft-protection.md)), `BiometricPrompt` and `Passkeys` ([Chapter 13](13-biometrics-passkeys.md)), and X.509 `Key Attestation` ([Chapter 15](15-key-attestation-rkp.md)); motivates `EL2` `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) for general compute workloads too complex to fit inside `KeyMint`.

## Threat Model & Ecosystem Constraint

Placing an `AES` or `ECDSA` engine inside `TrustZone` or `StrongBox` ([Chapter 3](03-trustzone-strongbox.md)) solves key storage only halfway. Consider three concrete attacks that succeed even if raw private keys never leave `Titan M2` in plaintext [36, 40, 41]:

First is *cryptographic purpose confusion and metadata tampering*. Because `StrongBox` has only kilobytes of internal `NVM` while an Android handset may generate thousands of application, Wi-Fi, VPN, passkey, and filesystem keys across hundreds of apps, `KeyMint` cannot store all keys inside `StrongBox` flash. Instead, `KeyMint` wraps keys into encrypted `key_blob` files stored on mutable `/data/misc/keystore2` managed by the Normal World OS [36, 38]. If an attacker with `Ring 0` write access to `/data` could strip a `"user authentication required"` flag or flip `"ECDSA verify"` to `"ECDSA sign"` on a stored `key_blob` before feeding it back into `KeyMint`, hardware isolation would collapse into an unrestricted signing oracle.

Second is *cross-boot-state key unsealing*. Suppose a thief steals a locked `GREEN` handset, exploits a bootloader flaw (or unlocks a misconfigured OEM bootloader that forgot to wipe `/data`), boots a backdoored `ORANGE` kernel, and asks `KeyMint` to unwrap the victim's existing `/data` encryption key blob. Unless `KeyMint`'s internal symmetric wrapping key mathematically depends on the immutable `RootOfTrust` (`verifiedBootKey` + `deviceLocked` + `verifiedBootState`) latched by the bootloader *before* Linux runs, a modified kernel could read secrets created under a genuine verified OS [14, 36].

Third is *low-entropy human passcode brute-forcing (`NAND mirroring`)* [41]. Human users routinely pick six-digit PINs ($10^6 \approx 2^{19.93}$ possibilities) or four-digit PINs ($10^4$ possibilities). Even slow password-hashing functions (`scrypt` or `Argon2`) tuned to take $200\text{ ms}$ on a smartphone CPU evaluate $10^6$ candidates in seconds on an offline GPU rig if the encrypted verifier can be extracted. Worse, if retry counters live on external flash, a lab attacker can snapshot the flash chip before making ten PIN guesses on the phone, restore the snapshot when the counter increments, and exhaust $10^6$ PINs in $10^5$ power cycles [40, 41].

## Architecture & AOSP Implementation

### From `Keymaster` to `KeyMint` AIDL and Rust `keystore2`

Across Android 6 through Android 11, Android's hardware keystore evolved through `Keymaster 1.0` to `4.1` (`HIDL`). Starting in Android 12 (`API 31`), Google replaced both halves of the stack simultaneously [36, 38, 42]: the HAL contract transitioned to versioned Stable `AIDL` `KeyMint` (`android.hardware.security.keymint.IKeyMintDevice`, reaching `KeyMint` v3/v4 in Android 14-16), and the privileged C++ `keystored` userspace broker was rewritten from scratch in memory-safe *Rust* as `keystore2` (`system/security/keystore2`), backed by a local SQLite metadata database tracking key ownership `(domain, namespace, alias)` and per-UID `Binder` grant ACLs [38, 42].

![Figure: KeyMint hardware-enforced vs. keystore2 daemon-enforced AuthorizationList tags and boot-state wrapping.](diagrams/04-keymint-authorization-binding.svg)

Every key managed by `KeyMint` is governed by an immutable set of typed `KeyParameter` entries (`Tag.aidl`) partitioned strictly into two `AuthorizationList` buckets: `teeEnforced` (or `StrongBox`-enforced) and `softwareEnforced` (`keystore2`-enforced) [37]. Understanding which tags live in `teeEnforced` is foundational:

Cryptographic primitive constraints (`Tag::PURPOSE` such as `SIGN`, `VERIFY`, `ENCRYPT`, `DECRYPT`, `WRAP_KEY`, `AGREE_KEY`; `Tag::ALGORITHM`; `Tag::KEY_SIZE`; `Tag::DIGEST`; `Tag::PADDING`; `Tag::EC_CURVE`; `Tag::CALLER_NONCE` prohibition ensuring `AES-GCM` IVs are generated internally by hardware `TRNG`) reside in `teeEnforced` [37]. Human-presence and lock-state constraints (`Tag::NO_AUTH_REQUIRED` vs. `Tag::USER_SECURE_ID` storing 64-bit Gatekeeper/Biometric `SID`s, `Tag::AUTH_TIMEOUT` in seconds using `KeyMint`'s monotonic secure timer, `Tag::UNLOCKED_DEVICE_REQUIRED`, and `Tag::TRUSTED_CONFIRMATION_REQUIRED`) are likewise enforced inside silicon [37]. Conversely, tags requiring wall-clock UTC time (`Tag::CREATION_DATETIME`) or package-manager certificate lookups (`Tag::ATTESTATION_APPLICATION_ID`, serialized by `keystore2` from `PackageManager`) sit in `softwareEnforced` when the `TEE` lacks an independent trusted real-time clock [37, 110].

### AEAD Key-Blob Wrapping and Boot / Patch-Level Binding

How does `KeyMint` store thousands of keys on untrusted `/data/misc/keystore2` without risking tag tampering or `ORANGE` unlock unsealing? Inside silicon fuses, every `SoC` (`TEE`) and discrete `StrongBox` (`Titan M2`) holds a unique, hardware-bound root secret $K_{\text{HBK}}$ inaccessible to software outside the key-derivation engine [36]. During pre-OS boot ([Chapter 1](01-bootrom-avb-vbmeta.md)), `ABL` invokes a one-time `SetBootParams` command over `SMC`/`SPI` (permanently locked before `ABL` jumps to `EL1` Linux!), latching the verified boot parameters $B = (\text{verifiedBootKey}, \text{deviceLocked}, \text{verifiedBootState}, \text{verifiedBootHash})$ and active `OS_VERSION`, `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` (`YYYYMMDD`) into `KeyMint` RAM [14, 36].

When `KeyMint::generateKey(keyParams)` creates a new key $k_{\text{raw}}$, it embeds the hardware-enforced `AuthorizationList` $A_{\text{hw}}$ (including the current `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` tags!), derives a Key Encryption Key (`KEK`) from $K_{\text{HBK}}$ mixed with the latched boot identity $B$ and an optional `Tag::APPLICATION_ID` / `ROLLBACK_RESISTANCE` counter, and seals the blob via `AES-256-GCM` [9, 36]:

$$K_{\text{KEK}} = \text{HKDF}\bigl(K_{\text{HBK}}, B \parallel \text{context}\bigr), \qquad \text{blob} = \text{IV}_{96} \parallel \text{AES-GCM-Enc}_{K_{\text{KEK}}}\bigl(\text{AAD} = A_{\text{hw}}, \text{plaintext} = k_{\text{raw}}\bigr)$$

Look at the three immediate consequences of this construction [36, 37]:

First, modifying *any* tag in $A_{\text{hw}}$ on disk invalidates the 128-bit `AES-GCM` authentication tag inside `KeyMint::begin()`, causing hardware unwrap to fail immediately with `ErrorCode::INVALID_KEY_BLOB`.

Second, if an attacker unlocks the bootloader (`ORANGE`) or flashes an alternate unpinned key, the latched boot tuple $B'$ changes (`deviceLocked = false`, `verifiedBootState = UNVERIFIED`), producing $K_{\text{KEK}}' \ne K_{\text{KEK}}$ so *not a single previously sealed `GREEN` or `YELLOW` key blob can be decrypted by `KeyMint` itself*.

Third, when an OTA updates `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, or `BOOT_PATCHLEVEL` (for example from `20260105` to `20260505`), unwrapping an older blob returns `ErrorCode::KEY_REQUIRES_UPGRADE`; `keystore2` transparently calls `KeyMint::upgradeKey(oldBlob)` to re-seal $k_{\text{raw}}$ at `20260505` (and increments its `RPMB` rollback slot if `Tag::ROLLBACK_RESISTANCE` is set), permanently preventing a downgraded OS revision from unwrapping the upgraded blob!

### `SyntheticPassword`, `Gatekeeper`, and `StrongBox` `Weaver`

To bind cryptographic keys and `File-Based Encryption` ([Chapter 12](12-fbe-usb-theft-protection.md)) to the user's PIN, pattern, or password (`LSKF`) without allowing offline brute-forcing or breaking escrow/biometric flows, Android 8.0+ replaced direct password-to-key derivation with the two-layer `SyntheticPassword` (`SP`) architecture inside `LockSettingsService` [39, 40, 91].

At enrollment, `LockSettingsService` generates a high-entropy random 256-bit `SyntheticPassword` $S$. All downstream secrets (the user's `CE` `fscrypt` storage master key, `Gatekeeper` enrollment handle, and cloud backup/passkey vault recovery wrappers) derive deterministically from $S$ via `HKDF`, *not* directly from the user's 6-digit PIN! Consequently, when a user changes their PIN from `149203` to `883104`, Android never needs to re-encrypt gigabytes of `/data` files; it simply re-wraps the unchanging 256-bit `SyntheticPassword` $S$ under a new `LSKF` protector [91].

![Figure: SyntheticPassword unwrap sequence using StrongBox Weaver slot rate limiting and KeyMint boot-bound sealing.](diagrams/04-gatekeeper-vs-weaver.svg)

How is $S$ protected so neither an `EL1` root exploit nor a physical `NAND mirroring` rig can brute-force the 6-digit PIN? Android provides two hardware HAL tiers, with `StrongBox` `Weaver` (`android.hardware.weaver.IWeaver`) representing the flagship gold standard [39, 40]:

On `TEE`-only devices lacking `StrongBox`, `LockSettingsService` uses `Gatekeeper` (`IGatekeeper` in `S-EL1` + `RPMB` failure counter) paired with a `KeyMint` key requiring a fresh `HardwareAuthToken` [39]. While `Gatekeeper` defeats software `EL1` brute-forcing, `TEE` implementations that lack internal chip flash or rely on shared SoC power rails remain theoretically exposed to invasive lab glitching or `RPMB` bus interposition if `RPMB` is improperly isolated [41].

On `StrongBox` devices (`Google Titan M2` and `Samsung Knox Vault`), Android uses `Weaver` (`hardware/interfaces/weaver`) [33, 40]. Inside `Titan M2`'s private on-die `NVM` sits a fixed array of hardware slots (typically 64 slots, indexed `slotId = 0..63`), where each slot stores a tuple `(key_16B, value_16B, failure_counter)` that never leaves the `Titan M2` die:

During PIN enrollment, `LockSettingsService` stretches the user's `LSKF` with a random per-protector salt via `scrypt` into $(K_{\text{weaver}}, K_{\text{app}})$, generates a random 128-bit `weaverSecret` $V$, calls `IWeaver::write(slotId, K_weaver, V)` to store $(K_{\text{weaver}}, V, 0)$ inside `Titan M2` NVM, and seals `SyntheticPassword` $S$ under $K_{\text{app}}$, $V$, and a `KeyMint` key bound to Verified Boot state [40]. During subsequent unlocks, `LockSettingsService` derives candidate $\widehat{K}_{\text{weaver}}$ from the entered PIN and calls `IWeaver::read(slotId, candidate_K_weaver)` over `SPI`. Inside `Titan M2`, before checking $\widehat{K}_{\text{weaver}} \stackrel{?}{=} K_{\text{weaver}}$, `Weaver` checks its internal hardware backoff timer against `failure_counter` and writes the incremented counter to internal `Titan M2` flash before evaluating the comparison, defeating sudden power-cut tearing attacks. Only if $\widehat{K}_{\text{weaver}} = K_{\text{weaver}}$ in constant time does `Titan M2` reset `failure_counter = 0` and return the 128-bit secret $V$; otherwise it returns `WeaverReadStatus::INCORRECT_KEY` along with the enforced millisecond delay [33, 40].

Examine the delay schedule enforced inside `Titan M2` / `LockSettingsService` [40]: attempts $1\text{ to }4$ carry zero delay; attempt $5$ enforces a $30\text{-second}$ hardware lockout; attempts $6\text{ to }9$ require zero delay up to attempt $10$ ($30\text{s}$); from attempt $11\text{ to }29$, *every single wrong guess* enforces a $30\text{-second}$ hardware sleep; from $30\text{ to }139$, the delay escalates exponentially ($30 \cdot 2^{\lfloor (c - 30)/10 \rfloor}$ seconds, reaching $86{,}400\text{ seconds} = 24\text{ hours}$ per single guess at attempt $140+$!). Exhausting even half of a 6-digit PIN space ($5 \times 10^5$ guesses) at 1 guess per day requires *over 1,300 years* of continuous powered wall-clock time on that physical `Titan M2` chip, and cloning external `UFS` flash changes nothing because $V$ never existed on `UFS` [33, 40, 41].

Once $S$ is unwrapped, `Gatekeeper` (or `BiometricManager` for Class 3 biometrics in [Chapter 13](13-biometrics-passkeys.md)) mints a 69-byte `HardwareAuthToken` authenticated under a boot-ephemeral `HMAC-SHA256` key shared inside secure hardware between `Gatekeeper`, `Fingerprint`/`Face` TAs, and `KeyMint` [37, 39]:

```c
/* Logical wire layout of HardwareAuthToken (KeyMint AIDL) */
struct HardwareAuthToken {
  int64_t  challenge;          /* Operation handle from KeyMint::begin() */
  int64_t  userId;             /* 64-bit Gatekeeper Secure User ID (SID) */
  int64_t  authenticatorId;    /* 64-bit Biometric Enrollment ID (0 if LSKF) */
  int32_t  authenticatorType;  /* HW_AUTH_PASSWORD (1) | HW_AUTH_BIOMETRIC (2) */
  Timestamp timestamp;         /* Big-endian ms from secure monotonic clock */
  byte[32] mac;                /* HMAC-SHA256 under shared hardware HMAC key */
};
```

When an app invokes an auth-bound `KeyMint` key (`TAG_USER_SECURE_ID` + `TAG_AUTH_TIMEOUT = 0` for every-use confirmation or $T > 0$ seconds for timed unlock), `KeyMint` verifies `mac`, confirms `userId` or `authenticatorId` matches the blob's sealed `TAG_USER_SECURE_ID`, and verifies $\text{now}_{\text{secure}} - \text{timestamp} \le T$ (or `challenge == opHandle` for per-operation prompts) before touching the private key [37].

## Vendor, OEM, & Custom-OS Boundaries

`CDD` Section 9.11 mandates hardware-backed `KeyMint` and anti-brute-force rate limiting across compatible handsets, while `VTS` (`VtsHalKeyMintTargetTest` and `VtsHalWeaverTargetTest`) tests every tag combination, `AUTH_TIMEOUT` expiration, `INVALID_KEY_BLOB` tamper rejection, and `Weaver` backoff timer directly against the vendor HAL [2, 3].

Two custom-OS and enterprise extensions stand out atop this baseline. First, `GrapheneOS` (`YELLOW` locked Pixel) adds a second optional *duress PIN/password* wired directly into `Titan M2`'s `Weaver` slots: entering the duress credential at any lock screen or biometric prompt immediately overwrites all occupied `Weaver` slots inside `Titan M2` NVM and wipes key metadata before rebooting, rendering `CE` storage and sealed `KeyMint` blobs cryptographically irrecoverable in milliseconds without requiring menu navigation [96]. Second, Samsung `Knox` layers enterprise Dual Data-At-Rest (`DualDAR`) atop `Knox Vault` so corporate containers ([Chapter 17](17-android-enterprise.md)) combine two independent hardware-wrapped encryption layers even in `BFU` state [34, 125].

## Exploit Chains & Structural Limits

Vulnerabilities in the `Keystore`/`KeyMint` tier historically centered on legacy C++ `keystored` memory corruption, flawed `Gatekeeper` software fallbacks, or vendor `Keymaster` implementations omitting boot-state inputs from `KEK` derivation.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Legacy C++ `keystored` Binder Overflows (CVE-2014-3100, CVE-2018-9411) | 2014-2018 | Userspace `keystored` (`UID 1017`) | Malformed Binder parcel from local `untrusted_app` | Stack/heap memory corruption in C++ key-alias and parcel deserialization allowed cross-UID key invocation | Complete rewrite of `keystore2` in memory-safe Rust in Android 12+ [38, 42] |
| Qualcomm `KeyMaster` FDE Brute-Force (`CVE-2016-2431` chain) | 2016 | `S-EL0` `KeyMaster` TA (pre-`Weaver`) | Normal World root + `TrustZone` exploit extracting `HBK`-derived verifier | Full-Disk Encryption tied PIN stretch directly to `TrustZone` TA without off-SoC `Weaver` NVM slots, permitting offline GPU cracking once TA broke | `SyntheticPassword` + discrete `StrongBox` `Weaver` slots (`Titan M2` / `Knox Vault`) [30, 40] |
| Vendor `Keymaster` Missing `ORANGE` `RootOfTrust` KEK Mix | 2018-2020 | OEM `Keymaster` HAL implementation | Unlocking bootloader or flashing modified boot on buggy BSP | Certain early `Treble` BSPs reported `UNVERIFIED` in attestation but forgot to mix `verifiedBootState` into `KEK` HKDF | Mandatory `VTS` boot-binding tests + compulsory `userdata` wipe on unlock [14, 36] |
| Biometric Enrollment Addition Bypass (App Logic Misuse) | Ongoing | App `KeyGenParameterSpec` configuration | Attacker with temporary PIN adds new fingerprint to unlock app key | Developer set `setInvalidatedByBiometricEnrollment(false)`, failing to bind key to static `authenticatorId` | Default `setInvalidatedByBiometricEnrollment(true)` seals `TAG_USER_SECURE_ID` to exact biometric template `authenticatorId` [37, 99] |

### Why `TrustZone` + `KeyMint` Alone Could Not Scale to General Isolation

With Part I complete, trace what silicon and boot have established: `Boot ROM` fuses, `AVB 2.0` `VBMeta`, `RPMB` rollback floors, `dm-verity` with Reed-Solomon `FEC`, `StrongBox` (`Titan M2` / `Knox Vault`), `KeyMint` `AuthorizationList` sealing, and `Weaver` passcode throttling form a rock-solid anchor for fixed-schema keys and read-only partitions.

Yet modern Android increasingly needs to isolate *rich, stateful code and large models* from the host Linux kernel: on-device compilation of `ART` boot classpaths (`Isolated Compilation`), proprietary OEM computer-vision algorithms, DRM content pipelines, and confidential AI inference. Putting megabytes of dynamic C++/Rust/ML code inside `Titan M2` is physically impossible over `SPI`, and putting it inside `S-EL1` `TrustZone` recreates the exact bloated `QSEE` attack surface that broke in [Chapter 3](03-trustzone-strongbox.md)! Part II opens in [Chapter 5](05-pkvm-avf-microdroid.md) by showing how Android solved that dilemma cleanly: moving *beneath* the host Linux kernel into `EL2` with `Protected KVM` (`pKVM`) and `Microdroid`.

## Inspecting via ADB, Fastboot, & Attestation

Inspect active `keystore2` daemon status, `SELinux` label (`u:r:keystore:s0`), and current `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` values sealed into newly generated `KeyMint` blobs:

```bash
adb shell ps -AZ | grep keystore2
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.vendor.build.security_patch
```

Query `locksettings` state (read-only via `dumpsys lock_settings`) to verify `SyntheticPassword` activation, `Weaver` hardware slot backing (`Weaver: enabled`), and active credential type without exposing secrets:

```bash
adb shell dumpsys lock_settings | grep -iE 'weaver|synthetic|sp-state|credential' | head -n 10
```

Verify registered `KeyMint` and `Gatekeeper` AIDL/HIDL HAL versions via `dumpsys` / `getprop` to confirm `KeyMint` v2/v3+ hardware enforcement:

```bash
adb shell lshal 2>/dev/null | grep -iE 'keymint|keymaster|weaver|gatekeeper' | head -n 8
```
