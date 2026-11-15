# KeyMint Authorization Tags, Boot Binding, and Weaver Throttling

## Overview

* **Link in the Chain:** Cryptographic policy-enforcement and human-passcode rate-limiting bridge; binds `TEE` and `StrongBox` keys ([Chapter 3](03-trustzone-strongbox.md)) to immutable AEAD `KeyParameter` tags, Verified Boot `RootOfTrust` ([Chapter 1](01-bootrom-avb-vbmeta.md)), OS and boot security patch levels, and hardware-throttled passcode secrets.
* **Core Security Invariant:** Hardware `KeyMint` unwraps an `AES-256-GCM` key blob and executes an operation if and only if the request satisfies every tag in the blob's AEAD-authenticated `AuthorizationList`, active boot state and patch levels meet or upgrade the blob's sealed floor, and any `USER_SECURE_ID` predicate carries a valid `HMAC-SHA256` `HardwareAuthToken`.
* **Ecosystem Enforcement Tier:** Full hardware key binding and `Weaver`/`Gatekeeper` rate limiting in `GREEN` and `YELLOW` locked states; transitioning to `ORANGE` unlocked state alters the latched `RootOfTrust` input (`deviceLocked = false`, `verifiedBootState = UNVERIFIED`), changing the hardware Key Encryption Key (`KEK`) so previously sealed `GREEN`/`YELLOW` blobs never unwrap.
* **Trusted Computing Base (TCB):** `IKeyMintDevice` `TEE`/`StrongBox` implementation (including Rust `kmr`), bootloader-to-`KeyMint` `RootOfTrust` latch, `ISharedSecret` HMAC agreement, `IWeaver` `StrongBox` 64-slot NVM (or `IGatekeeper` + `RPMB`), `SyntheticPasswordManager` in `system_server`, and Rust `keystore2` (`system/security/keystore2`).
* **Seam & Handoff:** Transforms raw silicon isolation into fine-grained, boot-bound, brute-force-resistant keys for `File-Based Encryption` ([Chapter 12](12-fbe-usb-theft-protection.md)), `BiometricPrompt` and `Passkeys` ([Chapter 13](13-biometrics-passkeys.md)), and X.509 `Key Attestation` ([Chapter 15](15-key-attestation-rkp.md)); motivates `EL2` `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) for general confidential compute too stateful to fit inside `KeyMint`.

## Threat Model & Ecosystem Constraint

Placing an `AES` or `ECDSA` engine inside `TrustZone` or discrete `StrongBox` silicon ([Chapter 3](03-trustzone-strongbox.md)) solves key residence only halfway. Three concrete attack vectors succeed even when raw private scalars never enter Normal World DRAM in plaintext [28, 62, 185]:

First is *cryptographic purpose confusion and metadata tampering on `/data`*. A discrete `Titan M2` chip possesses only kilobytes of private internal flash (`NVM`), whereas an Android handset generates thousands of TLS client keys, FIDO2 passkeys, Wi-Fi `WPA3-Enterprise` credentials, `odsign` boot keys, and `fscrypt` protectors across hundreds of installed apps and profiles [28, 186]. `KeyMint` therefore exports generated keys as encrypted `key_blob` records stored inside `keystore2`'s SQLite database on untrusted `/data/misc/keystore2` [186, 187]. If an attacker with `EL1` kernel write access to `/data` could strip `Tag::USER_SECURE_ID` from a stored blob, substitute a caller-chosen `AES-GCM` nonce (`CVE-2021-25444` [169]), or flip `KeyPurpose::VERIFY` into `KeyPurpose::SIGN` before passing the blob back into `IKeyMintDevice::begin()`, hardware isolation would collapse into an unrestricted signing and decryption oracle [97, 98].

Second is *cross-boot-state or downgraded-OS key unsealing*. Suppose a physical attacker steals a powered-off `GREEN` handset, exploits a bootloader flaw (or unlocks a buggy OEM bootloader that failed to erase `/data`), boots a modified `ORANGE` kernel or an older unpatched signed boot image, and asks `KeyMint` to unwrap the victim's `File-Based Encryption` protector blob. Unless `KeyMint`'s internal wrapping key mathematically mixes the immutable `RootOfTrust` latched by `ABL` *before* Linux starts alongside monotonic `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` floors, a subverted or downgraded OS could unseal secrets created under a newer verified OS [19, 28, 98].

Third is *offline and hardware-cloned brute-forcing of human passcodes (`NAND mirroring`)* [62]. Users overwhelmingly choose six-digit numeric PINs ($10^6 \approx 2^{19.93}$ combinations) or nine-dot patterns ($389{,}112$ combinations). Memory-hard stretching via `scrypt` (`RFC 7914` [94]) tuned to run in $150\text{ ms}$ on an Arm CPU evaluates all $10^6$ six-digit PINs in seconds on an offline GPU cluster if the encrypted verifier can be extracted. Even when verification runs inside a `TEE`, if the retry counter resides on external flash without internal chip state, a physical lab adversary can snapshot the flash chip before ten guesses, re-flash the snapshot when lockout triggers, and exhaust $10^6$ PINs across $10^5$ automated power cycles [62, 185].

## Architecture & AOSP Implementation

### `IKeyMintDevice.aidl`, Rust `keystore2`, and `kmr`

Between Android 6 and Android 11, Android's hardware keystore evolved across `Keymaster 1.0` through `4.1` (`HIDL` `hardware/interfaces/keymaster/4.0/types.hal` [188]). Starting in Android 12 (`API 31`) and advancing through `KeyMint` v3 and v4 in Android 14 through Android 16, Google overhauled every layer of the subsystem [28, 98, 170, 186, 189]: the vendor contract migrated to VINTF-stable `AIDL` (`hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/IKeyMintDevice.aidl`), Google published an open-source memory-safe *Rust* reference `KeyMint` TA implementation (`kmr` in `system/keymint` [170]), and the privileged userspace C++ `keystored` daemon (`UID 1017`, `AID_KEYSTORE`) was replaced from scratch by Rust `keystore2` (`system/security/keystore2` [186, 187]).

Inside userspace, `keystore2` manages key namespaces `(Domain, namespace, alias)` inside `/data/misc/keystore2/persistent.sqlite`, checks caller `Binder` `UID`s and `SELinux` `keystore2_key` access vectors (`manage_blobs`, `use`, `grant`, `delete` in `permission.rs` [187]), superencrypts auth-bound blobs via `SuperKeyManager`, and multiplexes hardware session handles: because `IKeyMintDevice` guarantees at least 16 concurrent live `IKeyMintOperation` slots, `keystore2` consumes at most 15 slots (evicting the least-recently-used slot via `abort()` on contention) so 1 hardware slot always remains free for `vold` storage encryption operations [190]!

### AEAD Key-Blob Wrapping, Patch-Level `upgradeKey()`, and Early-Boot Keys

How does `KeyMint` store thousands of keys on untrusted `/data` while defeating tag tampering, `ORANGE` bootloader unsealing, and OS downgrades? Every `TEE` SoC and discrete `StrongBox` (`Titan M2` / `Knox Vault`) fuses a per-chip 256-bit Hardware-Bound Key $K_{\text{HBK}}$ accessible exclusively to its internal key-derivation engine [28, 97]. During pre-OS boot ([Chapter 1](01-bootrom-avb-vbmeta.md)), `ABL` sends a one-shot `SetBootParams` message latching the Verified Boot tuple $B = (\text{verifiedBootKey}, \text{deviceLocked}, \text{verifiedBootState}, \text{verifiedBootHash})$ plus `BOOT_PATCHLEVEL` (`YYYYMMDD`), while early HAL initialization latches `OS_VERSION` (`MMmmss`), `OS_PATCHLEVEL` (`YYYYMM`), and `VENDOR_PATCHLEVEL` (`YYYYMMDD`) once per boot [97, 98].

When `IKeyMintDevice::generateKey(keyParams)` creates a private or symmetric key $k_{\text{raw}}$, the secure environment partitions the validated `KeyParameter` list into its hardware-enforced `AuthorizationList` $A_{\text{hw}}$ (automatically stamping `Tag::ORIGIN = GENERATED`, `OS_VERSION`, `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` into $A_{\text{hw}}$!), draws a fresh 96-bit random nonce $\text{IV}_{96}$ from its internal hardware `TRNG`, derives a Key Encryption Key (`KEK`) from $K_{\text{HBK}}$ mixed with the latched `RootOfTrust` $B$ plus any caller-supplied `Tag::APPLICATION_ID` / `Tag::APPLICATION_DATA` bytes, and wraps $k_{\text{raw}}$ via `AES-256-GCM` [28, 85, 97, 190]:

$$K_{\text{KEK}} = \text{HKDF}\bigl(K_{\text{HBK}}, \; B \parallel \texttt{appId} \parallel \texttt{appData} \parallel \texttt{rollbackSlot}\bigr)$$

$$\text{key\_blob} = \text{version} \parallel \text{IV}_{96} \parallel A_{\text{hw}} \parallel \text{AES-256-GCM-Enc}_{K_{\text{KEK}}}\bigl(\text{IV}_{96}, \; \text{AAD} = A_{\text{hw}}, \; \text{plaintext} = k_{\text{raw}}\bigr)$$

Trace the four security properties enforced mathematically by this single AEAD envelope [28, 97, 98, 190]:

First, *tamper-proof metadata*: flipping a single bit of `Tag::PURPOSE` or `Tag::USER_SECURE_ID` inside $A_{\text{hw}}$ on `/data` invalidates the 128-bit `AES-GCM` authentication tag inside `IKeyMintDevice::begin()`, aborting with `ErrorCode::INVALID_KEY_BLOB`.

Second, *cryptographic boot-state isolation*: unlocking the bootloader (`ORANGE`) mutates the latched tuple $B \to B'$ (`deviceLocked = false`, `verifiedBootState = UNVERIFIED`), yielding an unrelated $K_{\text{KEK}}' \ne K_{\text{KEK}}$ so `KeyMint` itself cannot decrypt any `GREEN`- or `YELLOW`-sealed blob even if `/data` were cloned offline.

Third, *monotonic patch-level ratcheting via `upgradeKey()`*: inside $A_{\text{hw}}$, every blob carries the exact `OS_VERSION`, `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and `BOOT_PATCHLEVEL` active when it was sealed [97, 98]. If an attacker manages to boot an older signed kernel or vendor image whose patch level is *lower* than the blob's stamped tag, `KeyMint` rejects the blob immediately with `ErrorCode::INVALID_KEY_BLOB`! Conversely, after a legitimate monthly OTA advances `BOOT_PATCHLEVEL` from `20260905` to `20261005`, calling `begin()` on a `20260905` blob returns `ErrorCode::KEY_REQUIRES_UPGRADE`; `keystore2` automatically invokes `IKeyMintDevice::upgradeKey(oldBlob, upgradeParams)` [98, 190], which verifies that live system patch levels are strictly greater than or equal to the old blob's tags, re-wraps $k_{\text{raw}}$ at `20261005`, and (for keys carrying `Tag::ROLLBACK_RESISTANCE` [97, 190]) increments a hardware `RPMB`/`StrongBox` deletion counter so backups of `oldBlob` become permanently unusable!

Fourth, *standalone pre-`/data` usability*: in legacy `Keymaster 3.0/4.0`, `vold` had to pass `Tag::KEY_BLOB_USAGE_REQUIREMENTS` (`KeyBlobUsageRequirements::STANDALONE` vs. `REQUIRES_FILE_SYSTEM` [188]) so full-disk/file encryption blobs could unwrap before `/data` mounted `TEE` secure-storage daemons. `KeyMint` makes standalone self-contained AEAD blobs the universal default, adding `Tag::STORAGE_KEY` (`convertStorageKeyToEphemeral()` wrapping inline `UFS` `ICE` hardware keys under per-boot ephemeral secrets so plaintext storage keys never touch `EL1` kernel RAM [97, 191]) and `Tag::EARLY_BOOT_ONLY` [97].

### Hardware-Enforced vs. `keystore2`-Enforced `KeyParameter` Tags

![Figure: KeyMint hardware-enforced vs. keystore2 daemon-enforced AuthorizationList tags and boot-state wrapping.](diagrams/04-keymint-authorization-binding.svg)

Every `KeyParameter` defined in `Tag.aidl` (`hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl` [97]) carries a strict bit-masked `TagType` (`ENUM`, `ENUM_REP`, `UINT`, `ULONG_REP`, `DATE`, `BOOL`, `BYTES`) and falls into a deterministic enforcement domain reported in `KeyCharacteristics` (and attested in X.509 `KeyDescription` in [Chapter 15](15-key-attestation-rkp.md)) [29, 97]:

| `KeyParameter` Tag (`Tag.aidl`) | Enforcement Domain (`SecurityLevel`) | Hardware / Daemon Mechanism & Failure `ErrorCode` |
|---|---|---|
| `Tag::PURPOSE` (`1`), `ALGORITHM` (`2`), `KEY_SIZE` (`3`), `BLOCK_MODE` (`4`), `DIGEST` (`5`), `PADDING` (`6`), `EC_CURVE` (`10`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Checked inside `KeyMint::begin()`; rejects mismatches with `INCOMPATIBLE_PURPOSE` / `INCOMPATIBLE_DIGEST` [97, 98] |
| `Tag::CALLER_NONCE` (`7`) & `Tag::MIN_MAC_LENGTH` (`8`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Blocks caller-chosen `AES-GCM`/`CBC` IVs (`CALLER_NONCE_PROHIBITED`) unless explicitly authorized; enforces $\ge 96\text{-bit}$ GCM tag [97] |
| `Tag::BOOTLOADER_ONLY` (`302`) & `Tag::EARLY_BOOT_ONLY` (`305`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | `EARLY_BOOT_ONLY` works only until `vold`/`init` invokes one-way `IKeyMintDevice::earlyBootEnded()`, then fails with `EARLY_BOOT_ENDED` [97, 157] |
| `Tag::ROLLBACK_RESISTANCE` (`303`) & `Tag::MAX_USES_PER_BOOT` (`404`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Binds key deletion to `RPMB`/`StrongBox` NVM slots; caps per-boot invocations (`MAX_OPS_EXCEEDED`) [97, 190] |
| `Tag::USER_SECURE_ID` (`502`), `NO_AUTH_REQUIRED` (`503`), `USER_AUTH_TYPE` (`504`), `AUTH_TIMEOUT` (`505`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Demands valid `HMAC-SHA256` `HardwareAuthToken` matching 64-bit `SID` and `ISecureClock` window (`KEY_USER_NOT_AUTHENTICATED`) [97, 192] |
| `Tag::TRUSTED_USER_PRESENCE_REQUIRED` (`507`) & `TRUSTED_CONFIRMATION_REQUIRED` (`508`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Demands physical GPIO button press (`PROOF_OF_PRESENCE_REQUIRED`) or `ConfirmationUI` CBOR HMAC (`NO_USER_CONFIRMATION`) [97, 181] |
| `Tag::OS_VERSION` (`705`), `OS_PATCHLEVEL` (`706`), `VENDOR_PATCHLEVEL` (`718`), `BOOT_PATCHLEVEL` (`719`) | `TRUSTED_ENVIRONMENT` or `STRONGBOX` | Stamped by `KeyMint` from boot latches; rejects downgrades and triggers `KEY_REQUIRES_UPGRADE` on forward OTAs [97, 98] |
| `Tag::UNLOCKED_DEVICE_REQUIRED` (`509`) | `KEYSTORE` (`SuperKeyManager`) | Hardware `deviceLocked()` deprecated in `Tag.aidl` as racy; enforced in `keystore2` by superencrypting blobs under `SP`-derived keys evicted on lock [97, 187] |
| `Tag::CREATION_DATETIME` (`701`) & `ATTESTATION_APPLICATION_ID` (`709`) | `KEYSTORE` / `SOFTWARE` | Populated by `keystore2` from UTC wall clock and `PackageManager` signing certificates (`TEE` lacks UTC clock & package DB) [29, 97] |
| `Tag::MAX_BOOT_LEVEL` (`1010`) | `KEYSTORE` (`BootLevelKeyCache` + `EARLY_BOOT_ONLY` L0) | Ratcheting `HKDF` key chain in `boot_level_keys.rs` (`odsign` stage `30` $\to$ `1000000000` post-boot) dropping prior keys irreversibly [97, 157] |

Look closely at `Tag::MAX_BOOT_LEVEL` (`system/security/keystore2/src/boot_level_keys.rs` [97, 157]), a subtle masterpiece of Rust `keystore2` engineering! Components such as `odsign` ([Chapter 2](02-antirollback-verity-apex.md)) must sign or verify `ART` boot-classpath artifacts at early `init` boot level `30`, before untrusted apps start, yet must *never* allow a later compromised `system_server` at boot level `1000` to access that signing key. During early `init`, `keystore2` invokes an `EARLY_BOOT_ONLY` `KeyMint` HMAC key (`"Create boot level key"`) to seed level-0 key $K_0$ inside `BootLevelKeyCache`, then calls `IKeyMintDevice::earlyBootEnded()` [157]. As `init` advances `keystore.boot_level`, `BootLevelKeyCache` ratchets $K_{i+1} = \text{HKDF-Expand}(K_i, \texttt{"Advance KDF one step"})$ and *zeroizes $K_i$ in RAM (`ZVec`)*, mathematically guaranteeing that keys superencrypted for `MAX_BOOT_LEVEL = 30` evaporate permanently before `Zygote` forks its first app [157]!

### `HardwareAuthToken`, `ISharedSecret`, and `ISecureClock`

How does `KeyMint` know inside `Titan M2` or `TrustZone` that the human owner just entered their PIN or touched a Class 3 fingerprint sensor ([Chapter 13](13-biometrics-passkeys.md)) without trusting `EL1` Linux? During early boot, `KeyMint`, `Gatekeeper`, and hardware biometric TAs execute a symmetric key-agreement ceremony over `ISharedSecret.aidl` (`hardware/interfaces/security/sharedsecret/aidl` [183, 193]): each component contributes a random nonce mixed over a factory pre-shared hardware key to derive a single per-boot 256-bit `HMAC` key $H_{\text{boot}}$ that *never leaves secure hardware*.

Whenever `Gatekeeper::verify()` or a Class 3 biometric TA authenticates a user, it mints a `HardwareAuthToken` (`HardwareAuthToken.aidl` [97, 192]) whose 32-byte `mac` covers a strict 37-byte canonical wire concatenation:

$$\text{mac} = \text{HMAC-SHA256}_{H_{\text{boot}}}\bigl(\texttt{0x00}_{1} \parallel \texttt{challenge}_{\text{LE64}} \parallel \texttt{userId}_{\text{LE64}} \parallel \texttt{authenticatorId}_{\text{LE64}} \parallel \texttt{authType}_{\text{BE32}} \parallel \texttt{timestamp}_{\text{BE64}}\bigr)$$

Notice how `Tag::USER_SECURE_ID` interacts with `Tag::AUTH_TIMEOUT` and `Tag::UNLOCKED_DEVICE_REQUIRED` across `KeyMint` and `keystore2` [97, 187, 190, 192]. First, inspect the exact 69-byte wire structure defined in `HardwareAuthToken.aidl` (preserving binary compatibility with legacy `hw_auth_token_t` so `TEE` `Gatekeeper` and `StrongBox` `KeyMint` interoperate across HAL generations):

```c
/* Canonical 69-byte HardwareAuthToken (HardwareAuthToken.aidl) */
struct HardwareAuthToken {
  uint8_t  version;            /* Always 0x00 in HMAC input prefix */
  uint64_t challenge;          /* Machine-endian opHandle from begin() */
  uint64_t userId;             /* Machine-endian 64-bit Gatekeeper SID */
  uint64_t authenticatorId;    /* Machine-endian 64-bit Biometric ID */
  uint32_t authenticatorType;  /* Big-endian: PASSWORD(1) | BIOMETRIC(2) */
  uint64_t timestamp;          /* Big-endian ms from ISecureClock */
  uint8_t  mac[32];            /* HMAC-SHA256 under ISharedSecret H_boot */
};
```

If a key carries `Tag::AUTH_TIMEOUT = T` seconds, it is a *timed-auth key*: `KeyMint::begin()` verifies `mac`, checks `(token.authenticatorType & Tag::USER_AUTH_TYPE) != 0`, verifies `token.userId` or `token.authenticatorId` matches a sealed `USER_SECURE_ID`, and verifies $\text{now}_{\text{secure}} - \text{token.timestamp} \le 1000 \cdot T$ against its internal monotonic `ISecureClock` (or verifies a cross-domain signed `TimeStampToken` when `Gatekeeper` runs in `TEE` while the key lives in `StrongBox`!) [97, 192]. If `Tag::AUTH_TIMEOUT` is *omitted*, the key is an *auth-per-operation key*: `KeyMint::begin()` returns a fresh random 64-bit operation handle as `challenge`, `BiometricPrompt` (`CryptoObject`) authenticates against that exact `challenge`, and `KeyMint::update()`/`finish()` refuses with `KEY_USER_NOT_AUTHENTICATED` unless `token.challenge == opHandle` [97, 190, 194]! Meanwhile, for `Tag::UNLOCKED_DEVICE_REQUIRED`, `keystore2`'s `SuperKeyManager` (`system/security/keystore2/src/super_key.rs` [187]) adds a defense-in-depth userspace AEAD layer *outside* `KeyMint`'s `key_blob`: when the user locks the screen, `SuperKeyManager` wipes the symmetric unlocking key from RAM and retains only an ephemeral ECDH public key (`ECDH P-521` / `X25519`) so newly generated keys can still be encrypted while locked, yet existing `UNLOCKED_DEVICE_REQUIRED` blobs cannot even be unwrapped to hand to `KeyMint` until `SyntheticPassword` unlocks again [187]!

### `SyntheticPassword` v3 and 64-Slot `Weaver` Hardware Backoff

To connect a human's low-entropy PIN, pattern, or password (`LSKF`) to high-entropy storage (`FBE` `CE`), `Gatekeeper`, and `keystore2` keys without ever re-encrypting `/data` on PIN changes or exposing offline brute-force targets, `LockSettingsService` implements `SyntheticPassword` v3 (`SyntheticPasswordManager.java` and `SyntheticPasswordCrypto.java` [96, 195]).

![Figure: SyntheticPassword v3 unwrap chain, Titan M2 64-slot Weaver hardware backoff, and NIST SP 800-108 subkey derivation.](diagrams/04-extra-synthetic-password-weaver-chain.svg)

Trace the exact cryptographic construction inside `SyntheticPasswordManager.java` [96, 195]:

At initial user creation, Android generates two 256-bit cryptographically random splits $P_0, P_1 \in \{0,1\}^{256}$ and defines the user's permanent 256-bit master `SyntheticPassword` as $S = \text{SHA-512}_{\text{trunc}}(\texttt{"sp-split"} \parallel P_0 \parallel P_1)$ [96]. On personal consumer devices (where enterprise reset escrow is disabled), the encrypted split files `e0` and `p1` are never persisted (or deleted immediately), making escrow reconstruction mathematically impossible; on managed corporate devices ([Chapter 17](17-android-enterprise.md)), an admin `EscrowToken` wraps $P_0$ while `e0` and `p1` remain on disk so enterprise IT can revoke escrow capability at any instant simply by erasing `e0` and `p1` without changing $S$ [96]! From $S$, `SP800Derive` (`NIST SP 800-108` counter-mode HMAC-SHA256 KDF [95, 96]) derives strictly isolated domain subkeys: `"fbe-key"` (unlocking `fscrypt` Credential Encrypted `/data` in [Chapter 12](12-fbe-usb-theft-protection.md)), `"sp-gk-authentication"` (enrolled into `Gatekeeper` so unlocking $S$ mints the user's `SID` `HardwareAuthToken`), `"keystore-password"` (`keystore2` superencryption), and `"authsecret-hal"` (`IAuthSecret` [179], notifying `Titan M2` `StrongBox` that the genuine owner unlocked the phone to authorize `Insider Attack Resistance` firmware updates!).

![Figure: SyntheticPassword unwrap sequence using StrongBox Weaver slot rate limiting and KeyMint boot-bound sealing.](diagrams/04-gatekeeper-vs-weaver.svg)

How is `spblob` (`/data/system_de/<userId>/spblob/<protectorId>.spblob`) sealed so neither `EL1` root nor physical `UFS` `NAND mirroring` can brute-force a 6-digit PIN [96, 185, 195, 196]? On `StrongBox` handsets (`Google Titan M2` and `Samsung Knox Vault`), Android binds `spblob` to `IWeaver.aidl` (`hardware/interfaces/weaver/aidl/android/hardware/weaver/IWeaver.aidl` [196]). Inside `Titan M2`'s private on-die flash sits an array of 64 hardware slots (`slotId` $\in \{0, \dots, 63\}$), each holding `(key_16B, value_16B, failure_counter)` inaccessible to any bus external to `Titan M2`:

During PIN enrollment, `SyntheticPasswordManager` stretches the user's `LSKF` with a random 16-byte salt (`pwd` file) via `scrypt` ($N = 2^{11} = 2048, r = 8, p = 1$ [94, 96]) into a 32-byte stretched credential, derives a 128-bit `weaverKey` $K_W$ (`"weaver-key"`) and an inner key $K_{\text{pwd}}$ (`"weaver-pwd"`), generates a fresh 128-bit random `weaverSecret` $V$ inside `SecureRandom`, and writes $(K_W, V)$ into `slotId` via `IWeaver::write(slotId, K_W, V)` [96, 196]. Next, `SyntheticPasswordCrypto.createBlob()` wraps $S$ inside *two* nested `AES-256-GCM` layers [195]: an inner software AEAD layer keyed by $\text{protectorSecret} = K_{\text{pwd}} \oplus / \text{Hash}(V)$, and an outer hardware `KeyMint` AEAD layer (`NAMESPACE_LOCKSETTINGS`, alias `"synthetic_password_<id>"`) whose `KEK` is bound inside `KeyMint` to Verified Boot `RootOfTrust` and patch levels! (On non-`Weaver` `TEE`-only devices, `spblob` mixes a $16\text{ KiB}$ random `/data` file `secdis` for best-effort flash erasure and gates the outer `KeyMint` key on `Gatekeeper` `SID` verification backed by `RPMB` [96, 193, 195].)

When an attacker enters a guessed PIN at the lockscreen, `LockSettingsService` stretches the guess into $\widehat{K}_W$ and invokes `IWeaver::read(slotId, candidate_K_W)` over `SPI` [96, 196]. Inside `Titan M2`, firmware *first* checks if a backoff timer is active (returning `STATUS_THROTTLE` and remaining milliseconds even if the right key were presented!), *commits `failure_counter + 1` to internal on-die flash before comparing $\widehat{K}_W$ against $K_W$* (defeating power-cut tearing mid-comparison!), and only on a constant-time 128-bit match resets `failure_counter = 0` and releases $V$ [26, 185, 196]. Wrong guesses hit an uncompromising hardware wall: $0\text{ s}$ delay on attempts $1\text{..}4$, $30\text{ s}$ at attempt $5$ and attempt $10$, $30\text{ s}$ on *every single attempt* from $11\text{..}29$, and exponential doubling every $10$ attempts from $30\text{..}139$ ($30 \cdot 2^{\lfloor (c-30)/10 \rfloor}\text{ s}$) up to *$86{,}400\text{ s}$ ($24\text{ hours}$) per single wrong guess* from attempt $140$ onward [185]. At 1 guess per day on that physical `Titan M2` chip, exhausting half of a 6-digit PIN space takes over 1,369 years of powered wall-clock time, and cloning external `UFS` flash accomplishes nothing because $V$ and `failure_counter` never leave `Titan M2` silicon [26, 62, 196].

## Vendor, OEM, & Custom-OS Boundaries

`CDD` Section 9.11 requires hardware-backed `KeyMint` and tamper-resistant lockscreen throttling, continuously validated by `VtsHalKeyMintTargetTest` (which tests every `Tag.aidl` combination, `KEY_REQUIRES_UPGRADE`, `EARLY_BOOT_ONLY` cutoff, and corrupted-AAD `INVALID_KEY_BLOB` rejection) and `VtsHalWeaverTargetTest` (which verifies per-slot isolation and `STATUS_THROTTLE` timers) [9, 11, 78].

Two high-assurance extensions atop `Weaver` and `SyntheticPassword` illustrate how custom OS and enterprise vendors leverage those 64 hardware slots. First, `GrapheneOS` (`YELLOW` locked Pixel) reserves dedicated `Titan M2` `Weaver` slots to implement a hardware-backed *duress PIN/password* [116]: entering the duress credential at any lockscreen or `BiometricPrompt` immediately invokes `IWeaver::write()` with random overwrite bytes across *all* occupied user `Weaver` slots inside `Titan M2` on-die flash, erases `/data` header keys, and powers off within milliseconds, rendering `spblob` and `CE` `fscrypt` keys permanently unrecoverable even under chip-off forensic microscopy [116, 196]. Second, Samsung `Knox` layers enterprise Dual Data-At-Rest (`DualDAR`) atop `Knox Vault` and `SyntheticPassword` so managed containers ([Chapter 17](17-android-enterprise.md)) require two independent cryptographic unwraps even before first unlock [27, 197].

## Exploit Chains & Structural Limits

Historical vulnerabilities across the `Keystore`, `KeyMint`, and lockscreen tier highlight memory-corruption bugs in legacy C++ brokers, vendor `Keymaster` cryptographic shortcuts, and UI lockscreen bypasses that circumvented `Keyguard` without touching `Weaver`.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Legacy C++ `keystore` `encode_key` Overflow (`CVE-2014-3100`) | 2014 | Userspace `/system/bin/keystore` (`UID 1017`) | Malformed overlong key alias over `Binder` from `untrusted_app` | Stack-based buffer overflow in C++ key-name encoding granted `UID 1017` code execution and cross-UID key use | Complete rewrite of `keystore2` in memory-safe Rust in Android 12+ [186, 189, 198] |
| Qualcomm `KeyMaster` FDE Offline Cracking (`CVE-2016-2431` chain) | 2016 | `S-EL0` `KeyMaster` TA (pre-`Weaver`) | `EL1` root + `QSEE` exploit extracting `HBK`-derived verifier | Legacy Full-Disk Encryption lacked off-SoC `Weaver` NVM slots; compromising `QSEE` enabled high-speed offline GPU PIN brute-forcing | `SyntheticPassword` v3 + discrete `StrongBox` 64-slot `Weaver` (`Titan M2` / `Knox Vault`) [14, 96, 196] |
| Early Treble Vendor `Keymaster` Missing `ORANGE` KEK Mix | 2018-2020 | OEM `Keymaster` TA KDF implementation | Unlocking bootloader on non-wiping / buggy vendor BSP | Buggy vendor TAs reported `UNVERIFIED` in attestation but omitted `verifiedBootState` from `AES-GCM` `KEK` HKDF | Mandatory `VTS` boot-binding tests + unconditional `userdata` wipe on lock change [28, 78, 122] |
| Samsung `TEEGRIS` `Keymaster` IV Reuse & Downgrade (`CVE-2021-25444`, `CVE-2021-25490`) | 2021-2022 | Samsung `S-EL0` `Keymaster` TA (`S9`–`S21`) | `EL1` root supplying custom `Tag::NONCE` + v15 blob downgrade | `Keymaster` TA accepted caller-controlled IVs for internal `key_blob` `AES-GCM` wrapping, leaking raw private keys via stream XOR | Generate blob-wrapping IVs exclusively from internal `TRNG`; enforce strict blob version floors [98, 169] |
| Pixel SIM PUK `Keyguard` Dismiss Bypass (`CVE-2022-20465`) | 2022 | `SystemUI` `KeyguardHostViewController.java` | Physical attacker swapping SIM & entering PUK reset code on `AFU` phone | SIM PUK completion called `.dismiss()` on mismatched security screen, unlocking `AFU` UI without invoking `Weaver`/`LockSettingsService` | Bind `.dismiss()` strictly to expected `SecurityMode` (`AFU` UI != `BFU` crypto; in `BFU`, `CE` keys stay locked inside `Weaver`!) [117] |
| Biometric New-Template Addition (`setInvalidatedByBiometricEnrollment`) | Ongoing | App `KeyGenParameterSpec` developer config | Attacker with temporary PIN knowledge enrolls own fingerprint | Developer passed `setInvalidatedByBiometricEnrollment(false)`, binding key to mutable user `SID` instead of specific biometric `authenticatorId` | Default `true` seals `Tag::USER_SECURE_ID` to exact enrolled biometric `authenticatorId` [97, 192, 194] |
| `OP-TEE` `RSA-OAEP` Timing Padding Oracle (`CVE-2026-41515`) | 2026 | `OP-TEE` `NXP CAAM` RSA driver (`< 4.11.0`) | Local caller submitting ~1,500 adaptive `RSA-OAEP` ciphertexts | Non-constant-time `memcmp()` on OAEP label hash + distinct error codes created a Manger padding oracle | Constant-time OAEP unpadding & unified `ErrorCode` branches in `optee_os` / Rust `kmr` [170, 199] |
| `KeyMint` Caller Check & `VerifyHat` Logic Flaws (`CVE-2026-0145`, `CVE-2026-56929`) | 2026 | `keystore2`/`KeyMint` permission & `TrustyKeyMintManager::VerifyHat` | Local process invoking `KeyMint` with crafted auth state | Logic errors in caller permission enforcement and `HardwareAuthToken` (`HAT`) verification path | Patched in 2026 Android Security Bulletins + `VtsHalKeyMintTargetTest` negative `HAT` regression tests [78, 200] |

### Why `CVE-2022-20465` Illuminates `BFU` vs. `AFU` and Why `KeyMint` Needed `pKVM`

David Schutz's `CVE-2022-20465` SIM PUK lockscreen bypass [117] offers an unforgettable lesson in separating UI lockscreens from cryptographic sealing ([Foundations](00b-foundations.md)). On a phone sitting warm in `After First Unlock` (`AFU`), the owner had *already* unlocked `Weaver` and `SyntheticPassword` earlier that morning, leaving `CE` `fscrypt` keys active inside `UFS` Inline Crypto hardware; bypassing `SystemUI`'s Java `Keyguard` screen therefore exposed unlocked `AFU` app data immediately [117, 201]. Yet on a cold-booted `Before First Unlock` (`BFU`) Pixel, triggering `CVE-2022-20465` hit an impenetrable cryptographic brick wall: dismissing the Java lockscreen widget could not conjure the 128-bit `weaverSecret` $V$ out of `Titan M2`, leaving `/data` `CE` directories unreadable ciphertext!

> **Key idea.**
> With Part I complete, see what silicon, Verified Boot, `KeyMint`, `SyntheticPassword`, and `Weaver` jointly achieve: fixed-schema keys, passcode counters, and read-only OS partitions are anchored beneath `EL1` Linux with mathematical rigor. Yet modern Android also needs to isolate *dynamic, megabyte-scale code and stateful data* (`ART` boot-classpath compilers, `Remote Key Provisioning` attestation VMs, OEM biometric/DRM pipelines, and confidential ML inference) from a compromised host Linux kernel without stuffing C trustlets back into `TrustZone`. Part II opens in [Chapter 5](05-pkvm-avf-microdroid.md) by showing how Android built that third isolation world in Normal World `EL2` using `Protected KVM` (`pKVM`) and `Microdroid`.

## Inspecting via ADB, Fastboot, & Attestation

Inspect the running Rust `keystore2` daemon (`UID 1017` `keystore`, `u:r:keystore:s0`) and check active `OS_PATCHLEVEL`, `VENDOR_PATCHLEVEL`, and early-boot `keystore.boot_level` values sealed into keys:

```bash
adb shell ps -AZ | grep keystore2
adb shell getprop ro.build.version.security_patch
adb shell getprop ro.vendor.build.security_patch
adb shell getprop keystore.boot_level
```

Query `lock_settings` service diagnostics to confirm `SyntheticPassword` v3 state, hardware `Weaver` slot backing, and credential type without exposing sensitive material:

```bash
adb shell dumpsys lock_settings | grep -iE 'weaver|synthetic|sp-state|credential' | head -n 8
```

Verify active `IKeyMintDevice`, `IWeaver`, `IGatekeeper`, and `ISharedSecret` AIDL interface versions registered in `VINTF`:

```bash
adb shell service list | grep -iE 'keymint|weaver|gatekeeper|sharedsecret'
adb shell dumpsys android.security.maintenance 2>/dev/null | head -n 8
```
