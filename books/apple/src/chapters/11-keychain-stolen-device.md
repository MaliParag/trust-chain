# Keychain Custody, Legacy macOS Gaps, and Stolen Device Protection

## Overview

* **Link in the Chain:** Structured credential vault and anti-theft policy layer in Part III; builds atop `SEP` keybags ([Chapter 3](03-secure-enclave.md)), `DER` entitlements ([Chapter 6](06-amfi-txm-notarization.md)), and `APFS` lock classes ([Chapter 10](10-apfs-data-protection.md)) to guard application tokens, cryptographic keys, and device ownership.
* **Core Security Invariant:** Items stored in the modern Data Protection Keychain (`secd`) are encrypted individually under `SEP`-bound class keys and readable only by processes whose `TXM`-verified `DER` entitlements match the item's `keychain-access-groups`, while `Stolen Device Protection` (`iOS 17.3+`) strips passcode fallback from sensitive account/credential mutations outside familiar locations.
* **Platform Matrix:** `iOS`, `iPadOS`, `watchOS`, and `visionOS` use the `SEP`-backed Data Protection Keychain exclusively; `macOS` runs a split architecture retaining the legacy file-based `login.keychain-db` (`SecurityServer`) alongside the Data Protection Keychain, while `Stolen Device Protection` is currently `iOS`-focused (`Activation Lock` spans `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS`).
* **Trusted Computing Base (TCB):** `secd` (Data Protection Keychain daemon) and `SEP` `SKS`, `TXM`/`AMFI` `keychain-access-groups` checks, legacy `SecurityServer` on `macOS`, `CoreRoutine` on-device familiar-location state, and Apple's `Find My` Activation Lock servers.
* **Failure Horizon & Handoff:** `macOS` apps omitting `kSecUseDataProtectionKeychain` store secrets in `~/Library/Keychains/login.keychain-db`, allowing commodity stealers (*Atomic macOS Stealer*) to copy and decrypt the vault offline with a phished login password, while live `iOS` exploit chains (*DarkSword*) read unlocked app tokens in `AFU`; hands off remote hardware proof of `SEP` keys to [Chapter 12](12-sep-app-device-attestation.md).

## Threat Model & Design Tension

`APFS` Data Protection ([Chapter 10](10-apfs-data-protection.md)) encrypts whole files on disk, yet credentials (OAuth refresh tokens, `Wi-Fi` `802.1X` secrets, `SSH` passphrases, `Passkeys`, and biometric-gated `P-256` signing keys) demand stricter isolation than file permissions provide [101]. First, a complex app ecosystem needs controlled secret sharing across companion extensions (for example, a messaging app and its `NotificationServiceExtension`) from the *same* verified developer `TeamID` without exposing those tokens to sibling processes running under the same UNIX `UID`. Second, high-value keys (`Apple Pay`, corporate VPN keys, banking tokens) should support *non-exportable enclave execution* where the app can request an `ECDSA` signature only after a live `Face ID` scan, without ever receiving raw private-key bytes in user memory.

Across Apple's ecosystem, however, two severe real-world threat vectors collided with Keychain assumptions between 2022 and 2026 [102, 103, 106]. On `macOS`, twenty-five years of backward compatibility with NeXT/Carbon/UNIX CLI binaries preserved a legacy *File-Based Keychain* (`~/Library/Keychains/login.keychain-db`) unlocked automatically at login and protected solely by a software master key derived from the user's `macOS` password, creating a lucrative target for commodity infostealers (*Atomic macOS Stealer* `AMOS` and *Poseidon*) [102, 103]. Meanwhile, on `iPhone`, organized physical theft rings discovered an architectural single point of failure reported in *The Wall Street Journal* in 2023 [106]: because `iOS` allowed the 6-digit device passcode as a universal fallback whenever `Face ID` failed, thieves who shoulder-surfed a victim typing their passcode in a crowded bar and then snatched the phone could immediately reset the victim's Apple Account password, generate a new 28-character Recovery Key, disable `Find My` Activation Lock, and drain saved Keychain passwords within three minutes!

## Silicon & System Mechanics

### The SEP Data Protection Keychain (secd) and Access Groups

On `iOS`, `iPadOS`, `watchOS`, and `visionOS` (and on `macOS` whenever a caller sets `kSecUseDataProtectionKeychain: true` (or targets `kSecAttrSynchronizable: true`)) credential operations route over `XPC` to `secd`, backed by an encrypted SQLite store (`keychain-2.db`) sealed under `SEP` hardware keys [101, 102].

Every Keychain item undergoes two-layer `AES-256-GCM` wrapping [101]. An outer *metadata key* (per protection class, unlocked in `AFU` so `secd` can execute indexed queries over attributes like `kSecAttrAccount` and `kSecAttrService`) encrypts searchable metadata columns; an inner per-row random *secret key* encrypts the actual secret value (`v_Data`) and sits wrapped inside `SEP` under the item's `kSecAttrAccessible` class (`WhenUnlocked`, `AfterFirstUnlock`, `WhenPasscodeSetThisDeviceOnly`, along with `*ThisDeviceOnly` variants that forbid inclusion in `iCloud` or Finder backups) [101].

Furthermore, developers can attach a `SecAccessControlRef` (`SecAccessControlCreateWithFlags`) binding `SKS` key release inside `SEP` directly to hardware biometric predicates [41, 101]:

$$\text{Unwrap}_{\text{SEP}}(\text{item}) \iff \text{ClassUnlocked} \;\land\; \bigl(\text{BiometryMatch} \;\land\; H(\text{EnrolledSet}_{\text{now}}) = H(\text{EnrolledSet}_{\text{creation}})\bigr)$$

Under `.biometryCurrentSet`, `SEP` hashes the set of enrolled `Face ID` or `Touch ID` templates at item creation; if an attacker or local admin later adds a *new* fingerprint to the device using a known passcode, $H(\text{EnrolledSet}_{\text{now}})$ changes and `SEP` permanently invalidates the item's key! Going one step further, setting `kSecAttrTokenID: kSecAttrTokenIDSecureEnclave` instructs `SEP` itself to generate a hardware `P-256` keypair whose private scalar never enters `secd` or app RAM at all; `keychain-2.db` stores only an opaque `SEP`-sealed key blob usable solely via `SecKeyCreateSignature` / `SecKeyCreateDecryptedData` mailbox calls [37, 101].

Caller isolation in `secd` ignores POSIX file permissions completely, relying instead on `TXM`-verified `DER` entitlements extracted from the caller's `audit_token_t` ([Chapter 6](06-amfi-txm-notarization.md), [Chapter 7](07-ipc-seatbelt-blastdoor.md)) [101]: `secd` constructs the caller's allowed access-group list from `application-identifier` (`<TeamID>.<BundleID>`), `keychain-access-groups` (provisioned by Apple only for matching `<TeamID>.*` prefixes), and `com.apple.token`. No unrelated third-party process (even running as the same `UID 501` on `macOS`) can forge another developer's `<TeamID>` inside a `TXM`-verified signature to read its Data Protection Keychain items!

### The Legacy macOS File-Based Keychain Gap (login.keychain-db)

Why, then, do commodity `macOS` infostealers routinely harvest Chrome encryption keys, Slack tokens, and CLI credentials on Apple Silicon Macs? Because `macOS` `SecItemAdd` / `SecItemCopyMatching` still defaults to the *File-Based Keychain* (`SecurityServer` managing `~/Library/Keychains/login.keychain-db`) whenever `kSecUseDataProtectionKeychain` is omitted, so unprovisioned CLI binaries (`git-credential-osxkeychain`, Homebrew binaries, Electron apps lacking an Apple Provisioning Profile) continue working without `App ID` entitlements [102]!

![Figure: Split macOS Keychain architecture contrasting the SEP-sealed, entitlement-isolated Data Protection Keychain (secd) against the legacy password-derived login.keychain-db targeted by Atomic Stealer (AMOS).](diagrams/11-dp-keychain-vs-file-keychain.svg)

Inside `login.keychain-db`, the master wrapping key is derived purely in software (`PBKDF2-3DES` / `AES`) from the user's `macOS` login password (with *zero* `SEP` `UID` tangling and *zero* `SEP` hardware anti-replay counters [102, 103]! Access control between local apps relies on legacy per-item `SecACL` lists (path/signature ACLs checked by `SecurityServer` that prompt *"app wants to use your confidential information stored in 'Chrome Safe Storage' in your keychain"*). Worse, if an attacker tricks the user into typing their login password once into a fake `osascript` (`display dialog "System Preferences requires your password..." with hidden answer`) prompt) the exact playbook of *Atomic macOS Stealer* (`AMOS`), the malware simply copies `~/Library/Keychains/login.keychain-db` off the Mac to an attacker server and decrypts *every single item inside the file offline* using the captured password, bypassing `SecurityServer` ACLs completely [103]!

### Activation Lock and Stolen Device Protection

At the physical device-theft layer, two complementary mechanisms defend device resale value and account custody [104, 105]. First, *Activation Lock* (`Find My`) binds a device's `ECID`/hardware identity and `SEP` state to an owner's Apple Account on Apple's activation servers [104]. Even if a thief places an iPhone or Apple Silicon Mac into `DFU` mode ([Chapter 1](01-secure-boot.md)) and flashes a clean OS via Finder/Configurator, Setup Assistant queries Apple's activation server before issuing an operational ticket; without the owner's Apple Account credentials (or original proof-of-purchase unlock / enterprise `MDM` Activation Lock bypass code escrowed at enrollment, [Chapter 14](14-ddm-platform-sso.md)), the wiped hardware refuses to activate [104, 121].

Second, *Stolen Device Protection* (`iOS 17.3+`, expanded in `iOS 18+`/`26`) severs the catastrophic assumption that *"possessing the 6-digit unlock passcode equals full owner authority"* [105, 106].

![Figure: Stolen Device Protection three-stage gate defeating shoulder-surfed passcodes through mandatory live biometrics, CoreRoutine familiar-location evaluation, and a 1-hour security delay.](diagrams/11-stolen-device-protection-gate.svg)

When enabled, `Stolen Device Protection` divides high-risk operations into two tiers enforced jointly by `SEP`, `LocalAuthentication`, `secd`, and `AuthKit` [105]:

First, for *credential access* (viewing saved passwords or `Passkeys` in the `Passwords` app (`Keychain`), using saved payment methods in Safari autofill, applying for Apple Card, or erasing all content) `iOS` requires a live `Face ID` or `Touch ID` biometric match with *zero passcode fallback*; typing the shoulder-surfed passcode is no longer offered when biometrics fail [105]. Second, for *irreversible account-custody mutations* (changing the Apple Account password, adding or removing a Recovery Key or Recovery Contact, adding/removing `Face ID` or changing the device passcode, turning off `Find My`, or disabling `Stolen Device Protection` itself) the device checks `CoreRoutine`'s encrypted on-device Significant Locations model (home, workplace). Whenever the iPhone is *outside* a familiar location (or if Significant Locations was recently reset), `iOS` enforces a mandatory *one-hour security delay*: the user must pass live `Face ID`/`Touch ID` once to start a 60-minute timer, wait a full hour (giving the mugging/bar-theft victim ample time to mark the device Lost via `icloud.com/find` or a friend's phone!), and pass a *second* live `Face ID`/`Touch ID` scan before `SEP` and `AuthKit` authorize the change [105].

## Platform Forks Across Apple OSes

`iOS`, `iPadOS`, `watchOS`, and `visionOS` enjoy clean single-vault hygiene because legacy `SecurityServer` file keychains were never shipped on Darwin mobile platforms; every `SecItemAdd` call automatically lands in `secd`'s `SEP`-backed Data Protection Keychain [101]. `macOS` remains the lone platform straddling both worlds: Apple migrated Safari AutoFill passwords, `iCloud Keychain` synced items, and the standalone `Passwords.app` (`macOS Sequoia 15+`) exclusively into the Data Protection Keychain, yet third-party Mac apps (`Chromium`-derived browsers storing cookie-encryption keys, Electron apps, CLI helpers) remain vulnerable to `login.keychain-db` theft until explicitly compiled with provisioning profiles and `kSecUseDataProtectionKeychain = true` [102, 103]. Meanwhile, `Stolen Device Protection`'s location-gated one-hour delay was engineered first for `iPhone` street-theft threat models (with `Familiar Locations` toggleable to *Always* require the 1-hour delay even at home for domestic/shared-space threat models) [105].

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Keychain` Access-Group / Backup Downgrades | 2019-2022 | `iOS` | Non-`ThisDeviceOnly` items in backups | Encrypted local backups migrated non-device-bound keychain items to attacker-controlled test devices if backup password was weak | Defaulted sensitive tokens (`Passkeys`, enterprise certs) to `*ThisDeviceOnly` or E2EE `iCloud Keychain` [101, 125] |
| Shoulder-Surfed Passcode Account Takeover | 2022-2023 | `iOS` | Passcode fallback on `AuthKit` & `Keychain` | Knowing a 6-digit unlock PIN allowed resetting Apple Account password via trusted-device `SEP` token and disabling Activation Lock in seconds | Shipped `Stolen Device Protection` (`iOS 17.3+`): biometric-only + 1-hour unfamiliar-location delay [105, 106] |
| *Atomic macOS Stealer* (`AMOS`) / *Poseidon* | 2023-2026 | `macOS` | Legacy `login.keychain-db` confidentiality | Fake `osascript` dialog captures user password; stealer copies `~/Library/Keychains/login.keychain-db` off-box for offline decryption of unmigrated app keys | Migrate Mac apps to `kSecUseDataProtectionKeychain` (`secd` + `SEP` `UID` blocks offline decryption); `XProtect` blocks `AMOS` [89, 102, 103] |
| *DarkSword* Post-Exploit Credential Harvest | 2025-2026 | `iOS` (`< 18.7.5`, `< 26.3`) | Live `AFU` Keychain & app containers | Full-chain `WebKit`-to-kernel zero-day (`CVE-2026-20700` et al.) executing as kernel/privileged daemon inside unlocked `AFU` session reads `AfterFirstUnlock` items without needing `UID` extraction | Gate high-value keys with `.biometryCurrentSet` / `.userPresence` per-operation prompts; keep OS patched & `MIE` active [5, 79, 101] |

> **Key idea.**
> Why can *Atomic macOS Stealer* decrypt a copied `login.keychain-db` file on an attacker's Linux VPS using a phished password, whereas copying `keychain-2.db` (the Data Protection Keychain) off the exact same Mac + knowing the user's password yields *zero* decrypted secrets? Because every keybag wrapping `keychain-2.db` is tangled through the physical Mac's unreadable `SEP` `UID` hardware `AES` engine ([Chapter 3](03-secure-enclave.md)) [37, 101, 102]!

## Verification & Forensic Artifacts

On `macOS`, list active legacy file-based keychains managed by `SecurityServer` (`security list-keychains`) and check automatic lock-timeout settings (`security show-keychain-info`: note that default `login.keychain-db` has *no* lock-on-sleep timeout unless hardened, though migrating apps to `secd` is the structural fix) [102]:

```bash
security list-keychains
ls -lh ~/Library/Keychains/login.keychain-db ~/Library/Keychains/*/keychain-2.db 2>/dev/null
```

Representative output showing *both* the legacy `login.keychain-db` and the hardware-UUID-scoped `keychain-2.db` Data Protection Keychain side by side on `macOS`:

```text
    "/Users/alice/Library/Keychains/login.keychain-db"
    "/Library/Keychains/System.keychain"
-rw-r--r--  1 alice  staff   1.4M Nov 15 09:12 /Users/alice/Library/Keychains/login.keychain-db
-rw-------  1 alice  staff   8.2M Nov 15 10:40 /Users/alice/Library/Keychains/4A8F19C2-.../keychain-2.db
```

Audit whether a downloaded third-party `macOS` binary carries provisioned `keychain-access-groups` / `application-identifier` entitlements enabling it to use the `SEP`-backed Data Protection Keychain [101, 102]:

```bash
codesign -d --entitlements :- /System/Applications/Passwords.app 2>/dev/null | grep -E 'keychain-access-groups|application-identifier' -A 2 | head -n 6
```

Verify `Activation Lock` (`Find My Mac`) hardware registration state in `ioreg` / `nvram` (`fmm-mobileme-token-FMM` presence indicates active `Find My` Activation Lock binding) [104]:

```bash
nvram -p | grep -c 'fmm-mobileme-token-FMM' || true
```

Storing non-exportable keys inside `SEP` protects secrets locally on the endpoint, yet a remote banking backend, game server, or enterprise Zero Trust gateway cannot physically inspect the client's silicon. [Chapter 12](12-sep-app-device-attestation.md) derives how `SEP` proves hardware residency and OS posture cryptographically across the network via `App Attest` and `ACME` `Managed Device Attestation`.
