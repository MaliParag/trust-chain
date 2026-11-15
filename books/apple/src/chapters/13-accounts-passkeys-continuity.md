# Apple Account, Passkeys, Continuity, and Spatial Gaze Isolation

## Overview

* **Link in the Chain:** Personal identity, multi-device proximity mesh, and spatial human-intent boundary in Part III; binds user accounts and phishing-resistant `WebAuthn` credentials to `SEP`-synced circles ([Chapter 11](11-keychain-stolen-device.md)) while gating cross-device `Continuity` and `visionOS` eye-gaze input.
* **Core Security Invariant:** User passwords never traverse the wire in cleartext during `GrandSlam` (`GSA`) `SRP-6a` authentication, `Passkeys` sign challenges strictly bound to the relying party's verified `rpId` origin, `watchOS` `Auto Unlock` enforces physical speed-of-light Time-of-Flight (`ToF`) distance bounds, and `visionOS` isolates raw eye-tracking cameras inside the `R1` co-processor and system compositor until an explicit pinch occurs.
* **Platform Matrix:** `GSA`, `Sign in with Apple`, synced `Passkeys`, and `Continuity` (`Handoff`, `AirDrop`) span `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS`; `Auto Unlock` specifically pairs `watchOS` + `macOS` (and `iOS` Face ID with mask), while `R1` hardware gaze isolation is unique to `visionOS` on `Apple Vision Pro`.
* **Trusted Computing Base (TCB):** `AuthKit` (`akd`) and Apple's `GrandSlam` `SRP` servers, `ASAuthorization` (`authenticationservicesd`) origin validators, `iCloud Keychain` E2EE sync circles, Wi-Fi Fine Timing Measurement / UWB ranging transceivers, `sharingd` (`BLE` + `AWDL` mTLS), and the `Apple Vision Pro` `R1` co-processor + `RealityKit` system compositor.
* **Failure Horizon & Handoff:** Token-claim validation flaws (`CVE-2020-9768`) or local account/credential access bugs (`CVE-2026-43760`) compromise federated auth, while truncated contact-hash PSI in legacy `AirDrop` leaked phone numbers (`PrivateDrop`); hands off organizational fleet supervision, `DDM`, and enterprise `Platform SSO` to [Chapter 14](14-ddm-platform-sso.md).

## Threat Model & Design Tension

A modern user rarely owns a single isolated Apple device; an `iPhone`, `MacBook`, `iPad`, `Apple Watch`, and `Apple Vision Pro` operate as a unified personal mesh sharing clipboard items, unlocking one another by proximity, autofilling `WebAuthn` credentials, and logging into third-party websites [1, 115, 116]. Extending trust seamlessly across that personal device constellation introduces four distinct adversarial threats spanning Tier 1 through Tier 4 [112, 116, 117, 118].

First, at account sign-in and web authentication, password replay, credential stuffing, and real-time adversary-in-the-middle (`AiTM`) phishing proxies defeat traditional password + SMS/TOTP two-factor flows, while federated OAuth providers ("Sign in with...") routinely track every app a user opens [112, 113, 115]. Second, if syncing `Passkeys` across a user's devices exposed private keys to Apple's cloud servers, a cloud breach could impersonate users across every bank and email provider on earth [115, 125]. Third, in wireless proximity protocols (`Apple Watch` unlocking a locked MacBook, or `AirDrop` discovering nearby contacts over Bluetooth Low Energy), two classic RF attacks loom: *relay ("mafia fraud") attacks*, where two colluding attackers with transceivers relay Bluetooth frames between a victim sitting in a cafe and their locked MacBook back in the office, and *passive identifier tracking*, where strangers sniff BLE advertisements to enumerate phone numbers [116, 117]. Fourth, when `Apple Vision Pro` turns where the human eye looks into the primary cursor of spatial computing, exposing raw $90\text{+}\text{ Hz}$ pupil, iris, and gaze-vector streams to untrusted apps would leak involuntary cognitive, medical, emotional, and password-entry secrets before the user ever intended to click [118]!

## Silicon & System Mechanics

### GrandSlam (GSA) SRP-6a and Sign in with Apple

Underlying every Apple Account login (`AuthKit` / `akd` on-device talking to `gsa.apple.com`) is *GrandSlam (`GSA`)*, built around the `RFC 5054` *Secure Remote Password (`SRP-6a`)* zero-knowledge password-authenticated key exchange [112]. Rather than transmitting a plaintext or TLS-wrapped password hash to Apple's login servers, the client stretches the user's Apple Account password locally with `PBKDF2-HMAC-SHA256` into secret scalar $x$ and proves knowledge of $x$ against Apple's stored verifier $v = g^x \bmod N$ through an ephemeral Diffie-Hellman exchange blinded by $k v$, establishing a mutually authenticated session key without Apple's login frontend ever handling the raw password [112]. Following `SRP-6a`, two-factor authentication (`2FA`) pushes an encrypted geolocation + 6-digit verification challenge exclusively to existing *trusted devices* already enrolled in the user's `SEP`-backed account circle (or verifies a hardware `FIDO2` USB/NFC Security Key for high-risk accounts enrolled in Apple Account Security Keys, which completely disables SMS/push fallback!) [1].

For third-party apps and websites, *Sign in with Apple* (`ASAuthorizationAppleIDProvider`, built on `OpenID Connect` / `OAuth 2.0` JWTs signed by Apple's `auth/keys` JWK set) adds two privacy-preserving invariants [113]: pairwise team-scoped `sub` subject identifiers (so two unrelated developer teams cannot correlate the same user unless same-TeamID migration is invoked) and *Hide My Email* private relay addresses (`@privaterelay.appleid.com`) that strip tracking headers and restrict each generated alias strictly to one sender domain.

### Synced Passkeys Over iCloud Keychain Circles

Implemented via `ASAuthorizationPlatformPublicKeyCredentialProvider` (`authenticationservicesd`), *Passkeys* instantiate `W3C WebAuthn` Level 3 / `FIDO2` discoverable credentials (`P-256` `ECDSA` keypairs) synchronized end-to-end across all of a user's Apple devices via their encrypted *iCloud Keychain circle* ([Chapter 15](15-icloud-hsm-adp.md)) [115, 125].

![Figure: Personal identity and proximity sequence integrating GSA SRP-6a login, E2EE iCloud Keychain synced Passkeys, and Apple Watch Auto Unlock Time-of-Flight (ToF) physical distance bounding.](diagrams/13-gsa-passkey-continuity-flow.svg)

When a user registers or authenticates a Passkey on `example.com` (or inside a native app linked bi-directionally to `example.com` via an HTTPS `/.well-known/apple-app-site-association` `webcredentials` manifest verified by `swcd`), `authenticationservicesd` (*not* the untrusted web page) verifies TLS origin identity and computes `clientDataJSON` + `rpIdHash = SHA-256("example.com")`, gating private-key signing behind live `Face ID` or `Touch ID` [115]. Even if a user is lured onto a pixel-perfect real-time phishing proxy at `examp1e-login.com`, `authenticationservicesd` computes `SHA-256("examp1e-login.com")`, finds zero matching credentials for that origin, and cannot be socially engineered into signing a challenge for `example.com`! Cross-ecosystem login on a nearby Windows or Linux PC (`FIDO CTAP 2.2` Hybrid Transport / `caBLE`) pairs an ephemeral QR-scanned elliptic-curve key with a physical Bluetooth Low Energy proximity check so a remote attacker phishing a QR code on a webinar screen cannot complete the Passkey signature without physically sitting within BLE range of the user's iPhone [115].

### Continuity: Watch Auto Unlock Time-of-Flight and AirDrop Mutual TLS

How does *Auto Unlock with Apple Watch* unlock a `FileVault`-authenticated Mac session when the owner wakes their laptop without falling victim to a two-person Bluetooth/Wi-Fi relay attack [116]? First, during one-time setup, the unlocked Mac's `SEP` and the wrist-detected, passcode-unlocked Apple Watch's `SEP` establish long-term pairwise Continuity keys via the user's `iCloud` account circle. When the Mac wakes, `sharingd` detects the Watch's encrypted BLE Continuity advertisement and opens a mutually authenticated peer-to-peer Wi-Fi session. Second, before releasing the unlock secret, the Mac and Watch execute hardware *Time-of-Flight (`ToF`) ranging* (`IEEE 802.11v` Fine Timing Measurement / Ultra-Wideband nanosecond timestamp exchange) [116]:

$$d_{\text{measured}} = c \cdot \frac{(t_4 - t_1) - (t_3 - t_2)}{2} \le d_{\text{max}} \approx 3\text{ meters}$$

where $c \approx 0.30\text{ m/ns}$ is the speed of light in air, $(t_4 - t_1)$ is total round-trip hardware PHY counter elapsed time on the Mac, and $(t_3 - t_2)$ is the calibrated turnaround time on the Watch! Because electromagnetic waves cannot travel faster than $c$, any attacker attempting to capture packets near the victim's wrist $30\text{ meters}$ away and relay them over coax, Wi-Fi, or LTE adds $\ge 100\text{ ns}$ of unavoidable propagation and amplifier delay, failing the nanosecond `ToF` gate instantly [116]!

Other `Continuity` features (`Handoff`, `Universal Clipboard`, `Instant Hotspot`, and `AirDrop`) pair low-power encrypted BLE advertisements (`sharingd`) with high-throughput peer-to-peer `Apple Wireless Direct Link` (`AWDL` ad-hoc `802.11` interface `awdl0`) links wrapped inside *mutual TLS (`mTLS`)* authenticated by Apple-Account-issued `Apple ID Validation Record` X.509 identity certificates stored in Keychain [116, 117]. When two contacts share a file via `AirDrop` (*Contacts Only*), BLE broadcasts a short rotated tag while full identity exchange occurs only inside the encrypted `AWDL` TLS handshake (or over ultra-short-range NFC tap via `NameDrop` in `iOS 17+`, eliminating ambient RF broadcast altogether) [116, 117].

### visionOS and R1 Hardware Spatial Gaze Isolation

On `Apple Vision Pro`, the user navigates dense 3D workspaces simply by looking at an interface control and tapping thumb to index finger. High-frequency infrared eye tracking (`Optic ID` / gaze cameras) is extraordinarily sensitive biometric telemetry: pupil dilation, saccade cadence, and dwell heatmaps reveal reading comprehension, neurological conditions, sexual or political attention, and PIN keypad entries [42, 118].

![Figure: visionOS spatial gaze privacy pipeline isolating raw internal IR eye-camera streams inside the R1 co-processor and RealityKit system compositor so sandboxed apps receive only pinch-committed tap events.](diagrams/13-visionos-r1-gaze-isolation.svg)

Rather than gating raw eye-tracking behind a `TCC` *"Allow App X to track your eyes?"* prompt (which nearly every spatial UI app would demand just to highlight buttons!) Apple engineered a *zero-trust UI compositor architecture* anchored in the dedicated *R1 co-processor* [118]. Raw internal eye-camera frames travel over dedicated hardware buses into `R1`, which computes real-time sensor fusion ($12\text{ ms}$ photon-to-photon) and delivers the 3D gaze ray *exclusively* to the privileged `visionOS` system compositor (`backboardd` / `RealityKit` render server) [118]. Developers attach declarative `HoverEffectComponent` shaders/styles to their 3D entities or `SwiftUI` buttons; the *system compositor itself* evaluates ray-intersection tests and renders the visual hover glow on display pixels without executing a single callback or changing a single readable bit inside the application's address space! Only at the exact millisecond when external hand-tracking cameras confirm an intentional *thumb-to-index pinch gesture* does `visionOS` synthesize a discrete `UIEvent` / `SpatialTapGesture` coordinate on that single targeted element and deliver it to the sandboxed app [118]. (Only specialized assistive/enterprise apps granted an explicit, heavily audited `Hands` / `Head` pose or accessibility API ever receive broader motion data, while raw consumer eye gaze stays architecturally off-limits.)

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS`, `GSA`, `Sign in with Apple`, and synced `Passkeys` maintain cryptographic parity so credentials move frictionlessly across devices [113, 115]. Enterprise environments, however, frequently disable consumer `iCloud Keychain` Passkey sync via MDM restrictions (`allowCloudKeychainSync = false`) and substitute *device-bound* `SEP` enterprise passkeys managed through `Platform SSO` ([Chapter 14](14-ddm-platform-sso.md)) so corporate credentials never sync onto an employee's unmanaged home iPad [115, 122]. Meanwhile, `AWDL` (`awdl0`) and `Continuity` listen sockets expose local-adjacent Wi-Fi attack surface (famously exploited in Ian Beer's 2020 wormable `XNU` `AWDL` vulnerability `CVE-2020-3843`), prompting security-conscious `macOS` and `iOS` users to set `AirDrop` to *Contacts Only* or *Receiving Off* (which `iOS 16.2+` enforces automatically by reverting *Everyone* to *10 Minutes* max!).

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Sign in with Apple` OIDC Bypass (`CVE-2020-9768`) | 2020 | All Apple OSes / Web | `Sign in with Apple` JWT account binding | Server logic flaw discovered by Bhavuk Jain failed to bind authenticated session subject strictly to requested Apple ID email when minting OIDC authorization tokens ($100k bounty) | Patched Apple OIDC token-issuance subject binding server-side; zero wild exploitation [113, 114] |
| `AWDL` Kernel Wi-Fi RCE (`CVE-2020-3843` / `CVE-2020-9906`) | 2020 | `iOS` / `macOS` | Proximity `Continuity` `AWDL` driver | Buffer overflow in `IO80211Family` `AWDL` frame parsing reachable over radio adjacency without pairing | Patched `AWDL` driver bounds, defaulted `AirDrop Everyone` to 10-minute timeout, & added `MIE` (`EMTE`) [5, 116] |
| `AirDrop` Contact Hash Reversal (`PrivateDrop`) | 2021 | `iOS` / `macOS` | BLE contact-discovery unlinkability | BLE advertisements broadcast truncated `SHA-256` hashes of phone numbers/emails; brute-forcing $10^{10}$ E.164 phone numbers reversed hashes in milliseconds | Introduced `NameDrop` physical tap (`iOS 17+`) and tightened BLE/AWDL discovery schedules [117] |
| Account / Credential Access Flaw (`CVE-2026-43760`) | 2026 | `macOS` (`< 26.6`, `< 14.8.8`), `iOS` (`< 26.6`) | Local user-sensitive account/auth data | Insufficient access restrictions on local account/authentication data allowed a local app to read user-sensitive credential state | Patched access restrictions across `macOS Tahoe 26.6`, `Sonoma 14.8.8`, and `iOS 26.6` (`July 2026`) [114] |

### Hover Side-Channel Bounds on visionOS and Contact-Hash Limits in AirDrop

Two subtle theoretical boundaries deserve close architectural attention. In `AirDrop`, TU Darmstadt's *PrivateDrop* paper proved a timeless cryptographic lesson: hashing low-entropy structured identifiers like 10-digit telephone numbers (`SHA-256("+12065550199")`) without a shared secret salt provides *zero* confidentiality against an offline rainbow table or GPU hash-reversal dictionary (motivating True Private Set Intersection (`PSI`) or tap-to-pair `NameDrop` [117]. Similarly, on `visionOS`, while `R1` and `RealityKit` block raw eye-coordinate readout completely, academic spatial-UI research notes that if an app renders custom dynamic textures or triggers network/asset loads *only* inside CSS/web hover states where permitted, timing side channels must be suppressed) which is why `visionOS` restricts custom hover callbacks completely in native `HoverEffectComponent` and isolates `WebKit` `:hover` evaluation so pages cannot poll eye movement [118]!

## Verification & Forensic Artifacts

On `macOS`, inspect the `awdl0` peer-to-peer Continuity interface state and active `AirDrop` `DiscoverableMode` (`Contacts Only`, `Off`, or `Everyone`) without altering network configuration [116]:

```bash
ifconfig awdl0 2>/dev/null | head -n 4
defaults read com.apple.sharingd DiscoverableMode 2>/dev/null || echo "Default (Contacts Only)"
```

Verify bi-directional `Passkeys` / `Sign in with Apple` Associated Domains (`swcd` `apple-app-site-association` trust database) cached on `macOS` using `swcutil` [115]:

```bash
# Inspect swcd daemon status via Unified Logging:
log show --last 30m --predicate 'subsystem == "com.apple.AuthenticationServices"' --style compact | tail -n 5
```

Check `AuthKit` (`akd`) Apple Account circle and `Continuity` (`sharingd` Auto Unlock) events in Unified Logging [90, 112, 116]:

```bash
log show --last 1h --predicate 'subsystem IN {"com.apple.authkit", "com.apple.sharing"}' --style compact | tail -n 4
```

Consumer Apple Accounts and personal Continuity meshes assume the individual human user is the ultimate sovereign of the device. What happens when a global enterprise buys 100,000 MacBooks and iPhones that must never bypass corporate management even after a `DFU` wipe, and must bind Microsoft Entra ID or Okta sessions directly to `SEP` silicon? [Chapter 14](14-ddm-platform-sso.md) closes Part III with `Automated Device Enrollment`, `Declarative Device Management`, and `Platform SSO`.
