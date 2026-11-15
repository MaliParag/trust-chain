# Offline Find My Cryptography and Anti-Tracking Bounds

## Overview

* **Link in the Chain:** Zero-knowledge crowd-sourced RF location and physical anti-stalking layer in Part IV; enables offline Apple devices and accessories (`AirTag`) to report encrypted GPS coordinates through stranger devices without revealing device identity or location to relays or Apple.
* **Core Security Invariant:** Offline beacons derive rotating `NIST P-224` public keys $P_i$ and Bluetooth MAC addresses from a symmetric ratchet synced only inside the owner's `Octagon` Keychain circle, while finder devices encrypt their own GPS coordinates via `ECIES` directly to $P_i$ and upload ciphertexts indexed solely by $\text{SHA-256}(P_i)$.
* **Platform Matrix:** Offline beacon emission runs across `iOS`, `iPadOS`, `macOS` (even when asleep or powered off on supported silicon via low-power Bluetooth controllers), `watchOS`, `AirPods`, and `AirTag`; finder relay participation spans `iOS`, `iPadOS`, and `macOS`, while cross-ecosystem unwanted-tracker detection (`IETF DULT`) spans both `iOS` (`17.5+`) and `Android`.
* **Trusted Computing Base (TCB):** Owner `SEP`/`Octagon` master `P-224` private key ($d_0$) and symmetric chain seed ($SK_0$), low-power Bluetooth beacon firmware, finder `locationd`/`searchpartyd` `ECIES` encryption, and on-device trajectory-clustering algorithms (`searchpartyd` / `DULT`).
* **Failure Horizon & Handoff:** Fundamental cryptographic trade-off between *unlinkability* (fast 15-minute key rotation hiding passersby from RF tracking) and *anti-stalking detection* (separated-from-owner slower rotation required so a stalked victim's phone recognizes one rogue tag moving with them), plus cloned/modified third-party microcontroller beacons (`OpenHaystack`); hands off on-device AI and tool isolation to [Chapter 18](18-agentic-ai-workload-isolation.md).

## Threat Model & Design Tension

Locating a stolen laptop whose thief immediately turned off Wi-Fi (or a lost set of keys with a coin-cell `AirTag` lacking GPS or cellular radios) requires enlisting nearby strangers' smartphones as opportunistic Bluetooth relays [128]. Designing a billion-node crowd-sourced Bluetooth location network without building a global Orwellian surveillance grid forces a direct confrontation with four simultaneous adversarial models [128, 129].

First, against *passive RF trackers* (retail malls, ad beacons, municipal Bluetooth sniffers), a user's `iPhone` or `MacBook` in a backpack must never broadcast a static Bluetooth MAC address or static public key that allows sniffers along a highway to correlate the same person passing Sensor A at 9:00 a.m. and Sensor B at 9:15 a.m. [128]. Second, against a *curious or malicious Finder phone*, a stranger's `iPhone` relaying a lost beacon must learn neither whose device it just heard nor be able to track that device later. Third, against *Apple's own cloud servers* (Tier 4), the backend storing billions of encrypted location reports every day must learn neither which Apple Account owns a queried beacon hash, nor the plaintext GPS coordinates inside the report, nor which stranger uploaded it [128]!

Fourth (and hardest of all) the moment Apple shipped inexpensive coin-sized `AirTag` accessories in 2021, an *abusive domestic partner or physical stalker* could slip their own `AirTag` into a victim's coat or car [129]! Notice the mathematical paradox: *total cryptographic unlinkability* (rotating the `AirTag`'s public key and MAC every 15 minutes unconditionally so nobody can tell Beacon $t_1$ and Beacon $t_2$ came from the same tag) would simultaneously make it *mathematically impossible for the stalked victim's phone to realize that a single hidden tracker has been following them across town all afternoon* [129]! Reconciling anti-surveillance unlinkability with physical anti-stalking safety required state-dependent rotation schedules and the cross-industry *IETF DULT* (`Detecting Unwanted Location Trackers`) standard [129].

## Silicon & System Mechanics

### Master P-224 Pairing and Unlinkable Rolling Public Keys

When a user enables `Find My network` on an `iPhone`, `MacBook`, `iPad`, or pairs an `AirTag`, the owner device generates an elliptic-curve keypair $(d_0, P_0 = d_0 G)$ on the *`NIST P-224` (`secp224r1`)* curve alongside a random 256-bit initial symmetric secret $SK_0$, syncing $(d_0, SK_0)$ end-to-end encrypted across the owner's `Octagon` `iCloud Keychain` circle ([Chapter 15](15-icloud-hsm-adp.md)) [13, 125, 128]. Why did Apple choose `P-224` (`28 bytes`) instead of `P-256` (`32 bytes`) everywhere else in the OS? Because Bluetooth Low Energy (`BLE 4.0`) legacy non-connectable advertising PDUs carry a strict *31-byte maximum payload* (minus 3 bytes of Apple manufacturer header, leaving *exact room for a 28-byte compressed `P-224` $x$-coordinate*, with 2 extra key/status bits tucked neatly into the randomized 6-byte BLE MAC address header!) [128, 129].

![Figure: Offline Find My zero-knowledge location pipeline showing 15-minute unlinkable P-224 key rotation, finder ECIES GPS encryption, blind SHA-256 server indexing, and owner-only private decryption.](diagrams/17-find-my-p224-beacon-flow.svg)

When the device goes offline (or even powers *off* on modern iPhones, where the Ultra-Wideband and Bluetooth controller continue running in ultra-low-power *Find My After Power Off* reserve mode without booting `XNU`!), the Bluetooth firmware steps an autonomous ratchet every 15 minutes (in near-owner / normal lost state) [128]:

$$SK_i = \text{ANSI-X9.63-KDF}(SK_{i-1}, \text{"update"}), \qquad (u_i, v_i) = \text{KDF}(SK_i, \text{"diversify"}, 72\text{ B})$$

From those two pseudorandom scalars $(u_i, v_i)$ reduced modulo the `P-224` prime group order $q$, the beacon derives its $i$-th rolling keypair:

$$d_i = (d_0 \cdot u_i + v_i) \bmod q, \qquad P_i = d_i G = u_i P_0 + v_i G$$

Look at the algebraic elegance of that affine scalar blinding [128, 129]:
First, the offline Bluetooth microcontroller (or coin-cell `AirTag` MCU) does *not* even need to store the master private scalar $d_0$ in vulnerable accessory RAM! Provisioned only with $(P_0, SK_0)$, the accessory computes $P_i = u_i P_0 + v_i G$ purely from public-point scalar multiplications, so physically decapping a stolen `AirTag` never leaks prior keys before the current $SK_i$ ratchet state! Second, under the Decisional Diffie-Hellman / PRF assumption, consecutive broadcast points $(P_i, P_{i+1})$ (paired with fresh BLE random static MAC addresses derived from $P_i$) are computationally indistinguishable from two completely unrelated random points on `P-224` to every observer lacking $SK_0$ [128].

### Finder ECIES Encryption and Blind Server Lookup

Whenever any participating Apple device in the world (`searchpartyd` on `iOS`, `iPadOS`, or `macOS`) hears an offline Find My BLE advertisement carrying $P_i$, it checks its own recent GPS/Wi-Fi location fix $(lat, lon, acc)$, generates a brand-new ephemeral `P-224` keypair $(e, Q_e = e G)$, and runs Elliptic Curve Integrated Encryption Scheme (`ECIES`) encryption directly to $P_i$ [15, 128]:

$$(K_{\text{enc}}, IV) = \text{KDF}\bigl(\text{ECDH}(e, P_i),\; Q_e \| P_i\bigr), \qquad C_{\text{loc}} = \text{AES-128-GCM}_{K_{\text{enc}}, IV}(lat \| lon \| acc \| \text{status})$$

The Finder device strips its own user identity, authenticates only that it is a genuine Apple device (`BAA`/device certificate over an oblivious/unlinked upload channel), computes the 32-byte lookup index $I_i = \text{SHA-256}(P_i)$, and uploads the tuple $\langle I_i, t_{\text{coarse}}, Q_e, C_{\text{loc}}, \text{tag}_{\text{GCM}} \rangle$ to Apple's `Find My` server [128].

Notice what Apple's cloud database holds: a massive blind key-value table mapping opaque 256-bit hashes $I_i$ to `ECIES` ciphertexts! Apple cannot reverse $I_i \to P_i \to P_0 \to \text{Owner}$, nor compute $\text{ECDH}(e, P_i)$ without $d_i$ [128]. When the *legitimate owner* opens `Find My.app` on their `MacBook` or a borrowed friend's device (`icloud.com/find` requires full 2FA/`Octagon` access to fetch $(d_0, SK_0)$; basic Lost Mode tap lacks decryption keys!), `Find My.app` locally steps $(d_0, SK_0)$ forward over the recent window of 15-minute intervals $i \in [i_{\text{now}} - W, i_{\text{now}}]$, computes the exact set of lookup hashes $\{\text{SHA-256}(P_i)\}$, batch-queries Apple's server for matching blobs, and recovers plaintext coordinates locally via $\text{ECDH}(d_i, Q_e) = d_i e G = e P_i$ [128]!

### Anti-Stalking Countermeasures and IETF DULT

How did Apple modify this protocol so a rogue `AirTag` planted inside a victim's bag triggers an unwanted-tracking warning without destroying anti-theft utility [129]?

![Figure: Architectural evolution balancing offline beacon unlinkability against unwanted-stalking detection across near-owner rotation, separated-owner AirTag windows, and cross-OS IETF DULT alerts.](diagrams/17-dult-anti-tracking-tradeoff.svg)

`AirTag` and `Find My` accessories implement a two-state proximity machine (`Near-Owner` vs. `Separated-From-Owner`) [128, 129]:

While an `AirTag` hears encrypted BLE keep-alives from its paired owner's `iPhone` (`Near-Owner`), it rotates $P_i$ and its BLE MAC rapidly (~15 minutes) so strangers riding the same subway car cannot track the owner. However, once an `AirTag` goes without hearing its owner's phone for an extended window (~15 to 30 minutes, entering `Separated-From-Owner` mode), two anti-stalking defenses activate [129]:
First, its separated-mode rolling key $P_{\text{sep}}$ rotates on a *deliberately slower cadence* (up to ~24 hours, paired with an explicit `Separated` status flag in the BLE payload). That slower window gives a nearby victim's phone (`searchpartyd` on `iOS` or Google Play Services on `Android`) enough consistent observations across distinct geographic clusters (leaving home, driving across town, arriving at a hotel) to determine mathematically that *one specific separated tracker is physically moving with the victim*, surfacing `"AirTag Found Moving With You"`, mapping the path where it accompanied them, allowing the victim to trigger the tag's piezo speaker remotely, and on U1/U2 Ultra-Wideband iPhones guiding them to within centimeters via *Precision Finding*! Second, even if the victim carries *no smartphone at all*, an `AirTag` separated from its owner that detects accelerometer motion automatically emits an audible acoustic chime on a randomized 8-to-24-hour window [129].

To close the cross-ecosystem blind spot where an attacker planted an `AirTag` on an `Android` user (or a Samsung/Chipolo/Pebblebee tag on an `iPhone` user!), Apple and Google jointly authored the *IETF DULT* (`Detecting Unwanted Location Trackers`, `draft-ietf-dult-*`, shipped natively in `iOS 17.5` and `Android 6.0+` in May 2024 and refined through 2026) [129]: standardizing BLE separated-state advertisement bits, tracker metadata lookup (`last 4 digits` of the registered owner's phone number / serial readable via NFC tap for law enforcement!), and acoustic sound-trigger GATT commands across all compliant Bluetooth trackers.

## Platform Forks Across Apple OSes

While `iOS`, `iPadOS`, and `macOS` all act as both Find My *beacons* and *Finder relays*, hardware power topologies introduce important nuances [1, 128]. Recent `iPhones` (`iPhone 11` and `15`/`16`/`17` UWB/BLE power-reserve architectures) keep broadcasting offline `P-224` beacons and `UWB` ranging even *after* battery shutdown or manual power-off (explicitly indicated on the *"iPhone Findable After Power Off"* slider so users entering high-security RF-silent facilities can disable reserve broadcast once via passcode!). `Apple Silicon MacBooks` emit BLE beacons while asleep with the lid closed, while `visionOS` (`Apple Vision Pro`) omits background street-level crowd-relaying when unpowered (detached external battery pack removes all power rails cleanly).

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `OpenHaystack` / Custom ESP32 Spoofed Beacons | 2021-2026 | `Find My` Relay Network | Unauthenticated BLE broadcast input | Because offline beacons cannot run interactive TLS with stranger iPhones over 31-byte BLE ads, custom `ESP32`/`nRF51` boards broadcasting valid `P-224` points get relayed by real iPhones (and can omit `DULT` separated flags!) | Rate-limited `Find My` report queries per Apple Account (`Anisette`/`GSA` attestation) and heuristic unknown-beacon clustering [129] |
| Desoldered Speaker ("Silent AirTag") Stalking Modification | 2022-2026 | Physical `AirTag` hardware | Acoustic chime fallback | Physical stalkers pried open `AirTag` enclosures to disconnect the voice-coil speaker while keeping BLE active | Visual `iOS` + `Android` (`DULT`) push alerts & `UWB` Precision Finding locate muted tags without relying on sound [129] |
| MAC / Key Rotation Boundary Correlation (`Heinrich et al.`) | 2021 | `iOS` / `macOS` | 15-min rotation boundary | Early implementations rotated BLE MAC and `P-224` key out of phase by milliseconds, allowing continuous RF sniffers to stitch adjacent windows | Synchronized atomic MAC + `P-224` payload rotation in Bluetooth firmware [129] |
| Airline / Trusted Item Sharing Scope (`Share Item Location`) | 2024-2026 | `iOS 18.2+` | Temporary 3P location delegation | Users sharing lost-luggage `AirTag` links with airline staff risk over-sharing if links never expire | Enforced automatic link expiration on owner reunion or 7-day hard cap with E2EE link keys [128] |

> **Key idea.**
> Custom `ESP32` microcontrollers (`OpenHaystack`) illustrate an irreducible cryptographic impossibility in passive 31-byte BLE broadcast networks [129]: a stranger's iPhone hearing a random point $P_i \in E(\mathbb{F}_p)$ over the air *cannot distinguish* whether $P_i$ came from a genuine `AirTag` enforcing `DULT` anti-stalking rules or a modified DIY microcontroller keeping its `Near-Owner` bit permanently set! Apple bounds abuse at the *retrieval* end instead (requiring full `GSA` + 2FA Apple Account attestation and strict query rate limits to download reports from Apple's servers) while researching unknown-moving-MAC heuristics on-device [128, 129].

## Verification & Forensic Artifacts

On `macOS`, check whether `Find My Mac` (`fmm`) and offline `searchpartyd` beacon/relay services are active without modifying account settings [104, 128]:

```bash
launchctl print system/com.apple.searchpartyd 2>/dev/null | grep -E 'state =|path =' | head -n 4
nvram -p | grep -E 'fmm-computer-name' | head -n 2 || true
```

Observe `searchpartyd` (`com.apple.icloud.searchpartyd`) beacon and unwanted-tracker (`UT` / `DULT`) evaluation activity in Unified Logging [90, 128, 129]:

```bash
log show --last 30m --predicate 'subsystem == "com.apple.icloud.searchpartyd"' --style compact | tail -n 5
```

Chapters 15 through 17 showed how cryptographic protocols keep backups, post-quantum messages, and location beacons outside Apple's server TCB. In 2024-2026, however, a transformative new workload arrived across `iOS`, `macOS`, and `Xcode`: *autonomous and agentic Large Language Models* reading personal context and invoking real-world tools. [Chapter 18](18-agentic-ai-workload-isolation.md) analyzes how Apple isolates on-device `App Intents`, `Foundation Models` `.onToolCall` guards, `MCP` coding agents, and `Virtualization.framework` micro-VMs.
