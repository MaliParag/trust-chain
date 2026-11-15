# iMessage PQ3 Post-Quantum Ratcheting and Contact Key Verification

## Overview

* **Link in the Chain:** End-to-end encrypted real-time messaging and verifiable key-directory layer in Part IV; protects interpersonal communication across Apple's untrusted `APNs`/`IDS` cloud transport against both future cryptanalytic quantum computers and compelled key-server equivocation.
* **Core Security Invariant:** Under `PQ3` (`Level 3` messaging security), every `iMessage` conversation combines `NIST P-256` elliptic-curve keys with initial `ML-KEM-768` and periodic `ML-KEM-1024` post-quantum KEM re-encapsulations so neither harvest-now/decrypt-later quantum adversaries nor transient state compromises expose ongoing messages, while `Contact Key Verification` (`KT`) commits `IDS` identity keys into an append-only cryptographic Merkle map audited automatically by user devices.
* **Platform Matrix:** `PQ3` runs automatically by default across all `iMessage` conversations where participants run `iOS 17.4+`, `iPadOS 17.4+`, `macOS 14.4+`, `watchOS 10.4+`, and `visionOS 1.1+` (gracefully negotiating maximum supported protocol version per device pair), while `Contact Key Verification` spans `iOS 17.2+`, `iPadOS 17.2+`, `macOS 14.2+`, `watchOS 10.2+`, and `visionOS` (`PQ3` explicitly excludes legacy `SMS`/`RCS` carrier fallbacks).
* **Trusted Computing Base (TCB):** Per-device `SEP`-protected `IDS` signing and registration keys, `identityservicesd` `PQ3` ratchet state machines (`P-256` + `ML-KEM` + `HKDF-SHA256`), the `KT` append-only verifiable Merkle log and `VRF` commitments, and user devices' continuous background `KT` self-audit daemons (`transparencyd`).
* **Failure Horizon & Handoff:** Endpoint zero-click memory compromises (*FORCEDENTRY*, *DarkSword*) read decrypted `chat.db` messages after `PQ3` unwraps them in `AFU` RAM, and Standard `iCloud Backup` (unless `ADP` from [Chapter 15](15-icloud-hsm-adp.md) is enabled) backs up `Messages` keys to server-accessible storage; hands off zero-knowledge offline beacon cryptography (`Find My`) to [Chapter 17](17-find-my-anti-tracking.md).

## Threat Model & Design Tension

From its 2011 launch (`iOS 5`), `iMessage` encrypted messages end-to-end between devices (`RSA-1280` + `AES-128` initially, upgraded in 2019 to `ECIES` `P-256` with `SEP`-protected device private keys) [1, 6]. By 2023-2024, however, two fundamental Tier 4 cryptographic weaknesses had rendered static device-key `ECIES` messaging obsolete against nation-state threat models [6, 126].

First, static-key `ECIES` lacked both *forward secrecy* (if a physical exploit ever extracted an old device's encryption key, historical ciphertexts decrypted retroactively) and *quantum resistance*: Shor's algorithm running on a future cryptanalytically relevant quantum computer (`CRQC`) solves the Elliptic Curve Discrete Logarithm Problem (`ECDLP`) on `NIST P-256` in polynomial time. A nation-state tapping submarine fiber links today can simply archive encrypted `iMessage` blobs in cheap cold storage (`harvest-now, decrypt-later`) and decrypt every diplomatic, journalistic, and executive conversation a decade later [6]! Even early post-quantum messaging upgrades elsewhere (`Signal`'s September 2023 `PQXDH`, which Apple classifies as *Level 2*) added a lattice Key Encapsulation Mechanism (`KEM`) *only* to the initial session handshake while leaving ongoing Double Ratchet steps purely on classical elliptic curves, meaning if an adversary ever glimpsed ephemeral session RAM once, a future quantum computer could break all subsequent classical DH ratchet steps forever [6]!

Second, every end-to-end encrypted messenger relies on a central public-key directory (in Apple's case, the *Apple Identity Service (`IDS`)* mapping `alice@icloud.com` or `+12065550100` to the list of `P-256` / `ML-KEM` public keys belonging to Alice's enrolled iPhone, iPad, and Mac [126]. What stops a breached `IDS` server) or a sovereign government serving a secret compulsion order on Apple, from executing a *split-view (equivocation) attack*: returning Alice's real keys to Alice while silently inserting an intelligence agency's "ghost iPad" public key into the bundle returned to Bob so every message Bob sends is encrypted to the agency too [126]? Solving both problems at billion-device scale required pairing *PQ3* continuous hybrid ratcheting with *Contact Key Verification (`KT`)* verifiable transparency logs.

## Silicon & System Mechanics

### Apple's Messaging Security Taxonomy and the PQ3 Level-3 Ratchet

In February 2024, Apple SEAR formalized a four-level cryptographic hierarchy for messaging protocols [6]: `Level 0` (no E2EE), `Level 1` (classical E2EE such as legacy `iMessage` or standard `Signal` X3DH + Double Ratchet), `Level 2` (hybrid post-quantum *initial key establishment* only, such as `PQXDH`), and *Level 3 (`PQ3`)*: hybrid post-quantum initial key establishment *plus* ongoing post-quantum ratcheting providing continuous *post-compromise security (`PCS`)* against a quantum-equipped adversary [6].

![Figure: iMessage PQ3 Level-3 protocol architecture combining P-256 + ML-KEM-768 initial hybrid key agreement with per-message symmetric chains and periodic ML-KEM-1024 post-quantum healing ratchets.](diagrams/16-pq3-hybrid-ratchet.svg)

Under `PQ3`, every enrolled Apple device generates and registers a signed prekey bundle on `IDS` (signed by the device's `SEP`-backed `P-256` Identity Key $IK$) containing both classical `P-256` Diffie-Hellman prekeys and post-quantum module-lattice prekeys standardized in `NIST FIPS 203` (`ML-KEM-768` / `Kyber-768`) [6, 13, 127]. Notice why `PQ3` is strictly *hybrid* rather than pure post-quantum: if an unforeseen algebraic breakthrough ever weakened module-lattice cryptography (`ML-KEM`), the session remains at least as secure as classical `NIST P-256`!

When Alice initiates a `PQ3` session to one of Bob's devices, `identityservicesd` executes a 0-RTT hybrid key establishment combining classical `X3DH`-style `P-256` Diffie-Hellman shared secrets ($DH_1 \| DH_2 \| \dots$) with `ML-KEM-768.Encaps`($pk_{\text{Bob}}^{\text{PQ}}$) $\to (ct_0, ss_{\text{PQ},0})$ through `HKDF-SHA256` [6, 15, 127]:

$$(RK_0, CK_0) = \text{HKDF-SHA256}\bigl(\text{salt}_0,\; DH_{\text{classical}} \;\|\; ss_{\text{PQ},0},\; \text{"PQ3-Init"}\bigr)$$

During ongoing conversation, `PQ3` runs three nested ratchets simultaneously [6]:

First, a fast *Symmetric Hash Ratchet* derives a one-time message key $MK_j$ and next chain key $CK_{j+1} = \text{HMAC-SHA256}(CK_j, \text{const})$ for every single message, deleting $MK_j$ and $CK_j$ immediately upon decryption to enforce immediate forward secrecy. Second, whenever conversation direction flips, a classical *Elliptic-Curve Diffie-Hellman (`P-256`) Ratchet* rolls fresh ephemeral scalars into $RK_i$ at compact 32-byte key-header cost. Third (the defining innovation of `Level 3`) whenever a configurable threshold of messages (for example, every ~50 messages or elapsed time/byte budget) passes, `PQ3` triggers a *Periodic Post-Quantum KEM Ratchet* using higher-margin `ML-KEM-1024` (`1,568`-byte public keys and `1,568`-byte ciphertexts, amortized cleanly so everyday short texts do not pay 3 KB headers on every single keystroke!) [6, 127]:

$$(RK_{k+1}, CK_{k+1,0}) = \text{HKDF-SHA256}\bigl(RK_k,\; DH_{\text{step}} \;\|\; ss_{\text{ML-KEM-1024}},\; \text{"PQ3-Heal"}\bigr)$$

Even if an adversary transiently dumps session state $RK_k$ from a device and *also* possesses a future quantum computer capable of breaking every `P-256` $DH_{\text{step}}$, the very next `ML-KEM-1024` ratchet step injects fresh quantum-hard lattice entropy ($ss_{\text{ML-KEM-1024}}$) that locks the attacker back out of all future messages, verified formally by Apple SEAR using automated symbolic (`Tamarin`) and computational (`CryptoVerif`) machine-checked proofs [6]! Because `iMessage` supports multi-device fan-out (Alice has 2 devices, Bob has 3 devices), `identityservicesd` maintains independent pairwise `PQ3` ratchets across active device pairs so compromising a secondary desktop never exposes un-synced device pairs.

### Contact Key Verification (KT): Auditing the IDS Key Directory

Even `Level 3` `PQ3` cryptography fails if `IDS` hands Alice an attacker's `ML-KEM` and `P-256` public keys when she looks up `bob@icloud.com`! *iMessage Contact Key Verification (`KT`, `transparencyd`)* eliminates blind trust in `IDS` by adapting `CONIKS` and `SEEMless` verifiable *Key Transparency* trees to billion-user scale [126].

![Figure: Contact Key Verification (KT) sequence anchoring IDS public-key lookups in an append-only VRF-indexed Merkle map continuously self-audited by recipient devices.](diagrams/16-contact-key-verification-kt.svg)

`KT` maintains a globally consistent, append-only *Verifiable Log-Backed Map* structured as a sparse binary Merkle prefix tree whose signed tree heads (`STH`) advance across monotonic epochs [126]. Simply publishing `alice@icloud.com -> [DeviceKey1, DeviceKey2]` in a public tree like Certificate Transparency (`CT` for TLS websites) would let spammers scrape billions of private phone numbers and device counts! `KT` prevents directory enumeration using a *Verifiable Random Function (`VRF`)*: to map an identifier $u$ (`mailto:bob@icloud.com`), the log server computes $idx = \text{VRF}_{SK_{\text{VRF}}}(u)$ alongside proof $\pi_{\text{VRF}}$, placing a cryptographic commitment to Bob's registered `IDS` keys at pseudorandom leaf position $idx$ [126]:

$$\text{VerifyKT}(u, \text{Keys}_{\text{Bob}}, \pi_{\text{VRF}}, \pi_{\text{Merkle}}, \text{STH}) = 1$$

Three independent checks close the equivocation trap [126]. First, whenever Alice messages Bob, `IDS` must return Bob's keys *plus* $\pi_{\text{VRF}}$ and a Merkle inclusion proof $\pi_{\text{Merkle}}$ chaining to a signed `STH` pinned across gossip and consistency proofs so Apple cannot show one tree to Alice and a forked tree to Bob. Second, *Bob's own iPhone and Mac (`transparencyd`) periodically self-audit Bob's leaf* in the background: if `IDS` ever logged an unauthorized "ghost device" key under `bob@icloud.com` to satisfy Alice's inclusion check, Bob's iPhone compares the logged key list against his `SEP`-trusted `Octagon` account circle ([Chapter 15](15-icloud-hsm-adp.md)), spots the unknown key immediately, and flashes a prominent tampering alert inside `Messages` and `Settings`. Third, high-risk users (`KT` explicitly enabled on both ends) can compare a short *8-digit Public Verification Code* over a phone call or in person (or paste their static `APVR...` verification URI into a Contact card), mathematically pinning Bob's exact identity root against even first-contact (`TOFU`) interception before background self-audit completes [126].

Notice why coupling `KT` specifically with `Octagon` ([Chapter 15](15-icloud-hsm-adp.md)) solves a usability failure that plagued first-generation academic Key Transparency designs [125, 126]. In standalone messengers lacking a hardware-attested multi-device circle, whenever a user legitimately bought a new laptop or reinstalled an app, peers received false-positive "safety number changed!" warnings that trained users to click through key-change alerts blindly. In Apple's architecture, `IDS` signs new device registrations with the user's `Octagon` peer-signing key inside `SEP`: `transparencyd` distinguishes an *authorized* device addition signed by the user's own `SEP` circle from an *unauthenticated* server-injected key, suppressing false alarms during normal hardware upgrades while halting immediately on genuine directory anomalies [126].

## Platform Forks Across Apple OSes

Both `PQ3` and `KT` (`transparencyd`) execute identically across `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS` [6, 126]. Two crucial operational forks govern mixed-device conversations. First, within `iMessage`, if Bob still owns an unretired legacy `iPad` running `iOS 15` (`Level 1` E2EE) alongside his `iPhone 17` running `iOS 26` (`PQ3` `Level 3`), Alice's pairwise fan-out encrypts Bob's `iPhone 17` copy with `PQ3` while falling back to classical `ECIES` *for that legacy iPad copy*, meaning full post-quantum confidentiality and `KT` verification require purging pre-`17.2`/`17.4` devices from the `Apple Account` circle [6, 126]! Second, green-bubble `SMS` and carrier `RCS` chats bypass `IDS`, `PQ3`, and `KT` completely, routing through telecom carrier relays outside Apple's E2EE trust chain.

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| Pre-`PQ3` Static `ECIES` Harvest-Now / Decrypt-Later Risk | 2011-2023 | Legacy `iMessage` (`< iOS 17.4`) | Long-term quantum confidentiality | Static per-device `P-256` encryption keys lacked both symmetric/DH ratchets and post-quantum KEMs | Deployed `PQ3` (`Feb 2024+`): per-message symmetric ratchet + classical DH + periodic `ML-KEM-1024` [6] |
| Legacy Un-Audited `IDS` Directory (`TOFU` Blind Trust) | 2011-2023 | `IDS` (`iMessage` & `FaceTime`) | Compelled or breached directory server | Clients accepted whatever `P-256` device list `IDS` returned without verifiable append-only Merkle proofs | Deployed `Contact Key Verification` (`KT`, `Dec 2023+`) with `VRF` Merkle maps & `Octagon` self-auditing [126] |
| Legacy Secondary Device Downgrade in Multi-Device Fan-Out | Operational | Multi-device `Apple Account`s | Account-wide `PQ3` / `KT` floor | Keeping an old `macOS 12` / `iOS 15` device signed into `iMessage` forces `Level 1` copy fan-out to that device | `KT` requires all signed-in devices to support `KT` (`17.2+`/`14.2+`) and alerts on incompatible devices [6, 126] |
| Post-Decryption `AFU` Endpoint Spyware (*FORCEDENTRY*, *DarkSword*) | 2021-2026 | All OSes | Post-ratchet plaintext in `chat.db` | Once `identityservicesd` decrypts a `PQ3` message and writes it to `Class C` `sms.db`/`chat.db`, an `AFU` endpoint 0-day reads plaintext directly | Pair `PQ3` + `KT` with `Lockdown Mode` ([Chapter 10](10-apfs-data-protection.md)), `ADP` ([Chapter 15](15-icloud-hsm-adp.md)), and `A19`/`M5` `MIE` (`EMTE`) [5, 99, 124] |

> **Warning.**
> `PQ3` and `Contact Key Verification` make network wiretapping and silent `IDS` server key injection mathematically intractable, yet *endpoint security always bounds transport cryptography*: if `iCloud Backup` is left on *Standard* protection rather than `ADP` ([Chapter 15](15-icloud-hsm-adp.md)), decrypted messages re-upload into server-escrowed backups; and if a mercenary chain compromises the phone in `AFU`, it reads `sms.db` after `PQ3` finishes its job [6, 124]!

## Verification & Forensic Artifacts

On `macOS`, inspect `KT` (`transparencyd`) verification state and `IDS` (`identityservicesd`) `PQ3` session/ratchet logs via Unified Logging without exposing message contents [6, 90, 126]:

```bash
log show --last 1h --predicate 'subsystem == "com.apple.Transparency"' --style compact | tail -n 5
log show --last 30m --predicate 'subsystem == "com.apple.ids"' --style compact | tail -n 5
```

Check whether the `transparencyd` Contact Key Verification daemon is active in the current user LaunchAgent domain [126]:

```bash
launchctl print "gui/$(id -u)/com.apple.transparencyd" 2>/dev/null | grep -E 'state =|path =' | head -n 4
```

Expected output confirming live background `KT` Merkle self-auditing:

```text
	path = /System/Library/LaunchAgents/com.apple.transparencyd.plist
	state = running
```

In `Messages` and `CloudKit`, the communicating devices both have active internet connections. What if a stolen `MacBook` is asleep in a backpack with Wi-Fi disconnected, or an `AirTag` has no cellular modem at all? [Chapter 17](17-find-my-anti-tracking.md) examines how Apple's offline `Find My` network turns one billion stranger iPhones into a zero-knowledge location relay, and where mathematical unlinkability collides with physical anti-stalking safety.
