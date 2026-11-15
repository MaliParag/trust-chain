# Hardware Key Attestation and Remote Key Provisioning

## Overview

* **Link in the Chain:** Hardware-to-cloud cryptographic proof bridge; serializes `KeyMint` key tags ([Chapter 4](04-keymint-weaver-throttling.md)) and `AVB` Verified Boot state ([Chapter 1](01-bootrom-avb-vbmeta.md)) into X.509 extension `1.3.6.1.4.1.11129.2.1.17`, signed by short-lived certificates provisioned dynamically via `Remote Key Provisioning` (`RKP`).
* **Core Security Invariant:** A remote verifier checking an unrevoked hardware attestation certificate chain over a fresh server-generated `attestationChallenge` receives cryptographic proof that the leaf public key was generated inside genuine `TEE` or `StrongBox` silicon under the exact `RootOfTrust`, patch levels, and package identity recorded in `teeEnforced`.
* **Ecosystem Enforcement Tier:** Full hardware `Key Attestation` and `RKP` operate across both `GREEN` (`verifiedBootState = Verified`, OEM root key) and `YELLOW` (`verifiedBootState = SelfSigned`, `GrapheneOS` `avb_custom_key` digest in `verifiedBootKey`!) locked states; `ORANGE` unlocked state honestly attests `deviceLocked = FALSE` and `verifiedBootState = Unverified`.
* **Trusted Computing Base (TCB):** Per-chip silicon `Unique Device Secret` (`UDS`) and `OpenProfile for DICE` Boot Certificate Chain (`BCC`), `IRemotelyProvisionedComponent` (`KeyMint` / `StrongBox` / `AVF`), userspace `rkpd` Mainline `APEX`, Google `RKP` backend CA + revocation list (`android.googleapis.com/attestation/status`), and the relying party's ASN.1 X.509 verifier.
* **Seam & Handoff:** Eliminates catastrophic factory OEM batch-keybox leaks via `RKP` dynamic rotation and enables sovereign direct verification (`Auditor` / enterprise backends), setting up the direct contrast with `Play Integrity` verdicts and `TrickyStore` root-hiding wars in [Chapter 16](16-play-integrity-keybox-wars.md).

## Threat Model & Ecosystem Constraint

Suppose a mobile banking backend, enterprise Zero Trust Policy Decision Point, or government digital-ID issuer generates a challenge and asks an Android app to register an `ECDSA P-256` client authentication key. Across the Internet, the server sees only bytes over TLS: how can that server distinguish a private key sitting safely inside a `Google Titan M2` `StrongBox` chip on a locked `GREEN` (or `YELLOW` `GrapheneOS`) Pixel 9 running last week's security patch from a Python script running on an attacker's Linux laptop, or an Android emulator running inside a click-farm rack, or a rooted `ORANGE` phone running `Frida` hooks [110, 111]?

Early Android `Key Attestation` (introduced in Android 7.0 / 8.0) solved the cryptographic format by embedding an ASN.1 X.509 extension signed by hardware-provisioned batch keys ("factory keyboxes") injected on Original Design Manufacturer (`ODM`) factory assembly lines [110, 113]. By 2020-2024, that factory-provisioning model suffered a *systemic supply-chain breakdown* across the multi-vendor ecosystem [112, 113, 115]:

First, *factory keybox leaks at ODM lines*: under factory provisioning, Google issued batch attestation private keys (`XML` keyboxes shared across cohorts of `10,000` to `100,000+` handsets to preserve user privacy against per-device tracking) to OEMs and ODMs to flash into `RPMB`/`TEE` during board manufacturing. Repeatedly, poorly secured factory flashing servers or unscrupulous insiders leaked raw `RSA`/`ECDSA` attestation keybox XML files onto underground Telegram channels, giving root-hiding modules (`TrickyStore`, [Chapter 16](16-play-integrity-keybox-wars.md)) real Google-chained private keys to sign fake `GREEN` `RootOfTrust` extensions in software [112, 119]!

Second, *irrevocable bricking risk*: whenever Google revoked a leaked factory batch certificate on `https://android.googleapis.com/attestation/status` [112], `100,000` innocent consumers whose genuine locked phones happened to share that factory batch permanently lost hardware attestation, with *no way to push a new keybox* without re-flashing secure factory storage!

Third, *silent factory provisioning bugs*: if an ODM's `TEE` firmware had a subtle bug in `RootOfTrust` reporting at launch, Google had zero cryptographic visibility into the silicon's internal `DICE` boot chain before signing its attestation intermediate [113, 115]. Android needed to abolish factory-injected attestation private keys entirely in favor of zero-trust, silicon-anchored, short-lived certificate rotation: `Remote Key Provisioning` (`RKP`) [113].

## Architecture & AOSP Implementation

### X.509 Key Attestation Extension (`OID 1.3.6.1.4.1.11129.2.1.17`)

When an application calls `KeyPairGeneratorSpec` / `KeyGenParameterSpec.Builder.setAttestationChallenge(serverNonce)` and invokes `generateKeyPair()`, `keystore2` passes `Tag::ATTESTATION_CHALLENGE` and `Tag::ATTESTATION_APPLICATION_ID` (containing the calling APK's package name, version, and `SHA-256` signing certificate digest from `PackageManager`!) into `IKeyMintDevice` [37, 110]. Inside `TEE` or `StrongBox`, hardware generates the new keypair, constructs a DER-encoded X.509 leaf certificate containing the public key, attaches Google's Android Keystore Attestation extension at OID `1.3.6.1.4.1.11129.2.1.17`, and signs the leaf TBS certificate using a hardware-protected attestation signing key [110]:

```asn1
-- Core schema from AOSP Key Attestation (OID 1.3.6.1.4.1.11129.2.1.17)
KeyDescription ::= SEQUENCE {
  attestationVersion         INTEGER,       -- e.g. 100, 200, 300 (KeyMint 1..3)
  attestationSecurityLevel   SecurityLevel, -- Software(0), TEE(1), StrongBox(2)
  keyMintVersion             INTEGER,
  keyMintSecurityLevel       SecurityLevel,
  attestationChallenge       OCTET STRING,  -- Must match fresh server nonce!
  uniqueId                   OCTET STRING,  -- Empty for non-system apps
  softwareEnforced           AuthorizationList,
  teeEnforced                AuthorizationList
}

RootOfTrust ::= SEQUENCE {
  verifiedBootKey            OCTET STRING,  -- SHA-256 of locked AVB root pubkey!
  deviceLocked               BOOLEAN,       -- TRUE in GREEN & YELLOW; FALSE in ORANGE
  verifiedBootState          VerifiedBootState, -- Verified(0), SelfSigned(1), Unverified(2), Failed(3)
  verifiedBootHash           OCTET STRING   -- ro.boot.vbmeta.digest (SHA-256)
}
```

![Figure: X.509 Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) verification hierarchy and teeEnforced RootOfTrust inspection.](diagrams/15-key-attestation-asn1-tree.svg)

Every relying-party backend engineer must internalize the exact six-step server-side verification algorithm (`android-key-attestation` reference library [111, 112]), because skipping *any single step* creates a trivial bypass:

First, fetch Google's live JSON revocation list (`https://android.googleapis.com/attestation/status`, cached via HTTP `Cache-Control` headers [112]), verify every X.509 signature from the leaf up to the pinned *Google Hardware Attestation Root CA* (`RSA-4096` / `ECDSA P-384`), and confirm *zero* certificate serial numbers (lowercase hex) in the chain appear as `REVOKED` or `SUSPENDED` in the status map!

Second, extract extension `1.3.6.1.4.1.11129.2.1.17` (verifying no conflicting duplicate/unparsed critical extensions exist) and assert *exact byte-for-byte equality* between `attestationChallenge` and the cryptographically random, single-use challenge nonce your server minted seconds ago, preventing replay of an attestation chain captured on a clean phone!

Third, verify `attestationSecurityLevel == TrustedEnvironment (1)` or `StrongBox (2)` (rejecting `Software (0)`, which `keystore2` mints in userspace with a non-hardware test root when hardware attestation is absent or bypassed!).

Fourth, *read security invariants exclusively from `teeEnforced`, never `softwareEnforced`* (save for `ATTESTATION_APPLICATION_ID` on older KeyMint versions before TEE package-info plumbing, cross-checked carefully!) [110, 111]. Inside `teeEnforced`, verify `Tag::ORIGIN == KM_ORIGIN_GENERATED` (`0`, proving the key was born inside silicon rather than imported from outside!), check `Tag::PURPOSE`, and enforce minimum security floors on `osPatchlevel` (`YYYYMM`), `vendorPatchlevel` (`YYYYMMDD`), and `bootPatchlevel` (`YYYYMMDD`).

Fifth, parse `teeEnforced.rootOfTrust` (`Tag 704`): verify `deviceLocked == TRUE`, check `verifiedBootState`, and inspect `verifiedBootKey`! On a `GREEN` stock device, `verifiedBootState == Verified (0)` and `verifiedBootKey` holds the 32-byte `SHA-256` digest of the OEM's root `AVB` key. On a `YELLOW` locked custom-OS device (`GrapheneOS`), `deviceLocked == TRUE`, `verifiedBootState == SelfSigned (1)`, and `verifiedBootKey` holds the exact 32-byte `SHA-256` digest of `GrapheneOS`'s official `avb_custom_key` release signing key (documented publicly by `GrapheneOS` for relying parties and its `Auditor` app [16]!), allowing a high-assurance verifier to accept *both* stock OEM `GREEN` and genuine locked `GrapheneOS` `YELLOW` while rejecting random attacker self-signed builds!

Sixth, verify `attestationApplicationId` (`Tag 709`) contains your exact expected `packageName` and your own `APK Signature Scheme v3` signing certificate `SHA-256` digest, proving a repackaged clone app didn't generate the key on a genuine phone.

### `Remote Key Provisioning` (`RKP`): Silicon `UDS` and `DICE` Replaces Factory Keyboxes

Mandatory starting with Android 13 (`API 33`) launch devices and expanded across `KeyMint`, `StrongBox`, and `AVF` Protected VMs in Android 14-16, `Remote Key Provisioning` (`RKP`, `android.hardware.security.rkp.IRemotelyProvisionedComponent`) eliminates factory attestation keyboxes completely [113, 115]!

![Figure: Remote Key Provisioning (RKP) protocol deriving Boot Certificate Chains from silicon UDS/DICE and rotating short-lived attestation pools via rkpd.](diagrams/15-rkp-provisioning-sequence.svg)

Under `RKP`, *no Google-chained attestation private key is ever flashed on the factory assembly line* [113, 115]. Instead, during chip fabrication (inside the secure SoC foundry or `Titan M2` wafer test, *before* chips ever ship to untrusted ODM assembly plants!), each silicon die fuses or derives a unique 256-bit `Unique Device Secret` (`UDS`) and registers only the corresponding *public* `UDS_Pub` key (`Ed25519` or `ECDSA P-256`/`P-384`) with the silicon vendor / Google `RKP` backend database [47, 113].

Trace how `RKP` dynamically provisions and rotates attestation keys in the field via the `com.android.rkpd` Mainline `APEX` [113, 114, 115]. At every boot, immutable ROM and early firmware execute the `OpenProfile for DICE` derivation ([Chapter 5](05-pkvm-avf-microdroid.md)) from `UDS`, producing a `CBOR`/`COSE_Sign1` (`RFC 9052` [114]) *Boot Certificate Chain* (`BCC`) whose certificates record exact firmware hashes, security version numbers (`SVN`), and debug/normal mode flags up to the `IRemotelyProvisionedComponent` (`KeyMint` TA or `Titan M2` `StrongBox`). Periodically in the background, userspace `rkpd` contacts Google's `RKP` Provisioning Server to fetch a signed `Geek` (*Google Endpoint Encryption Key*, an `ECDH` `COSE_Key` protected against MITM) and a fresh random `challenge`, then calls `IRemotelyProvisionedComponent::generateEcdsaP256KeyPair()` $M$ times to generate a pool of device-bound attestation keypairs whose private scalars never leave `KeyMint`/`StrongBox` [113]. Next, `rkpd` invokes `generateCertificateRequestV2(keysToSign, challenge)`: inside silicon, `IRemotelyProvisionedComponent` authenticates `keysToSign` (`MacedPublicKey`), signs the `CSR` payload + `challenge` using the leaf `DICE` `CDI_Attest` key, attaches the full `DICE` `BCC` rooted in `UDS_Pub`, and encrypts privacy-sensitive silicon identifiers to Google's `Geek` via `COSE_Encrypt` so neither `rkpd` nor network observers can track `UDS_Pub` across apps [113, 114]. Finally, Google's `RKP` backend decrypts the `CSR`, validates `UDS_Pub` against registered silicon foundry manifests, *inspects every `DICE` layer in the `BCC`* (confirming the TEE/StrongBox firmware itself isn't running a vulnerable downgraded or debug build!), and issues a batch of *short-lived X.509 attestation certificates* (expiring every few weeks/months, assigned *one distinct attestation certificate per `(app_uid, key_pool)`* so two apps on the same phone cannot correlate a user via shared intermediate cert serials!) [113, 115].

Think through what `RKP` changed overnight across the ecosystem [115]: there are *zero factory XML keyboxes on the ODM floor to steal*; if a vulnerability is discovered in a specific TEE firmware version (`SVN = 4`), the `RKP` server simply *refuses to renew short-lived attestation certs* until the user installs the OTA updating `SVN >= 5`, healing the device automatically once patched instead of permanently bricking `100,000` phones!

## Vendor, OEM, & Custom-OS Boundaries

Devices launched with Android 12 or earlier (upgraded to Android 14/15 under `GRF`) may still carry legacy factory-provisioned keyboxes alongside hybrid `RKP` support, whereas Android 13+ launch devices (`CDD` Section 9.11.3) mandate `IRemotelyProvisionedComponent` (`RKP`-only mode on Pixel 7/8/9/10+ where zero factory fallback keybox exists!) [2, 113, 115].

What about privacy-focused custom OS users on `GrapheneOS` (`YELLOW`)? First, `GrapheneOS`'s open-source `Auditor` app uses offline/peer-to-peer *direct hardware `Key Attestation`* (pairing an initial Trust-On-First-Use hardware key enrollment with chained `StrongBox` `Titan M2` attestations verifying exact `verifiedBootKey`, `verifiedBootHash`, `osPatchlevel`, and `deviceLocked == TRUE`) to verify device integrity *with zero network connection to Google servers* [16]! Second, for apps needing `RKP`-issued X.509 chains on `GrapheneOS`, `rkpd` proxies only the minimal `COSE` provisioning payload (or allows user network toggles) while per-app certificate assignment prevents cross-app device fingerprinting [16, 113].

## Exploit Chains & Structural Limits

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Server Trusting `softwareEnforced` or Skipping Revocation Check | 2018-2025 | Relying-party backend X.509 verifier | Rooted phone / script sending software-attested or revoked cert chain | Verifier checked `X509TrustManager` validity or read `softwareEnforced` without checking OID `.17` `teeEnforced` + `/attestation/status` | Use canonical `android-key-attestation` verifier; enforce `teeEnforced` + live status list + fresh nonce [111, 112] |
| Leaked ODM Factory Keybox Waves | 2020-2025 | Pre-`RKP` ODM factory provisioning servers | Stolen OEM XML `RSA`/`EC` private keys sold to root-spoofing tools | Shared batch keys injected outside silicon foundry leaked in plaintext | Revoke leaked serials on `/attestation/status` + mandatory `RKP`-only silicon (`UDS`/`DICE`) [112, 113, 115] |
| Replay / Relay ("Farm Proxy") Attestation | 2022-2025 | App protocol omitting session binding to attested key | Attacker relays single registration `attestationChallenge` to real clean phone, then uses session cookie on bot | Server verified key attestation once at signup, then issued bearer JWT unbound to the `KeyMint` private key! | Bind ongoing high-risk requests / `DPoP` tokens via signatures from the attested `KeyMint` key itself [111, 120] |
| Pre-Android 12 `TEE` Patch-Level Spoofing (`boot.img` header edit on `ORANGE`) | 2019-2021 | Legacy `Keymaster` trusting kernel-reported `OS_PATCHLEVEL` | Unlocked `ORANGE` phone booting modified `boot.img` header | `deviceLocked` already flipped `FALSE`, but naive verifiers checked `osPatchlevel` while forgetting `deviceLocked == TRUE`! | Always check `rootOfTrust.deviceLocked == TRUE` AND `verifiedBootState` first [110, 111] |

### Why Direct Key Attestation Beats Opaque Client Scores, Leading to `Play Integrity`

Notice Row 3 in that table (*Session Binding*): hardware `Key Attestation` proves *a specific cryptographic key lives inside genuine locked silicon*. Yet thousands of commercial app developers, reluctant to write X.509 ASN.1 verifiers on their backends, chose instead to call Google's high-level `SafetyNet` and `Play Integrity API`, kicking off the longest-running cat-and-mouse war in mobile security against `Magisk`, `KernelSU`, `TrickyStore`, and leaked OEM keyboxes. [Chapter 16](16-play-integrity-keybox-wars.md) dissects that war from both sides.

## Inspecting via ADB, Fastboot, & Attestation

Verify that the handset exposes `IRemotelyProvisionedComponent` (`RKP` hardware HAL for `default` TEE, `strongbox`, and `avf` virtual machines) and that the `com.android.rkpd` Mainline `APEX` daemon is active:

```bash
adb shell service list | grep -i remotelyprovisioned
adb shell cmd package list packages --apex-only | grep rkpd
```

Fetch and inspect Google's live public *Key Attestation Revocation Status List* from a workstation using `curl` to see exact revoked/suspended factory keybox serials (`REASON: KEY_COMPROMISE` / `CA_COMPROMISE`):

```bash
curl -fsSL https://android.googleapis.com/attestation/status | head -n 25
```

When inspecting a DER/PEM leaf certificate exported from `KeyStore.getCertificateChain(alias)` during backend development, dump raw X.509 extensions including OID `1.3.6.1.4.1.11129.2.1.17` via `openssl`:

```bash
openssl x509 -in attestation_leaf.pem -text -noout | grep -A 6 '1.3.6.1.4.1.11129.2.1.17'
```
