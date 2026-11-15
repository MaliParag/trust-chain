# Hardware Key Attestation and Remote Key Provisioning

## Overview

* **Link in the Chain:** Silicon-to-cloud cryptographic proof bridge; serializes `KeyMint` `hardwareEnforced` key policies ([Chapter 4](04-keymint-weaver-throttling.md)), `AVB` `RootOfTrust` ([Chapter 1](01-bootrom-avb-vbmeta.md)), and package signing digests into X.509 extension `1.3.6.1.4.1.11129.2.1.17`, signed by short-lived per-app certificates dynamically rotated via `Remote Key Provisioning` (`RKP`).
* **Core Security Invariant:** A remote relying party validating an X.509 attestation chain (`BasicConstraints cA=FALSE` on leaf, unrevoked against `/attestation/status`, anchored to Google's `RSA-4096` and 2026 `ECDSA P-384` roots) over a single-use server `attestationChallenge` obtains mathematical proof that the leaf private key was generated inside genuine `TEE` or `StrongBox` silicon under the exact boot state, patch levels, and APK identity in `hardwareEnforced`.
* **Ecosystem Enforcement Tier:** Hardware `Key Attestation` and `RKP` operate identically across `GREEN` (`verifiedBootState = Verified`, OEM root key) and `YELLOW` (`verifiedBootState = SelfSigned`, `GrapheneOS` `avb_custom_key` digest in `verifiedBootKey`!) locked states; `ORANGE` unlocked state truthfully reports `deviceLocked = FALSE` and `verifiedBootState = Unverified`.
* **Trusted Computing Base (TCB):** Wafer-fused 256-bit `Unique Device Secret` (`UDS`) and `OpenProfile for DICE` Boot Certificate Chain (`DiceCertChain`), `IRemotelyProvisionedComponent` v3 (`KeyMint`, `StrongBox`, `rkp-vm`), Mainline `com.android.rkpd` `APEX`, Google `RKP` Provisioning CA + `OID .30` metadata, and the relying party's RFC 5280 + ASN.1 verifier (`android/keyattestation`).
* **Seam & Handoff:** Abolishes leaked ODM factory `keybox.xml` batch credentials via `RKP` silicon `DICE` chains and enables sovereign zero-cloud verification (`Auditor` and `eIDAS` wallets), setting up the architectural contrast with `Play Integrity` verdicts and `TrickyStore` root-hiding wars in [Chapter 16](16-play-integrity-keybox-wars.md).

## Threat Model & Ecosystem Constraint

When a mobile banking server, enterprise Zero Trust Policy Decision Point, or government Mobile Driver's License (`ISO/IEC 18013-5` `mDL`) issuer receives a TLS registration request presenting a fresh `ECDSA NIST P-256` (or post-quantum `ML-DSA`) public key, raw TLS packets carry zero physical provenance [29, 426, 427]. Without hardware-rooted attestation, the backend cannot tell whether that private key lives inside a Common Criteria `EAL4+`/`AVA_VAN.5` `Google Titan M2` `StrongBox` processor on a locked `GREEN` or `YELLOW` smartphone, inside a Python script running on a headless cloud VM farm, or inside an `ORANGE` unlocked handset instrumented with `Frida` [427, 428].

Android 7.0 (`Keymaster 2`) and Android 8.0 (`Keymaster 3`) introduced X.509 Hardware `Key Attestation` and `Device ID Attestation` to bridge silicon state to remote verifiers, initially anchoring trust in *factory-provisioned batch attestation keys* ("keyboxes") injected on Original Design Manufacturer (`ODM`) assembly lines [29, 429, 430]. Between 2020 and 2025, that factory-keybox provisioning model suffered a systemic ecosystem failure across three coupled fault lines [30, 108, 109, 428, 430]:

First was *ODM supply-chain `keybox.xml` leakage and legacy `TEE` extraction*. Because burning a globally unique, static X.509 signing certificate into every phone would let any two colluding apps track users permanently across factory resets, Google issued shared RSA and ECDSA attestation keypairs (`keybox.xml` files bundling a raw PEM `<PrivateKey>` and `<CertificateChain>` shared across cohorts of `10,000` to `100,000+` devices per SKU) to OEMs and ODMs to flash into secure storage during board manufacturing [108, 430]. Because those private keys had to exist outside the target phone's silicon before flashing, insecure factory provisioning servers, contractor test benches, and legacy `TEE` vulnerabilities (such as MediaTek `CVE-2024-20017` [431]) leaked hundreds of genuine Google-chained `keybox.xml` files onto underground Telegram resale markets, allowing root-spoofing frameworks (`TrickyStore`, [Chapter 16](16-play-integrity-keybox-wars.md)) to forge `GREEN` `StrongBox` leaf certificates entirely in software [108, 428, 430, 431]!

Second was *the revocation collateral-damage trap*. Whenever Google added a leaked batch intermediate or attestation key serial to its public revocation list (`https://android.googleapis.com/attestation/status` [108]), all `100,000` unrooted consumers whose legitimate locked handsets shared that factory batch risked losing banking, wallet, and enterprise access overnight, because pre-`RKP` devices possessed *no over-the-air mechanism* to replace a revoked factory keybox without physically returning the motherboard to an RMA line [30, 109, 430]!

Third were *catastrophic relying-party X.509 parser bugs*. At Black Hat USA 2025 (*Breaking Chains: Hacking Android Key Attestation* [428]), Amazon security researcher Alex Gonzalez demonstrated that thousands of production anti-bot backends using Google's unversioned 2016 sample verifier failed to enforce `RFC 5280` `BasicConstraints` (`cA = FALSE`) and relied on client-supplied certificate array ordering! An attacker holding *any* uncompromised Android phone could ask its genuine `TEE` to generate a standard user signing key, use that `TEE` user key to sign a *child forged X.509 certificate* carrying an off-device OpenSSL public key and a fake `StrongBox` `OID .17` extension, append or reorder the chain, and fool the backend into trusting a laptop Python script as hardware-backed silicon (remediating the bug slashed live bot traffic on the target production service from `30%` down to `2%`) [428, 432]!

## Architecture & AOSP Implementation

### X.509 Extensions `OID 1.3.6.1.4.1.11129.2.1.17` and `OID .30` (`KeyMint 1.0-5.0`)

When an application invokes `KeyPairGenerator` for `"AndroidKeyStore"` with `KeyGenParameterSpec.Builder.setAttestationChallenge(serverNonce)`, `keystore2` queries `PackageManager` for the caller's `UID` package list and `APK Signature Scheme v3` signing certificate `SHA-256` digests, packs them into `Tag::ATTESTATION_APPLICATION_ID` (`Tag 709`), and invokes `IKeyMintDevice::generateKey()` followed by `attestKey()` inside `TEE` or `StrongBox` [29, 433]. The secure hardware generates the asymmetric keypair internally, constructs an `RFC 5280` X.509 v3 leaf certificate (`serialNumber = 1`, `CN = "Android Keystore Key"`, `KeyUsage = digitalSignature` with `cA = FALSE`), embeds the DER-encoded `KeyDescription` ASN.1 `SEQUENCE` at OID `1.3.6.1.4.1.11129.2.1.17`, and signs the leaf TBS certificate with a provisioned attestation key [29, 432, 433]:

```asn1
-- Android Key Attestation Schema v500 (KeyMint 5.0 / Android 17, OID 1.3.6.1.4.1.11129.2.1.17)
KeyDescription ::= SEQUENCE {
  attestationVersion         INTEGER,       -- 100..400 (KeyMint 1..4), 500 (KeyMint 5.0)
  attestationSecurityLevel   SecurityLevel, -- Software(0), TrustedEnvironment(1), StrongBox(2)
  keyMintVersion             INTEGER,       -- Matches KeyMint HAL version (e.g. 400, 500)
  keyMintSecurityLevel       SecurityLevel,
  attestationChallenge       OCTET STRING,  -- Single-use server-generated random nonce!
  uniqueId                   OCTET STRING,  -- Empty for third-party apps; 30-day HMAC for system
  softwareEnforced           AuthorizationList, -- Untrusted HLOS claims (keystore2)
  hardwareEnforced           AuthorizationList  -- Authoritative TEE / StrongBox claims!
}

RootOfTrust ::= SEQUENCE {                  -- Context tag [704] EXPLICIT inside hardwareEnforced
  verifiedBootKey            OCTET STRING,  -- SHA-256 of locked AVB root pubkey (zeroes in ORANGE)
  deviceLocked               BOOLEAN,       -- TRUE in GREEN & YELLOW; FALSE in ORANGE
  verifiedBootState          VerifiedBootState, -- Verified(0), SelfSigned(1), Unverified(2), Failed(3)
  verifiedBootHash           OCTET STRING   -- SHA-256 VBMeta aggregate digest (ro.boot.vbmeta.digest)
}

AttestationApplicationId ::= SEQUENCE {     -- DER inside OCTET STRING at tag [709]
  package_infos              SET OF AttestationPackageInfo, -- { package_name, version }
  signature_digests          SET OF OCTET STRING            -- SHA-256(PackageInfo.signatures[i])
}
```

*(Note the schema evolution across `KeyMint` releases [433]: versions `100` through `300` covered `KeyMint 1.0-3.0` adding second-IMEI tag `[723]`; version `400` (`KeyMint 4.0`, Android 15/16) added `moduleHash [724]` committing a cryptographic hash of installed Mainline `APEX` module versions into `hardwareEnforced`; and version `500` (`KeyMint 5.0`, Android 17) added `mlDsaVariant [11]` supporting post-quantum `ML-DSA` attested keys! Notice also how `uniqueId` in `KeyDescription` preserves privacy: for normal third-party apps `uniqueId` is always empty (`0` bytes), and even when privileged system apps request `Tag::INCLUDE_UNIQUE_ID`, `KeyMint` computes a 128-bit truncated `HMAC-SHA256(T || C || R, HBK)` where temporal counter $T = \lfloor \text{CREATION\_DATETIME} / 2{,}592{,}000{,}000 \rfloor$ rotates automatically every 30 days and `C` scopes the value to the caller's `APPLICATION_ID` [29, 433]!)*

On `RKP`-provisioned devices, Google's provisioning CA also attaches a second X.509 extension on the *attestation signing certificate* at OID `1.3.6.1.4.1.11129.2.1.30` (*Provisioning Information* [434]), containing a compact CBOR map `{ 1 : certs_issued, 4 : validated_attested_entity, ? 6 : is_lost_device }`. If a single physical phone in a click-farm rack mints `50,000` fresh attestation chains in 30 days to register fake accounts, `certs_issued` exposes the velocity anomaly immediately without revealing a persistent hardware serial number, while `validated_attested_entity` (`"STRONG_BOX"` vs. `"TEE"`) conveys silicon-vendor-vouched enclave provenance and `is_lost_device` flags stolen phones [428, 434]!

![Figure: X.509 Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) verification hierarchy and teeEnforced RootOfTrust inspection.](diagrams/15-key-attestation-asn1-tree.svg)

To defeat every PKI and chain-extension flaw cataloged by Gonzalez [428], production backend verifiers (using Google's maintained `android/keyattestation` Rust/Java library [435] or `WebAuthn4J` rather than the deprecated 2016 sample code) must execute seven deterministic checks [108, 426, 428, 432, 436]:

First, *canonicalize chain order and enforce `RFC 5280` `BasicConstraints`*: build a strict PKIX path from a pinned trust store holding *both* Google's legacy `RSA-4096` Hardware Attestation Root CA (used by pre-`RKP` factory devices) and Google's *2026 `ECDSA P-384` KeyMint Root CA* (introduced February 2026 and used *exclusively* by all `RKP`-enabled devices since April 10, 2026 [430, 436]!). Verify every cryptographic signature down to the target leaf, enforce `BasicConstraints: cA == TRUE` and `KeyUsage: keyCertSign` on every intermediate CA, and assert that the target leaf certificate carries `cA == FALSE` (and is the *sole* certificate in the path carrying `OID .17`), closing the Black Hat 2025 appended-leaf bypass completely [428, 432].

Second, *enforce live CRL status*: fetch `https://android.googleapis.com/attestation/status` (honoring HTTP `Cache-Control` headers) and reject the entire chain if *any* certificate's lowercase hexadecimal serial number appears as `REVOKED` or `SUSPENDED` [108, 428].

Third, *assert challenge freshness*: confirm byte-for-byte equality between `attestationChallenge` and a single-use, cryptographically random ($\ge 16$-byte) nonce generated by your backend within a tight TTL window [426].

Fourth, *require hardware backing*: assert `attestationSecurityLevel == TrustedEnvironment (1)` or `StrongBox (2)` and `keyMintSecurityLevel == attestationSecurityLevel`, rejecting `Software (0)` [29, 433].

Fifth, *parse security invariants strictly from `hardwareEnforced`*: ignore claims inside `softwareEnforced` (save for `attestationApplicationId [709]`, which `keystore2` measures in `system_server` under a locked `AVB` OS!). Inside `hardwareEnforced`, verify `origin [702] == KM_ORIGIN_GENERATED (0)` (rejecting `IMPORTED`), verify `purpose [1]`, and check minimum acceptable security floors on `osPatchLevel [706]`, `vendorPatchLevel [718]`, `bootPatchLevel [719]`, and `moduleHash [724]` [29, 426, 433].

Sixth, *validate `hardwareEnforced.rootOfTrust [704]`*: require `deviceLocked == TRUE`. On stock OEM `GREEN` builds, `verifiedBootState == Verified (0)` and `verifiedBootKey` holds the 32-byte `SHA-256` digest of the OEM's fused `AVB` root public key. On locked `GrapheneOS` `YELLOW` builds, `deviceLocked == TRUE`, `verifiedBootState == SelfSigned (1)`, and `verifiedBootKey` equals the published 32-byte `SHA-256` digest of `GrapheneOS`'s official release `avb_custom_key` (`0fb9...` per Pixel generation [20, 437]), allowing verifiers to admit both stock `GREEN` and genuine locked `GrapheneOS` `YELLOW` while rejecting unlocked `ORANGE` (`deviceLocked == FALSE`, `verifiedBootKey == 0x00..00`) [20, 433]!

Seventh, *pin `AttestationApplicationId [709]` and bind ongoing sessions*: confirm `package_infos` names your exact `packageName` and `signature_digests` matches your production `APK Signature Scheme v3` cert `SHA-256`, then require subsequent high-risk API requests to carry `RFC 9449` Demonstrating Proof of Possession (`DPoP`) signatures produced by that attested private key so click-farms cannot proxy a single registration challenge to a clean phone and export a bearer cookie to a bot [426, 433, 438]!

### Device ID Attestation and Tamper-Evident `HMAC(HBK, ID)` Storage

Consumer apps must never track hardware serial numbers or cellular `IMEI`s, so `KeyMint` rejects `Tag::ATTESTATION_ID_*` requests from normal third-party UIDs. For enterprise `Zero-Touch Enrollment` ([Chapter 17](17-android-enterprise.md)) and carrier eSIM provisioning, however, Android 8.0+ provides *Device ID Attestation* (`Tag::ATTESTATION_ID_BRAND [710]` through `ATTESTATION_ID_SECOND_IMEI [723]`), gated strictly by `READ_PRIVILEGED_PHONE_STATE` or `DevicePolicyManager.generateKeyPair()` (`ID_TYPE_SERIAL`, `ID_TYPE_IMEI`, `ID_TYPE_MEID`) on managed devices [429, 433, 439].

Look at the elegant cryptographic storage construction specified by AOSP inside `TEE`/`StrongBox` [429]. Rather than storing raw `IMEI` strings in plaintext inside factory flash, factory provisioning derives a dedicated, single-purpose 128-bit+ Hardware-Bound Key (`HBK`) from silicon fuses and writes only a MACed digest blob $S$:

$$D = \text{HMAC-SHA256}(\text{HBK}, \text{ID}_1) \parallel \dots \parallel \text{HMAC-SHA256}(\text{HBK}, \text{ID}_n), \qquad S = D \parallel \text{HMAC-SHA256}(\text{HBK}, D)$$

When an authorized enterprise `DPC` requests ID attestation, the caller passes the expected `IMEI`/`Serial` UTF-8 strings in `attestParams`; the `TEE` validates `HMAC(HBK, D)` in *strict constant time* across all $n$ slots (returning `ErrorCode::CANNOT_ATTEST_IDS` on any tampering or mismatch!) before copying the verified IDs into `hardwareEnforced` [429]. Moreover, invoking `destroyAttestationIds()` permanently erases $S$ so neither factory reset nor re-locking can resurrect hardware ID attestation without secure factory RMA re-initialization [429].

### `Remote Key Provisioning` (`RKP`): Silicon `UDS`, `OpenProfile for DICE`, and `CSR` v3

To eradicate ODM factory `keybox.xml` leaks permanently, Android 12 introduced, Android 13 mandated (`IRemotelyProvisionedComponent` v2), Android 14 streamlined (`v3` + updatable `com.android.rkpd` Mainline `APEX`), and Android 16+ made *exclusive* (`RKP-only`, zero factory keybox fallback on launch devices!) *Remote Key Provisioning* (`RKP`, `hardware/interfaces/security/rkp/` [30, 436, 440, 441, 442, 443]):

![Figure: Remote Key Provisioning (RKP) protocol deriving Boot Certificate Chains from silicon UDS/DICE and rotating short-lived attestation pools via rkpd.](diagrams/15-rkp-provisioning-sequence.svg)

Under `RKP`, *zero Google-chained attestation private keys ever touch an ODM smartphone factory* [30, 430, 440]. Instead, trust begins inside the semiconductor wafer foundry (or discrete `Titan M2` / `Knox Vault` chip fab) *months before* chips ship to board assemblers: each silicon die fuses a random 256-bit `Unique Device Secret` (`UDS`) into One-Time Programmable (`OTP`) memory, derives an asymmetric root identity keypair (`UDS_Pub` / `UDS_Priv` using `Ed25519`, `ECDSA P-256`, or `ECDSA P-384`), and either uploads *only* the public `UDS_Pub` to the provisioning registry or signs `UDS_Pub` under an air-gapped SoC-vendor HSM `UdsCertChain` [33, 440, 441, 444].

At every power-on, immutable Boot ROM reads `UDS`, derives the Stage-0 Compound Device Identifier (`CDI`), *engages a hardware latch blocking all read access to `UDS` until next cold reset*, and executes the `OpenProfile for DICE` layered derivation ([Chapter 5](05-pkvm-avf-microdroid.md)) up to every `IRemotelyProvisionedComponent` (`IRPC`: `default` TEE `KeyMint`, `strongbox` SE, and `avf` `pKVM`'s `rkp-vm` service VM!) [33, 441, 444, 445]. Each boot stage $k$ hashes its own secret $\text{CDI}_{k-1}$ with the next stage's code hash, authority key hash, configuration descriptor, and mode to derive $\text{CDI}_k$, signing a `CBOR Web Token` (`RFC 8392` `CWT` [446]) wrapped in an untagged `COSE_Sign1` (`RFC 9052` [99]) certificate (`DiceChainEntry` in `generateCertificateRequestV2.cddl` [444]):

```cddl
; AOSP RKP v3 CSR & OpenProfile for DICE Schema (generateCertificateRequestV2.cddl)
AuthenticatedRequest<CsrPayload> = [
  version: 1,
  UdsCerts,          ; Optional SoC vendor X.509 chain vouching for UDS_Pub
  DiceCertChain,     ; [ UDS_Pub (COSE_Key), + DiceChainEntry (BL1 -> ... -> KeyMint/StrongBox) ]
  SignedData<[ challenge: bstr .size (0..64), bstr .cbor CsrPayload ]> ; COSE_Sign1 by CDI_Leaf_Priv
]

DiceChainEntryPayload = {              ; CWT [RFC 8392] claims per boot stage
  1 : tstr,  2 : tstr,                 ; Issuer, Subject
  -4670554 : "android.16",             ; DICE Profile Name ("android.14" / "android.15" / "android.16")
  -4670545 : bstr,                     ; Code Hash (SHA-256/384/512 of next firmware stage)
  -4670548 : bstr .cbor {              ; ConfigurationDescriptor:
    ? -70002 : tstr,                   ;   Component name (e.g. "trusty", "keymint", "rkp-vm")
    ? -70003 : int / tstr,             ;   Component version
    ? -70004 : null,                   ;   Resettable (rotates across factory reset if present)
    ? -70005 : uint,                   ;   Security Version Number (SVN - monotonic patch counter!)
    ? -70006 : null                    ;   RKP VM marker (identifies AVF pKVM guest chain)
  },
  -4670549 : bstr,                     ; Authority Hash (firmware signing key digest)
  -4670551 : bstr                      ; Mode (MUST equal 0x01 "normal" for production certs!)
}
```

![Figure: OpenProfile for DICE CBOR/COSE_Sign1 Boot Certificate Chain (UDS_Pub to CDI_Leaf_Priv) and RKP v3 AuthenticatedRequest CSR provisioning under Google's 2026 ECDSA P-384 Root CA.](diagrams/15-extra-dice-bcc-cbor-rkp-flow.svg)

Compare how `RKP` evolved from `v1/v2` to `v3` (`CHANGELOG.md` [442]) and how `com.android.rkpd` (`packages/modules/RemoteKeyProvisioning/` [443]) manages live certificate pools:

| Provisioning Era | HAL / Method | CSR & Silicon Root Format | Revocation & Privacy Model |
|---|---|---|---|
| Factory Keybox (`Android 7-12`) | Factory ODM flash (`keybox.xml`) | Long-lived RSA/EC batch private key shared across `10k-100k+` phones [430] | Coarse CRL serial ban bricks innocent batchmates permanently [108, 430] |
| `RKP` v1 / v2 (`Android 12-13`) | `IRPC::generateCertificateRequest` | `ProtectedData` (`COSE_Encrypt` under Google `EEK`) + `COSE_Mac0` `MacedKeysToSign` [440, 441] | Split-server identity/cert blind; short-lived per-`(UID, pool)` certs [440] |
| `RKP` v3 + `P-384` Root (`Android 14-17`) | `IRPC::generateCertificateRequestV2` | `testMode` & `EEK` removed; single `COSE_Sign1` `AuthenticatedRequest<CsrPayload>` + `SHA-384`/`P-384` `DICE` [436, 442, 444] | Per-die `UDS_Pub` + per-stage `SVN` (`-70005`) gating; instant post-OTA self-healing [441, 444] |

Why did `RKP` v3 (`Android 14+`) remove `ProtectedData` and the `Endpoint Encryption Key` (`EEK`) used in `v1/v2` [441, 442]? In `v1/v2`, `KeyMint` encrypted the `BCC` to Google's `EEK` inside `TEE` so userspace could not read `UDS_Pub`; in `v3`, Android isolated `DICE` chain access exclusively inside the privileged `rkpd` system daemon (`SELinux`-barred from all apps) over TLS 1.3 while retaining strict backend separation between the `UDS_Pub` validator and the certificate issuer, collapsing a complex multi-layer `COSE_Encrypt` + `COSE_Mac0` + `COSE_Sign1` dance into a single auditable `COSE_Sign1` `AuthenticatedRequest` [441, 442, 444]!

Appreciate the three game-changing security properties `RKP` achieves in the field [30, 441, 444, 445]. First, *per-application non-correlatability*: `rkpd` maintains a pool of `MacedPublicKey` `ECDSA P-256` keys inside `KeyMint`/`StrongBox` and assigns *a distinct short-lived RKP attestation certificate to each `(app_uid, key)`*, so two apps on the same handset never observe a shared batch intermediate serial! Second, *surgical `SVN` gating and automatic OTA healing*: if a vulnerability (`CVE-2024-20017`-style [431]) is discovered inside `TEE` firmware `SVN = 3`, updating that `TEE` image via OTA changes its `Code Hash (-4670545)` and increments `SVN (-70005)` to `4`, which *mathematically alters every downstream `CDI` private key* via `DICE` one-way hashing (`no compromised SVN = 3 implant can predict post-update SVN = 4 CDI keys!` [441]). Google's `RKP` backend simply pauses issuing new short-lived certificates to chains presenting `SVN <= 3` (or `Mode != normal`) and resumes issuing fresh certificates the instant the user installs the security OTA! Third, *hypervisor VM attestation (`CertificateType = "rkp-vm"`)*: because `IRemotelyProvisionedComponent` is decoupled from `KeyMint`, Android 14-17 extend `RKP` directly into the Android Virtualization Framework (`AVF`, [Chapter 5](05-pkvm-avf-microdroid.md))! Protected Virtual Machines booted under `pKVM` and `pvmfw` inherit their own `OpenProfile for DICE` chain marked with configuration tag `-70006` (`RKP VM marker`), allowing a dedicated `rkp-vm` guest to obtain Google-signed `RKP` certificates and attest isolated `Microdroid` AI or DRM workloads without trusting either the host `EL1` Linux kernel or a monolithic vendor `TEE` [444, 445]!

## Vendor, OEM, & Custom-OS Boundaries

Under `CDD` Section 9.11.3 and Google's provisioning roadmap, devices launching with Android 13+ implement `IRemotelyProvisionedComponent`, and devices launching with Android 16+ operate in *strict `RKP`-only mode* with zero factory attestation keyboxes provisioned at manufacturing [30, 436]. Furthermore, on April 10, 2026, Google completed migrating all `RKP`-enabled devices onto its new `ECDSA P-384` KeyMint Root CA, requiring every relying-party verifier to pin *both* the legacy `RSA-4096` root (for older non-`RKP` phones) and the `ECDSA P-384` root [430, 436]. For national electronic IDs (`eIDAS 2.0`) and mobile driver's licenses (`mDL`), Google's *Android Digital Credential Alliance* (evolved in September 2026 from *Android Ready SE*) pairs `RKP` hardware attestation with `StrongBox` applets certified to Common Criteria `EAL4+` with `AVA_VAN.5` physical side-channel resistance [427].

On `GrapheneOS` (`YELLOW` locked Pixel), hardware attestation empowers user sovereignty without forcing blind reliance on Google cloud verdicts [20, 437]. First, `GrapheneOS`'s open-source `Auditor` app (`attestation.app`) performs *direct hardware `Key Attestation`* (`Titan M2` `StrongBox` initial Trust-On-First-Use key pinning followed by periodic signed `attestationChallenge` QR handshakes checking `deviceLocked == TRUE`, `verifiedBootState == SelfSigned`, `verifiedBootKey == GrapheneOS avb_custom_key`, `osPatchLevel`, and `origin == GENERATED`), detecting persistent boot/OS tampering completely offline or peer-to-peer between two phones [20, 437]! Second, when apps on `GrapheneOS` request `RKP`-backed X.509 chains, `rkpd` fetches short-lived per-app certificates over minimal `COSE` requests (with user-controllable network toggles) while preserving `YELLOW` `RootOfTrust` honesty [20, 443].

## Exploit Chains & Structural Limits

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Leaf-Appended Chain Bypass (`Black Hat USA '25`) [428] | 2016-2025 | Backend X.509 verifier (`android-key-attestation`) | `TEE` user key signs forged child leaf cert + reversed chain order | Legacy library skipped `BasicConstraints cA=FALSE` & assumed leaf-first array order | Enforce `RFC 5280` PKIX `cA=FALSE` on leaf + migrate to `android/keyattestation` [428, 432, 435] |
| Trusting `softwareEnforced` or Skipping Status CRL [426, 428] | 2018-2026 | Custom relying-party backend parsers | Script / `TrickyStore` sending software-attested or revoked keybox chain | Verifier checked root CA signature without rejecting `Software(0)` or `/attestation/status` | Enforce `StrongBox`/`TEE`, read `hardwareEnforced` only, & poll live status JSON [108, 426] |
| ODM Factory `keybox.xml` & `TEE` Leaks (`CVE-2024-20017`) [430, 431] | 2020-2025 | Pre-`RKP` ODM factory lines & legacy `TEE`s | Leaked PEM batch keys resold on Telegram to `TrickyStore` users | Long-lived batch private keys existed outside target silicon before flashing | Revoke serials on `/attestation/status` + Android 16+ `RKP`-only `UDS`/`DICE` silicon [108, 430, 441] |
| April 2026 `ECDSA P-384` Root Transition Outages [430, 436] | 2026 | Relying parties hardcoding single legacy `RSA-4096` root | Genuine `RKP` Android 15-17 phones failing enterprise/passkey attestation | Verifiers pinned only 2016 `RSA` root and rejected 2026 `ECDSA P-384` RKP chains | Pin full Google Attestation Root bundle (`RSA-4096` + `ECDSA P-384`) with rotation tests [430, 436] |
| Registration-Only "Click-Farm Relay" Proxy [426, 438] | 2022-2026 | App session protocol decoupling JWT from attested key | Bot proxies one signup `challenge` to real phone, then exports bearer token | Backend verified `OID .17` once at signup without binding subsequent API calls to key | Require ongoing `RFC 9449` `DPoP` / mTLS signatures from the attested `KeyMint` key [438] |
| Single-Device High-Velocity Bot Minting [428, 434] | 2023-2026 | Genuine locked phone in click-farm rack | One physical handset minting `50,000` attested keys for fake accounts | Valid `StrongBox` hardware used as an automated account-generation oracle | Inspect `OID 1.3.6.1.4.1.11129.2.1.30` CBOR `certs_issued` 30-day counter [428, 434] |
| Pre-Android 12 `ORANGE` `boot.img` Patch-Level Spoof [29, 426] | 2019-2021 | Naive verifiers checking `osPatchLevel` before `deviceLocked` | Unlocked `ORANGE` phone booting edited `boot.img` header | Verifier inspected patch integer while forgetting `rootOfTrust.deviceLocked == TRUE` | Assert `deviceLocked == TRUE` and `Verified`/`SelfSigned` before reading patch tags [29, 426] |
| Test Root Allowlist Escaping to Production [428] | 2020-2025 | Pre-production integration test bypasses | Attacker submits static test cert chain accepted in staging/prod config | Staging allowlists for synthetic non-hardware test certs shipped to production | `RKP` v3 removes `testMode` (`STATUS_REMOVED`); ban test roots in prod config [428, 442] |

### Why Direct Key Attestation Collided With Developer Convenience (`Play Integrity`)

Look at what properly implemented X.509 `Key Attestation` + `RKP` + `DPoP` delivers: *cryptographic, zero-middleman proof that every signed request comes from a non-exportable key inside unrevoked, up-to-date `StrongBox`/`TEE` silicon on a locked `GREEN` or `YELLOW` handset* [428, 438, 441]. Yet writing and maintaining RFC 5280 + ASN.1 + CBOR verifiers intimidated thousands of app teams, who instead outsourced trust decisions to Google's high-level `Play Integrity API` (`MEETS_DEVICE_INTEGRITY` / `MEETS_STRONG_INTEGRITY`), sparking a fierce multi-year cat-and-mouse war against `Magisk`, `Zygisk`, `KernelSU`, `APatch`, and `TrickyStore`. [Chapter 16](16-play-integrity-keybox-wars.md) dissects both sides of that battlefield.

> **Key idea.**
> Hardware `Key Attestation` attests a *cryptographic key*, never a bearer cookie: always enforce `BasicConstraints cA=FALSE`, check `/attestation/status`, trust both Google's `RSA-4096` and `ECDSA P-384` roots, read `hardwareEnforced.rootOfTrust` directly, and bind live session tokens via `DPoP` signatures from that attested key [428, 432, 436, 438].

## Inspecting via ADB, Fastboot, & Attestation

Enumerate all `IRemotelyProvisionedComponent` (`RKP`) hardware HAL instances (`default` TEE, `strongbox` discrete SE, and `avf` `pKVM` virtual machine) and confirm the `com.android.rkpd` Mainline `APEX` is active:

```bash
adb shell service list | grep -i remotelyprovisioned
adb shell cmd package list packages --apex-only | grep rkpd
```

Inspect `RemoteProvisioner` (`rkpd`) provisioned key-pool status and `KeyMint` HAL version (`300`, `400`, or `500`) on a connected handset:

```bash
adb shell dumpsys remote_provisioning 2>/dev/null | head -n 16
adb shell getprop ro.hardware.keystore
```

Poll Google's live public Key Attestation Revocation List (`attestation/status`) from a workstation to inspect revoked or suspended factory keybox serial numbers:

```bash
curl -fsSL https://android.googleapis.com/attestation/status | head -n 24
```

Inspect `BasicConstraints` (`CA:FALSE`), `OID 1.3.6.1.4.1.11129.2.1.17` (`KeyDescription`), and `OID 1.3.6.1.4.1.11129.2.1.30` (`ProvisioningInformation`) on an exported leaf/intermediate certificate:

```bash
openssl x509 -in attestation_leaf.pem -text -noout | grep -E -A 4 'Basic Constraints|1.3.6.1.4.1.11129.2.1.(17|30)'
```

