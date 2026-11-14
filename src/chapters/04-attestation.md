# Attestation

## Overview

* **Role in the Chain:** Cryptographic reporting bridge between local silicon state and remote relying parties; packages hardware-measured PCR digests ([Chapter 4](03-measured-boot.md)), `WBCL` event logs, and TPM-resident identity proofs ([Chapter 2](01-tpm.md), [Chapter 3](02-pluton.md)) into verifiable health claims without trusting the host operating system to self-report.
* **Core Security Invariant:** A remote verifier accepts a platform boot report if and only if (1) the `TPMS_ATTEST` structure carries a fresh challenge nonce signed by a restricted `Attestation Key` (`AK`) cryptographically bound via `TPM2_ActivateCredential` to a genuine `Endorsement Key` (`EK`), and (2) replaying the accompanying `WBCL` log reproduces the signed `pcrDigest` and satisfies security policy.
* **Trusted Computing Base (TCB):** The TPM 2.0 or Pluton hardware protecting `EK` and `AK` private material, the silicon manufacturer's `EK` certificate authority, the attestation broker (`Microsoft Azure Attestation` or enterprise CA) certifying `AK` binding and evaluating quotes, and the pre-OS CRTM/DRTM chain feeding the PCRs.
* **Primary Failure Modes:** Relaying attestation challenges from an unmeasured host to an external clean TPM when `EK` identity is unbound to device enrollment (`Cuckoo` attack), compromised vendor `EK` key generation (`ROCA`), verifiers skipping `WBCL`-to-`PCR` cryptographic replay, and post-boot runtime compromise occurring after a valid boot quote (`TOCTOU`).
* **Handoff:** Delivers signed, standards-based platform posture claims (such as `secureBootEnabled`, `virtualSecureMode`, and `codeIntegrity`) to cloud policy engines; delegates runtime kernel isolation to Part II ([Chapter 6](05-secure-kernel.md) through [Chapter 9](19-mitigations.md)) and enterprise session enforcement to Part IV ([Chapter 19](13-zero-trust.md) through [Chapter 22](29-confidential-vms.md)).

## Core Engineering Problem & Threat Model

Measured Boot ([Chapter 4](03-measured-boot.md)) constructs an append-only hash history inside local hardware PCRs and seals on-box secrets such as the BitLocker Volume Master Key. Yet local sealing does nothing for a remote resource server (an Entra ID token endpoint, an Active Directory Certificate Services (`ADCS`) CA, an enterprise VPN concentrator, or Azure Key Vault) that must decide whether an incoming network connection originates from a genuinely healthy Windows device or from an attacker-controlled host spoofing management telemetry. Querying user-mode agents (`msinfo32`, WMI, or MDM sync payloads) directly is useless against a ring-0 or administrative adversary, because compromised OS code can forge any plaintext JSON or XML compliance report at will.

To prove local boot integrity across a network without trusting the host OS, TCG specifications introduced two foundational mechanisms starting with TPM 1.1b/1.2 [50, 143, 144] and modernized in TPM 2.0 [57]: credential activation, which binds a restricted signing Attestation Key (`AK`, historically `AIK`) to the chip's manufacturer-certified Endorsement Key (`EK`) via an attestation broker (`Privacy-CA` / `AttCA`), and cryptographic quoting (`TPM2_Quote`), which signs selected PCR digests alongside a verifier-supplied freshness nonce. In modern Windows 10 and Windows 11 fleets, Microsoft operationalizes this brokered pipeline end to end through the HealthAttestation Configuration Service Provider (`CSP`), Microsoft Azure Attestation (`MAA`), and Microsoft Intune Device Health Attestation [139, 145, 146, 147].

The remote attestation threat model assumes an adversary with full control over the target machine's VTL0 operating system (capable of intercepting network packets, editing `WBCL` files in RAM, generating arbitrary software RSA/ECDSA keys, or replaying old network transcripts) and potential possession of a separate, uncompromised TPM-equipped machine on the same network. Against this adversary, the attestation protocol must prove *hardware residency* of the signing key, *device-specific binding* to the enrolled chassis, *temporal freshness* against replay, and *exact consistency* between detailed `WBCL` configuration claims and signed PCR digests.

## Architectural Deep Dive

### Establishing Hardware Provenance: EK Validation and Credential Activation

Every compliant physical TPM 2.0 (discrete, chipset fTPM, or Pluton) possesses a non-exportable Endorsement Key (`EK`) derived from the Endorsement Primary Seed (`EPS`) and backed by an X.509 `EKCert` signed by the silicon manufacturer's CA (Infineon, STMicroelectronics, Nuvoton, Intel, AMD, or Microsoft) ([Chapter 2](01-tpm.md)) [64, 65, 139]. Because the `EK` is globally unique to one chip and restricted to decryption (`TPM_ALG_RSA` / `TPM_ALG_ECC` decrypt-only), TPM 2.0 forbids using `EKPriv` to sign quotes directly, both as a cryptographic role separation and to prevent every relying party on the internet from tracking the hardware serial identifier [57, 143].

Instead, Windows generates a restricted signing Attestation Key (`AK`) inside the TPM (`fixedTPM | fixedParent | sensitiveDataOrigin | restricted | sign`) and proves to an attestation service or enterprise CA that the `AK` resides inside the *exact same physical TPM* as the certified `EK` using the two-command Credential Activation ceremony [57, 64, 65, 139]:

1. **Enrollment Request:** The Windows client transmits `EKCert` (or pre-registered `EKPub`), the public structure `TPMT_PUBLIC` of the newly created `AK` (`AKPub`), and attestation parameters to the attestation broker (`MAA` or an `ADCS` CA) [65, 139].
2. **Broker Challenge Construction (`TPM2_MakeCredential` logic):** The broker validates `EKCert` up to a trusted TPM manufacturer root CA and checks that `AKPub`'s object attributes include `fixedTPM` and `restricted`. It then computes the cryptographic `Name` of `AKPub` (the algorithm ID concatenated with the hash of `TPMT_PUBLIC`), generates a random symmetric credential secret, encrypts that secret to `EKPub`, and integrity-binds the outer `credentialBlob` structure to `Name(AKPub)` [57, 64].
3. **Hardware Unwrapping (`TPM2_ActivateCredential`):** The client passes `credentialBlob` and the encrypted seed to `TPM2_ActivateCredential(activateHandle = AK, keyHandle = EK)`. Inside the TPM boundary, the chip uses `EKPriv` to decrypt the seed, verifies the HMAC integrity tag, and crucially confirms that the currently loaded `activateHandle` has `fixedTPM` set and matches `Name(AKPub)` byte for byte. Only if both keys reside inside the same TPM does the chip release the decrypted secret [57, 64].
4. **Certificate or Token Issuance:** Returning the decrypted secret (or decrypting a symmetrically wrapped AIK certificate issued in a single pass) proves possession of `EKPriv` and co-residency of `AK`. The broker issues an X.509 AIK certificate (carrying the TCG/Microsoft TPM attestation EKU) or an attested JWT token [65, 139].

### Cryptographic State Reporting: `TPM2_Quote`, `TPM2_Certify`, and `TPMS_ATTEST`

Why can a compromised OS kernel not simply pass a crafted byte buffer matching a `PCR` digest to `TPM2_Sign` using a TPM-resident key? Because the `AK` carries the `restricted` attribute (`TPMA_OBJECT_restricted`): the TPM refuses to sign any externally supplied hash with a `restricted` signing key unless the digest was computed *internally* by the TPM itself over a marshaled `TPMS_ATTEST` structure prefixed with the 4-byte magic constant `TPM_GENERATED_VALUE` (`0xFF544347`, ASCII `ÿTCG`) [57, 64]. External callers invoking `TPM2_Sign` cannot forge that header.

When an attestation client invokes `TPM2_Quote`, the TPM constructs and hashes `TPMS_ATTEST` internally before signing it with `AKPriv` [57]:

| `TPMS_ATTEST` Field | Type / Value | Security Function |
|---|---|---|
| `magic` | `0xFF544347` (`TPM_GENERATED_VALUE`) | Proves structure was generated inside the TPM, preventing external `TPM2_Sign` spoofing |
| `type` | `TPM_ST_ATTEST_QUOTE` (`0x8018`) | Distinguishes a PCR quote from key certification (`TPM_ST_ATTEST_CERTIFY`) or time attestation |
| `qualifiedSigner` | `TPM2B_NAME` | Cryptographic qualified name of the signing `AK`, binding its hierarchy chain |
| `extraData` | `TPM2B_DATA` (verifier nonce) | Binds the quote to the relying party's fresh random challenge, defeating replay of stale clean boots |
| `clockInfo` | `TPMS_CLOCK_INFO` | Records internal `clock`, `resetCount`, `restartCount` (hibernate/suspend cycles), and `safe` flag |
| `firmwareVersion` | `UINT64` | Reports current TPM/Pluton active firmware security version |
| `attested.quote` | `TPMS_QUOTE_INFO` | Contains `pcrSelect` (`TPML_PCR_SELECTION` bank/register bitmask) and `pcrDigest` (hash of concatenated selected PCRs) |

A parallel mechanism, TPM Key Attestation, invokes `TPM2_Certify` (`type = TPM_ST_ATTEST_CERTIFY`) using the same certified `AK` to sign a `TPMS_ATTEST` structure over the `Name` and `TPMA_OBJECT` flags of an application key (such as an `ADCS` client-authentication key or a Windows Hello for Business logon key) [65, 70]. That signature proves to the issuing enterprise CA that the user's private key is non-exportable inside genuine TPM silicon before the CA ever mints a domain certificate ([Chapter 17](12-hello.md)).

### Verifier Appraisal: Replaying the WBCL Into Security Claims

![Figure: Production Windows Measured Boot attestation pipeline. Inside the endpoint, TPM 2.0 signs a nonced TPMS_ATTEST quote (0xFF544347) with its restricted AIK alongside the unauthenticated WBCL event log; the cloud verifier (HealthAttestation CSP / Microsoft Azure Attestation) replays the WBCL to match PCR digests and emits signed posture claims consumed by Intune and Entra Conditional Access.](diagrams/04-attestation-windows-flow.svg)

A raw `TPM2_Quote` proves only `pcrDigest`, a single hash over concatenated registers (for example, `PCR[0..7, 11..14]` for SRTM plus `PCR[17..20]` when System Guard Secure Launch DRTM is active). To translate opaque hashes into actionable security claims, a verifier executes a strict four-phase appraisal pipeline [129, 139, 146]:

1. **Identity & Signature Verification:** Validate the `AK` certificate chain back to the trusted `EK` broker/manufacturer root, confirm `TPMS_ATTEST.magic == 0xFF544347` and `type == TPM_ST_ATTEST_QUOTE`, and verify the `AK` cryptographic signature over `TPMS_ATTEST`.
2. **Freshness & Counter Validation:** Verify that `extraData` matches the single-use cryptographic nonce issued for this session, and cross-check `resetCount` / `restartCount` when evaluating hibernate (`winresume.efi`) vs. cold-boot transitions.
3. **Cryptographic WBCL Replay:** Parse the untrusted binary `WBCL` (`TCG_PCR_EVENT2` log, [Chapter 4](03-measured-boot.md)) submitted alongside the quote. Starting from initial register state (`0x00...00` for `PCR[0..14]`, or Locality-4 `0x00...00` for `PCR[17..22]`), iteratively apply $R_i \leftarrow H(R_i \Vert d)$ across every logged event for the selected bank, hash the resulting simulated register set, and verify exact byte equality with `TPMS_ATTEST.attested.quote.pcrDigest` [57, 129]. Any single forged or omitted `WBCL` record causes replay to fail immediately.
4. **Claim Extraction & Policy Evaluation:** Once cryptographic replay authenticates the `WBCL` contents, the verifier parses the now-proven `WBCL` tags to extract structured boolean and version claims: `secureBoot` (from `PCR[7]`), `dbx` revocation baseline, `bootDebugging` and `testSigning` (from `PCR[12]` BCD records), `codeIntegrity` and `earlyLaunchAntiMalwareDriverProtection` (from `PCR[13]`), and `virtualSecureMode` / VBS and DRTM `Secure Launch` status (from `WBCL` VSM entries and `PCR[17..18]`) [139, 146].

### Windows Production Architecture: HealthAttestation CSP, MAA, and Intune

On shipping Windows endpoints, device health attestation is orchestrated by the `HealthAttestation` Configuration Service Provider (`CSP`) (`./Vendor/MSFT/HealthAttestation`, surfaced locally via the `MDM_HealthAttestation` WMI bridge class) in coordination with cloud attestation and MDM services [146, 147]:

* **Windows 10 Legacy Flow (`HAS`):** During MDM check-in, Microsoft Intune supplies a fresh `Nonce` via `HealthAttestation CSP`. Windows collects the `AIK` quote, `EKCert`, and `WBCL` (`SRTMBoot.dat` / `DRTMBoot.dat`), transmits them to the cloud Windows Health Attestation Service (`HAS`), and receives an opaque encrypted Health Attestation Certificate blob cached on the client. Upon sync, the client forwards that blob to Intune, which validates it with `HAS` to populate compliance posture [147].
* **Windows 11 Modern Flow (`Microsoft Azure Attestation` / `MAA-CSP`):** Windows 11 replaces the proprietary `HAS` blob flow with standards-based Microsoft Azure Attestation (`MAA`) integration (`MAA-CSP` nodes inside `HealthAttestation CSP`) [139, 145, 147]. Triggered by MDM, the endpoint submits TPM evidence (`EKCert`, `AK` binding, `TPMS_ATTEST` quote, and `WBCL`) directly to a tenant or regional `MAA` endpoint. `MAA` validates hardware provenance, replays the `WBCL`, evaluates customizable appraisal policy, and returns a standard JSON Web Token (`JWT`, RFC 7519) signed by `MAA`'s OpenID Connect discovery keys (`jku` / `jwks_uri`) [139, 145].
* **Management and Conditional Access Consumption:** Microsoft Intune ingests the attested `MAA` report and projects normalized posture attributes into Microsoft Graph's `deviceHealthAttestationState` resource (`secureBoot`, `bitLockerStatus`, `codeIntegrity`, `bootDebugging`, `virtualSecureMode`, `firmwareProtection`, `memoryIntegrityProtection`) [146]. Compliance policies mark endpoints non-compliant if `secureBoot` or `codeIntegrity` is disabled or `bootDebugging` is enabled, allowing Entra ID Conditional Access to block token issuance before corporate resources are reached ([Chapter 19](13-zero-trust.md)). Beyond MDM, Azure Trusted Launch VMs and Azure Key Vault Secure Key Release (`SKR`) consume the same `MAA` TPM JWT claims (`x-ms-attestation-type`, `secureBootEnabled`) to gate cryptographic key release ([Chapter 22](29-confidential-vms.md)) [74, 145].

### Why Production Chose Brokered PKI Over Direct Anonymous Attestation (`ECDAA`)

A recurring architectural question arises when inspecting the TPM 2.0 specification: why do Windows, Pluton, and Azure Attestation rely on an `EK`-to-`AK` certificate broker (`Privacy-CA` / `AttCA`) rather than Direct Anonymous Attestation (`DAA` / `TPM_ALG_ECDAA`)?

![Figure: Two ways to prove a TPM is genuine without naming it. Left, the brokered Privacy-CA flow: the CA validates the EK certificate and issues a certificate on the AIK, but it sees the EK, AIK linkage and stays online for every enrollment, so the privacy property is an operational promise. Right, the DAA flow: a one-time Join issues a blind CL credential and Sign proves possession in zero knowledge, with no opener and no online CA, so the privacy property is cryptographic.](diagrams/04-attestation-privacy-ca-vs-daa.svg)

Introduced by Brickell, Camenisch, and Chen in 2004 [148] and standardized for elliptic curves in TPM 2.0 via `TPM_ALG_ECDAA` (`0x001A`) over the pairing-friendly Barreto-Naehrig curve `TPM_ECC_BN_P256` (`0x0010`) using the split `TPM2_Commit` / `TPM2_Sign` command pair [57], `ECDAA` eliminates broker linkability mathematically: after a one-time blind `Join` over `TPM2_ActivateCredential`, the TPM proves group membership in zero knowledge (with optional per-verifier basename pseudonyms $N_V = \zeta^f$) without an online CA ever linking `EK` to signatures [57, 148].

Despite its cryptographic elegance, `ECDAA` saw virtually zero production adoption: TCG demoted `TPM_ALG_ECDAA` to *optional* in PC Client Platform TPM Profile v1.04 (2020) [63], W3C removed `ECDAA` entirely in WebAuthn Level 2 (2021) [149, 150], Pluton omits it from its published algorithm surface [79], and Windows exposes no `CNG` or `NCrypt` DAA provider. Production platforms converged on `AttCA` brokers (and 100,000-unit shared batch keys for consumer FIDO2 authenticators [151]) for four concrete engineering reasons:

1. **Enterprise Identifiability Requirement:** In corporate zero-trust fleets (`Autopilot`, `Intune`, `ADCS`), administrators *want* deterministic binding between a specific `EKCert` hardware serial and an Entra device object to defeat `Cuckoo` relay attacks; anonymity is an anti-goal for managed fleet posture [65, 139].
2. **Centralized Revocation vs. Rogue-Key Distribution:** Revoking an `AK` or `EK` cohort in a brokered PKI requires updating a single cloud CA policy or CRL; revoking compromised `ECDAA` secrets without an opener requires pushing growing rogue-key or signature revocation lists to every relying-party verifier [152].
3. **Standard X.509/JWT Tooling and Debuggability:** Every cloud language SDK natively parses X.509 chains and `RS256`/`ES256` `MAA` JWTs with clear failure telemetry, whereas `BN-P256` bilinear-pairing verifiers exist in no mainstream standard library.
4. **Protocol Driving Fragility:** Academic analysis in 2016-2017 (*One TPM to Bind Them All*, IEEE S&P 2017) revealed that naive host software driving TPM 2.0's split `TPM2_Commit` interface exposed a static Diffie-Hellman oracle over the TPM's secret $f$, breaking unlinkability unless host libraries patched the protocol sequence [153, 154].

## Attack Catalog & Gap Analysis

Because `TPMS_ATTEST` magic tagging (`0xFF544347`) prevents a compromised kernel from forging `AK` quotes via `TPM2_Sign`, real-world attestation breaks target unbound hardware identities, compromised vendor `EK` roots, naive custom verifiers, or the temporal gap after boot completes.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Cuckoo Relay Attack (Parno) | 2008 | Binding of valid `TPM2_Quote` to the physical host under inspection | Malware on target host + network path to attacker-owned clean TPM | Forwards verifier challenge nonce and enrollment requests to an external clean physical TPM; returns authentic `AK`-signed quote and clean `WBCL` | Pre-register and pin hardware `EKPub`/`EKCert` to device identity during Autopilot / MDM provisioning; bind TLS channel (`Channel Binding`) [65, 138, 139] |
| ROCA `EK` Compromise (CVE-2017-15361) | 2017 | Hardware non-forgeability of TPM `EKPriv` during `ActivateCredential` | Vulnerable Infineon `EKPub` (`RSALib 1.02.013`) accepted by broker CA | Factors RSA-2048 `EKPub` offline; decrypts `TPM2_MakeCredential` challenges in software to obtain `AttCA` certificates for non-TPM keys | Reject vulnerable Infineon firmware cohorts at CA/MAA policy; apply `ADV170012` firmware update [65, 81, 82, 83] |
| TPM 2.0 `ECDAA` DH-Oracle (CDL16 / IEEE S&P) | 2017 | Anonymity / unlinkability of `TPM2_Commit` + `TPM2_Sign` `ECDAA` | Local host code invoking unpatched `TPM2_Commit` points | Supplies crafted curve points to `TPM2_Commit` to extract static Diffie-Hellman oracle responses over secret $f$, linking anonymous sessions | Apply CDL16 host-driver point validation; use `AttCA` or FIDO batch attestation instead of `ECDAA` [153, 154] |
| Unreplayed `WBCL` Spoofing | Architectural | Integrity of extracted claims (`secureBoot`, `bootDebugging`, `codeIntegrity`) | Custom verifier inspecting `WBCL` events or `pcr0` strings without hash replay | Submits authentic `TPM2_Quote` over malicious PCRs paired with a doctored `WBCL` claiming Secure Boot and HVCI are active | Enforce strict cryptographic replay of `TCG_PCR_EVENT2` digests against `TPMS_ATTEST.attested.quote.pcrDigest` [57, 129] |
| Post-Quote Runtime Compromise (`TOCTOU`) | Architectural | Currency of boot-time health claims during active session | Ring-0 (BYOVD) or user-mode exploit occurring *after* boot attestation | Compromises kernel or steals session tokens on a machine that booted cleanly hours earlier and still holds a valid `MAA` / Intune compliance state | Combine boot attestation with HVCI/VBS ([Chapter 6](05-secure-kernel.md), [Chapter 7](06-code-integrity.md)), ETW telemetry ([Chapter 18](28-etw.md)), and Continuous Access Evaluation ([Chapter 20](14-cae.md)) [146, 155] |

### Hardware Relay and Unbound Enrollment: The Cuckoo Attack

If an attestation verifier checks only *"was this quote signed by an `AK` certified under *some* genuine Infineon or Pluton `EKCert`?"*, it proves only that *a* genuine TPM somewhere on Earth booted cleanly, not that the endpoint requesting corporate data owns that TPM [138]. An adversary running malware on a rootkitted laptop (or bare Linux attack box) simply proxies the `MakeCredential` / `ActivateCredential` and `TPM2_Quote` RPC messages over a tunnel to a clean $300 Windows mini-PC sitting on the attacker's desk.

Defeating Cuckoo relays in enterprise Windows deployments requires binding two layers simultaneously: out-of-band `EK` inventory pinning (capturing the device's `EKPub` hash during factory Windows Autopilot hardware-hash registration or supervised ADCS TPM Key Attestation so an attacker cannot substitute an unknown TPM [65, 139]) and cryptographic key binding, where the same TPM that signs the health quote also holds the non-exportable client TLS, Windows Hello, or Primary Refresh Token (`PRT`) session key ([Chapter 16](11-pth-prt.md), [Chapter 17](12-hello.md)), ensuring the proxied mini-PC cannot sign session requests without holding the victim's identity key inside the *same* `fixedTPM` hierarchy.

### Compromised Silicon Roots (`ROCA`) and Naive Verifier Pitfalls

Brokered attestation concentrates trust in TPM manufacturer `EK` CAs. During the 2017 `ROCA` vulnerability (`CVE-2017-15361`, [Chapter 2](01-tpm.md)), factoring an affected Infineon `EKPub` allowed an attacker to compute `EKPriv` in software, pass `TPM2_MakeCredential` decryption challenges on a server without touching hardware, and mint fraudulent `AttCA`-certified keys [65, 81, 82]. Consequently, production `MAA` and `ADCS` deployments must maintain manufacturer root allowlists *and* firmware-version blocklists (`TPMS_ATTEST.firmwareVersion` and `EKCert` subject OIDs `2.23.133.2.*`) [65, 156]. Equally critical in custom attestation pipelines is skipped `WBCL` replay: because `TPMS_ATTEST` signs only the compressed `pcrDigest` (not the megabyte-scale `WBCL` buffer), any verifier that parses `WBCL` flags before verifying that the replayed `WBCL` hashes equal `pcrDigest` accepts completely unauthenticated host assertions [57, 129].

### The Time-of-Check to Time-of-Use (`TOCTOU`) Window

Even a cryptographically flawless `MAA` evaluation suffers an inherent temporal boundary: boot attestation proves initial launch state, not ongoing runtime state. Once Windows completes startup, submits its `TPM2_Quote` and `WBCL` via `HealthAttestation CSP`, and receives a compliant `deviceHealthAttestationState` in Intune, MDM compliance re-evaluation typically runs on multi-hour intervals (and standard Entra access tokens remain valid for roughly an hour, with Continuous Access Evaluation propagating administrative revocations rather than live kernel memory scans) [146, 155]. If an attacker loads a vulnerable signed driver (`BYOVD`, [Chapter 7](06-code-integrity.md)) or steals a browser cookie thirty minutes after boot, `PCR[0..14]` and `PCR[17..22]` remain unchanged and the prior boot quote remains mathematically valid.

## Theoretical Limits & Structural Invariants

### Initial-State Proof vs. Continuous Runtime Introspection

A TPM 2.0 quote over static (`PCR[0..14]`) and dynamic late-launch (`PCR[17..22]`) registers is a point-in-time proof of initialization, bounded at the kernel's `EV_SEPARATOR` marker ([Chapter 4](03-measured-boot.md)). Because arbitrary ring-3 process creation, network I/O, and dynamic data mutations are non-deterministic, extending every runtime memory page into a PCR would make baseline policy comparison impossible. Bridging the gap between *clean boot* and *clean runtime* requires invariant-preserving isolation: launching the hypervisor and Secure Kernel inside the attested `MLE` (`PCR[18]`) so VTL1 enforces immutable kernel code pages (`HVCI`) even after boot measurement stops ([Chapter 6](05-secure-kernel.md), [Chapter 7](06-code-integrity.md)).

### Decoupling Platform Attestation from Principal and Resource Authorization

Per Law 16, platform attestation claims must be strictly separated from identity authentication and resource authorization.

> **Key idea.**
> A valid `Microsoft Azure Attestation` JWT (`x-ms-attestation-type: tpm`, `secureBootEnabled: true`, `virtualSecureMode: true`) proves *what software stack booted on a specific piece of silicon*. It says nothing about *who* is sitting at the keyboard, whether their user session is compromised, or whether they are authorized to read a sensitive mailbox. Enterprise Zero Trust ([Chapter 19](13-zero-trust.md)) composes platform attestation with phishing-resistant user authentication ([Chapter 17](12-hello.md)) and least-privilege access control ([Chapter 10](25-access-control.md)) as independent, conjunctive predicates.

### Virtual TPM (`vTPM`) Host Equivalence in Cloud Workloads

When inspecting `Get-TpmEndorsementKeyInfo` or `MAA` tokens from virtualized Windows instances (such as Azure Trusted Launch Gen2 VMs [74]), practitioners must distinguish emulated `vTPM` roots from physical silicon roots. On a standard Trusted Launch VM, the `vTPM` and its `EKCert` are provisioned and hosted by the cloud provider's hypervisor stack: an `MAA` quote proves the guest VM booted with virtual Secure Boot enabled inside Azure's management boundary, *assuming the underlying host hypervisor and fabric are trusted* [74, 145]. Removing the cloud host hypervisor from the guest's TCB requires hardware-isolated Confidential VMs backed by AMD SEV-SNP or Intel TDX silicon attestation reports ([Chapter 22](29-confidential-vms.md)).

## Inspecting and Verifying on a Running System

Operational diagnostics on Windows verify three local prerequisites of the remote attestation chain: `EK` certificate and TPM 2.0 attestation readiness, `MDM_HealthAttestation` CSP state, and TPM/Attestation operational event telemetry.

### Verifying Endorsement Key Certificates and Attestation Readiness

Confirm that the TPM exposes a valid `EKPub` and manufacturer X.509 certificate chain (`OID 2.23.133.2.*` attributes) and reports `Ready For Attestation` (elevated PowerShell) [65, 133, 156]:

```powershell
Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 |
    Select-Object IsPresent, PublicKeyHash, ManufacturerCertificates
tpmtool getdeviceinformation | Select-String 'Attestation|Version'
```

Expected output format on an attestation-capable endpoint:

```text
IsPresent                : True
PublicKeyHash            : 70769c52b6e24ef683693c2a0208da68d77e94192e1f4080ae7c9b97c6caa681
ManufacturerCertificates : {[Subject] OID.2.23.133.2.3=1.2... [Issuer] CN=Infineon OPTIGA(TM) TPM 2.0 RSA CA...}

-TPM Version: 2.0
-Ready For Attestation: True
-Is Capable For Attestation: True
```

If `Ready For Attestation` is `False` or `ManufacturerCertificates` is empty on bare metal (for instance, on offline-imaged devices blocked from fetching vendor EK certificates), `TPM2_MakeCredential` / `MAA` enrollment will fail until `EKCert` provisioning completes.

### Querying the HealthAttestation CSP via the WMI MDM Bridge

Inspect the local `MDM_HealthAttestation` instance managed by `DMWmiBridgeProv.dll`. Because `MDM_HealthAttestation` is marked `[InPartition("local-system")]`, the query must run as `NT AUTHORITY\SYSTEM` (an ordinary elevated `Administrators` prompt receives `Access Denied`) [147]:

```powershell
# Run in a SYSTEM context (e.g., via Intune remediation or scheduled task as SYSTEM)
Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_HealthAttestation' |
    Select-Object Status, TpmReadyStatus, HASEndpoint, CurrentProtocolVersion
```

Expected output format on an MDM-enrolled Windows 11 client:

```text
Status TpmReadyStatus HASEndpoint                                    CurrentProtocolVersion
------ -------------- -----------                                    ----------------------
     0              1 https://sharedeus.eus.attest.azure.net/...                          3
```

`Status = 0` indicates a clean attestation report cached from the configured `MAA` / `HAS` endpoint without protocol errors [147].

### Checking Local TPM and Attestation Operational Events

Query the `Microsoft-Windows-TPM-WMI` and `DeviceManagement-Enterprise-Diagnostics-Provider` logs to diagnose AIK enrollment, EK certificate retrieval, or `HealthAttestation CSP` failures (elevated PowerShell):

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TPM-WMI/Operational' -MaxEvents 5 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message
```

Expected healthy provisioning output:

```text
TimeCreated          Id LevelDisplayName Message
-----------          -- ---------------- -------
11/14/2026 8:15:04 AM 14 Information     The Trusted Platform Module (TPM) provisioning completed...
```

Errors in this channel (or Event IDs `1795`/`1801` for Secure Boot servicing and `HealthAttestation` errors in `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin`) pinpoint whether an attestation rejection stems from missing `EKCert` trust, `WBCL` truncation, or disabled Secure Boot / VBS prerequisites.

## Summary & Handoff

Remote attestation completes Part I (Silicon) by carrying hardware-rooted boot evidence off the local machine. By binding a `restricted` signing `Attestation Key` (`AK`) to a manufacturer-certified `Endorsement Key` (`EK`) via `TPM2_ActivateCredential`, signing nonce-fresh `TPMS_ATTEST` PCR quotes (`TPM2_Quote`), and replaying the `WBCL` inside Microsoft Azure Attestation (`MAA`) to emit signed JWT posture claims, Windows allows cloud services to verify boot integrity without trusting VTL0 software. Production systems overwhelmingly selected this brokered `AttCA` PKI architecture over zero-knowledge `ECDAA` because enterprise fleets require deterministic device identity, centralized revocation, and debuggable X.509/JWT tooling.

Yet even a valid `MAA` quote proves only how the system *launched*: the instant `ExitBootServices()` and `EV_SEPARATOR` complete, Part II (Kernel & Code) must defend the running operating system against runtime compromise:

* **Hypervisor-Enforced Runtime Isolation:** Using SLAT and Virtual Trust Levels (`VTL0` vs. `VTL1`) to isolate security-critical code and secrets away from `ntoskrnl.exe` begins in [The Secure Kernel and VBS (Chapter 6)](05-secure-kernel.md).
* **Kernel and Application Code Integrity:** Enforcing Authenticode, HVCI (`W^X` kernel memory), and Windows Defender Application Control (`WDAC`) against vulnerable drivers and unapproved code is owned by [Code Integrity and Application Control (Chapter 7)](06-code-integrity.md).
* **Cloud Policy Enforcement and Confidential Compute:** Consuming `MAA` health claims inside Conditional Access ([Chapter 19](13-zero-trust.md)), revoking active sessions ([Chapter 20](14-cae.md)), and extending hardware attestation to CPU-encrypted cloud VMs ([Chapter 22](29-confidential-vms.md)) complete the end-to-end chain in Part IV (Cloud).
