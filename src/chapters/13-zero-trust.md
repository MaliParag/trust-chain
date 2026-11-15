# Zero Trust

## Overview

* **Role in the Chain:** Translates every on-box hardware, kernel, credential, and telemetry link (`Chapters 1-18`) into explicit, cryptographically bound policy inputs evaluated by a cloud Policy Decision Point (`PDP`, Microsoft Entra Conditional Access) and enforced by downstream Policy Enforcement Points (`PEPs`) regardless of network location.
* **Core Security Invariant:** Network presence (`LAN` or `VPN`) confers zero implicit authority; access to any resource requires simultaneous satisfaction of every matching Conditional Access policy across user identity, authentication strength (`AAL2`/`AAL3`), attested device identity and compliance (`PRT` + Intune MDM), behavioral risk (`Defender XDR` + Entra ID Protection), and session binding.
* **Trusted Computing Base (TCB):** Entra ID token-signing keys, federated SAML/WS-Trust trust anchors (`AD FS`), the Conditional Access evaluation engine and administrator policy graph, `TPM`-bound device registration keys (`dk`/`tk`), the Intune/MDM compliance pipeline, and software build provenance (`SLSA` / `Authenticode`).
* **Primary Failure Modes:** Pre-signature build-pipeline injection paired with federated signing-key theft (`SUNSPOT` / `SUNBURST` → `Golden SAML`), pre-authenticated front-end `SSRF` (`ProxyLogon`) or legacy `SYSTEM` RPC (`PrintNightmare`), Conditional Access policy exclusions and permutation drift, MDM compliance sync latency, unbound post-issuance token replay, and cloud IdP signing-key compromise (`Storm-0558`).
* **Handoff:** Establishes point-in-time (`t = 0`) multi-signal cloud authorization; hands mid-session (`t > 0`) revocation to [Continuous Access Evaluation (Chapter 20)](14-cae.md), cloud hypervisor isolation to [Confidential VMs (Chapter 22)](29-confidential-vms.md), and IdP root-key compromise analysis to [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).

## Core Engineering Problem & Threat Model

Parts I through III hardened the individual Windows endpoint from reset vector to runtime telemetry: `Secure Boot` and `Measured Boot` anchor platform firmware (Chapters 1 and 4), `VBS` and `HVCI` isolate `VTL1` secrets and kernel code pages (Chapters 6, 7, and 12), `WHfB` and `WebAuthn` replace replayable passwords with hardware-bound keys ([Chapter 17](12-hello.md)), and `ETW` / `EtwTi` stream host behavioral signals ([Chapter 18](28-etw.md)). Throughout the 2010s, however, enterprise architecture still delegated resource authorization to network topology. Packets arriving from a corporate LAN segment or an authenticated perimeter VPN inherited ambient trust, vendor-signed software updates bypassed behavioral scrutiny, and on-premises federation servers (`AD FS`) bridged Active Directory compromises straight into cloud tenants.

Between December 2020 and December 2021, four cascading global intrusions dismantled every assumption behind perimeter-centric defense. In December 2020, Russian SVR operators (`Midnight Blizzard`, formerly tracked as `Nobelium`, `APT29`, and `UNC2452`) compromised SolarWinds' build pipeline using the `SUNSPOT` implant, injecting the `SUNBURST` backdoor into `SolarWinds.Orion.Core.BusinessLayer.dll` prior to legitimate `Authenticode` signing; the trojanized update reached fewer than `18,000` customers and enabled operators to steal on-premises `AD FS` signing keys and pivot via `Golden SAML` into roughly `100` high-value cloud tenants, including Microsoft's corporate environment [222, 647, 648, 649, 650, 651, 652, 653]. Three months later, in March 2021, `Silk Typhoon` (`HAFNIUM`) exploited Exchange `ProxyLogon` by chaining an unauthenticated front-end `X-BEResource` `SSRF` (`CVE-2021-26855`) into back-end arbitrary file writes (`CVE-2021-27065` and `CVE-2021-26858`, alongside Unified Messaging deserialization flaw `CVE-2021-26857`), dropping `SYSTEM` web shells across `30,000` to `60,000+` organizations directly over inbound `TCP/443` [654, 655, 656, 657, 658, 659, 660].

Internal LAN trust and software dependency assumptions collapsed just as rapidly over the second half of 2021. In June and July 2021, following earlier `PrintDemon` flaws (`CVE-2020-1048` [661]), `PrintNightmare` (`CVE-2021-1675` and `CVE-2021-34527`) in the `MS-RPRN` `RpcAddPrinterDriverEx` interface allowed any low-privilege domain user on the internal network to load a remote UNC driver DLL as `SYSTEM` on Domain Controllers running `spoolsv.exe`, prompting emergency directive `CISA ED 21-04` and `KB5005010` [662, 663, 664, 665, 666]. Then, in December 2021, `Log4Shell` (`CVE-2021-44228`, `CVSS 10.0`, addressed across Log4j `2.16.0-2.17.1`) turned attacker-controlled `${jndi:ldap://...}` strings inside routine application logs into remote code execution across Windows-hosted Java enterprise fleets (`Tomcat`, `vCenter`, `Confluence`), exposing widespread operational blindness over transitive open-source dependencies [667, 668, 669, 670, 671].

The architectural replacement had already been standardized four months before `SUNBURST` came to light. Coined by John Kindervag (*No More Chewy Centers*, 2010 [672]), proven at enterprise production scale by Rory Ward and Betsy Beyer in Google's *BeyondCorp* rollout (2014-2017 [673, 674, 675]), and codified vendor-neutrally in `NIST SP 800-207` (*Zero Trust Architecture*, August 2020) [676], the Zero Trust model was subsequently mandated across U.S. federal agencies under `OMB M-22-09` and `CISA ZTMM v2.0` [677, 678] and operationalized across the Windows-to-Entra stack around three engineering axioms: *Verify Explicitly, Use Least Privilege, Assume Breach* [679].

![Figure: The Zero Trust intellectual lineage. Four origin strands: Kindervag's name (2010), BeyondCorp's production exemplar (2014-17), and Forrester's ZTX taxonomy with Gartner's CARTA continuous-risk framing (2017-18): converge in NIST SP 800-207 (2020), the vendor-neutral synthesis that federal mandates and Microsoft's product guidance then operationalized.](diagrams/13-zero-trust-lineage.svg)

## Architectural Deep Dive

### `NIST SP 800-207` Control and Data Planes (`PDP` and `PEP`)

`NIST SP 800-207` partitions every resource access into an out-of-band Control Plane and an inline Data Plane [676]. Within the Control Plane, a Policy Decision Point (`PDP`), logically comprising a Policy Engine paired with a Policy Administrator, ingests user identity, authentication assurance, device health posture, real-time threat intelligence, and target resource sensitivity to compute a per-transaction grant, step-up, or block verdict. On the Data Plane, a Policy Enforcement Point (`PEP`) sits directly in front of or inside the protected workload, terminating or admitting client requests strictly on the presence of a fresh, cryptographically verifiable authorization assertion issued by the `PDP` [676].

In Microsoft's cloud architecture (following the July 2023 rebranding of Azure Active Directory to Microsoft Entra ID [680, 681]), Entra Conditional Access serves as the centralized `PDP`. Downstream enforcement is distributed across multiple `PEPs`: the Entra Security Token Service (`STS`) refuses to mint tokens when grant conditions fail, first-party resource servers (`Exchange Online`, `SharePoint Online`, `Microsoft Graph`, and `Azure Resource Manager`) enforce audience, scope, and session claims on every API call, and `Global Secure Access` identity-aware proxies mediate private and SaaS network flows [676, 682].

![Figure: Conditional Access, CAE, and the PRT: the cloud-identity decision loop with the NIST SP 800-207 roles named. The PRT strengthens device binding with TPM-protected key material where available; Conditional Access implements the Policy Decision Point role for covered Microsoft Entra decisions; token issuance and the resource server provide Policy Enforcement Point behavior; and Continuous Access Evaluation feeds critical events and policy changes back before ordinary token expiry.](diagrams/13-zero-trust-conditional-access.svg)

### How On-Box Windows Trust Travels Off the Machine as `PDP` Signals

Zero Trust repositions the local Windows security stack from an isolated, self-contained fortress into four continuous, cryptographically anchored signal streams evaluated by Conditional Access whenever an endpoint requests a cloud token:

| On-Box Windows Subsystem | Local Mechanism | Transport to Cloud `PDP` | Entra Sign-In / Policy Claim |
|---|---|---|---|
| Silicon & Boot (`Chapters 1-5`) | `Secure Boot`, `TPM 2.0` / `Pluton` `PCRs`, `WBCL` event log, `VBS`/`HVCI` | `HealthAttestation CSP` → Intune MDM compliance engine | `deviceDetail.isCompliant = true`, `isManaged = true` [683] |
| SSO Device Broker ([Chapter 16](11-pth-prt.md)) | `TPM`-sealed `dk`/`tk` + `CloudAP` `PRT` `PoP` signature (`x-ms-RefreshTokenCredential`) | `WAM` / `cloudap.dll` → `login.microsoftonline.com` | `deviceDetail.deviceId`, `trustType` (`AzureAd` / `ServerAd`), `Token Protection` [535, 551, 684] |
| Passwordless Auth ([Chapter 17](12-hello.md)) | `WHfB` (`NGC`), `ESS` (`BioIso.exe`), `WebAuthn` `rpId`-bound `FIDO2` keys | `PKINIT` / `FIDO2` assertion to Entra `STS` | `authenticationStrength` (`Phishing-resistant MFA`), `amr` claims [559, 677] |
| Host Telemetry ([Chapter 18](28-etw.md)) | `ETW` (`EtwTi`, `AMSI`, `Security-Auditing`) + kernel callbacks (`WdFilter.sys`) | `Sense` → Defender for Endpoint → Defender XDR → Entra ID Protection | `riskLevelDuringSignIn`, `riskLevelAggregated`, Defender machine risk [685, 686, 687] |

Cross-domain telemetry correlation inside Microsoft Defender XDR joins four separate sensor planes (Defender for Endpoint catching `w3wp.exe` spawning `cmd.exe`/`powershell.exe` in `ProxyLogon` [688], Defender for Identity watching DC `4662` `DCSync` SACLs and `AD FS` anomalies [685], Defender for Cloud Apps scoring anomalous OAuth/SAML session behavior [687], and Defender for Office 365), feeding unified device and user risk scores directly back into Conditional Access [686, 689].

![Figure: Defender XDR as the composition primitive. Four product-level Defenders (Endpoint, Identity, Cloud Apps, Office 365) feed one common KQL advanced-hunting and incident-correlation plane that joins four separately triaged alerts into a single cross-domain incident, which can in turn trigger Automated Investigation and Response playbooks spanning product boundaries.](diagrams/13-zero-trust-defender-xdr.svg)

### Conditional Access Evaluation Semantics (`AND` Across Policies, `Block` Wins)

Unlike ordered firewall ACLs that halt at the first matching rule, Entra Conditional Access evaluates every enabled policy across the tenant in parallel through a deterministic two-phase algorithm [682, 690, 691]. During phase one, condition matching tests each policy's `Assignments` (users, groups, directory roles, and workload identities, minus explicit `Exclusions`), `Target Resources` (cloud applications, user actions such as security-info registration, or dynamic Authentication Context labels), and environmental `Conditions`, spanning `Sign-in risk`, `User risk`, `Device platforms`, `Locations`, `Client apps` (isolating legacy Basic Authentication protocols), and attribute-based `Filter for devices` expressions. Every policy whose scope and conditions match enters the active enforcement set.

Phase two aggregates controls across all matched policies under strict explicit-deny and conjunctive-union rules. If even a single matched policy specifies `Block access`, evaluation terminates immediately and refuses the token, regardless of how many other matched policies would permit the session. Otherwise, the caller must satisfy the conjunctive union (`AND`) of every matched `Grant` policy: if Policy A requires `Phishing-resistant MFA` and Policy B requires `Compliant device`, Entra demands both before issuing a token, while multiple controls checked inside a single policy combine according to that policy's `Require all` (`AND`) or `Require one` (`OR`) operator [682, 691]. Finally, matched `Session` controls attach post-issuance constraints directly into the token claims or broker response, governing `Sign-in frequency`, `Persistent browser session` cookies, `Conditional Access App Control` (`MCAS` reverse-proxy inspection), `Token Protection` ([Chapter 16](11-pth-prt.md) [535]), and `Continuous Access Evaluation` ([Chapter 20](14-cae.md) [155]).

### Closing the Build-Server Seam: `SLSA Build Level 3`, `Sigstore`, and `SBOM`

Because `SUNSPOT` injected malicious C# source on SolarWinds' build server before legitimate `Authenticode` signing occurred, endpoint code-integrity checks ([Chapter 7](06-code-integrity.md)) verified the resulting DLL cleanly across all `18,000` victim environments [222, 648, 650].

![Figure: The SUNSPOT-to-SUNBURST chain: from build-time source replacement on the SolarWinds build server to forged cloud tokens via Golden SAML against ADFS.](diagrams/sunburst-golden-saml.svg)

Post-2021 Zero Trust architecture extends explicit verification upstream into software build pipelines under Executive Order `14028` [692, 693]. Standardized machine-readable Software Bills of Materials (`SBOMs` formatted in `SPDX` `ISO/IEC 5962` or `CycloneDX` `ECMA-424` and generated via `sbom-tool`, `syft`, or `trivy`) inventory transitive dependencies [694, 695, 696, 697, 698], while `in-toto` step attestations [699] and OpenSSF `SLSA v1.0` Build Level 3 paired with `Sigstore` bind compiled binaries to isolated, tamper-evident build environments [700, 701, 702]. Under keyless `Sigstore` signing, ephemeral CI runners obtain short-lived workflow-bound OIDC tokens [703], exchange them at the `Fulcio` certificate authority for roughly ten-minute X.509 certificates tied to the exact repository workflow and commit SHA, sign build artifacts and `SLSA` provenance predicates via `cosign` using ephemeral in-memory keys that eliminate stealable long-lived PFX files, and anchor immutable verification entries in the `Rekor` Merkle transparency log [704, 705, 706, 707].

## Attack Catalog & Gap Analysis

Real-world bypasses against Zero Trust architectures target either upstream build and federation roots before Conditional Access runs, unmediated legacy server interfaces, or configuration drift and latency inside the policy plane itself.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `SUNSPOT` / `SUNBURST` → `Golden SAML` (`shimit`, `Midnight Blizzard`) | 2020 | Vendor `Authenticode` build trust & federated `AD FS` → Entra boundary | Compromised vendor CI server; stolen on-prem `AD FS` token-signing cert | Swaps `InventoryManager.cs` during `MsBuild.exe`; steals `AD FS` key to forge SAML assertions bypassing MFA/CA | Adopt `SLSA L3` + `Sigstore`; decommission `AD FS` in favor of native Entra `Cloud Kerberos Trust` ([Chapter 17](12-hello.md)); `MDI` monitoring [647, 650, 651, 685, 702] |
| Pre-Auth Front-End `SSRF` & Legacy `SYSTEM` RPC (`ProxyLogon`, `PrintNightmare`) | 2021 | Server-side proxy auth (`CVE-2021-26855`) & DC `spoolsv.exe` (`CVE-2021-34527`) | HTTPS reach to Exchange or domain user RPC reach to DC Spooler | Forges `X-BEResource` cookie to hit Exchange back-end as `SYSTEM`, or loads UNC driver via `RpcAddPrinterDriverEx` | Retire internet-facing legacy servers behind Zero Trust proxies; disable `Spooler` on DCs (`ED 21-04`, `KB5005010`) [657, 664, 665, 666] |
| Transitive Dependency RCE (`Log4Shell` `CVE-2021-44228`, `3CX`, `MOVEit`) | 2021-2024 | Application memory & outbound egress inside Windows Server fleets | Untrusted string logged by `Log4j 2.x` (`< 2.16.0`) with outbound LDAP/RMI egress | Injects `${jndi:ldap://...}` loading remote Java bytecode under `SYSTEM`/service identity | Enforce egress filtering, least-privilege service accounts (`gMSA`/`dMSA`), and continuous `SBOM` vulnerability indexing [667, 669, 695, 708, 709] |
| Conditional Access Policy Drift & Exclusion Gaps (`CAOptics`, `AzureHound`) | Persistent | Completeness of `PDP` policy coverage across apps/users | Over-broad `Exclude` groups, `Report-only` policies, or legacy resource gaps | Authenticates via excluded client app, guest user path, or unguarded service principal | Continuously audit `PDP` state as code using `Maester` (`What-If` API), `CAOptics`, and `BloodHound CE` / `AzureHound` [710, 711, 712, 713] |
| MDM Compliance Latency & Rogue Device Registration (`roadtx`) | 2021-present | Freshness and authenticity of `deviceDetail.isCompliant` | Unblocked personal device enrollment or newly infected compliant host | Enrolls attacker VM via phished MFA or operates during Intune's periodic compliance re-evaluation lag | Restrict device enrollment via hardware `TPM` attestation; wire real-time Defender EDR risk directly into CA [553, 683, 686] |
| Cloud IdP Signing-Key Compromise (`Storm-0558`) | 2023 | Root cryptographic authenticity of `PDP`/`STS` assertions | Stolen IdP signing key + cross-realm key-validation flaw | Forges cloud access tokens directly so `PEPs` accept requests never evaluated by Conditional Access | HSM-isolated per-realm signing keys, strict `kid`/issuer separation, anomaly hunting ([Chapter 23](15-storm0558.md)) [687, 714] |

### Why Federated Bridges (`Golden SAML`) Bypass Conditional Access

During the `SolarWinds` intrusion, once `Midnight Blizzard` extracted victim organizations' on-premises `AD FS` token-signing private keys, they minted arbitrary SAML 2.0 assertions (`Golden SAML` [651, 715]) offline, claiming both user identity and completed multi-factor authentication (`authnmethodsreferences`) without touching a Domain Controller or prompting a user [653, 716]. Because Entra ID trusted the federated `AD FS` signing certificate for that domain, Entra exchanged the forged SAML assertion for valid cloud tokens. Migrating away from federated on-premises `AD FS` to cloud-native authentication (`WHfB` / `FIDO2` + `Cloud Kerberos Trust`, [Chapter 17](12-hello.md)) removes that on-premises federation key from the cloud `TCB` entirely [577, 653].

### Single-Vendor Homogeneous Stacks vs. Multi-Vendor Seams

Enterprise deployments instantiate `NIST SP 800-207` across three competing patterns: Microsoft Full-Stack (Entra ID + Intune + Defender XDR + Global Secure Access [679, 689, 717]), Best-of-Breed Multi-Vendor (e.g., Okta/Ping + CrowdStrike + Zscaler/Palo Alto [718]), and Federal `CISA ZTMM v2.0` / `OMB M-22-09` Baselines [677, 678, 719]. Single-vendor integration eliminates cross-vendor schema friction (such as real-time Defender XDR → Conditional Access risk signaling), yet concentrates supply-chain and orchestration-plane risk inside a single provider, a tension highlighted when `Midnight Blizzard` accessed subsets of Microsoft source repositories in late 2020 [653] and later during `Storm-0558` ([Chapter 23](15-storm0558.md)) [714].

## Theoretical Limits & Structural Invariants

### Thompson's Trusting Trust (1984) and Rice's Theorem (1953) Bound Provenance and `SBOM`

Two foundational results in computer science bound what build provenance, static inventory, and device compliance attestations can ever prove. In his 1984 Turing Award lecture, Ken Thompson demonstrated that a subverted compiler or lower-layer build toolchain can inject self-reproducing backdoors into compiled binaries that leave zero trace in the audited source repository [720, 721]. `SLSA Build Level 3` narrows that exposure by cryptographically proving *which hardened, isolated build service compiled a specific commit*, forcing an adversary higher up the infrastructure stack, yet it cannot eliminate residual trust in the build platform's own silicon, hypervisor, and bootstrap compiler binary [701, 702].

A parallel boundary follows from Rice's Theorem (1953) and Fred Cohen's 1984 proof of the undecidability of viral detection: any non-trivial semantic property of an arbitrary program's runtime behavior is undecidable by static inspection [722]. An accurate `SBOM` joined against a vulnerability database decidably answers syntactic membership queries such as whether a server image contains `log4j-core 2.14.1`, compressing fleet-wide incident triage from weeks into minutes. Neither a static `SBOM`, a valid `Authenticode` signature, nor an Intune `isCompliant: true` claim, however, can prove that an unknown or freshly trojanized binary will behave benignly once loaded into memory.

### Decoupling Point-in-Time Policy Evaluation from Continuous Post-Issuance Validity

Evaluating every Zero Trust signal correctly at token issuance (`t = 0`) neither protects the orchestration plane itself nor revokes a bearer token when reality changes at `t = 1` minute.

> **Key idea.**
> Zero Trust centralizes access governance into the `PDP` (`Conditional Access`) and `STS`. That centralization creates two structural invariants: first, the orchestration-plane paradox, where stealing the IdP's signing key (`Golden SAML` or `Storm-0558`) lets downstream `PEPs` cryptographically trust assertions the `PDP` never approved (`Assume Breach` [679, 714]); second, temporal decay, where an OAuth access token minted for a compliant, low-risk laptop at `09:00` remains a valid bearer credential until `10:00` even if the user is terminated or Defender detects `Mimikatz` at `09:02`, unless an active revocation channel intervenes ([Chapter 20](14-cae.md)).

## Inspecting and Verifying on a Running System

Operational verification joins three concrete surfaces: the endpoint's local `DeviceId` and `TPM`-backed `PRT` state, the cloud Microsoft Graph `signIns` record confirming `isCompliant` and `appliedConditionalAccessPolicies`, and automated `What-If` policy-drift testing.

### Inspecting Local `DeviceId`, `TPM` Protection, and `PRT` Authority

Extract the endpoint's Entra `DeviceId` (the exact primary key evaluated by Conditional Access), `TPM` key provider status, and `PRT` update state [551, 684]:

```powershell
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|DeviceId|KeyProvider|TpmProtected|DeviceAuthStatus|AzureAdPrt |AzureAdPrtUpdateTime'
```

Expected output:

```text
    AzureAdJoined : YES
    DomainJoined : NO
    DeviceId : 00aa00aa-bb11-cc22-dd33-44ee44ee44ee
    KeyProvider : Microsoft Platform Crypto Provider
    TpmProtected : YES
    DeviceAuthStatus : SUCCESS
    AzureAdPrt : YES
    AzureAdPrtUpdateTime : 2026-04-12 15:20:04.000 UTC
```

### Verifying Cloud `PDP` Evaluation via Microsoft Graph `auditLogs/signIns`

Using the `Microsoft.Graph` PowerShell SDK (`AuditLog.Read.All`), verify that the local `DeviceId` arrived in `deviceDetail`, passed MDM compliance (`isCompliant: true`), and triggered the intended Conditional Access `Grant` and `Session` controls [683, 690, 691]:

```powershell
Get-MgAuditLogSignIn -Filter "deviceDetail/deviceId eq '00aa00aa-bb11-cc22-dd33-44ee44ee44ee'" -Top 1 |
    Select-Object UserPrincipalName, AppDisplayName, ConditionalAccessStatus,
        @{N='Compliant';E={$_.DeviceDetail.IsCompliant}},
        @{N='Policies';E={($_.AppliedConditionalAccessPolicies | Where-Object Result -eq 'success').DisplayName -join ', '}}
```

Expected output confirming end-to-end signal evaluation:

```text
UserPrincipalName AppDisplayName         ConditionalAccessStatus Compliant Policies
----------------- --------------         ----------------------- --------- --------
alice@contoso.com Microsoft Exchange ... success                      True Require-PhishingResistantMFA-And-CompliantDevice
```

### Auditing Conditional Access Policy Completeness with `Maester`

Run `Maester` against the tenant (`Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess` for `What-If` simulation) to detect exclusion loopholes, legacy-auth gaps, or policies stranded in `Report-only` mode [711, 723, 724]:

```powershell
Connect-Maester
Invoke-Maester -Tag 'CA', 'CISA' -OutputHtmlFile .\maester-zt-audit.html
```

## Summary & Handoff

Zero Trust replaces network-location privilege with explicit, per-transaction policy evaluation (`NIST SP 800-207`), converting every local Windows security mechanism (`TPM` and `Pluton` boot measurements, `VBS` and `HVCI` kernel integrity, `CloudAP` `PRTs`, `WHfB` and `WebAuthn` phishing-resistant credentials, and `ETW`-fed Defender XDR risk scores) into cryptographic and behavioral signals adjudicated by Microsoft Entra Conditional Access and reinforced upstream by `SLSA Build Level 3` and `SBOM` provenance. Point-in-time (`t = 0`) authorization at token issuance, however, still leaves critical post-issuance and infrastructure boundaries open across the cloud stack. [Continuous Access Evaluation (Chapter 20)](14-cae.md) addresses temporal session decay (`t > 0`), showing how Entra ID and cooperating `PEPs` invalidate active OAuth bearer tokens within minutes of account disablement, credential reset, IP shift, or elevated identity risk. Further down the cloud stack, [Confidential VMs (Chapter 22)](29-confidential-vms.md) removes the cloud host hypervisor itself from the workload trusted computing base using `AMD SEV-SNP`, `Intel TDX`, and attested `vTPM` key release, before [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md) examines what happens when the cloud identity provider's own signing root leaks and cross-realm token validation fails.
