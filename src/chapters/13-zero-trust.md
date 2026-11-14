# Zero Trust

## Overview

* **Role in the Chain:** Translates every on-box hardware, kernel, credential, and telemetry link (`Chapters 1-18`) into explicit, cryptographically bound policy inputs evaluated by a cloud Policy Decision Point (`PDP`, Microsoft Entra Conditional Access) and enforced by downstream Policy Enforcement Points (`PEPs`) regardless of network location.
* **Core Security Invariant:** Network presence (`LAN` or `VPN`) confers zero implicit authority; access to any resource requires simultaneous satisfaction of every matching Conditional Access policy across user identity, authentication strength (`AAL2`/`AAL3`), attested device identity and compliance (`PRT` + Intune MDM), behavioral risk (`Defender XDR` + Entra ID Protection), and session binding.
* **Trusted Computing Base (TCB):** Entra ID token-signing keys, federated SAML/WS-Trust trust anchors (`AD FS`), the Conditional Access evaluation engine and administrator policy graph, `TPM`-bound device registration keys (`dk`/`tk`), the Intune/MDM compliance pipeline, and software build provenance (`SLSA` / `Authenticode`).
* **Primary Failure Modes:** Pre-signature build-pipeline injection paired with federated signing-key theft (`SUNSPOT` / `SUNBURST` → `Golden SAML`), pre-authenticated front-end `SSRF` (`ProxyLogon`) or legacy `SYSTEM` RPC (`PrintNightmare`), Conditional Access policy exclusions and permutation drift, MDM compliance sync latency, unbound post-issuance token replay, and cloud IdP signing-key compromise (`Storm-0558`).
* **Handoff:** Establishes point-in-time (`t = 0`) multi-signal cloud authorization; hands mid-session (`t > 0`) revocation to [Continuous Access Evaluation (Chapter 20)](14-cae.md), cloud hypervisor isolation to [Confidential VMs (Chapter 22)](29-confidential-vms.md), and IdP root-key compromise analysis to [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).

## Core Engineering Problem & Threat Model

Parts I through III hardened the individual Windows endpoint: `Secure Boot` and `Measured Boot` anchor firmware (`Chapters 1, 4`), `VBS` and `HVCI` isolate `VTL1` secrets and kernel code (`Chapters 6, 7, 12`), `WHfB` and `WebAuthn` eliminate shared passwords ([Chapter 17](12-hello.md)), and `ETW` / `EtwTi` stream host telemetry ([Chapter 18](28-etw.md)). Yet throughout the 2010s, enterprise networks still delegated access authority to network topology: packets originating inside the corporate LAN or across a perimeter VPN inherited ambient trust, vendor-signed updates bypassed behavioral scrutiny, and federated identity servers (`AD FS`) bridged on-premises Active Directory straight into cloud tenants.

Between December 2020 and December 2021, four cascading global incidents invalidated every pillar of perimeter-centric security:
1. **SolarWinds `SUNSPOT` / `SUNBURST` (December 2020):** Russian SVR operators (`Midnight Blizzard`, formerly `Nobelium` / `APT29` / `UNC2452`) compromised SolarWinds' build server (`SUNSPOT`), injecting the `SUNBURST` backdoor into `SolarWinds.Orion.Core.BusinessLayer.dll` *before* legitimate `Authenticode` signing, reaching `< 18,000` customers and pivoting via `Golden SAML` against `AD FS` into roughly `100` high-value cloud tenants (including Microsoft's own corporate environment) [222, 647, 648, 649, 650, 651, 652, 653].
2. **Exchange `ProxyLogon` (March 2021):** `Silk Typhoon` (`HAFNIUM`) chained an unauthenticated front-end `X-BEResource` `SSRF` (`CVE-2021-26855`) into back-end arbitrary file writes (`CVE-2021-27065` / `CVE-2021-26858`, alongside parallel Unified Messaging deserialization `CVE-2021-26857`), dropping `SYSTEM` web shells across `30,000-60,000+` organizations directly through HTTPS `TCP/443` [654, 655, 656, 657, 658, 659, 660].
3. **`PrintNightmare` (June-July 2021):** Following `PrintDemon` (`CVE-2020-1048` [661]), `CVE-2021-1675` and `CVE-2021-34527` in `MS-RPRN` `RpcAddPrinterDriverEx` allowed any authenticated domain user to load a UNC driver DLL as `SYSTEM` on Domain Controllers running `spoolsv.exe` (`CISA ED 21-04`, `KB5005010`) [662, 663, 664, 665, 666].
4. **`Log4Shell` (December 2021):** `CVE-2021-44228` (`CVSS 10.0`, followed by `2.16.0-2.17.1` patches) turned `${jndi:ldap://...}` strings inside Apache Log4j 2.x into remote code execution across Windows-hosted Java enterprise fleets (`Tomcat`, `vCenter`, `Confluence`), exposing total blindness over transitive software dependencies [667, 668, 669, 670, 671].

The architectural replacement was already standardized four months before `SUNBURST` broke (`diagrams/13-zero-trust-lineage.svg`): coined by John Kindervag (*No More Chewy Centers*, 2010 [672]), demonstrated at Google scale by Rory Ward and Betsy Beyer (*BeyondCorp*, 2014-2017 [673, 674, 675]), and codified vendor-neutrally in **`NIST SP 800-207` (*Zero Trust Architecture*, August 2020)** [676], subsequently mandated across U.S. federal agencies by `OMB M-22-09` and `CISA ZTMM v2.0` [677, 678] and operationalized by Microsoft as *Verify Explicitly, Use Least Privilege, Assume Breach* [679].

![Figure: The Zero Trust intellectual lineage. Four origin strands: Kindervag's name (2010), BeyondCorp's production exemplar (2014-17), and Forrester's ZTX taxonomy with Gartner's CARTA continuous-risk framing (2017-18): converge in NIST SP 800-207 (2020), the vendor-neutral synthesis that federal mandates and Microsoft's product guidance then operationalized.](diagrams/13-zero-trust-lineage.svg)

## Architectural Deep Dive

### `NIST SP 800-207` Control and Data Planes (`PDP` and `PEP`)

`NIST SP 800-207` divides every resource transaction into an out-of-band Control Plane and an inline Data Plane [676]:
* **Policy Decision Point (`PDP` = Policy Engine + Policy Administrator):** Ingests identity, device posture, threat intelligence, and data sensitivity rules to compute a per-request grant, step-up, or block verdict and instruct the enforcement layer to establish or tear down session credentials.
* **Policy Enforcement Point (`PEP`):** Sits directly in front of (or inside) the target resource, refusing any connection lacking a fresh, cryptographically valid `PDP` authorization assertion.

In Microsoft's cloud architecture (`diagrams/13-zero-trust-conditional-access.svg`, where *Azure AD* was renamed Microsoft Entra ID in July 2023 [680, 681]), Entra Conditional Access implements the `PDP`, while Entra Security Token Service (`STS`) token issuance, resource servers (`Exchange Online`, `SharePoint Online`, `Microsoft Graph`, `Azure Resource Manager`), and `Global Secure Access` proxies act as `PEPs` [676, 682].

![Figure: Conditional Access, CAE, and the PRT: the cloud-identity decision loop with the NIST SP 800-207 roles named. The PRT strengthens device binding with TPM-protected key material where available; Conditional Access implements the Policy Decision Point role for covered Microsoft Entra decisions; token issuance and the resource server provide Policy Enforcement Point behavior; and Continuous Access Evaluation feeds critical events and policy changes back before ordinary token expiry.](diagrams/13-zero-trust-conditional-access.svg)

### How On-Box Windows Trust Travels Off the Machine as `PDP` Signals

Zero Trust demotes the local Windows security stack from a self-sufficient fortress into four verifiable signal streams consumed by Conditional Access during every token request:

| On-Box Windows Subsystem | Local Mechanism | Transport to Cloud `PDP` | Entra Sign-In / Policy Claim |
|---|---|---|---|
| Silicon & Boot (`Chapters 1-5`) | `Secure Boot`, `TPM 2.0` / `Pluton` `PCRs`, `WBCL` event log, `VBS`/`HVCI` | `HealthAttestation CSP` → Intune MDM compliance engine | `deviceDetail.isCompliant = true`, `isManaged = true` [683] |
| SSO Device Broker ([Chapter 16](11-pth-prt.md)) | `TPM`-sealed `dk`/`tk` + `CloudAP` `PRT` `PoP` signature (`x-ms-RefreshTokenCredential`) | `WAM` / `cloudap.dll` → `login.microsoftonline.com` | `deviceDetail.deviceId`, `trustType` (`AzureAd` / `ServerAd`), `Token Protection` [535, 551, 684] |
| Passwordless Auth ([Chapter 17](12-hello.md)) | `WHfB` (`NGC`), `ESS` (`BioIso.exe`), `WebAuthn` `rpId`-bound `FIDO2` keys | `PKINIT` / `FIDO2` assertion to Entra `STS` | `authenticationStrength` (`Phishing-resistant MFA`), `amr` claims [559, 677] |
| Host Telemetry ([Chapter 18](28-etw.md)) | `ETW` (`EtwTi`, `AMSI`, `Security-Auditing`) + kernel callbacks (`WdFilter.sys`) | `Sense` → Defender for Endpoint → Defender XDR → Entra ID Protection | `riskLevelDuringSignIn`, `riskLevelAggregated`, Defender machine risk [685, 686, 687] |

Cross-domain telemetry correlation inside Microsoft Defender XDR (`diagrams/13-zero-trust-defender-xdr.svg`) joins four separate sensor planes (Defender for Endpoint catching `w3wp.exe` spawning `cmd.exe`/`powershell.exe` in `ProxyLogon` [688], Defender for Identity watching DC `4662` `DCSync` SACLs and `AD FS` anomalies [685], Defender for Cloud Apps scoring anomalous OAuth/SAML session behavior [687], and Defender for Office 365), feeding unified device and user risk scores directly back into Conditional Access [686, 689].

![Figure: Defender XDR as the composition primitive. Four product-level Defenders (Endpoint, Identity, Cloud Apps, Office 365) feed one common KQL advanced-hunting and incident-correlation plane that joins four separately triaged alerts into a single cross-domain incident, which can in turn trigger Automated Investigation and Response playbooks spanning product boundaries.](diagrams/13-zero-trust-defender-xdr.svg)

### Conditional Access Evaluation Semantics (`AND` Across Policies, `Block` Wins)

Unlike firewall rule lists that stop at the first matching row, Entra Conditional Access evaluates every enabled policy in parallel in a deterministic two-phase algorithm [682, 690, 691]:
1. **Condition Matching:** Evaluates `Assignments` (users, groups, directory roles, workload identities, minus explicit `Exclusions`), `Target Resources` (cloud apps, user actions, or dynamic Authentication Context labels), and `Conditions` (`Sign-in risk`, `User risk`, `Device platforms`, `Locations`, `Client apps` blocking legacy Basic Auth, and `Filter for devices`).
2. **Control Aggregation:**
   * **Explicit Deny Precedence:** If *any* matched policy specifies `Block access`, the entire transaction terminates immediately, even if ten other matched policies grant access.
   * **Conjunctive Union Across Policies:** Every matched `Grant` policy must be satisfied (`Policy A` requiring `Phishing-resistant MFA` + `Policy B` requiring `Compliant device` forces the caller to satisfy *both*). Within a single policy, administrators select whether multiple checked controls combine via `Require all` (`AND`) or `Require one` (`OR`).
   * **Session Controls:** Attach constraints stamped into the issued token or broker response: `Sign-in frequency`, `Persistent browser session`, `Conditional Access App Control` (`MCAS` reverse proxy), `Token Protection` ([Chapter 16](11-pth-prt.md) [535]), and `Continuous Access Evaluation` ([Chapter 20](14-cae.md) [155]).

### Closing the Build-Server Seam: `SLSA Build Level 3`, `Sigstore`, and `SBOM`

Because `SUNSPOT` injected malicious C# source on SolarWinds' build server *before* legitimate `Authenticode` signing (`diagrams/sunburst-golden-saml.svg`), endpoint code-integrity verification ([Chapter 7](06-code-integrity.md)) passed on all `18,000` victim networks [222, 648, 650].

![Figure: The SUNSPOT-to-SUNBURST chain: from build-time source replacement on the SolarWinds build server to forged cloud tokens via Golden SAML against ADFS.](diagrams/sunburst-golden-saml.svg)

Post-2021 Zero Trust extends explicit verification upstream into CI/CD pipelines via Executive Order `14028` [692, 693], machine-readable Software Bills of Materials (`SBOMs` in `SPDX` `ISO/IEC 5962` or `CycloneDX` `ECMA-424` via `sbom-tool`, `syft`, `trivy`) [694, 695, 696, 697, 698], `in-toto` step attestations [699], and OpenSSF `SLSA v1.0` Build Level 3 paired with `Sigstore` [700, 701, 702]:
* Ephemeral CI runners obtain short-lived workflow-bound OIDC tokens [703], exchange them at `Fulcio` for ~10-minute X.509 certificates tied to the exact repository workflow and commit SHA, sign artifacts and provenance predicates via `cosign` with ephemeral in-memory keys (eliminating stealable long-lived code-signing PFX files), and record immutable timestamps in the `Rekor` Merkle transparency log [704, 705, 706, 707].

## Attack Catalog & Gap Analysis

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

Two classical computer-science results bound what supply-chain and compliance attestations can ever prove:
1. **Thompson's Compiler Subversion (1984):** Ken Thompson proved that a compromised compiler or lower-layer build toolchain can inject self-propagating backdoors invisible in source code [720, 721]. `SLSA Build Level 3` proves *which hardened build service compiled a commit*, pushing the attacker higher up the tree, but cannot eliminate trust in the build platform's own hardware and compiler binary [701, 702].
2. **Rice's Theorem (1953) and Cohen's Undecidability of Viral Behavior (1984):** Any non-trivial semantic behavior of an arbitrary program is undecidable [722]. An `SBOM` + CVE database decidably answers *"does this host run `log4j-core 2.14.1`?"* (turning weeks of incident triage into minutes), but no static `SBOM`, `Authenticode` signature, or Intune `isCompliant: true` boolean can prove that an unknown or freshly trojanized binary behaves benignly at runtime.

### Decoupling Point-in-Time Policy Evaluation from Continuous Post-Issuance Validity

Consistent with Law 16, evaluating every Zero Trust signal correctly at token issuance (`t = 0`) neither protects the orchestration plane itself nor revokes a bearer token when reality changes at `t = 1` minute.

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

Zero Trust replaces network-location privilege with explicit, per-transaction policy evaluation (`NIST SP 800-207`), converting every local Windows security mechanism (`TPM`/`Pluton` boot measurements, `VBS`/`HVCI` integrity, `CloudAP` `PRTs`, `WHfB`/`WebAuthn` phishing-resistant keys, and `ETW`/Defender XDR risk scores) into cloud inputs adjudicated by Microsoft Entra Conditional Access and reinforced upstream by `SLSA Build Level 3` and `SBOM` provenance. Yet point-in-time (`t = 0`) policy decisions leave three acute cloud boundaries unresolved, forming the final three chapters of this book:

* **Closing the Post-Issuance Bearer-Token Window (`t > 0`):** How Entra ID and participating `PEPs` invalidate active OAuth access tokens within minutes of user disablement, credential change, IP shift, or elevated risk is the subject of [Continuous Access Evaluation (Chapter 20)](14-cae.md).
* **Removing the Cloud Hypervisor from the Guest `TCB`:** How Azure Confidential VMs (`AMD SEV-SNP` and `Intel TDX` + `vTPM`) protect Windows workloads even from a compromised cloud host belongs to [Confidential VMs (Chapter 22)](29-confidential-vms.md).
* **When the Cloud Identity Provider's Own Signing Key Leaks:** Dissecting how `Storm-0558` forged cross-realm enterprise tokens (the cloud structural twin of `Golden SAML` and `krbtgt` compromise) closes the manuscript in [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).
