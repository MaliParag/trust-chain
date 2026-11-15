# Pass-the-Hash to Pass-the-PRT

## Overview

* **Role in the Chain:** Maps the 29-year structural evolution of Windows credential-replay tradecraft (`Pass-the-Hash` → `Pass-the-Ticket` → `Overpass-the-Hash` → `Pass-the-Certificate` → `Pass-the-PRT`) from on-premises `LSASS` symmetric secrets ([Chapter 12](08-credential-guard.md)) and `AD CS` PKI keys ([Chapter 15](31-enterprise-pki.md)) to Microsoft Entra ID Primary Refresh Tokens (`PRTs`) brokered by `cloudap.dll`.
* **Core Security Invariant:** Preventing cross-machine credential replay requires three simultaneous guarantees: hardware-bound non-exportability of the root secret (`TPM 2.0` / `VTL1` `LsaIso`), isolation of every in-use derived signing context inside the local broker, and mandatory cryptographic proof-of-possession (`PoP`) verification at every downstream resource server.
* **Trusted Computing Base (TCB):** `TPM 2.0` (`Microsoft Platform Crypto Provider` device and transport keys), `LsaIso.exe` (`VTL1`), `cloudap.dll` in `VTL0` `lsass.exe`, Web Account Manager (`WAM` / `TokenBroker`), `AD CS` issuing CAs (`KB5014754`), and Microsoft Entra ID Conditional Access (`Token Protection` and `CAE`).
* **Primary Failure Modes:** Substituting `NTOWF` hashes or `.kirbi` tickets into `LSASS`, abusing `AD CS` `ESC1-ESC16` enrollment/ACL/relay misconfigurations or `Schannel` `LDAPS` client-cert fallback, and extracting or coercing `VTL0` `CloudAP` derived context keys (`dpapi::cloudapkd` / `roadtx prt`) to mint `x-ms-RefreshTokenCredential` SSO cookies accepted by unbound web and SaaS endpoints.
* **Handoff:** Demonstrates why isolating credential *storage* fails whenever *in-use derivation* or *downstream verification* remains unbound; hands asymmetric password replacement to [Windows Hello and Passkeys (Chapter 17)](12-hello.md), telemetry over `LSASS`/`CloudAP` handle access to [ETW: The EDR Substrate (Chapter 18)](28-etw.md), and verifier-side policy and revocation to [Zero Trust (Chapter 19)](13-zero-trust.md) and [Continuous Access Evaluation (Chapter 20)](14-cae.md).

## Core Engineering Problem & Threat Model

Across three decades of Windows enterprise architecture, five named offensive techniques (`Pass-the-Hash`, `Pass-the-Ticket`, `Overpass-the-Hash`, `Pass-the-Certificate`, and `Pass-the-PRT`) instantiate a single structural theorem: any reusable authentication proof or key-derivation context reachable by the software process that consumes it can be replayed from another host unless both the in-use derivation path is hardware-isolated and the verifier enforces cryptographic channel or device binding.

Paul Ashton proved the theorem in April 1997 with a 5-line `smbclient` diff (`Exploit-DB 19197`) feeding a stored LanMan/NT hash straight into SMB challenge encryption without knowing the cleartext password [531]. Eleven years later, Hernan Ochoa's *Pass-the-Hash Toolkit* (`iam.exe`, 2008) moved that substitution inside live Windows `lsass.exe` memory (`PROCESS_VM_WRITE`) so native OS tools (`net.exe`, `sc.exe`, `wmic`, `DCOM`) inherited the replayed identity transparently [532, 533, 534]. Every subsequent defensive milestone (`Protected Users` and `RunAsPPL` in 2013-2014 [292, 431, 435], `Credential Guard` / `LsaIso.exe` in `VTL1` in 2015 [69], `KB5014754` strong certificate mapping in 2022-2025 [501], and Entra `Token Protection` in 2023-2025 [535]) closed one storage class or verifier path while leaving adjacent credentials exposed (`diagrams/11-pth-prt-storage-class-ladder.svg`).

![Figure: The storage-class progression as a layered staircase, read as gap analysis. Each defense relocates the long-term secret inward to a stronger boundary: on-disk SAM to the lsass.exe cache to the LsaIso VTL1 trustlet to a TPM/VSC key container, and the family targets the next artifact just outside it. The bottom rung is the crux: the CloudAP-held PRT and its session key live in VTL0 LSASS outside Credential Guard's scope, with only the device/transport keys TPM-sealed at rest, so an attacker with local admin can extract and replay them.](diagrams/11-pth-prt-storage-class-ladder.svg)

The threat model assumes an adversary who has already obtained local administrative (`SYSTEM`) execution in `VTL0` on an enterprise workstation (via phishing, local exploit, or service impersonation as analyzed in [Chapter 10](25-access-control.md)) on a fully patched Windows 11 host running `HVCI`, `Credential Guard`, and `KB5014754` enforcement. Even when `sekurlsa::logonpasswords` returns zero `NTOWF` hashes and zero exportable `TGT` session keys ([Chapter 12](08-credential-guard.md)), the attacker pivots to the two credential families operating outside `LsaIso`'s classic Active Directory scope: X.509 client certificates (`AD CS`) and Microsoft Entra ID Primary Refresh Tokens (`PRTs`) [69, 454, 536, 537].

## Architectural Deep Dive

### Generations 1-3: On-Premises `LSASS` Hash and Ticket Substitution

The first three generations of credential-replay tradecraft targeted symmetric Active Directory secrets co-resident inside `VTL0` `lsass.exe`. Generation 1 (`Pass-the-Hash`, 1997 and 2008) injects an `NTOWF` digest (`MD4(UTF-16LE(password))`) into an `msv1_0` logon session (`iam.exe` or `sekurlsa::pth`) so outbound `NTLMv2` `HMAC-MD5` responses authenticate without cleartext [459, 531, 534]. Ironically, Microsoft's 2013-2014 Restricted Admin RDP mode (`KB2871997`), introduced to prevent interactive administrators from stranding cleartext or hash material on untrusted jump hosts, simultaneously weaponized `Pass-the-Hash` over `mstsc.exe /restrictedadmin` (`BloodHound` `CanRDP`) [431, 538, 539].

Generation 2 (`Pass-the-Ticket`, 2011-2014) pivoted from `NTLM` to Kerberos: `sekurlsa::tickets` extracts `.kirbi` `TGT` and service-ticket blobs paired with their session keys $K_{c,\text{tgs}}$, and `kerberos::ptt` or `Rubeus` injects them into another session via the documented `LsaCallAuthenticationPackage` (`KerbSubmitTicketMessage`) API [525, 540, 541]. Note the historical causality: `Pass-the-Ticket` (2011-2014) *predated* `Credential Guard` (2015) simply because `TGTs` sat unprotected beside `NTOWF` inside `LSASS` [283, 525]. Generation 3 (`Overpass-the-Hash` or `Pass-the-Key`, 2014) bridged the two protocols by exploiting `RFC 4757` (`enctype 23` `RC4-HMAC`, [Chapter 14](10-kerberos.md)), promoting a stolen `NTOWF` hash or extracted `AES-256` long-term key into a live `AS-REQ` pre-authentication proof so the `KDC` mints a genuine, fresh `TGT` accepted by Kerberos-only targets [504, 542, 543].

On hardware-eligible non-DC endpoints running Credential Guard ([Chapter 12](08-credential-guard.md)), `NTOWF` hashes and `TGT` session keys move into `VTL1` `LsaIso.exe`, closing *local memory extraction* of Generations 1-3 while leaving `SAM`/`ntds.dit`/`DCSync` secrets, X.509 private keys, and cloud SSO tokens outside its boundary [69].

### Generation 4: `Pass-the-Certificate` and the `AD CS` `ESC1-ESC16` Surface

When symmetric domain secrets moved into `VTL1`, Will Schroeder and Lee Christensen (*Certified Pre-Owned*, June 2021) demonstrated that enterprise Active Directory Certificate Services (`AD CS`) templates routinely issue long-lived authentication credentials outside `Credential Guard`'s protection [454, 544]. Once an attacker obtains an X.509 certificate and usable private key, either enrolled directly into software or exported from non-TPM `CryptoAPI`/`CNG` storage, two wire-level replay paths open against the domain. Over Kerberos `PKINIT` (`RFC 4556`), presenting the signed `PA-PK-AS-REQ` to the `KDC` yields a `TGT` for the principal mapped by the certificate and optionally recovers the account's underlying `NTOWF` hash via `PKINIT` `PAC_CREDENTIAL_INFO` ("UnPAC-the-Hash") [499, 545]. Even when Domain Controllers lack `PKINIT` support (`KDC_ERR_PADATA_TYPE_NOSUPP`), Yannick Meheut's `PassTheCert` technique (May 2022) authenticates directly to `LDAPS` (`TCP/636`) via `Schannel` TLS client-certificate authentication and modifies directory ACLs (`RBCD` or `DCSync` grants) without requesting a `TGT` at all [546, 547].

While Microsoft's `KB5014754` (enforced September 9, 2025) patched SAN/UPN/`dNSHostName` spoofing (`Certifried` `CVE-2022-26923`, `CVE-2022-26931`, `CVE-2022-34691`) by requiring strong `SID` mapping via OID `1.3.6.1.4.1.311.25.2` [489, 501], the broader `ESC1-ESC16` taxonomy (`Certipy` / `Microsoft Defender for Identity`) remains an administrative hardening problem: permissive SAN templates (`ESC1`/`ESC2`), enrollment-agent abuse (`ESC3`), writable template/CA ACLs (`ESC4`/`ESC7`), HTTP/RPC `NTLM` relay (`ESC8`/`ESC11`), and templates or CAs explicitly setting `CT_FLAG_NO_SECURITY_EXTENSION` (`ESC9`/`ESC16`), which strips the `KB5014754` SID extension by design [501, 545, 548, 549, 550].

### Generation 5: Entra Device Join, `CloudAP`, `WAM`, and the `PRT` Architecture

On Entra-joined and Hybrid-joined Windows 10/11 endpoints, cloud Single Sign-On bypasses `msv1_0` and `kerberos.dll`, flowing instead through two user-mode components: the Web Account Manager (`WAM`, `TokenBroker` svchost + `Microsoft.AAD.BrokerPlugin`) in the user session and the Cloud Authentication Provider (`cloudap.dll`) authentication package loaded inside `VTL0` `lsass.exe` [536, 537, 551].

Device registration (`dsregcmd`) provisions two asymmetric RSA keys inside the `Microsoft Platform Crypto Provider` (`TPM 2.0`): a Device Key (`dk`) backing the X.509 device identity certificate, and a Transport Key (`tk` / `stk`) used by Entra ID to encrypt secrets bound to that specific chassis [551]. Upon user sign-in (via Windows Hello or password), Entra ID issues a Primary Refresh Token (`PRT`) valid for 90 days on a rolling activity window, paired with a symmetric PRT Session Key (`HMAC-SHA256`) encrypted under the TPM-bound Transport Key [536, 551].

Whenever Edge, Office, Teams, or `WAM` requests Entra ID Single Sign-On, `cloudap.dll` executes a proof-of-possession (`PoP`) exchange [536, 537, 552]:
1. **Challenge Request:** The client requests a server-generated `Nonce` from `login.microsoftonline.com` (`POST` `grant_type=srv_challenge`).
2. **Derived Context Key & `x-ms-RefreshTokenCredential` Construction:** Rather than sending the raw `PRT` in cleartext, `cloudap.dll` derives a 32-byte `KDF` context key from the `PRT` Session Key (using a random 24-byte `ctx` context value) and signs an `HS256` JSON Web Token (`x-ms-RefreshTokenCredential` SSO cookie) containing `{"refresh_token": "<opaque PRT>", "is_primary": "true", "request_nonce": "<srv_challenge>"}` [536, 537].
3. **Token Issuance:** Entra ID verifies the `HMAC-SHA256` signature using its copy of the `PRT` Session Key plus `ctx`, checks `request_nonce` freshness, evaluates Conditional Access policies (including device compliance embedded via the `PRT`), and issues OAuth 2.0 access and refresh tokens for the target resource [551, 552].

### Why `Pass-the-PRT` Survives `TPM` Sealing and `Credential Guard`

Dirk-jan Mollema and Benjamin Delpy's August 2020 research (*Abusing Azure AD SSO with the Primary Refresh Token* and *Digging further into the Primary Refresh Token*) exposed a fundamental storage-versus-use seam [536, 537]. Even when `TpmProtected : YES` seals the raw `PRT` Session Key inside `TPM 2.0` (and on modern Windows 11 builds where `LsaIso` / `Credential Guard` isolates long-lived `CloudAP` key state), `cloudap.dll` in `VTL0` `lsass.exe` must still derive `KDF` context keys or invoke the local key-derivation broker during normal SSO operation [69, 536].

With `SYSTEM` privileges in `VTL0`, an adversary never needs to extract the hardware-sealed Transport Key out of the physical TPM. Using `Mimikatz` (`sekurlsa::cloudap` paired with `dpapi::cloudapkd`) or `ROADtools` (`roadtx prt`), the attacker either extracts cached `PRT` blobs and derived `KeyValue` context material from `CloudAP` memory or invokes the local cryptographic and broker APIs on the compromised host to compute a valid `KDF` derived key for a chosen `ctx` value [536, 552]. Exfiltrating that opaque `PRT` string, `ctx`, and 32-byte derived key to an attacker-controlled Linux laptop across the internet lets `roadtx` fetch fresh `srv_challenge` nonces on demand and mint valid `x-ms-RefreshTokenCredential` cookies, simultaneously bypassing Credential Guard (out of scope for `VTL0` `CloudAP` cookie derivation), `KB5014754` (no `KDC` involved), and `Protected Users` (an AD-only construct) whenever the target cloud application accepts unbound session proofs [69, 435, 501, 536, 552].

### The 5x5 Attack/Defense Coverage Matrix

Mapping all five credential-replay generations against Microsoft's five defensive eras reveals why no single control closes the lineage (`diagrams/11-pth-prt-attack-defense-matrix.svg`) [69, 435, 501, 535]:

![Figure: The 5x5 attack/defense matrix as a heatmap. Five attack generations (rows) against five defense generations (columns), each cell graded Closed (returns empty buffers or fails authentication), Partial (one sub-case or raised cost), or Open (outside the defense's design scope) on a hardware-eligible 2026 Windows 11 endpoint with every control on. The fully-Closed cells form a single green block in the Credential Guard column, confined to Generations 1-3; Pass-the-Certificate and Pass-the-PRT reach only Partial, so the staircase of closed cells never reaches the cloud era.](diagrams/11-pth-prt-attack-defense-matrix.svg)

Notice the rightmost column: Conditional Access Token Protection (`ms-appx-web` / `WAM` proof-of-possession binding) requires the client to prove possession of the local device-bound session key when redeeming tokens, blocking cross-machine `PRT` replay *only* for supported native applications against five named Microsoft resources (Exchange Online, SharePoint Online, Microsoft Teams, Azure Virtual Desktop, and Windows 365), while browser-based web sessions and third-party SaaS applications remain unsupported [535].

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `Pass-the-Hash` (`smbclient` patch, `iam.exe`, `Mimikatz` `T1550.002`) | 1997 / 2008 | Password secrecy across `NTLM` (`SMB`, `RPC`, `Restricted Admin RDP`) | Local admin (`LSASS` / `SAM`) or `DCSync` hash access | Substitutes `NTOWF` into `msv1_0` logon memory or client challenge encryptor | Enable `Credential Guard` (`LsaIso`), `Protected Users`, and retire `NTLM` ([Chapter 13](09-ntlm.md)) [69, 435, 531, 534] |
| `Pass-the-Ticket` & `Overpass-the-Hash` (`Mimikatz`, `Rubeus` `T1550.003`) | 2011-2014 | Domain Kerberos session isolation | Local admin over `VTL0` `LSASS` without `Credential Guard` | Exports `.kirbi` + session key via `sekurlsa::tickets` or promotes `NTOWF`/`AES` key into `AS-REQ` | Enable `Credential Guard` + `AES`-only Kerberos (`CVE-2026-20833`) [69, 505, 525, 540, 542] |
| `Pass-the-Certificate` & `AD CS ESC1-ESC16` (`Certify`, `Certipy`, `PassTheCert` `T1649`) | 2021-present | Domain Tier-0 identity via `PKINIT` (`TCP/88`) or `Schannel` `LDAPS` (`TCP/636`) | Exportable user/machine PFX or misconfigured `AD CS` template/ACL/HTTP endpoint | Enrolls rogue SAN/agent cert or steals PFX and authenticates via `PKINIT` or `LDAPS` TLS client cert | Enforce `KB5014754` SID mapping, audit `ESC1-ESC16` + `CT_FLAG_NO_SECURITY_EXTENSION`, seal keys in `TPM` [454, 501, 545, 546, 548] |
| `Pass-the-PRT` & `CloudAP` Derivation Replay (`dpapi::cloudapkd`, `roadtx` `T1528`) | 2020-present | Entra ID device-bound Single Sign-On across cloud resources | Local `SYSTEM` / admin on Entra-joined or Hybrid-joined endpoint | Extracts `PRT` + `KDF` context key or drives `VTL0` `cloudap.dll` to mint `x-ms-RefreshTokenCredential` cookies | Remove standing local admin, enforce `Token Protection` on supported apps + `CAE`, join `Sysmon 10` with Entra sign-in logs [535, 536, 537, 551, 552] |
| `Device-Registration Phishing` & `Actor Token` Replay (`CVE-2025-55241`) | 2023-2025 | Entra device identity provisioning & cross-tenant `S2S` validation | Device-code / MFA phishing (`roadtx`) or internal `S2S` Actor-token bug (patched) | Registers attacker-held software transport key as compliant device (`PRT` minting) or forges unvalidated Actor claims | Block rogue device enrollment via Conditional Access / Intune hardware attestation; cloud-side `CVE-2025-55241` fix [553, 554, 555] |

### Why Browser Cookies and `DPAPI` Remain an Adjacent Seam

Even if future Windows releases move 100% of `cloudap.dll`'s `KDF` cookie-signing pipeline inside a `VTL1` trustlet, any cloud application accessed through a browser (`Edge`, `Chrome`) exchanges that initial `x-ms-RefreshTokenCredential` assertion for standard HTTP session cookies (`ESTSAUTH`, `ESTSAUTHPERSISTENT`) or OAuth refresh tokens stored inside the user's profile (`DPAPI` / `App-Bound Encryption`). Unlike `Pass-the-PRT` (which requires `SYSTEM` / local admin to reach `lsass.exe`), same-user malware running at Medium Integrity ([Chapter 10](25-access-control.md)) can inject into or debug an unisolated browser/COM context or abuse `DevTools` / `WAM` user-session token requests, demonstrating why endpoint storage isolation must be paired with protocol-level token binding (`Token Protection` / `RFC 9449` `DPoP`) [535, 556].

### Continuation Frontier: `Pass-the-DeviceKey` and Device-Identity Abuse

Notice that taxonomy order (`Generations 1-5`) differs from strict calendar chronology: Mollema published `Pass-the-PRT` in August 2020, ten months *before* Schroeder and Christensen published `ESC1-ESC8` in June 2021 [454, 536, 537]. As `Token Protection` expands across native apps, Mollema's 2023-2025 continuation research targets the device identity layer itself: phishing interactive MFA flows to register an attacker-controlled software `Device Key` and `Transport Key` directly in Entra ID (so Entra issues a legitimate `PRT` to the attacker's virtual device without touching a victim Windows laptop's `TPM` at all) alongside adjacent cloud control-plane bugs like unvalidated internal `Actor` tokens (`CVE-2025-55241`, patched September 2025) [553, 554, 555].

## Theoretical Limits & Structural Invariants

### Storage Isolation Does Not Imply Use-Path Isolation

A hardware security module (`TPM 2.0` or `VTL1` `LsaIso`) prevents an attacker from copying a raw private or symmetric root key ($K_{\text{root}}$) off the machine. However, if the protocol design permits an unisolated `VTL0` broker (`cloudap.dll`) to derive an intermediate, time-unlimited subkey ($K_{\text{ctx}} = \text{KDF}(K_{\text{root}}, \text{ctx})$) that the cloud verifier accepts alongside `ctx` for arbitrary future challenges (`srv_challenge`), then $K_{\text{ctx}}$ becomes a portable root-equivalent secret [536]. Hardware isolation closes replay only when the isolated environment signs *each nonced authentication challenge directly* without ever releasing a reusable derived key to `VTL0`.

### Decoupling Endpoint Key Custody from Verifier-Enforced Binding

Consistent with Law 16, proving that a client device stores its identity key inside a `TPM` (`TpmProtected : YES`) guarantees nothing about whether a cloud resource server rejects unbound tokens.

> **Key idea.**
> Closing the credential-replay family across an enterprise requires the simultaneous intersection of three independent controls controlled by different engineering teams: (1) Non-exportable hardware key custody and isolated per-request signing on the endpoint (`TPM 2.0` + `VTL1` trustlet), (2) Mandatory protocol-layer Proof-of-Possession (`Token Protection` / `DPoP` `RFC 9449`) enforced at *every* identity issuer and downstream resource server, and (3) Near-real-time session revocation (`CAE`) [155, 535, 556]. Whenever any one of those three legs is missing (such as a browser SaaS app accepting bearer tokens without `Token Protection`), the replay lineage survives intact.

## Inspecting and Verifying on a Running System

Practitioners verify an endpoint's exposure across `Pass-the-Hash`, `Pass-the-Certificate`, and `Pass-the-PRT` by auditing Entra `PRT` and `TPM` key backing, confirming active `Credential Guard` `VTL1` state, and verifying `KB5014754` strong certificate mapping.

### Auditing Entra Join, `PRT` Presence, and `TPM` Transport-Key Protection

Query `dsregcmd /status` in the interactive user session to verify Entra/Hybrid join health, active `AzureAdPrt` presence, refresh timestamps, and `TPM` backing of the device transport key [551]:

```powershell
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|DeviceAuthStatus|AzureAdPrt |AzureAdPrtUpdateTime|KeyProvider|TpmProtected'
```

Expected output on a healthy Entra-joined, `TPM`-backed Windows 11 workstation:

```text
    AzureAdJoined : YES
    DomainJoined : NO
    DeviceAuthStatus : SUCCESS
    KeyProvider : Microsoft Platform Crypto Provider
    TpmProtected : YES
    AzureAdPrt : YES
    AzureAdPrtUpdateTime : 2026-04-12 15:20:04.000 UTC
```

`TpmProtected : YES` confirms the device and transport keys reside inside `Microsoft Platform Crypto Provider` (`TPM 2.0`), raising raw key-export cost while reminding defenders that `AzureAdPrt : YES` exposes the `CloudAP` SSO broker path if an attacker gains local `SYSTEM` [536, 551].

### Cross-Checking Active `Credential Guard` (`LsaIso`) State and `AAD` Operational Telemetry

Verify that `Credential Guard` (`1` in `SecurityServicesRunning`, not merely `SecurityServicesConfigured`) is actively isolating Generations 1-3, and inspect recent `CloudAP` / `WAM` broker activity in the `Microsoft-Windows-AAD/Operational` event log [69, 551]:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
Get-WinEvent -LogName 'Microsoft-Windows-AAD/Operational' -MaxEvents 3 | Select-Object TimeCreated, Id, LevelDisplayName
```

Expected output:

```text
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
                                2 {1, 2}                     {1, 2}

TimeCreated           Id LevelDisplayName
-----------           -- ----------------
4/12/2026 3:20:04 PM 1104 Information
```

### Auditing `KB5014754` Strong Certificate Mapping Enforcement on Domain Controllers

On Domain Controllers, confirm that `StrongCertificateBindingEnforcement` under `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc` is absent (defaulting to Full Enforcement since February/September 2025) or explicitly set to `2` (`Full Enforcement`), never `0` or `1` [501]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id = 39, 40, 41 } -MaxEvents 5 -ErrorAction SilentlyContinue
```

Zero KDC events `39`/`40`/`41` alongside Full Enforcement (`2` or post-September 2025 default) confirms no legacy `AD CS` certificates lacking `OID 1.3.6.1.4.1.311.25.2` strong `SID` mapping are failing or bypassing `PKINIT` validation [501].

## Summary & Handoff

From Ashton's 1997 `smbclient` diff and Ochoa's 2008 `LSASS` overwrite to Delpy's `Mimikatz`, Schroeder and Christensen's `AD CS` `ESC1-ESC16` catalog, and Mollema's `Pass-the-PRT`, every generation of Windows credential replay exploits the gap between *where a root secret rests* and *where derived proofs are computed and verified*. `Credential Guard` (`LsaIso`) decisively closed local `VTL0` extraction of `NTOWF` hashes and `TGT` session keys, and `KB5014754` closed SAN-spoofed `PKINIT` mapping, yet `Pass-the-PRT` and `AD CS` template misconfigurations remain live wherever local `SYSTEM` compromises `VTL0` `cloudap.dll` or cloud verifiers omit `Token Protection`.

Eliminating shared replayable secrets at enrollment and catching local broker abuse in flight requires the next four links of the trust chain. [Windows Hello and Passkeys (Chapter 17)](12-hello.md) replaces shared passwords with `TPM`-bound, origin-scoped asymmetric keys across both `PKINIT` (`Windows Hello for Business`) and the web (`CTAP2` and `WebAuthn` passkeys). On the endpoint telemetry plane, [ETW: The EDR Substrate (Chapter 18)](28-etw.md) details how detection sensors monitor `PROCESS_VM_READ` handles, RPC broker calls, and process tampering across `LSASS` and `CloudAP`. Finally, [Zero Trust (Chapter 19)](13-zero-trust.md) and [Continuous Access Evaluation (Chapter 20)](14-cae.md) move enforcement to the cloud verifier, pairing Conditional Access `Token Protection` with near-real-time session revocation across Microsoft Entra ID.
