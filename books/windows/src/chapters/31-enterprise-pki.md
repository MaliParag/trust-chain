# Enterprise PKI, Service Identities, and Hybrid Bridges

## Overview

* **Role in the Chain:** Sits alongside `Kerberos` ([Chapter 14](10-kerberos.md)) in Active Directory's realm authority layer, governing X.509 certificate issuance (`AD CS`), public-key account mapping (`PKINIT` and `Shadow Credentials`), automated local and service credentials (`Windows LAPS`, `gMSA`, and Windows Server 2025 `dMSA`), and hybrid directory synchronization (`Microsoft Entra Connect`).
* **Core Security Invariant:** An enterprise certificate, key-credential link, or managed service account authenticates a target principal if and only if the directory cryptographically binds the credential to that principal's immutable `objectSid` (`szOID_NTDS_CA_SECURITY_EXT`) and restricts enrollment, attribute write, and predecessor-link permissions to Tier-0 administrators.
* **Trusted Computing Base (TCB):** Enterprise Certification Authorities (`certsvc`) and their CA private keys, the forest `NTAuthCertificates` store (`CN=NTAuthCertificates,CN=Public Key Services`), Domain Controller `KDC` `PKINIT` and `dMSA` `PAC`-synthesis engines, `[MS-GKDI]` Group Key Distribution root keys, and `Microsoft Entra Connect` synchronization servers (`ADSync` database and `MSOL_*` directory accounts).
* **Primary Failure Modes:** Misconfigured certificate templates permitting requester-supplied Subject Alternative Names (`ESC1`), unauthenticated `HTTP` web enrollment relay (`ESC8`), `dNSHostName` spoofing (`Certifried`, `CVE-2022-26923`), unmonitored writes to `msDS-KeyCredentialLink` (`Shadow Credentials`), `OU` `CreateChild` escalation via Windows Server 2025 `dMSA` predecessor attributes (`BadSuccessor`, `CVE-2025-53779`), and `MSOL_*` `DCSync` pivot across hybrid sync servers.
* **Handoff:** Completes the on-premises Active Directory credential and non-human identity surface, handing off cross-era credential replay mechanics and cloud `Primary Refresh Token` (`PRT`) SSO brokering to [Pass-the-Hash to Pass-the-PRT](11-pth-prt.md) (Chapter 16).

## Core Engineering Problem & Threat Model

Active Directory domains do not have a single root of trust. While [Chapter 14](10-kerberos.md) established `krbtgt` (`RID 502`) as the symmetric root of `Kerberos` ticket issuance, almost every enterprise forest simultaneously operates a second, parallel cryptographic root: `Active Directory Certificate Services` (`AD CS`) [544]. Any Certification Authority (`CA`) listed inside the forest's `NTAuthCertificates` configuration container holds unilateral authority to sign X.509 client-authentication certificates that Domain Controllers accept via `PKINIT` (`RFC 4556`) in exchange for full `Kerberos` Ticket-Granting Tickets (`TGTs`), or via `Schannel` for `LDAPS` binds [544, 891]. Retiring `NTLM` ([Chapter 13](09-ntlm.md)) and enabling `Credential Guard` ([Chapter 12](08-credential-guard.md)) leave this public-key root completely intact.

At the same time, enterprise estates must provision and rotate credentials for millions of non-human principals that cannot type passwords or tap hardware security keys. Shared local administrator passwords across fleet workstations historically turned a single compromised laptop into immediate lateral movement across thousands of peers, motivating the native `Windows Local Administrator Password Solution` (`Windows LAPS`) [893]. On member servers, static human-chosen passwords on service accounts running `IIS`, `SQL Server`, or scheduled tasks enabled offline `Kerberoasting` ([Chapter 14](10-kerberos.md)), driving the architectural progression from `Group Managed Service Accounts` (`gMSA`) in Windows Server 2012 to `Delegated Managed Service Accounts` (`dMSA`) in Windows Server 2025 [894]. Bridging on-premises Active Directory to `Microsoft Entra ID` introduces a third non-human credential class: bidirectional Connector accounts (`MSOL_*` and `AAD_*`) inside `Microsoft Entra Connect` that hold `Replicating Directory Changes All` (`DCSync`) permissions on-premises alongside high-privilege directory synchronization roles in the cloud [896].

The threat model assumes an authenticated domain user or compromised workstation who cannot read `ntds.dit` or `LsaIso.exe` directly, and therefore hunts ACL misconfigurations across `AD CS` certificate templates, `msDS-KeyCredentialLink` attributes, `dMSA` organizational units, or unhardened `Entra Connect` Tier-0 servers to mint Domain-Admin-equivalent credentials legitimately.

## Architectural Deep Dive

### AD CS, NTAuthCertificates, and KB5014754 Strong Certificate Mapping

In an `AD CS` deployment, Domain Controllers trust roots published in `Certification Authorities` (`Trusted Root`) and delegate logon-certificate issuance specifically to CAs whose certificates appear in the forest-wide `NTAuthCertificates` object under `CN=Public Key Services,CN=Services,CN=Configuration,DC=...` [544]. Enrollment policy is governed by `pKIEnrollmentService` objects (identifying each Enterprise CA) and `pKICertificateTemplate` objects in Active Directory, whose `DACLs` specify which security principals hold `Enroll` or `Autoenroll` extended rights.

When a client presents an X.509 certificate to the `KDC` inside a `PKINIT` `PA-PK-AS-REQ` pre-authentication structure (`[MS-PKCA]`), the `KDC` validates the X.509 chain up to a trusted root, verifies CA presence in `NTAuthCertificates`, checks revocation (`CRL`/`OCSP`), confirms the `Client Authentication` (`1.3.6.1.5.5.7.3.2`), `PKINIT Client Authentication` (`1.3.6.1.5.2.3.4`), or `Smart Card Logon` (`1.3.6.1.4.1.311.20.2.2`) Enhanced Key Usage (`EKU`), and maps the certificate to an Active Directory account $u$ [544, 891]:

$$\mathrm{VerifyChain}(\mathrm{Cert}, \mathrm{NTAuth}) \land \mathrm{ValidEKU}(\mathrm{Cert}) \land \mathrm{MapPrincipal}(\mathrm{Cert}) = u \implies \mathrm{IssueTGT}(u)$$

For two decades, `MapPrincipal` relied by default on *weak implicit name matching*: reading the string `SubjectAltName` (`otherName` `UPN` or `dNSName`) from the certificate and looking up the matching `userPrincipalName` or `sAMAccountName` in `AD` without verifying that the enrollee who requested the certificate actually owned that identity [544, 890].

![Figure: AD CS ESC1 plus PKINIT domain escalation and KB5014754 SID-extension closure](diagrams/31-adcs-esc1-pkinit.svg)

In 2021, Will Schroeder and Lee Christensen (*Certified Pre-Owned*) systematized the `ESC1` through `ESC8` template and enrollment failure classes, a taxonomy subsequently expanded by researchers through `ESC16` [544, 548]. The most direct escalation path, `ESC1`, arises whenever a certificate template sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x00000001` in `msPKI-Certificate-Name-Flag`), enables a logon `EKU`, requires zero CA manager approval, and grants `Enroll` to `Domain Users`; any low-privilege user can then submit a `CSR` specifying `UPN = Administrator@corp.example` and receive a valid Domain Admin logon certificate [544]. Adjacent template misconfigurations reach the same outcome indirectly: overly permissive `Certificate Request Agent` or Any-Purpose `EKU` templates (`ESC2` and `ESC3`) allow an attacker to enroll on behalf of privileged users, while writable template ACLs (`WriteDacl` or `WriteProperty` in `ESC4`) let an attacker rewrite a benign template into an `ESC1` configuration on demand [544].

Even when every template is locked down, legacy unauthenticated HTTP web enrollment (`http://<ca>/certsrv/`, `ESC8`) or `RPC` `[MS-ICPR]` listeners lacking Extended Protection for Authentication (`EPA`) allow an adversary to coerce Domain Controller `NTLM` authentication (`PetitPotam` or `SpoolSample`) and relay it into the CA to mint a persistent `DC$` machine certificate capable of `DCSync` [544]. Nor did standard templates omitting `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` prevent identity spoofing: in 2022, Oliver Lyak demonstrated in `Certifried` (`CVE-2022-26923`, alongside related `ESC9` and `ESC10` mapping flaws) that any domain user creating or modifying a computer account could clear its `SPNs` and set its `dNSHostName` to match a Domain Controller (`dc01.corp.example`), causing default `Machine` templates to mint a certificate that the `KDC` mapped directly to `DC01$` [890].

To close string-spoofing permanently, Microsoft shipped `KB5014754` (phased from May 2022 to Full Enforcement Mode in 2025) [891]. Enterprise CAs now embed a non-forgeable private extension, `szOID_NTDS_CA_SECURITY_EXT` (`1.3.6.1.4.1.311.25.2`), carrying the requester's actual Active Directory `objectSid` read from `AD` at issuance time. Under Full Enforcement (`StrongCertificateBindingEnforcement = 2`), the `KDC` rejects any certificate lacking either the matching `1.3.6.1.4.1.311.25.2` `SID` extension or an explicit strong `altSecurityIdentities` (`X509:<I>...<SR>...` / `<SHA1-PUKEY>`) mapping [891].

### Shadow Credentials (`msDS-KeyCredentialLink`)

Even in domains that never install `AD CS`, Windows Server 2016+ Domain Controllers natively support `Key Trust` public-key authentication to back `Windows Hello for Business` ([Chapter 17](12-hello.md)) [892]. Each user and computer object exposes the multi-valued attribute `msDS-KeyCredentialLink`, storing `KEYCREDENTIAL_STRUCT` binary blobs containing a raw RSA-2048 public key alongside device metadata.

As Elad Shamir demonstrated in *Shadow Credentials* (2021), if an attacker holds `GenericWrite` or `AddKeyCredentialLink` over a target user or computer object (for instance via `NTLM`/`Kerberos` relay to `LDAP` when signing and channel binding are missing, or via delegated helpdesk ACLs), the attacker appends a self-generated public key to the target's `msDS-KeyCredentialLink` attribute [892]. Presenting a self-signed certificate matching that raw public key via `PKINIT` causes the `KDC` to issue a `TGT` for the target principal, bypassing `AD CS` CAs entirely and allowing subsequent extraction of the target's `NTOWF` hash via `U2U` (`PKINIT` `PAC_CREDENTIALS_INFO`) [892].

### Windows LAPS, gMSA, and Windows Server 2025 dMSA (`BadSuccessor`)

To eliminate static passwords across local administrators and domain services, Windows evolved through three generations of directory-managed accounts. At the workstation and server local-account tier, `Windows LAPS` (built natively into Windows 11 and Windows Server 2019+) rotates each machine's local administrator password on schedule and encrypts it via `[MS-GKDI]` (`DPAPI-NG`) to a designated administrative group `SID` before writing the ciphertext to Active Directory (`msLAPS-EncryptedPassword`) or `Microsoft Entra ID`, paired with automatic post-authentication password rotation after administrative use [893].

For domain workloads, Windows Server 2012 introduced Group Managed Service Accounts (`gMSA`, `msDS-GroupManagedServiceAccount`), delegating 120-character random password generation to the `KDC` under `[MS-GKDI]` keys rotated every 30 days; authorized hosts listed in `msDS-GroupMSAMembership` retrieve the current password blob over `LDAP`/`RPC`, eliminating human password knowledge while leaving `gMSA` blobs readable to anyone who compromises an authorized member host (`gMSADumper`) [894]. Windows Server 2025 closed both host secret exposure and service migration friction with Delegated Managed Service Accounts (`dMSA`, `msDS-DelegatedManagedServiceAccount`). A `dMSA` binds keys strictly to designated machine identities on the `KDC` and supports *seamless migration* from an existing legacy service account through two directory attributes: `msDS-ManagedAccountPrecededByLink`, pointing to the superseded account, and `msDS-DelegatedMSAState`, where a value of `2` indicates completed migration [894].

![Figure: BadSuccessor CVE-2025-53779 privilege escalation via Windows Server 2025 dMSA attributes](diagrams/31-dmsa-badsuccessor.svg)

In May 2025, Akamai researcher Yuval Gordon disclosed `BadSuccessor` (`CVE-2025-53779`), exposing a profound architectural flaw in the initial `dMSA` KDC `PAC` builder [895]. When a Windows Server 2025 `KDC` issued a ticket for a `dMSA` with `msDS-DelegatedMSAState = 2`, `kdcsvc.dll` read `msDS-ManagedAccountPrecededByLink` and blindly copied the referenced account's `SID` and group memberships into the `dMSA`'s Kerberos `PAC` without verifying that the superseded account had actually authorized the link [895]. Consequently, *any* principal holding `CreateChild` for `msDS-DelegatedManagedServiceAccount` on *any* Organizational Unit (`OU`) in the domain could create a rogue `dMSA`, write `msDS-ManagedAccountPrecededByLink = CN=Administrator,CN=Users,DC=...` on their own newly created object, authenticate as the `dMSA`, and receive a `TGT` carrying full `Domain Admins` (`RID 512`) privileges [895]. Microsoft patched `CVE-2025-53779` in August 2025 by requiring bidirectional authorization (`WriteProperty` on the target superseded account) before the `KDC` honors `msDS-ManagedAccountPrecededByLink` [895].

### Hybrid Identity Sync Bridges (`Microsoft Entra Connect`)

In hybrid enterprises, `Microsoft Entra Connect` (`ADSync`) synchronizes identities and, when Password Hash Synchronization (`PHS`) is enabled, `PBKDF2-HMAC-SHA256` derivatives of `NTOWF` hashes between on-premises `AD` and `Microsoft Entra ID` [896]. Architecturally, the `Entra Connect` host operates as a bidirectional Tier-0 bridge rather than an ordinary member server: its on-premises AD Connector account (`MSOL_<hex>`) frequently holds `Replicating Directory Changes` and `Replicating Directory Changes All` (`DCSync`) rights on the root domain naming context alongside `WriteProperty` when Password Writeback or Device Writeback is active, while its local SQL Express `ADSync` database encrypts those Connector credentials under a local `DPAPI` and `KeySet` hierarchy accessible to local Administrators on the sync server [896].

Compromising local Administrator on an `Entra Connect` server therefore grants immediate on-premises `DCSync` over `krbtgt` ([Chapter 14](10-kerberos.md)) and synchronized cloud user manipulation, collapsing the boundary between on-premises Tier-0 and cloud identity unless `Entra Connect` is isolated strictly as a Domain Controller equivalent with zero Tier-1/Tier-2 admin access and Cloud-Only Global Administrators.

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `AD CS` `ESC1` (`Certipy`, `Certify`) | 2021-present | Domain user → Domain Admin (`PKINIT`) | Low-priv `Enroll` on `ENROLLEE_SUPPLIES_SUBJECT` template | Submits CSR with `SAN` `UPN = Administrator`; swaps issued cert via `PKINIT` for Admin `TGT` [544] | Disable `ENROLLEE_SUPPLIES_SUBJECT` or require CA manager approval + enforce `KB5014754` |
| `AD CS` `ESC8` HTTP/RPC Relay (`ntlmrelayx`) | 2021-present | Coerced DC auth → Forest compromise | Unprotected `/certsrv/` HTTP or `[MS-ICPR]` without `EPA` | Coerces `DC$` via RPC and relays `NTLM` to CA enrollment to obtain `DC$` cert for `DCSync` [544] | Disable HTTP `/certsrv/`, enforce `EPA` (`IF_ENFORCEENCRYPTICERTREQUEST`) on CAs, and disable `NTLM` |
| `Certifried` (`CVE-2022-26923`) | 2022 | Machine account → Domain Controller impersonation | Ability to create/edit one AD computer (`MachineAccountQuota > 0`) | Sets rogue computer `dNSHostName` to `dc01.corp`; default `Machine` cert maps to `DC01$` on KDC [890] | Enforce `KB5014754` Full Enforcement (`1.3.6.1.4.1.311.25.2` `SID` OID) and set `MachineAccountQuota = 0` [891] |
| `Shadow Credentials` (`Whisker`, `PyWhisker`) | 2021-present | ACL write → persistent `PKINIT` + `NTOWF` theft | `GenericWrite` / `WriteProperty` on `msDS-KeyCredentialLink` | Appends attacker RSA public key to target `msDS-KeyCredentialLink` and runs `PKINIT` + `U2U` [892] | Block `LDAP` relay via signing + channel binding; audit `5136` writes to `msDS-KeyCredentialLink` |
| `BadSuccessor` (`CVE-2025-53779`) | 2025 | `OU` `CreateChild` → Domain Admin `PAC` | `CreateChild` on any `OU` + one Server 2025 DC in forest | Creates `dMSA` with `msDS-ManagedAccountPrecededByLink` pointing at `Administrator`; KDC copies Admin SIDs into `PAC` [895] | Apply Aug 2025 `CVE-2025-53779` DC update and restrict `CreateChild` (`dMSA`) on all `OUs` [895] |
| `Entra Connect` `MSOL_*` Extraction (`AADInternals`) | 2019-present | Sync server Admin → Forest `DCSync` | Local Admin on `Microsoft Entra Connect` host | Decrypts `ADSync` SQL Connector credentials via local `DPAPI`/`cryptkeys` and runs `DCSync` as `MSOL_*` [896] | Isolate `Entra Connect` in Tier-0 alongside DCs, migrate to `Entra Cloud Sync` where possible, and keep Global Admins cloud-only |

### Gap Analysis: Why String-Based Identity Mapping Failed Across Both AD CS and dMSA

Comparing `ESC1` and `Certifried` (2021-2022) with `BadSuccessor` (2025) exposes the same structural anti-pattern recurring across Active Directory extensions: *unilateral pointer trust*. In pre-`KB5014754` `AD CS`, an unprivileged object (`Certifried` computer account or `ESC1` CSR) wrote a *claim* (`dNSHostName = dc01` or `SAN = Administrator`) onto a credential *it* controlled, and the `KDC` resolved that string pointer to a Tier-0 target without verifying target consent or immutable `objectSid` provenance [544, 890]. Three years later in Windows Server 2025, `dMSA` repeated that exact structural mistake in LDAP schema form: an unprivileged `OU` manager wrote a forward DN link (`msDS-ManagedAccountPrecededByLink`) onto a `dMSA` object *they* controlled, and the `KDC` dereferenced that forward link to grant the target's `SIDs` without requiring a back-link or write permission on the target principal [895].

Notice also what `KB5014754` *does* and *does not* close: Full Enforcement Mode (`StrongCertificateBindingEnforcement = 2`) completely neutralizes `Certifried` (`CVE-2022-26923`) and `ESC9`/`ESC10` because the CA stamps the requester's true `objectSid` into OID `1.3.6.1.4.1.311.25.2`, *except* when a template still sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`ESC1`). Under `ESC1`, the CA intentionally omits the requester's `SID` extension because the template explicitly instructs the CA to trust the requester-supplied subject, meaning `ESC1`, `ESC4`, `ESC8`, and `Shadow Credentials` remain fatal even on fully patched 2026 Domain Controllers unless template ACLs and enrollment endpoints themselves are hardened [548, 891].

> **Key idea.**
> Every Enterprise CA listed in `NTAuthCertificates` and every `Microsoft Entra Connect` sync server holds identity-minting or `DCSync` authority co-equal with `krbtgt` (`RID 502`). Leaving a CA or sync server in Tier 1 while locking Domain Controllers in Tier 0 leaves Tier 0 open via `PKINIT` or `MSOL_*` replication.

## Theoretical Limits & Structural Invariants

### Dual-Root Equivalence and Bidirectional Delegation Consent

In any Active Directory forest where `PKINIT` is enabled on Domain Controllers, the set of Certification Authorities in `NTAuthCertificates` possesses realm-wide identity-minting authority strictly equivalent to `krbtgt` (`RID 502`). Securing Domain Controllers inside Tier-0 while leaving an Enterprise CA on a Tier-1 member server managed by server operators violates TCB closure: compromising the Tier-1 CA immediately compromises Tier-0 via `PKINIT`. Within the directory schema itself, delegation soundness obeys a second structural invariant: whenever principal $A$ claims authority inherited from or acting as principal $B$ (whether via X.509 `SAN`, `RBCD` `msDS-AllowedToActOnBehalfOfOtherIdentity`, or `dMSA` `msDS-ManagedAccountPrecededByLink`), the authorizing link must be stored on, or cryptographically signed by, principal $B$ (`RBCD`'s inbound descriptor model), never solely on principal $A$ (`BadSuccessor`'s outbound link flaw).

### Persistence Beyond Password Rotation

Public-key credentials also break traditional password-reset remediation assumptions. Unlike stolen cleartext passwords or symmetric hashes, `X.509` client certificates (`ESC1` or `ESC8`) and raw public keys written to `msDS-KeyCredentialLink` (`Shadow Credentials`) survive target password resets completely because `PKINIT` authenticates the key pair without consulting the user's password hash; full eviction requires explicit certificate revocation (`CRL`/`OCSP`), `NTAuthCertificates` pruning, or clearing `msDS-KeyCredentialLink` on affected objects [544, 892].

## Inspecting and Verifying on a Running System

Operational verification across Active Directory's public-key and service-identity plane focuses on enumerating forest-trusted `NTAuth` CAs and `ESC1` templates, confirming `KB5014754` enforcement on Domain Controllers, and auditing `Shadow Credentials`, `dMSA` migration links, and `Windows LAPS` encryption.

### Audit Trusted CAs in `NTAuthCertificates` and Dangerous `ESC1` Templates

Enumerate all CA certificates currently trusted inside the forest `NTAuthCertificates` store [544]:

```powershell
certutil -viewstore -enterprise NTAuth | Select-String "Subject:|Issuer:|Serial Number:|NotAfter:"
```

Query Active Directory configuration templates for dangerous `ESC1` combinations (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` bit `0x1` enabled):

```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
  -LDAPFilter "(msPKI-Certificate-Name-Flag:1.2.840.113556.1.4.803:=1)" -Properties msPKI-Certificate-Name-Flag, pkiExtendedKeyUsage
```

Any returned template combining bit `0x1` with a client-authentication `EKU` (`1.3.6.1.5.5.7.3.2` or `1.3.6.1.4.1.311.20.2.2`) must either require CA manager approval or restrict `Enroll` permissions exclusively to Tier-0 principals [544].

### Verify Domain Controller `KB5014754` Strong Certificate Binding Enforcement

Check `StrongCertificateBindingEnforcement` (`2` = Full Enforcement Mode; `1` = Compatibility Mode; `0` = Disabled) on Domain Controllers [891]:

```powershell
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" `
  -Name StrongCertificateBindingEnforcement, CertificateBackdatingCompensation -ErrorAction SilentlyContinue
```

On post-2025 Domain Controllers, `StrongCertificateBindingEnforcement` should resolve to `2` (or be absent so the OS enforces Full Enforcement Mode by default) with zero `CertificateBackdatingCompensation` overrides left behind from migration windows [891].

### Audit `Shadow Credentials`, `dMSA` Predecessor Links, and `Windows LAPS`

Detect accounts populated with `msDS-KeyCredentialLink` values outside expected `Windows Hello for Business` populations, and inspect any Windows Server 2025 `dMSA` objects with active `msDS-ManagedAccountPrecededByLink` bindings [892, 895]:

```powershell
Get-ADObject -LDAPFilter "(msDS-ManagedAccountPrecededByLink=*)" `
  -Properties msDS-ManagedAccountPrecededByLink, msDS-DelegatedMSAState, whenCreated
```

Verify `Windows LAPS` policy state and encrypted password protection on a managed endpoint [893]:

```powershell
Get-LapsDiagnostics | Select-Object CurrentConfiguration, IsConfigured, EncryptionEnabled
```

Every `dMSA` predecessor link should correspond to a documented service migration on a `CVE-2025-53779`-patched Domain Controller, while `EncryptionEnabled : True` confirms that `Windows LAPS` stores `[MS-GKDI]`-encrypted ciphertexts rather than cleartext passwords in directory attributes [893, 895].

## Summary & Handoff

`AD CS`, `msDS-KeyCredentialLink`, `Windows LAPS`, `gMSA`/`dMSA`, and `Microsoft Entra Connect` govern public-key, machine, service, and hybrid identity authority across Active Directory. Treating Enterprise CAs and `Entra Connect` servers as strict Tier-0 assets, enforcing `KB5014754` `SID` binding alongside `ESC1`/`ESC8` template hardening, and patching outbound-link flaws like `BadSuccessor` (`CVE-2025-53779`) prevent adversaries from minting persistent `PKINIT` TGTs or `DCSync` privileges around `Credential Guard` and `NTLM` disablement.

With every on-premises credential and PKI primitive established across Chapters 11 through 15, the remainder of Part III follows those identities across hosts and into the cloud. [Pass-the-Hash to Pass-the-PRT](11-pth-prt.md) (Chapter 16) traces how five generations of credential-replay tradecraft evolved from local `NTOWF` hashes and `AD CS` certificates to `CloudAP`-brokered `TPM` `Primary Refresh Tokens` (`PRTs`), pinpointing where local `SYSTEM` adversaries hijack in-use session derivation. [Windows Hello and Passkeys](12-hello.md) (Chapter 17) then closes the shared-secret era at the user boundary by binding interactive sign-in to hardware-isolated `Windows Hello` and `WebAuthn` asymmetric ceremonies.
