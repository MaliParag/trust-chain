# Kerberos and Ticket Forgery

## Overview

* **Role in the Chain:** Primary domain and (via `Local KDC` / `IAKerb`) local authentication and authorization protocol of Windows; replaces symmetric password-hash challenges with Key Distribution Center (`KDC`) tickets carrying signed Privilege Attribute Certificates (`PACs`).
* **Core Security Invariant:** Within an Active Directory realm, a Ticket Granting Ticket (`TGT`) is accepted by the `KDC` if and only if its `EncTicketPart` decrypts and its `[MS-PAC]` signatures (`Server`, `KDC`, `Ticket`, and `Full PAC`) verify under the current or previous key of the `RID 502` `krbtgt` account, while application servers validate `AP-REQ` service tickets locally under their own long-term key.
* **Trusted Computing Base (TCB):** Every writable Domain Controller (`ntds.dit` and `kdcsvc.dll`), the `krbtgt` long-term key set, per-service SPN keys, `AD CS` PKINIT CAs (`KB5014754` SID-mapped), directory delegation descriptors (`msDS-AllowedToActOnBehalfOfOtherIdentity`), and synchronized domain clocks (`5`-minute default skew).
* **Primary Failure Modes:** Offline password cracking of `RC4-HMAC` (`enctype 23`) or weak-password `TGS-REP`/`AS-REP` ciphertexts (`Kerberoasting`, `AS-REP Roasting`), delegation and Kerberos-relay abuse (`RBCD`, `KrbRelayUp`, `Bronze Bit` `CVE-2020-17049`), `PKINIT` SAN spoofing (`Certifried` `CVE-2022-26923`), service-key `Silver` tickets, and `DCSync` extraction of `krbtgt` enabling `Golden`, `Diamond`, and `Sapphire` `TGT` forgery.
* **Handoff:** Governs ticket-based identity inside Active Directory; hands hybrid and cloud bearer-token evolution (`Primary Refresh Tokens`) to [Pass-the-Hash to Pass-the-PRT (Chapter 16)](11-pth-prt.md), passwordless `PKINIT`/`FIDO2` key enrollment to [Windows Hello and Passkeys (Chapter 17)](12-hello.md), and the cloud-key-compromise parallel of `krbtgt` theft to [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).

## Core Engineering Problem & Threat Model

Disabling `NTLM` ([Chapter 13](09-ntlm.md)) eliminates unbound challenge-response fallbacks, concentrating nearly the entire authentication weight of Windows onto Kerberos. Yet Kerberos was never designed to survive weak human-chosen service passwords, unauthenticated LDAP channels, permissive directory delegation defaults, or disclosure of its own signing keys. Even in a domain with zero `NTLM` traffic, an unprivileged domain user on a default Active Directory installation can create a machine account (`ms-DS-MachineAccountQuota = 10`), relay a Kerberos `AP-REQ` to an unsigned `LDAP` endpoint (`KrbRelayUp`), configure Resource-Based Constrained Delegation (`RBCD`), and impersonate `Administrator` using 100% standards-compliant Kerberos messages [451, 478].

Kerberos's architecture descends directly from Roger Needham and Michael Schroeder's 1978 trusted-third-party symmetric key-distribution protocol [480], augmented in 1981 by Dorothy Denning and Giovanni Sacco's timestamp freshness defense (the direct ancestor of Windows' default 5-minute clock-skew ceiling) [481, 482] and built out at MIT Project Athena (`1983-1991`, Steiner, Neuman, and Schiller, February 1988 [483, 484, 485]). Standardized as Kerberos v5 in `RFC 1510` (1993) and `RFC 4120` (2005) [482, 486], Kerberos became Active Directory's default authentication fabric in Windows 2000 through two normative Microsoft extensions: `[MS-KILE]` (wire profile, `FAST`, `S4U` delegation) and `[MS-PAC]` (embedding Windows SIDs and group memberships inside tickets) [487, 488].

Against this protocol surface, the Active Directory Kerberos threat model spans three escalating adversary footholds. At the outer perimeter, a low-privilege domain user holding a single valid `TGT` can mine `TGS-REP` ciphertexts offline (`Kerberoasting`) or chain `MachineAccountQuota`, `PKINIT` certificate templates, and `RBCD` access control lists to reach host or Tier-0 administration [449, 451, 489]. One rung deeper, an attacker who compromises a single server or service account's long-term key can forge offline `Silver` service tickets (`T1558.002`) for that host or tamper with delegation flags (`Bronze Bit`) [490, 491]. At the apex of the realm, a Tier-0 adversary who replicates the `RID 502` `krbtgt` secret via `DRSGetNCChanges` (`DCSync`, `T1003.006`) [448, 492] mints arbitrary domain `TGTs` (`Golden`, `Diamond`, and `Sapphire` tickets [493, 494, 495]), subverting identity verification across the entire domain.

## Architectural Deep Dive

### The Six-Message Protocol (`AS`, `TGS`, `AP`) and `PA-DATA` Extensions

Kerberos separates authentication into three two-message exchanges mediated by the Key Distribution Center (`KDC`, `kdcsvc.dll` on every writable DC) (`diagrams/10-kerberos-message-triple.svg`) [482, 488].

![Figure: The 1988 Kerberos message triple (AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP) structurally unchanged thirty-eight years later. The AS and TGS exchanges are the two logical halves of one KDC; the service validates the final ticket locally with its own long-term key.](diagrams/10-kerberos-message-triple.svg)

Authentication opens with the Authentication Service (`AS-REQ` / `AS-REP`) exchange, in which the client announces its principal, realm, supported encryption types, and a Pre-Authentication Data (`PA-DATA`) proof. Once validated, the `KDC` returns `AS-REP` carrying two independently encrypted structures: the opaque `TGT` (`EncTicketPart` containing the `TGT` session key $K_{c,\text{tgs}}$ and `[MS-PAC]`, sealed under `krbtgt`'s long-term key so the client cannot inspect or modify it) alongside a client-readable reply block encrypted under the client's own key delivering $K_{c,\text{tgs}}$ and ticket validity flags (`forwardable`, `renewable`, `pre-authent`) [482].

Whenever that client subsequently accesses a network resource identified by a Service Principal Name (`SPN`, such as `cifs/fs01.contoso.com`), it initiates the Ticket-Granting Service (`TGS-REQ` / `TGS-REP`) exchange rather than re-exposing its long-term secret. Presenting its opaque `TGT` paired with a fresh `Authenticator` (the current timestamp encrypted under $K_{c,\text{tgs}}$), the client requests a targeted credential from the `KDC`. The `KDC` decrypts the `TGT` with `krbtgt`'s key, verifies `PAC` integrity, and returns `TGS-REP`: a service ticket encrypted under the target `SPN` account's long-term key containing a fresh service session key $K_{c,s}$ and updated `PAC`, accompanied by $K_{c,s}$ wrapped under $K_{c,\text{tgs}}$ [482, 496]. In the final Client/Server (`AP-REQ` / `AP-REP`) exchange, the client transmits that service ticket plus a fresh $K_{c,s}$-encrypted `Authenticator` directly to the application server (`SMB`, `HTTP`, `LDAP`). Crucially, the server never contacts the `KDC` during standard `AP-REQ` verification: it decrypts the ticket locally in $O(1)$ time using its own long-term key, checks its 5-minute clock-skew replay cache, extracts the `PAC` SIDs to construct a Windows access token ([Chapter 10](25-access-control.md)), and optionally returns `AP-REP` when the caller demands mutual server authentication [482, 487].

Modern Windows hardens the initial `AS-REQ` `PA-DATA` negotiation with armored tunnels and asymmetric pre-authentication extensions alongside the `IAKerb` and `Local KDC` transports examined in [Chapter 13](09-ntlm.md). Classic `PA-ENC-TIMESTAMP` pre-authentication encrypts a client timestamp directly under the user's password-derived key, exposing weak human passwords to offline brute force on passive wire captures; Flexible Authentication Secure Tunneling (`FAST`, `RFC 6113`) closes that exposure by wrapping the user's `AS-REQ` inside an outer encrypted armor tunnel keyed from the host computer's high-entropy machine `TGT` [497, 498]. Where enterprises deploy smart cards or Windows Hello ([Chapter 17](12-hello.md)), `PKINIT` (`RFC 4556`) replaces symmetric password pre-authentication altogether with asymmetric `PA-PK-AS-REQ` signatures [499]. To defend `PKINIT` against pre-computed signatures and mutable subject spoofing, `RFC 8070` (`PA-AS-FRESHNESS`) enforces live private-key possession over a KDC-supplied freshness token [500], while `KB5014754` (enforced February 2025, with legacy compatibility fallback removed September 2025) mandates binding X.509 logon certificates to immutable Active Directory object SIDs via extension OID `1.3.6.1.4.1.311.25.2` rather than mutable DNS or UPN names [501].

### Encryption Types (`s2k`), `gMSA`/`dMSA`, and the Beyond-RC4 Flip (`CVE-2026-20833`)

Under `RFC 3961`, each Kerberos `enctype` defines a String-to-Key (`s2k`) function converting a password into a symmetric key [502, 503]:

| Enctype Name | ID | `s2k` Key Derivation | Active Directory Status |
|---|---|---|---|
| `DES-CBC-CRC` / `DES-CBC-MD5` | `1`, `3` | 56-bit DES key | Disabled since Windows Server 2008 R2 [503] |
| `RC4-HMAC` (`RFC 4757`) | `23` (`0x17`) | `MD4(UTF-16LE(password))` (unsalted, 1 round = `NTOWF`) | Legacy default fallback; default-disabled by `CVE-2026-20833` (2026) [504, 505, 506] |
| `AES128` / `AES256-CTS-HMAC-SHA1-96` | `17`, `18` | `PBKDF2-HMAC-SHA1(password, salt, 4096)` + `DK(tkey, "kerberos")` | Production standard (`RFC 3962`); KDC assumed default from 2026 [505, 507] |
| `AES128` / `AES256-CTS-HMAC-SHA2` | `19`, `20` | `PBKDF2-HMAC-SHA256/384` (`RFC 8009`) | Defined in `[MS-KILE]` bits `K`/`L`; not yet default-enabled [503, 508] |

Because Windows 2000 defined `enctype 23` (`RC4-HMAC`) directly over the unsalted `NTOWF` hash, offline GPUs test billions of candidate passwords per second against `RC4` service tickets, whereas `AES-256` (`4,096` `PBKDF2` iterations salted with realm + principal name) slows cracking by roughly four orders of magnitude [506, 507]. Under Microsoft's Beyond-RC4 rollout (`CVE-2026-20833`, 2026), Domain Controllers change the assumed `msDS-SupportedEncryptionTypes` for unconfigured service accounts from permissive `RC4` fallback to AES-SHA1 only, accompanied by new `Available Keys` and `Session Encryption Type` fields in Security Events `4768` and `4769` [505]. To eliminate human-chosen service passwords entirely, Windows Server 2012 introduced Group Managed Service Accounts (`gMSA`) (240-character random passwords rotated every 30 days via `kdssvc.dll` [420]), and Windows Server 2025 added Delegated Managed Service Accounts (`dMSA`), binding credentials to specific host identities on the DC so raw service secrets never reside on member servers [509].

### The `KRBTGT` Root (`RID 502`) and `[MS-PAC]` Four-Signature Convergence

Every Active Directory domain contains one built-in, disabled, indelible account at `S-1-5-21-<domain>-502`: `krbtgt` (paired with isolated `krbtgt_<rid>` accounts for Read-Only Domain Controllers) [510, 511, 512]. Its system-generated secret, stored with a password history of 2 (`current` and `previous` key sets across supported enctypes) inside `ntds.dit` and loaded in cleartext by `kdcsvc.dll` on every writable DC, encrypts every `TGT` in the realm [488, 513].

Inside `EncTicketPart.authorization-data`, Windows embeds the `[MS-PAC]` Privilege Attribute Certificate carrying the user's primary SID, domain/universal group RIDs, `ExtraSIDs` (`SIDHistory`), and up to four cryptographic signatures (`diagrams/23-krbtgt-pac-convergence.svg`) [487, 490, 514, 515]:

![Figure: A TGT's four PAC signatures (Server Signature, KDC Signature, Ticket Signature added for CVE-2020-17049, and Full PAC Signature added for CVE-2022-37967 / KB5020805) all terminate at a single node: the krbtgt (RID 502) long-term key. Enlarging the signed surface closed partial-PAC tampering, but an adversary holding krbtgt recomputes all four in one step.](diagrams/23-krbtgt-pac-convergence.svg)

1. **`PAC_SERVER_CHECKSUM` (Type `6`):** Keyed HMAC over the `PAC` buffer using the *target service's* long-term key (which, for a `TGT` targeting `krbtgt/DOMAIN`, is `krbtgt` itself; for an `AP-REQ` service ticket, it is the target server's key, verifiable locally without calling a DC) [487].
2. **`PAC_PRIVSVR_CHECKSUM` (`KDC` Signature, Type `7`):** Keyed HMAC computed under `krbtgt` over the `Server Signature` bytes, preventing a compromised application server from fabricating arbitrary group SIDs in a `PAC` it hands back to the `KDC` [487].
3. **`PAC_TICKET_CHECKSUM` (Type `16`, added for `CVE-2020-17049`):** `krbtgt`-keyed HMAC over the outer `EncTicketPart` (excluding `authorization-data`), cryptographically binding the `PAC` to the outer ticket's `cname` and `TicketFlags` (such as `forwardable`) [487, 490].
4. **`PAC_FULL_CHECKSUM` (`KrbtgtFullPacSignature`, added for `CVE-2022-37967` / `KB5020805`):** Enforced permanently since October 2023; `krbtgt`-keyed HMAC over the *entire* serialized `PAC` structure, closing partial-`PAC` tampering [514, 515].

Notice the structural convergence: on a `TGT`, every single `PAC` signature and the outer `EncTicketPart` cipher terminate at the exact same `krbtgt` key.

### Service-for-User (`S4U`) and Delegation Models

When a front-end web application or middle-tier service must access a back-end database *as* the connected client, Active Directory's three delegation architectures trace a two-decade effort to bound impersonation blast radius [451, 481, 516]. Windows 2000 introduced Unconstrained Delegation (`UF_TRUSTED_FOR_DELEGATION`), in which the client embeds a full copy of its own `TGT` inside the `AP-REQ` authenticator; the front-end server extracts that `TGT` into local `lsass.exe` memory and can impersonate the user to *any* service in the forest, which is why modern deployments block unconstrained delegation for `Protected Users` and forbid `TGT` forwarding under Credential Guard ([Chapter 12](08-credential-guard.md)). Windows Server 2003 narrowed that exposure with Classic Constrained Delegation (`KCD`, `msDS-AllowedToDelegateTo`) paired with the Service-for-User (`S4U`) extensions: `S4U2Self` allows a front-end service to request a service ticket to itself on behalf of an arbitrary user during protocol transition, and `S4U2Proxy` presents that user's service ticket back to the `KDC` inside `additional-tickets` as cryptographic evidence to obtain a ticket strictly for an administrator-listed back-end `SPN` [481, 516].

Because classic `KCD` required Domain Administrators to configure `msDS-AllowedToDelegateTo` on the front-end principal, Windows Server 2012 inverted the administrative boundary with Resource-Based Constrained Delegation (`RBCD`). Under `RBCD`, the *back-end resource owner* writes a security descriptor directly into `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer object specifying which front-end principals may execute `S4U2Proxy` against it [451, 517]. Placing delegation consent on the target resource unlocked cross-domain delegation and self-service administration, yet it quietly turned write access over a computer object's LDAP attributes into a complete host-takeover primitive.

## Attack Catalog & Gap Analysis

Every major Active Directory Kerberos compromise exploits either weak password-derived service keys, legitimate delegation/certificate mapping mechanics, or direct possession of `SPN` and `krbtgt` symmetric keys.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `MS14-068` Checksum Bug (`CVE-2014-6324`) | 2014 | Domain user → Domain Admin `PAC` integrity | Any authenticated domain user against unpatched pre-Nov 2014 DC | Forges `PAC` with Domain Admin SIDs signed using unkeyed `CRC32`/`MD5` checksum accepted by buggy `kdcsvc.dll` | Patched in `MS14-068` enforcing keyed `HMAC` `PAC` signatures [518, 519] |
| `Kerberoasting` (`T1558.003`) & `AS-REP Roasting` (`T1558.004`) | 2014-present | Confidentiality of human-chosen SPN / preauth-off passwords | Any domain user (`Kerberoasting`) or network reach to `UF_DONT_REQUIRE_PREAUTH` user | Requests `TGS-REP` for SPNs (preferring `RC4` `0x17`) or `AS-REP` and cracks long-term key ciphertext offline on GPUs | Migrate services to `gMSA` / `dMSA`, enforce `AES`-only (`CVE-2026-20833`), and require pre-auth [420, 449, 450, 505, 509, 520] |
| `RBCD` (`Wagging the Dog`), `Bronze Bit` (`CVE-2020-17049`), & `KrbRelayUp` | 2019-2022 | Target host privilege isolation via `S4U2Self` + `S4U2Proxy` | Write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` (via ACL or unsigned LDAP relay) + SPN account (`MAQ = 10`) | Registers rogue computer SPN, sets target `RBCD` attribute, and runs `S4U2Self` + `S4U2Proxy` as `Administrator` (or flips `forwardable` in `2020-17049`) | Set `ms-DS-MachineAccountQuota = 0` (`KB5008380`), enforce `LDAP` signing/CBT, and apply `CVE-2020-17049` patch [451, 478, 490, 521] |
| `Certifried` (`CVE-2022-26923`) | 2022 | `PKINIT` machine-certificate-to-account binding | Authenticated user editing `dNSHostName` on owned computer object | Sets owned computer's `dNSHostName` to DC FQDN, enrolls `Machine` cert, and runs `PKINIT` to obtain a DC `TGT` | Enforce `KB5014754` strong SID certificate mapping (`OID 1.3.6.1.4.1.311.25.2`) [489, 501] |
| `Silver Ticket` (`T1558.002`) | 2014-present | Local `AP-REQ` authentication on a specific target server | Compromised target service / computer account long-term key | Forges a `TGS` service ticket + `PAC_SERVER_CHECKSUM` offline and sends `AP-REQ` directly to target without touching the `KDC` | Enable `ValidateKdcPacSignature` where needed, rotate computer/gMSA keys, and correlate server `4624` vs. DC `4769` [283, 487, 491] |
| `Golden`, `Diamond`, & `Sapphire` Tickets (`T1558.001`) | 2014-present | Entire Kerberos realm identity & authorization (`TGT` root) | `krbtgt` key extracted via `DCSync` (`DRSGetNCChanges`) or `ntds.dit` theft | Forges `TGT` from scratch (`Golden`), edits decrypted genuine `TGT` `PAC` (`Diamond`), or splices real `S4U2Self+U2U` `PAC` (`Sapphire`) | Restrict `DCSync` ACLs, monitor `MDI`/`4768`/`4769`, execute double `krbtgt` rotation + Tier-0 forest recovery [493, 494, 495, 513, 515, 522] |

### Post-`NTLM` Delegation and Relay Chains: `RBCD` and `KrbRelayUp`

Elad Shamir's *Wagging the Dog* (2019) [451] and Mor Davidovich's `KrbRelayUp` (2022) [478] demonstrate why Kerberos delegation + Active Directory defaults reproduce instant local and remote privilege escalation with zero `NTLM` packets (`diagrams/10-kerberos-rbcd-chain.svg`):

![Figure: The post-NTLM RBCD chain: six steps from a low-privileged user to Administrator-level access on the file server, with zero NTLM messages in the path. Five of the six exchanges touch only the Domain Controller; the trust boundary abused is the msDS-AllowedToActOnBehalfOfOtherIdentity directory attribute, not a password fallback.](diagrams/10-kerberos-rbcd-chain.svg)

Because fresh Active Directory forests ship with `ms-DS-MachineAccountQuota = 10`, any domain user can create `ATTACKER$` (which automatically holds an `SPN`, enabling `S4U2Self`). If the attacker either holds `GenericWrite` over a server object via ACL misconfiguration *or* coerces the local machine account into Kerberos-authenticating to a local listener and relays that Kerberos `AP-REQ` to a Domain Controller where LDAP signing is not required (`KrbRelayUp`), the attacker writes `ATTACKER$`'s SID into the victim machine's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute [451, 478]. From there, `S4U2Self` + `S4U2Proxy` yields a valid `cifs/` or `HOST/` service ticket as `Administrator`, even if `S4U2Self`'s output was non-forwardable (`RBCD` protocol transition) [451].

### The `KRBTGT` Forgery Evolution: `Golden`, `Diamond`, and `Sapphire` Tickets

Once `MS14-068` (`CVE-2014-6324`) closed unkeyed `PAC` checksum acceptance in November 2014 [518, 519], arbitrary `TGT` forgery required extracting the `krbtgt` key, canonically via `Mimikatz` `lsadump::dcsync` invoking `MS-DRSR` `DRSGetNCChanges` [448, 492]. Over the following decade, adversaries refined *how* they wielded that stolen `krbtgt` secret to evade Microsoft Defender for Identity (`MDI`) and SIEM telemetry [494, 495, 523, 524].

First-generation Golden Tickets, introduced by Benjamin Delpy and Gentil Duckwall in 2014 [493, 522, 525], construct a `TGT` and `PAC` entirely offline from scratch without ever sending an `AS-REQ` to the `KDC`. Although cryptographically valid, early operator defaults such as `RC4` (`enctype 23`) encryption, hardcoded 10-year ticket lifetimes, nonexistent principal names, or `TGS-REQ` activity (`Event 4769`) unpreceded by any `AS-REP` logon (`Event 4768`) triggered dedicated `MDI` detections (`Alerts 2009, 2013, 2022, 2027`) [524, 526]. To restore wire causality and policy-accurate ticket headers, Charlie Clark and Semperis researcher Andrew Schwartz introduced Diamond Tickets in 2022 [494, 527]: the operator requests a *genuine* `AES-256` `TGT` from the `KDC` via a normal `AS-REQ` (matching domain lifetime policies and emitting a legitimate `4768` event), decrypts `EncTicketPart` locally under the stolen `krbtgt` `AES-256` key, appends privileged group RIDs (`512` Domain Admins or `519` Enterprise Admins) to the `PAC`, recomputes all `krbtgt`-keyed `PAC` signatures including `KB5020805`'s `Full PAC Signature`, and re-encrypts the modified ticket [494, 515]. Later in 2022, Charlie Bromberg (`Shutdown`) eliminated manual `PAC` field editing altogether with Sapphire Tickets [495, 523, 528]. Starting from a normal `TGT`, the attacker chains `S4U2Self` with User-to-User (`U2U`) ticket encryption so the `KDC` itself builds an authentic `PAC` for a target Domain Admin, extracts that genuine `PAC`, and seals it inside the decrypted `TGT` under the held `krbtgt` `AES-256` key, leaving only the unusual `S4U2Self` plus `U2U` `TGS` request pair on the wire [495, 528].

Defensively, Windows Server 2025 Domain Controllers hardened the surrounding realm baseline by disabling `RC4-HMAC` `TGT` issuance by default, enforcing `LDAP` signing and `Schannel` `TLS 1.3` on new directory deployments, and blocking machine accounts from setting their password equal to their own account name [900]. Against post-`DCSync` ticket forgery, however, blue-team detection narrows dramatically across the three generations: `Golden` tickets trigger unissued-`TGT` (`4769` without preceding `4768`) and lifetime/enctype alerts in `MDI`; `Diamond` tickets satisfy `4768`/`4769` causality and lifetime rules unless `PAC` privilege jumps are baselined per host; and `Sapphire` tickets bypass static `PAC` anomaly checks completely, requiring SIEM correlation on unexpected `S4U2Self` + `ENC-TKT-IN-SKEY` (`U2U`) `4769` pairs from non-service workstation principals [523, 524].

## Theoretical Limits & Structural Invariants

### Stateless $O(1)$ Service Verification Precludes Real-Time Revocation

Kerberos's greatest scalability triumph, that a file server or web server validates incoming `AP-REQ` service tickets locally using only its own secret key without querying the `KDC`, creates an immutable security ceiling. Because no online `OCSP`-style lookup occurs during `AP-REQ` acceptance, an issued `TGT` or forged `Silver`/`Golden`/`Diamond`/`Sapphire` ticket cannot be individually revoked mid-flight [482]. Until either the ticket's `endtime` passes (`MaxTicketAge = 10` hours default) *or* the verifying principal's long-term key is rotated out of both `current` and `previous` slots, every verifier accepts the cryptographic proof unconditionally.

### Decoupling `KRBTGT` Key Rotation from Systemic Domain Recovery

Consistent with Law 16, invalidating forged cryptographic tickets (`krbtgt` double rotation) does not evict an adversary who held Tier-0 authority.

> **Key idea.**
> Because Active Directory retains a 2-password history (`current` $K_1$ and `previous` $K_0$) on `krbtgt` to avoid breaking active user sessions during routine maintenance, a single `krbtgt` reset leaves the attacker's stolen key $K_0$ valid in the `previous` slot. Evicting $K_0$ requires two password resets separated by at least `MaxTicketAge` (10 hours by default) with verified `repadmin` directory convergence after each reset [513]. Yet an adversary capable of running `DCSync` almost certainly extracted service/machine keys (`Silver` tickets), `AD CS` CA private keys (`Golden Certificate`), the `KDS` root key (`Golden gMSA`), inter-forest trust keys, `DSRM` local passwords, or planted `AdminSDHolder` / `SIDHistory` backdoors, making confirmed `krbtgt` theft a full Tier-0 forest recovery incident rather than a routine key rotation [513, 529].

## Inspecting and Verifying on a Running System

Operational auditing covers four high-signal checks: inspecting local ticket enctypes, verifying `krbtgt` key age and `MachineAccountQuota`, auditing `DCSync` ACLs on the domain root, and hunting `RC4` (`0x17`) service tickets ahead of `CVE-2026-20833` enforcement.

### Inspecting Local Ticket Cache Encryption Types and Flags

Inspect the active session's cached `TGT` and service tickets to confirm `AES-256-CTS-HMAC-SHA1-96` encryption for both `KerbTicket Encryption Type` and `Session Key Type` [481, 505]:

```powershell
klist | Select-String 'Client:|Server:|KerbTicket Encryption Type:|Ticket Flags'
```

Expected output on an `AES`-enforced domain client:

```text
        Client: alice @ CONTOSO.COM
        Server: krbtgt/CONTOSO.COM @ CONTOSO.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
```

Any ticket displaying `RSADSI RC4-HMAC(NT)` signals a legacy account lacking `AES` keys or unconfigured `msDS-SupportedEncryptionTypes` exposed to rapid offline `Kerberoasting` [505, 506].

### Auditing `krbtgt` Rotation Age and `ms-DS-MachineAccountQuota`

On a management workstation or Domain Controller with the `ActiveDirectory` module, verify `krbtgt`'s `PasswordLastSet` timestamp (recommended semi-annual/annual cadence in healthy operations) and confirm `ms-DS-MachineAccountQuota` is hardened from `10` to `0` [510, 513, 521]:

```powershell
Get-ADUser -Identity krbtgt -Properties PasswordLastSet, 'msDS-SupportedEncryptionTypes' |
    Select-Object SamAccountName, Enabled, SID, PasswordLastSet, 'msDS-SupportedEncryptionTypes'
(Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
```

Expected output on a hardened domain:

```text
SamAccountName Enabled SID                                        PasswordLastSet       msDS-SupportedEncryptionTypes
-------------- ------- ---                                        ---------------       -----------------------------
krbtgt           False S-1-5-21-194827361-847261920-319283746-502 9/15/2026 2:00:00 AM                             24
0
```

`ms-DS-MachineAccountQuota = 0` prevents standard users from creating rogue `SPN`-bearing computer accounts to bootstrap `RBCD` / `KrbRelayUp` / `Certifried` chains [451, 489, 521].

### Auditing Unauthorized `DCSync` Replication Rights on the Domain Root

Enumerate principals holding `DS-Replication-Get-Changes` (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`), `DS-Replication-Get-Changes-All` (`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`), or `DS-Replication-Get-Changes-In-Filtered-Set` (`89e95b76-444d-4c62-991a-0facbeda640c`) on the domain naming context [492, 530]:

```powershell
$dn = ([ADSI]'LDAP://RootDSE').defaultNamingContext
(Get-Acl "AD:\$dn").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ObjectType -match '1131f6aa|1131f6ad|89e95b76' } |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType
```

Expected output (only Domain Controllers and Enterprise Domain Controllers should hold replication-all rights):

```text
IdentityReference                  ActiveDirectoryRights ObjectType
-----------------                  --------------------- ----------
NT AUTHORITY\ENTERPRISE DOMAIN ...         ExtendedRight 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
BUILTIN\Administrators                     ExtendedRight 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
```

Any user, service account (such as an over-privileged Entra Connect `MSOL_*` account), or non-Tier-0 group appearing here possesses direct `DCSync` authority to extract `krbtgt` [448, 492, 530]. Before executing an emergency two-reset `krbtgt` rotation (`> 10` hours apart), always verify clean replication (`repadmin /replsummary`) so Domain Controllers do not fall out of key synchronization [513].

## Summary & Handoff

Active Directory Kerberos replaces password-equivalent wire challenges with encrypted tickets (`AS`/`TGS`/`AP`), `FAST` armoring, SID-mapped `PKINIT` (`KB5014754`), `gMSA`/`dMSA` managed secrets, `AES`-only enforcement (`CVE-2026-20833`), and four-signature `[MS-PAC]` validation (`KB5020805`). Yet its core 1988 design trade-offs remain permanent: offline `AP-REQ` decryption precludes real-time ticket revocation, `RBCD` and unsigned `LDAP` preserve Kerberos relay paths (`KrbRelayUp`), and every `TGT` in the realm reduces to the single symmetric secret of `RID 502` `krbtgt`, turning `DCSync` disclosure into undetectable `Diamond` and `Sapphire` ticket forgery recoverable only through double rotation and Tier-0 remediation.

Because production Active Directory estates pair Kerberos with X.509 certificates, managed service accounts, and cloud federation, defending `krbtgt` alone does not close realm identity. [Enterprise PKI, Service Identities, and Hybrid Bridges (Chapter 15)](31-enterprise-pki.md) examines how `AD CS` (`ESC1` through `ESC16`), `Shadow Credentials`, `Windows LAPS`, Windows Server 2025 `dMSA` (`BadSuccessor`), and `Microsoft Entra Connect` establish parallel Tier-0 trust roots alongside the `KDC`. From there, [Pass-the-Hash to Pass-the-PRT (Chapter 16)](11-pth-prt.md) traces how single sign-on moved into `cloudap.dll` and `TPM`-backed Primary Refresh Tokens (`PRTs`), showing where `Pass-the-PRT` and browser cookie theft bypass local storage isolation, while [Windows Hello and Passkeys (Chapter 17)](12-hello.md) replaces shared password secrets altogether with hardware-bound asymmetric keys across both Kerberos (`PKINIT`) and the web (`CTAP2`/`WebAuthn`). Finally, [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md) analyzes the cross-tenant token-signing key compromise that mirrored `Golden Ticket` forgery inside Microsoft's cloud control plane.
