# The Death of NTLM

## Overview

* **Role in the Chain:** Legacy symmetric challenge-response wire protocol inside `lsass.exe` (`msv1_0.dll`) backing `SPNEGO` (`Negotiate`) whenever Kerberos cannot run; represents the primary protocol-level relay and password-equivalence liability inherited by modern Active Directory.
* **Core Security Invariant:** Under hardened transitional configurations prior to default disablement, `NTLMv1` and `LM` are refused (`LmCompatibilityLevel = 5` and 24H2+ `NTLMv1` removal), `MIC` binds all three handshake messages, and every accepting target enforces transport signing (`SMB`/`LDAP` signing) plus TLS Channel Binding Tokens (`EPA` `MsvAvChannelBindings`).
* **Trusted Computing Base (TCB):** Client and server `msv1_0.dll` (`[MS-NLMP]`), `Negotiate` / `[MS-NEGOEX]` mechanism selection, Domain Controller `Netlogon` pass-through validation, `IAKerb` and `Local KDC` Kerberos replacements, and Group Policy locks preventing `NTLM` fallback or re-enablement.
* **Primary Failure Modes:** Password-equivalence of static `NTOWF` digests (`Pass-the-Hash`), cross-protocol man-in-the-middle forwarding of unbound `CHALLENGE`/`AUTHENTICATE` exchanges (`SMBRelay`), negotiated `MIC` stripping (`Drop the MIC`, `CVE-2019-1040`), RPC forced-authentication coercion (`PetitPotam`, `SpoolSample`), and `AD CS` HTTP/HTTPS relay (`ESC8`).
* **Handoff:** Retires network `NTLM` across a three-phase roadmap culminating in default-off enforcement via `IAKerb`, `Local KDC`, and `IP-SPN`, transferring all interactive domain and local wire authentication (along with surviving relay obligations such as `KrbRelay`) to [Kerberos and Ticket Forgery (Chapter 14)](10-kerberos.md).

## Core Engineering Problem & Threat Model

[Chapter 12](08-credential-guard.md) demonstrated that moving long-term `NTOWF` hashes into `VTL1` `LsaIso.exe` (`Credential Guard`) solved *credential extraction* from workstation memory while leaving *credential use and live protocol relay* completely exposed (`Pass-the-Challenge` [443]). Even on a fully patched enterprise network with Credential Guard and `SMB` signing enabled everywhere, an unauthenticated or low-privilege attacker on the local network can coerce a Domain Controller's `SYSTEM` service into initiating an outbound `NTLM` authentication and forward that live three-message handshake to an Active Directory Certificate Services (`AD CS`) web endpoint (`ESC8`), achieving full forest compromise in seconds without ever extracting a password hash [454, 455, 456].

`NTLM` originated in a pre-internet architecture: IBM and Microsoft's 1987 OS/2 LAN Manager (`LM` hash, splitting an uppercased 14-character password into two 56-bit DES keys encrypting `KGS!@#$%` [457, 458]), succeeded in Windows NT 3.1 (1993) by `NTLMv1` (`NTOWF = MD4(UTF-16LE(password))` keying three 56-bit DES blocks) and in Windows NT 4.0 SP4 (1998) by `NTLMv2` (`HMAC-MD5` over server/client nonces and `AV_PAIRS`) [458, 459]. Although Windows 2000 replaced `NTLM` with Kerberos as Active Directory's primary protocol behind the `SPNEGO` (`Negotiate`) SSPI wrapper [460], `NTLM` survived for twenty-five more years because Kerberos could not satisfy four operational fallback conditions [461]. First, clients authenticating across segmented networks or VPN edges often lacked direct network line-of-sight to a Domain Controller's Key Distribution Center (`KDC`). Second, local `SAM` and standalone workgroup accounts operated without any `KDC` infrastructure. Third, connections targeting raw IP literals (`\\10.1.2.3\share`), `CNAME` aliases, or unregistered hostnames left `kerberos.dll` unable to construct a target Service Principal Name (`SPN`). Fourth, legacy applications continued invoking `AcquireCredentialsHandle(..., "Ntlm", ...)` or `RPC_C_AUTHN_WINNT` directly rather than negotiating through `"Negotiate"`.

The `NTLM` threat model assumes an adversary positioned on an internal subnet (capable of coercing RPC services and relaying TCP sessions) or holding a stolen 16-byte `NTOWF` digest. Because two decades of point retrofits failed to close cross-protocol relay paths across those four fallbacks, Microsoft deprecated all versions of `NTLM` in June 2024 and committed to disabling network `NTLM` by default once Kerberos natively covers all four scenarios [279, 461, 462].

## Architectural Deep Dive

### The `[MS-NLMP]` Three-Message Handshake and `NTOWFv2` Math

On the wire, `NTLM` executes a three-leg challenge-response embedded inside application transports (`SMB`, `HTTP`, `RPC`, `LDAP`, `MSSQL`) (`diagrams/09-ntlm-handshake.svg`) [458]:

![Figure: The three-message NTLMv2 handshake on the wire. The client opens with NEGOTIATE (capability flags, no identity); the server replies with CHALLENGE (a 64-bit nonce plus TargetInfo AV_PAIRS); the client derives NTOWFv2 and NTProofStr from the NT-hash and returns AUTHENTICATE, carrying the proof plus an optional MIC and optional MsvAvChannelBindings CBT. The server holds no plaintext, so it pass-throughs the response to the domain controller via Netlogon to verify. The structural point is the oxblood callout: nothing in the three messages binds the exchange to a transport, a server, or a service: the property NTLM relay eats for twenty-five years.](diagrams/09-ntlm-handshake.svg)

Across those three frames, the client opens with a Type 1 `NEGOTIATE_MESSAGE` advertising dialect and security flags (`NTLMSSP_NEGOTIATE_UNICODE`, `NTLMSSP_NEGOTIATE_SIGN`, `NTLMSSP_NEGOTIATE_SEAL`, `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`, and `NTLMSSP_NEGOTIATE_KEY_EXCH`) without revealing user identity [458]. The server replies with a Type 2 `CHALLENGE_MESSAGE` supplying an 8-byte random `ServerChallenge` nonce alongside a length-prefixed `TargetInfo` list of `AV_PAIR` structures carrying server NetBIOS and DNS names, a `FILETIME` timestamp, and capability flags [458]. The client concludes the exchange with a Type 3 `AUTHENTICATE_MESSAGE` proving possession of `NTOWF = MD4(UTF-16LE(password))` by returning the `NTLMv2` response (`NTProofStr || temp`) together with the username, domain, workstation name, an optional encrypted `RandomSessionKey`, and optional message-integrity and channel-binding fields [458].

Under `[MS-NLMP]` §3.3.2, constructing that Type 3 `NTLMv2` proof evaluates three deterministic expressions: `NTOWFv2 = HMAC-MD5(NTOWF, UNICODE(Upper(User) || UserDom))`, the client blob `temp = 0x01 || 0x01 || Z(6) || Time || ClientChallenge || Z(4) || ServerName(AV_PAIRS) || Z(4)`, and `NTProofStr = HMAC-MD5(NTOWFv2, ServerChallenge || temp)` [458]. When `NTLMSSP_NEGOTIATE_KEY_EXCH` is negotiated, the client wraps `RandomSessionKey` under `SessionBaseKey = HMAC-MD5(NTOWFv2, NTProofStr)`. For domain accounts, a member server cannot verify `NTProofStr` locally because it never holds the user's `NTOWF`; instead, it forwards `(ServerChallenge, NTProofStr, temp)` over a secure `Netlogon` RPC channel to a Domain Controller, which checks the MAC and returns the user's PAC and SIDs together with `SessionBaseKey` [458].

Two fatal properties stand out immediately in those equations. First, `NTOWF` is unsalted and password-equivalent: `NTOWFv2` depends only on `NTOWF` and public identity strings, meaning anyone holding `NTOWF` computes valid responses indefinitely without the password, while offline GPU clusters test weak MD4 and NetNTLMv2 candidates at billions of guesses per second [427, 459]. Second, the server never authenticates itself to the client, and nothing in the core `NTProofStr` calculation proves *which* physical server or TLS session the client intended to reach.

### Twenty Years of Bolt-On Retrofits: Signing, `MIC`, and `EPA` (`CBT`)

To contain man-in-the-middle relays without breaking wire compatibility, Microsoft layered three optional cryptographic bindings onto `NTLMv2` across two decades [458, 463, 464]. The earliest defense was transport-layer signing and sealing (`SMB` signing, `LDAP` signing and sealing, and RPC packet integrity), which uses `ExportedSessionKey` to attach a per-message MAC or cipher stream to subsequent application frames such as `SMB2` AES-CMAC/GMAC packets or `LDAP` SASL-wrapped messages [458, 464]. When an attacker relays an `NTLM` handshake to an SMB server that *requires* signing, the three-message handshake completes, yet the attacker lacks `ExportedSessionKey` (delivered out-of-band to the real target server by the Domain Controller over `Netlogon`) and therefore cannot forge signed SMB commands. Crucially, however, transport signing protects only protocols that mandate per-packet MACs; relaying an `SMB` handshake cross-protocol into plain `HTTP` bypasses `SMB` signing flags completely [454, 465].

Because an inline attacker could otherwise strip `NTLMSSP_NEGOTIATE_SIGN` out of `NEGOTIATE` before forwarding it to an acceptor where signing was optional, Microsoft added a whole-transcript Message Integrity Code (`MIC`). Whenever `MsvAvFlags` bit `0x00000002` is set inside the Type 3 `AUTHENTICATE` `AV_PAIRS`, the client embeds a 16-byte `MIC = HMAC-MD5(ExportedSessionKey, NEGOTIATE || CHALLENGE || AUTHENTICATE_zeroed_MIC)` over the exact wire bytes of all three messages so tampering with negotiated capability flags invalidates authentication [458].

Closing relays into TLS-wrapped protocols such as HTTPS and `LDAPS` required a third layer: service binding (`MsvAvTargetName`) and Extended Protection for Authentication (`EPA`, implementing `RFC 5929` `tls-server-end-point`) [458, 463]. Under `EPA`, a TLS client hashes the server's X.509 leaf certificate, writes the resulting 16-byte MD5 GSS channel-binding digest into the `MsvAvChannelBindings` `AV_PAIR` (covered by both `NTProofStr` and `MIC`), and records the intended target `SPN` in `MsvAvTargetName`. When an HTTPS or `LDAPS` endpoint enforces `EPA = Always / Required`, an attacker terminating the victim's TLS connection on a rogue listener (`Cert_A`) and opening a second TLS leg to `/certsrv/` (`Cert_B`) fails authentication because `MsvAvChannelBindings(Cert_A)` cannot match `Hash(Cert_B)` [456, 463].

### Engineering the Exit: `IAKerb`, `Local KDC`, `IP-SPN`, and the Three-Phase Roadmap

Because point retrofits collapsed whenever *any* single endpoint left `EPA` or transport signing optional (`ESC8` [454]), Microsoft announced in October 2023 and detailed in January 2026 a structural replacement for all four `NTLM` fallback triggers inside the existing `SPNEGO` / `[MS-NEGOEX]` (`Negotiate`) envelope (`diagrams/09-ntlm-fallback-closure.svg`) [461, 462, 466, 467].

![Figure: The removal architecture for NTLM's fallback. Each of the four reasons Negotiate fell back to NTLM (amber, left) is closed by an engineered mechanism (green): no DC line-of-sight by IAKerb, no domain by a Local KDC over the SAM, a missing SPN by IP-SPN policy, and hard-coded `Ntlm` call sites by the Negotiate refactor. All four ride NEGOEX inside the existing Negotiate/SSPI envelope, so the unchanged API now prefers Kerberos with no application change.](diagrams/09-ntlm-fallback-closure.svg)

To eliminate no-DC line-of-sight fallbacks, Windows revives the GSS-API `IAKerb` protocol (`draft-ietf-kitten-iakerb`, long supported in MIT `krb5` and macOS [468]) inside `[MS-NEGOEX]`: a client unable to reach a Domain Controller directly encapsulates standard Kerberos `AS-REQ` and `TGS-REQ` messages inside `Negotiate` tokens addressed to the target application server, which forwards them as an untrusted courier to a reachable `KDC` and relays back the encrypted replies [461, 466, 467, 468]. To eliminate non-domain `NTLM` logons, Windows pairs `IAKerb` with `Local KDC`, a lightweight Kerberos `KDC` backed by the local machine `SAM` database and exposed exclusively over `IAKerb` / `NEGOEX` so local accounts (`.\LocalAdmin`) and workgroup file shares achieve full Kerberos mutual authentication and ticket encryption without touching `NTLM` [461, 466, 469]. The remaining two fallback paths close through Server 2025+ `IP-SPN` policies permitting Kerberos ticket issuance for IP-literal connections [466] and an OS-wide refactoring of inbox callers away from explicit `"Ntlm"` and `RPC_C_AUTHN_WINNT` bindings onto `"Negotiate"` [461, 462].

Microsoft sequenced this retirement as a three-phase dependency chain (`diagrams/09-ntlm-disablement-roadmap.svg`) [279, 462, 470]. Phase 1, shipped across 2024 and 2025, formally deprecated all `NTLM` dialects in June 2024, removed the `NTLMv1` server feature outright in Windows 11 24H2 and Windows Server 2025 in November 2024 [279], and delivered Enhanced `NTLM` Auditing (`KB5064479`, July 2025) to record process-level callers, target endpoints, and fallback reason codes under `Event IDs 4020-4033` [470]. Phase 2 (`H2 2026` pre-release) flights `IAKerb`, `Local KDC`, `IP-SPN` policies, and inbox `Negotiate` refactors to drain the legitimate `NTLMv2` fallback traffic identified by Phase 1 telemetry [462, 466]. Once those replacements reach general availability, Phase 3 (the next major Windows and Windows Server release) disables network `NTLM` by default across client and server SKUs, while retaining `NTLMv2` binaries inside the OS for explicit, scoped Group Policy exceptions rather than deleting files immediately [462].

![Figure: The three-phase NTLM disablement roadmap drawn as a dependency chain. Each phase produces the input the next consumes. Phase 1 (NOW) is audit: KB 5064479 enhanced logging plus NTLMv1 removal in 24H2/WS2025, whose telemetry names the callers Phase 2 must refactor. Phase 2 (H2 2026) ships the closures in pre-release (IAKerb, Local KDC, IP-SPN policy, and the Negotiate-first refactor) all of which must reach GA before Phase 3 (next major release) flips network NTLM off by default. The amber caveat records the honest limit: disabled is not removed. NTLM stays in the OS and policy can re-enable it.](diagrams/09-ntlm-disablement-roadmap.svg)

## Attack Catalog & Gap Analysis

The twenty-eight-year offensive history of `NTLM` demonstrates how every point mitigation (`MS08-068`, `SMB` signing, `MIC`, `Credential Guard`) left an adjacent cross-protocol or forced-coercion path open until `ESC8` forced protocol retirement.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `Pass-the-Hash` (`PtH`, Ashton / `Mimikatz`) | 1997-present | Password-knowledge proof in `NTLMv1`/`NTLMv2` | Stolen 16-byte `NTOWF` from `LSASS`, `SAM`, or `NTDS.dit` | Computes valid `NTOWFv2` and `NTProofStr` directly from static `NTOWF` without knowing plaintext password | Isolate `LSASS` via Credential Guard ([Chapter 12](08-credential-guard.md)), use `Protected Users`, and disable `NTLM` [69, 427, 435] |
| `SMBRelay` & Self-Relay (`CVE-2008-4037` / `MS08-068`) | 2001-present | Server/session binding of 3-message `NTLM` handshake | Victim connecting to attacker listener + target with `SMB` signing off | Relays `NEGOTIATE`/`CHALLENGE`/`AUTHENTICATE` inline to execute SMB/SCM commands as victim | Require `SMB` signing across all clients and member servers (default-expanded in Win11 24H2 / WS2025) [464, 471, 472] |
| `Drop the MIC` (`CVE-2019-1040`) | 2019 | `MIC` tamper protection over `NEGOTIATE` signing flags | Network relay from `SMB` coercion (`SpoolSample`) to `LDAP` | Strips `NTLMSSP_NEGOTIATE_SIGN`, `ALWAYS_SIGN`, `Version`, and `MIC` field so DC `LDAP` accepts unsigned relayed session for `RBCD`/`DCSync` | Apply June 2019 `CVE-2019-1040` patch; enforce `LDAP` signing and `LDAPS` channel binding [465, 473] |
| Forced RPC Coercion (`SpoolSample`, `PetitPotam` `CVE-2021-36942`, `Coercer`) | 2018-2022 | Spontaneous outbound `SYSTEM` machine-account authentication | Network access to `MS-RPRN`, `MS-EFSR` (`EfsRpcOpenFileRaw`), `MS-DFSNM`, or `MS-FSRVP` | Invokes RPC methods accepting attacker UNC paths, causing DC/server `SYSTEM` to `NTLM`-authenticate outbound on demand | Disable `Print Spooler` on DCs/servers, apply `CVE-2021-36942` EFS patches, and block outbound `NTLM` [455, 474, 475] |
| `AD CS` Web Relay (`ESC8`, `ntlmrelayx`) | 2021-present | Domain Tier-0 isolation via HTTP/HTTPS `/certsrv/` | Coercion vector + `AD CS` Web Enrollment lacking `EPA = Always` | Relays coerced DC machine-account `NTLM` auth to `/certsrv/`, enrolls `Machine` certificate, requests DC `TGT` via `PKINIT`, and runs `DCSync` | Disable HTTP `/certsrv/`, enforce HTTPS + `EPA = Always` (`KB5005413`), or disable `NTLM` on CA (`Phase 3`) [454, 456, 476, 477] |
| Marshaled-DNS Reflection (`CVE-2025-33073`, `CVE-2025-53778`) | 2025 | Loopback SMB/Kerberos reflection guard → Remote `SYSTEM` | Domain user registering DNS record + target lacking `SMB` signing | Appends serialized `CREDENTIAL_TARGET_INFORMATION` to attacker DNS record; coerced host believes remote relay is local loopback `SYSTEM` auth [897, 898] | Apply June/Aug 2025 patches (`ksecdd!CredUnmarshalTargetInfo` check) and require `SMB` signing + `SMBv3.1.1` encryption / `SMB over QUIC` [897, 899] |

### Negotiated-Integrity Stripping: `Drop the MIC` (`CVE-2019-1040`)

Cross-protocol relays (`SMB → LDAP`) normally stall because an `SMB` client sets `NTLMSSP_NEGOTIATE_SIGN`, causing `LDAP` to reject unsealed/unsigned subsequent LDAP `ModifyRequest` writes unless stripped, and stripping flags breaks the `MIC`. In June 2019, Marina Simakov and Yaron Zinar (`Preempt`) discovered that whether `AUTHENTICATE` *contained* a `MIC` was signaled solely by an unauthenticated flag (`MsvAvFlags & 0x2`) and `Version` structure [465, 473]. By zeroing `MsvAvFlags`'s `MIC` bit, stripping `SIGN` flags from `NEGOTIATE`, and zeroing the `MIC` field, a relay tricked unpatched Domain Controllers into accepting modified `SMB` authentications over `LDAP` to configure `RBCD` (`msDS-AllowedToActOnBehalfOfOtherIdentity`) or `ACL` `DCSync` rights [465, 473].

### Confused-Deputy Coercion + Unbound HTTP: `PetitPotam` and `ESC8`

Disclosed side by side in summer 2021 by Will Schroeder and Lee Christensen (*Certified Pre-Owned*, `ESC8` [454, 476]) and Gilles Lionel (*PetitPotam*, `CVE-2021-36942` [455]), the `PetitPotam → ESC8` kill chain proved why piecemeal endpoint retrofits could never rescue `NTLM`. An unauthenticated attacker on the network invoked `EfsRpcOpenFileRaw` over `LSARPC` (`\pipe\lsarpc`) against a Domain Controller while passing an attacker-controlled UNC path (`\\AttackerIP\share\file`) [455], one of dozens of `SYSTEM` UNC-coercion RPC methods spanning `MS-RPRN`, `MS-DFSNM`, and `MS-FSRVP` subsequently cataloged by `Coercer` [474, 475]. In response, the Domain Controller's `SYSTEM` service dutifully initiated an outbound `NTLM` handshake as `DC01$` toward `AttackerIP`: Credential Guard did not interfere because no hash left `VTL1`, and `SMB` signing did not interfere because `AttackerIP` never completed an `SMB` session.

Instead, `Impacket`'s `ntlmrelayx.py` forwarded the live `NTLM` tokens inline over HTTP or HTTPS to Active Directory Certificate Services Web Enrollment (`/certsrv/certfnsh.asp`), where `EPA` defaulted to off or `WhenSupported` [456, 476, 477]. Accepting the relayed `DC01$` authentication, `/certsrv/` issued a valid X.509 client-authentication certificate for the Domain Controller machine account. Presenting that certificate to the `KDC` via Kerberos `PKINIT` ([Chapter 14](10-kerberos.md), [Chapter 15](31-enterprise-pki.md)) yielded a genuine `DC01$` `TGT` alongside `NT` hash recovery (`UnPAC-the-hash`), enabling immediate `DCSync` extraction of `krbtgt` [454].

### The 2025 Reflection Revival: `CVE-2025-33073` Across Both `NTLM` and `Kerberos`

After `MS08-068` (`2008`) blocked relaying a machine's `SMB` `NTLM` handshake back to the exact same machine, defenders treated self-relay (`reflection`) as extinct. In June 2025, RedTeam Pentesting and Synacktiv disclosed `CVE-2025-33073` (followed by channel-binding bypass `CVE-2025-53778`), proving that reflection survived inside `LSASS`'s loopback optimization [897, 898]. By registering an Active Directory DNS record appending a base64-marshaled `CREDENTIAL_TARGET_INFORMATION` (`1UWhRCAAA...`) suffix to a hostname and coercing a target machine (`PetitPotam` / RPC) to connect to it, `srvcli` stripped the suffix via `CredUnmarshalTargetInfo` and tricked `msv1_0` / `kerberos` into treating the outbound connection as a *local loopback authentication* carrying the live `NT AUTHORITY\SYSTEM` token context [897]. Relaying that authentication straight back to the victim's own `TCP/445` `SMB` service granted immediate remote `SYSTEM` command execution on any Windows host that did not enforce `SMB` signing, across both `NTLM` and `Kerberos` [897, 898]. That disclosure reinforced why Windows 11 `24H2` and Windows Server 2025 turned `SMB` signing on by default across all connections and promoted `SMBv3.1.1` (`AES-128-GCM` / `AES-256-GCM`) encryption and TLS-1.3-backed `SMB over QUIC` [899].

## Theoretical Limits & Structural Invariants

### Weakest-Target Collapse in Cross-Protocol Relays

In any symmetric challenge-response protocol lacking mandatory, cryptographic target-and-channel binding inside the core proof (`NTProofStr`), the security of every outbound client authentication degrades to the weakest accepting service anywhere in the forest. Enforcing `SMB` signing on 99.9% of servers and `LDAP` signing on all Domain Controllers buys zero protection if a single legacy IIS `/certsrv/` virtual directory, MSSQL listener, or Exchange endpoint accepts unbound `NTLM` without `EPA = Always` [454, 456].

### Decoupling `NTLM` Disablement from Relay Elimination and Local `SAM` Risk

Consistent with Law 16, retiring `NTLM` as a wire protocol must not be confused with eliminating authentication relay or local password-equivalence.

> **Key idea.**
> Three structural limits survive Microsoft's Phase 3 default-off milestone. First, *disabled is not deleted*: because `NTLMv2` binaries remain in the OS for compatibility overrides [462], a Tier-0 GPO compromise can silently re-enable `NTLM`, requiring continuous monitoring of `RestrictSendingNTLMTraffic` and `NTLM/Operational` telemetry. Second, *Kerberos relay survives without channel binding*: coercing a machine or user into authenticating via Kerberos (`HTTP`, `SMB`, or `DCOM`) and relaying the `AP-REQ` token to an unsigned `LDAP` or `HTTP` endpoint lacking `EPA` (`KrbRelay` and `KrbRelayUp` [478], [Chapter 14](10-kerberos.md)) reproduces the exact `ESC8` and `RBCD` takeover without a single `NTLM` packet, keeping `LDAP` signing, `LDAPS` channel binding, and `EPA = Always` mandatory post-`NTLM` controls. Third, *local `SAM` hashes remain password-equivalent*: `Local KDC` removes `NTOWF` derivatives from the network wire via `IAKerb`, yet still derives keys from `SAM` hashes stored on disk, meaning a `SYSTEM` attacker dumping the local `SAM` still recovers offline-crackable or reusable `NTOWF` material [69, 461].

## Inspecting and Verifying on a Running System

Operational readiness for `NTLM` disablement requires auditing live callers via `KB5064479` enhanced logs, inspecting `Lsa` / `MSV1_0` restriction and `SMB` signing policies, and hunting residual `NTLMv1` events on down-level hosts.

### Querying `KB5064479` Enhanced `NTLM` Operational Telemetry (`Phase 1`)

Inspect the `Microsoft-Windows-NTLM/Operational` channel (client events `4020`/`4021`, server events `4022`/`4023`, DC events `4030`-`4033`) to identify exact calling processes, target SPNs/IPs, and fallback reason codes [470]:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-NTLM/Operational' -MaxEvents 5 -ErrorAction SilentlyContinue |
    Where-Object Id -ge 4020 | Select-Object TimeCreated, Id, Message
```

Expected output format when enhanced `NTLM` auditing GPOs are active:

```text
TimeCreated           Id Message
-----------           -- -------
11/14/2026 9:05:18 AM 4020 Outbound NTLM authentication: Process: C:\App\LegacySync.exe, Target: cifs/10.20.4.15, Reason: IPAddressTarget...
```

Mapping each event's `Reason` field (`IPAddressTarget` → `IP-SPN` or DNS migration, `NoDCConnectivity` → `IAKerb`, `LocalAccount` → `Local KDC`, `ExplicitNTLMPackage` → vendor refactor to `Negotiate`) builds the deterministic Phase 2 remediation backlog [462, 470].

### Auditing `LmCompatibilityLevel`, `RestrictNTLM`, and `SMB` Signing State

Verify that `LM` and `NTLMv1` responses are refused (`LmCompatibilityLevel = 5`), check outbound/inbound `NTLM` restriction/audit policy (`1` = Audit, `2` = Deny all), and confirm `SMB` signing enforcement from an administrative session [464, 470]:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic','AuditReceivingNTLMTraffic' -ErrorAction SilentlyContinue
Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature
```

Expected output on a hardened server enforcing `NTLMv2`-only, outbound `NTLM` deny/audit, and mandatory `SMB` signing:

```text
LmCompatibilityLevel : 5

RestrictSendingNTLMTraffic : 2
AuditReceivingNTLMTraffic  : 2

EnableSecuritySignature RequireSecuritySignature
----------------------- ------------------------
                   True                     True
```

Setting `RequireSecuritySignature = True` across both `Get-SmbServerConfiguration` and `Get-SmbClientConfiguration` blocks classic `SMB`-targeted relays, while `EPA = Always` on IIS `/certsrv/` (`KB5005413`) closes `ESC8` [456, 464].

### Hunting Residual `NTLMv1` Logons (`Event ID 4624`) on Mixed Estates

While Windows 11 24H2 and Windows Server 2025 removed the `NTLMv1` server component [279], verify across older member servers and Domain Controllers that zero logons negotiate `NTLM V1` [479]:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 3 -and $_.Properties[10].Value -match 'NTLM' -and $_.Properties[14].Value -eq 'NTLM V1' } |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='Workstation';E={$_.Properties[11].Value}}
```

Expected output on a clean estate:

```text
# Empty output (zero NTLM V1 network logons detected)
```

Any returned host indicates an appliance, legacy script, or misconfigured `LmCompatibilityLevel < 3` endpoint transmitting trivially crackable 56-bit DES `NTLMv1` responses [441, 479].

## Summary & Handoff

For nearly three decades, `NTLM` persisted as Active Directory's silent foundation because Kerberos could not handle offline `KDCs`, local `SAM` accounts, IP-literal targets, or hard-coded `RPC_C_AUTHN_WINNT` callers. That persistence sustained five generations of attacks (from `Pass-the-Hash` and `SMBRelay` through `Drop the MIC` `CVE-2019-1040`, `PetitPotam`, and `AD CS` `ESC8`), proving that per-endpoint retrofits collapse whenever any single acceptor leaves `EPA` or signing optional. By engineering `IAKerb`, `Local KDC`, and `IP-SPN` inside `[MS-NEGOEX]` alongside `KB5064479` telemetry and `NTLMv1` removal, Windows finally makes default-off `NTLM` operationally achievable.

Once `Negotiate` routes every domain and local authentication exclusively through Kerberos, the adversary's focus shifts immediately to the tickets, Privilege Attribute Certificates (`PACs`), delegation edges, and root `krbtgt` keys of Kerberos itself. [Kerberos and Ticket Forgery (Chapter 14)](10-kerberos.md) examines how Active Directory executes `AS`, `TGS`, and `AP` exchanges, validates `PAC` signatures, and defends against `Kerberoasting`, `KrbRelay`, `RBCD`, `Silver` tickets, and `Golden` tickets (`krbtgt` compromise), while [Chapter 16](11-pth-prt.md) and [Chapter 17](12-hello.md) trace how enterprise single sign-on extends beyond domain tickets to Entra ID `Primary Refresh Tokens` and hardware-bound `FIDO2` passkeys.
