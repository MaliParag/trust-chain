# Continuous Access Evaluation

## Overview

* **Role in the Chain:** Closes the post-issuance OAuth 2.0 bearer-token revocation window (`t > 0`) created by Zero Trust point-in-time evaluation ([Chapter 17](13-zero-trust.md)), pushing critical account, credential, and risk state changes from Microsoft Entra ID to cooperating Resource Providers (`RPs`) without reintroducing per-request IdP bottlenecks.
* **Core Security Invariant:** A CAE-enlightened Resource Provider (`Exchange Online`, `SharePoint Online`, `Microsoft Teams`, `Microsoft Graph`) validates incoming JWTs locally in $O(1)$ time against cached subject revocation watermarks and rejects stale tokens on the next HTTP request (`401 Unauthorized` + `WWW-Authenticate` `claims` challenge) within 15 minutes for critical events and instantly for enforced IP-location shifts.
* **Trusted Computing Base (TCB):** Microsoft Entra ID as event transmitter, Entra's internal pub-sub delivery bus (and OpenID `SSF 1.0` / `RFC 8417` `SET` streams in cross-vendor deployments), each CAE-participating Resource Provider's local revocation cache, and `MSAL` clients advertising `xms_cc: ["cp1"]`.
* **Primary Failure Modes:** Non-`cp1` client fallback to static 1-hour tokens, pivoting to non-CAE planes (`Azure Resource Manager`, `SAML` apps, third-party SaaS lacking `CAEP` receivers, or SharePoint's user-risk gap), automated exfiltration inside the 15-minute propagation window, pre-detection replay of unbound bearer tokens, `Pass-the-PRT` token re-minting, and offline IdP signing-key forgery (`Storm-0558`).
* **Handoff:** Governs temporal authorization freshness for legitimately issued cloud session tokens; hands cloud workload memory isolation against untrusted hypervisors to [Confidential VMs (Chapter 19)](29-confidential-vms.md), and dissects forged tokens that never trigger CAE state transitions in [When the Chain Snaps: Storm-0558 (Chapter 20)](15-storm0558.md).

## Core Engineering Problem & Threat Model

When Dick Hardt and the IETF OAuth Working Group published `RFC 6749` (*The OAuth 2.0 Authorization Framework*, October 2012) [725], they deliberately inverted the 2000s Web Access Management (`WAM`) architecture. Whereas `WAM` forced every protected HTTP request through a synchronous Policy Decision Point (`PDP`) round-trip (yielding instant revocation at the cost of chatty latency and zero cross-tenant federation), OAuth 2.0 replaced per-request checks with self-contained JSON Web Tokens (`JWTs`) verified locally by Resource Servers in $O(1)$ cryptographic time.

Local verification scaled cloud APIs to billions of requests per second, but introduced a severe temporal blind spot: an access token minted at `09:00` remained cryptographically valid until its `exp` timestamp (`10:00` or later) even if an administrator disabled the user, reset their password, or confirmed account compromise at `09:01` [155, 725]. Across the next eight years, three obvious patches failed at cloud hyperscale:
1. **`RFC 7009` Token Revocation (`/revoke`, August 2013 [726]):** Client-initiated logout endpoint; useless against hostile token thieves or terminated insiders, and explicitly unable to invalidate self-contained JWTs cached at independent Resource Servers.
2. **`RFC 7662` Token Introspection (`/introspect`, October 2015 [727]):** Synchronous per-request Resource-Server-to-IdP polling; appropriate for low-volume opaque tokens, but catastrophic at Microsoft 365 scale where an IdP blip would take down every API request globally.
3. **Ultra-Short Access-Token Lifetimes (`5-minute` experiments, 2018-2020 [728, 729]):** Multiplied token-refresh load across every open Outlook, Teams, and OneDrive client, degraded offline/flaky-network reliability, and still left a multi-minute exfiltration window ("a blunt object" in Microsoft Identity Security Director Alex Weinert's April 2020 retrospective [728]).

Closing the fired-employee and active-intrusion gap required a fourth architecture (`diagrams/14-cae-timeline.svg`): server-initiated publish-subscribe push decoupling revocation from token expiry, proposed as `CAEP` by Google's Atul Tulshibagwale in February 2019 [730, 731], shipped in production as Microsoft Entra Continuous Access Evaluation (`CAE`, Preview 2020; GA January 2022) [728, 732, 733], and standardized vendor-neutrally on September 2, 2025 as the OpenID Foundation `SSF 1.0`, `CAEP 1.0`, and `RISC 1.0` Final Specifications [734].

![Figure: The thirteen-year arc from RFC 6749's static-expiry bargain (October 2012) to the OpenID Shared Signals Final Specifications (September 2025), shown as two rails: the IETF and OpenID standards track, and Zero Trust thinking alongside Microsoft Entra's CAE rollout. The oxblood bracket is the fired-employee window: for roughly a decade, 2012-2022, a revoked user's token stayed cryptographically valid until expiry, and Entra CAE's general availability is what finally closed it.](diagrams/14-cae-timeline.svg)

## Architectural Deep Dive

### Pub-Sub Subscription, `401` Claims Challenges, and `28`-Hour Lifetimes

Microsoft Entra `CAE` reconciles near-real-time revocation with zero hot-path IdP round-trips by interlocking three mechanisms (`diagrams/14-cae-roundtrip.svg`) [155, 735]:

![Figure: The end-to-end CAE claims-challenge round trip. A control-plane state change at Entra (steps 1-3) propagates by push to the resource provider, which caches the new revocation state; the next stale-token request is rejected on the data-plane hot path (steps 4-5) with a 401 claims challenge; MSAL then re-acquires and Entra refuses because the account is disabled, so the session terminates (step 6). The hot path is an O(1) signature verification plus an O(1) cached-state lookup, with no authorization-server round-trip.](diagrams/14-cae-roundtrip.svg)

1. **Out-of-Band Push Subscription:** Participating Microsoft 365 Resource Providers subscribe to Entra's critical-event feed. Control-plane traffic scales strictly with *state-mutation rate* (password resets, disablements, risk spikes), never *HTTP request rate*. On the data plane, the RP verifies the JWT signature in $O(1)$ time and checks its local in-memory revocation watermark table in $O(1)$ time [155].
2. **In-Band `401` Claims Challenge:** When a client presents an unexpired JWT issued (`iat` / `nbf`) *before* a cached subject revocation watermark, the RP rejects the request with `HTTP/1.1 401 Unauthorized` and a structured `WWW-Authenticate` header [735]:
   `WWW-Authenticate: Bearer authorization_uri="https://login.windows.net/common/oauth2/authorize", error="insufficient_claims", claims="<base64url JSON>"`
   Decoded, the `claims` JSON typically demands `"nbf": {"essential": true, "value": "<unix_epoch>"}`, instructing the client's Microsoft Authentication Library (`MSAL`) to bypass its local token cache and request a fresh token from Entra ID, where Conditional Access immediately blocks disabled or high-risk accounts [155, 735].
3. **Capability Negotiation (`xms_cc: ["cp1"]`) and Extended `28`-Hour Tokens:** Clients declare ability to parse `insufficient_claims` challenges by sending `xms_cc: ["cp1"]` in token requests (`WithClientCapabilities(new[] {"cp1"})` in `MSAL.NET` / `clientCapabilities: ["CP1"]` in `MSAL.js`) [735, 736, 737]. Once `CAE` handles mid-life revocation, expiry no longer carries the security burden: Entra issues CAE-capable sessions tokens valid up to 28 hours (proactively refreshed in the background), slashing IdP refresh traffic and surviving transient identity outages while non-`cp1` clients remain capped at 1-hour static lifetimes [155, 735].

### Critical Events (`<= 15` Min) vs. Instant IP Evaluation and Workload Scope

Entra `CAE` operates across two distinct enforcement paths with different latency budgets and workload coverage [155, 738]:

| Trigger Event | Signal Origin | Propagation Latency | Enforcing CAE Resource Providers |
|---|---|---|---|
| User account deleted or disabled | Entra ID Directory | Up to 15 minutes | Exchange Online, SharePoint Online, Teams, MS Graph (CA) [155] |
| User password changed or reset | Entra ID / On-Prem Sync | Up to 15 minutes | Exchange Online, SharePoint Online, Teams, MS Graph (CA) [155] |
| MFA enabled for user | Entra ID Directory | Up to 15 minutes | Exchange Online, SharePoint Online, Teams, MS Graph (CA) [155] |
| Admin explicitly revokes refresh tokens | `Revoke-MgUserSignInSession` | Up to 15 minutes | Exchange Online, SharePoint Online, Teams, MS Graph (CA) [155] |
| High user risk detected | Entra ID Protection (`P2`) | Up to 15 minutes | Exchange Online, Teams, MS Graph (not SharePoint Online [155]) |
| Client IP leaves allowed CA Named Location | Direct HTTP socket / proxy observation at RP | Instant (`0` propagation lag) | Exchange, SharePoint, Teams, MS Graph under *Strict Location Enforcement* [155, 738] |

Notice two operational boundaries frequently misstated in secondary literature:
* **Signal Sources Are Not CAE Resource Providers:** *Microsoft Defender for Endpoint* and *Microsoft Intune* feed machine risk and compliance signals *into* Entra ID / Conditional Access ([Chapter 17](13-zero-trust.md)), which can elevate user risk; they are *not* OAuth Resource Providers enforcing `401` CAE claims challenges [155].
* **Non-Participating Planes:** Azure management APIs (Azure Resource Manager `ARM`, Azure Portal/CLI), SAML 2.0 federated web sessions, and several browser/Web-App combinations documented in Microsoft's client matrix remain outside first-party CAE enforcement, falling back to static token expiry [155].

### Vendor-Neutral Shared Signals (`RFC 8417`, `SSF 1.0`, `CAEP 1.0`, `RISC 1.0`) and `PoP` Composition

Because Microsoft's internal Entra-to-M365 pub-sub wire protocol is proprietary, revoking sessions across third-party SaaS (`ServiceNow`, `Workday`, `Salesforce`, `Google Workspace`, `Okta`) relies on the four-layer OpenID Shared Signals architecture finalized in September 2025 [734, 739, 740, 741, 742, 743]:
1. **Envelope (`IETF RFC 8417`, 2018):** Signed Security Event Token (`SET`) JWT carrying event metadata (`events` claim) distinct from access assertions [744].
2. **Delivery (`RFC 8935` Push / `RFC 8936` Poll, 2020):** HTTPS `POST` delivery or long-poll retrieval between Transmitter and Receiver [745].
3. **Stream Control (`OpenID SSF 1.0`, Sept 2025):** Stream configuration, subject registration, and verification heartbeats [734, 746].
4. **Event Vocabularies (`CAEP 1.0` & `RISC 1.0`, Sept 2025):** Standardized schemas for `session-revoked`, `token-claims-change`, `credential-change`, `assurance-level-change`, and `device-compliance-change` (`CAEP`), alongside account-compromise coordination (`RISC`) [734, 747, 748].

Crucially, `CAE` / `CAEP` and Sender-Constrained Tokens occupy orthogonal axes of the session-security plane (`diagrams/14-cae-design-space.svg`) [535, 556, 749]:
* **`CAE` / `CAEP` solves *stale authorization*** (revoking a token when user/policy state changes).
* **`Token Protection` ([Chapter 14](11-pth-prt.md) [535]), `OAuth DPoP` (`RFC 9449` [556]), and `mTLS` Certificate-Bound Tokens (`RFC 8705` [749]) solve *stolen bearer possession*** (preventing an attacker on another host from presenting an unrevoked token). Production cloud security requires composing both.

![Figure: The CAE design space on two axes: what a mechanism solves (stale authorization versus token possession) and how it learns of change (per-request poll versus push and cached state). CAE and OpenID SSF/CAEP cluster as push-based, stale-authorization controls; DPoP and mTLS-bound tokens sit on the possession axis and compose with CAE; RFC 7662 introspection is the per-request-poll alternative; short access-token lifetime is the degenerate fallback; and an identity-aware proxy enforces at a different architectural layer.](diagrams/14-cae-design-space.svg)

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Non-`CP1` Client Capability Omission (`curl`, custom OAuth scripts) | 2022-present | Extended-token CAE contract | Stolen refresh token or phished auth code redeemed without `xms_cc: ["cp1"]` | Requests standard 1-hour non-CAE access token so non-strict endpoints fall back to static 60-minute expiry | Pair `CAE` with Strict Location Enforcement, `Token Protection`, and refresh-token revocation [155, 535, 735, 738] |
| Non-CAE Plane Pivot (`ARM`, `SAML` SaaS, SharePoint Risk Gap) | 2022-present | Tenant-wide uniform revocation assumption | Stolen session/tokens for Azure `ARM`, `SAML` SaaS, or SharePoint under High User Risk | Operates against `management.azure.com` (`ARM`), SAML web apps, or SharePoint (ignoring user-risk events) until natural expiry | Shorten `Sign-in Frequency` for `ARM`/admin portals; onboard SaaS to `OpenID SSF`/`CAEP`; explicitly disable compromised accounts [155, 734] |
| 15-Minute Fan-Out Race & In-Flight Stream Egress | Architectural | Immediate post-detection containment | Automated `Graph` / `EWS` / `SharePoint` exfiltration script | Drains thousands of emails/files inside the `<= 15`-minute critical-event propagation budget or single open HTTP stream | Enforce `Defender for Cloud Apps` rate/session controls and `Strict Location` instant IP checks [155, 687, 738] |
| Unbound Bearer Token Replay Prior to Detection | Persistent | Bearer token confidentiality (`RFC 6749`) | `ESTSAUTH` / access token stolen via `AitM` or infostealer before alert fires | Replays valid `28`-hour CAE token from allowed IP geography; `CAE` stays silent because no critical event fired | Enforce Conditional Access Token Protection (`WAM` PoP) and `Phishing-Resistant MFA` (`Chapters 14, 15`) [535, 559] |
| `Pass-the-PRT` Fresh CAE Token Minting (`roadtx`) | 2020-present | Downstream access-token invalidation | Compromised `PRT` + derived `CloudAP` context key ([Chapter 14](11-pth-prt.md)) | Responds to `401` `nbf` claims challenges by minting brand-new CAE tokens from the stolen `PRT` unless refresh tokens are revoked | Execute `Revoke-MgUserSignInSession` + device disablement in Entra ID alongside password reset [155, 536, 551] |
| Forged IdP Signing Key (`Storm-0558`) | 2023 | Issuance-ledger assumption of `CAE` | Stolen Microsoft/IdP signing key ([Chapter 20](15-storm0558.md)) | Mints valid access tokens offline; Entra never issued the session and pushes zero `CAE` revocation events | Hardware-isolated per-tenant/realm signing keys and strict `kid` validation ([Chapter 20](15-storm0558.md)) [714] |

### Why `Pass-the-PRT` Survives Password Reset Without Session/Device Remediation

When an incident responder resets a user's Active Directory password or triggers a soft policy change without invalidating underlying device/session roots, a `CAE` claims challenge simply asks `MSAL` (or an attacker's `roadtx` client holding stolen `PRT` material from [Chapter 14](11-pth-prt.md)) for a token with a newer `nbf` timestamp [536, 551, 735]. Only when the responder executes explicit refresh-token revocation (`Revoke-MgUserSignInSession`), disables the user/device object, or enforces `Phishing-Resistant MFA` / `Token Protection` that the attacker cannot satisfy does Entra refuse the re-acquisition request [155, 535].

### Emerging Frontier: Non-Human Workload and AI-Agent Identities

Both Microsoft `CAE` and `OpenID CAEP 1.0` model human or managed-device subjects [155, 747]. OAuth `client_credentials` service principals, managed identities, and autonomous AI agent identities (*Conditional Access for Agent Identities*, 2026 [750]) increasingly hold high-privilege Microsoft Graph scopes yet sit largely outside `CAEP` user-session revocation profiles, making short-lived workload identity federation (`OIDC` + `CAE`-enabled workload policies) a primary 2026 engineering frontier [747, 750].

## Theoretical Limits & Structural Invariants

### Distributed Fan-Out Latency ($L_{\text{net}} + L_{\text{queue}}$) and Cooperative RP Integrity

No distributed pub-sub revocation protocol can achieve zero-millisecond global preemption. Even in small, tuned `SSF`/`CAEP` deployments achieving sub-second delivery [751], revocation latency is bounded below by speed-of-light WAN transit ($L_{\text{net}} \approx 70\text{ ms}$ transcontinental) plus global multi-region cache replication ($L_{\text{queue}} \le 15\text{ min}$ SLO across Microsoft 365 [155]). Moreover, `CAE` acts strictly at request-admission boundaries (never preempting an already-accepted HTTP stream) and assumes an honest, uncompromised Resource Provider: a compromised SaaS backend can silently drop incoming `SET` revocation events and continue serving traffic.

### Decoupling Temporal Revocation from Token Binding and Cryptographic Provenance

Consistent with Law 16, shrinking revocation latency (`CAE`) proves neither that the presenter is the legitimate client nor that the identity provider ever issued the token.

> **Key idea.**
> `CAE` answers exactly one question: *"Has the authorization state of a principal whose token Entra legitimately issued changed since `iat`?"* If an attacker steals an active bearer token and replays it *before* any detection fires, `CAE` approves every request unless sender-constrained Proof-of-Possession (`Token Protection` / `DPoP`) is enforced [535, 556]. Worse, if an attacker steals the IdP's signing key and forges tokens offline (`Storm-0558`), `CAE` has no session record to revoke unless an explicit subject-level revocation watermark is pushed ([Chapter 20](15-storm0558.md)) [714].

## Inspecting and Verifying on a Running System

Practitioners verify `CAE` operation across a tenant by auditing Conditional Access `ContinuousAccessEvaluation` session controls, decoding `xms_cc` / `cae` JWT claims and `401` `WWW-Authenticate` challenges, and exercising `Revoke-MgUserSignInSession`.

### Auditing Conditional Access `CAE` Mode and `Strict Location` Policies

Query Microsoft Graph (`Policy.Read.All`) to confirm no Conditional Access policies disable `CAE` and inspect whether `strictLocation` instant IP enforcement is active [155, 738]:

```powershell
Get-MgIdentityConditionalAccessPolicy -All |
    Where-Object { $null -ne $_.SessionControls.ContinuousAccessEvaluation.Mode } |
    Select-Object DisplayName, State, @{N='CaeMode';E={$_.SessionControls.ContinuousAccessEvaluation.Mode}}
```

Expected output (`strictEnforcement` / `strictLocation` enables instant IP evaluation; `disabled` overrides leave legacy 1-hour blind spots):

```text
DisplayName                          State   CaeMode
-----------                          -----   -------
Global-ZeroTrust-M365-Locations      enabled strictLocation
```

### Decoding `401` `WWW-Authenticate` `insufficient_claims` Challenges

When testing a CAE-enabled API (`Microsoft Graph` / `Exchange Online`) after triggering a user revocation, decode the base64url `claims` parameter returned in `WWW-Authenticate: Bearer error="insufficient_claims", claims="..."` to inspect the required `nbf` watermark [735]:

```powershell
$b64 = 'eyJhY2Nlc3NfdG9rZW4iOnsibmJmIjp7ImVzc2VudGlhbCI6dHJ1ZSwgInZhbHVlIjoiMTc3NjAwNzIwMCJ9fX0'
$pad = $b64.Replace('-','+').Replace('_','/'); $pad += '=' * ((4 - $pad.Length % 4) % 4)
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($pad))
```

Expected decoded JSON demanding a token minted at or after Unix epoch `1776007200`:

```json
{"access_token":{"nbf":{"essential":true,"value":"1776007200"}}}
```

### Triggering Immediate `CAE` Revocation and Verifying Audit Propagation

During incident containment, revoke all refresh tokens and push a `CAE` critical event (`<= 15`-minute propagation across Exchange, SharePoint, Teams, and Graph), then confirm the directory audit record [155]:

```powershell
Revoke-MgUserSignInSession -UserId 'alice@contoso.com'
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'StsRefreshTokenValidFrom Timestamp' or activityDisplayName eq 'RevokeSignInSessions'" -Top 3 |
    Select-Object ActivityDateTime, ActivityDisplayName, Result
```

## Summary & Handoff

Continuous Access Evaluation resolves OAuth 2.0's 2012 scalability-versus-revocation dilemma: out-of-band push subscriptions from Entra ID (and vendor-neutral `OpenID SSF 1.0` / `CAEP 1.0` streams) populate local $O(1)$ Resource Provider caches, `HTTP 401` `insufficient_claims` challenges evict stale tokens within 15 minutes (or instantly on IP shifts), and `cp1`-capable `MSAL` clients safely carry 28-hour tokens without pounding the IdP. Yet `CAE` governs only *cooperating session endpoints* for *legitimately issued tokens*; it cannot shield a cloud VM's RAM from its hypervisor host or detect tokens forged outside the IdP's ledger.

The final two chapters examine those two ultimate cloud trust boundaries:

* **Removing the Cloud Host and Hypervisor from the Workload `TCB`:** How Azure Confidential VMs use `AMD SEV-SNP` and `Intel TDX` hardware memory encryption plus `vTPM` attestation to invert host-to-guest trust is the subject of [Confidential VMs (Chapter 19)](29-confidential-vms.md).
* **When a Stolen Cloud Signing Key Forges Tokens Outside Both Conditional Access and `CAE`:** Dissecting the July 2023 `Storm-0558` intrusion, where every local and session boundary held yet cross-realm key validation snapped, concludes the book in [When the Chain Snaps: Storm-0558 (Chapter 20)](15-storm0558.md).
