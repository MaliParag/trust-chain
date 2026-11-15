# Continuous Access Evaluation

## Overview

* **Role in the Chain:** Closes the post-issuance OAuth 2.0 bearer-token revocation window (`t > 0`) created by Zero Trust point-in-time evaluation ([Chapter 19](13-zero-trust.md)), pushing critical account, credential, and risk state changes from Microsoft Entra ID to cooperating Resource Providers (`RPs`) without reintroducing per-request IdP bottlenecks.
* **Core Security Invariant:** A CAE-enlightened Resource Provider (`Exchange Online`, `SharePoint Online`, `Microsoft Teams`, `Microsoft Graph`) validates incoming JWTs locally in $O(1)$ time against cached subject revocation watermarks and rejects stale tokens on the next HTTP request (`401 Unauthorized` + `WWW-Authenticate` `claims` challenge) within 15 minutes for critical events and instantly for enforced IP-location shifts.
* **Trusted Computing Base (TCB):** Microsoft Entra ID as event transmitter, Entra's internal pub-sub delivery bus (and OpenID `SSF 1.0` / `RFC 8417` `SET` streams in cross-vendor deployments), each CAE-participating Resource Provider's local revocation cache, and `MSAL` clients advertising `xms_cc: ["cp1"]`.
* **Primary Failure Modes:** Non-`cp1` client fallback to static 1-hour tokens, pivoting to non-CAE planes (`Azure Resource Manager`, `SAML` apps, third-party SaaS lacking `CAEP` receivers, or SharePoint's user-risk gap), automated exfiltration inside the 15-minute propagation window, pre-detection replay of unbound bearer tokens, `Pass-the-PRT` token re-minting, and offline IdP signing-key forgery (`Storm-0558`).
* **Handoff:** Governs temporal authorization freshness for legitimately issued cloud session tokens; hands cloud workload memory isolation against untrusted hypervisors to [Confidential VMs (Chapter 22)](29-confidential-vms.md), and dissects forged tokens that never trigger CAE state transitions in [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).

## Core Engineering Problem & Threat Model

When Dick Hardt and the IETF OAuth Working Group published `RFC 6749` (*The OAuth 2.0 Authorization Framework*, October 2012) [725], they deliberately inverted the 2000s Web Access Management (`WAM`) architecture. Whereas `WAM` forced every protected HTTP request through a synchronous Policy Decision Point (`PDP`) round-trip (yielding instant revocation at the cost of chatty latency and zero cross-tenant federation), OAuth 2.0 replaced per-request checks with self-contained JSON Web Tokens (`JWTs`) verified locally by Resource Servers in $O(1)$ cryptographic time.

Local verification scaled cloud APIs to billions of requests per second, yet introduced an acute temporal blind spot: an access token minted at `09:00` remained cryptographically valid until its `exp` timestamp (`10:00` or later) even if an administrator disabled the account, rotated the user's credentials, or confirmed active compromise at `09:01` [155, 725]. Over the subsequent eight years, three seemingly straightforward remedies failed under hyperscale operational constraints. Client-initiated `RFC 7009` Token Revocation (`/revoke`, August 2013 [726]) provided a polite logout hook for cooperative applications, which proved useless against hostile token thieves or terminated insiders and could not purge self-contained JWTs already accepted by independent Resource Servers. Synchronous `RFC 7662` Token Introspection (`/introspect`, October 2015 [727]) restored real-time revocation by forcing Resource Servers to poll the authorization server on every call, an acceptable trade-off for low-rate opaque tokens that becomes catastrophic at Microsoft 365 scale, where any transient IdP brownout would stall global mail, file, and collaboration traffic. Shrinking access-token lifetimes down to five minutes (`2018-2020` experiments [728, 729]) multiplied background token-refresh load across every open Outlook, Teams, and OneDrive client, broke resilience across lossy mobile networks, and still left automated scripts ample time to drain mailboxes, earning the verdict of "a blunt object" in Microsoft Identity Security Director Alex Weinert's April 2020 engineering retrospective [728].

Closing the fired-employee and active-intrusion gap without sacrificing $O(1)$ data-plane verification required a fourth design: server-initiated publish-subscribe push decoupling revocation events from token expiry. Proposed as the Continuous Access Evaluation Profile (`CAEP`) by Google's Atul Tulshibagwale in February 2019 [730, 731], shipped in production as Microsoft Entra Continuous Access Evaluation (`CAE`, public preview in 2020 and general availability in January 2022) [728, 732, 733], and finalized vendor-neutrally on September 2, 2025 in the OpenID Foundation `SSF 1.0`, `CAEP 1.0`, and `RISC 1.0` specifications [734], push-based session governance turned revocation into an asynchronous control-plane state stream.

![Figure: The thirteen-year arc from RFC 6749's static-expiry bargain (October 2012) to the OpenID Shared Signals Final Specifications (September 2025), shown as two rails: the IETF and OpenID standards track, and Zero Trust thinking alongside Microsoft Entra's CAE rollout. The oxblood bracket is the fired-employee window: for roughly a decade, 2012-2022, a revoked user's token stayed cryptographically valid until expiry, and Entra CAE's general availability is what finally closed it.](diagrams/14-cae-timeline.svg)

## Architectural Deep Dive

### Pub-Sub Subscription, `401` Claims Challenges, and `28`-Hour Lifetimes

Microsoft Entra `CAE` reconciles near-real-time revocation with zero hot-path IdP round-trips by coordinating out-of-band event push, in-band HTTP claims challenges, and client capability negotiation [155, 735].

![Figure: The end-to-end CAE claims-challenge round trip. A control-plane state change at Entra (steps 1-3) propagates by push to the resource provider, which caches the new revocation state; the next stale-token request is rejected on the data-plane hot path (steps 4-5) with a 401 claims challenge; MSAL then re-acquires and Entra refuses because the account is disabled, so the session terminates (step 6). The hot path is an O(1) signature verification plus an O(1) cached-state lookup, with no authorization-server round-trip.](diagrams/14-cae-roundtrip.svg)

On the control plane, participating Microsoft 365 Resource Providers maintain persistent subscriptions to Entra ID's critical-event feed. Event traffic therefore scales strictly with the *state-mutation rate* of directory and risk transitions (account disablements, password resets, refresh-token revocations, and risk spikes) rather than with the *HTTP request rate* of user workloads. On the data-plane hot path, each Resource Provider validates the incoming JWT's cryptographic signature in $O(1)$ time and compares the token's issuance timestamp (`iat` / `nbf`) against a local in-memory subject revocation watermark table in $O(1)$ time, adding zero network calls to normal API execution [155].

Whenever a client presents an otherwise unexpired JWT whose `nbf` predates the cached subject revocation watermark, or violates a synced Conditional Access location policy, the Resource Provider refuses the request on the spot with `HTTP/1.1 401 Unauthorized` and an `RFC 6750`-extended `WWW-Authenticate` header carrying `Bearer authorization_uri="https://login.windows.net/common/oauth2/authorize", error="insufficient_claims", claims="<base64url JSON>"` [735]. Base64url-decoded, that `claims` payload typically specifies `"nbf": {"essential": true, "value": "<unix_epoch>"}`, instructing the caller's Microsoft Authentication Library (`MSAL`) to bypass its cached access token and return to Entra ID for a fresh assertion, where Conditional Access immediately enforces the updated block, step-up MFA, or risk policy [155, 735].

Because older OAuth clients treat a `401` on an unexpired token as a fatal error or enter tight retry loops, `CAE` relies on explicit capability negotiation. Enlightened clients advertise support for `insufficient_claims` challenges by including `xms_cc: ["cp1"]` in their token requests, configured via `WithClientCapabilities(new[] {"cp1"})` in `MSAL.NET` or `clientCapabilities: ["CP1"]` in `MSAL.js` [735, 736, 737]. Once Entra confirms that both client (`cp1`) and target Resource Provider enforce `CAE`, static expiration no longer carries the primary revocation burden: Entra issues CAE-capable access tokens with lifetimes up to `28` hours (proactively refreshed by `MSAL` in the background), dramatically cutting token-endpoint load and insulating active work sessions from transient IdP outages, whereas non-`cp1` clients remain restricted to traditional one-hour lifetimes [155, 735].

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

Two architectural boundaries in this table are frequently conflated in operational runbooks. First, upstream signal producers are not `CAE` Resource Providers: *Microsoft Defender for Endpoint* and *Microsoft Intune* stream endpoint risk and compliance state *into* Entra ID and Conditional Access ([Chapter 19](13-zero-trust.md)), which can elevate user risk and indirectly trigger a `CAE` push, yet neither acts as an OAuth Resource Provider issuing `401` `insufficient_claims` challenges to productivity clients [155]. Second, major cloud control planes remain outside first-party `CAE` coverage: Azure management APIs (including Azure Resource Manager `ARM`, the Azure Portal, and Azure CLI), SAML 2.0 federated web sessions, and specific browser or single-page-app flows documented in Microsoft's client matrix still rely on traditional static token expiry [155].

### Vendor-Neutral Shared Signals (`RFC 8417`, `SSF 1.0`, `CAEP 1.0`, `RISC 1.0`) and `PoP` Composition

Because Microsoft's internal Entra-to-M365 pub-sub wire bus is proprietary, propagating mid-session revocations across heterogeneous enterprise SaaS estates (`ServiceNow`, `Workday`, `Salesforce`, `Google Workspace`, and `Okta`) depends on the four-layer OpenID Shared Signals stack finalized in September 2025 [734, 739, 740, 741, 742, 743]. At the bottom layer, `IETF RFC 8417` (2018) defines the Security Event Token (`SET`), a signed JWT envelope carrying structured `events` metadata syntactically prevented from being replayed as an OAuth access assertion [744]. Above the envelope, `RFC 8935` Push and `RFC 8936` Poll (2020) specify authenticated HTTPS `POST` delivery and long-poll retrieval between Event Transmitters and Event Receivers [745], while `OpenID SSF 1.0` governs stream configuration, dynamic subject registration, and health-verification heartbeats [734, 746]. At the top semantic layer, `CAEP 1.0` standardizes continuous-session event schemas (`session-revoked`, `token-claims-change`, `credential-change`, `assurance-level-change`, and `device-compliance-change`), complemented by `RISC 1.0` for cross-provider account-compromise signaling [734, 747, 748].

Even with universal `CAE` or `CAEP` coverage, event-driven revocation and sender-constrained tokens address orthogonal failure modes across the session-security design space [535, 556, 749]. `CAE` and `CAEP` solve *stale authorization*, invalidating tokens after the directory or risk engine learns that user or policy state has changed. Sender-constrained Proof-of-Possession mechanisms, including Entra `Token Protection` ([Chapter 16](11-pth-prt.md) [535]), `OAuth DPoP` (`RFC 9449` [556]), and `mTLS` Certificate-Bound Access Tokens (`RFC 8705` [749]), solve *stolen bearer possession*, stopping an adversary on another host from replaying an unrevoked token prior to detection. Defensible cloud session architecture requires composing both axes rather than treating one as a substitute for the other.

![Figure: The CAE design space on two axes: what a mechanism solves (stale authorization versus token possession) and how it learns of change (per-request poll versus push and cached state). CAE and OpenID SSF/CAEP cluster as push-based, stale-authorization controls; DPoP and mTLS-bound tokens sit on the possession axis and compose with CAE; RFC 7662 introspection is the per-request-poll alternative; short access-token lifetime is the degenerate fallback; and an identity-aware proxy enforces at a different architectural layer.](diagrams/14-cae-design-space.svg)

## Attack Catalog & Gap Analysis

Adversaries operating against `CAE`-enabled tenants exploit capability downgrade paths, non-participating API planes, propagation race windows, and stolen primary refresh credentials below the access-token layer.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Non-`CP1` Client Capability Omission (`curl`, custom OAuth scripts) | 2022-present | Extended-token CAE contract | Stolen refresh token or phished auth code redeemed without `xms_cc: ["cp1"]` | Requests standard 1-hour non-CAE access token so non-strict endpoints fall back to static 60-minute expiry | Pair `CAE` with Strict Location Enforcement, `Token Protection`, and refresh-token revocation [155, 535, 735, 738] |
| Non-CAE Plane Pivot (`ARM`, `SAML` SaaS, SharePoint Risk Gap) | 2022-present | Tenant-wide uniform revocation assumption | Stolen session/tokens for Azure `ARM`, `SAML` SaaS, or SharePoint under High User Risk | Operates against `management.azure.com` (`ARM`), SAML web apps, or SharePoint (ignoring user-risk events) until natural expiry | Shorten `Sign-in Frequency` for `ARM`/admin portals; onboard SaaS to `OpenID SSF`/`CAEP`; explicitly disable compromised accounts [155, 734] |
| 15-Minute Fan-Out Race & In-Flight Stream Egress | Architectural | Immediate post-detection containment | Automated `Graph` / `EWS` / `SharePoint` exfiltration script | Drains thousands of emails/files inside the `<= 15`-minute critical-event propagation budget or single open HTTP stream | Enforce `Defender for Cloud Apps` rate/session controls and `Strict Location` instant IP checks [155, 687, 738] |
| Unbound Bearer Token Replay Prior to Detection | Persistent | Bearer token confidentiality (`RFC 6749`) | `ESTSAUTH` / access token stolen via `AitM` or infostealer before alert fires | Replays valid `28`-hour CAE token from allowed IP geography; `CAE` stays silent because no critical event fired | Enforce Conditional Access Token Protection (`WAM` PoP) and `Phishing-Resistant MFA` (`Chapters 16, 17`) [535, 559] |
| `Pass-the-PRT` Fresh CAE Token Minting (`roadtx`) | 2020-present | Downstream access-token invalidation | Compromised `PRT` + derived `CloudAP` context key ([Chapter 16](11-pth-prt.md)) | Responds to `401` `nbf` claims challenges by minting brand-new CAE tokens from the stolen `PRT` unless refresh tokens are revoked | Execute `Revoke-MgUserSignInSession` + device disablement in Entra ID alongside password reset [155, 536, 551] |
| Forged IdP Signing Key (`Storm-0558`) | 2023 | Issuance-ledger assumption of `CAE` | Stolen Microsoft/IdP signing key ([Chapter 23](15-storm0558.md)) | Mints valid access tokens offline; Entra never issued the session and pushes zero `CAE` revocation events | Hardware-isolated per-tenant/realm signing keys and strict `kid` validation ([Chapter 23](15-storm0558.md)) [714] |

### Why `Pass-the-PRT` Survives Password Reset Without Session/Device Remediation

When an incident responder resets a user's Active Directory password or triggers a soft policy change without invalidating underlying device/session roots, a `CAE` claims challenge simply asks `MSAL` (or an attacker's `roadtx` client holding stolen `PRT` material from [Chapter 16](11-pth-prt.md)) for a token with a newer `nbf` timestamp [536, 551, 735]. Only when the responder executes explicit refresh-token revocation (`Revoke-MgUserSignInSession`), disables the user/device object, or enforces `Phishing-Resistant MFA` / `Token Protection` that the attacker cannot satisfy does Entra refuse the re-acquisition request [155, 535].

### Emerging Frontier: Non-Human Workload and AI-Agent Identities

Both Microsoft `CAE` and `OpenID CAEP 1.0` model human or managed-device subjects [155, 747]. OAuth `client_credentials` service principals, managed identities, and autonomous AI agent identities (*Conditional Access for Agent Identities*, 2026 [750]) increasingly hold high-privilege Microsoft Graph scopes yet sit largely outside `CAEP` user-session revocation profiles, making short-lived workload identity federation (`OIDC` + `CAE`-enabled workload policies) a primary 2026 engineering frontier [747, 750].

## Theoretical Limits & Structural Invariants

### Distributed Fan-Out Latency ($L_{\text{net}} + L_{\text{queue}}$) and Cooperative RP Integrity

No distributed pub-sub revocation protocol can achieve zero-millisecond global preemption. Even in small, tuned `SSF`/`CAEP` deployments achieving sub-second delivery [751], revocation latency is bounded below by speed-of-light WAN transit ($L_{\text{net}} \approx 70\text{ ms}$ transcontinental) plus global multi-region cache replication ($L_{\text{queue}} \le 15\text{ min}$ SLO across Microsoft 365 [155]). Moreover, `CAE` acts strictly at request-admission boundaries (never preempting an already-accepted HTTP stream) and assumes an honest, uncompromised Resource Provider: a compromised SaaS backend can silently drop incoming `SET` revocation events and continue serving traffic.

### Decoupling Temporal Revocation from Token Binding and Cryptographic Provenance

Consistent with Law 16, shrinking revocation latency (`CAE`) proves neither that the presenter is the legitimate client nor that the identity provider ever issued the token.

> **Key idea.**
> `CAE` answers exactly one question: *"Has the authorization state of a principal whose token Entra legitimately issued changed since `iat`?"* If an attacker steals an active bearer token and replays it *before* any detection fires, `CAE` approves every request unless sender-constrained Proof-of-Possession (`Token Protection` / `DPoP`) is enforced [535, 556]. Worse, if an attacker steals the IdP's signing key and forges tokens offline (`Storm-0558`), `CAE` has no session record to revoke unless an explicit subject-level revocation watermark is pushed ([Chapter 23](15-storm0558.md)) [714].

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

Continuous Access Evaluation resolves OAuth 2.0's decade-old scalability-versus-revocation dilemma: out-of-band push subscriptions from Entra ID (and vendor-neutral `OpenID SSF 1.0` and `CAEP 1.0` streams across third-party SaaS) populate local $O(1)$ Resource Provider revocation caches, `HTTP 401` `insufficient_claims` challenges evict stale tokens within `15` minutes or instantly upon strict IP-location shifts, and `cp1`-capable `MSAL` clients safely carry `28`-hour sessions without saturating token endpoints. Yet `CAE` governs only *cooperating session endpoints* evaluating *legitimately issued human and device tokens*; it does not bound autonomous software deputies, encrypt guest VM memory against a compromised cloud host, or detect tokens forged outside the identity provider's issuance ledger.

The concluding chapters of Part IV and the Finale close each of those remaining cloud boundaries in turn. [Workload and AI Agent Security (Chapter 21)](32-agent-security.md) extends least-privilege containment to non-human service workloads and nondeterministic AI agents through Windows 11 `Agent Workspace` sandboxes, signed `MCP` brokers, and `Microsoft Entra Agent ID` On-Behalf-Of scope intersections. [Confidential VMs (Chapter 22)](29-confidential-vms.md) then removes the cloud host hypervisor from the workload trusted computing base using `AMD SEV-SNP` and `Intel TDX` hardware memory encryption paired with `vTPM` remote attestation, before [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md) dissects the July 2023 intrusion in which every endpoint and session control held intact while a stolen signing key and an omitted cross-tier issuer check bypassed both Conditional Access and `CAE` altogether.
