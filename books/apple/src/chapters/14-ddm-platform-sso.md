# Automated Enrollment, Declarative Device Management, and Platform SSO

## Overview

* **Link in the Chain:** Organizational governance and enterprise identity-binding capstone of Part III; couples hardware activation ([Chapter 11](11-keychain-stolen-device.md)) and `SEP` attestation ([Chapter 12](12-sep-app-device-attestation.md)) to non-removable fleet supervision (`ADE`), autonomous client policy (`DDM`), and hardware-bound corporate single sign-on (`Platform SSO`).
* **Core Security Invariant:** Devices registered in `Apple Business Manager` (`ABM`) cannot complete post-wipe activation without enrolling into their assigned `MDM`/`DDM` server (`is_supervised = true`), evaluate `Declarative Device Management` state predicates locally without waiting for server polling loops, and bind enterprise IdP session tokens (`PRT` / OIDC / Kerberos) to non-exportable `SEP` keys.
* **Platform Matrix:** `ABM`, `Automated Device Enrollment` (`ADE`), supervision, and `DDM` span `iOS`, `iPadOS`, `macOS`, `visionOS`, and `tvOS` (`watchOS` supervises via paired `iPhone`), while `Bootstrap Token` (`FileVault` / `1TR` escrow) and full `LoginWindow` `Platform SSO` target `macOS` (with `Extensible Enterprise SSO` shared on `iOS`/`iPadOS`).
* **Trusted Computing Base (TCB):** Apple's `ABM` and device activation servers (`albert.apple.com`), `Setup Assistant` (`mbsetupagent`), `mdmclient` / `remotemanagementd` (`DDM` engine), `SEP` `Bootstrap Token` / `Recovery Lock` slots, and the `Platform SSO` extension + `SEP` `SecureEnclaveKey` signing boundary.
* **Failure Horizon & Handoff:** Compromising the enterprise `MDM` server or `ABM` administrator tenant grants fleet-wide `EraseDevice`, `PPPC` `TCC` consent (`Full Disk Access`), and root package installation on supervised Macs, while pre-activation network blockages historically tested `Setup Assistant` edge cases; hands off zero-knowledge cloud storage, post-quantum messaging, and AI enclaves to Part IV ([Chapter 15](15-icloud-hsm-adp.md) through [Chapter 19](19-private-cloud-compute.md)).

## Threat Model & Design Tension

Without a hardware-anchored enterprise ownership model, managing Apple devices in a corporate fleet suffers two fatal weaknesses [119, 122]. First, if an employee or laptop thief places an un-supervised MacBook or iPhone into `DFU` mode ([Chapter 1](01-secure-boot.md)) and restores a clean `Image4`-signed OS from Apple's CDN, any locally installed management agent vanishes completely, letting the user set up a fresh local `admin` account free of EDR sensors, `TCC` restrictions, or disk encryption! Second, on workstations joined to cloud identity providers (`Microsoft Entra ID`, `Okta`, `Ping`), storing OAuth refresh tokens or Primary Refresh Tokens (`PRT`s) inside ordinary user-space files (`~/Library/`) allows commodity infostealers or post-exploitation scripts to copy those bearer tokens off the Mac and replay them from an attacker's machine (*Pass-the-PRT*) without ever touching the Mac again [122, 123].

Conversely, employees enrolling personal Bring-Your-Own-Device (`BYOD`) iPhones to check corporate Slack and Mail rightfully refuse to grant their employer's IT department the technical ability to read personal `Photos`, inspect personal browser history, or factory-wipe their family videos [119]! Furthermore, as enterprise Apple fleets scaled past 100,000+ endpoints, legacy `Mobile Device Management` (`MDM`) (an imperative protocol from 2010 where the server pushes an empty `APNs` poke, waits for every device to wake up, polls `DeviceInformation`, computes diffs on the server, and sends `InstallProfile` commands one by one) suffered massive thundering-herd latency and compliance drift whenever a critical zero-day OS update (`iOS 26.3` for `CVE-2026-20700`) needed immediate enforcement [120].

Apple's modern fleet architecture resolves all three tensions cleanly: *Automated Device Enrollment (`ADE`)* vs. cryptographic *Account-Driven User Enrollment* separates corporate-owned supervision from BYOD privacy at the `APFS` volume boundary [119]; *Declarative Device Management (`DDM`)* turns the endpoint itself into an autonomous state-reconciliation engine [120]; and *Platform Single Sign-On (`Platform SSO`)* binds corporate IdP tokens into non-exportable `SEP` silicon [122, 123].

## Silicon & System Mechanics

### Apple Business Manager, ADE Supervision, and Bootstrap Tokens

Corporate ownership begins in the supply chain before the shrink-wrap opens [119]. When an enterprise purchases Macs, iPhones, iPads, or Vision Pros through authorized channels (or adds devices physically via Apple Configurator subject to a 30-day provisional user-leave grace period), the device's hardware serial number is bound cryptographically to the organization's *Apple Business Manager (`ABM`)* tenant and assigned to an enterprise `MDM` server public key.

During initial boot (and after *every* subsequent `DFU` restore or `Erase All Content and Settings`) `Setup Assistant` must contact Apple's activation servers (`albert.apple.com`) over TLS (or wired Ethernet/tethered host) to obtain an activation record signed by Apple's Activation CA [104, 119]. When the serial number belongs to an `ABM` `ADE` assignment, the signed activation record sets two immutable kernel/configuration flags: `IsSupervised = true` and `IsMDMUnremovable = true`, forcing `Setup Assistant` to complete `ACME` `Managed Device Attestation` ([Chapter 12](12-sep-app-device-attestation.md)) and enroll into the assigned `MDM` server *before* creating a local user desktop [111, 119]!

On supervised Apple Silicon Macs, `ADE` pairs with two critical `SEP` escrow primitives [29, 121]: `SetRecoveryLock` (setting an enterprise-escrowed password inside `SEP` required to enter `1TR` Startup Security Utility, preventing even local administrators from downgrading `Full Security` or disabling `SIP`, [Chapter 2](02-mac-localpolicy.md)) and the *Bootstrap Token* (`SEP`-generated secret automatically escrowed to the `MDM` server during setup that authorizes `mdmclient` to grant `SecureToken` to new mobile/Platform-SSO accounts and silently authorize `SSV`/`Cryptex` OS updates without prompting for a local admin password) [121].

By sharp contrast, when a user enrolls a personal `BYOD` iPhone, iPad, or Mac via *Account-Driven User Enrollment* (*Settings $\to$ VPN & Device Management $\to$ Sign in with Managed Apple Account*), the OS mounts a *completely separate, cryptographically isolated `APFS` Enterprise Data volume* and separate `SEP` Keychain scope [119]! Under `User Enrollment`, the `MDM` server *cannot* wipe the entire device (issuing `Unenroll` merely crypto-shreds the enterprise `APFS` volume key!), *cannot* read personal app lists or serial numbers, and *cannot* force full-tunnel device-wide VPNs inspecting personal apps, preserving personal sovereignty mathematically.

### Declarative Device Management (DDM): Autonomous State Reconciliation

Published openly by Apple in `github.com/apple/device-management`, *Declarative Device Management (`DDM`, `remotemanagementd`)* replaces imperative server-polled `MDM` commands with a reactive desired-state data model inspired by modern declarative infrastructure controllers [120].

![Figure: Enterprise fleet management contrasting legacy server-polled imperative MDM commands against ADE-supervised Declarative Device Management (DDM) autonomous local predicate evaluation and proactive StatusChannel streaming.](diagrams/14-ade-ddm-autonomous-loop.svg)

A `DDM` server delivers four JSON declaration primitives verified via sync tokens (`DeclarationsToken`) [120]: *Configurations* (atomic payloads such as `com.apple.configuration.softwareupdate.enforcement.specific` mandating `iOS 26.3` by `2026-03-01T18:00:00Z`, `ACME` certificates, or passcode rules), *Assets* (reusable credentials/identities referenced by configurations), *Activations* (attaching sets of Configurations conditional on boolean *Predicate* expressions such as `@status(device.operating-system.family) == 'macOS'`), and *Management* properties.

Instead of waiting for the server to poll inventory and push conditional changes, `remotemanagementd` evaluates `Activation` predicates *autonomously on the device in real time* (applying software-update countdown notifications, escalating `LaunchDaemon` service configs, or rotating `ACME` certificates even while offline) and streams compact asynchronous JSON diffs back over the *StatusChannel* (`status.softwareupdate.install-state`, `status.device.operating-system.build-version`, `status.security.certificate.list`) the instant local state changes [120]!

### Platform Single Sign-On (Platform SSO) on macOS

Introduced in `macOS Ventura` (`1.0`) and expanded in `macOS Sonoma`/`Sequoia`/`Tahoe` (`2.0` provisioning local accounts on demand directly at the FileVault/LoginWindow screen), *Platform Single Sign-On (`Platform SSO`, `AuthenticationServices` `ASAuthorizationProviderExtensionAuthorizationRequest`)* eliminates AD domain-bind fragility while bringing hardware-bound Windows-Hello-class Primary Refresh Token (`PRT`) security to `macOS` [122, 123].

![Figure: macOS Platform SSO registration and login sequence binding SEP non-exportable Device Signing and Encryption keys to Enterprise IdP PRT/OIDC assertions and Kerberos TGT mapping.](diagrams/14-platform-sso-sep-binding.svg)

During `DDM`/`MDM` enrollment of the vendor's SSO System/App Extension (such as Microsoft Company Portal's Entra ID Enterprise SSO plug-in or Okta Verify), `Platform SSO` asks `SEP` to generate non-exportable `P-256` *Device Signing* and *Device Encryption* (`ECDH`) keys inside `SKS` (`SecureEnclaveKey` storage) and registers their public keys (certified by an `ACME` `Managed Device Attestation` leaf certificate ([Chapter 12](12-sep-app-device-attestation.md))) with the enterprise Identity Provider (`IdP`) [111, 122, 123].

When the user authenticates at `LoginWindow` (via IdP password, smart card, or `SEP`-bound synced/enterprise Passkey / `Touch ID` fast-unlock), `Platform SSO` constructs a signed JWT assertion (`grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer`) signed directly inside `SEP`:

$$\text{Assertion}_{\text{PSSO}} = \text{Sign}_{\text{SK}_{\text{SEP-Device}}}\bigl(\text{Header} \;\|\; \{\text{iss}, \text{aud}, \text{nonce}_{\text{IdP}}, \text{iat}, \text{user\_cred}\}\bigr)$$

The IdP (`Entra ID` or `Okta`) verifies the `SEP` signature against the registered corporate device public key and returns a Primary Refresh Token (`PRT`) whose symmetric session key ($K_{\text{session}}$) is encrypted (`ECIES` / `JWE`) directly to `SEP`'s non-exportable *Device Encryption Key* [122, 123]. Whenever Safari, `Chrome` (via broker integration), native Office or Slack apps, or background CLI tools subsequently request an OAuth access token (or an on-premises Active Directory *Kerberos TGT* mapped automatically via `Platform SSO`'s Kerberos ticket-mapping profile), the SSO extension asks `SEP` to compute proof-of-possession (`PoP`) signatures over the IdP's fresh nonce without $K_{\text{session}}$ or $SK_{\text{SEP-Device}}$ ever becoming exportable to user-space disk thieves [122, 123].

Under `Platform SSO 2.0` (`macOS Sonoma` through `Tahoe`), enterprise deployments can further enable *Just-In-Time (`JIT`) local account creation at the LoginWindow* alongside `AuthenticationMethod = Password` or `SmartCard` / `UserSecureEnclaveKey` (passwordless `SEP`-bound phish-resistant login) [122]. When a new employee unpacks a factory-sealed Mac shipped directly from a warehouse, `ADE` enrolls the machine into `DDM`, deploys the IdP's `Platform SSO` System Extension, and presents an organizational cloud login prompt right at the macOS login screen: authenticating against Entra ID or Okta automatically provisions the local `OpenDirectory` user record, synchronizes or escrows `FileVault` `SecureToken` custody via the `Bootstrap Token`, and establishes a `SEP`-bound `PRT` in a single atomic ceremony without ever creating a shared IT staging password [121, 122, 123].

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, and `visionOS` (single-user session devices without a multi-user `LoginWindow`), enterprise identity uses the companion *Extensible Enterprise SSO (`ESSO`)* framework (`AppSSO.framework`), sharing the exact same `SEP` `SecureEnclaveKey` `PRT` broker mechanics (for example, Microsoft Authenticator acting as the Entra ID `PRT` broker across all managed apps on an `iPhone` and triggering `Conditional Access` device-compliance gates) while omitting multi-user `OpenDirectory` account creation and `FileVault` `SecureToken` password synchronization [122, 123]. `Shared iPad` for Business/Education bridges both models on `iPadOS` by partitioning per-user `APFS` containers dynamically authenticated via Managed Apple Accounts and `DDM`.

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| Offline `/etc/hosts` `ADE` Setup Bypass (Pre-`1TR`/Tethered Fix) | 2018-2021 | `macOS` (legacy) | `ADE` enrollment mandatory gate | Skipping network during initial Setup Assistant created an unmanaged local admin who blocked `iprofiles.apple.com` in `/etc/hosts` | Supervision can require mandatory internet connection inside Setup Assistant before local account creation (`AwaitDeviceConfigured`) [119] |
| Compromised Enterprise `MDM` Server Blast Radius | Architectural | Supervised `macOS` / `iOS` | `MDM` server in enterprise TCB | A supervised `macOS` `MDM` server can run `InstallEnterpriseApplication` (`root` pkg scripts), push `PPPC` Full Disk Access, and wipe devices fleet-wide | Harden `MDM`/`ABM` admin accounts with phishing-resistant Passkeys, `ACME` `MDA`, and dual-control change approvals [119, 120] |
| Unbound Browser Session Cookies Post-`PSSO` | 2023-2026 | `macOS` | Web session cookie exfiltration | Even when `Platform SSO` locks the root `PRT` inside `SEP`, downstream web apps setting long-lived plaintext HTTP session cookies inside third-party browser SQLite DBs remain stealable by `UID 501` malware | Deploy Device-Bound Session Credentials (`DBSC`), short-lived `CAE` tokens, and `EndpointSecurity` cookie-access rules (`Bastion`, [Chapter 9](09-esf-xprotect-forensics.md)) [89, 123] |

> **Warning.**
> On a corporate-supervised `macOS` workstation, your `MDM`/`DDM` server is effectively *Ring 0 across your entire fleet* [119]: it holds `Bootstrap Token` authority, `Recovery Lock` secrets, `PPPC` `TCC` override privileges, and arbitrary root `pkg` deployment power. Securing `ABM` federation and the `MDM` control plane itself is every bit as critical as securing an Active Directory Domain Controller.

## Verification & Forensic Artifacts

On `macOS`, verify `Apple Business Manager` `ADE` enrollment and supervision status (`Enrolled via DEP: Yes`, `MDM enrollment: Yes (User Approved)`), plus `Bootstrap Token` server escrow status, using `profiles` [119, 121]:

```bash
profiles status -type enrollment
profiles show -type bootstraptoken 2>/dev/null || true
```

Expected read-only output on a supervised corporate Mac:

```text
Enrolled via DEP: Yes
MDM enrollment: Yes (User Approved)
MDM server: https://mdm.corp.example.com/mdm
```

Inspect active *Platform Single Sign-On (`Platform SSO`)* registration state, IdP extension bundle ID, and `SEP` `SecureEnclaveKey` binding on `macOS` via `app-sso` [122]:

```bash
app-sso platform -s 2>/dev/null || true
```

Observe `Declarative Device Management` (`remotemanagementd`) autonomous activation, predicate evaluation, and `StatusChannel` updates in Unified Logging [90, 120]:

```bash
log show --last 1h --predicate 'subsystem == "com.apple.remotemanagementd"' --style compact | tail -n 5
```

Parts I through III have established the complete on-device and enterprise trust chain from `Boot ROM` and `SEP` up to `Platform SSO`. Part IV ([Chapter 15](15-icloud-hsm-adp.md) through [Chapter 19](19-private-cloud-compute.md)) crosses the network horizon to ask Apple's hardest architectural question: how can backups, photos, messages, lost-device location beacons, agentic AI workflows, and cloud LLM inference operate at global scale while *mathematically excluding Apple's own servers* from the Trusted Computing Base?
