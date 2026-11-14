# Windows Hello and Passkeys

## Overview

* **Role in the Chain:** Eliminates shared passwords and password-equivalent server verifiers at interactive and web sign-in by pairing local user verification (`PIN`, near-infrared face, or fingerprint) with hardware-bound (`TPM 2.0` / FIDO2) or end-to-end synced asymmetric key pairs across **Windows Hello (`NGC`)* and *W3C `WebAuthn` / `CTAP 2.x` passkeys**.
* **Core Security Invariant:** Neither biometric templates, `PINs`, nor private keys cross the network; relying parties store only public keys and verify fresh challenge signatures cryptographically bound (`WebAuthn` `clientDataJSON.origin` + `SHA256(rpId)`) to the exact origin the client connected to.
* **Trusted Computing Base (TCB):** `TPM 2.0` (`Microsoft Platform Crypto Provider`), the `NGC` container, `WBF` (`WbioSrvc`) or Enhanced Sign-in Security (`ESS`, `VTL1` `BioIso.exe` + secure sensors), `webauthn.dll`, browser origin enforcement, and, for synced or vault passkeys (`BE=1`), the cloud sync fabric or `Windows 11 24H2` `IPluginAuthenticator` COM provider plus every enabled account-recovery path.
* **Primary Failure Modes:** Peripheral sensor or `VTL0` template spoofing on non-`ESS` hardware (`CVE-2021-34466`, `Faceplant`), post-unlock bearer-token theft ([Chapter 14](11-pth-prt.md)), `AAL3`-to-`AAL2` key exportability in synced/plug-in passkeys, and account-recovery downgrade (`SMS`, email, or socially engineered helpdesk `Temporary Access Pass` flows).
* **Handoff:** Completes Part III (*Credentials & Access*) by hardening front-door authentication to `NIST AAL2/AAL3`; hands local process/provider telemetry (including `WebAuthn` plug-in registration and `LSASS` access) to [ETW: The EDR Substrate (Chapter 16)](28-etw.md), and continuous post-sign-in session governance to [Zero Trust (Chapter 17)](13-zero-trust.md) and [Continuous Access Evaluation (Chapter 18)](14-cae.md).

## Core Engineering Problem & Threat Model

For four decades, enterprise authentication categorized credentials by what the human felt they produced: *something you know, something you have, something you are* (`DOD 5200.28-STD` Orange Book, 1985; early `NIST SP 800-63`, 2004 [557, 558]). By 2024-2026, commodity Adversary-in-the-Middle (`AitM`) reverse-proxy kits (`Evilginx`, `EvilProxy`, `Tycoon 2FA`) shattered that taxonomy: a user typing a password and approving an OTP or push notification produces "two factors," yet the reverse proxy relays both across TLS to `login.microsoftonline.com` and steals the resulting session cookie in real time [559, 560]. Meanwhile, Microsoft telemetry recorded password-spray and stuffing volume surging from `115` attacks per second in 2015 to `7,000` password attacks per second by May 2025 [561, 562].

Replacing shared secrets requires scoring authenticators not by user sensation, but by five cryptographic attacker-defeat criteria synthesized from `NIST SP 800-63-4` / `SP 800-63B-4` (July 2025), FIDO certification levels, and IETF channel-binding standards (`RFC 5056`, `RFC 9266`) [563, 564, 565, 566, 567]:
1. **Verifier-Impersonation (Phishing) Resistance:** Can an `AitM` look-alike domain induce a signature accepted by the genuine Relying Party (`RP`)? [559, 568]
2. **Verifier-Compromise Resistance:** Does exfiltrating the server's credential database yield crackable or replayable secrets? [569]
3. **Replay and Relay Resistance:** Does each ceremony sign a fresh challenge bound to origin/channel state? [570, 571, 572]
4. **Step-Up User Verification (`UP` / `UV`):** Can high-risk actions force fresh local presence and biometric/PIN verification? [570]
5. **Lifecycle and Recovery Floor:** What minimum factor recreates access when the primary device is lost? [559, 564]

The threat model spans remote `AitM` operators, database-breach crackers, physical or peripheral attackers injecting frames/templates into local biometric pipelines (`CVE-2021-34466`, `Faceplant` [573, 574]), same-host malware awaiting user unlock, and social engineers targeting fallback recovery channels.

## Architectural Deep Dive

### `NGC`, the Gesture-to-Key Separation, and `WHfB` Trust Models

Windows Hello's foundational design separates local user verification from remote cryptographic authentication (`diagrams/12-hello-auth-flow.svg`) [575].

![Figure: The gesture-to-key-to-signature flow. A relying-party challenge enters the device; a local gesture (PIN, face, or fingerprint) authorizes a non-exportable TPM key that signs the challenge; the signed assertion leaves, and the server verifies it with the public key enrolled at provisioning. The biometric template, the PIN, and the private key never leave the device: the server only ever holds a public key and a signature.](diagrams/12-hello-auth-flow.svg)

During provisioning, after a bootstrap MFA ceremony, Windows creates a Next Generation Credentials (`NGC`) container (`NgcSet : YES` in `dsregcmd /status`) backed by `TPM 2.0` (`Microsoft Platform Crypto Provider`) [575]. The TPM generates an asymmetric key pair whose private half never enters normal `VTL0` memory in plaintext; only the public key is registered with Microsoft Entra ID, Active Directory, or a `WebAuthn` relying party. A Windows Hello PIN is therefore an *activation secret* bound to one physical TPM and its hardware anti-hammering lockout counter, not a roaming password: learning a user's 6-digit PIN without stealing their physical laptop buys an attacker zero remote signatures [575, 576].

In enterprise Windows Hello for Business (`WHfB`), three deployment models govern how Active Directory and Entra ID verify that public key [575, 577, 578]:
* **Cloud Kerberos Trust (GA 2022, Recommended Default):** Eliminates enterprise PKI overhead for hybrid estates. The user registers their `NGC` public key in Entra ID; Entra ID's `AzureADKerberos` virtual Read-Only Domain Controller object issues a partial `TGT` during sign-in that an on-premises writable DC exchanges for a full `TGT` ([Chapter 13](10-kerberos.md)) [577, 578, 579].
* **Key Trust:** Registers the raw public key in Active Directory (`msDS-KeyCredentialLink`) against Windows Server 2016+ `KDCs` via `PKINIT` [575, 578].
* **Certificate Trust:** Enrolls an X.509 client certificate bound to the `NGC` TPM key from `AD CS` ([Chapter 14](11-pth-prt.md)) [575].

### `WBF` vs. Enhanced Sign-in Security (`ESS`) at the Sensor Boundary

Cryptographic key isolation inside `TPM 2.0` is moot if an attacker can forge the `"match"` signal sent by the operating system's biometric stack. Beginning in Windows 7, the Windows Biometric Framework (`WBF`, `WbioSrvc`) standardized sensor, engine, and storage adapters in `VTL0` user mode [580]. While Windows Hello Face required near-infrared (`NIR`) illumination to reject 2D RGB photographs and targeted a False Acceptance Rate (`FAR`) below `0.001%` ($1$ in $100,000$, where multi-attempt cumulative risk scales as $1 - (1 - p)^n$) [581, 582], classic `WBF` left USB camera streams and on-disk biometric templates reachable by local `SYSTEM` or malicious peripherals.

Enhanced Sign-in Security (`ESS`) closes that `VTL0` sensor-and-template gap using Virtualization-Based Security ([Chapter 6](05-secure-kernel.md)) and dedicated hardware buses [185]:
* **ESS Face:** Restricts capture to physically integrated `NIR` cameras wired over secure buses (`MIPI` or IOMMU/DMA-isolated USB controllers attested via ACPI/firmware tables), routing frames into the `VTL1` `BioIso.exe` (`Secure Biometrics`) trustlet where matching runs and templates are encrypted under `VTL1`-only keys [185].
* **ESS Fingerprint:** Requires certified match-on-sensor hardware speaking Microsoft's encrypted Secure Device Connection Protocol (`SDCP`), ensuring raw fingerprint images and templates never leave the sensor microcontroller [185].

### W3C `WebAuthn`, `CTAP 2.x`, Attestation, and Hybrid Transport (`caBLE`)

Where `WHfB` replaces domain passwords, FIDO2 (the pairing of W3C `WebAuthn` `Level 1` 2019, `Level 2` 2021, and `Level 3` Candidate Recommendation January 2026 [149, 570, 583, 584] with FIDO `CTAP 2.x` `2.0` 2019, `2.1` 2021, `2.2` July 2025, and `2.3` February 2026 [585, 586, 587, 588]) generalizes origin-bound public-key authentication to every web application, descending directly from FIDO `U2F` (`AppID` binding, 2014 [589, 590]).

When a site calls `navigator.credentials.create()` or `get()`, the browser (not page JavaScript) writes the actual HTTPS origin into `clientDataJSON.origin`. The authenticator computes `authenticatorData` (comprising `rpIdHash` as `SHA256(rpId)` where `rpId` must be a registrable suffix of `origin`, a 1-byte `flags` bitmap with `UP` user present, `UV` user verified, `BE` backup eligible, `BS` backup state, `AT` attested data, and `ED` extensions, a 32-bit signature counter, and on registration `AAGUID`, `credentialId`, and `COSE_Key` using `ES256` ECDSA P-256 or `EdDSA` [591]) and signs `authenticatorData || SHA256(clientDataJSON)` [570, 592]. An `AitM` proxy on `login-microsoft0nline.example` cannot forge `origin` or obtain a signature over `SHA256("microsoft.com")`: phishing fails mathematically at step one [559, 568].

`CTAP 2.1+` hardened roaming USB/NFC/BLE keys with `rpId`-scoped `pinUvAuthToken` permissions, `credProtect` (`0x03` requiring `UV=1` before enumerating resident credentials), and enterprise attestation [586], while IANA defines seven registration attestation formats (`packed`, `tpm` using `TPM2_Certify` + `AIK`/`EK` from [Chapter 2](01-tpm.md), `apple`, `android-key`, legacy `fido-u2f`, retired `android-safetynet`, and privacy-preserving `none` [149, 593, 594, 595]). When signing in on a borrowed Windows PC lacking local keys, Hybrid Transport (`caBLE`) (`diagrams/24-webauthn-hybrid-transport.svg`) pairs a mobile phone authenticator via a QR-code-seeded ephemeral `ECDH` handshake, `BLE` physical proximity routing, and an end-to-end encrypted `CTAP2` cloud tunnel relay without stranding credentials on the PC [570, 584].

![Figure: Hybrid transport (caBLE). A phone authenticates a sign-in on a laptop that holds no credential. Three channels do three jobs: the QR code is the cryptographic binding (ephemeral ECDH), BLE supplies a physical-proximity signal (not identity), and the cloud Tunnel Service is an encrypted CTAP2 relay, not a trust anchor. The phone performs local user verification and signs over the laptop's clientDataJSON.origin and rpIdHash, so origin binding (and phishing resistance) holds end to end.](diagrams/24-webauthn-hybrid-transport.svg)

### `webauthn.dll`, Synced Passkeys (`BE`/`BS`), and `Windows 11 24H2` Plug-In Providers

Since Windows 10 `1903`, browsers and native apps on Windows do not speak raw `CTAP2` over USB/BLE; they call the OS dispatcher `webauthn.dll` (`WebAuthNAuthenticatorMakeCredential`, `WebAuthNAuthenticatorGetAssertion`, and `Conditional UI` autofill mediation [596, 597, 598, 599]) (`diagrams/24-webauthn-windows-registration.svg`).

![Figure: A platform-bound WebAuthn registration on Windows. The browser calls MakeCredential() across the OS dispatch boundary into webauthn.dll; Windows Hello collects the user-verification gesture, CNG/NCrypt provisions the key, and the TPM 2.0 generates a non-exportable keypair and certifies the attestation. The caller hands off a request and receives only bytes (clientDataJSON, authenticatorData, attestationObject) and never holds the TPM private key or speaks raw CTAP transport.](diagrams/24-webauthn-windows-registration.svg)

Following the May 2022 Apple/Google/Microsoft joint commitment rebranding discoverable `WebAuthn` resident keys as passkeys [600, 601], Windows 11 24H2 introduced a native Microsoft Account synced passkey provider alongside a third-party `IPluginAuthenticator` COM plug-in architecture (`WebAuthNPluginAddAuthenticator`, `1Password`, `Bitwarden`, `Dashlane`) in which third-party vaults store passkeys while delegating user verification back to Windows Hello via `WebAuthNPluginPerformUserVerification` [596, 597, 602, 603, 604]. That creates three distinct assurance tiers behind the same Windows UI picker [564, 568, 605]:

| Credential Class | Private Key Residency | `BE` / `BS` Flags | `NIST SP 800-63B-4` Ceiling |
|---|---|---|---|
| Device-Bound (`WHfB` / TPM Passkey / Hardware FIDO2 Key) | Non-exportable inside single `TPM 2.0` or FIDO L3 Secure Element | `BE=0, BS=0` | `AAL3` (when paired with `AAL3` recovery) [564, 565, 568] |
| Platform-Synced Passkey (`MSA`, `iCloud Keychain`, `Google PM`) | E2EE cloud sync fabric unlocked by recovery key / device passcode | `BE=1, BS=1` | `AAL2` (recoverable outside original hardware) [564, 605, 606] |
| Vault Plug-In Passkey (`24H2` `IPluginAuthenticator`) | Third-party vault storage, sync, and export policy | Provider-defined (`BE=1` typical) | `AAL2` or lower (governed by vault master secret) [602, 605] |

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `AitM` Reverse-Proxy Phishing (`Evilginx`, `Tycoon 2FA`) | 2018-present | Password + OTP / Push MFA (`AAL1`/`AAL2`) | Victim clicks phishing link; `RP` still permits non-FIDO fallback | Proxies TLS login + MFA challenge live and captures session cookie; blocked by `WebAuthn` `rpIdHash` unless user downgrades | Enforce Conditional Access Phishing-Resistant MFA strength and disable OTP/push fallbacks [559, 560, 564] |
| USB IR Camera Spoofing (`CVE-2021-34466`) | 2021 | Non-`ESS` Windows Hello Face `VTL0` capture | Physical USB access on non-`ESS` host with Hello Face enabled | Emulates USB UVC infrared camera injecting pre-recorded target IR + RGB frames into `WBF` | Patch `CVE-2021-34466` and require `ESS` (`BioIso.exe` rejecting external USB cameras) [185, 573] |
| `WBF` Template Injection (`Faceplant`) & `NIR` Presentation | 2021-2023 | Non-`ESS` biometric database or physical sensor liveness | Local `SYSTEM` on non-`ESS` PC (`Faceplant`) or custom RGB-to-NIR rig | Overwrites `VTL0` `WinBio` template on disk with attacker face (`ERNW`) or projects translated `NIR` imagery | Require `ESS` (`VTL1`-encrypted templates + `SDCP` fingerprint sensors) and updated liveness models [185, 574, 607, 608] |
| Same-Host `UV` Prompt Racing & Rogue `24H2` Plug-Ins | 2024-present | Local user-session / `webauthn.dll` mediation | Malware running on unlocked endpoint | Triggers concurrent `WebAuthn` prompt during user gesture, steals post-auth cookies, or registers rogue `IPluginAuthenticator` | Enforce `WDAC`/`App Control` ([Chapter 7](06-code-integrity.md)), monitor `WebAuthn` ETW plug-in events ([Chapter 16](28-etw.md)), bind sessions (`CAE`) [570, 597, 602] |
| Sync-Fabric Compromise & Counter False Positives | 2022-present | Multi-device synced passkey confidentiality (`BE=1`) | Stolen cloud recovery key / vault master password | Restores E2EE passkey vault onto attacker device; separately, naive RPs block valid `BS=1` users on `0`/non-monotonic counters | Restrict Tier-0 admins to `BE=0` device-bound keys; enforce counter checks only when `BS=0` [568, 570, 605] |
| Account-Recovery Downgrade (`SMS` / Email / Helpdesk `TAP`) | Persistent | Whole-account authentication assurance (`System AAL`) | Lost-device claim or SIM-swap / helpdesk social engineering | Bypasses `AAL3` passkey completely by resetting account via `SMS-OTP`, alternate email, or unverified helpdesk `TAP` | Eliminate `SMS`/password recovery; enforce dual `BE=0` hardware keys + identity-proofed `TAP` issuance [559, 564, 609] |

### Sensor and Template Attacks: Why Non-`ESS` Biometrics Are Convenience, Not `AAL3`

Omer Tsarfati's `CVE-2021-34466` (CyberArk, 2021) [573] and ERNW's `Faceplant` research (2023) [574, 608] illustrate why `TPM` key non-exportability alone cannot secure biometric sign-in. On a laptop without `ESS`, `WbioSrvc` runs in `VTL0` and trusts standard USB Video Class (`UVC`) descriptors or local `SYSTEM`-accessible template stores: plugging in a microcontroller replaying `NIR` frames or overwriting the stored `WBF` template tricks Windows into commanding the `TPM` to sign legitimately. `ESS` severs both vectors by rejecting external USB biometric peripherals for sign-in, encrypting templates inside `VTL1` `BioIso.exe`, and binding match-on-sensor fingerprint readers via cryptographic `SDCP` channels [185].

### The Recovery Floor Theorem: `System AAL = min(Ceremony, Recovery)`

Across every consumer and enterprise platform surveyed, account recovery is where phishing-resistant cryptography collapses back into shared secrets (`diagrams/24-webauthn-recovery-floor.svg`) [559, 564, 602, 609, 610]:

![Figure: The surveyed passkey platforms start from the same origin-bound ceremony, but expose different ladders of account-recovery primitives, and the common weak floors are out-of-band recovery primitives such as SMS-OTP, email, a retained secret, or an admin Temporary Access Pass. Per-leaf AAL tags show the drop; the system's assurance is the minimum: System AAL = min(ceremony, recovery).](diagrams/24-webauthn-recovery-floor.svg)

Whether an account uses Apple `iCloud Keychain` (28-character Recovery Key / trusted device [606, 610]), Google Password Manager or Microsoft Account synced passkeys (recovery key or fallback `SMS`/email [602]), a `24H2` vault plug-in (master password + Secret Key), or Microsoft Entra ID's Temporary Access Pass (`TAP`) [609], an attacker never needs to break `ECDSA P-256` or `TPM 2.0` if calling the helpdesk yields a single-string `TAP` over the phone. True `AAL3` operations require enrolling two physically separate `BE=0` authenticators (e.g., `WHfB` TPM key + backup FIDO2 security key stored offline) and gating administrative `TAP` issuance behind verified multi-party or live video/in-person proofing [564, 568, 609].

## Theoretical Limits & Structural Invariants

### Biometrics Are Noisy Physical Signals, Not Revocable Secrets

Unlike a compromised cryptographic key or password, a human user possesses one face and ten fingers [611]. Biometric matching is inherently a statistical threshold classifier over noisy physical measurements (`FAR` vs. False Rejection Rate), subject to adversarial ML synthesis and physical presentation advances, while cancelable biometric transforms trade matching accuracy against template irreversibility [611]. Biometrics therefore belong strictly inside a local hardware-isolated activation gate (`ESS`), never on the wire or in a server database [185, 575]. Moreover, neither `WebAuthn` nor `COSE` currently standardizes post-quantum signature algorithms (`ML-DSA` `FIPS 204` remains pending future `IANA COSE` / `TPM` integration [95, 591]), and no local gesture protocol can detect coerced user consent under physical duress [564].

### Decoupling Front-Door Origin Binding from Recovery and Post-Sign-In Sessions

Consistent with Law 16, proving phishing-resistant possession of a `TPM`-bound key at `t = 0` guarantees neither the strength of account recovery nor the integrity of the bearer session at `t > 0`.

> **Key idea.**
> A relying party that verifies `clientDataJSON.origin`, `rpIdHash`, `UV = 1`, and `BE = 0` proves exactly one proposition: the legitimate hardware authenticator authorized a sign-in to the genuine origin right now [570]. If that sign-in mints an unbound OAuth refresh token or browser cookie ([Chapter 14](11-pth-prt.md)), post-unlock malware steals the session without ever touching the `TPM`; if the user's account still permits password, `SMS`, or unverified `TAP` recovery, the attacker bypasses `WebAuthn` entirely (`System AAL = min(ceremony, recovery)`) [559, 564, 609].

## Inspecting and Verifying on a Running System

Operational verification checks three independent layers: `NGC` and `TPM` provisioning state, `WBF` and `ESS` (`Secure Biometrics`) isolation prerequisites, and `webauthn.dll` platform authenticator readiness.

### Verifying `NGC` Container Provisioning and `TPM 2.0` Readiness

Confirm that the signed-in user has an active `NGC` Windows Hello key container (`NgcSet : YES`) backed by `TPM 2.0` [551, 575]:

```powershell
dsregcmd /status | Select-String 'AzureAdJoined|NgcSet|WamDefaultSet|KeyProvider|TpmProtected'
certutil -tpminfo | Select-String 'TPM Version|Manufacturer'
```

Expected output on a provisioned `WHfB` workstation:

```text
    AzureAdJoined : YES
    KeyProvider : Microsoft Platform Crypto Provider
    TpmProtected : YES
    NgcSet : YES
    WamDefaultSet : YES
TPM Version: 2.0
```

### Auditing `WBF` Service State and Enhanced Sign-in Security (`ESS`) `VTL1` Isolation

Verify `WbioSrvc` availability and check `Win32_DeviceGuard` plus the `WinBio` registry policy to confirm whether Secure Biometrics (`ESS`) is actively running inside `VTL1` (`SecurityServicesRunning` containing `7` / `Secure Biometrics` on supported hardware) [185, 580]:

```powershell
Get-Service WbioSrvc | Select-Object Name, Status, StartType
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio' -ErrorAction SilentlyContinue
```

Expected `DeviceGuard` output on an `ESS`-active Windows 11 system (`1` = Credential Guard, `2` = HVCI, `7` = Secure Biometrics / `ESS`):

```text
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
                                2 {1, 2, 7}                  {1, 2, 7}
```

If `7` is absent despite working face/fingerprint sign-in, the endpoint is operating in non-`ESS` `WBF` mode (`VTL0` sensor/template boundary) and should not be treated as `ESS`-isolated for Tier-0 administration [185].

### Probing `webauthn.dll` API Version and Platform Authenticator (`UV`) Availability

Invoke the documented `Win32` `webauthn.dll` sentinels (`WebAuthNGetApiVersionNumber` and `WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable`) to verify OS passkey dispatch readiness [596, 597, 598]:

```powershell
$w = Add-Type -Name WebAuthn -PassThru -MemberDefinition '[DllImport("webauthn.dll", ExactSpelling=true)] public static extern uint WebAuthNGetApiVersionNumber(); [DllImport("webauthn.dll", ExactSpelling=true)] public static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool a);'
$uv = $false; $hr = $w::WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable([ref]$uv)
[PSCustomObject]@{ ApiVersion = $w::WebAuthNGetApiVersionNumber(); HResult = ('0x{0:X8}' -f $hr); UvPlatformAvailable = $uv }
```

Expected output on Windows 11 `24H2+` with Windows Hello configured (`ApiVersion >= 7` indicates `24H2` `IPluginAuthenticator` support) [596, 598]:

```text
ApiVersion HResult    UvPlatformAvailable
---------- -------    -------------------
         8 0x00000000                True
```

## Summary & Handoff

Windows Hello (`NGC`) and `WebAuthn`/`CTAP 2.x` passkeys sever the 65-year dependency on shared remote secrets: biometric templates and `PINs` stay local, `ESS` (`BioIso.exe` + `SDCP`) isolates sensor matching in `VTL1`, `TPM 2.0` signs challenges without exporting private keys, and `clientDataJSON.origin` + `rpIdHash` defeat reverse-proxy `AitM` phishing by construction. Yet front-door cryptographic ceremony strength remains bounded above by account recovery (`System AAL = min(ceremony, recovery)`), diluted from `AAL3` to `AAL2` whenever keys leave dedicated hardware for synced (`BE=1`) or `24H2` vault plug-in fabrics, and silent once post-sign-in malware hijacks the resulting user session.

With the silicon, kernel, and credential foundations of Parts I through III complete, the final two sections of the book pivot to host telemetry and the cloud control plane:

* **Observing Endpoint Credential, Process, and Kernel Activity:** Before leaving the local machine, [ETW: The EDR Substrate (Chapter 16)](28-etw.md) examines the kernel-to-user event tracing architecture (`EtwTi`, `AMSI`, `Sysmon`, and `WebAuthn`/`LSASS` providers) that every modern Windows detection sensor relies on, and how attackers blind it.
* **Governing Every Request and Revoking Stolen Sessions in the Cloud:** How Microsoft Entra ID evaluates device compliance, `Phishing-Resistant MFA` strength, and `Token Protection` on every resource request, while shrinking bearer-token lifetime from hours to minutes, forms Part IV: [Zero Trust (Chapter 17)](13-zero-trust.md) and [Continuous Access Evaluation (Chapter 18)](14-cae.md).
