# Code Integrity and Application Control

## Overview

* **Role in the Chain:** Cryptographic code-identity and execution-policy layer spanning Ring 0 and Ring 3; binds PE binaries and detached catalogs to X.509 signers (`Authenticode`), enforces kernel driver admission and `W^X` page immutability from `VTL1` (`KMCS` and `HVCI`), and restricts user-mode execution via `App Control for Business` (`WDAC`) and `AppLocker`.
* **Core Security Invariant:** Under `HVCI` with an organization-signed `App Control` policy, `VTL1` Secure Kernel Code Integrity (`SKCI`) maps a kernel or user page executable if and only if its Authenticode/page digest and signer satisfy active `.cip` allow rules and evade all deny rules (`DriverSiPolicy.p7b` and Recommended Block Rules), while `SLAT` forbids simultaneous write and execute permissions (`W^X`).
* **Trusted Computing Base (TCB):** `skci.dll` and `Trustlet ID 0` in `VTL1`, `ci.dll` and `wintrust.dll` parsers, the `CatRoot` catalog subsystem (`CryptSvc`), trusted root CAs and RFC 3161 Time-Stamping Authorities (`TSAs`), organization policy-signing keys, and (for per-user `AppLocker` only) the `VTL0` `AppIDSvc` service.
* **Primary Failure Modes:** Bring Your Own Vulnerable Driver (`BYOVD`) attacks abusing validly signed drivers with unsafe IOCTLs (`Capcom.sys`, `gdrv.sys`, `RTCore64.sys`), attacker-scriptable Microsoft-signed `LOLBins` (`msbuild.exe`, `cdb.exe`, `dotnet.exe`), compromised vendor keys or MD5-collided CAs (`Stuxnet`, `Flame`, `ShadowHammer`), unhashed certificate-table padding (`CVE-2013-3900`), and `g_CiOptions` patching or `AppIDSvc` termination when `HVCI` or signed `WDAC` is absent.
* **Handoff:** Guarantees *which* signed code pages may map and execute; delegates process-handle protection lattices to Protected Process Light ([Chapter 8](18-ppl.md)), control-flow memory mitigations against data/ROP exploits inside allowed code to Process Mitigation Policies ([Chapter 9](19-mitigations.md)), and telemetry of blocked loads and driver callbacks to ETW ([Chapter 16](28-etw.md)).

## Core Engineering Problem & Threat Model

Isolating `VTL1` ([Chapter 6](05-secure-kernel.md)) does not by itself decide which drivers may enter `VTL0` Ring 0 or which executables may launch in Ring 3. For Windows' first decade of code signing (1996 to 2005), execution trust was purely advisory: `Authenticode` prompted users on Internet Explorer ActiveX downloads [208], 32-bit driver installation defaulted to a dismissible `SetupAPI` warning dialog exploited by rootkits such as Sony BMG's `XCP` filter driver [2, 209], and Windows XP's Software Restriction Policies (`SRP`) evaluated rules inside the caller's own user-mode process via `WinSafer*` APIs [210, 211]. Any attacker who socially engineered a click or reached local `Administrator` bypassed the gate trivially.

Moving enforcement into the kernel with 64-bit Windows Vista's Kernel-Mode Code Signing (`KMCS`) [2, 212] eliminated unsigned Ring 0 rootkits in default configurations, yet exposed a deeper architectural problem that defines modern endpoint defense: cryptographic provenance is not behavioral safety. Across the next twenty years, state actors stole semiconductor signing keys (`Stuxnet` [213]) and forged intermediate CAs (`Flame` [214]), ransomware operators shipped genuine signed hardware-utility drivers carrying raw physical-memory write IOCTLs (`BYOVD` [159, 215, 216]), and post-exploitation frameworks executed arbitrary C# and shellcode through inbox Microsoft-signed developer utilities (`LOLBins` [217, 218]).

The Code Integrity and Application Control threat model spans two distinct adversary tiers mapped explicitly to Microsoft Security Response Center (`MSRC`) servicing boundaries [173, 219]:

1. **Standard-User Containment (Operational Hygiene):** Preventing non-administrative users on shared workstations or VDI hosts from executing unauthorized binaries or scripts (`AppLocker` and unsigned `App Control` policies).
2. **Administrator- and `SYSTEM`-Resistant Code Enforcement (Security Boundary):** Preventing an adversary who *already holds `SYSTEM` or Ring 0 write primitives in `VTL0`* from mapping unsigned kernel code, zeroing kernel integrity flags (`ci.dll!g_CiOptions`), deleting application-control policy files, or loading known-vulnerable signed drivers and `LOLBins` (`HVCI` + organization-signed `App Control` policy + `DriverSiPolicy.p7b` + Recommended Block Rules) [159, 183, 217, 219].

## Architectural Deep Dive

### Authenticode Anatomy, Detached Catalogs, and RFC 3161 Timestamping

Every Windows code-identity decision, from `ci.dll` driver loads and `App Control` rules down to UAC publisher prompts, consumes a single cryptographic envelope introduced in 1996 on top of PKCS#7 / CMS (`RFC 5652`) [208, 220, 221]. Inside a signed Portable Executable (`PE`), the envelope nests across four layers (`diagrams/20-authenticode-signature-nest.svg`):

![Figure: The four nesting levels of an Authenticode signature on disk. The optional header points by file offset (not an RVA) at a WIN_CERTIFICATE, which wraps a CMS SignedData, whose SpcIndirectDataContent carries the one signed value, the Authenticode hash. the optional page-hash signed attribute and the RFC 3161 timestamp hang off the SignerInfo, and the three PE regions excluded from the hash are shaded.](diagrams/20-authenticode-signature-nest.svg)

1. **PE Security Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`):** Entry 4 of the PE `OptionalHeader.DataDirectory` stores a raw *file offset* (unique among PE directories, which otherwise store RVAs) and byte length pointing to an unmapped trailing Attribute Certificate Table of `WIN_CERTIFICATE` records (`wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002`) [16, 220]. Dual-signed binaries embed secondary signatures inside the primary signature's `unsignedAttrs` (`szOID_NESTED_SIGNATURE`).
2. **CMS `SignedData` (`1.2.840.113549.1.7.2`):** Carries the X.509 certificate chain (`certificates`), digest identifiers, and `SignerInfo` structures holding `signedAttrs`, the asymmetric RSA/ECDSA `encryptedDigest`, and `unsignedAttrs` [221].
3. **`SpcIndirectDataContent` (`1.3.6.1.4.1.311.2.1.4`):** Microsoft's encapsulated content payload, binding an artifact descriptor (`SPC_PE_IMAGE_DATAOBJ`, `1.3.6.1.4.1.311.2.1.15`) to `messageDigest` [220].
4. **PE Authenticode Digest and 4 KiB Page Hashes:** Rather than hashing raw file bytes, the Authenticode digest algorithm skips `OptionalHeader.CheckSum` (4 bytes), skips `DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]` (8 bytes), hashes non-empty sections ordered by `PointerToRawData`, omits the Attribute Certificate Table, and hashes any remaining trailing bytes [220]. When signed with `/ph`, `signedAttrs` additionally carries `SpcPeImagePageHashes2` (`1.3.6.1.4.1.311.2.3.2`): an array of `(RVA, SHA-256)` pairs for each 4 KiB page, enabling `HVCI` to verify individual code pages on demand faults in RAM rather than only once at file open [220].

Two structural decouplings allow this format to scale across an entire operating system and across decades:

* **Detached Catalog Files (`.cat`) and `CatRoot`:** Because `SpcIndirectDataContent` signs a *digest* rather than an inline file, Windows packages thousands of inbox system files and multi-file driver packages (`.sys`, `.dll`, `.inf`) into a single CMS-signed `.cat` table of member thumbprints [222, 223, 224]. Installed catalogs reside in `%SystemRoot%\System32\CatRoot\{GUID}\` and are indexed by `CryptSvc`. When `wintrust.dll!WinVerifyTrust` or `ci.dll` encounters an executable lacking an embedded `WIN_CERTIFICATE`, it computes the PE Authenticode digest and queries the catalog index; a matching `.cat` supplies the effective signer without mutating a single byte of the binary on disk [222, 223].
* **RFC 3161 Trusted Timestamping (`1.3.6.1.4.1.311.3.3.1`):** End-entity code-signing certificates expire every one to three years. At build time, the signer hashes `SignerInfo.encryptedDigest` and submits it to a Time-Stamping Authority (`TSA`), attaching the signed CMS `TimeStampToken` (`TSTInfo.genTime`) inside `unsignedAttrs` [225]. Verifiers validate both the code-signing chain and the TSA chain, accepting an expired signing certificate so long as the signature was timestamped inside its original validity window prior to any compromise revocation date [225].

### Kernel-Mode Code Signing (`KMCS`) and Portal Counter-Signing

On 64-bit Windows, `ci.dll` intercepts `MmLoadSystemImage` during `IopLoadDriver` and refuses any Ring 0 module lacking a valid kernel-trusted signature (unless developer overrides such as `bcdedit /set testsigning on` or `nointegritychecks` are active, both blocked when UEFI Secure Boot is enforcing, [Chapter 1](16-secure-boot.md)) [2].

Historically (2006 to 2015), `KMCS` accepted third-party commercial code-signing CAs cross-signed by the `Microsoft Code Verification Root` [2, 226]. Beginning with Windows 10 version 1607 (for certificates issued after July 29, 2015, with cross-certificates expiring across the industry by July 2021), Microsoft retired commercial cross-signing for new drivers and made the Windows Hardware Developer Center the sole counter-signing authority terminating at Microsoft Root Authorities [2, 227, 228]:

* **WHQL / HLK Release Signing:** Requires passing the Windows Hardware Lab Kit (`HLK`) test suite; produces a Microsoft counter-signed `.cat` eligible for Windows Update distribution across client and server SKUs [229, 230].
* **Attestation Signing:** Requires authenticating the publisher's portal account with an hardware-backed Extended Validation (`EV`) certificate and passing automated malware/primitive scans; produces a Microsoft counter-signature valid for client Windows SKUs without full `HLK` lab runs [231, 232, 233].

Crucially, `KMCS` preserves backward-compatibility grandfathering carve-outs: legacy cross-signed drivers issued prior to July 29, 2015 remain loadable on systems upgraded from pre-1607 releases, systems with Secure Boot disabled, or where the cross-signed chain remains unrevoked, leaving a multi-decade pool of legacy signed drivers valid under pure `KMCS` rules unless blocked by higher policy layers [2].

### Hypervisor-Protected Code Integrity (`HVCI`), `SKCI`, and `KDP`

When `ci.dll` runs solely in `VTL0`, it suffers the Same-Privilege Paradox ([Chapter 6](05-secure-kernel.md)): a single vulnerable driver with a Ring 0 write primitive can overwrite `ci.dll!g_CiOptions` to `0x0`, disabling Driver Signature Enforcement (`DSE`) across the running OS [234]. **Hypervisor-Protected Code Integrity (`HVCI`, surfaced in Windows Security as *Memory Integrity*)** closes that loop by splitting `ci.dll` across Virtual Trust Levels (`diagrams/06-code-integrity-hvci-vtl-split.svg`) [183, 234]:

![Figure: The trust-domain split under HVCI. VTL0, the normal world, holds the NT kernel, its drivers, and `ci.dll` with the `g_CiOptions` policy page; the smaller VTL1, the secure world, holds the Secure Kernel and SKCI, the code-integrity judge that verifies signatures at section-create time and enforces W^X. Beneath both sits the hypervisor's SLAT, which enforces two invariants: VTL1 pages carry no VTL0 mapping, and KDP marks the VTL0 `g_CiOptions` page read-only at the SLAT level. The one legitimate crossing is the mediated section-create secure call.](diagrams/06-code-integrity-hvci-vtl-split.svg)

1. **`VTL1` Verification (`skci.dll` and `Trustlet ID 0`):** Whenever `VTL0` attempts to map an executable kernel image section or fault in a code page, `hvix64.exe`/`hvax64.exe` traps the transition to Secure Kernel Code Integrity (`SKCI`) inside `VTL1`. `SKCI` validates full Authenticode/catalog chains, checks `SpcPeImagePageHashes2` per-page digests, and evaluates active `Code Integrity` policies inside `VTL1`-private memory unreachable from `VTL0` [183, 220].
2. **SLAT-Enforced `W^X` and `MBEC`/`GMET`:** `HVCI` programs `VTL0`'s SLAT tables so no guest-physical page is ever simultaneously writable and executable, eliminating classic Ring 0 shellcode allocation (`ExAllocatePool` RWX) and live code patching [183]. On Intel Kabylake+ (Mode-Based Execution Control, `MBEC`) and AMD Zen 2+ (Guest Mode Execute Trap, `GMET`), SLAT entries split kernel-execute (`Xs`) from user-execute (`Xu`) bits natively in silicon, avoiding the steep performance overhead of legacy Restricted User Mode emulation [183].
3. **Kernel Data Protection (`KDP`):** Exposed via `MmProtectDriverSection`, `KDP` instructs `VTL1` to lock static `VTL0` driver data pages (specifically the `ci.dll` data page housing `g_CiOptions`) as read-only in `VTL0`'s SLAT tree, causing any Ring 0 write attempt against `g_CiOptions` to fault at the hypervisor boundary [234].

### Application Control Engines: `App Control for Business` (`WDAC`), `AppLocker`, and `SAC`

Windows ships three distinct policy products that consume these Authenticode and `ci.dll` primitives for different administrative models [219, 235]:

| Dimension | `AppLocker` (2009+) | `App Control for Business` / `WDAC` (2015+) | `Smart App Control` / `SAC` (2022+) |
|---|---|---|---|
| MSRC Boundary Status | Defense-in-depth hygiene; *not* a serviced security feature [219] | Serviced security feature when policy is org-signed + `HVCI` is running [173, 219] | Consumer baseline protection (unmanaged) [235, 236] |
| Enforcement Engine | `AppID.sys` minifilter deferring verdict to user-mode `AppIDSvc` (`LocalService`) [237] | In-kernel `ci.dll` + `VTL1` `skci.dll` (`HVCI`); no user-mode service to stop [183, 219] | Same `ci.dll` / `skci.dll` engine [235] |
| Policy Scope & Storage | Per-user / per-SID XML rules via `AuthzAccessCheck` [237, 238] | Whole-device compiled `{GUID}.cip` binaries in `CodeIntegrity\CiPolicies\Active\` [239] | Whole-device binary toggle (Evaluation → On / Off); disabled on MDM hosts [235, 236] |
| Rule Granularity | `Publisher`, `Path`, `Hash` across `.exe`, `.dll`, `.msi`, `.appx`, and scripts (incl. `.bat`/`.cmd`) [238, 240] | 12 rule levels (`Hash`, `FilePublisher`, `Publisher`, `WHQLFilePublisher`, `PcaCertificate`, non-user-writable `FilePath`) + enlightened script hosts (PowerShell Constrained Language, JScript/VBScript, MSI; excludes `.bat`/`.cmd`) [238, 241, 242, 243] | Cloud `ISG` reputation + Trusted Root CA signature fallback + `DriverSiPolicy.p7b` [235] |
| Admin Tamper Resistance | None (`sc.exe stop AppIDSvc` halts enforcement immediately) [244, 245] | Unsigned `.cip`: admin can delete file; Signed `.cip`: requires org PKI private key to remove/replace across Secure Boot [219, 239] | User/Administrator can toggle off in Windows Security UI [236] |

Two architectural subtleties govern enterprise `App Control for Business` (renamed from Configurable Code Integrity in 2017 (`WDAC`) and rebranded in 2024 [246, 247]):
* **Multi-Policy Algebra and Signed Policy Binding:** Modern Windows (with the 32-policy ceiling removed in April 2024 via `KB5036893` / `KB5036892` [239, 248, 249]) evaluates multiple `.cip` files simultaneously: multiple *base* policies intersect (a binary must pass all base policies), *supplemental* policies union with their parent base policy, and explicit deny rules always win. Crucially, an unsigned `.cip` file can be deleted by `SYSTEM`; only signing the `.cip` with an enterprise PKI certificate (enabling `Signed Policy` rules) seals the policy signer set across UEFI Secure Boot so even `SYSTEM` cannot strip enforcement without a signed replacement policy [219].
* **Extended-Attribute Trust Propagation (`Managed Installer` and `ISG`):** To avoid brittle hash maintenance, `App Control` uses NTFS Extended Attributes (`$KERNEL.SMARTLOCKER.ORIGINCLAIM`) written by kernel components when a binary is dropped by a designated Managed Installer (such as Intune Management Extension or ConfigMgr, configured via an internal AppLocker rule collection [250]) or classified as *known good* by Microsoft's cloud Intelligent Security Graph (`ISG`) reputation service (an ML telemetry classifier refreshed daily, *not* a static list, with `Enabled:Invalidate EAs on Reboot` available to purge stale claims) [251].

For kernel drivers specifically, Windows 11 22H2+ overlays five defense-in-depth gates (`diagrams/06-code-integrity-five-gates.svg`): `KMCS` root verification, the inbox Vulnerable Driver Blocklist (`%windir%\System32\CodeIntegrity\DriverSiPolicy.p7b`, updated via Windows Update from quarterly block-rule releases [159, 252]), `HVCI`/`SKCI` `VTL1` `W^X` enforcement, enterprise `App Control` / consumer `SAC` rules, and Microsoft Defender Attack Surface Reduction (`ASR` rule `56a863a9-875e-4185-98a7-b882c64b5ce5`) covering `HVCI`-off endpoints [232, 253].

![Figure: The 2026 stack as a defense-in-depth funnel. A kernel driver image encounters overlapping predicates, each catching a blind spot the previous one cannot reach: KMCS signature/chain (misses signed-but-vulnerable) → the `DriverSiPolicy.p7b` Vulnerable Driver Block List (misses unknown-vulnerable) → HVCI / SKCI in VTL1 with W^X (misses behavioral BYOVD) → App Control / Smart App Control policy and app reputation where applicable (misses allow-listed defects) → Defender ASR for HVCI-off coverage (misses non-listed drivers). A driver that survives the applicable gates still maps into ring 0, and the gap no gate closes is the undecidable question of whether a signed driver hides a kernel-write primitive (Rice's theorem).](diagrams/06-code-integrity-five-gates.svg)

## Attack Catalog & Gap Analysis

Every major code-integrity and application-control bypass exploits one of four structural gaps: compromised upstream signing identities, parser discrepancies in unhashed PE regions, unprotected `VTL0` evaluators (`g_CiOptions` or `AppIDSvc`), or dangerous runtime capabilities inside legitimately signed drivers (`BYOVD`) and applications (`LOLBins`).

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| Stuxnet, Flame (`MS12-038`), & ShadowHammer | 2010, 2012, 2019 | Assumption that valid X.509 chain implies benign publisher | Stolen Realtek/JMicron keys (`Stuxnet`), MD5 collision (`Flame`), or ASUS build breach | Signs malicious `.sys` drivers or software updaters with authentic vendor keys or MD5 chosen-prefix rogue Microsoft sub-CA | Hardware HSM/EV key custody, SHA-256 mandate, certificate revocation, and `WDAC` least-privilege allowlists [213, 214, 254, 255, 256] |
| `WinVerifyTrust` Padding (`CVE-2013-3900`) | 2013-2026 | Coverage of PE Authenticode digest over trailing `WIN_CERTIFICATE` bytes | Ability to modify signed installer PE on disk; default opt-out config (CISA KEV) | Appends malicious archive/config payload inside `bCertificate[]` padding excluded from Authenticode hash calculation | Enable `EnableCertPaddingCheck = 1` across 64-bit and `Wow6432Node` `Wintrust\Config` keys [257, 258] |
| `g_CiOptions` Patching (`DSE` Bypass) | 2014-present | `VTL0` `ci.dll` kernel-mode enforcement state | Ring 0 write primitive on a host with `HVCI` disabled | Overwrites `ci.dll!g_CiOptions` to `0` in `VTL0` kernel memory, disabling `KMCS` so unsigned rootkit drivers load freely | Enable `HVCI` (`Memory Integrity`), locking `g_CiOptions` read-only via `SLAT`-backed `KDP` [183, 234] |
| `BYOVD` (`Capcom.sys`, `gdrv.sys`, `RTCore64.sys`, `KProcessHacker`) | 2016-present | Ring 0 memory, MSR, and `PPL` isolation via signed third-party drivers | Local `Administrator` loading unblocked signed `.sys` (`CVE-2018-19320`, `CVE-2019-16098`) | Sends crafted IOCTLs to legitimate signed drivers (`0xAA013044` SMEP-off exec, `MmMapIoSpace` physical R/W, or `PPL` process kill) | Enforce `HVCI` + updated `DriverSiPolicy.p7b` XML, `WHQLFilePublisher` `WDAC` rules, and Defender `ASR` [159, 253, 259, 260, 261, 262] |
| `AppLocker` Service Stop & Path Bypasses | 2017-present | User-mode `AppLocker` execution restrictions | `Administrator`/`SYSTEM` (`sc stop AppIDSvc`) or user-writable subdirectories (`C:\Windows\Tasks`) | Terminates `LocalService` `AppIDSvc` evaluator or drops payloads into default-allowed user-writable paths (`UltimateAppLockerByPassList`) | Use organization-signed `App Control` (`.cip`) + `HVCI` where admin resistance is required; tighten path rules with `AaronLocker` [219, 244, 245, 263] |
| Publisher-Gate `LOLBins` (`msbuild`, `cdb`, `dotnet`, `mshta`, `wsl`) | 2016-present | `App Control` allowlists trusting broad `Microsoft` signers | Execution access on host lacking Recommended Block Rules (`UltimateWDACBypassList`) | Invokes allowed Microsoft-signed compilers, debuggers, or script hosts to execute inline C#, shellcode, or unmanaged subsystems | Merge Microsoft Recommended Block Rules into every base `App Control` policy [217, 218, 264, 265, 266] |

### Compromised Provenance and Parser Gaps: Stuxnet, Flame, ShadowHammer, and CVE-2013-3900

Cryptographic verification proves only that a private key chaining to a trusted root signed an Authenticode hash. In June 2010, `Stuxnet` loaded `mrxcls.sys` and `mrxnet.sys` cleanly under x64 `KMCS` using genuine private keys stolen from Realtek and JMicron [213, 267]. In 2012, `Flame` went further: exploiting MD5 chosen-prefix collisions (building on Sotirov et al.'s 2008 rogue-CA cryptanalysis [268]), its authors forged an unauthorized `Microsoft Enforced Licensing Intermediate PCA` certificate accepted by Windows for code validation (`MS12-038` / Advisory `2718704`) [214, 254]. And in 2019, `Operation ShadowHammer` compromised ASUSTeK's build pipeline to sign trojanized `ASUS Live Update` binaries with ASUS's legitimate certificate [256] (a supply-chain pattern repeated across ecosystems, including the April 2026 `@bitwarden/cli` OIDC publishing compromise [269, 270]).

At the parser layer, `CVE-2013-3900` (`MS13-098`, listed on CISA's Known Exploited Vulnerabilities catalog) exploits the fact that the Attribute Certificate Table is omitted from the PE Authenticode digest [220, 257, 258]. If an attacker appends extra archive or configuration bytes to `WIN_CERTIFICATE.bCertificate[]` and adjusts `dwLength` and `DataDirectory[SECURITY].Size`, legacy `WinVerifyTrust` ignores the unauthenticated trailing bytes and reports a valid signature while self-extracting installers parse the attacker's appended payload. Because broken legacy installers relied on trailing certificate padding, Microsoft kept the strict `EnableCertPaddingCheck` fix opt-in by default across Windows releases [257].

### Signed-Driver Primitives: The BYOVD Arms Race

Even with `HVCI` active in `VTL1` and `g_CiOptions` locked read-only via `KDP` [234], `SKCI` checks only whether a driver is signed, `W^X`-compliant, and absent from active deny rules. Over two thousand legitimately signed hardware, overclocking, diagnostic, and anti-cheat drivers cataloged in `LOLDrivers` [271, 272] expose catastrophic capabilities by design:

* **Arbitrary Ring 0 Function Execution (`Capcom.sys`, 2016):** Shipped with Street Fighter V, `Capcom.sys` exposed IOCTL `0xAA013044`, disabling `CR4.SMEP` and jumping directly to a caller-supplied user-mode pointer in Ring 0 [259, 273].
* **Arbitrary Physical/Kernel Memory Read-Write (`gdrv.sys` CVE-2018-19320; `RTCore64.sys` CVE-2019-16098):** Gigabyte's APP Center driver and MSI Afterburner's driver exposed `MmMapIoSpace`, MSR, and I/O port primitives to local administrators, weaponized by `RobbinHood` and `BlackByte` ransomware to zero kernel `ETW` / callback arrays across security sensors without ever allocating an unsigned executable page [215, 216, 260, 261].
* **Protected Process Termination (`KProcessHacker`):** Abused by `DoppelPaymer` and post-exploitation kits to open kernel handles (`ZwTerminateProcess`) and kill `PPL`-protected antivirus/EDR processes ([Chapter 8](18-ppl.md)) from a legitimately signed driver context [262].

### Evaluator Removal (`AppIDSvc`) and Publisher-Gate `LOLBins`

In user mode, application-control bypasses divide strictly by enforcement architecture. Against `AppLocker`, any `Administrator` or `SYSTEM` process can stop `AppIDSvc` (`sc.exe stop AppIDSvc`), removing the user-mode `AuthzAccessCheck` oracle so `AppID.sys` stops blocking launches, while standard users target default `C:\Windows\*` path rules via writable subdirectories (`C:\Windows\Tasks`, `C:\Windows\Temp`) unless hardened with `AaronLocker` [237, 244, 245, 263].

Against kernel-enforced, signed `App Control` (`WDAC`), stopping services or deleting `.cip` files fails. Adversaries pivot instead to Living Off The Land Binaries (`LOLBins`) (`diagrams/21-app-control-publisher-gate.svg`) [217, 218]:

![Figure: The publisher-gate's structural blind spot, drawn as a before/after timeline. At policy-evaluation time the allow decision is fixed from signer / hash / path. `msbuild.exe` is Microsoft-signed, so the policy admits it. Only at runtime, after the entry point, does the binary read attacker-controlled input and compile inline C#. No policy-time check spans both moments.](diagrams/21-app-control-publisher-gate.svg)

If an enterprise base policy trusts `"Microsoft Windows"` or `"Microsoft Corporation"` signers without merging Microsoft's Recommended Block Rules (~40+ denied Microsoft binaries [217]), `ci.dll` admits signed hosts whose legitimate purpose is executing caller-supplied code: `msbuild.exe` (inline C# `<UsingTask>`), `cdb.exe` / `windbg.exe` (debugger shellcode scripting, Matt Graeber [264]), `csi.exe` / `dnx.exe` / `dotnet.exe` (arbitrary .NET assembly loading, Casey Smith, Matt Nelson, Jimmy Bayne [266, 274, 275]), `addinprocess.exe` (James Forshaw [265]), `mshta.exe`, `wmic.exe` XSL processing, and `wsl.exe` [217, 218].

## Theoretical Limits & Structural Invariants

### Provenance vs. Behavioral Undecidability (Rice's Theorem)

Consistent with Law 16, code signing and publisher allowlists prove syntactic provenance ($\mathrm{Sig}_{sk}(H(p))$), whereas "absence of exploitable IOCTLs or scriptable side effects" is a semantic property of program execution.

> **Key idea.**
> By Rice's theorem, determining whether an arbitrary Turing-complete driver or executable can be coerced by untrusted input into granting an arbitrary write or code-execution primitive is undecidable in the general case. Every static admission gate (`KMCS`, `SKCI`, `WDAC`) evaluates decidable syntactic predicates: hash equality, X.509 chain validity, `W^X` section flags, and finite set membership (`DriverSiPolicy.p7b` and Recommended Block Rules). Because no static signer can block *all and only* unsafe programs, curated blocklists and runtime exploit mitigations ([Chapter 9](19-mitigations.md)) remain permanent architectural complements rather than temporary workarounds.

### The Published-vs.-Shipped Blocklist Lag and Compatibility Friction

Even for *known*-vulnerable binaries, defensive enforcement lags public disclosure for operational reasons. Microsoft explicitly holds back certain vulnerable drivers from the inbox Windows Update `DriverSiPolicy.p7b` binary to avoid Blue-Screen boot failures or broken OEM hardware on unupdated endpoints, making the downloadable XML on Microsoft Learn strictly more complete than the inbox OS file [159, 276]. Similarly, aggressive user-mode block rules carry real production side effects (for example, blocking `webclnt.dll` in the Recommended Block Rules to stop WebDAV NTLM coercion has caused documented 5-to-15-second UI hangs in Microsoft Word OneDrive saves [277]), and offline endpoints rely on potentially stale `CatRoot` and `.cip` snapshots until serviced, while RFC 3161 `TSAs` lack public Certificate-Transparency-style append logs against backdated compromises [225, 278].

### Non-Substitutability of `AppLocker` and `App Control` (`2x2` Scope Matrix)

Practitioners frequently misstate that `AppLocker` is deprecated; in fact, Microsoft maintains `AppLocker` with ongoing security servicing (`KB5044288` [279, 280]) because `AppLocker` and `App Control` occupy distinct quadrants (`diagrams/21-app-control-threat-quadrant.svg`) [219, 238]:

![Figure: Threat-model fit as a 2×2: per-user requirement on the horizontal axis, admin-resistant requirement on the vertical. AppLocker (per-user, no PKI), App Control for Business (signed + HVCI), and Smart App Control land in different quadrants, and the per-user-AND-admin-resistant quadrant is empty for any single product. A side-by-side deployment composition can approximate it (AppLocker for per-user policy and App Control for the admin-resistant boundary) at the cost of running two evaluators.](diagrams/21-app-control-threat-quadrant.svg)

`ci.dll` evaluates `App Control` at section creation *device-wide* without per-user SID scoping, whereas `AppLocker` evaluates per-user/group SIDs in `AppIDSvc` without admin resistance. Multi-user RDS/Citrix hosts requiring per-role software restrictions alongside Ring 0 / admin tamper resistance must layer both mechanisms concurrently: a signed device-wide `App Control` baseline (`+ HVCI + Recommended Block Rules + DriverSiPolicy`) underneath per-user `AppLocker` collections [219, 238].

## Inspecting and Verifying on a Running System

Operational verification checks four planes: embedded versus catalog Authenticode provenance, strict `WinVerifyTrust` padding enforcement (`CVE-2013-3900`), `HVCI` and `DriverSiPolicy.p7b` status, and active `App Control` `.cip` policies plus `CodeIntegrity` telemetry.

### Inspecting Embedded vs. Catalog Authenticode Provenance

Compare an embedded-signed executable against a catalog-signed inbox kernel driver to observe `WinVerifyTrust` and `CatRoot` resolution [222, 223]:

```powershell
Get-AuthenticodeSignature 'C:\Windows\System32
otepad.exe','C:\Windows\System32\drivers\disk.sys' |
    Select-Object Path, Status, SignatureType, @{N='Subject';E={$_.SignerCertificate.Subject}}
```

Expected output format:

```text
Path                                    Status SignatureType Subject
----                                    ------ ------------- -------
C:\Windows\System32
otepad.exe          Valid  Authenticode CN=Microsoft Windows, O=Microsoft Corporation...
C:\Windows\System32\drivers\disk.sys     Valid       Catalog CN=Microsoft Windows, O=Microsoft Corporation...
```

`SignatureType = Catalog` confirms `disk.sys` carries no inline `WIN_CERTIFICATE` and was authenticated via its Authenticode member hash inside `%SystemRoot%\System32\CatRoot\` [223].

### Verifying HVCI, Vulnerable Driver Blocklist, and CVE-2013-3900 Hardening

Check that `HVCI` (`SecurityServicesRunning` contains `2`) and system Code Integrity enforcement are active, the inbox `DriverSiPolicy.p7b` blocklist is enabled, and strict `WinVerifyTrust` certificate-padding validation (`CVE-2013-3900`) is configured (elevated PowerShell) [159, 183, 257]:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object SecurityServicesRunning, CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable' -ErrorAction SilentlyContinue
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -ErrorAction SilentlyContinue
```

Expected output on a hardened Windows 11 host:

```text
SecurityServicesRunning CodeIntegrityPolicyEnforcementStatus UsermodeCodeIntegrityPolicyEnforcementStatus
----------------------- ------------------------------------ --------------------------------------------
{1, 2}                                                     2                                            2

VulnerableDriverBlocklistEnable : 1
EnableCertPaddingCheck          : 1
```

In `Win32_DeviceGuard`, `EnforcementStatus` values map to `0` (`Off`), `1` (`Audit`), and `2` (`Enforced`) [183, 281]. On 64-bit Windows, verify `EnableCertPaddingCheck = 1` (`REG_DWORD`) under `HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config` as well to cover 32-bit `WinVerifyTrust` callers [257].

### Auditing Active App Control `.cip` Policies and Block Telemetry

Enumerate compiled multi-policy `.cip` binaries loaded by `ci.dll` and inspect `Microsoft-Windows-CodeIntegrity/Operational` for audit (`3076`) or enforced block (`3077` policy, `3033` signing level) events [239, 282]:

```powershell
Get-ChildItem "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active\*.cip" |
    Select-Object Name, Length, LastWriteTime
Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 5 |
    Where-Object Id -in 3033, 3076, 3077 | Select-Object TimeCreated, Id, Message
```

Expected output format when active base and supplemental `.cip` policies block an unapproved binary:

```text
Name                                     Length LastWriteTime
----                                     ------ -------------
{A244370E-44C9-4C06-B551-F6016E563076}.cip 38412 11/14/2026 8:00:12 AM

TimeCreated           Id Message
-----------           -- -------
11/14/2026 9:14:22 AM 3077 Code Integrity determined that a process (\Device\HarddiskVolume3\...) attempted to load ... that did not meet the Enterprise signing level requirements or violated code integrity policy.
```

Correlating Event IDs `3076` (audit-only hit) and `3077` (enforced block) with `AppIDSvc` status (`Get-Service AppIDSvc`) distinguishes kernel `ci.dll` policy enforcement from user-mode `AppLocker` rules [237, 282].

## Summary & Handoff

Windows code identity and application control layer thirty years of policy engineering onto the 1996 PKCS#7 `SpcIndirectDataContent` primitive: detached `CatRoot` catalogs and RFC 3161 timestamps made signature verification scale across the OS, `KMCS` and portal counter-signing centralized Ring 0 admission, `HVCI` (`SKCI` + `SLAT` `W^X` + `KDP`) placed the policy judge and `g_CiOptions` out of `VTL0`'s reach, and organization-signed `App Control for Business` policies paired with `DriverSiPolicy.p7b` and Recommended Block Rules turned execution control into an admin-resistant boundary. Yet because static signatures cannot decide semantic safety (Rice's theorem), allowed drivers and applications remain capable of runtime abuse or memory corruption once mapped.

Containing what *allowed* processes can do to one another and to their own address spaces requires the remaining two links of Part II (Kernel & Code):

* **Protecting Critical User-Mode Processes by Signer Lattice:** Shielding `lsass.exe`, `csrss.exe`, and anti-malware services against handle opening, memory reading, and code injection from `Administrator`/`SYSTEM` callers in `VTL0` belongs to [Protected Process Light (Chapter 8)](18-ppl.md).
* **Hardening Runtime Control Flow Inside Allowed Code:** Defending admitted binaries and kernel modules against memory-corruption exploits, ROP/JOP chains, and dynamic code generation (`ASLR`, `DEP`, `ACG`, `CIG`, `CFG`, `XFG`, and hardware `Intel CET` shadow stacks) is owned by [Process Mitigation Policies (Chapter 9)](19-mitigations.md).
