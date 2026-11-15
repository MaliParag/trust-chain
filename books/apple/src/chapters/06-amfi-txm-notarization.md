# AMFI, TXM Trust Caches, Launch Constraints, and Notarization

## Overview

* **Link in the Chain:** Mandatory code-signing, capability-entitlement, and software-admission layer bridging `APFS`/`XNU` ([Chapter 5](05-apfs-ssv-dyld.md)) and `SPTM`/`TXM` monitors ([Chapter 4](04-silicon-memory-safety.md)) to user-space process execution.
* **Core Security Invariant:** `XNU` and `SPTM` map a 4 KB page with execute permission (`PROT_EXEC`) if and only if `TXM` (or `AMFI`/`CoreTrust`) validates its `SHA-256` page slot inside a signed `Mach-O` `CS_CodeDirectory` rooted in a Static/Dynamic Trust Cache or an authorized Apple/Developer certificate, and `execve()` succeeds only if the process satisfies its `DER` `Launch Constraints`.
* **Platform Matrix:** Shared `Mach-O` `CS_CodeDirectory`, `DER` entitlements, `TXM` trust caches, and `Launch Constraints` across all Apple OSes; third-party admission forks sharply between `iOS`/`watchOS`/`visionOS` (mandatory App Store or EU `DMA` Alternative Marketplace Notarization) and `macOS` (`Gatekeeper`, `com.apple.quarantine`, Developer ID + Apple Notary Service, plus owner override).
* **Trusted Computing Base (TCB):** `Trusted Execution Monitor` (`TXM` in `GL0`), `AppleMobileFileIntegrity.kext` (`AMFI`), `CoreTrust.kext` X.509/CMS parser, Static and Dynamic Trust Caches (`Image4`), `syspolicyd` / `Gatekeeper` on `macOS`, and Apple's App Store and Notary signing authorities.
* **Failure Horizon & Handoff:** Parser bugs in `CoreTrust` CMS/ASN.1 handling (`CVE-2021-30869`, `CVE-2023-41991`) or social-engineered `macOS` quarantine removal (`xattr -d` / right-click Open prior to `Sequoia` tightening) admit unauthorized binaries; hands off post-launch IPC, sandboxing, and parser containment to [Chapter 7](07-ipc-seatbelt-blastdoor.md).

## Threat Model & Design Tension

Even when the operating system's own binaries sit immutable inside an `APFS` `Signed System Volume` ([Chapter 5](05-apfs-ssv-dyld.md)), every useful device must load third-party applications from its writable `Data` volume, mount developer tools, and spawn background daemons. That requirement exposes three distinct attack vectors across Tier 1 (commodity malware) and Tier 3 (targeted exploit chains) [64, 65, 66]. First, if executable pages were verified only once when `execve()` opened a file (as legacy signature checkers did) an attacker could modify an unmapped file extent on disk mid-run or overwrite code in memory (`TOCTOU`), executing arbitrary unsigned shellcode. Second, if privileged capabilities (keychain access, debugging, sandbox exemptions, `SIP` installer rights) lived in mutable configuration files rather than cryptographically bound inside the binary's signature, any local `UID 0` exploit could grant itself arbitrary system authority. Third, even when Apple signs every system helper cleanly, *living-off-the-land* (`LotL`) attackers on `macOS` and `iOS` discovered they could copy an entitled Apple daemon from `/System` to `/tmp` (or spawn it directly from a compromised shell with crafted command-line arguments and environment variables) to abuse its genuine Apple signature outside its intended `launchd` context [65, 70].

At the ecosystem level, Apple also faces a sharp philosophical fork between pocket appliances and general-purpose workstations [66, 68]. On `iPhone`, `Apple Watch`, and `Vision Pro`, users expect zero commodity ransomware or adware, motivating mandatory pre-distribution review or automated notarization (expanded in the European Union under the Digital Markets Act `DMA` to third-party Alternative App Marketplaces without abandoning Apple-rooted binary notarization) [68]. On `macOS`, however, a developer compiling `cargo build` or `clang hello.c` must be able to execute `./a.out` immediately offline without asking Cupertino's servers for permission, forcing Apple Silicon `macOS` to require mandatory ad-hoc `arm64` code-directory hashes locally while gating *internet-downloaded* software through `Quarantine` extended attributes, `Gatekeeper`, and Apple Notarization [66, 67].

## Silicon & System Mechanics

### Mach-O SuperBlobs, Per-Page CodeDirectories, and DER Entitlements

Every native Apple Silicon executable and `.dylib` embeds an `LC_CODE_SIGNATURE` load command pointing to the `__LINKEDIT` segment at the tail of the `Mach-O` slice (`osfmk/kern/cs_blobs.h` in `XNU`) [10, 63]. That region begins with a big-endian `CS_SuperBlob` (`CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0`) indexing typed sub-blobs: the primary `CS_CodeDirectory` (`0xfade0c02`), code-signing requirements (`0xfade0c01`), legacy XML entitlements (`0xfade7171`), canonical `ASN.1` `DER` entitlements (`0xfade7172`), `DER` launch constraints, and a Cryptographic Message Syntax (`CMS` / `PKCS#7`) signature wrapper (`0xfade0b01`) [63].

Unlike Windows `PE` Authenticode (which hashes the entire executable linearly into one `SHA-256` digest, requiring the loader to read the whole binary into RAM up front) Apple's `CS_CodeDirectory` divides the `Mach-O` file into fixed 4 KB (`4096`-byte, matching virtual memory page granularity) chunks and stores an array of per-page `SHA-256` digests [63, 64]:

$$\text{CodeDirectory} = \bigl[\underbrace{h_{-7}, \dots, h_{-1}}_{\text{special metadata slots}} \;\big\|\; \underbrace{h_{0}, h_{1}, \dots, h_{P-1}}_{\text{4 KB executable file pages}}\bigr], \qquad \text{CDHash} = \text{Trunc}_{160/256}\bigl(\text{SHA-256}(\text{CodeDirectory})\bigr)$$

Negative *special slots* bind security metadata inextricably to the executable's cryptographic identity: slot `-1` hashes `Info.plist`, slot `-2` hashes internal code requirements, slot `-3` hashes bundle resources (`_CodeSignature/CodeResources`), slot `-5` hashes XML plist entitlements, and slot `-7` hashes the canonical `ASN.1` `DER`-encoded entitlements dictionary [63]. Moving entitlements from loose XML plists (`slot -5`, which historically suffered dangerous parser differentials between `CoreFoundation` and kernel `IOCFUnserialize`!) to canonical `DER` (`slot -7`) enabled fast, unambiguous deterministic parsing inside `CoreTrust` and `TXM` [11, 64].

![Figure: Mach-O CS_CodeDirectory verification across Static Trust Caches, Dynamic Trust Caches, TXM/CoreTrust CMS evaluation, and lazy vm_fault per-page SHA-256 enforcement.](diagrams/06-txm-trustcache-pipeline.svg)

Crucially, `XNU`'s virtual memory fault handler (`vm_fault` $\to$ `ubc_cs_page_validate`) enforces code integrity *lazily on every executable page fault* rather than eagerly on `execve()` [10, 64]. Only the `CS_SuperBlob` and `CDHash` are validated when the file is registered; later, as CPU execution touches page $k$, the pager reads those 4 KB from flash, computes $\text{SHA-256}(\text{page}_k)$, and verifies equality against slot $h_k$ inside the registered `CS_CodeDirectory` *before* asking `SPTM` (`GL2`) to map the physical frame executable [49, 64]. Across a process's lifetime, kernel `cs_flags` govern violation behavior: `CS_VALID` tracks clean state, `CS_HARD` refuses to map invalid pages, `CS_KILL` immediately delivers uncatchable `SIGKILL` (`EXEC_EXIT_REASON_CODESIGNING`) the instant any code page fails verification, and `CS_RUNTIME` enables the `macOS` Hardened Runtime (enforcing `W^X`, stripping `DYLD_*` injection variables, and turning on Library Validation so a process can `dlopen()` only Apple platform libraries or dylibs signed with the *exact same* Developer `TeamID`) [63, 66].

### Static Trust Caches, Dynamic Trust Caches, and AMFI-to-TXM Migration

How does `XNU` decide whether a binary's `CDHash` is trusted to run? Parsing `X.509` certificate chains and `RSA`/`ECDSA` `CMS` signatures inside the kernel on every system binary launch would expose complex `ASN.1` attack surface unnecessarily. Instead, all first-party OS binaries carry *zero* embedded `CMS` certificates inside `__LINKEDIT`; their 20-byte truncated `SHA-256` `CDHash` values are pre-sorted into compact binary lookup tables called *Static Trust Caches* baked directly into the `Image4`-authenticated `BootKC` / `ltrs` firmware payload [64]. Supplementary first-party images (`Cryptexes` from [Chapter 5](05-apfs-ssv-dyld.md) or Xcode Developer Disk Images) load *Dynamic Trust Caches* (`rtsc` / `ltrs` `Image4` payloads verified via `TSS`).

Prior to `A15`/`M2` and `iOS 17` / `macOS Sequoia`, `AppleMobileFileIntegrity.kext` (`AMFI`, backed by `CoreTrust.kext` in `EL1` and user-space `amfid`) owned trust-cache lookups and entitlement tables inside normal kernel memory, meaning an attacker with `EL1` kernel read/write could locate the `proc` `cs_flags` or dynamic trust cache in RAM, patch in a fake `CDHash`, and spawn arbitrary unsigned rootkit binaries [48, 64]. On modern Apple Silicon (`SPTM` systems, [Chapter 4](04-silicon-memory-safety.md)), Apple migrated code-signing custody out of `XNU` into the *Trusted Execution Monitor (`TXM`)* running in Guarded Execution `GL0` above `EL1` [49, 64]. Static and Dynamic Trust Caches, registered `CS_CodeDirectory` blobs, and parsed `DER` entitlement dictionaries reside inside `TXM_GLOBAL` physical frames write-locked by `SPTM`: `XNU` can no longer forge a `CDHash` or flip `CS_PLATFORM_BINARY` in memory even after total `EL1` compromise!

Only when a `CDHash` misses both Static and Dynamic Trust Caches (third-party App Store apps, enterprise apps, TestFlight builds, EU Marketplace apps, or `macOS` Developer ID / ad-hoc binaries) does evaluation step down to `CoreTrust` and `TXM`/`amfid` to validate the embedded `CMS` certificate chain, Provisioning Profile (`embedded.mobileprovision` binding allowed entitlements and UDIDs), or `macOS` `syspolicyd` verdict [64, 66].

### Launch Constraints and Environment Constraints

Introduced across `iOS 16` and `macOS Ventura`/`Sonoma` (`2022-2024`), *Launch Constraints* eliminated an entire decade of privilege-escalation tradecraft where attackers executed legitimate, entitled Apple binaries outside their intended context [65]. Encoded as `ASN.1` `DER` boolean constraint trees (embedded either inside the OS trust cache for system binaries or inside a third-party `Mach-O` signature via Xcode's `LWCR` dictionaries), a Launch Constraint specifies predicates over four `audit_token`/code-signing dictionaries at `posix_spawn` / `execve()` time [65]:

$$\text{AllowSpawn} = P_{\text{self}}(\text{target}) \;\land\; P_{\text{parent}}(\text{caller}) \;\land\; P_{\text{responsible}}(\text{resp}) \;\land\; P_{\text{existing}}(\text{loaded})$$

For example, every Apple system LaunchDaemon (`systemmigrationd`, `tccd`, `diskmanagementd`) now carries a trust-cache Launch Constraint requiring `validation-category == platform` AND `parent == launchd` (`PID 1`)! If a local attacker or compromised shell copies `/System/Library/.../systemmigrationd` to `/tmp/exploit` or invokes `posix_spawn()` on `/usr/libexec/some_daemon` directly from `bash` (`CVE-2023-28206` *Migraine* style [35]), `TXM`/`AMFI` evaluates $P_{\text{parent}}$, sees the caller is `bash` rather than `launchd`, and immediately aborts `execve()` with `EPERM` (`Launch Constraint Violation`) before a single instruction of the daemon runs [65]. Paired *Environment Constraints* further restrict dynamic linker environment state and library loading rules per category.

## Platform Forks Across Apple OSes

Nowhere do Apple's operating systems diverge more visibly (while sharing identical `TXM` and `CS_CodeDirectory` mechanics underneath) than in third-party software admission [64, 66, 68].

![Figure: Software admission fork across Launch Constraints for system daemons, App Store and EU DMA Notarization on iOS, and Gatekeeper Quarantine plus Notary tickets on macOS.](diagrams/06-launch-constraints-vs-gatekeeper.svg)

On `iOS` (worldwide outside the EU), `watchOS`, and `visionOS`, `TXM`/`CoreTrust` admits third-party code *only* if countersigned directly by the Apple App Store (`validation-category = App Store`), bound to a short-lived Xcode Development / Ad-Hoc / Enterprise Provisioning Profile (`embedded.mobileprovision` matching `ECID`s or supervised MDM enterprise certs), or TestFlight [64]. In the European Union (`iOS 17.4+` and `iPadOS 18+` under the Digital Markets Act `DMA`), Apple introduced *Alternative App Marketplaces and iOS Notarization* [68]: developers submit encrypted app bundles to Apple's automated review + human baseline safety pipeline (checking malware, sandbox integrity, and accurate developer identity rather than content/business-model rules); Apple issues a cryptographic Notarization signature bound to an authorized Marketplace app's `CoreTrust` certificate, while the device's region-eligibility daemon (`countryd`) verifies EU physical/account eligibility before permitting marketplace installation [68].

On `macOS`, by contrast, Apple Silicon requires every native `arm64` binary to carry at least an *ad-hoc* `CS_CodeDirectory` (`codesign -s -`, automatically emitted by Apple's `ld` linker with zero certificate required so local builds always have per-page `SHA-256` hashes for `vm_fault`), while internet distribution is governed by *Gatekeeper* (`syspolicyd`) and *Quarantine* [66, 67]. When a browser, mail client, or archive utility writes a downloaded file, `Quarantine.kext` / `LSFileQuarantineEnabled` attaches the `com.apple.quarantine` extended attribute recording source URL, downloading agent, timestamp, and event UUID. On first launch of any quarantined executable (and re-evaluated on subsequent launches in modern `macOS` via `syspolicyd` cache checks against live `XProtect` revocations), `Gatekeeper` enforces three checks [66, 67]: a valid `Developer ID Application` signature chaining to Apple's Root CA, `CS_RUNTIME` (Hardened Runtime), and a cryptographic *Notarization Ticket* issued by Apple's cloud Notary Service (`notarytool`, either *stapled* offline inside the bundle/DMG or fetched online via `CloudKit`) proving Apple scanned every Mach-O inside the archive for known malware and code-signing defects. Starting in `macOS Sequoia 15` (`2024+`), Apple removed the trivial Finder Control-click $\to$ *Open* one-click Gatekeeper bypass that social-engineering malware (`AMOS`) abused, requiring explicit navigation into *System Settings $\to$ Privacy & Security* to override an unnotarized binary [66, 103].

## In-the-Wild Failures & Architectural Bounds

Code signing proves *who signed an immutable sequence of pages*; it cannot prove that a complex `ASN.1`/`CMS` verifier parsed the signature without ambiguity, nor that a newly compiled zero-day stealer uploaded to Apple's automated Notary Service is benign.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Fugu14` `CoreTrust` Bypass (`CVE-2021-30869`) | 2021 | `iOS` / `macOS` | `CoreTrust` `Mach-O` / `DER` verification | Confusion between `arm64` Mach-O slice / custom signature blob parsing allowed executing arbitrary code with App Store trust | Hardened `CoreTrust` Mach-O header and `CodeDirectory` validation [69] |
| `TrollStore` `CoreTrust` CMS Bug (`CVE-2023-41991`) | 2023 | `iOS` / `iPadOS` (`14.0`-`16.6.1`, `17.0`) | `CoreTrust` `CMS` multi-signer attribution | When a `CMS` `SignedData` blob contained multiple `SignerInfo` entries, `CoreTrust` validated Apple's legitimate root signature on one entry while trusting attacker-appended `CDHash` attributes from a second entry, granting permanent arbitrary entitlements! | Patched `CoreTrust` `SignerInfo` binding in `iOS 16.7` / `17.0.1` and reinforced `TXM` (`GL0`) parsing [64, 69] |
| Notarized Malware (`Shlayer`, `AMOS` campaigns) | 2020-2026 | `macOS` | Automated Apple Notary Service | Attackers used stolen or shell-company `Developer ID` accounts to notarize obfuscated stage-1 droppers that fetched malicious payloads dynamically after passing automated scans | Rapid `CloudKit` ticket revocation + `XProtect` behavioral (`Bastion`) post-launch blocking ([Chapter 9](09-esf-xprotect-forensics.md)) [66, 70, 89] |
| `Gatekeeper` Archive / `Quarantine` Stripping | 2021-2024 | `macOS` | `com.apple.quarantine` propagation | Specific archive formats or CLI tools (`curl` without quarantine flag, or social-engineered `xattr -c` terminal paste attacks) bypassed `Gatekeeper` first-launch triggers | Expanded `syspolicyd` execution checks even on unquarantined unsigned code and removed right-click Open shortcut in `macOS 15+` [66, 70] |

### CVE-2023-41991 (TrollStore) and the Peril of Multi-Signer CMS

Linus Henze's `Fugu14` (`CVE-2021-30869`) and the subsequent `CVE-2023-41991` `CoreTrust` bug exploited by `TrollStore` across `iOS 14.0` through `17.0` provide a textbook illustration of `editorial.md`'s principle separating mechanism validity from parser semantics [69]. `PKCS#7` / `CMS` `SignedData` was standardized in the 1990s for email S/MIME workflows supporting *multiple independent co-signers* (`SET OF SignerInfo`). An attacker took a genuine Apple-signed App Store or system binary's valid `CMS` signature block and appended a *second*, attacker-generated `SignerInfo` referencing the attacker's own trojanized `CS_CodeDirectory` (complete with `platform-application = true` and `com.apple.private.*` arbitrary entitlements!). Because `CoreTrust` verified that *an* Apple-chained `SignerInfo` existed in the `CMS` container without strictly binding the extracted `CDHash` attribute list exclusively to that verified `SignerInfo`, `iOS` treated arbitrary sideloaded binaries as genuine Apple platform executables across reboots without needing a kernel exploit [69].

## Verification & Forensic Artifacts

Inspect any `macOS` binary's `Mach-O` `CS_CodeDirectory` format, `CDHash`, `flags` (`0x10000(runtime)` for `CS_RUNTIME`), `TeamIdentifier`, and `DER` entitlements (`slot -7`) using `codesign` [63, 66]:

```bash
codesign -dvvv /Applications/Safari.app
codesign -d --entitlements :- /Applications/Safari.app 2>/dev/null | head -n 10
```

Representative output confirming `arm64e`, sealed `CodeDirectory v=20400`, and platform flags:

```text
Executable=/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari
Format=app bundle with Mach-O thin (arm64e)
CodeDirectory v=20400 size=21024 flags=0x0(none) hashes=646+7 location=embedded
CDHash=8f4a21c9...
```

Extract and inspect the embedded `Launch Constraints` (`--launch-constraints`) on a system daemon to verify that it can only be spawned by `launchd` [65]:

```bash
codesign -d --launch-constraints :- /usr/libexec/securityd 2>/dev/null | head -n 12
```

Evaluate `Gatekeeper` (`spctl`), `com.apple.quarantine` extended attributes, and stapled Notarization tickets on a downloaded third-party `.app` bundle [66, 67]:

```bash
xattr -p com.apple.quarantine /Applications/*.app 2>/dev/null | head -n 3
spctl -a -t exec -vv /System/Applications/Calculator.app 2>&1
xcrun stapler validate /Applications/*.app 2>/dev/null | head -n 3
```

Once `TXM`, `Launch Constraints`, and `Notarization` admit a binary into memory, code signing's job is done: a legitimately signed browser renderer (`WebContent`) or messaging daemon (`imagent`) still processes untrusted attacker packets every second. [Chapter 7](07-ipc-seatbelt-blastdoor.md) traces how `Mach` IPC capabilities, `XPC` `audit_token_t` identity, `Seatbelt` sandboxes, and `BlastDoor` contain compromised processes after launch.
