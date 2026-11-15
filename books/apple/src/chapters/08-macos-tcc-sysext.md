# macOS Privacy Governance, TCC, and System Extensions

## Overview

* **Link in the Chain:** Workstation privacy-consent and kernel-deprivileging fork in Part II; governs how un-sandboxed `macOS` processes access sensitive user files/sensors via `Transparency, Consent, and Control` (`TCC`) and relocates third-party kernel drivers (`kexts`) into user-space `SystemExtensions`.
* **Core Security Invariant:** Access to `TCC`-protected user resources (`Documents`, `Desktop`, `Camera`, `Microphone`, `ScreenCapture`, `AppleEvents`, `Full Disk Access`) requires an explicit user grant or supervised `MDM` `PPPC` profile recorded in `TCC.db` bound to the responsible application's `CodeRequirement` (`csreq`), while third-party hardware, network, and security drivers execute in `EL0` (`DriverKit`, `NetworkExtension`, `EndpointSecurity`) rather than `EL1`.
* **Platform Matrix:** `SystemExtensions`, `DriverKit` (shared selectively with `iPadOS` on M-series iPads), and `responsible_pid` desktop `TCC` attribution are architecturally centered on `macOS`, whereas `iOS`, `watchOS`, and `visionOS` enforce per-app container isolation directly without unbundled shell inheritance or arbitrary `AppleEvents` automation.
* **Trusted Computing Base (TCB):** User and system `tccd` daemons, `SIP`- and Data-Vault-protected `TCC.db` SQLite databases, `XNU` `responsibility` tracking (`responsible_pid`), `Sandbox.kext` / `FileProvider` enforcement hooks, Apple's private `com.apple.private.tcc.allow` entitlement surface, and `sysextd` (`SystemExtensions.framework`).
* **Failure Horizon & Handoff:** Inherited `responsible_pid` trust across consented terminals/IDEs/browsers (`HM Surf` `CVE-2024-44133`, `MCP` agents in [Chapter 18](18-agentic-ai-workload-isolation.md)) and over-privileged accessibility services (`CVE-2025-43530` `com.apple.scrod`) produce recurring confused-deputy `TCC` bypasses; hands off enterprise `EndpointSecurity` telemetry and `iOS` forensic visibility to [Chapter 9](09-esf-xprotect-forensics.md).

## Threat Model & Design Tension

On `iOS`, every third-party app lives inside its own `/var/mobile/Containers/Data/Application/<UUID>` sandbox ([Chapter 7](07-ipc-seatbelt-blastdoor.md)); no `Photos` or `Contacts` database is visible in its POSIX path namespace unless brokered explicitly through an out-of-process `XPC` picker or privacy daemon. On `macOS`, however, decades of UNIX and desktop workflows assume a shared user home directory (`/Users/alice`) populated with un-sandboxed `Developer ID` applications, Homebrew CLI binaries (`/opt/homebrew/bin/python3`, `git`, `rg`), shell scripts, and inter-application `AppleEvents` (`osascript`) automation [80, 81]. Under traditional POSIX discretionary access control (`DAC`), every process launched by Alice runs as `UID 501`, meaning a trojanized npm package, malicious Electron utility, or macro-launched Python script running as `UID 501` previously enjoyed silent read/write access to `~/Desktop`, `~/Documents`, `~/.ssh`, Mail, Messages, the webcam, and the screen!

Simultaneously, `macOS` historically suffered a second desktop-specific vulnerability surface in Ring 0 (`EL1`): third-party `IOKit` kernel extensions (`.kext`) for USB interfaces, VPN tunnels, antivirus hooks, and storage adapters ran inside `XNU`'s shared kernel address space [33, 85]. A single memory-corruption bug in a third-party `.kext` bypassed user-space isolation completely or crashed the Mac, and under Apple Silicon `Full Security` ([Chapter 2](02-mac-localpolicy.md)), loading *any* third-party `.kext` forces the owner to boot `1TR` and downgrade the volume group to `Reduced Security`.

Apple's answer on modern `macOS` pairs two architectural pillars [80, 85]. First, *Transparency, Consent, and Control (`TCC`)* interposes mandatory per-application privacy gates inside `UID 501` so running as Alice is no longer sufficient to read Alice's `~/Documents`, capture her screen, or script `Finder`. Second, *System Extensions* (`DriverKit`, `NetworkExtension`, and `EndpointSecurity`) evict third-party kernel code from `EL1` into sandboxed `EL0` user-space daemons fenced by `AppleDART` IOMMUs, keeping workstations on `Full Security` [85, 86]. Yet grafting app-centric consent onto UNIX process trees (`fork` + `execve` of unbundled CLI binaries) creates one of the most fertile confused-deputy surfaces in modern `macOS` security: the `responsible_pid` attribution problem [81, 84].

## Silicon & System Mechanics

### TCC Architecture: Dual Databases, csreq Binding, and responsible_pid Attribution

`TCC` splits enforcement between kernel `MACF` / VFS / `IOKit` gates (`Sandbox.kext`, `WindowServer`, `coreaudiod`, `appleeventsd`) and two instances of the user-space policy daemon `tccd` [80, 81]: a *system* instance (`root`) managing machine-wide privileges inside `/Library/Application Support/com.apple.TCC/TCC.db` (such as `kTCCServiceSystemPolicyAllFiles` Full Disk Access, `kTCCServiceScreenCapture`, `kTCCServiceAccessibility`, `kTCCServiceListenEvent` keystroke monitoring, and `kTCCServiceEndpointSecurityClient`), and a per-*user* instance (`UID 501`) managing user-scoped privileges inside `~/Library/Application Support/com.apple.TCC/TCC.db` (`kTCCServiceSystemPolicyDesktopFolder`, `DocumentsFolder`, `DownloadsFolder`, `Camera`, `Microphone`, `AddressBook`, `Calendar`, and `kTCCServiceAppleEvents` per target bundle ID) [80, 81]. Both `TCC.db` SQLite databases sit inside kernel-enforced `SIP` / `UF_DATAVAULT` storage so neither `UID 501` nor unentitled `UID 0` `root` processes can `sqlite3`-insert fake `auth_value = 2` (Allowed) rows directly on disk [31, 81].

![Figure: macOS TCC attribution chain resolving unbundled child CLI processes back to the GUI parent's responsible_pid and CodeRequirement (csreq), illustrating confused-deputy bypass surfaces.](diagrams/08-tcc-attribution-chain.svg)

How does `tccd` attribute an access request when a user opens `iTerm.app` (or `Terminal.app`, `Xcode`, or `Cursor`) and runs `/bin/zsh` $\to$ `/usr/bin/python3 backup.py`, which calls `open("/Users/alice/Desktop/tax.pdf")`? `/usr/bin/python3` is a bare UNIX Mach-O binary with no `.app` bundle, no `Info.plist` usage description strings, and no independent UI identity; prompting the user *"Allow `sh` to access Desktop?"* would break UNIX composability and train users to click Allow blindly (or let malware invoke `/usr/bin/curl` to piggyback on a global `curl` grant!).

`XNU` solves this via kernel-tracked *process responsibility* (`responsible_pid` stored on the kernel `proc` / `task` structure and inspectable via private `responsibility_get_pid_responsible_for_pid()`) [81]. When `LaunchServices` spawns a bundled GUI application (`Terminal.app`, `PID 1200`), `XNU` marks `PID 1200` as its own responsible process. Across subsequent `fork()`, `posix_spawn()`, and `execve()` calls spawning `/bin/zsh` (`PID 1205`) and `python3` (`PID 1490`), `XNU` propagates `responsible_pid = 1200` down the entire descendant tree (unless a child calls `POSIX_SPAWN_SETEXEC` via `LaunchServices` / `xpcproxy` to establish a new independent responsible bundle) [81, 84]:

$$\text{EvaluateTCC}(\tau_{\text{caller}}, \tau_{\text{responsible}}, \text{service}) \iff \text{MatchCSReq}\bigl(\tau_{\text{responsible}},\, \texttt{TCC.db}[\text{service, client}]\bigr)$$

When `Sandbox.kext` intercepts `open("~/Desktop/tax.pdf")` from `PID 1490`, it upcalls `tccd` passing *both* the immediate caller's `audit_token_t` ($\tau_{\text{caller}}$) and the responsible GUI process's `audit_token_t` ($\tau_{\text{responsible}}$ for `Terminal.app`) [81]. `tccd` verifies that `Terminal.app`'s live signature satisfies the binary `CodeRequirement` (`csreq` blob stored in `TCC.db` pinning `identifier "com.apple.Terminal" and anchor apple`, or a third-party app's `TeamID`), prompts the user *"Terminal would like to access files in your Desktop folder"*, and once granted (`auth_value = 2`), silently permits *every future child process spawned inside `Terminal.app`* to read `~/Desktop`!

Enterprise fleets bypass interactive end-user prompts on supervised Macs through MDM *Privacy Preferences Policy Control (`PPPC`)* configuration profiles (`com.apple.TCC.configuration-profile-policy`), which allow administrators to pre-grant Full Disk Access or `EndpointSecurity` permissions, though Apple intentionally forbids MDM from *silently* enabling `Camera`, `Microphone`, or `ScreenCapture` (`Standard` users can only be allowed to approve Screen Recording themselves, not silently recorded by IT without indicator visibility) [80, 119].

### Replacing EL1 Kexts: SystemExtensions, DriverKit, and NetworkExtension

To retire `EL1` kernel extensions (`IOKit` `.kext`) without breaking enterprise security agents, VPNs, or pro audio/USB hardware, Apple introduced `SystemExtensions.framework` (`sysextd`) paired with three domain-specific user-space (`EL0`) frameworks [85, 86]:

![Figure: Architectural migration from legacy EL1 IOKit kernel extensions (requiring 1TR Reduced Security) to EL0 sandboxed DriverKit, NetworkExtension, and EndpointSecurity System Extensions under Full Security.](diagrams/08-kext-to-driverkit-migration.svg)

First, *DriverKit* (`.dext` bundles) replaces C++ `IOKit` kernel drivers for USB (`USBDriverKit`), PCIe (`PCIDriverKit`, behind mandatory `AppleDART` IOMMU stream isolation!), networking (`NetworkingDriverKit`), serial, HID, and audio (`AudioDriverKit`) [28, 85]. Packaged inside a notarized host `.app` in `/Applications` and staged by `sysextd` into `SIP`-protected `/Library/SystemExtensions/`, a `.dext` executes as a dedicated, unprivileged, tightly sandboxed `EL0` process communicating with `XNU`'s `IOUserServer` kernel nub over high-speed `IODispatchQueue` / `Mach` RPC channels and shared `IOMemoryDescriptor` DMA buffers mapped strictly through `AppleDART` [28, 85]. If a buggy USB or PCIe `.dext` dereferences a null pointer or overflows a heap buffer, `XNU` does not kernel-panic; the `.dext` process simply crashes in `EL0` and `launchd` restarts it cleanly while `Full Security` (`BootKC` immutability) remains completely intact!

Second, *NetworkExtension* (`NEFilterDataProvider`, `NEDNSProxyProvider`, `NEAppProxyProvider`, and `NEPacketTunnelProvider`) replaces deprecated `BSD` `NKE` (Network Kernel Extensions) socket filters, streaming flow metadata or packets between `XNU`'s `necp` (Network Extension Control Policy) kernel subsystem and a user-space daemon via memory-mapped `skywalk` / kernel channels [86]. Third, *EndpointSecurity* (`ESF`, examined in depth in [Chapter 9](09-esf-xprotect-forensics.md)) replaces deprecated `Kauth` (`kauth_listen_scope`) kernel file/process hooks [87]. Installing any System Extension requires a signed `com.apple.developer.system-extension.install` entitlement plus interactive administrator approval in System Settings (or pre-authorization via a supervised MDM `com.apple.system-extension-policy` payload) [85, 119].

## Platform Forks Across Apple OSes

Comparing `TCC` and `SystemExtensions` across Apple's platforms exposes how user-consent architecture adapts to form factor [1, 80, 85]. On `iOS`, `iPadOS`, `watchOS`, and `visionOS`, `tccd` also governs `Camera`, `Microphone`, `Photos` (increasingly superseded by out-of-process `PHPickerViewController` which grants *zero* full-library `TCC` entitlement at all, passing only the single user-tapped photo!), `Location`, `Contacts`, and `LocalNetwork`, but because every mobile app is bundled, sandboxed, and forbidden from spawning arbitrary shells or sending cross-app `AppleEvents`, `responsible_pid` confused-deputy chains essentially vanish on mobile [1, 91].

Interestingly, `DriverKit` itself forked partially *onto* `iPadOS 16+` exclusively for `M`-series iPads: hardware vendors can ship `USBDriverKit`, `PCIDriverKit` (Thunderbolt), and `AudioDriverKit` `.dext` extensions inside App Store iPad apps so professional external interfaces work safely in `EL0` on `iPad Pro`, while `EndpointSecurity` System Extensions remain strictly `macOS`-only [85, 91].

## In-the-Wild Failures & Architectural Bounds

No subsystem on `macOS` has accumulated more CVEs between 2020 and 2026 than `TCC` [82, 83, 84]. Because Apple pre-grants private `com.apple.private.tcc.allow` entitlements to dozens of first-party system apps and accessibility daemons so the OS itself doesn't drown the user in pop-ups (and because `responsible_pid` trusts every child of a consented developer tool) attackers repeatedly hijack trusted deputies rather than attacking `TCC.db` directly.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| Electron `RUN_AS_NODE` / `DYLD` Bundle Injection | 2020-2024 | `macOS` | `TCC` `csreq` & `responsible_pid` | Third-party apps signed without Hardened Runtime (`CS_AST_LV` / disabled library validation) or exposing `ELECTRON_RUN_AS_NODE=1` let malware run arbitrary JS/code *inside* the consented app's `audit_token_t` (`Camera`, `Mic`, `FDA`) | Hardened Runtime enforcement + Electron `FuseV1Options.RunAsNode = false` fuse [81, 84] |
| Mounted DMG Old-Binary Downgrade (`Time Machine` / `Finder`) | 2020-2023 | `macOS` | Apple `anchor apple` `TCC` entitlements | Mounting an older signed `macOS` installer DMG let attackers execute vulnerable older Apple binaries that still satisfied `anchor apple` and held `com.apple.private.tcc.allow` | `Launch Constraints` ([Chapter 6](06-amfi-txm-notarization.md)) block executing system binaries outside sealed `/` [65, 84] |
| `HM Surf` (`CVE-2024-44133`, *AdLoad*) | 2024 | `macOS` (`< 14.7` / `15.0`) | `Safari` `com.apple.private.tcc.allow` | `Safari` held broad private `TCC` camera/mic/location/directory bypass entitlements while reading mutable per-user configuration files (`~/Library/Safari`) outside `Data Vault` protection; *AdLoad* modified Safari config to browse arbitrary local/device resources silently | Tightened `Safari` container/config Data Vault protections in `macOS Sonoma 14.7` and `Sequoia 15` [82] |
| VoiceOver `scrod` `AppleEvents` Bypass (`CVE-2025-43530`) | 2025-2026 | `macOS` | `TCC` `AppleEvents` & Privacy Prompts | Mickey Jin discovered a private API inside `ScreenReader.framework`'s `com.apple.scrod` accessibility daemon that executed arbitrary `AppleScript` files and sent `AppleEvents` to `Finder` and target apps on an unprivileged caller's behalf without any `TCC` prompt | Restricted `com.apple.scrod` IPC caller entitlements and `AppleScript` execution gates [83] |

### HM Surf (CVE-2024-44133) and VoiceOver Automation (CVE-2025-43530)

Both `HM Surf` (`CVE-2024-44133`, caught in the wild by Microsoft Threat Intelligence being abused by the *AdLoad* macOS malware family) and `CVE-2025-43530` (disclosed by researcher Mickey Jin) expose the structural fragility of ambient private `TCC` entitlements [82, 83]. In `HM Surf`, Apple granted `Safari` private `TCC` entitlements so WebKit could manage its own per-website camera, microphone, and file permissions internally; however, because `~/Library/Safari` configuration preferences were not fully sealed against local process tampering, an unprivileged `UID 501` process could rewrite Safari's local state files, launch `Safari` headlessly/minimized, and ride `Safari`'s `TCC` exemptions [82]. In `CVE-2025-43530`, VoiceOver's `com.apple.scrod` daemon needed broad `AppleEvents` authority to assist visually impaired users across every app on the desktop; failing to authenticate IPC callers and restrict script paths inside `ScreenReader.framework` allowed any local process to turn `scrod` into a silent "ghost user" driving `Finder` to exfiltrate `TCC`-protected folders without triggering a single consent dialog [83]. And as [Chapter 18](18-agentic-ai-workload-isolation.md) will demonstrate, even with zero Apple OS bugs, granting Full Disk Access to an IDE or terminal that subsequently runs an untrusted `Model Context Protocol` (`MCP`) agent recreates this exact `responsible_pid` confused deputy by design!

## Verification & Forensic Artifacts

List installed and active `DriverKit`, `NetworkExtension`, and `EndpointSecurity` user-space System Extensions on `macOS` without elevated privileges [85]:

```bash
systemextensionsctl list
```

Representative output showing active user-space extensions (`[activated enabled]`) preserving `Full Security`:

```text
2 extension(s)
--- com.apple.system_extension.endpoint_security
enabled	active	teamID	bundleID (version)	name	[state]
*	*	EQHXZ8M8AV	com.vendor.edr.sensor (2.4/1)	Vendor EDR	[activated enabled]
```

From a terminal application that *already* holds Full Disk Access (for defensive auditing), query the read-only system and user `TCC.db` tables to audit which `client` bundle identifiers hold `kTCCServiceSystemPolicyAllFiles` (`auth_value = 2` means Allowed) [80, 81]:

```bash
sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, service, auth_value, last_modified FROM access WHERE auth_value = 2 LIMIT 8;" 2>/dev/null || true
```

Observe live `tccd` attribution decisions (`AttributionChain` showing `responsible` vs `requesting` processes) in Unified Logging [81, 90]:

```bash
log show --last 5m --predicate 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS "AttributionChain"' --style compact | tail -n 4
```

Having built the entire execution and containment stack across Parts I and II, we pause at the midpoint of the trust chain in [Chapter 9](09-esf-xprotect-forensics.md) to ask a defender's question: how can security teams *observe* these layers in practice on an open `macOS` workstation versus a locked `iOS` pocket device?
