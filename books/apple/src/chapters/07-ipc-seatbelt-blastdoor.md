# Mach IPC, XPC Audit Tokens, Seatbelt, and BlastDoor

## Overview

* **Link in the Chain:** Runtime inter-process communication (`IPC`) and process-containment layer; governs how processes admitted by `TXM`/`AMFI` ([Chapter 6](06-amfi-txm-notarization.md)) communicate across privilege boundaries and how untrusted network/media parsers (`WebKit`, `iMessage`) are fenced inside minimal `MACF` sandboxes.
* **Core Security Invariant:** Privileged `XPC` and `Mach` services authenticate callers exclusively via kernel-minted `audit_token_t` trailers (incorporating monotonic `pidversion`) paired with `DER` code-signing requirements, while `Seatbelt` (`Sandbox.kext`) denies every file, `Mach` bootstrap lookup, `IOKit` user-client, and syscall outside the process's compiled sandbox profile.
* **Platform Matrix:** Shared `Mach` ports, `XPC` `audit_token_t`, `Seatbelt` bytecode engine, `WebKit` multi-process split, and `BlastDoor` airlock across `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS`; forks in mandatory App Sandbox scope (`100%` of third-party apps on mobile/watch/spatial vs. opt-in for non-Mac-App-Store `Developer ID` apps on `macOS`) and EU `iOS`/`iPadOS` `BrowserEngineKit` extensions.
* **Trusted Computing Base (TCB):** `XNU` `osfmk/ipc` port right tables and `audit_token_t` generation, `launchd` bootstrap namespaces, `libxpc` / `Security.framework` peer requirement evaluators, `Sandbox.kext` `MACF` bytecode interpreter, `APRR` thread-local JIT write locks, and `BlastDoor`'s Swift/sandboxed parser boundary.
* **Failure Horizon & Handoff:** Logic flaws in privileged `XPC` handlers, `IOKit`/VM kernel bugs reachable through residual sandbox allowlists (`CVE-2025-43510`), and Turing-complete logic inside "safe" non-JIT decoders (*FORCEDENTRY* `JBIG2` `CVE-2021-30860`) breach containment; hands off user-consent privacy prompts (`TCC`) and `DriverKit` extensions on `macOS` to [Chapter 8](08-macos-tcc-sysext.md).

## Threat Model & Design Tension

Code signing ([Chapter 6](06-amfi-txm-notarization.md)) guarantees only that `Safari`'s `WebContent` renderer or `Messages`'s attachment previewer started from genuine Apple-signed pages; the instant that process ingests an attacker-crafted HTML document, `WebGL` shader, `WebP` image, `TrueType` font, or `iMessage` `BPList` over the network, memory safety inside the parser is under direct Tier 1 and Tier 3 assault [3, 77, 78]. Worse, modern Apple OSes follow a heavily decomposed service-oriented design: hundreds of privileged `root` or user LaunchDaemons and LaunchAgents (`tccd`, `installd`, `nsurlsessiond`, `mediaplaybackd`, third-party `SMJobBless` / `SMAppService` privileged helpers) expose `Mach` and `XPC` endpoints to lower-privileged clients so apps can render audio, install updates, or fetch credentials without holding ambient privileges themselves [17, 72].

This micro-service decomposition creates two acute failure modes. First, at the IPC boundary, if a privileged root `XPC` helper validates who called it using mutable POSIX process attributes (such as the caller's `pid_t` (`NSXPCConnection.processIdentifier`)) a local sandboxed attacker can send a privileged request and immediately `execve()` into a trusted Apple binary so the helper checks the *new* binary's signature and executes the *attacker's* request as `root` [72, 73]. Second, inside media and web parsers, legacy formats (`PDF`, `JBIG2`, `Font`, `DNG`, `HEVC`) carry decades of C/C++ complexity: if `imagent` parses zero-click incoming `iMessage` attachments directly inside a daemon holding Contacts, Photos, and home-directory read access, one single-packet parser overflow compromises the user's entire digital life without a single tap [3, 77]. Containment must therefore pair *unforgeable kernel IPC identity* with *default-deny micro-sandboxes* that strip network, filesystem, JIT, and kernel driver reachability from every parser.

## Silicon & System Mechanics

### Mach Port Capabilities, MIG, and XPC audit_token_t Authentication

Beneath every `XPC` call, `AppleEvents` message, `IOKit` driver invocation (`io_connect_method`), and `EndpointSecurity` notification lies `Mach` IPC (`osfmk/ipc/`) [10, 71]. As established in [Foundations](00b-foundations.md), a `Mach` port (`ipc_port_t` in kernel memory) is a kernel-protected message queue referenced in user space by a task-local 32-bit capability handle (`mach_port_name_t`). Exactly *one* task holds the `MACH_PORT_RIGHT_RECEIVE` right for a port; any number of client tasks may hold `MACH_PORT_RIGHT_SEND` (reusable) or `MACH_PORT_RIGHT_SEND_ONCE` (single-reply capability automatically destroyed upon use) [71]. Clients discover system services by querying `launchd` (`bootstrap_look_up()`), which acts as the root namespace broker enforcing `Seatbelt` `mach-lookup` policies before handing out a send right [17, 74].

Raw `Mach` interfaces compiled with the legacy `Mach Interface Generator` (`MIG`, `.defs` files generating C marshaling stubs for kernel traps and old daemons) historically produced dozens of out-of-bounds read/write and port-reference-counting vulnerabilities (`mach_port_deallocate` lifecycle mismatches when `MIG` routines returned errors without consuming out-of-line `OOL` memory or port descriptors) [72]. Apple therefore migrated user-space IPC onto *XPC* (`libxpc` C API and `NSXPCConnection` Objective-C/Swift API), which serializes strongly typed dictionaries, file descriptors, and shared memory over `Mach` ports with deterministic reference counting [73].

![Figure: XPC peer authentication contrasting the broken POSIX pid_t TOCTOU race against XNU's unforgeable mach_msg_audit_trailer_t (audit_token_t with monotonic pidversion) and peer signing requirements.](diagrams/07-xpc-audit-token-vs-pid.svg)

How must an `XPC` server (especially a `root` privileged helper registered via `SMAppService` or `LaunchDaemons`) verify its client? When a client sends a message via `mach_msg()`, `XNU` itself (inside `EL1` kernel space before the client returns from the trap) appends a `mach_msg_audit_trailer_t` containing an 8-word `audit_token_t` [10, 72]:

$$\tau = (\text{auid},\; \text{euid},\; \text{egid},\; \text{ruid},\; \text{rgid},\; \text{pid},\; \text{asid},\; \text{pidversion})$$

Suppose an attacker process (`PID 4812`, $\text{pidversion} = 91$) dispatches an asynchronous `XPC` message to a privileged root helper and, nanoseconds later, invokes `execve("/usr/bin/true")` (or forks 99,999 processes until `PID 4812` wraps around to an Apple-signed daemon). If the server calls `[connection processIdentifier]` (`pid_t = 4812`) and passes `4812` to `SecCodeCopyGuestWithAttributes()`, the kernel looks up *whatever image currently occupies PID 4812* ($\text{pidversion} = 92$, signed by Apple!) and reports a valid Apple signature [72]! By contrast, when the server inspects `audit_token_t` directly (either via modern `xpc_connection_set_peer_code_signing_requirement(conn, req_str)` (added in `macOS 12+` / `iOS 15+` and exposed as `NSXPCConnection.setCodeSigningRequirement(_:)`) or `SecTaskCreateWithAuditToken(NULL, auditToken)`) `XNU` checks whether `PID 4812` *still has* $\text{pidversion} = 91$ [73]. Because `execve()` monotonically incremented the process's kernel `p_idversion` to $92$, the kernel immediately detects $\text{pidversion}_{\text{trailer}} \neq \text{pidversion}_{\text{current}}$ and rejects the peer!

> **Warning.**
> Every security check performed using `pid_t` (`NSXPCConnection.processIdentifier`, `xpc_connection_get_pid()`) across a privilege boundary on `Darwin` is structurally vulnerable to `execve()` or PID-wrap `TOCTOU` spoofing [72]. Privileged daemons must bind authorization exclusively to `audit_token_t` and require both an anchored `TeamID`/Apple certificate and explicit `DER` entitlements via `xpc_connection_set_peer_code_signing_requirement` [73].

### The Seatbelt Sandbox (Sandbox.kext), App Groups, and Data Vaults

Process containment on Apple OSes is enforced by `Seatbelt` (`Sandbox.kext` paired with `libsandbox.dylib`), a `MACF` policy module originally inspired by TrustedBSD and Scheme-based policy DSLs [74]. On `macOS`, human-readable *Sandbox Profile Language (`SBPL`)* files (`.sb` S-expressions under `/System/Library/Sandbox/Profiles/`, such as `(version 1) (deny default) (allow file-read* (subpath "/usr/lib"))`) are compiled into compact deterministic state-machine bytecode blobs; on `iOS`, `iPadOS`, `watchOS`, and `visionOS`, all built-in daemon and `container` App Sandbox profiles ship pre-compiled directly into binary bytecode inside `Sandbox.kext` / sealed system bundles to eliminate runtime compiler surface [17, 74].

Once a process enters a `Seatbelt` profile (either at `posix_spawn` via LaunchDaemon plists / App Sandbox `com.apple.security.app-sandbox` entitlement, or voluntarily via `sandbox_init()` before parsing untrusted input, a *one-way* transition that can only tighten, never relax, authority), `Sandbox.kext` intercepts over 120 `MACF` hooks [10, 74]: VFS paths (`file-read*`, `file-write*`), `Mach` service lookups (`mach-lookup`), `POSIX` shm/semaphores, network sockets (`network-outbound`, `network-inbound`), `sysctl` writes, `ioctl` commands, `IOKit` driver `IOServiceOpen` classes (`iokit-open` filtered by `IOUserClient` class name and properties!), and even raw `XNU` kernel syscall numbers (`syscall-unix`, `syscall-mach` bitmasks blocking obscure traps).

Each sandboxed third-party app receives an isolated container directory (`~/Library/Containers/<BundleID>/Data` on `macOS`; `/private/var/mobile/Containers/Data/Application/<UUID>` on `iOS`). Controlled sharing between apps from the same developer `TeamID` uses *App Groups* (`com.apple.security.application-groups`, verified via `DER` provisioning entitlements to mount a shared group container) [75], while Apple's own ultra-sensitive databases (`TCC.db`, Mail, Safari History, Messages `chat.db`) reside inside *Data Vaults* (`UF_DATAVAULT` BSD file flag enforced by `Sandbox.kext` at the kernel VFS layer so *not even unconstrained `UID 0` `root` processes* can open the directory unless signed by Apple with matching private `com.apple.rootless.storage.<vault>` entitlements) [31, 75].

### BrowserEngineKit, APRR JIT Isolation, and the BlastDoor Airlock

Two remote zero-click/one-click surfaces face adversarial input constantly: web browsers and `iMessage` / `FaceTime` [3, 76, 77]. Modern `WebKit` (and third-party browser engines on EU `iOS`/`iPadOS` implemented through Apple's `BrowserEngineKit` framework [76]) splits rendering across at least four strictly isolated privilege domains: the UI Process (holding user bookmarks/tabs), per-site `WebContent` extension processes (tight `Seatbelt` sandbox with *zero* direct file-system, microphone, camera, or raw network socket access), a `Networking` extension process (terminating TLS/HTTP without running JS), and a `GPU` extension process (brokering `Metal`, `WebGL`/`ANGLE`, and hardware video decode over IPC) [76, 79]. Inside `WebContent`, Just-In-Time (`JIT`) compilation uses hardware `APRR` (`pthread_jit_write_protect_np`) so JIT pages are globally mapped `R-X` while only a dedicated compiler thread momentarily flips its *core-local* `APRR` register to `RW-` (simultaneously losing execute permission on that core) to emit verified machine code [48, 76].

![Figure: Deprivileged parser containment via the stateless BlastDoor Swift service for incoming iMessage/FaceTime traffic and BrowserEngineKit's split WebContent, GPU, and Networking processes.](diagrams/07-blastdoor-webkit-containment.svg)

After Citizen Lab and Google Project Zero uncovered repeated zero-click `iMessage` chains targeting `imagent` (`2019-2020`), Apple introduced *BlastDoor* in `iOS 14` (subsequently brought to `macOS`, `watchOS`, and `visionOS`) [77]. Written predominantly in memory-safe Swift and locked inside one of the tightest `Seatbelt` profiles in the OS, `BlastDoor` sits as an untrusted-data airlock *in front of* `imagent` and `Messages.app` [1, 77]. Every incoming `APNs`/`IDS` `iMessage` payload, `NSKeyedArchiver` `BPList`, image preview, contact card, or `PassKit` bundle is routed into an ephemeral `BlastDoor` instance that denies all network sockets, denies nearly all `Mach` lookups and `IOKit` user-clients, restricts syscalls via kernel bitmasks, unpacks nested formats safely (replacing unsafe `NSKeyedUnarchiver` polymorphism with strict schema decoding), rasterizes untrusted images down into flat uncompressed pixel bitmaps in isolated workers, and hands only sanitized plain-data structs back to `imagent`; if any memory error or sandbox violation occurs, `BlastDoor` crashes and respawns cleanly without exposing user state [77].

## Platform Forks Across Apple OSes

On `iOS`, `iPadOS`, `watchOS`, and `visionOS`, *every* third-party application runs inside the `Seatbelt` App Sandbox unconditionally, and `JIT` compilation (`dynamic-codesigning` entitlement) is completely forbidden to third-party apps, except exclusively inside `WebKit` and `BrowserEngineKit`'s dedicated `WebContentExtension` sandbox in the EU [1, 76]. That absence of third-party `JIT` forces mobile attackers targeting non-browser apps to rely on pure ROP/JOP or logic/data-only primitives.

On `macOS`, applications distributed through the Mac App Store must enable `com.apple.security.app-sandbox`, whereas `Developer ID` notarized applications distributed directly from the web (`Chrome`, `Docker`, `VS Code`, CLI tools) are *not* required to enable the App Sandbox (requiring only Hardened Runtime `CS_RUNTIME`, though browsers voluntarily deploy custom `sandbox_init` child profiles) [66, 74]. That `macOS` fork (allowing un-sandboxed `Developer ID` processes to browse the filesystem except where fenced by `SIP`, Data Vaults, and `TCC`) is precisely why [Chapter 8](08-macos-tcc-sysext.md) exists.

## In-the-Wild Failures & Architectural Bounds

`BlastDoor` and `WebKit` process splitting dramatically raised zero-click exploit cost (moving chains from single-bug exploits in 2019 to four-to-six-bug full chains in 2021-2026) yet three historic campaigns reveal the exact theoretical bounds of user-mode parser sandboxing [3, 78, 79].

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `NSXPCConnection` `pid_t` Spoofing Class | 2018-2024 | `macOS` (3P privileged helpers) | `SMJobBless` root `XPC` auth | Third-party helpers checked `connection.processIdentifier` (`pid_t`) without `audit_token_t` or `TeamID` pinning | Introduced `xpc_connection_set_peer_code_signing_requirement` & `SMAppService` constraints [72, 73] |
| *FORCEDENTRY* (`CVE-2021-30860`) | 2021 | `iOS`, `macOS`, `watchOS` | `BlastDoor` image airlock (`CoreGraphics`) | Fake `.gif` attachment triggered legacy `PDF` $\to$ `JBIG2` monochrome fax decoder inside `BlastDoor`; attacker built 70,000+ boolean `AND`/`OR`/`XOR`/`XNOR` logic gates out of `JBIG2` bitmap refinement segments to create a Turing-complete virtual CPU without `JIT`! | Patched `JBIG2` bounds, moved image rasterizers into tighter sub-workers, and blocked `JBIG2`/PDF pre-rendering in `Lockdown Mode` ([Chapter 10](10-apfs-data-protection.md)) [3, 99] |
| *BLASTPASS* (`CVE-2023-41064` + `CVE-2023-41061`) | 2023 | `iOS` / `macOS` (`< 16.6.1`) | `BlastDoor` `ImageIO` & `PassKit` | Zero-click `PassKit` (`Apple Wallet` pass) attachment over `iMessage` triggered libwebp Huffman heap overflow (`CVE-2023-41064`) chained with `PassKit` validation flaw (`CVE-2023-41061`) | Patched `ImageIO`/`PassKit` and blocked zero-click Wallet/attachment paths under `Lockdown Mode` [78, 100] |
| *DarkSword* Multi-Hop Escape (`CVE-2025-14174` + `CVE-2025-43510`) | 2025-2026 | `iOS` (`18.4`-`18.7`, `< 26.3`) | `WebContent` $\to$ `GPU` $\to$ `XNU` CoW | `JavaScriptCore` DFG JIT bug (`CVE-2025-43529`) escaped `WebContent` into `GPU` process via `ANGLE` WebGL OOB (`CVE-2025-14174`), then exploited `XNU` VM copy-on-write flaw (`CVE-2025-43510`) to reach `mediaplaybackd` & `dyld` | Patched `JSC`, `ANGLE`, `XNU` VM CoW, and `dyld` (`CVE-2026-20700`); `MIE` (`EMTE`) traps heap steps on `A19`/`M5` [5, 79] |

### FORCEDENTRY's Weird Machine and Multi-Hop Broker Escapes

Google Project Zero's teardown of NSO Group's *FORCEDENTRY* (`CVE-2021-30860`) remains one of the most illuminating case studies in computer security [3]. `BlastDoor` prevented `JIT` code generation completely and enforced `PAC` on every C++ pointer. Yet `CoreGraphics` inside `BlastDoor` still dispatched `.gif`-named files by content sniffing into its legacy `PDF` parser, which supported 1990s `JBIG2` bi-level compression (a format that refines monochrome bitmap regions by combining source bitmaps using arbitrary bitwise operators (`AND`, `OR`, `XOR`, `XNOR`). Exploiting an integer overflow in `JBIG2` segment table allocation so bitmap operations could read and write out-of-bounds heap memory, the attackers wired over *70,000 bitwise bitmap blits* into full adders, comparators, and registers) constructing an unauthenticated Turing-complete computer entirely out of `JBIG2` decompression commands to locate shared-cache pointers, forge data structures, and escape `BlastDoor` over residual IPC [3]!

Similarly, *DarkSword* (`2025-2026`) shows why broker processes (`GPU` extension, `mediaplaybackd`) define modern sandbox bounds: because `WebContent` must still send `WebGL` commands to the `GPU` process (`ANGLE` `CVE-2025-14174`) and share Mach VM memory objects (`CVE-2025-43510` copy-on-write bug), containment turns single-bug RCE into a costly multi-hop obstacle course rather than an absolute mathematical wall [79].

## Verification & Forensic Artifacts

Inspect compiled or human-readable `Seatbelt` (`SBPL`) profiles on `macOS` (including `blastdoord`'s live profile) to see explicit `(deny default)` rules, syscall filters, and allowed `mach-lookup` endpoints [74, 77]:

```bash
ls -la /System/Library/Sandbox/Profiles/*blastdoor* /System/Library/Sandbox/Profiles/application.sb 2>/dev/null
head -n 20 /System/Library/Sandbox/Profiles/com.apple.BlastDoorService.sb 2>/dev/null || true
```

Audit third-party privileged `XPC` LaunchDaemons installed in `/Library/LaunchDaemons` to check their `MachServices` endpoints and verify their binaries enforce `CS_RUNTIME` and modern code signing [72, 73]:

```bash
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | grep -E 'ProgramArguments|MachServices' -A 2 | head -n 12
```

Stream real-time `Sandbox.kext` (`Seatbelt`) policy denials from Unified Logging on `macOS` to observe blocked file, `Mach` port, or `IOKit` operations without altering system state [74, 90]:

```bash
log show --last 5m --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "deny"' --style compact | tail -n 5
```

Representative output showing `Sandbox.kext` enforcing `MACF` denials:

```text
2026-11-15 10:42:11.402 Df kernel[0:1a4] (Sandbox) Sandbox: mdworker_shared(8412) deny(1) file-read-data /Users/...
```

On `iOS`, `App Sandbox` and per-app containerization isolate user documents automatically; on `macOS`, however, un-sandboxed `Developer ID` tools, scripts, and terminals run outside App Sandbox containers altogether. [Chapter 8](08-macos-tcc-sysext.md) examines how `macOS` retrofits user-consent privacy (`TCC`) and user-space `DriverKit`/`SystemExtensions` across that open desktop model.
