# The Apple Silicon Mac Fork: One True Recovery and LocalPolicy

## Overview

* **Link in the Chain:** First intentional platform fork above `Boot ROM` and `iBoot` ([Chapter 1](01-secure-boot.md)); governs how Apple Silicon Macs permit owner-authorized boot-security downgrades, third-party kernel extensions (`AuxKC`), and custom operating systems without weakening silicon boot roots.
* **Core Security Invariant:** `iBoot` relaxes `Full Security` for an `APFS` volume group if and only if it validates a `LocalPolicy` (`IM4M`) signed by this Mac's own `SEP` `Owner Identity Hardware Root` (`OIHR`) key inside paired One True Recovery (`1TR`) following physical power-button confirmation and `SEP`-verified owner authentication, bound to the current monotonic anti-replay counter.
* **Platform Matrix:** Exclusive to `macOS` on Apple Silicon (`M1` through `M5`); intentionally absent on `iOS`, `iPadOS`, `watchOS`, `visionOS`, and `Private Cloud Compute`, which hardwire `Full Security` with no user-accessible policy relaxation.
* **Trusted Computing Base (TCB):** `Boot ROM` and `iBoot`, the Power Management Unit (`PMU`) physical power-button latch, paired One True Recovery (`1TR` `recoveryOS`), `SEP` `OIHR` and `BAA` attestation keys, the monotonic `LocalPolicy` anti-replay counter, and entitled `macOS` installer paths guarding `System Integrity Protection` (`SIP`).
* **Failure Horizon & Handoff:** Does not protect a downgraded volume group against vulnerabilities inside owner-approved `AuxKC` drivers or disabled `SIP`, and runtime `SIP` on booted `macOS` remains exposed to over-entitled Apple installer daemons (`Shrootless`, `Migraine`); hands off hardware key custody and `OIHR` signing mechanics to `SEP` ([Chapter 3](03-secure-enclave.md)).

## Threat Model & Design Tension

If Apple shipped `M`-series Macs with the exact closed boot policy of an `iPhone`, `macOS` would cease to function as a self-hosting workstation platform. Kernel engineers could not boot self-compiled `XNU` builds; Linux distributions such as Asahi Linux could never run natively on bare metal [34]; legacy audio, storage, and hardware-capture workflows transitioning off `IOKit` kernel extensions (`kexts`) would break overnight; and security researchers could not selectively disable `System Integrity Protection` (`SIP`) on a scratch volume to instrument system internals.

Conversely, if Apple copied the x86 PC solution (exposing a BIOS/UEFI Setup menu where toggling `Secure Boot = Disabled` globally turns off bootloader signature verification across the entire machine, or allowing root (`UID 0`) inside the running OS to rewrite NVRAM boot variables) two critical invariants from [Chapter 1](01-secure-boot.md) would collapse [29, 30]. First, a remote root exploit inside booted `macOS` could silently disable `SIP` or `Secure Boot` across reboots, installing a persistent kernel rootkit without touching a physical button. Second, dual-booting an experimental Linux partition on an external or secondary `APFS` container would force the user to turn off `Full Security` for their primary corporate `macOS` installation as well.

Apple Silicon resolves this conflict through three architectural separations: *physical intent* (proving via hardware `PMU` state that a human physically held the power button at cold boot to enter One True Recovery), *cryptographic ownership* (requiring `SEP` to verify a volume owner's password/SecureToken before signing a `LocalPolicy` with a hardware-bound `OIHR` key), and *per-OS isolation* (scoping every `LocalPolicy` strictly to one `APFS` volume group so an experimental `Permissive Security` installation and a `Full Security` enterprise `macOS` volume coexist safely on the same internal SSD) [29, 30].

## Silicon & System Mechanics

### One True Recovery (1TR) and Physical Button Intent

On Intel Macs, `macOS` Recovery (`Command-R`) was simply an unprivileged recovery image that shared `UEFI` NVRAM state across volumes. On Apple Silicon, Apple introduced *One True Recovery* (`1TR`): a single privileged `recoveryOS` container paired cryptographically to the active System Firmware (`iBoot` and `SEP` firmware) stored on the internal storage device [26, 29]. While auxiliary recovery partitions can exist for older secondary OS installs (`fallback recoveryOS`), only `1TR` booted via a deliberate cold-boot physical gesture receives hardware authority to lower security policies [26, 30].

When a user powers off a Mac completely and presses and holds the physical Touch ID / power button for several seconds ("Loading startup options..."), the Power Management Unit (`PMU`) records a dedicated hardware latch indicating sustained physical button assertion from cold reset [26, 29]. `iBoot` reads that `PMU` state and passes an authenticated `1TR` boot measurement to `SEP` over the hardware mailbox before `XNU` starts. If an attacker with `UID 0` root privileges inside normal `macOS` sets `nvram auto-boot=false` or invokes `reboot` into recovery remotely over SSH, `recoveryOS` boots *without* the `PMU` physical-hold latch; `SEP` inspects its boot-mode state register and flatly refuses to sign any `LocalPolicy` transition that weakens security posture (`Full` $\to$ `Reduced`, disabling `SIP`, or authorizing a new `AuxKC`) [29, 30]. Raising security (`Reduced` $\to$ `Full`), by contrast, is permitted without physical ceremony because tightening invariants never benefits a remote rootkit.

### The Three Boot Security Tiers and Per-Volume Isolation

Inside `1TR`'s Startup Security Utility (or via the `bputil` command-line tool), each installed `APFS` operating-system volume group independently occupies one of three cryptographic boot modes [29, 30]:

![Figure: Apple Silicon Mac Startup Security Policy tiers (Full, Reduced, and Permissive Security) anchored in One True Recovery (1TR) and isolated per APFS volume group via SEP-signed LocalPolicy.](diagrams/02-mac-1tr-security-modes.svg)

Under `Full Security` (the factory default), the Mac behaves identically to an `iPhone` [29]. `iBoot` requires a `TSS`-personalized `Image4` manifest (`ApTicket`) binding the currently signed `BootKC` and `APFS` `SSV` seal hash to this Mac's `ECID`; superseded `macOS` builds whose `TSS` signing window has closed cannot be installed, third-party `EL1` kernel extensions are forbidden, and `SIP` and `SSV` stay strictly enforced.

Under `Reduced Security`, `iBoot` relaxes the live-`TSS` freshness constraint to accept *any* Apple-signed `BootKC` covered by a global ("universal") `Image4` signature (allowing enterprise rollbacks to older `macOS` releases) and optionally unlocks two further sub-policies if explicitly authorized by the owner in `1TR` [29, 33]: loading third-party `IOKit` kernel extensions compiled into an `Auxiliary Kernel Collection` (`AuxKC`), or booting with weakened `System Integrity Protection` (`csrutil disable`) / unsealed `SSV` (`csrutil authenticated-root disable`) for kernel debugging.

Under `Permissive Security`, `iBoot` suspends the requirement that the booted kernel carry an Apple signature altogether, allowing `iBoot` to load a custom `Mach-O` kernel image (such as a developer-compiled open-source `XNU` kernel or the Asahi Linux `m1n1` stage-1 bootloader, which subsequently chainloads U-Boot, GRUB, and an upstream ARM64 Linux kernel) [29, 32, 34]. Even in `Permissive Security`, however, `Boot ROM`, `LLB`, `iBoot`, and `SEP` firmware remain strictly Apple-signed and verified: the custom kernel runs only *after* `iBoot` verifies an explicit `LocalPolicy` signed by `SEP` authorizing that exact custom binary's `SHA-384` hash [30, 34].

### LocalPolicy Cryptography: OIHR, BAA, and Anti-Replay Chaining

How does `iBoot` verify a custom kernel or `AuxKC` when Apple's `TSS` servers obviously never signed the user's local build? Apple solves this by turning the Mac's own `Secure Enclave` into a per-machine `Image4` signing authority [30]. During factory manufacturing or activation, `SEP` generates an asymmetric signing keypair called the `Owner Identity Hardware Root` (`OIHR`, alongside the `Basic Attestation Authority` `BAA` certificate certifying `OIHR`'s hardware residency inside genuine Apple silicon) [30, 107]. The `OIHR` private key never leaves `SEP`.

Each bootable `APFS` volume group stores its active `LocalPolicy` as an `Image4` manifest (`IM4M`) inside `/System/Volumes/Preboot/<VolumeUUID>/boot/<BootHash>/usr/standalone/firmware/LocalPolicy` [30]. Inside `MANP`, the `LocalPolicy` encodes four-character `DER` tags recording the volume group UUID (`vuid`), the Boot Policy UUID (`coih` / `nsih` next-stage `Image4` hash pointing to the authorized OS `ApTicket` or custom kernel), boolean flags for `SIP` (`sip0`), `SSV` (`ssv0`), third-party `kext` authorization (`smb0`/`smb2`), the exact `SHA-384` hash of any approved `AuxKC` (`auxp`/`auxk`), the `SHA-384` hash of the *immediately preceding* `LocalPolicy` (`lpnh`), and a monotonic anti-replay counter value (`rpnh`) [30, 32].

![Figure: Owner-authorized LocalPolicy ratchet inside 1TR, binding PMU physical hold, SEP owner credential verification, OIHR hardware signing, and monotonic anti-replay counters.](diagrams/02-localpolicy-sep-signing.svg)

Updating a `LocalPolicy` executes a strict cryptographic ratchet between `1TR` and `SEP` [30]:

$$\sigma_{\text{LP}_{i+1}} = \text{Sign}_{\text{SK}_{\text{OIHR}}}\Bigl(\text{policy}_{i+1} \;\|\; H(\text{LP}_i) \;\|\; c_{i+1}\Bigr), \quad c_{i+1} = c_i + 1$$

First, `bputil` or Startup Security Utility inside `1TR` collects the local volume owner's password, unwrapping their `SecureToken`-backed `SEP` credential slot to prove administrative ownership of that specific `macOS` volume [30, 121]. Second, `SEP` verifies three hardware preconditions simultaneously: the `PMU`-derived `1TR` physical-hold boot state is active (if the requested $\text{policy}_{i+1}$ is less restrictive than $\text{LP}_i$), the caller presented a valid owner credential for `vuid`, and the supplied prior policy $\text{LP}_i$ matches `SEP`'s stored monotonic counter $c_i$. Third, `SEP` increments its hardware anti-replay counter to $c_{i+1}$, signs the new `LocalPolicy` `IM4M` with $\text{SK}_{\text{OIHR}}$, and writes it to `Preboot` [30].

> **Key idea.**
> Because `LocalPolicy` embeds both $H(\text{LP}_i)$ (`lpnh`) and `SEP`'s hardware anti-replay counter $c_{i+1}$, an attacker who previously backed up a weakened `Permissive Security` `LocalPolicy` file while testing cannot copy that old file back onto `/System/Volumes/Preboot` months later after the owner restored `Full Security`: `iBoot` queries `SEP` during boot, detects $c_{\text{old}} < c_{\text{current}}$, and halts boot immediately [30].

### Auxiliary Kernel Collections (AuxKC) and System Integrity Protection (SIP)

When an enterprise or audio engineer enables `Reduced Security` with `Allow user management of kernel extensions from identified developers`, `macOS` still never loads loose `.kext` bundles off the mutable Data volume at boot [33]. Instead, `kmutil` in booted `macOS` validates the developer's `kext` code signature and notarization ticket, prompts the administrator in System Settings (blocked against synthetic mouse clicks via secure UI input checks), links the approved `.kext` binaries together with `BootKC` symbols into a single prelinked `Auxiliary Kernel Collection` (`AuxKC`), and requests `SEP` to sign an updated `LocalPolicy` pinning `SHA-384(AuxKC)` [32, 33]. At the next reboot, `iBoot` verifies `BootKC` against Apple's universal `IM4M` and `AuxKC` against the `OIHR`-signed `LocalPolicy` digest before `XNU` starts.

Orthogonal to boot-image authentication, `System Integrity Protection` (`SIP`, introduced as *Rootless* in `OS X El Capitan` and hardware-backed via `LocalPolicy` on Apple Silicon) strips ambient authority from POSIX `UID 0` (`root`) at runtime [31]. Driven by a bitmask (`csr_active_config`, where `0x0` means all protections active and flags such as `CSR_ALLOW_UNTRUSTED_KEXTS = 0x1`, `CSR_ALLOW_UNRESTRICTED_FS = 0x2`, `CSR_ALLOW_TASK_FOR_PID = 0x4`, and `CSR_ALLOW_UNAPPROVED_KEXTS = 0x200` selectively relax checks) passed from `iBoot` via `LocalPolicy` into read-only `XNU` state, `SIP` enforces three primary boundaries via `Sandbox.kext` `MACF` hooks [10, 31]: blocking filesystem writes to `/System`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, and files bearing the `SF_RESTRICTED` flags (`chflags restricted`), blocking `task_for_pid()` / Mach debugging attachment against Apple-signed platform processes even from `root`, and protecting NVRAM security variables against user-space mutation.

## Platform Forks Across Apple OSes

Comparing `macOS` directly against `iOS`, `iPadOS`, `watchOS`, `visionOS`, and `PCC` highlights why `LocalPolicy` is the keystone of Apple's platform differentiation [1, 29, 30]. On mobile, wearable, spatial, and `PCC` platforms, there is no `1TR` Startup Security Utility, no `OIHR`-signed `Reduced` or `Permissive` tier, no `AuxKC`, and no `csrutil`: `SIP`-equivalent filesystem and `task_for_pid()` restrictions are permanently compiled into `XNU` and `AMFI`/`TXM` with zero runtime bitmask overrides (outside factory-fused Apple Security Research Devices `[18]`).

Even on Apple Silicon Macs, enterprise fleets can lock the `1TR` fork shut when required. When a Mac is enrolled via `Automated Device Enrollment` (`ADE`) in `Apple Business Manager` ([Chapter 14](14-ddm-platform-sso.md)), an MDM server can set a Recovery Lock password inside `SEP` (`SetRecoveryLock` command) [29, 119]. Once Recovery Lock is active, holding the physical power button at cold boot stops before entering `1TR` and demands the enterprise-escrowed Recovery Lock secret, preventing even a local `macOS` administrator who knows their login password from booting `1TR`, disabling `SIP`, or installing Asahi Linux / `AuxKC` rootkits.

## In-the-Wild Failures & Architectural Bounds

While no public exploit has forged an `OIHR` signature or bypassed the `PMU` physical button-hold requirement to downgrade `LocalPolicy` remotely, booted `macOS` exposes an unavoidable architectural surface inside `SIP`: Apple's own OS updaters and migration assistants must modify `SIP`-protected Data-volume directories (`/Library/Apple`, `/private/var/db/ConfigurationProfiles`, TCC stores) during live updates without rebooting into `1TR`, accomplished via private `com.apple.rootless.install*` entitlements [31, 35, 36].

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Shrootless` (`CVE-2021-30892`) | 2021 | `macOS` | `SIP` filesystem restriction (`SF_RESTRICTED`) | `system_installd` (`com.apple.rootless.install.heritable`) ran package postinstall scripts via `zsh`, which automatically sourced attacker-writable `/etc/zshenv` with inherited `SIP`-bypass privilege | Stripped `zsh` environment startup sourcing and restricted heritable `rootless` child spawns [35] |
| Entitled Installer Symlink / Bundle Hijacks | 2022-2023 | `macOS` | `SIP` installer daemons | Over 30 Apple-signed tools held `rootless.install` entitlements without strict path/library validation or `TOCTOU`-safe file extraction | Added `Launch Constraints` ([Chapter 6](06-amfi-txm-notarization.md)) and hardened runtime flags across system helpers [36, 65] |
| `Migraine` (`CVE-2023-28206`) | 2023 | `macOS` | `SIP` & `TCC.db` integrity | `Setup Assistant` / `systemmigrationd` (`com.apple.rootless.install.heritable`) could be automated via `MigrationTool` flags from an attacker disk image to overwrite `SIP`-protected `/Library/Application Support/com.apple.TCC/TCC.db` | Restricted `systemmigrationd` invocation context and enforced Launch Constraints [35, 65] |
| `Permissive Security` Multi-Boot Exposure | Architectural | `macOS` (Apple Silicon) | Cross-OS NVMe Data Confidentiality | A custom unsigned OS booted in `Permissive Security` has raw NVMe block access; it cannot forge `Full Security` `SSV` seals on sibling volumes, nor unwrap `FileVault` `SEP` keys, *unless* the sibling macOS volume left `FileVault` disabled | Enable `FileVault` (`XTS-AES` `SEP`-sealed volume encryption) on every `Full Security` volume sharing the SSD [29, 30, 94] |

### Why Rootless Exceptions Remain SIP's Weakest Link

`Shrootless` (`CVE-2021-30892`) and `Migraine` (`CVE-2023-28206`), both discovered by Jonathan Bar Or and Microsoft Threat Intelligence, illustrate the sharp contrast between immutable `SSV` read-only snapshots (`/System` mounted read-only at the block/VFS layer, [Chapter 5](05-apfs-ssv-dyld.md)) and mutable Data-volume `SIP` paths (`/Library/Application Support/com.apple.TCC`, `/Library/Apple/System/Library`) [35, 56]. Because the `SSV` root snapshot has no writable B-tree mounted at runtime, not even `com.apple.rootless.install.heritable` can modify `/System/Library/Kernels`. Mutable `SIP`-protected paths on `/System/Volumes/Data`, however, rely on `Sandbox.kext` exempting any process carrying `com.apple.rootless.install.heritable` (which propagates across `fork()`/`execve()` to child scripts!). Whenever a root attacker tricked `system_installd` or `systemmigrationd` into executing arbitrary shell commands under that heritable entitlement, `SIP` stepped aside, allowing direct SQLite overwrites of system `TCC.db` and `EndpointSecurity` configurations without ever touching `1TR` or `LocalPolicy` [35, 36].

## Verification & Forensic Artifacts

Query `bputil -d` and `csrutil status` on an Apple Silicon Mac (usable read-only without entering `1TR`) to audit the booted volume group's `LocalPolicy` security mode, `SIP` bitmask, `SSV` authenticated-root enforcement, and `AuxKC` authorization [30, 31, 32]:

```bash
bputil -d
csrutil status
csrutil authenticated-root status
```

Expected output on a hardened `Full Security` enterprise or personal workstation:

```text
Boot Policy:
    Security Mode                 : Full (1)
    One True RecoveryOS           : 26.3
    SIP                           : Enabled
    Signed System Volume          : Enabled
    Kernel CTRR                   : Enabled
    Boot Args Filtering           : Enabled
    Allow 3rd Party Kexts         : Disabled
System Integrity Protection status: enabled.
Authenticated Root status: enabled
```

Verify whether any third-party `IOKit` kernel extensions have been linked into an `Auxiliary Kernel Collection` (`AuxKC`) on disk using `kmutil` [32, 33]:

```bash
kmutil inspect --collection-type auxiliary --no-header 2>/dev/null | head -n 5
```

On a system running pure `Full Security` (or `DriverKit`/`SystemExtensions` only), no `AuxKC` is loaded and `kmutil` reports no active auxiliary third-party kexts.

Enumerate which installed system binaries hold dangerous `com.apple.rootless.install*` entitlements when auditing patch levels for `SIP`-bypass surfaces [35, 36]:

```bash
codesign -d --entitlements :- /System/Library/PrivateFrameworks/PackageKit.framework/Resources/system_installd 2>/dev/null | grep -A 2 'rootless'
```

Representative output showing the scoped installer entitlement:

```text
	<key>com.apple.rootless.install.heritable</key>
	<true/>
```

Every cryptographic guarantee in `LocalPolicy` (from `OIHR` hardware signatures to monotonic anti-replay counters and volume-owner password verification) depends on an enclave that even `XNU` at `EL1` cannot read or subvert. [Chapter 3](03-secure-enclave.md) opens that silicon black box: the `Secure Enclave Processor` (`SEP`), its fused `UID`/`GID` keys, and the biometric pipelines that unlock them.
