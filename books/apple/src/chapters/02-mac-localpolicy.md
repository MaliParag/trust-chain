# The Apple Silicon Mac Fork: One True Recovery and LocalPolicy

## Overview

* **Link in the Chain:** First intentional platform fork above `Boot ROM` and `LLB` ([Chapter 1](01-secure-boot.md)); governs how Apple Silicon Macs permit owner-authorized boot-security downgrades, third-party kernel extensions (`AuxKC`), and custom operating systems (`CustomOS`) without weakening silicon boot roots.
* **Core Security Invariant:** `LLB` and `iBoot` relax `Full Security` for an `APFS` volume group if and only if they validate a `LocalPolicy` (`IM4M`) signed by this Mac's `SEP` `Owner Identity Hardware Root` (`OIHR`) key inside paired One True Recovery (`1TR`) following a hardware `PMU`/`SMC` power-button hold latch and `SEP`-verified owner `SecureToken` authentication, bound to the active `lpnh` anti-replay nonce in `SEP` secure storage.
* **Platform Matrix:** Exclusive to `macOS` on Apple Silicon (`M1` through `M5`); intentionally absent on `iOS`, `iPadOS`, `watchOS`, `visionOS`, and `Private Cloud Compute`, which hardwire `Full Security` with zero user-accessible policy relaxation.
* **Trusted Computing Base (TCB):** `Boot ROM`, `LLB`, and `iBoot`, the `SMC`/`PMU` cold-boot power-button latch, paired One True Recovery (`1TR` `recoveryOS`) and `Bootability.framework`, `SEP` `OIHR` and `BAA` attestation keys, `xART` `LocalPolicy` nonces (`LPN`, `RPN`, `SPN`), and entitled `macOS` daemons guarding `System Integrity Protection` (`SIP`).
* **Failure Horizon & Handoff:** Does not protect a downgraded volume group against bugs inside owner-approved `AuxKC` kexts or disabled `CTRR`/`SIP`, while runtime `SIP` on mutable Data-volume paths remains exposed to over-entitled installer and storage daemons (`Shrootless`, `Migraine`, `CVE-2023-42860`, `CVE-2024-44243`); hands off hardware key custody and `xART` mechanics to `SEP` ([Chapter 3](03-secure-enclave.md)).

## Threat Model & Design Tension

If Apple shipped `M`-series Macs with the identical closed boot policy of an `iPhone`, `macOS` would cease to function as a general-purpose, self-hosting workstation operating system. Kernel engineers could not boot self-compiled `XNU` kernels from Apple's open-source releases; upstream ARM64 Linux distributions such as Asahi Linux could never execute natively on bare metal [9, 115]; enterprise storage, broadcast audio, and hardware-capture workflows still migrating off `IOKit` kernel extensions (`kexts`) would fail outright; and security researchers could not disable `System Integrity Protection` (`SIP`) or `Configurable Text Read-only Region` (`CTRR`) locks on a scratch partition to trace kernel internals with `DTrace` [114].

Conversely, if Apple copied the x86 PC model by exposing a global `UEFI` Setup menu where toggling `Secure Boot = Disabled` turns off signature verification across the entire machine, or allowing POSIX `root` (`UID 0`) inside the booted OS to rewrite NVRAM security flags (`csr-active-config`), two foundational guarantees from [Chapter 1](01-secure-boot.md) would collapse immediately [7, 8]. First, a remote root exploit inside booted `macOS` could silently disable `SIP` or `Secure Boot` across a warm reboot, planting a persistent `EL1` kernel rootkit without touching physical hardware. Second, installing an experimental Linux build or beta `macOS` release onto a secondary `APFS` container or external Thunderbolt SSD would force the owner to disable `Full Security` globally, stripping rollback and kernel-integrity protections from their primary corporate `macOS` volume on the internal SSD.

Apple Silicon resolves this tension through three orthogonal separations: *physical presence* (proving via a hardware `PMU`/`SMC` latch that a human physically held the power button from cold off to enter One True Recovery), *cryptographic volume ownership* (requiring `SEP` to verify a local administrator's `SecureToken`-backed credential before signing a `LocalPolicy` with the chip's `OIHR` key), and *per-volume-group scoping* (binding every `LocalPolicy` strictly to one `APFS` Volume Group UUID so a `Permissive Security` Linux installation and a `Full Security` enterprise `macOS` installation coexist safely on the same NVMe drive) [7, 8, 116].

## Silicon & System Mechanics

### One True Recovery (1TR), Paired recoveryOS, and the PMU/SMC Physical Latch

On legacy Intel Macs, `macOS` Recovery (`Command-R`) was merely an auxiliary boot partition sharing global `UEFI` NVRAM state across every installed operating system. On Apple Silicon, Apple introduced a three-tier recovery hierarchy centered on *One True Recovery* (`1TR`), managed through `Bootability.framework` and `bputil(1)` [7, 114, 117, 118]. Beginning with `macOS 12 Monterey`, every installed `macOS` `APFS` Volume Group carries its own *paired `recoveryOS`* matching that OS build's exact version (whereas `macOS 11 Big Sur` relied on a shared *System `recoveryOS`* container, and secondary emergency boots use *Fallback `recoveryOS`*) [114, 117]. Critically, `SEP`'s `BootPolicy` application enforces strict version-pairing invariants: holding the power button boots the `recoveryOS` paired to the default boot volume, and a paired `recoveryOS` can downgrade security settings *only* for its own paired `macOS` Volume Group, preventing an attacker from booting an older, unpatched `macOS 11` recovery image to weaken a `macOS Tahoe` volume [114, 117].

Physical user intent is anchored in dedicated power-controller silicon rather than keyboard scan codes [7, 114, 119]. When a user powers down an Apple Silicon Mac completely and presses and holds the physical Touch ID / power button for several seconds (`"Loading startup options..."`), the Power Management Unit (`PMU`) and System Management Controller (`SMC`, `drivers/mfd/macsmc.c`) assert a dedicated hardware long-press boot latch from cold reset [7, 119]. `LLB` and `iBoot` sample that hardware latch before starting any mutable kernel and forward an authenticated boot-mode measurement (`1TR` vs. normal OS vs. software-triggered recovery) to `SEP` over the hardware mailbox, after which the boot-mode register locks until the next cold power-off [7, 8, 114].

If a remote attacker holding `UID 0` root privileges inside normal `macOS` sets `nvram auto-boot=false` or triggers a software reboot into `recoveryOS` over SSH, the machine enters *software-launched `recoveryOS`* without the `PMU` cold-hold latch [114]. As documented in `bputil(1)`, `SEP` inspects the `AP` boot-environment state and enforces an asymmetric ratchet: software-launched `recoveryOS` (or even normal `macOS` for `-f`) may *tighten* security back to `Full Security` (`bputil -f`) or clean up orphaned policies (`bputil -r`/`-z`), because raising security never aids an attacker, whereas security-weakening operations (`--permissive-security` `-n`, `--enable-kexts` `-k`, `--disable-kernel-ctrr` `-c`, `--disable-boot-args-restriction` `-a`, `--disable-ssv` `-s`, `--enable-mdm` `-m`, and `csrutil disable`) unconditionally require `1TR` *and* valid paired `recoveryOS` status [8, 114].

### The Three Boot Security Tiers and Per-Volume Isolation

Within `1TR`'s Startup Security Utility or `bputil`, each bootable `APFS` Volume Group (`vuid`) independently occupies one of three cryptographic boot modes [7, 8, 114]:

![Figure: Apple Silicon Mac Startup Security Policy tiers (Full, Reduced, and Permissive Security) anchored in One True Recovery (1TR) and isolated per APFS volume group via SEP-signed LocalPolicy.](diagrams/02-mac-1tr-security-modes.svg)

Under `Full Security` (the factory default), the Mac enforces the exact `iPhone` boot model [7, 114]. `LLB` and `iBoot` demand a `TSS`-personalized `Image4` manifest (`ApTicket`) binding the active `BootKC` and `APFS` `SSV` seal hash to this Mac's `ECID`; superseded `macOS` releases whose `TSS` signing window has closed cannot be newly installed, third-party `EL1` `kexts` are rejected, `CTRR` and boot-arg filtering stay locked, and `SIP` plus `SSV` remain unconditionally active (`bputil -f` even performs an online `TSS` currency check before re-enabling `Full Security` on a previously downgraded volume) [7, 114].

Under `Reduced Security` (`bputil -g`), `LLB` and `iBoot` relax the per-`ECID` live-`TSS` freshness requirement and accept Apple's *global* ("universal") `Image4` signature attached to any official `macOS` release supported by that hardware model, enabling enterprise version pinning or rollbacks while still requiring every kernel byte to be signed by Apple [7, 114]. Only if explicitly opted in from paired `1TR` can `Reduced Security` unlock two additional capabilities: linking notarized third-party `IOKit` drivers into an `Auxiliary Kernel Collection` (`AuxKC`, `bputil -k`) or delegating update/kext approval to an enrolled Mobile Device Management server (`bputil -m`) [114, 120].

Under `Permissive Security` (`bputil -n`, selectable only via CLI tools `bputil`, `csrutil`, or `kmutil configure-boot` inside paired `1TR`), `iBoot` lifts the requirement that the Stage-3 kernel carry an Apple signature, allowing `iBoot` to transfer `EL1`/`EL2` execution to an arbitrary owner-enrolled `Mach-O` binary such as a self-compiled `XNU` research kernel or the Asahi Linux `m1n1` stage-1 hardware proxy/bootloader (which subsequently chainloads U-Boot, `GRUB`, and an upstream ARM64 Linux kernel) [7, 9, 114, 115]. Provisioning such a custom OS exercises Apple's `Bootability.framework` workflow without ever inventing a fake Apple certificate: `asahi-installer` creates a dedicated stub `APFS` volume group paired with its own `recoveryOS`, boots into that volume's paired `1TR` via the `PMU` physical power-button hold, and invokes `kmutil configure-boot -c m1n1.macho -v /Volumes/...` [9, 115, 121]. `Bootability.framework` wraps the raw `m1n1` `Mach-O` inside an `IM4P` (`krnl` / `coih` object), authenticates the administrator's `SecureToken` password against `SEP`, sets `smb0 = true` and `smb1 = true`, signs both the custom payload ticket and the volume group's `LocalPolicy` (`coih`) using the Mac's own `OIHR` private key, and leaves `iBoot` handoff running at `EL2` (when configured for hypervisor/Linux boot) so Linux owns native `Virtualization` and `AppleDART` initialization for that boot session [9, 115, 116]. Even under `Permissive Security`, however, `Boot ROM`, `LLB`, `iBoot`, and `SEP` firmware remain 100% Apple-signed: `m1n1` runs only after `iBoot` validates the `OIHR`-signed `LocalPolicy` pinning that exact binary's `SHA-384` digest (`coih`), and rebooting back into the primary `macOS` volume group immediately re-engages `Full Security`, `CTRR`, `SPTM`, and `SSV` with zero residual state [8, 9, 116].

### LocalPolicy Image4 Schema: OIHR, BAA, 4CC Tags, and xART Nonces

How do `LLB` and `iBoot` cryptographically verify a user-configured `AuxKC` or custom Linux bootloader that Apple's `TSS` servers never saw? Apple turns each Mac's own `Secure Enclave Processor` into a hardware-attested local `Image4` Certificate Authority [8, 122]. During factory provisioning (or enclave initialization), `SEP` generates a non-exportable asymmetric signing keypair inside `SKS` named the `Owner Identity Hardware Root` (`OIHR`), certified by a device-unique `Basic Attestation Authority` (`BAA`) X.509 certificate chain anchored to Apple's manufacturing PKI [8, 122].

For every bootable `APFS` Volume Group, `BootPolicy` stores the signed `LocalPolicy` as an `Image4` `IM4M` file at `/System/Volumes/Preboot/<VolumeGroupUUID>/boot/<BootHash>/usr/standalone/firmware/LocalPolicy` [8, 116, 118]. As documented in Apple's *Contents of a LocalPolicy file for a Mac with Apple silicon* (`secc745a0845`), the `MANP` body of `LocalPolicy` combines standard silicon identity tags (`ECID`, `CHIP`, `BORD`, `CEPO`, `SDOM`) with four specialized families of four-character codes (`4CC`s) [116]:

![Figure: Apple Silicon Mac LocalPolicy Image4 4CC schema binding anti-replay xART nonces (lpnh, rpnh, spnh), boot manifest hashes (nsih, coih), security mode bits (smb0-smb4), CSR flags (sip0-sip3), and AuxKC digests (auxp, auxi/aukh, auxr).](diagrams/02-extra-localpolicy-hash-chain.svg)

First, *anti-replay nonce hashes* (`lpnh`, `rpnh`, and `spnh`) defeat file-level policy rollback [116]. Rather than trusting a plaintext counter on the mutable `Preboot` partition, `SEP` generates a secret random `LocalPolicy Nonce` (`LPN`) stored exclusively inside `SEP`'s hardware-paired Secure Storage Component (`xART`), never exposing raw `LPN` bytes to the `AP`, and embeds only $\texttt{lpnh} = \text{SHA-384}(\text{LPN})$ inside `LocalPolicy` (paired with $\texttt{rpnh} = \text{SHA-384}(\text{RPN})$ for the paired `recoveryOS` policy and $\texttt{spnh} = \text{SHA-384}(\text{SPN})$ for System `recoveryOS`) [8, 116]. Keeping `spnh` distinct from `lpnh`/`rpnh` enables an elegant remote-lock invariant: if an owner triggers a `Find My` remote lock, `SEP` deletes `LPN` and `RPN` from Secure Storage, instantly rendering all installed OS volumes unbootable at `LLB` while preserving `SPN` so System `recoveryOS` can still boot to display recovery/lock instructions [116]!

Second, *boot-object manifest hashes* (`vuid`, `nsih`, and `coih`) bind the policy to exact executable code [116]. `nsih` (*Next Stage Image4 Hash*) stores the `SHA-384` digest of the target `macOS` `Image4` manifest (`ApTicket` covering `iBoot`, static trust cache, `DeviceTree`, `BootKC`, and the `APFS` `SSV` root hash), checked by `LLB` before launching `iBoot` [116]. When a user configures a third-party kernel via `kmutil configure-boot` in `1TR` (as `asahi-installer` invokes via `Bootability.framework`), `LocalPolicy` populates `coih` (*CustomOS Image4 Hash*), instructing `iBoot` to load and verify that `SEP`-signed custom `Mach-O` payload instead of `XNU` [9, 115, 116].

Third, *Security Mode Bits* (`smb0`–`smb4`) and *SIP/Hardware Flags* (`sip0`–`sip3`) encode explicit capability relaxations [114, 116]. Presence of `smb0 = true` enables `Reduced Security` (global signatures) and serves as a mandatory structural prerequisite in `SEP` before `smb1` (`Permissive Security` allowing `OIHR`-signed custom kernels) or `smb2` (user-authorized third-party `kexts`) can be set; `smb3 = true` records owner opt-in allowing MDM authentication to manage updates and kexts (`smb4` tracks account/MDM reduced-security policy state) [114, 116]. Meanwhile, `sip0` holds the 32-bit `csr_config_t` `SIP` bitmask consumed only by `macOS`, whereas `sip1`, `sip2`, and `sip3` govern early `iBoot` hardware locks directly: `sip1 = true` (`bputil -s`) permits `SSV` seal-hash failures (disallowed if `FileVault` is enabled), `sip2 = true` (`bputil -c`) instructs `iBoot` *not* to lock the `CTRR` read-only kernel text register, and `sip3 = true` (`bputil -a`) disables NVRAM `boot-args` filtering [114, 116].

Fourth, *Auxiliary Kernel Collection (`AuxKC`) tags* (`auxp`, `auxi`/`aukh`, and `auxr`) prevent kext tampering or cross-OS splicing [116, 120]. Approving a third-party developer kext in System Settings updates the User-Authorized Kext List (`UAKL`) and records $\texttt{auxp} = \text{SHA-384}(\text{UAKL})$ (requiring `smb2 = true`) [116]. When `kernelmanagerd` and `kmutil` link the `AuxKC`, `SEP` verifies the active `UAKL` against `auxp`, signs the `AuxKC` `Image4` manifest, embeds the `SHA-384` hash of that `AuxKC` manifest signature (`auxi` / `aukh`) into `LocalPolicy` so an older vulnerable signed `AuxKC` cannot be mixed onto a newer OS, and records $\texttt{auxr} = \text{SHA-384}(\text{Receipt})$ documenting the exact subset of kexts linked after excluding revoked drivers on Apple's `KextExcludeList` [116, 120, 121].

![Figure: Owner-authorized LocalPolicy ratchet inside 1TR, binding PMU physical hold, SEP owner credential verification, OIHR hardware signing, and monotonic anti-replay nonces.](diagrams/02-localpolicy-sep-signing.svg)

Every `LocalPolicy` mutation executes an atomic ratchet inside `SEP` [8, 116]:

$$\text{LPN}_{i+1} \xleftarrow{\$}\{0,1\}^{256}, \qquad \sigma_{\text{LP}_{i+1}} = \text{Sign}_{\text{SK}_{\text{OIHR}}}\Bigl(\text{MANP}_{i+1}\bigl[\texttt{lpnh} := \text{SHA-384}(\text{LPN}_{i+1})\bigr]\Bigr)$$

First, `BootPolicy` collects an administrator's password (or recovery key / MDM token when `smb3` applies) and unwraps their `SecureToken`-backed `SEP` slot for `vuid` [8, 114, 123]. Second, `SEP` checks that `AP` boot state satisfies `1TR` + paired `recoveryOS` if $\text{MANP}_{i+1}$ weakens any flag relative to the currently active policy verified against $\text{LPN}_i$. Third, `SEP` overwrites $\text{LPN}_i \leftarrow \text{LPN}_{i+1}$ inside `xART` Secure Storage and signs the new `IM4M` with $\text{SK}_{\text{OIHR}}$ [8, 116].

> **Key idea.**
> Because raw $\text{LPN}_{i+1}$ lives exclusively inside `SEP`'s `xART` Secure Storage while `LocalPolicy` on `Preboot` carries only $\texttt{lpnh} = \text{SHA-384}(\text{LPN}_{i+1})$, an attacker who backed up a `Permissive Security` `LocalPolicy` file during developer testing cannot copy that file back onto `/System/Volumes/Preboot` after `Full Security` is restored: `LLB`/`iBoot` queries `SEP`, observes $\text{SHA-384}(\text{LPN}_{\text{current}}) \neq \texttt{lpnh}_{\text{old}}$, and halts boot immediately [8, 116].

### BootKC, AuxKC, and System Integrity Protection (bsd/sys/csr.h)

Even when `smb2` is enabled under `Reduced Security`, `macOS` never loads loose `.kext` files dynamically from `/Library/Extensions` into a running kernel [120, 121]. Instead, `kmutil(8)` and `kernelmanagerd(8)` enforce a static prelinked `MH_FILESET` collection architecture: all first-party Apple kernel extensions reside inside the immutable `Boot Kernel Collection` (`BootKC`) on `Preboot` (Apple Silicon omits Intel's separate `SystemKC`), while approved third-party kexts are staged into a `SIP`-protected repository, validated for notarization and `KextExcludeList` absence, linked against `BootKC` symbol tables into a single `Auxiliary Kernel Collection` (`AuxKC`), wrapped in `IM4P`, and pinned into `LocalPolicy` (`auxp`/`auxi`/`auxr`) for `iBoot` to map *before* `CTRR` locks kernel read-only memory on the next reboot (`arm_auxkc_init()`, which also disables `XNU_KERNEL_RESTRICTED` `pmap` tightenings when third-party `EL1` code is present) [116, 120, 121].

At runtime inside booted `macOS`, `System Integrity Protection` (`SIP`, internally *Rootless*) strips ambient kernel-modification and system-tampering authority from POSIX `UID 0` (`root`) [124, 125]. Initialized in `bsd/kern/kern_csr.c` from `LocalPolicy.sip0` (where `0x0` enforces all protections), `SIP` is governed by the `csr_config_t` flags in `bsd/sys/csr.h` [125, 126]:

```c
/* Exact bitmask definitions from xnu/bsd/sys/csr.h */
#define CSR_ALLOW_UNTRUSTED_KEXTS            (1 << 0)  /* 0x0001 */
#define CSR_ALLOW_UNRESTRICTED_FS            (1 << 1)  /* 0x0002 */
#define CSR_ALLOW_TASK_FOR_PID               (1 << 2)  /* 0x0004 */
#define CSR_ALLOW_KERNEL_DEBUGGER            (1 << 3)  /* 0x0008 */
#define CSR_ALLOW_APPLE_INTERNAL             (1 << 4)  /* 0x0010 */
#define CSR_ALLOW_UNRESTRICTED_DTRACE        (1 << 5)  /* 0x0020 */
#define CSR_ALLOW_UNRESTRICTED_NVRAM         (1 << 6)  /* 0x0040 */
#define CSR_ALLOW_DEVICE_CONFIGURATION       (1 << 7)  /* 0x0080 */
#define CSR_ALLOW_ANY_RECOVERY_OS            (1 << 8)  /* 0x0100 */
#define CSR_ALLOW_UNAPPROVED_KEXTS           (1 << 9)  /* 0x0200 */
#define CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE (1 << 10) /* 0x0400 */
#define CSR_ALLOW_UNAUTHENTICATED_ROOT       (1 << 11) /* 0x0800 (SSV off) */
#define CSR_ALLOW_RESEARCH_GUESTS            (1 << 12) /* 0x1000 */
```

Running `csrutil disable` in `1TR` sets `CSR_DISABLE_FLAGS` (`0x7f`, bits `0` through `6`), whereas `CSR_ALWAYS_ENFORCED_FLAGS` (`0x180`) remain enforced unconditionally [126]. When `csr_check(mask)` returns `EPERM` (default `sip0 = 0`), `Sandbox.kext` `MACF` hooks block `UID 0` writes to paths listed in `/System/Library/Sandbox/rootless.conf` and inodes stamped with `SF_RESTRICTED` (`0x00080000`), deny `task_for_pid()` / `mach_vm_write()` against platform binaries, filter NVRAM writes, and block unapproved kexts [124, 126, 127].

## Platform Forks Across Apple OSes

Comparing `macOS` against `iOS`, `iPadOS`, `watchOS`, `visionOS`, and `PCC` clarifies why `1TR` and `LocalPolicy` form the architectural fulcrum of Apple's ecosystem [7, 8]. Mobile, wearable, spatial, and cloud-blade operating systems ship *zero* `1TR` Startup Security Utility, zero `OIHR`-signed `smb0`/`smb1` modes, zero `AuxKC` third-party kext loader, and zero `csrutil` overrides: `SIP`-equivalent filesystem, NVRAM, and `task_for_pid()` restrictions are permanently compiled into `XNU`, `Sandbox.kext`, and `TXM` (except on factory-fused Security Research Devices) [8, 124].

Even on Apple Silicon Macs, enterprise fleets can lock the `1TR` escape hatch shut or delegate tightly bounded policy control to Mobile Device Management [7, 116, 128]. When an organization supervises a Mac via Automated Device Enrollment (`ADE`, [Chapter 14](14-ddm-platform-sso.md)), MDM can issue `SetRecoveryLock` to program an escrow-backed `Recovery Lock` secret inside `SEP` [7, 128]. With `Recovery Lock` active, holding the physical power button at cold boot halts *before* `1TR` launches and demands the MDM-escrowed password, blocking a local `macOS` administrator (even one holding a valid `SecureToken`) from entering `1TR`, disabling `SIP`, or booting Asahi Linux / `Permissive Security` kernels [128]. Conversely, when an enterprise still requires a notarized third-party security or storage `kext` (`AuxKC`) across thousands of deployed laptops without dispatching technicians to hold power buttons on desks, an administrator can opt a volume into MDM control (`bputil -m`, setting `smb0 = true` and `smb3 = true`) once during staging; thereafter, `SEP`'s `BootPolicy` service accepts cryptographic MDM authentication (paired with an escrowed `Bootstrap Token` in `SEP` [123]) to authorize `UAKL` (`auxp`) updates and unattended OS patches without weakening `SIP` (`sip0 = 0`), `SSV` (`sip1` absent), or `CTRR` (`sip2` absent) [114, 116, 123].

## In-the-Wild Failures & Architectural Bounds

No public exploit has forged a `SEP` `OIHR` signature, replayed an invalidated `lpnh` nonce past `xART`, or spoofed the `PMU` cold-boot button latch remotely. Instead, real-world `macOS` compromises repeatedly bypass runtime `SIP` from `UID 0` by abusing over-entitled Apple updaters, migration tools, and disk utilities that hold `com.apple.rootless.install` or `com.apple.rootless.install.heritable` (`CS_INSTALLER` / `CS_EXEC_INHERIT_SIP`) to service mutable `SIP`-protected directories on `/System/Volumes/Data` [127, 129, 130, 131, 132].

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| `Shrootless` (`CVE-2021-30892`, Bar Or) | 2021 | `macOS` (`< 11.6.1`, `< 12.0.1`) | `SIP` `SF_RESTRICTED` filesystem guard | `system_installd` (`rootless.install.heritable`) ran `.pkg` postinstall scripts via `zsh`, which automatically sourced root-writable `/etc/zshenv` with inherited `SIP` bypass | Stripped `/etc/zshenv` sourcing and constrained child script inheritance (`HT212869`) [129, 133] |
| `installer` / `OSDUIHelper` Hijacks (`CVE-2022-32899`, `CVE-2023-23533`) | 2022-2023 | `macOS` (`12`-`13`) | `SIP` installer file writes | Entitled Apple installer helpers followed attacker symlinks or mounted bundle paths without strict `TOCTOU` path validation | Hardened path descriptors (`O_NOFOLLOW`) and added `Launch Constraints` [127, 130, 134] |
| `rootless.install` Daemon Sprawl (Fitzl) | 2022-2023 | `macOS` (`12`-`14`) | `CS_INSTALLER` (`0x08`) TCB width | Over 30 Apple binaries carried `com.apple.rootless.install*` entitlements, creating broad `GTFOBins`-class living-off-the-land primitives | Pruned entitlements and bound helpers via `Launch Constraints` ([Chapter 6](06-amfi-txm-notarization.md)) [127, 130] |
| `Migraine` (`CVE-2023-32369`, Bar Or) | 2023 | `macOS` (`< 13.4`) | `SIP` & system `TCC.db` integrity | Automated `Setup Assistant` / `systemmigrationd` (`rootless.install.heritable`) processed crafted requests in `/Library/SystemMigration/Queue` to execute `bash`/`perl` before `CS_OPS_CLEARINSTALLER` | Restricted `systemmigrationd` invocation state in `macOS 13.4` (`HT213758`) [131, 135] |
| `PackageKit` Postinstall Bypass (`CVE-2023-42860`) | 2023 | `macOS` (`< 14.1`, `< 13.6.1`) | `SIP` protected filesystem paths | Permissions validation flaw in `PackageKit` execution context allowed malicious apps/scripts to modify `SIP`-protected Data-volume locations | Tightened filesystem permission checks in `macOS Sonoma 14.1` (`HT213984`) [136] |
| `StorageKit` Kext/SIP Bypass (`CVE-2024-44243`, Bar Or) | 2024-2025 | `macOS` (`< 15.2`) | `SIP` & `KextExcludeList` enforcement | Root attacker dropped custom filesystem bundle into `/Library/Filesystems` and triggered Disk Utility repair/erase so `storagekitd` (`rootless.install.heritable`) spawned attacker binaries with full `SIP` bypass | Blocked untrusted `/Library/Filesystems` inheritance in `macOS Sequoia 15.2` [132, 137] |
| `Permissive Security` Unencrypted Sibling Volume | Architectural | `macOS` (Apple Silicon) | Cross-OS NVMe confidentiality | Custom kernel in `Permissive Security` owns raw NVMe block I/O; it cannot forge sibling `SSV` seals or unwrap `SEP` `FileVault` keys, *unless* the sibling volume left `FileVault` off | Enforce `FileVault` (`SEP`-bound `XTS-AES`) on all `Full Security` volumes [7, 8, 116] |

### Shrootless, Migraine (CVE-2023-32369), and StorageKit (CVE-2024-44243)

Comparing immutable `SSV` system paths (`/System/Library`, [Chapter 5](05-apfs-ssv-dyld.md)) against mutable `SIP`-protected paths on `/System/Volumes/Data` (`/Library/Application Support/com.apple.TCC/TCC.db`, `/Library/Apple/System/Library/CoreServices/MRT.app`, `KextExcludeList` bundles, `/Library/SystemMigration`) exposes `SIP`'s permanent Achilles' heel on `macOS` [124, 127, 131, 132]. Because `/` is mounted from a cryptographically sealed read-only `APFS` snapshot, not even `CS_INSTALLER` can write `/sbin/launchd` at runtime. Mutable `SIP` directories on `Data`, however, *must* be updated live by `macOS` installers, migration assistants, and storage daemons without forcing `1TR` reboots. `XNU` implements this exception via two process code-signing flags: `CS_INSTALLER` (`0x00000008`, granted by `com.apple.rootless.install`) and `CS_EXEC_INHERIT_SIP` (granted by `com.apple.rootless.install.heritable`, which propagates across `fork()` and `execve()` to child binaries until explicitly dropped via `csops(..., CS_OPS_CLEARINSTALLER = 12, ...)`!) [127, 131].

Across four years of disclosures by Jonathan Bar Or (Microsoft Threat Intelligence), Csaba Fitzl, and Mickey Jin, attackers repeatedly weaponized `com.apple.rootless.install.heritable` from `UID 0` [129, 130, 131, 132, 134, 136]. In `Shrootless` (`CVE-2021-30892`), `system_installd` invoked `.pkg` postinstall scripts under `zsh` before clearing `CS_EXEC_INHERIT_SIP`, causing `zsh` to execute attacker commands planted in `/etc/zshenv` with unrestricted `SIP` write power [129, 133]. In `Migraine` (`CVE-2023-32369`), automating `Setup Assistant` with a mounted Time Machine backup disk image caused `systemmigrationd` (`com.apple.rootless.install.heritable`) to process migration tasks in `/Library/SystemMigration/Queue` and execute `bash`/`perl` payloads before `drop_sip` invoked `CS_OPS_CLEARINSTALLER`, allowing direct overwrites of system `TCC.db` [131, 135]. Most recently, in `CVE-2024-44243` (patched in `macOS Sequoia 15.2`), Bar Or showed that `storagekitd` also held `com.apple.rootless.install.heritable`: because `/Library/Filesystems` was writable by `root` without `SIP`, planting a trojanized `.fs` repair/erase utility bundle and triggering Disk Utility caused `storagekitd` to `posix_spawn` the attacker binary directly with inherited `SIP`-bypass authority, sufficient even to overwrite Apple's `KextExcludeList` on systems permitting kexts [132, 137].

## Verification & Forensic Artifacts

Audit the booted `APFS` Volume Group's `LocalPolicy` security mode, `lpnh`/`nsih` hashes, `SIP` configuration (`csr_config_t`), and `SSV` status read-only using `bputil` and `csrutil` [114, 116, 126]:

```bash
bputil -d
csrutil status
csrutil authenticated-root status
```

Expected output on a `Full Security` workstation (`smb0`–`smb4` and `sip0`–`sip3` all absent/enforced):

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

Verify whether any third-party `IOKit` kexts are prelinked into an active `Auxiliary Kernel Collection` (`AuxKC`) on `Preboot` via `kmutil` [120, 121]:

```bash
kmutil inspect --collection-type auxiliary --no-header 2>/dev/null | head -n 5
kmutil showloaded --collection aux --list-only 2>/dev/null | head -n 5
```

On a pure `Full Security` (or `DriverKit`-only) Mac, no `AuxKC` exists on `Preboot` and both commands return empty third-party kext lists.

Inspect whether system daemons such as `system_installd` or `storagekitd` carry `com.apple.rootless.install*` entitlements when auditing `SIP` attack surface across `macOS` point releases [127, 129, 132]:

```bash
codesign -d --entitlements :- /usr/libexec/storagekitd 2>/dev/null | grep -A 2 'rootless'
```

Representative XML/DER entitlement snippet:

```text
	<key>com.apple.rootless.install.heritable</key>
	<true/>
```

Every cryptographic guarantee in `LocalPolicy` (from `OIHR` signatures and `BAA` hardware attestation to `xART` `LPN` anti-replay nonces and `SecureToken` password checks) rests inside an enclave that neither `XNU` at `EL1` nor a custom `Permissive Security` kernel can read. [Chapter 3](03-secure-enclave.md) opens that co-processor: the `Secure Enclave` (`SEP`), its unreadable silicon `UID`/`GID` KDF hardware, and its isolated biometric pipelines.
