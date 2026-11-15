# APFS Per-File Data Protection, BFU/AFU States, and Lockdown Mode

## Overview

* **Link in the Chain:** Local data-at-rest custody layer opening Part III; binds `APFS` file extents on the mutable `Data` volume ([Chapter 5](05-apfs-ssv-dyld.md)) to silicon-fused `SEP` `UID` keys and passcode keybags ([Chapter 3](03-secure-enclave.md)) across device lock transitions.
* **Core Security Invariant:** Every file on an `APFS` Data volume is encrypted under an independent random 256-bit per-file key wrapped by a Data Protection class key (`A`, `B`, `C`, or `D`), such that Class `A` keys are wiped from RAM upon screen lock, Class `A`/`B`/`C` keys remain cryptographically unavailable inside `SEP` in the Before First Unlock (`BFU`) state, and idle `AFU` devices automatically reboot back to `BFU` after 72 hours (`iOS 18.1+`).
* **Platform Matrix:** Native per-file four-class Data Protection across `iOS`, `iPadOS`, `watchOS`, and `visionOS`; `macOS` anchors full-volume `XTS-AES` encryption via `SEP`-backed `FileVault` alongside opt-in per-file classes, while `Lockdown Mode` spans `iOS`, `iPadOS`, `macOS`, and `watchOS` (`visionOS` omits legacy attachment/wired surfaces by design).
* **Trusted Computing Base (TCB):** `SEP` `SKS` keybags and 72-hour inactivity timer, the inline `ANS`/NVMe hardware `XTS-AES` storage engine, `Effaceable Storage` media-key lockers, `apfs.kext` `cprotect` xattr handling, `USB Restricted Mode` port state machines, and `Lockdown Mode` profile gates.
* **Failure Horizon & Handoff:** Once a user enters their passcode after boot (`After First Unlock`, or `AFU`), Class `C` keys reside unwrapped so background daemons can process messages and mail, exposing seized `AFU` devices to physical USB/kernel exploits (`CVE-2025-24200`) during the 72-hour window; hands off structured secret storage (`Keychain`) and shoulder-surfed passcode defense to [Chapter 11](11-keychain-stolen-device.md).

## Threat Model & Design Tension

Full-disk encryption (`FDE`, such as classic `LUKS` on Linux or TPM-only `BitLocker` on Windows) encrypts an entire block partition under a single Volume Master Key (`VMK`) unwrapped at boot. On a mobile computer carried through airports, protests, bars, and taxis, single-key block encryption fails two critical Tier 2 and Tier 3 requirements [1, 94]. First, once the user boots the phone and enters their passcode at 8:00 a.m., single-key `FDE` leaves *every* byte on the disk equally accessible in kernel memory for the rest of the week, even while the phone sits screen-locked in a coat pocket or police evidence bag. Second, erasing a 1 TB flash drive securely at trade-in or under remote `Find My` wipe cannot wait twenty minutes to overwrite raw NAND cells block by block.

Conversely, evicting *all* encryption keys from RAM the instant the screen turns off would brick the smartphone experience: incoming phone calls could not match caller names against `Contacts`, `APNs` notifications could not wake `Messages` or `Mail`, alarms and health sensors could not write background samples, and Wi-Fi could not reconnect after an unattended overnight panic reboot (`BFU`) [94].

Apple's `APFS` Data Protection architecture resolves that tension by splitting storage cryptography across *fine-grained file lifecycles* rather than one monolithic volume key [55, 94]. Health records and password vaults (`Class A`) lock completely ten seconds after the screen dims; continuous sensor logs (`Class B`) accept encrypted writes while locked through asymmetric elliptic-curve key agreement without exposing prior blocks to reads; messaging and mail databases (`Class C`) stay sealed across cold reboots (`BFU`) until first passcode entry (`AFU`); and boot-critical Wi-Fi credentials (`Class D`) remain bound to the chip's `UID` and an instant-wipe `Effaceable Storage` key [94, 96]. When `iOS 18.1` later added a 72-hour `AFU`-to-`BFU` automatic inactivity reboot and `Lockdown Mode` stripped high-risk parser and USB surfaces, Apple turned temporal lock state itself into an active defense against physical forensic extraction boxes and zero-click spyware [97, 99].

## Silicon & System Mechanics

### Per-File Keys, XTS-AES Inline Hardware, and Effaceable Storage

Whenever `apfs.kext` creates a new file on the `Data` volume, it asks the kernel CSPRNG / `SEP` to mint a fresh, independent 256-bit *Per-File Key* ($K_{\text{file}}$) [55, 94]. `APFS` never writes $K_{\text{file}}$ to flash in plaintext; instead, it passes $K_{\text{file}}$ to `AppleKeyStore` (`SEP` `SKS`) to be wrapped (`AES-KW` / `RFC 3394`) under the active *Class Key* ($K_{\text{class}}$) for that file's assigned protection class, storing the wrapped blob and class identifier inside the inode's `com.apple.system.cprotect` extended attribute [55, 94].

![Figure: APFS per-file Data Protection hierarchy linking SEP UID fuses, stretched user passcodes, and Effaceable Storage lockers through Classes A, B, C, and D down to per-extent inline XTS-AES encryption.](diagrams/10-apfs-data-protection-hierarchy.svg)

Below the filesystem, physical read and write DMA streams pass through a dedicated inline `AES` engine built directly into the Apple `ANS` / NVMe storage controller on the SoC fabric [1, 94]. Operating in `NIST SP 800-38E` `XTS-AES` mode (`XTS-AES-128` on earlier A-series chips; `XTS-AES-256` on modern Apple Silicon Macs and recent A/M generations), the hardware storage engine derives a per-extent key and computes a unique 128-bit sector tweak $T_b$ from each 4 KB physical block's logical/physical block address (`LBA` / offset) so identical plaintext blocks at different disk offsets produce unrelated ciphertexts [14, 95]:

$$C_{b,j} = \text{AES}_{K_1}(P_{b,j} \oplus \Delta_{b,j}) \oplus \Delta_{b,j}, \qquad \Delta_{b,j} = \text{AES}_{K_2}(\text{tweak}_b) \otimes \alpha^{j}$$

where $(K_1, K_2)$ splits the unwrapped per-file extent key and $\otimes \alpha^j$ denotes modular multiplication in $\text{GF}(2^{128})$ across 16-byte cipher blocks $j$ [95]. Deleting an individual file destroys its `cprotect` wrapped $K_{\text{file}}$ inside `APFS` metadata (`crypto-shredding` that file once journal checkpoints age out).

To enable *instantaneous* whole-device cryptographic obliteration (`Erase All Content and Settings` or `MDM` `EraseDevice`), Apple interposes a dedicated NAND/NOR region called *Effaceable Storage* [96]. `Effaceable Storage` provides hardware-managed "lockers" (`DKey` for Class `D` media wrapping, `EMF` Effaceable Media Key, and `BAG1` wrapping the filesystem's System Keybag) that lack wear-leveling retention copies: issuing an obliterate command physically overwrites those few kilobytes of effaceable cells in milliseconds, rendering every single Class `A`, `B`, `C`, and `D` ciphertext extent across a multi-terabyte drive mathematically unrecoverable even if the user's passcode were later coerced [94, 96].

### The Four Data Protection Classes (A, B, C, and D)

Every file and Keychain item on `iOS`, `iPadOS`, `watchOS`, and `visionOS` belongs to one of four cryptographic lifecycle classes managed inside `SEP`'s `System Keybag` [38, 94].

Under *Class A* (`NSFileProtectionComplete`), the class private key inside `SEP` is wrapped under both the chip's `UID` and the user's stretched passcode [94]. Ten seconds after the user locks the screen, `XNU` purges all unwrapped Class `A` file keys from `AP` memory and instructs `SEP` to evict the unwrapped Class `A` master key from active `SKS` slots; reading or writing any Class `A` file while locked fails with `EPERM` until biometric or passcode unlock succeeds.

Under *Class B* (`NSFileProtectionCompleteUnlessOpen`), Apple employs elliptic-curve asymmetric cryptography (`ECDH` over `P-256`) so background daemons can *create new protected files* (such as incoming mail attachments or fitness samples) while the screen is locked without holding decryption capability over previously closed Class `B` files [94]! Specifically, `SEP` keeps only the Class `B` *public key* $Q_B = d_B G$ accessible while locked while purging the Class `B` *private key* $d_B$. To create a new Class `B` file while locked, the kernel generates an ephemeral per-file keypair $(e_f, Q_f = e_f G)$, derives the shared wrapping key via $\text{HKDF}(e_f Q_B)$, wraps $K_{\text{file}}$, stores $Q_f$ inside `cprotect`, and wipes $e_f$ and $K_{\text{file}}$ from RAM the instant the file descriptor closes. Once closed, not even `XNU` can reopen that file until the user unlocks `SEP` to recover $d_B Q_f = e_f Q_B$ [94]!

Under *Class C* (`NSFileProtectionCompleteUntilFirstUserAuthentication`, the default class for third-party app data containers not explicitly upgraded to `A` or `B`), the class key remains wrapped under `UID` + passcode across cold boot (*Before First Unlock*, `BFU`), becoming unwrapped and kept available inside `SEP` after the first post-boot passcode entry (*After First Unlock*, `AFU`) even when the screen subsequently locks [94]. Finally, *Class D* (`NSFileProtectionNone`) wraps file keys under `UID` + `Effaceable` `DKey` without user passcode entropy so boot daemons and emergency telephony run in `BFU`, while still defeating raw off-chip NAND desoldering [94, 96].

### BFU vs. AFU, the 72-Hour Inactivity Reboot, USB Restricted Mode, and Lockdown Mode

For incident responders and forensic analysts, the single most consequential state boundary on any Apple mobile device is `BFU` versus `AFU` [94, 97].

![Figure: Device lock lifecycle contrasting Before First Unlock (BFU) and After First Unlock (AFU), reinforced by USB Restricted Mode and the iOS 18.1+ 72-hour inactivity auto-reboot timer.](diagrams/10-bfu-afu-state-machine.svg)

In `BFU` (immediately after cold power-on, battery exhaustion, kernel panic, or intentional reboot before the passcode is typed once), biometrics are disabled, user daemons have never launched, zero third-party app caches sit in RAM, and Class `A`, `B`, and `C` keys sit encrypted inside `SEP` behind `UID` tangling and hardware backoff timers [41, 94]. Commercial physical forensic appliances (such as GrayKey or Cellebrite UFED) seized against an updated modern `iPhone` in `BFU` face a brick wall unless the user chose a trivial 4-digit/dictionary PIN guessable within `SEP`'s slow retry budget. In `AFU`, by contrast, Class `C` keys are unlocked for live `SEP` mailbox requests, Wi-Fi/cellular daemons hold active session state in RAM, and any local USB or kernel zero-day gained before reboot can exfiltrate the vast majority of app data (`Messages`, `WhatsApp`, `Signal` SQLite stores, photos, and tokens) without ever guessing the passcode [97, 98]!

Historically, law-enforcement laboratories kept seized `AFU` iPhones plugged into trickle-charging Faraday boxes for months waiting for a new kernel/USB zero-day to become available in their extraction toolkits [97]. To bound that indefinite `AFU` exposure window, Apple introduced an *inactivity reboot timer* in `iOS 18.1` and `iPadOS 18.1` (`October 2024`, analyzed in detail by Classen and Hollick) [97]: `keybagd` and `SEP` maintain a monotonic countdown clock initialized whenever the device enters locked `AFU` state; if 72 consecutive hours (`3 days`) elapse without a successful biometric or passcode unlock, `SEP` triggers an immediate kernel panic/clean reboot, transitioning the device irreversibly back into `BFU` and purging all unwrapped Class `C` keys and `AFU` RAM caches [97]!

In parallel, two physical and remote surface-reduction gates reinforce locked devices. First, *USB Restricted Mode* (`iOS 11.4.1+`, tightened in `iOS 15+` and `macOS 13+` on Apple Silicon laptops via *"Allow accessories to connect"*) electrically/protocol-disables data pins on the Lightning / USB-C / Thunderbolt controller whenever the device is locked (or locked for $> 1\text{ hour}$ when relaxed), forcing physical attackers to pass an explicit user unlock prompt before enumerating USB descriptors [28, 98]. Second, *Lockdown Mode* (`iOS 16+`, `iPadOS 16+`, `macOS Ventura+`, `watchOS 10+`) provides an optional extreme hardening profile for Tier 3 targets (journalists, diplomats, executives) that strips entire exploit classes preemptively [99, 100]: disabling `WebKit` `JIT` compilation completely (eliminating DFG/FTL JIT bugs like `CVE-2025-43529` in *DarkSword*), blocking most `iMessage` attachment types and `JBIG2`/complex font parsers inside `BlastDoor` (neutralizing *FORCEDENTRY* and *BLASTPASS* vectors), dropping incoming `FaceTime` calls and shared album invitations from unknown contacts, stripping `2G`/`3G` cellular baseband fallback, blocking unmanaged configuration profiles, and unconditionally severing wired USB/Thunderbolt data connections while locked [99, 100].

## Platform Forks Across Apple OSes

While `iOS`, `iPadOS`, `watchOS`, and `visionOS` mandate per-file Data Protection from first boot with zero toggle to turn encryption off, `macOS` inherits general-purpose POSIX disk expectations where millions of UNIX scripts expect `/Users/alice` files to behave uniformly once logged in [29, 94]. On Apple Silicon Macs, the `APFS` `Data` volume is *always* encrypted at the hardware `ANS` block layer (`XTS-AES-256` Volume Encryption Key wrapped inside `SEP` even before `FileVault` is toggled on, enabling instant cryptographic `Erase All Content and Settings` via `Effaceable Storage`!), and turning on *FileVault* wraps that `SEP` volume keybag under authorized `SecureToken` user passwords / Institutional Recovery Keys so the Mac boots into a strict pre-boot `LoginWindow` equivalent to `BFU` [29, 94, 121]. Once unlocked, `macOS` primarily operates at volume-level `AFU` rather than aggressive 10-second screen-lock Class `A` file eviction for POSIX paths, reserving strict Class `A`/biometric wrapping for the `SEP`-backed Data Protection Keychain ([Chapter 11](11-keychain-stolen-device.md)). Meanwhile, `macOS` portable laptops (`MacBook Air`/`Pro`) enforce a dedicated USB-C / Thunderbolt accessory-approval prompt before enabling `PCIDriverKit` or USB bus enumeration on untrusted docks [28].

## In-the-Wild Failures & Architectural Bounds

Cryptographic key wrapping is only as strong as the state machine gating physical port authorization and the developer discipline choosing Class `A` over Class `C`.

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| Third-Party App Default `Class C` Over-Reliance | Architectural | `iOS` / `iPadOS` | Screen-locked `AFU` confidentiality | Apps storing sensitive tokens/chats in standard files without setting `NSFileProtectionComplete` leave plaintext accessible to any `AFU` exploit | `iOS 18.1+` 72-hour `AFU`-to-`BFU` auto-reboot limits seizure window; developers advised to use `Class A` / `SEP` Keychain [94, 97] |
| Lightning / USB Accessory State Resets (`checkm8` / `MinaUSB` era) | 2018-2022 | `iOS` (`A5`-`A11`) | Early `USB Restricted Mode` 1-hour timer | Plugging specialized USB accessories reset countdown state or dropped into `DFU` `Boot ROM` *below* OS `USB Restricted Mode` | `SecureROM` `AppleDART` (`A14+`) + immediate locked-state USB data cutoff [23, 98] |
| `Lockdown Mode` Real-World Blocks (Citizen Lab) | 2023 | `iOS 16` | Mercenary zero-click `iMessage` chains | NSO Group `PWNYOURHOME` / *BLASTPASS* chains attempted delivery against civil-society targets with `Lockdown Mode` enabled and failed at the blocked `BlastDoor` surface, triggering real-time warnings | Validated deterministic surface removal over reactive signature patching [78, 100] |
| `USB Restricted Mode` Bypass (`CVE-2025-24200`) | 2025 | `iOS` / `iPadOS` (`< 18.3.1`, `< 17.7.5`) | Locked-device physical USB port gate | State-management authorization flaw allowed a physical attack (such as Assistive/UI or port-state manipulation on locked `AFU` devices) to disable `USB Restricted Mode` without unlocking, exploited in targeted attacks | Patched authorization state management in `iOS 18.3.1` (`February 2025`); reinforced by 72h `BFU` reboot [97, 98] |

### CVE-2025-24200 and Why Physical State Machines Remain High-Stakes

In February 2025, Apple shipped an emergency out-of-band update (`iOS 18.3.1` and `iPadOS 17.7.5`) patching `CVE-2025-24200`, acknowledging reports that the flaw had been exploited in *"an extremely sophisticated attack against specific targeted individuals"* with physical possession of a locked device [98]. Rather than breaking `XTS-AES` or `SEP`, `CVE-2025-24200` exploited an authorization state-management bug that let a physical operator re-enable USB data communication on a locked `AFU` iPhone despite `USB Restricted Mode` being active, re-opening the USB attack surface to forensic extraction tools before the 72-hour `BFU` reboot timer expired [97, 98]. For high-risk travelers crossing borders or surrendering a device temporarily, powering the phone completely *off* (forcing immediate `BFU` before handover rather than relying on `AFU` port blocks or waiting 72 hours) remains the decisive operational defense.

## Verification & Forensic Artifacts

On `macOS`, verify `FileVault` hardware-backed `APFS` volume encryption status and inspect `APFS` cryptographic flags (`FileVault: Yes`) via `fdesetup` and `diskutil` [94, 121]:

```bash
fdesetup status
diskutil apfs listCryptoUsers / | head -n 8
```

Expected output on an encrypted Apple Silicon Mac:

```text
FileVault is On.
Cryptographic users for disk3s5 (2 found)
|
+-- E48192A1-... (Local Open Directory User)
```

Verify whether `Lockdown Mode` is enabled on a `macOS` host (stored inside global preferences / boot posture) and inspect USB/Thunderbolt accessory connection policy [28, 99]:

```bash
defaults read .GlobalPreferences LDMGlobalEnabled 2>/dev/null || echo "Lockdown Mode not enabled"
```

On `iOS` and `iPadOS` forensic captures (`sysdiagnose`), `keybagd` logs and `ioreg` entries record lock-state transitions, `USB Restricted Mode` engagement (`AppleUSBHostController` port-lock events), and 72-hour inactivity reboot triggers (`panic-full-*.ips` or `ResetCounter` logs showing `inactivity_reboot` / `SEP` watchdog reset) [97, 98]. While `APFS` Data Protection secures bulk files on disk, applications also need fine-grained secret sharing, biometric-gated private keys, and defenses against an attacker who *watches the victim type their passcode* before snatching the unlocked phone, the exact domain of [Chapter 11](11-keychain-stolen-device.md).
