# File-Based Encryption, Physical USB Zero-Days, and Theft Locks

## Overview

* **Link in the Chain:** Data-at-rest cryptographic custody and physical-possession defense layer; encrypts files and filenames inline via `fscrypt` v2 + `UFS` Inline Crypto Engines (`ICE`), splits Direct Boot keys across `Before First Unlock` (`BFU`) and `After First Unlock` (`AFU`), and guards physical USB and street-theft vectors.
* **Core Security Invariant:** Credential Encrypted (`CE`) master keys remain completely absent from DRAM and hardware `ICE` keyslots during cold-boot `BFU` until `Weaver`/`KeyMint` unwraps the user's `LSKF`, while USB data signaling disabling, `Inactivity Reboot`, `Theft Detection Lock`, and `Identity Check` shrink the `AFU` window against physical extractors and shoulder-surfing thieves.
* **Ecosystem Enforcement Tier:** `File-Based Encryption` (`FBE` `fscrypt` v2) and Direct Boot enforce identically across `GREEN` and `YELLOW` locked states (`CDD` Section 9.9); lock-screen USB blocks and inactivity reboots reach their tightest hardware-level defaults on `GrapheneOS` (`YELLOW`) and Android 16/17 `Advanced Protection Mode` (`GREEN`), while `Identity Check` and `Theft Detection Lock` ship via Android 15-17 + Play Services.
* **Trusted Computing Base (TCB):** Linux kernel `fs/crypto/` (`fscrypt` v2 `HKDF-SHA512`), SoC Inline Encryption Hardware (`blk-crypto` / `UFS` `ICE` `AES-256-XTS` keyslots), `vold` (`system/vold`), `KeyMint` + `StrongBox` `Weaver` ([Chapter 4](04-keymint-weaver-throttling.md)), USB Type-C/Gadget HALs, on-device IMU `Theft Detection` ML, and `IdentityCheck` `BiometricPrompt` gates.
* **Seam & Handoff:** Renders powered-off / `BFU` handsets cryptographically opaque even to chip-off flash readers and kernel exploits, while highlighting why `AFU` runtime key residency requires strict USB port disabling and rapid re-locking; hands biometric strength classes and passkey authentication to [Chapter 13](13-biometrics-passkeys.md).

## Threat Model & Ecosystem Constraint

Desktop disk encryption (`BitLocker` TPM-only or un-passcoded `LUKS`) often optimizes for powered-off laptop theft while leaving all files decrypted once the machine boots to its login screen. On a smartphone, that model fails immediately: users rarely power off their phones, yet expect two seemingly contradictory properties simultaneously [91, 92]. When a phone reboots overnight after an unattended OTA update while the owner sleeps, the alarm clock must still ring at 7:00 a.m., emergency `911`/`112` calls and incoming telephony ringtones must work, and `TalkBack` accessibility screen readers must speak the PIN pad (`Direct Boot`); yet if a physical thief or forensic lab seizes that freshly rebooted phone, *zero* photos, Signal/WhatsApp messages, contacts, or browser tokens may exist in plaintext or unsealable memory [91, 92]!

Once the owner enters their PIN for the first time after boot, the handset transitions from `Before First Unlock` (`BFU`) into `After First Unlock` (`AFU`), even after the user presses the power button to re-lock the screen and slips the phone into their pocket! Why must `CE` encryption keys remain active in hardware during `AFU` while the screen is locked? Because while your phone sits locked in your pocket, background messaging apps must still receive and index end-to-end encrypted push messages, camera shortcuts must save photos, and health/calendar syncs must write to local SQLite databases [91, 96].

Two ruthless real-world physical adversaries target that exact `AFU` window [94, 97]:

First is the *physical forensic extraction rig* (*Cellebrite UFED / Premium*, *Magnet Graykey*): when law enforcement, border security, or authoritarian regimes seize a locked phone that has *not* rebooted since its owner last unlocked it (`AFU`), they keep it externally powered on a battery pack and plug custom USB-C hardware into its port. In February 2025, Amnesty International's Security Lab caught Cellebrite deploying a three-bug zero-day Linux kernel USB exploit chain (`CVE-2024-53104` UVC video + `CVE-2024-53197` ALSA USB audio + `CVE-2024-50302` HID) against an activist's locked Android handset, emulating malformed USB webcams and USB sound cards over the charging cable to achieve `EL1` kernel code execution and dump unlocked `AFU` `CE` files without ever guessing the user's PIN [94, 95]!

Second is the *shoulder-surfing street thief*: organized theft rings in London, São Paulo, and New York watch a victim enter their 6-digit PIN in a bar or train, snatch the unlocked handset out of their hands, immediately change the user's Google/Apple account password using the memorized PIN fallback, turn off *Find My Device*, enroll their own fingerprint, and drain banking and crypto apps [97].

## Architecture & AOSP Implementation

### `fscrypt` v2 File-Based Encryption (`FBE`) and `UFS` Inline Crypto (`ICE`)

Android 7.0 through Android 10 retired legacy block-level Full-Disk Encryption (`dm-crypt`, which had only a single volume key and forced an awkward pre-OS boot PIN screen where calls and alarms were dead) in favor of `File-Based Encryption` (`FBE`) built on the upstream Linux kernel `fscrypt` v2 subsystem (`fs/crypto/`) over `f2fs` and `ext4` [91, 93].

Under `fscrypt` v2, every encrypted directory tree on `/data` carries an extended attribute (`fscrypt_policy_v2`) naming a 16-byte `master_key_identifier` alongside encryption modes: `AES-256-XTS` for 4 KiB file contents and `AES-256-CTS-CBC` (or `HCTR2` on newer hardware) for filenames and symlink targets [9, 91, 93]. For each newly created inode $i$, the kernel generates a fresh random 16-byte per-file `nonce` stored in the inode's xattr and derives a unique per-file key via `HKDF-SHA512` (`RFC 5869` [10]):

$$K_{\text{inode}} = \text{HKDF-SHA512}\bigl(K_{\text{master}}, \; \text{"fscrypt\textbackslash 0"} \parallel \text{mode} \parallel \text{nonce}_{16}\bigr)$$

Notice an extraordinary hardware synergy on modern ARM64 SoCs (`Qualcomm ICE`, `Google Tensor UFS Crypto`, `Exynos FMP`, `MediaTek Inline Crypto`) managed via Linux `blk-crypto` [91]: *bulk file encryption keys do not even need to sit in general kernel slab memory during I/O*! Instead, `vold` and `KeyMint` support *Wrapped Storage Keys* (`STORAGE_KEY` tag in `KeyMint`), wrapping `AES-256-XTS` keys under an ephemeral/hardware key routed directly from `TEE`/hardware into dedicated cryptographic keyslots (`0..63`) inside the `UFS` host controller's Inline Crypto Engine (`ICE`) on the DMA path between DRAM and flash! File blocks are encrypted and decrypted at multi-gigabyte-per-second wire speed with near-zero CPU overhead and without exposing raw `XTS` key bytes to normal `EL1` kernel memory dumps [91].

### Direct Boot: `Device Encrypted` (`DE`) vs. `Credential Encrypted` (`CE`) Storage

`FBE` enables `Direct Boot` by partitioning `/data` into two cryptographically independent key hierarchies for every user $u$ (plus global `/data/unencrypted` metadata protected separately by `Metadata Encryption` at the block layer so filesystem superblocks and unencrypted directory layouts are also encrypted under a `KeyMint` boot-bound key!) [91, 92]:

![Figure: File-Based Encryption (fscrypt v2) and Direct Boot key custody across Before First Unlock (BFU) and After First Unlock (AFU) states.](diagrams/12-fbe-bfu-afu-key-hierarchy.svg)

First, `Device Encrypted` (`DE`) storage (`/data/user_de/0/<pkg>`, `/data/system_de/0`) is protected by master key $K_{\text{DE}, u}$, which is sealed inside `KeyMint` (`Tag::NO_AUTH_REQUIRED` + boot-state binding, [Chapter 4](04-keymint-weaver-throttling.md)). Immediately upon cold boot (`BFU`), `vold` asks `KeyMint` to unwrap $K_{\text{DE}, u}$ and installs it into the kernel/`ICE` keyring. Only explicit `android:directBootAware="true"` components (`DeskClock` alarms, `Telecom` dialer, `LatinIME` keyboard, `TalkBack`, Wi-Fi credentials) run during `BFU` using `Context.createDeviceProtectedStorageContext()` [92].

Second, `Credential Encrypted` (`CE`) storage (`/data/user/0/<pkg>`, `/data/media/0` user photos/downloads, `/data/system_ce/0`) is protected by master key $K_{\text{CE}, u}$, derived from the user's 256-bit `SyntheticPassword` $S$, which is sealed behind *both* `StrongBox` `Weaver` (`LSKF` PIN/password, [Chapter 4](04-keymint-weaver-throttling.md)) and `KeyMint` [40, 91]. During `BFU`, $K_{\text{CE}, u}$ *does not exist anywhere in DRAM, CPU registers, or `ICE` keyslots*: attempting `open("/data/user/0/com.whatsapp/databases/msgstore.db")` returns `-ENOKEY` from the Linux VFS! Only after the human enters their valid `LSKF` after boot does `LockSettingsService` unwrap $S$, derive $K_{\text{CE}, u}$, call `FS_IOC_ADD_ENCRYPTION_KEY` via `vold`, broadcast `ACTION_USER_UNLOCKED`, and transition the handset into `AFU` [91, 92].

### Defeating Physical USB Extraction Chains (`CVE-2024-53104` & `CVE-2024-53197`)

Why did Cellebrite's 2024-2025 zero-day chain documented by Amnesty International [94] target Linux kernel USB host-mode drivers (`uvcvideo` and `snd-usb-audio`) on a *locked* `AFU` smartphone? Look at how `USB Type-C` Dual-Role Data (`DRD`) controllers behave by default: while a locked phone ordinarily declines *peripheral-mode* `adb` or `MTP` file transfer until unlocked, plugging in a USB-C OTG adapter (so a user can plug USB-C headphones or a hardware YubiKey into their locked phone!) flips the phone's USB controller into *USB Host Mode* (`xhci-hcd`), causing the Linux kernel inside `EL1` to automatically enumerate whatever USB descriptors the external device presents and bind matching in-kernel class drivers [94, 95]!

![Figure: Physical USB forensic exploit chains (Cellebrite 2025 UVC/ALSA zero-days) vs. lock-screen USB data disabling, Theft Detection Lock, and Identity Check.](diagrams/12-usb-zero-day-vs-locks.svg)

Cellebrite's physical appliance exploited that exact USB Host Mode enumeration path on locked `AFU` devices [94, 95]. In `CVE-2024-53104` (`drivers/media/usb/uvc/uvc_driver.c`), presenting crafted `UVC_VS_UNDEFINED` USB Video Class format descriptors caused `uvc_parse_format()` to miscalculate buffer allocation sizes and trigger an out-of-bounds kernel heap write! In `CVE-2024-53197` (`sound/usb/card.c` and `stream.c`, ALSA USB Audio), presenting forged `bNumConfigurations` / audio clock-multiplier descriptors triggered slab out-of-bounds corruption inside `EL1` when emulating a USB-C headset, chained with `CVE-2024-50302` (`hid-core` uninitialized slab leak to defeat `KASLR`) to overwrite `selinux_state` and read unlocked `AFU` `/data` files [94, 95].

Android 15, Android 16/17 (`Advanced Protection Mode`), and `GrapheneOS` sever that physical vector through two orthogonal hardware/OS controls [89, 96]. First, under *Lock-Screen USB Data Signaling Block* (`UsbPort.enableLimitPowerTransfer` / Type-C Port Manager HAL `enableUsbDataWhileDocked` / `enableUsbData(false)`), when enabled (enforced automatically in `Advanced Protection Mode` and set to *Charging-only when locked* on `GrapheneOS`), the Type-C Port Controller (`TCPC`) disables USB 2.0 `D+/D-` and SuperSpeed `TX/RX` data lanes whenever the screen is locked, preventing *both* USB Peripheral and USB Host (`xhci` `UVC`/`ALSA`/`HID`) kernel drivers from receiving a single packet over the USB-C receptacle until the owner unlocks the screen [89, 96]! Second, under *Automatic Inactivity Reboot* (`AFU` $\to$ `BFU` eviction), Android 16 (`Advanced Protection` / Play Services security update) automatically reboots any locked handset left stationary/unlocked-idle for `72 hours` (configurable down to `10 minutes`..`18 hours` on `GrapheneOS`), calling `FS_IOC_REMOVE_ENCRYPTION_KEY` / cold reset to evict all `CE` keys from DRAM and `ICE` before a seized phone sitting in an evidence locker reaches a forensic lab [89, 96]!

### Street-Theft & Shoulder-Surfing Defenses: `Theft Detection Lock` and `Identity Check`

To close the snatch-and-run and shoulder-surfed-PIN threat vectors, Android 15 through Android 17 deployed four coordinated defenses [97]. First, `Theft Detection Lock` runs a low-power on-device machine-learning classifier over inertial measurement unit (`IMU` accelerometer/gyroscope) kinematics paired with Wi-Fi/Bluetooth disconnections; detecting the signature jerk-and-sprint (or bike/car acceleration) of a phone snatched from a pedestrian's hand immediately slams the lock screen shut mid-session! Second, `Offline Device Lock` and `Remote Lock` automatically lock the screen shortly after a thief toggles Airplane Mode or places the phone in a Faraday bag to sever network connectivity, while allowing victims to trigger an immediate lock from any borrowed phone at `android.com/lock` using only their verified phone number + security challenge without needing to log into their 2FA-locked Google account first [97]. Third, `Failed Authentication Lock` locks the handset down automatically after a burst of failed PIN/biometric guesses across system and sensitive settings prompts. Fourth, Android 16/17 `Identity Check` (*Mandatory Class 3 Biometric Gate*) solves the shoulder-surfed PIN problem decisively [5, 97]: whenever the handset's fused location engine detects the user is outside designated Trusted Places (away from home or office), knowing the genuine 6-digit `LSKF` PIN is no longer permitted as a fallback for critical account and device actions! Attempting to disable *Find My Device*, turn off `Theft Protection`, enroll a new fingerprint, change the PIN, view saved passwords/passkeys in `Google Password Manager`, factory reset, or access Google Account settings strictly requires a live `Class 3` (`Strong`) Biometric ([Chapter 13](13-biometrics-passkeys.md)), leaving a thief who filmed the victim's PIN in a pub completely locked out of account takeover [97]!

## Vendor, OEM, & Custom-OS Boundaries

`CDD` Section 9.9 mandates `File-Based Encryption` (`AES-256-XTS` + `AES-256-CTS`, or `Adiantum` `XChaCha12-AES-Poly1305` strictly on ultra-low-end entry SoCs lacking ARMv8 Cryptography Extensions) across every compatible Android device [2, 91]. Hardware USB-C pin disabling, however, depends on the handset's USB HAL (`android.hardware.usb.IUsb` `enableUsbData` v1.3 / AIDL): Pixel (`Tensor`) and modern flagship SoCs physically disconnect data signaling at the Type-C controller chip, whereas older boards lacking HAL support fall back to OS-level USB gadget/host authorization (`authorized_default = 0` in Linux `usbcore`) [89, 96].

## Exploit Chains & Structural Limits

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Cold-Boot DRAM Remanence on Legacy FDE (`FROST`) | 2013 | Plaintext AES key schedule in DRAM | Freezing powered phone + flashing custom recovery on unlocked bootloader | Software `dm-crypt` held expanded AES round keys in host RAM; unlocked bootloader didn't wipe | Locked `AVB` wipe gate ([Chapter 1](01-bootrom-avb-vbmeta.md)) + hardware `UFS` `ICE` Wrapped Storage Keys [91] |
| Cellebrite Linux USB Zero-Day Chain (`CVE-2024-53104`, `CVE-2024-53197`, `CVE-2024-50302`) | 2024-2025 | `GKI` `uvcvideo`, `snd-usb-audio`, & `hid-core` in `AFU` | Physical USB-C OTG host-mode enumeration on locked phone | USB host stack parsed untrusted webcam/audio descriptors while screen was locked in `AFU` | Upstream/ASB `GKI` patches + Lock-Screen USB Data Disable + Auto-Reboot to `BFU` [89, 94, 95, 96] |
| `adb` `PackageManager` `run-as` Escalation (`CVE-2024-0044`) | 2024 | Post-unlock `adb` (`UID 2000`) extraction on `AFU` device | Forensic rig with authorized `adb` or unlocked screen | Newline injection into `packages.list` allowed dumping non-debuggable app `CE` sandboxes | Patched in Oct 2024 ASB; revoke `adb` keys automatically after 7 days (`adb_allowed_connection_time`) [7, 94] |
| Shoulder-Surfed PIN Account Takeover Rings | 2022-2025 | `LSKF` PIN fallback on `BiometricPrompt` / Account settings | Thief observes PIN in public, snatches unlocked phone, resets cloud/passkey credentials | Historically, PIN was treated as universal root credential everywhere on the device | Android 15-17 `Theft Detection Lock` + `Identity Check` mandatory Class 3 biometric outside Trusted Places [97] |

### Why `BFU` Remains the Gold Standard Under High Physical Threat

Amnesty International's 2025 forensic investigation underscored a timeless operational truth for journalists, human-rights defenders, and executives crossing high-risk checkpoints: *in `BFU` (powered off or freshly rebooted before entering the PIN) with USB data disabled while locked and a strong 8+ digit PIN or passphrase backed by `StrongBox` `Weaver`, even nation-state physical extraction rigs have no `CE` keys in RAM or `ICE` to steal* [94, 96]. And in `Identity Check`, Android's final line of defense against a shoulder-surfed PIN rests entirely on the spoofing resistance of its biometric pipeline, bringing us to `BiometricPrompt` strength tiers and `Credential Manager` passkeys in [Chapter 13](13-biometrics-passkeys.md).

## Inspecting via ADB, Fastboot, & Attestation

Verify that the handset uses `file` (`File-Based Encryption` `fscrypt` v2), Metadata Encryption, and hardware `WrappedKey` / Inline Crypto Engine (`ICE`) backing:

```bash
adb shell getprop ro.crypto.state
adb shell getprop ro.crypto.type
adb shell getprop ro.crypto.uses_fs_ioc_add_encryption_key
```

Check current user Direct Boot unlock state (`RUNNING_UNLOCKED` corresponds to `AFU`; `RUNNING_LOCKED` corresponds to `BFU` before first unlock) and USB port/HAL data state:

```bash
adb shell dumpsys user | grep -E 'State:|mIsManaged' | head -n 6
adb shell dumpsys usb | grep -iE 'usbDataEnabled|powerBrick|connected' | head -n 8
```
