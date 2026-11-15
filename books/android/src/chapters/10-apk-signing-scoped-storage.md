# APK Signature Schemes, Developer Verification, and Scoped Storage

## Overview

* **Link in the Chain:** Application code-origin authentication, ecosystem developer accountability, and filesystem privacy-mediation layer; binds every installed `.apk` to an immutable cryptographic signing identity and confines shared media access behind `Scoped Storage`.
* **Core Security Invariant:** `PackageManager` installs or updates an APK if and only if its whole-archive `v2`/`v3` (and optional streaming `v4` `fs-verity`) Merkle digest verifies under the package's pinned signing key (or a cryptographically chained `SigningCertificateLineage` rotation proof), while certified devices bind sideloaded and Play packages to verified developer identities and mediate `/sdcard` via `MediaStore`/FUSE and the zero-permission Photo Picker.
* **Ecosystem Enforcement Tier:** Signature schemes `v2`-`v4`, runtime permissions, and `Scoped Storage` enforce identically across `GREEN` and `YELLOW` locked states; 2026 Android Developer Verification enforces on Google-certified (`GMS` `GREEN`) handsets across Play and sideloading while leaving `adb install` developer workflows and uncertified/custom-OS builds (`GrapheneOS` `YELLOW`) unencumbered.
* **Trusted Computing Base (TCB):** `PackageManagerService` and `ApkSignatureVerifier` (`frameworks/base/core/java/android/util/apk/`), kernel `fs-verity` (`v4`), `PermissionController` Mainline `APEX`, `MediaProvider` FUSE/passthrough daemon (`com.android.providers.media.module`), and Google Play / Android Developer Verification backend registries.
* **Seam & Handoff:** Eliminates archive-framing signature bypasses (`Janus`), reckless broad storage crawling, and anonymous mass re-signing of sideloaded malware, yet cannot stop a user from being tricked into granting high-privilege UI automation (`AccessibilityService`) to an installed app; hands UI-layer bypasses and `Advanced Protection Mode` to [Chapter 11](11-accessibility-advanced-protection.md).

## Threat Model & Ecosystem Constraint

Unlike Windows or macOS desktop binaries where code signing historically chained up to a central commercial Certificate Authority (`Authenticode` or Apple `Developer ID`), Android's original 2008 package model adopted *self-signed Trust-On-First-Use (`TOFU`)* certificates [4, 78]. Any developer could generate an RSA keypair on their laptop without paying a CA, sign `com.example.app`, and ship it; from that install onward, Android pinned `SHA-256(cert)` to `com.example.app` so future updates had to match the exact signing key [78].

Three real-world adversarial failures forced profound upgrades across this layer over the next eighteen years [79, 80, 82, 83]:

First, *parser differentials in ZIP/JAR archives (`Janus`, `CVE-2017-13156`)*: Android's original `v1` signature scheme reused Java `JAR` signing (`META-INF/MANIFEST.MF`), which hashed individual extracted ZIP entries while leaving ZIP archive framing and prepended bytes completely unsigned [78, 79]!

Second, *irrevocable key lock-in versus anonymous malware churn*: under pure self-signed `TOFU`, a legitimate bank that needed to rotate an aging 2010 `RSA-1024` signing key could not switch keys without forcing millions of users to uninstall and lose local data (`v3` solved this via `SigningCertificateLineage` [80]). Conversely, when Google Play Protect banned a sideloaded banking-trojan APK (`FluBot` or `SharkBot`), criminal operators generated a fresh anonymous self-signed key in ten milliseconds, changed the package name, and pushed a new phishing link to bypass hash/cert blocklists, motivating Google's *2026 Android Developer Verification* accountability layer on certified devices [82].

Third, *ambient shared-storage surveillance*: prior to Android 10/11, any app granted legacy `READ_EXTERNAL_STORAGE` gained raw POSIX access to the entire `/sdcard` (`/storage/emulated/0`) directory tree, quietly scraping `DCIM/` camera photos (complete with home GPS coordinates in `EXIF` headers!), `Download/` tax PDFs, voice recordings, and other apps' backup folders [83].

## Architecture & AOSP Implementation

### Why `v1` JAR Signing Broke (`Janus`) and How `v2` Whole-Archive Signing Closed It

An Android `.apk` is a ZIP archive containing compiled Dalvik/ART bytecode (`classes.dex`), native libraries (`lib/arm64-v8a/*.so`), resources, and `AndroidManifest.xml`. Crucially, the ZIP format locates its `End of Central Directory` (`EOCD`) record by scanning *backward from the end of the file*, whereas an uncompressed `DEX` header (`magic = "dex\n035\0"`) begins *at byte offset `0` of the file* [78, 79]!

Under legacy `APK Signature Scheme v1` (`JAR` signing), `PackageManager` parsed the ZIP `Central Directory` from EOF, verified `META-INF/*.SF` digests over each listed entry (`classes.dex`, `AndroidManifest.xml`), and ignored any unreferenced gap bytes preceding the first ZIP local file header [79]. In 2017, GuardSquare disclosed `Janus` (`CVE-2017-13156`) [79]: an attacker concatenated a malicious `classes.dex` directly in front of a legitimate OEM-signed `v1` APK (`malicious.dex || original.apk`) and adjusted ZIP offsets! When `PackageManager` verified the `v1` signature from EOF, every ZIP entry matched the OEM's genuine `UID 1000` signature; when older `ART` runtime loaders opened the file on pre-Android 7/8 builds and saw `"dex\n"` at offset `0`, they executed `malicious.dex` directly inside the OEM's privileged `UID`!

![Figure: Evolution from JAR v1 signing and the Janus framing vulnerability to whole-archive v2, v3 key rotation, v4 fs-verity streaming, and 2026 Developer Verification.](diagrams/10-apk-signing-schemes-evolution.svg)

Introduced in Android 7.0 (`Nougat`), `APK Signature Scheme v2` eliminated `Janus` structurally by abandoning per-entry ZIP hashing in favor of *whole-file binary container verification* [78]. An APK signed with `v2` (or `v3`) is partitioned into four contiguous byte ranges on disk:

$$\underbrace{\text{ZIP Contents}}_{\text{Section 1}} \;\parallel\; \underbrace{\text{APK Signing Block (`APK Sig Block 42`)}}_{\text{Section 2 (contains v2/v3 signatures)}} \;\parallel\; \underbrace{\text{ZIP Central Directory}}_{\text{Section 3}} \;\parallel\; \underbrace{\text{ZIP EOCD}}_{\text{Section 4}}$$

During verification (`ApkSignatureSchemeV2Verifier.java`), the verifier rejects extra `EOCD` comment tricks, splits Sections 1, 3, and 4 into $1\text{ MiB}$ ($2^{20}$-byte) chunks (rewriting the `EOCD`'s Central-Directory offset field in memory to point to the start of Section 2 so inserting Section 2 remains circularity-free), computes a two-level `SHA-256` or `SHA-512` Merkle digest over *every single byte of Sections 1, 3, and 4*, and verifies the `RSA-PSS` / `ECDSA` / `DSA` signature stored under Block ID `0x7109871a` inside Section 2 [78]. Prepending a single `Janus` byte at offset `0`, appending trailing garbage after `EOCD`, or mutating ZIP local-header flags changes Section 1/3/4's chunk digest and aborts installation before the ZIP entry parser ever runs! To prevent downgrade attacks where an attacker strips Section 2 and falls back to `v1`, `v2`/`v3` embed an `X-Android-APK-Signed: 2` (or `2, 3`) header inside `META-INF/*.SF`, and Android 11+ (`targetSdkVersion >= 30`) rejects `v1`-only signatures outright [78].

### `v3` Cryptographic Key Rotation (`SigningCertificateLineage`) and `v4` `fs-verity`

Android 9.0 (`Pie`) added `APK Signature Scheme v3` (Block ID `0xf05368c0` inside the APK Signing Block) to solve key rotation without central CAs [80]. Suppose an app originally signed by $K_1$ wants to rotate to a stronger `ECDSA P-384` or hardware HSM key $K_2$ (and later $K_3$). `apksigner rotate` constructs a linked `SigningCertificateLineage`:

$$\text{Node}_1(K_1) \xrightarrow{\text{Sign}_{K_1}(K_2 \parallel \text{flags}_1)} \text{Node}_2(K_2) \xrightarrow{\text{Sign}_{K_2}(K_3 \parallel \text{flags}_2)} \text{Node}_3(K_3)$$

Here the retiring key $K_1$ signs a cryptographic delegation proof over $K_2$ along with explicit capability bitflags (`PAST_CERT_INSTALLED_DATA`, `PAST_CERT_PERMISSION`, `PAST_CERT_SHARED_USER_ID`, `PAST_CERT_AUTH`), allowing the developer to strip a compromised or retired key $K_1$ of authority to match `signature` permissions while proving to devices still running `v1.0` (pinned to $K_1$) that `v2.0` (signed by $K_3$) is the authentic successor [80]!

Android 11 (`API 30`) then added `APK Signature Scheme v4` (`.apk.idsig` detached signature file) built directly atop the Linux kernel `fs-verity` subsystem introduced in [Chapter 2](02-antirollback-verity-apex.md) [24, 81]. Rather than hashing $1\text{ MiB}$ chunks once at install time, `v4` signs the exact $4\text{ KiB}$-block `SHA-256` Merkle root digest format consumed by kernel `fs-verity` (`FS_IOC_ENABLE_VERITY`). Combined with Incremental File System / Play streaming installation, games or large apps can launch while chunks stream over HTTPS, and on normal `/data/app` installs `fs-verity` pins the `.apk` inode permanently so every runtime page-in is verified by the kernel [81].

### Play App Signing vs. 2026 Android Developer Verification for Sideloading

Who actually holds an APK's signing private key? For apps distributed through Google Play since August 2021, *Play App Signing* splits key custody into two tiers: the developer signs `.aab` Android App Bundles with an *Upload Key* (revocable/rotatable via Google support if the developer's laptop is stolen), while Google re-signs delivered split APKs inside cloud HSMs using the app's long-term *App Signing Key* [78, 82].

Sideloaded APKs (`SESSION_INSTALLER` from web browsers, third-party app stores, or messaging apps), however, remained completely anonymous, creating the primary delivery highway for financial malware ([Chapter 11](11-accessibility-advanced-protection.md)) where scammers spun up dozens of throwaway self-signed banking clones per day after Play Protect blocked earlier hashes [82, 86]. Beginning in 2026-2027 across Google-certified (`GMS`) Android devices, Google introduced *Android Developer Verification* [82]. Much like checking passport ID at an airport without inspecting the traveler's luggage contents, certified Android devices verify during installation (across Play, third-party stores, and browser sideloading) that the APK's signing certificate and `packageName` are registered to a real, identity-verified developer or organization in the Android Developer Console [82]. Crucially, unlike Apple's App Store notarization and exclusivity model, Google does *not* review the sideloaded APK's source code, binary content, or business policy during Developer Verification, preserving alternative app stores and direct web downloads while destroying the economics of anonymous throwaway key churn: revoking a verified fraudster's identity invalidates their entire distribution operation instead of a single file hash [82]. Local `adb install` over USB for hobbyists, students, and enterprise debugging remains supported without public registration, and sovereign open-source AOSP builds (`GrapheneOS` in `YELLOW` state, which do not bundle proprietary GMS certification enforcement) remain completely independent of Google's developer registry [16, 82].

### Runtime Permissions, `Scoped Storage`, and the Zero-Permission Photo Picker

Even an authentically signed APK from a verified developer must not gain ambient access to user data. Android 6.0 switched dangerous permissions (`CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`) from install-time all-or-nothing manifests to revocable runtime prompts managed by the `PermissionController` Mainline `APEX`, enhanced in Android 11-15 with *One-Time Permissions* (`Only this time`), *Approximate vs. Precise Location* separation, and automatic *Permission Hibernation / Auto-Reset* revoking runtime grants from apps unused for 90 days [84].

![Figure: Scoped Storage isolation between unmediated app-private POSIX directories and mediated MediaStore, FUSE, and System Photo Picker access.](diagrams/10-scoped-storage-mediastore.svg)

At the filesystem layer, `Scoped Storage` (enforced universally for `targetSdkVersion >= 30` since Android 11, refined in Android 13-16) dismantled legacy `/sdcard` free-for-all access [83]:

First, every app receives unmediated, zero-permission access *only* to its own private internal directory (`/data/user/0/<pkg>`) and its own external app-specific directory (`/storage/emulated/0/Android/data/<pkg>`). Kernel mount namespaces (`CLONE_NEWNS`) and the `MediaProvider` FUSE daemon (`FUSE passthrough` in `GKI` Linux `5.10`+ delivering near-native POSIX I/O speeds on authorized descriptors!) hide `/Android/data/<other_pkg>` completely from every other installed app, stopping file-cleaner utilities from harvesting WhatsApp or Signal media caches [83].

Second, non-media documents (`PDF`, `DOCX`, `ZIP`) in `Download/` or user folders are inaccessible without explicit user selection via the Storage Access Framework (`ACTION_OPEN_DOCUMENT`), while broad `MANAGE_EXTERNAL_STORAGE` (`All files access`) is restricted by Play policy strictly to genuine file managers and backup utilities [83].

Third, Android 13+ replaced `READ_EXTERNAL_STORAGE` with granular media permissions (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`), redacted GPS `EXIF` location tags inside the `MediaProvider` FUSE read path unless the app explicitly holds `ACCESS_MEDIA_LOCATION`, added Android 14 *Selected Photos Access* (`READ_MEDIA_VISUAL_USER_SELECTED`), and introduced the out-of-process *System Photo Picker* (`PickVisualMedia`), which runs inside a system `MediaProvider` UI surface and returns a transient read-only `content://` URI for *only* the one or two photos the user tapped, requiring zero storage permissions at all [83]!

## Vendor, OEM, & Custom-OS Boundaries

Because `PermissionController` and `MediaProvider` (`com.android.providers.media.module`) are both Google-signed `Project Mainline` `APEX` modules ([Chapter 2](02-antirollback-verity-apex.md)), Google updates `Scoped Storage` FUSE mediation, Photo Picker UI, and runtime permission auto-reset logic uniformly across Samsung, Xiaomi, Motorola, and Pixel handsets without OEM modification [25, 83, 84].

`GrapheneOS` (`YELLOW`) adds two notable privacy capability wrappers atop AOSP's permission model: *Storage Scopes* and *Contact Scopes* [16]. When a legacy or aggressive app refuses to run unless `READ_CONTACTS` or media permissions appear `"granted"` via `checkSelfPermission()`, `GrapheneOS` lets the user enable Storage/Contact Scopes, returning `PERMISSION_GRANTED` to the app while feeding it an empty virtualized `MediaStore`/`ContactsContract` view containing *only* the specific individual files or contacts explicitly cherry-picked by the user!

## Exploit Chains & Structural Limits

Attacks against Android's package and storage tier cluster around archive/manifest parser differentials prior to `v2` enforcement, `MediaProvider` SQL/path validation flaws, and social-engineered abuse of `REQUEST_INSTALL_PACKAGES` dropper chains.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| `Janus` (`CVE-2017-13156`) | 2017 | `v1` JAR verifier vs. `ART` `DEX` loader | Malicious `DEX` prepended to `v1`-signed OEM APK | `v1` signed extracted ZIP entries from EOF while ignoring offset-`0` `DEX` header | `APK Signature Scheme v2`/`v3` whole-file Signing Block + `v1`-only deprecation [78, 79] |
| `v3` Lineage / `Parcel` Parsing Flaws (`CVE-2020-0443` / `CVE-2024-0044` "run-as" newline) | 2020-2024 | `PackageManagerService` `packages.list` serialization | Local `adb shell` (`UID 2000`) passing newline in installer package name (`CVE-2024-0044`) | Unsanitized newline in `installerPackageName` injected fake `packages.list` row letting `run-as` impersonate arbitrary `u0_a*` UIDs! | Strict newline/character validation in `PackageManagerService` (`2024-10` ASB; exploited by forensic tools) [7, 94] |
| `MediaProvider` SQL / Path Traversal (`CVE-2020-0240` et al.) | 2020-2022 | `MediaProvider` SQLite / FUSE path check | Malicious app querying crafted `MediaStore` `WHERE` / `_data` paths | Insufficient path canonicalization during early `Scoped Storage` transition | Patched fleet-wide via `com.android.providers.media` Mainline `APEX` [25, 83] |
| Multi-Stage Session-Installer Droppers (*Anatsa* / *SharkBot*) | 2022-2026 | Play Store benign utility staging malicious Stage-2 APK | Clean PDF/cleaner app downloads encrypted payload after install & calls `PackageInstaller.Session` | Static store scan saw benign Stage-1 code; anonymous self-signed Stage-2 bypassed static reputation | Play Protect Live Threat Detection ([Chapter 14](14-play-protect-intrusion-logging.md)), 2026 Developer Verification [82], & `Advanced Protection` sideload block [89] |

### When Every Cryptographic and Sandbox Check Passes, Yet the User Clicks "Allow"

Notice `CVE-2024-0044` and Stage-2 droppers (*Anatsa*, *SharkBot*, *FluBot*) in that table: even when `APK Signature Scheme v3`, `Scoped Storage`, `SELinux`, and `Arm MTE` work without a single memory-corruption flaw, how do modern banking trojans drain millions of euros from European, Asian, and Latin American bank accounts without burning a single kernel zero-day [86]? They move *above* the sandbox and cryptography into the human user-interface layer, tricking victims into granting `AccessibilityService` and `NotificationListenerService`. [Chapter 11](11-accessibility-advanced-protection.md) dissects UI-layer bypasses and Android 16/17 `Advanced Protection Mode`.

## Inspecting via ADB, Fastboot, & Attestation

Verify an APK's active signature schemes (`v1`, `v2`, `v3`, `v3.1`, `v4`), signing certificate `SHA-256` digest, and any `SigningCertificateLineage` key-rotation history offline using AOSP's `apksigner` tool:

```bash
apksigner verify --verbose --print-certs app-release.apk
apksigner lineage --print-certs --in app-release.apk
```

On a live device, inspect a package's verified signing lineage, `targetSdkVersion`, and granted vs. denied runtime and storage permissions:

```bash
adb shell dumpsys package com.google.android.apps.photos | grep -E 'targetSdk|apkSigningVersion|READ_MEDIA' | head -n 10
```

Verify that `MediaProvider` (`Scoped Storage` FUSE passthrough daemon) is running from an up-to-date `Project Mainline` `APEX` mount under its isolated `mediaprovider_app` `SELinux` domain:

```bash
adb shell ps -AZ | grep -i mediaprovider
adb shell mount | grep -E '/storage/emulated' | head -n 4
```
