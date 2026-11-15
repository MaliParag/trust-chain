# Per-App UID Sandboxing, WebView Isolation, and Binder IPC

## Overview

* **Link in the Chain:** Userspace principal isolation and kernel capability-IPC layer; instantiates every installed application inside a unique Linux `UID` via `Zygote`, confines untrusted web renderers inside zero-permission `isolatedProcess` `UID`s, and mediates all cross-process calls through `/dev/binder`.
* **Core Security Invariant:** No two applications signed by distinct developer keys share a Linux `UID`, ephemeral `isolated_app` processes possess zero filesystem, network, or permission authority, and the kernel `Binder` driver stamps every transaction with the unforgeable `sender_euid` and `sender_pid` of the calling task while translating object references via per-process kernel capability tables.
* **Ecosystem Enforcement Tier:** Enforced identically across `GREEN` and `YELLOW` locked states (`GrapheneOS` additionally supports per-app `Vanadium` `WebView` hardening and contact/storage scopes); remains active in `ORANGE` unlocked state unless bypassed by explicit `su` root daemons.
* **Trusted Computing Base (TCB):** `PackageManagerService` `packages.xml` `appId` allocator, `Zygote64` and `WebViewZygote` fork servers, Linux kernel `Binder` driver (`drivers/android/binder.c` and `binder_rust`), `servicemanager`, and `ActivityManagerService` `Intent` / `UriPermission` reference monitors.
* **Seam & Handoff:** Prevents direct cross-app memory or file tampering and guarantees unforgeable IPC caller identity, while exposing an application-logic seam whenever exported components re-dispatch attacker-controlled nested `Intent`s (`confused deputy`); hands cryptographic package identity and `Scoped Storage` to [Chapter 10](10-apk-signing-scoped-storage.md).

## Threat Model & Ecosystem Constraint

Kernel confinement ([Chapter 6](06-selinux-seccomp.md)) and heap memory tagging ([Chapter 8](08-arm-mte-scudo.md)) establish the walls of an application's cell, yet a mobile operating system cannot leave applications sealed inside mute black boxes. A camera app must pass a captured photo to a messaging app without exposing the user's entire photo roll; an email client must render untrusted HTML newsletters inside an embedded `WebView` without risking its IMAP credentials if Blink or V8 suffers a renderer vulnerability; and hundreds of concurrent services must invoke `system_server` APIs thousands of times per second at sub-millisecond latency without copying megabytes across sockets [4, 72, 73].

Two distinct adversaries test this userspace substrate every day. The first is a *remote web/content adversary* who exploits a browser or `WebView` memory-corruption vulnerability via a malicious advertisement or HTML message inside a legitimate host app, seeking to steal the host app's SQLite databases or OAuth tokens [72]. The second is a *malicious co-installed application* (`UID u0_a250`) holding zero runtime permissions that sends crafted `Binder` parcels, `PendingIntent`s, or nested `Intent` extras to exported `Activity`, `Service`, `BroadcastReceiver`, or `ContentProvider` endpoints of a privileged preloaded app or banking client, tricking the victim into exercising its own authority on the attacker's behalf [76, 77].

## Architecture & AOSP Implementation

### Install-Time `AID` Assignment, `Zygote`, and `isolatedProcess` `WebView` Sandboxes

When `PackageManagerService` installs an APK, it allocates a persistent Application ID (`appId`) from `[AID_APP_START, AID_APP_END]` (`10000..19999`), persisted inside `/data/system/packages.xml` [7, 121]. Under user profile $u$, the app's runtime kernel `UID` equals $100000 \cdot u + \text{appId}$. Historically, Android permitted two apps signed by the same developer key to request `android:sharedUserId` to run inside a single `UID`; because shared-UID coupling caused pervasive cross-component privilege leaks, Android 10 (`API 29`) deprecated `sharedUserId` for all new apps in favor of explicit `Binder` services and `ContentProvider`s [7].

Spawning a fresh Android Runtime (`ART`) virtual machine from `execve()` on every app launch would burn hundreds of milliseconds and tens of megabytes of duplicate class metadata. Instead, `init` starts `Zygote64` (`app_process64`) at boot to preload `ART`, framework Java classes, `ICU` localization tables, and read-only resources into memory once [71]. When `ActivityManagerService` launches an app, it sends specialization arguments over `/dev/socket/zygote` (accessible exclusively to `system_server` via DAC + `SELinux`). `Zygote64` calls `fork()` so the child shares preloaded pages via Copy-on-Write (`COW`), strips capabilities, installs the `seccomp-BPF` filter ([Chapter 6](06-selinux-seccomp.md)), switches to `u0_aXYZ` and private mount namespaces, and invokes the app's `ActivityThread.main()` without calling `execve()` [71].

![Figure: Process hierarchy across Zygote64, AppZygote, and WebViewZygote ephemeral u0_i* isolatedProcess renderer sandboxes.](diagrams/09-zygote-webview-uid-tree.svg)

Wait: if a banking app embeds an `android.webkit.WebView` to display help pages or promotional banners, and a remote attacker triggers a V8 or Blink exploit inside that `WebView`, why doesn't the attacker immediately inherit the banking app's `u0_a214` `UID` and read `/data/user/0/com.bank/databases`? Because since Android 8.0 (`Oreo`), `WebView` (like Chrome) uses *multi-process out-of-process rendering* backed by `android:isolatedProcess="true"` and a dedicated `WebViewZygote` [71, 72]!

Whenever any host app instantiates a `WebView`, `ActivityManagerService` instructs `WebViewZygote` to fork a separate renderer child assigned a *random, ephemeral isolated `UID`* in `[AID_ISOLATED_START, AID_ISOLATED_END]` (`99000..99999`, displayed as `u0_i*`) confined inside the `isolated_app` `SELinux` domain [7, 72]. That `u0_i*` renderer sandbox is one of the tightest userspace jails in consumer computing: it holds *zero* Android permissions regardless of what the host app holds, cannot open any `AF_INET` / `AF_INET6` network socket, cannot read or write *any* directory on `/data` or `/sdcard`, cannot query `PackageManager`, and is barred by `service_contexts` from reaching almost every `Binder` service in `system_server` (communicating strictly over a pre-passed UNIX/Binder pipe back to the browser broker process) [50, 72]. Android 10 further added `AppZygote` (`[90000, 98999]`), letting multi-process apps preload custom native libraries into an isolated intermediate fork server without granting that preloader network or storage write access [71].

### Kernel `Binder` as an Object-Capability Substrate

Because standard System V shared memory is disabled in `GKI` (`CONFIG_SYSVIPC` unset so crashed apps never leak immortal kernel segments) and `SELinux` forbids arbitrary cross-app UNIX sockets, all structured IPC on Android traverses the Linux kernel `Binder` driver (`/dev/binder` for framework/app IPC, `/dev/hwbinder` for legacy HIDL, and `/dev/vndbinder` for vendor-internal IPC) [57, 73].

Architecturally, `Binder` is not merely a message pipe; it is a *kernel-enforced object-capability system* derived from `OpenBinder` [4, 73]. Each process opening `/dev/binder` maps a read-only kernel-managed receive buffer (`1 MiB - 8 KiB` for typical apps) into its virtual address space via `mmap()`, allowing the kernel to copy serialized `Parcel` payloads *once* directly from the sender's user buffer into the receiver's mapped page without a second kernel-to-user copy.

More importantly, the kernel maintains a per-process red-black tree of `binder_node` objects (capabilities owned by a server process, keyed by userspace `BBinder` pointer + secret 64-bit `cookie` to defeat pointer-guessing) and a per-process table of `binder_ref` integer handles (unforgeable capability descriptors held by client processes, strictly analogous to UNIX file descriptors!) [73]:

```c
/* Simplified from Linux include/uapi/linux/android/binder.h */
struct flat_binder_object {
  struct binder_object_header hdr; /* BINDER_TYPE_BINDER or BINDER_TYPE_HANDLE */
  __u32 flags;
  union {
    binder_uintptr_t binder;       /* Local BBinder ptr (server -> client) */
    __u32            handle;       /* Capability table index (client -> server) */
  };
  binder_uintptr_t cookie;         /* Extra unforgeable server object token */
};
```

When Process A sends a `Parcel` containing an object reference (`BINDER_TYPE_BINDER`) or an open file descriptor (`BINDER_TYPE_FD`, used to share `ashmem`/`memfd` shared memory or `Scoped Storage` files) to Process B via `ioctl(BC_TRANSACTION)`, the kernel parses the parcel's out-of-band offset array, verifies `SELinux` `binder { call transfer }`, allocates a local `binder_ref` handle inside Process B's kernel capability table, and rewrites the wire `flat_binder_object` into `BINDER_TYPE_HANDLE` before Process B reads it [73]. Process C *cannot* guess integer `handle = 7` to invoke Process A's private callback unless Process A or Process B explicitly delegated that capability reference to Process C in a prior `Binder` transaction!

Simultaneously, on every synchronous `BC_TRANSACTION`, the kernel populates `binder_transaction_data.sender_pid` and `sender_euid` directly from `current_euid()` of the calling `task_struct` [73]. Inside any `Binder` stub in `system_server` or an exported app service, calling `Binder.getCallingUid()` reads thread-local kernel transaction state that *no userspace process can spoof*. (And remember the classic reference-monitor discipline rule: if a privileged service subsequently makes an outbound `Binder` call on its own thread before checking permissions, it *must* bracket that outbound call with `long token = Binder.clearCallingIdentity(); try { ... } finally { Binder.restoreCallingIdentity(token); }` so downstream services do not mistake the broker's own `UID 1000` for the untrusted caller's `UID`!)

### Confused Deputies Above `Binder`: `Intent` Redirection and `PendingIntent`s

If kernel `Binder` capabilities and `sender_euid` stamps are unforgeable, why do cross-app privilege escalations still top Android bug-bounty leaderboards every year [76, 77]? Because Android's high-level `Intent` messaging layer runs *asynchronously through `ActivityManagerService`*, stripping immediate synchronous `Binder.getCallingUid()` context unless developers use explicit identity APIs!

![Figure: Kernel Binder unforgeable sender_euid mediation vs. application-layer nested Intent redirection confused-deputy attack.](diagrams/09-binder-capability-vs-intent.svg)

Trace the canonical *`Intent` Redirection* confused-deputy flaw [76, 77]: suppose Victim App (`u0_a180`) declares an exported `ProxyActivity` (`android:exported="true"`) that extracts a parcelable extra `Intent next = getIntent().getParcelableExtra("next_intent")` and calls `startActivity(next)`. Attacker App (`u0_a250`) crafts an outer `Intent` targeting `ProxyActivity` whose nested `next_intent` targets Victim App's *non-exported* internal `WebViewActivity`, or sets `next.setData(Uri.parse("content://com.victim.fileprovider/root/databases/auth.db"))` with `Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION` pointing back to Attacker App's `ResultActivity`! When `ProxyActivity` calls `startActivity(next)`, `ActivityManagerService` sees `UID u0_a180` initiating the launch, so `u0_a180` unwittingly grants Attacker App read/write `UriPermission` to `u0_a180`'s own private database [76, 77]!

Three platform-level hardenings in Android 12 through Android 16 systematically closed the worst classes of `Intent` confused deputies [76]: Android 12 (`API 31`) required every component with an `<intent-filter>` to declare `android:exported="true|false"` explicitly (aborting APK installation if omitted) and forced every `PendingIntent` to specify `FLAG_IMMUTABLE` or `FLAG_MUTABLE` (stopping recipients from filling empty target `Intent` fields on `PendingIntent` capabilities); Android 14 (`API 34`) blocked `FLAG_MUTABLE` `PendingIntent`s carrying implicit `Intent`s; and Android 15/16 introduced strict platform *Safer Intents* (`StrictMode` + runtime `CreatorToken` unparceling checks in `ActivityManagerService`) that block nested `Intent` launches targeting non-exported internal components or carrying unverified URI grant flags unless explicitly opted in via `Intent.removeFlags()` / `SanitizedIntent` APIs [76].

## Vendor, OEM, & Custom-OS Boundaries

Preloaded OEM system apps (`/product/priv-app` and `/vendor/app` running as `UID 1000` `android.uid.system` or holding `signature|privileged` permissions on Samsung, Xiaomi, Motorola, and carrier ROMs) historically represented the largest concentration of `Intent` redirection, world-accessible `BroadcastReceiver`, and path-traversal `FileProvider` vulnerabilities across the ecosystem [77]. While AOSP's `privapp-permissions.xml` allowlist (`CTS` `PrivAppPermissionsTest`) forces OEMs to declare every privileged permission explicitly, `CTS` cannot statically prove the absence of application-logic confused deputies inside custom OEM helper apps, making minimal-bloat builds (`Pixel` and `GrapheneOS`, which ships zero third-party carrier/OEM `priv-app` bloatware and replaces `WebView` with hardened `Vanadium` disabling JIT by default where configured [16]) measurably narrower at the IPC layer.

## Exploit Chains & Structural Limits

Vulnerabilities in this layer split cleanly between kernel C `Binder` lifetime bugs (now eliminated structurally by the Rust `Binder` driver) and userspace `Intent`/`ContentProvider` confused deputies.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| `Bad Binder` (`CVE-2019-2215`, Project Zero / NSO) | 2019 | Kernel C `/dev/binder` (`binder_thread` + `epoll`) | Local `untrusted_app` or sandboxed renderer `BC_FREE_BUFFER` / `BINDER_THREAD_EXIT` | UAF in `binder_poll` `wait_queue_head_t` unlinking granted deterministic kernel R/W via `iovec` | Upstream fix + `GKI 2.0` + full Rust `Binder` driver rewrite (`binder_rust`) [58, 74, 75] |
| Kernel `Binder` Node/Ref Race (`CVE-2023-20938` / `CVE-2022-20421`) | 2022-2023 | Kernel C `binder_dec_node_nilocked` | Multi-threaded `BC_TRANSACTION` refcount race from `untrusted_app` | Complex manual C lock-dropping across `binder_proc` and `binder_node` spinlocks | Eliminated by ownership/lifetime types in `drivers/android/binder_rust` [62, 75] |
| OEM `priv-app` `Intent` Redirection & `FileProvider` Traversal (Oversecured) | 2021-2024 | Exported OEM `UID 1000` / `priv_app` Activities & Providers | Zero-permission malicious APK sending nested `Intent` with `FLAG_GRANT_READ_URI_PERMISSION` | Victim re-launched attacker `Intent` or failed to canonicalize `..` in custom `ContentProvider.openFile()` | Android 12-16 `FLAG_IMMUTABLE`, explicit `android:exported`, & platform nested-`Intent` Creator checks [76, 77] |
| `Parcel` Deserialization Mismatches (`Bundle` "LaunchAnyWhere" `CVE-2017-13288` to `CVE-2023-20963`) | 2017-2023 | `Parcelable` `writeToParcel` vs. `readFromParcel` byte lengths | Crafted self-mutating `Bundle` passed through `system_server` `AccountManager` / `WorkSource` | Asymmetric read/write cursor lengths caused `system_server` to re-serialize attacker bytes as a trusted `Intent`! | Strict `Parcel` item-length framing (`LazyValue`) & `SAFER_PARCEL` type-checked `getParcelable(..., Class)` APIs [76] |

### Why `UID` Sandboxing Depends on Cryptographic Package Identity

Reflect on how `PackageManagerService` preserves an application's `u0_a214` sandbox across app updates: when `com.bank v2.0` arrives from Google Play or an `.apk` installer to replace `com.bank v1.0` and inherit `/data/user/0/com.bank`'s existing encrypted database, *the sole proof that `v2.0` comes from the legitimate author of `v1.0` is its cryptographic `APK` signature*! If an attacker can modify code inside an `.apk` without invalidating its signature, or rotate keys fraudulently, per-app `UID` isolation collapses before the first `Zygote` fork. [Chapter 10](10-apk-signing-scoped-storage.md) traces `APK` Signature Schemes `v1` through `v4`, 2026 Android Developer Verification, and `Scoped Storage`.

## Inspecting via ADB, Fastboot, & Attestation

Inspect assigned `appId`, `UID`, `SELinux` `seinfo`, and active `isolatedProcess` renderer children (`u0_i*`) for an installed browser or `WebView`-hosting package:

```bash
adb shell dumpsys package com.android.chrome | grep -E 'userId=|appId=|seInfo=' | head -n 6
adb shell ps -AZ | grep -E 'u0_i[0-9]+|webview_zygote' | head -n 6
```

Examine live kernel `Binder` driver state, active node/reference counts, and whether Rust `Binder` (`binder_rust`) is active on recent `GKI` kernels:

```bash
adb shell ls -l /dev/binder*
adb shell service list | head -n 8
```

Audit exported `Activity`, `Service`, `Receiver`, and `Provider` attack surfaces declared by any target package via `dumpsys package`:

```bash
adb shell dumpsys package com.android.settings | grep -A 3 'Activity Resolver Table:'
```
