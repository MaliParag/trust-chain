# Universal Enforcing SELinux, CTS neverallow Gates, and seccomp-BPF

## Overview

* **Link in the Chain:** Host `EL1` kernel Mandatory Access Control (`MAC`) and system-call confinement layer; bounds every userspace daemon, HAL, and application inside default-deny domains while stripping unreachable kernel syscall surfaces.
* **Core Security Invariant:** Every kernel object access `(subject_context, target_context, object_class, permission)` is denied unless explicitly permitted by the compiled `sepolicy` binary, zero production domains run permissive, every OEM policy satisfies AOSP's `neverallow` invariants verified by `CTS`, and untrusted apps execute beneath an immutable `seccomp-BPF` syscall allowlist with zero POSIX capabilities.
* **Ecosystem Enforcement Tier:** 100% enforcing across `GREEN` and `YELLOW` locked builds (`GrapheneOS` further tightens `untrusted_app` `sepolicy` and `seccomp` surfaces); remains enforcing by default even on stock `ORANGE` unlocked builds unless a root user explicitly patches the kernel or boots a permissive custom `boot.img`.
* **Trusted Computing Base (TCB):** Linux Security Module (`LSM`) hooks (`security/selinux/`), Access Vector Cache (`AVC`) and `allowxperm` 16-bit `ioctl` evaluator, `init` early-boot policy loader, `system/sepolicy` + `vendor` CIL compiler, `Zygote` `bionic/libc/seccomp` BPF filter, and `CTS` `SELinuxHostTest`.
* **Seam & Handoff:** Contains compromised `UID 0` daemons and blocks untrusted apps from opening raw `/dev` driver nodes or exotic syscalls, but executes *inside* the host `EL1` kernel; hands `Treble`/`GKI` structural splitting, `KCFI`, and memory-safe kernel `Rust` hardening to [Chapter 7](07-treble-gki-rust.md).

## Threat Model & Ecosystem Constraint

Before Android 4.3 and 5.0 (`Lollipop`), Android relied primarily on traditional Linux Discretionary Access Control (`DAC`): per-app `UID`s (`u0_a*`) separated applications from one another, while dozens of system daemons (`vold`, `netd`, `installd`, `rild`, `mediaserver`, OEM camera/sensor daemons) executed as unconstrained `UID 0` (`root`) or `UID 1000` (`system`) [4, 51]. That DAC-only architecture collapsed regularly along three predictable vectors [50, 51, 53]:

First, *omnipotent root daemons*: whenever a remote media stream or local socket exploit compromised a single `UID 0` daemon (for instance `vold` or an OEM diagnostic service), POSIX `UID 0` immediately granted complete authority to read every app's `/data/data` sandbox, load kernel modules, `ptrace` `system_server`, or overwrite block devices.

Second, *permissive vendor sprawl*: OEMs routinely added proprietary debug daemons (`atfwd`, factory test servers, world-writable `/dev/diag` or `/dev/kgsl` nodes with `chmod 0666`) during Board Support Package bring-up, silently punching holes right through AOSP's app sandbox on tens of millions of retail phones [52, 53].

Third, *wide Linux kernel syscall and `ioctl` attack surfaces*: the upstream Linux kernel implements over `300` system calls (including enterprise filesystems, `keyctl`, `bpf()`, `userfaultfd`, `io_uring`, System V IPC, and obscure network protocol families such as `AF_PACKET` or `AF_RDS`) plus thousands of driver-specific `ioctl()` command codes that no mobile application ever legitimately needs, yet historically provided the exact heap-spraying and UAF primitives exploited by local root tools (*Towelroot*, *Dirty COW*, *KingRoot*) [53, 54, 56].

Turning `SELinux` from an optional server package often disabled by frustrated sysadmins into a *100 percent universal, zero-exception enforcing policy across billions of consumer phones from hundreds of OEMs* required pairing kernel MAC hooks with compile-time `neverallow` proofs enforced mechanically by `CTS` [50, 52].

## Architecture & AOSP Implementation

### Early-Boot Policy Loading, Default-Deny Domains, and MCS Categories

Android deploys `SELinux` (`security/selinux/` in the Linux kernel, originally adapted for Android by NSA and Google engineers in the SEAndroid project [51]) in strict Type Enforcement (`TE`) + Multi-Category Security (`MCS`) mode. During first-stage `init` (`system/core/init/selinux.cpp`), before spawning a single daemon or opening network interfaces, `PID 1` compiles or merges the split platform/vendor Common Intermediate Language (`CIL`) policies (verified via `dm-verity` on `/system/etc/selinux` and `/vendor/etc/selinux`), loads the binary policy into `/sys/fs/selinux/load`, enforces `/sys/fs/selinux/enforce = 1` unconditionally on `user` builds, and re-executes itself to transition from `kernel` into `u:r:init:s0` [50].

Every process (`subject`) and every file, socket, `/dev` node, system property, or `Binder` service (`object`) carries a four-part security context `user:role:type:mls_level` (for example `u:r:untrusted_app:s0:c214,c256,c512,c768`). In Android, `user` is fixed to `u` and `role` to `r` (for processes) or `object_r` (for objects); all access-control power concentrates in the *domain/type* (`untrusted_app`, `isolated_app_all`, `priv_app`, `platform_app`, `system_server`, `keystore`, `vold`, `hal_camera_default`) and the *MCS category set* [50, 51].

![Figure: Universal enforcing SELinux domain separation, allowxperm ioctl filtering, and CTS neverallow certification gates.](diagrams/06-selinux-domain-mediation.svg)

Whenever any process invokes a VFS, socket, `ptrace`, property, or `Binder` operation, the Linux kernel's LSM hook queries the Access Vector Cache (`avc_has_perm()`). Unless an explicit `allow source_type target_type:object_class { perm_set };` rule exists in the loaded binary policy, access fails with `-EACCES` and emits an `avc: denied` audit record [50]. Look at what this achieves across Android's trust hierarchy. First, *zero unconfined processes*: unlike desktop Linux distributions (`targeted` policy) where user sessions run in `unconfined_t`, every single process on Android runs inside a bounded domain. Even `init`, `vold`, and `ueventd` (`UID 0`) are strictly confined: `vold` can mount filesystems and configure `fscrypt` keys, but `SELinux` forbids `vold` from opening network sockets or reading app data files; `netd` configures routing/BPF tables, but cannot touch storage block devices [50]. Second, *double-locked per-app and multi-user isolation via `MCS`*: when `Zygote` spawns an application (`seapp_contexts`), `libselinux` computes unique `MCS` categories encoding the app's `appId` (`c0..c255` + bank bits) and `userId` (`c512..`). Policy `mlsconstrain` expressions mandate that an `untrusted_app` domain can read or write an `app_data_file` inode *only if the process's MCS category set dominates/equals the file's MCS category set* [50, 51]. Even if a developer foolishly called `chmod("secret.db", 0777)` inside their app directory, another app (`u0_a215`) attempting to read that world-readable file is blocked in the kernel by `SELinux` `mlsconstrain`! Third, *System Property and `ServiceManager` labeling*: Android extends `SELinux` userspace object managers into `init`'s property service (`property_contexts`, preventing apps or vendor HALs from spoofing `ro.boot.*` or `security.*` properties) and `servicemanager` (`service_contexts`, preventing `isolated_app` renderers from even looking up `Binder` handles to `IActivityManager` or `IKeystoreService`!) [50].

### `CTS` `neverallow` Assertions: Governing Hundreds of OEMs

How does Google stop an OEM engineer rushing a camera deadline from writing `allow hal_camera_default self:capability sys_admin;` or `permissive oem_diag_daemon;` inside `/vendor/etc/selinux`? Through `neverallow` compile-time assertions paired with `CTS` binary policy verification [52]!

In AOSP's `system/sepolicy/public/domain.te` and `untrusted_app.te`, hundreds of `neverallow` rules state negative security invariants across domain attributes, for example:

```text
# Simplified illustrative assertions from AOSP system/sepolicy/public/
neverallow { domain -kernel -init -vendor_init } kernel:security setenforce;
neverallow untrusted_app_all dev_type:blk_file { read write open };
neverallow { appdomain -shell } self:capability *;
neverallow domain { file_type -exec_type }:file entrypoint;
```

First, at build time, AOSP's `checkpolicy` / `secilc` compiler treats every `neverallow` rule as a static theorem prover assertion: if *any* `allow` rule anywhere in the combined `/system` + `/vendor` policy grants an intersection forbidden by a `neverallow` statement, compilation aborts with a fatal build error [52]. Second, in case an OEM altered `checkpolicy` on their own build servers, `CTS` runs `SELinuxHostTest` during mandatory GMS certification [3, 52]: `CTS` pulls the live `/sys/fs/selinux/policy` binary directly off the physical handset via `adb`, verifies `/sys/fs/selinux/enforce == 1`, confirms *zero* domains carry the `permissive` bit inside the binary policy table, and re-evaluates AOSP's canonical `neverallow` test suite directly against the handset's binary policy graph! No OEM phone can pass `CTS` with a permissive backdoor or an unapproved `untrusted_app` kernel access path [52].

### Fine-Grained `ioctl` Filtering (`allowxperm`)

Standard `SELinux` permission bits (`read`, `write`, `ioctl`) are coarse at the driver boundary: an `untrusted_app` *must* be permitted `ioctl` access on the GPU device node (`/dev/mali0` or `/dev/kgsl-3d0`) and `/dev/binder` to render UI frames and perform IPC, yet a GPU or socket driver might expose 80 `ioctl` command numbers including legacy debug, profiling, or performance-counter commands riddled with memory corruption bugs [53].

Android 7.0+ (`SELinux` extended permissions, `allowxperm`, upstreamed by Jeff Vander Stoep and Google's kernel security team) inspects the 16-bit `cmd` argument (`_IOC_TYPE` and `_IOC_NR`) of every `ioctl(fd, cmd, arg)` call inside `security/selinux/avc.c` [53]. Once *any* `allowxperm` rule is attached to a `(source, target, class, ioctl)` tuple, `SELinux` switches that descriptor's `ioctl` space to default-deny over all $2^{16}$ command codes, admitting *only* the exact hex command ranges allowlisted in policy (for example blocking `SIOCGIFHWADDR` MAC-address leaks and restricting socket/GPU debug `ioctl`s from `untrusted_app`) [53].

### `Zygote` Capability Stripping and `seccomp-BPF` Syscall Confinement

Because `SELinux` LSM hooks execute *inside* kernel subsystems (often *after* syscall argument copying or VFS/protocol dispatch begins), a vulnerability early in an obscure syscall entry path (`sys_keyctl`, `sys_io_uring_setup`, `sys_bpf`, `sys_kexec_load`, `sys_userfaultfd`) could still be reached before an LSM hook fires [54, 56]. Android closes that pre-LSM kernel surface by combining complete POSIX capability stripping with `seccomp-BPF` (`CONFIG_SECCOMP_FILTER`) inside `Zygote` (`bionic/libc/seccomp/`) [54, 55].

![Figure: Zygote process-specialization pipeline installing seccomp-BPF syscall filters, dropping POSIX capabilities, and locking SELinux domains.](diagrams/06-zygote-seccomp-pipeline.svg)

During `forkAndSpecializeCommon()` (`frameworks/base/core/jni/com_android_internal_os_Zygote.cpp`), before returning control to any untrusted Java/native app code, the child process executes an irreversible four-step privilege drop [54, 55, 71]:

First, it creates private mount namespaces (`CLONE_NEWNS`) so bind-mounts for Scoped Storage and per-app `/data/data` visibility ([Chapter 10](10-apk-signing-scoped-storage.md)) cannot leak across apps. Second, it zeroes all POSIX capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, etc.) across Effective, Permitted, Inheritable, Ambient, and Bounding sets (`prctl(PR_CAPBSET_DROP)`), sets `PR_SET_NO_NEW_PRIVS = 1` (ensuring no `execve()` of a `setuid` binary can ever elevate privilege), and calls `setresgid()` / `setresuid(u0_aXYZ)` [55, 71]. Third, `set_app_seccomp_filter()` attaches a compiled classic BPF program (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`) tailored to `ARM64` (`__NR_*` syscall numbers, rejecting 32-bit compatibility ABI syscalls outright on 64-bit-only chips!) that allowlists roughly `~270` required Android syscalls while immediately trapping (`SECCOMP_RET_TRAP` $\to$ `SIGSYS` crash dump in `debuggerd`) over `130` unused Linux syscalls (`acct`, `add_key`, `keyctl`, `request_key`, `bpf`, `kexec_load`, `init_module`, `finit_module`, `open_by_handle_at`, `swapon`, `syslog`, `uselib`, `vmsplice`) [54]. Fourth, `selinux_android_setcontext()` transitions the process permanently into `untrusted_app` or `isolated_app_all` [50, 71].

When Google Project Zero and kCTF vulnerability rewards data in 2022-2023 showed that over `60%` of Linux kernel zero-day/n-day submissions exploited `io_uring` asynchronous ring bugs, Android didn't wait for dozens of subtle upstream `io_uring` race fixes: AOSP restricted `io_uring_setup`, `io_uring_enter`, and `io_uring_register` via `SELinux` `io_uring` class permissions and `seccomp` policy so `untrusted_app` processes could never instantiate an `io_uring` instance at all [56]!

## Vendor, OEM, & Custom-OS Boundaries

Under `Project Treble` ([Chapter 7](07-treble-gki-rust.md)), `SELinux` policy is compiled modularly across two halves: Google's platform `system/sepolicy` (updated with OS / Mainline releases) and the OEM's `/vendor/etc/selinux` policy governing SoC HALs [50, 57]. To prevent vendor rules from naming private `/system` internals directly, AOSP exports versioned public `typeattribute` interfaces (`hal_camera_server`, `hal_keymint_server`) so `/system` can upgrade from Android 15 to Android 16 while `/vendor` CIL compiles cleanly on boot without weakening `neverallow` invariants [50, 52].

Hardened custom OS builds (`GrapheneOS` in `YELLOW` locked state) go significantly beyond AOSP's baseline `CDD`/`CTS` floor while preserving compatibility [16, 56]: `GrapheneOS` disables `userfaultfd` (a classic deterministic heap-race primitive that stalls kernel `copy_from_user()` page faults indefinitely during UAF exploitation) for unprivileged apps via `sysctl vm.unprivileged_userfaultfd = 0` and `SELinux`, restricts `perf_event_open` hardware counter side channels (`kernel.perf_event_paranoid = 3`), tightens `/proc` and `/sys` visibility, and provides per-app user toggles to revoke `INTERNET` (implemented cleanly via a dedicated network GID check in the kernel socket path, the only network permission in Android enforced directly at kernel `socket()` creation!) and dynamic native code execution (`W^X` memory / `execmod` restrictions) [16].

## Exploit Chains & Structural Limits

Because `SELinux` and `seccomp-BPF` eliminated easy access to exotic syscalls and unmediated `/dev` nodes, modern Android kernel exploits are forced through the narrow set of interfaces an `untrusted_app` *must* legitimately call (`Binder`, `GPU` rendering `/dev/mali0` or `/dev/kgsl-3d0`, `ashmem`/`dma-buf`, `futex`/`epoll`, and standard POSIX sockets), after which a post-exploitation kernel read/write primitive overwrites `SELinux` state directly in `EL1` RAM.

| Exploit / Campaign | Year | Target Layer | Entry Vector | Root Cause | Mitigation / CTS Gate |
|---|---|---|---|---|---|
| Pre-`allowxperm` Socket / Driver `ioctl` Root Chains | 2015-2016 | Kernel network & OEM `/dev` drivers | `untrusted_app` calling obscure `ioctl` subcommands on allowed fd | Coarse `ioctl` permission bit allowed every subcommand once fd access was permitted | `SELinux` `allowxperm` 16-bit `ioctl` command allowlisting in Android 7+ [53] |
| `userfaultfd` + `Binder`/`Pipe` Deterministic UAF Grooming (`CVE-2019-2215` era) | 2019-2021 | `EL1` kernel slab allocators | `untrusted_app` stalling `copy_from_user` via `userfaultfd` | Unprivileged `userfaultfd` turned microsecond UAF races into deterministic multi-second exploit windows | `SELinux` `userfaultfd` anon_inode mediation restricting `uffd` to `ART` GC only [50, 74] |
| `io_uring` Kernel Exploit Wave | 2021-2023 | Linux `io_uring/` subsystem | `io_uring_setup` from unprivileged userspace on upstream Linux | Complex shared ring-buffer lifetime/refcount bugs in rapid upstream `io_uring` growth | Android blocked `io_uring` completely from `untrusted_app` via `SELinux` + `seccomp` [56] |
| Data-Only `selinux_state.enforcing` Overwrite (`Predator` / GPU R/W) | 2021-2025 | In-memory `EL1` `struct selinux_state` & `struct cred` | Post-exploitation arbitrary kernel R/W via `Mali` or `Adreno` GPU bug | `SELinux` lives *inside* host `EL1` RAM; arbitrary kernel write zeros `enforcing` byte and patches `task_struct->cred` to `UID 0` / `u:r:kernel:s0` | Shrink kernel C/C++ bugs via `GKI`, `KCFI`, `Rust` ([Chapter 7](07-treble-gki-rust.md)), `Arm MTE` ([Chapter 8](08-arm-mte-scudo.md)), & isolate secrets in `pKVM` ([Chapter 5](05-pkvm-avf-microdroid.md)) [63, 136] |

### The Fundamental Boundary of In-Kernel MAC

That final row captures the exact theoretical ceiling of `SELinux` and `seccomp-BPF`: *a reference monitor residing inside `EL1` kernel memory stops untrusted processes from reaching buggy kernel code, but cannot survive once an allowed interface (`Binder` or a GPU shader `ioctl`) grants arbitrary `EL1` read/write execution* [4, 63]. Once an exploit achieves an arbitrary `EL1` write primitive, it does not even need to hijack a function pointer: overwriting `cred->uid = 0` and clearing `selinux_state.enforcing = 0` in kernel data memory (`data-only attack` [63]) neutralizes host `SELinux` until the next reboot (when `AVB` and `dm-verity` restore clean state).

Defending that remaining `EL1` perimeter requires attacking the root cause of kernel and HAL vulnerabilities directly: isolating vendor HALs into separate processes (`Project Treble`), unifying the kernel so upstream patches ship rapidly (`GKI`), enforcing forward- and backward-edge Control-Flow Integrity (`KCFI` and `SCS`), and rewriting C/C++ components in memory-safe *Rust*. [Chapter 7](07-treble-gki-rust.md) examines that transformation.

## Inspecting via ADB, Fastboot, & Attestation

Verify that `SELinux` is actively running in `Enforcing` mode (`1`) and inspect the live `SELinux` security contexts (`-Z`) of `init`, `system_server`, `keystore2`, vendor HALs, and running `untrusted_app` processes (noting the `MCS` category suffix `c*`):

```bash
adb shell getenforce
adb shell ps -AZ | grep -E 'init|system_server|keystore2|untrusted_app' | head -n 8
```

Inspect `seccomp` (`Seccomp: 2` indicates active `SECCOMP_MODE_FILTER` BPF enforcement!) and completely zeroed POSIX capability bitmasks (`CapEff: 0000000000000000`, `NoNewPrivs: 1`) on any running third-party application PID:

```bash
APP_PID=$(adb shell pidof com.android.chrome | awk '{print $1}')
adb shell grep -E 'Name|Uid|Gid|Groups|CapEff|CapBnd|NoNewPrivs|Seccomp' /proc/$APP_PID/status
```

Check the security context of `/dev` driver nodes (`ls -lZ /dev/binder /dev/mali0 /dev/kgsl-3d0`) and view recent `SELinux` `avc: denied` audit entries recorded in `logcat` / `dmesg` (requires `adb` shell read permissions where available):

```bash
adb shell ls -lZ /dev/binder /dev/hwbinder 2>/dev/null
adb shell logcat -d -b events -b main | grep 'avc: denied' | tail -n 5
```
