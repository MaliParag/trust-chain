# Service Sandboxing and D-Bus IPC Mediation

## Overview

* **Link in the Chain:** Confines long-running system daemons (`systemd.exec` units) and mediates inter-process privilege requests (`D-Bus`, `Polkit`, `Varlink`) immediately above capability/SUID primitives ([Chapters 9](09-capabilities-userns.md) and [10](10-suid-to-run0.md)).
* **Core Security Invariant:** Every background daemon executes inside a bespoke per-unit namespace, capability, and `seccomp-BPF` sandbox (`DynamicUser=yes`, `ProtectSystem=strict`, `SystemCallFilter=`), while every privileged IPC broker authenticates peers using immutable kernel-captured socket credentials (`SO_PEERCRED`) and race-free process file descriptors (`SO_PEERPIDFD` / `SCM_PIDFD`) rather than recyclable numeric `PID`s.
* **Deployment Profile Matrix:** Modern mutable distros (`Fedora`, `Ubuntu`, `Debian`, `RHEL`) ship progressively hardened upstream `systemd` unit files + `dbus-broker` (`Fedora`/`Arch`/`RHEL 10`) or `dbus-daemon` (`Ubuntu`); immutable appliances (`CoreOS`, `Flatcar`) lock `/usr` and `/etc` read-only across units; `Talos` omits `systemd` and `D-Bus` completely in favor of a minimal `machined` PID 1 speaking mTLS gRPC.
* **Trusted Computing Base (TCB):** `systemd` (`PID 1` unit spawner, mount-namespace builder, and `libseccomp` compiler), `dbus-broker` / `dbus-daemon` XML/SELinux bus policy engines, `polkitd`, `Varlink` UNIX socket listeners, and Linux `AF_UNIX` `SO_PEERCRED` / `pidfd` kernel primitives.
* **Integration Seam & Handoff:** Contains RCE inside network/system daemons so a compromised `nginx`, `bluetoothd`, or `cupsd` cannot pivot to host files or kernel exploits, and secures local RPC calls; delegates secret injection (`LoadCredentialEncrypted=`) to [Chapter 12](12-keyrings-systemd-creds.md).

## Problem Statement & Threat Model

When `run0` ([Chapter 10](10-suid-to-run0.md)), `NetworkManager`, `fwupd`, `systemd-resolved`, or `cupsd` operate on a modern Linux host, two distinct attack surfaces replace legacy monolithic root scripts [95, 97, 98]. First, dozens of C and C++ background daemons parse untrusted network packets (`DNS`, `DHCP`, `mDNS`, `IPP` print jobs, `Bluetooth` frames, `HTTP` requests) continuously. Under traditional SysV init scripts, every daemon that bound a low port or wrote to `/var/lib/<service>` started as unconstrained `UID 0` (or a static `/etc/passwd` service account) sharing the host's full writable `/tmp`, `/dev`, `/proc`, `/home`, and 350+ kernel system calls! A single heap overflow in an image filter or DNS parser handed the attacker read access to `/etc`, `/proc` process command lines, unprivileged `CLONE_NEWUSER` kernel exploit chains, and persistent sticky files in `/var/tmp` [95, 96].

Second, splitting privileged operations into dedicated daemons (`systemd-machined`, `systemd-logind`, `AccountsService`, `PackageKit`, `udisks2`) connected over Desktop Bus (`D-Bus` [97]) or `Varlink` [100] sockets creates a *local Confused Deputy IPC surface*. Unprivileged local users (`UID 1000` or a compromised daemon) can send structured RPC messages to root-owned system services at `/run/dbus/system_bus_socket`. How does the receiving daemon verify *who* sent the message and whether `Polkit` authorizes that peer? For over a decade, D-Bus services passed the caller's *32-bit numeric Process ID (`pid_t`)* or ephemeral bus unique name (`:1.84`) across asynchronous validation steps and looked up credentials inside `/proc/<pid>/status` [98, 99]. On Linux, default `pid_max` is often `32768` or `4194304`, and processes can exit or `execve()` in microseconds! If an unprivileged client fires a D-Bus request and immediately exits (`kill(SIGKILL)`) or forks rapid PID wraparound before `polkitd` finishes reading `/proc/<pid>`, numeric-PID authorization suffers catastrophic Time-of-Check to Time-of-Use (`TOCTOU`) races (`CVE-2021-3560` [98]). Hardening Linux userspace therefore requires both *declarative per-service sandboxing* and *race-free kernel-handle IPC authentication*.

## Kernel & Userspace Mechanics

### Declarative Daemon Confinement in `systemd.exec(5)` and `DynamicUser=yes`

Rather than requiring operators to wrap every system daemon inside Docker or author custom `SELinux` modules from scratch, `systemd` (`src/core/execute.c` and `namespace.c` [95]) compiles over sixty orthogonal Linux kernel isolation primitives directly from declarative `[Service]` unit directives *between `fork()` and `execve()`*:

![Figure: Four concentric layers of systemd.exec(5) daemon sandboxing: ephemeral DynamicUser=yes identity, per-service VFS mount namespaces (ProtectSystem=strict), kernel tunable/module/namespace locks, and seccomp-BPF SystemCallFilter allowlists.](diagrams/11-systemd-unit-sandbox-layers.svg)

At Layer 1 (Ephemeral Identity), setting `DynamicUser=yes` [96] eliminates static `/etc/passwd` service accounts entirely! When `my-api.service` starts, `PID 1` hashes the unit name into the reserved dynamic UID range `61184..65519` (`0xEF00..0xFFEF`), verifies via IPC lock that no active process or IPC object currently uses that UID, synthesizes NSS `getpwuid()` entries on the fly via `nss-systemd`, and releases the UID the instant the unit stops [96]. Wait: what if a compromised `DynamicUser=yes` process writes a backdoor file owned by `UID 62301` into `/tmp` or `/var/tmp` so the *next* dynamic service assigned `UID 62301` reads or executes it? `DynamicUser=yes` *automatically* implies `RemoveIPC=yes` (purging SysV/POSIX shared memory on stop), `PrivateTmp=yes` (giving the unit an isolated `tmpfs` `/tmp` and `/var/tmp` destroyed on stop), and `ProtectSystem=strict` + `ProtectHome=read-only` so zero world-writable directories remain reachable outside the unit's own persistent `/var/lib/private/<StateDirectory>` (exposed cleanly via a read-only `/var/lib/<StateDirectory>` symlink trick!) [95, 96]. Pairing `DynamicUser=yes` with `NoNewPrivileges=yes` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` strips all remaining root-equivalent capabilities at birth.

At Layer 2 (VFS Mount Namespace), `ProtectSystem=strict` unshares a private mount namespace (`CLONE_NEWNS` with `MS_SLAVE` propagation so host mounts flow in without service mounts leaking out) and remounts the *entire filesystem hierarchy* read-only (`MS_RDONLY`) except `/dev`, `/proc`, `/sys`, and explicitly declared `StateDirectory=`, `RuntimeDirectory=`, or `LogsDirectory=` paths [95]! `ProtectHome=yes` bind-mounts an empty inaccessible `tmpfs` over `/home`, `/root`, and `/run/user`; `PrivateDevices=yes` replaces `/dev` with a tiny `tmpfs` containing only safe pseudo-devices (`/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`, `/dev/tty`) with `nodev` enforced so `mknod` cannot recreate `/dev/sda` or `/dev/mem`; and `ProtectProc=invisible` + `ProcSubset=pid` mounts `/proc` with `hidepid=invisible,subset=pid`, hiding both sibling processes and all `/proc/kallsyms` / `/proc/sys` files [95]!

At Layer 3 and Layer 4 (Kernel Surface & `seccomp-BPF`), `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectControlGroups=yes`, and `RestrictNamespaces=yes` block `CLONE_NEWUSER` LPE chains ([Chapter 9](09-capabilities-userns.md)) and module loading. Finally, `SystemCallArchitectures=native` installs a `seccomp-BPF` filter immediately killing legacy 32-bit `x86` (`int 0x80` / `IA32_EMULATION`) or `x32` syscalls (whose completely distinct syscall numbers otherwise bypass naive 64-bit `seccomp` filters!), while `SystemCallFilter=@system-service` and `~@privileged ~@resources ~@mount ~@obsolete` compile a tight `libseccomp` BPF allowlist returning `EPERM` (or `SystemCallErrorNumber=EPERM` / immediate `SIGSYS` kill) on `kexec_load`, `bpf`, `io_uring_setup`, `userfaultfd`, `keyctl`, and `perf_event_open`, complemented by `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (blocking `AF_PACKET`, `AF_NETLINK` `nf_tables`, and obscure socket protocols like `AF_RDS` or `AF_TIPC`) and `MemoryDenyWriteExecute=yes` (`W^X` blocking `mmap(PROT_WRITE | PROT_EXEC)`) [95, 116]!

### `D-Bus`, `Polkit` (`CVE-2021-3560`), `SO_PEERCRED`, and `pidfd` / `Varlink`

When a sandboxed daemon or unprivileged CLI legitimately needs to interact with another service over IPC, classic Linux uses the `D-Bus` message bus (`dbus-daemon` or the modern high-performance kernel-focused `dbus-broker` [97]). Every client connects to `/run/dbus/system_bus_socket` (`AF_UNIX`, `SOCK_STREAM`). At the exact instant of `connect(2)`, the Linux kernel (`net/unix/af_unix.c`) captures an *immutable snapshot* of the client's `struct cred` (`uid`, `gid`, `pid`, `security` LSM label) inside `sock->sk_peer_cred` and `sock->sk_peer_pid` [97, 99]:

```c
/* Kernel-captured peer identity queried on AF_UNIX sockets (include/uapi/linux/socket.h) */
struct ucred {
    __u32 pid; /* Numeric PID at connect() time - unsafe alone if not paired with pidfd! */
    __u32 uid; /* Effective UID at connect() translated into receiver user_namespace */
    __u32 gid; /* Effective GID at connect() translated into receiver user_namespace */
};
```

When `dbus-broker` calls `getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len)`, `SO_PEERGROUPS` (supplementary GIDs), and `SO_PEERSEC` (retrieving the peer's exact `SELinux` `user:role:type:mls` or `AppArmor` label captured at `connect()` time), those credential values cannot be forged by userspace or raced after connection establishment. Crucially, `dbus-broker` also enforces per-UID resource accounting inside Ring 0 and userspace so an unprivileged local user flooding the system bus with megabyte-scale broadcast signals or thousands of pending reply slots hits strict per-UID byte and file-descriptor quotas instead of starving `PID 1` or `systemd-logind` (`Denial-of-Service` isolation that plagued legacy `dbus-daemon` architectures) [97].

![Figure: Why passing numeric PIDs across asynchronous D-Bus/Polkit lookups created CVE-2021-3560, and how SO_PEERCRED paired with kernel-pinned pidfds (SO_PEERPIDFD / SCM_PIDFD) and brokerless Varlink sockets eliminate PID-reuse TOCTOU.](diagrams/11-dbus-pidfd-vs-pid-toctou.svg)

Why, then, did `Polkit` suffer `CVE-2021-3560` (a seven-year-old unauthenticated local root privilege escalation across RHEL 8, Fedora, and Ubuntu [98])? Trace the exact integration seam between `dbus-daemon`, `AccountsService`, and `polkitd`! In `CVE-2021-3560`, an unprivileged user sent a `org.freedesktop.Accounts.CreateUser` D-Bus method call and killed `dbus-send` ~5 milliseconds later (`kill -9`) right while `AccountsService` asked `polkitd` to verify the caller's bus unique name (`:1.92`). To check the caller's UID, `polkit_system_bus_name_get_creds_sync()` called `GetConnectionUnixUser(":1.92")` on `dbus-daemon`. Because the client had *just disconnected*, `dbus-daemon` returned an error (`NameHasNoOwner`): *and a bug in `polkit_system_bus_name_get_creds_sync()` failed to propagate the error boolean while leaving the uninitialized/zeroed stack variable `*out_uid = 0` untouched*! `polkitd` concluded `UID == 0` (`root` is always authorized without a password!) and created a `wheel` administrator account with an attacker-chosen password hash [98]!

Even without an uninitialized `*out_uid = 0` bug, passing `UnixProcessID` (`ucred.pid`) across D-Bus so `polkitd` could check `(pid, start_time)` in `/proc/<pid>/stat` remained fundamentally fragile against rapid PID recycling and `/proc` mount hiding (`hidepid=2`) [99]. Modern Linux (`6.5+` / `6.9+`), `systemd` (`v254+`), `dbus-broker`, and `Polkit` permanently eradicate PID TOCTOU via Process File Descriptors (`pidfd`) [99]: calling `getsockopt(sock_fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len)` (or passing `SCM_PIDFD` ancillary control messages over `sendmsg`) hands the IPC broker an actual kernel file descriptor referencing the exact `struct pid` / `task_struct` that opened the socket! Even if that client exits a microsecond later and 100,000 new processes wrap around to the identical numeric PID, the `pidfd` remains pinned exclusively to the dead original task (returning `-ESRCH` cleanly rather than ever aliasing a newcomer) [99]! Going one step further, `systemd` (`v255`–`v259`) increasingly replaces central bus daemons altogether on performance- and security-critical control paths (`run0`, `systemd-creds`, `systemd-machined`, `userdb`) with `Varlink` [100]: lightweight, brokerless, point-to-point JSON-over-`AF_UNIX` sockets where the client connects *directly* to the target service's socket so `SO_PEERCRED` + `SO_PEERPIDFD` are verified in one hop with zero central bus intermediary in the TCB!

## Distro, Immutable-OS, & Cloud Trade-Offs

Upstream `systemd` ships `systemd-analyze security`, which scores every running unit from `0.0 SAFE` to `10.0 UNSAFE` across all sandboxing directives [95]. On `Fedora` and `RHEL 9/10`, core daemons (`systemd-resolved`, `systemd-timesyncd`, `chronyd`) typically score `< 2.5 OK`, reinforced by `SELinux` `targeted` Type Enforcement and `dbus-broker` (which enforces D-Bus policy in a Rust/C capability-isolated broker without `dbus-daemon`'s legacy XML complexity). On `Ubuntu` and `Debian`, third-party package units (`redis`, `postgresql`, custom enterprise agents) often ship with `9.6 UNSAFE` default scores to preserve backward compatibility with arbitrary admin scripts; operators can harden any third-party service non-destructively via drop-in overrides (`/etc/systemd/system/<unit>.d/hardening.conf`) that survive `apt`/`dnf` upgrades cleanly [95]. Meanwhile, `Talos Linux` demonstrates the minimalist extreme on Kubernetes worker nodes: omitting `D-Bus`, `Polkit`, and `systemd` completely so `machined` manages static containerd/kubelet services via authenticated `Varlink`/gRPC with zero local multi-user IPC bus [34].

## Seam Failures, CVEs, & Structural Bounds

Service sandboxing and IPC mediation break whenever unit drop-ins omit architecture locks on `seccomp`, expose writable D-Bus properties without Polkit checks, or rely on numeric PIDs instead of `pidfd`.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `Polkit` D-Bus Disconnect Race (`CVE-2021-3560`) | 2021 | `polkitd` `GetConnectionUnixUser` | Disconnected bus client error aborts UID check | Killing client mid-RPC returned `0` (`UID 0`) from sloppy error handler, bypassing auth on `AccountsService` | Check error returns strictly and pass kernel-pinned `SO_PEERPIDFD` / `SCM_PIDFD` handles [98, 99] |
| 32-Bit `int 0x80` `seccomp` Bypass | 2015-2023 | `SystemCallFilter=` without `SystemCallArchitectures=native` | Filtering x86_64 `__NR_*` numbers blocks equivalent 32-bit syscalls | Compromised 64-bit daemon invokes `int $0x80` (`IA32_EMULATION`) where syscall numbers map to completely different functions | Always pair `SystemCallFilter=` with `SystemCallArchitectures=native` (and `CONFIG_IA32_EMULATION_DEFAULT_DISABLED`) [95, 116] |
| `DynamicUser=yes` State-Dir Symlink Escape (`CVE-2018-15688` / `15686` historical) | 2018-2020 | Early `systemd` `StateDirectory=` chown logic | Compromised dynamic service cannot trick `PID 1` into `chown`ing host files on restart | Service planted symlink inside writable state dir followed by `PID 1` as root on next unit start | Isolate under `/var/lib/private/` (`0700 root:root`) and open all paths with `O_NOFOLLOW` / `openat2(RESOLVE_NO_SYMLINKS)` [96, 120] |
| Unmediated `cups-browsed` RCE (`CVE-2024-47176`) | 2024 | `CUPS` UDP `631` + PPD filter pipeline | Legacy print daemon needs ambient network & filesystem access | Unauthenticated UDP packet triggers outbound IPP fetch and arbitrary `FoomaticRIPCommandLine` execution inside unconfined unit | Disable unused `cups-browsed` and apply `DynamicUser` / `ProtectSystem=strict` / `RestrictAddressFamilies` [95] |

Even a tightly sandboxed `DynamicUser=yes` service still faces one critical operational question: *how does it read its TLS private key, database password, or API bearer token at startup without storing plaintext files in `/etc` readable by backups or exposing `Environment=` variables in `/proc`?* Solving local secret custody with kernel keyrings, `systemd-creds`, and `TPM 2.0` `PKCS#11` is the task of [Chapter 12](12-keyrings-systemd-creds.md).

## Inspecting on a Live Linux Host

Score the sandboxing posture of all active `systemd` services on the host (`SAFE`, `OK`, `MEDIUM`, `EXPOSED`, `UNSAFE`) and drill into a specific daemon (`sshd` or `systemd-resolved`):

```bash
systemd-analyze security --no-pager 2>/dev/null | head -n 20
systemd-analyze security systemd-resolved.service --no-pager 2>/dev/null | head -n 22
```

Inspect active `D-Bus` system-bus services and see which processes and security labels own well-known privileged bus names:

```bash
busctl list --no-pager 2>/dev/null | grep -v "^:" | head -n 18
```

List active `Varlink` UNIX domain sockets managed by `systemd` (`run0`, `userdb`, `pcrextend`, `creds`):

```bash
ls -la /run/systemd/io.* /run/systemd/userdb/ 2>/dev/null | head -n 15
```
