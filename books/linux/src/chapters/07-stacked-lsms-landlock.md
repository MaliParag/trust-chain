# Stacked Linux Security Modules: SELinux, AppArmor, and Landlock

## Overview

* **Link in the Chain:** Enforces mandatory object-level access control (`SELinux`, `AppArmor`) and unprivileged application self-sandboxing (`Landlock`) inside VFS, IPC, and socket paths atop the hardened Ring 0 substrate of [Chapters 5](05-kernel-lockdown-modules.md) and [6](06-kernel-memory-rust.md).
* **Core Security Invariant:** Every VFS, socket, IPC, and execution hook invoked via `security_*()` succeeds only if classic POSIX Discretionary Access Control (`DAC`) *and* every stacked Linux Security Module (`SELinux`/`AppArmor`, `Landlock`, `IPE`, `Lockdown`, `Yama`, `LSM-BPF`) all return `0`, evaluated on pinned kernel `inode`, `dentry`, `file`, and `sock` structs after user-memory copy-in.
* **Deployment Profile Matrix:** Red Hat family (`RHEL`, `Fedora`, `CoreOS`, `Bottlerocket`) enforces `SELinux` (`targeted` + `MCS` `sVirt` container labels); Debian/Ubuntu/SUSE family enforces `AppArmor` path/IPC/userns profiles; `Landlock` (`ABI v1`..`v7`) is enabled alongside *both* `SELinux` and `AppArmor` across modern `6.x` distros so unprivileged apps, systemd services, and AI CLI agents self-sandbox without `root`.
* **Trusted Computing Base (TCB):** Linux `security/security.c` stacking framework (`lsm_blob_sizes`), `SELinux` `AVC` and binary policy / `AppArmor` DFA engine, `security/landlock/` ruleset evaluator, `VFS` inode/dentry resolution, and `CAP_MAC_ADMIN` policy loaders.
* **Integration Seam & Handoff:** Confines even compromised `UID 0` daemons (`SELinux`/`AppArmor`) and unprivileged parsers (`Landlock`) to explicit files, TCP ports, `ioctl`s, and sockets; pairs with dynamic `eBPF` runtime enforcement in [Chapter 8](08-ebpf-dual-edge.md) and capability/daemon confinement in Part III ([Chapters 9](09-capabilities-userns.md) through [11](11-systemd-dbus-sandboxing.md)).

## Problem Statement & Threat Model

Classic Unix Discretionary Access Control (`DAC`) suffers from two congenital defects that no amount of file-permission tuning (`chmod 0600`) can repair [7, 62]. First, access is *discretionary*: whichever user owns an object (`i_uid == cred->fsuid`) may freely weaken its permissions (`chmod 0777 ~/.ssh/authorized_keys`), and every program launched by that user: whether a trusted password manager, a PDF viewer rendering an untrusted email attachment, or an autonomous coding agent running `npm test`: inherits the user's *entire* ambient authority over every file, SSH socket, and local TCP port belonging to that `UID`! Second, `DAC` grants `UID 0` (`CAP_DAC_OVERRIDE`) universal bypass authority: if an internet-facing daemon (`named`, `httpd`, `cupsd`, or a containerized root process) runs as `UID 0` and suffers a remote code execution flaw, `DAC` places zero barrier between that daemon and `/etc/shadow`, `/var/lib/kubelet`, or sibling tenant files [62, 68].

For twenty years, Linux Mandatory Access Control (`MAC`) engines (`SELinux` [62] and `AppArmor` [63]) solved the second problem brilliantly for *system daemons and containers*, while leaving two glaring operational gaps. First, `SELinux` and `AppArmor` historically competed for a single raw `void *security` pointer inside `struct cred`, `struct inode`, and `struct file`, preventing distributions or container platforms from stacking multiple stateful security models simultaneously [61]. Second, and even more consequentially for application developers, *loading a `SELinux` policy module or `AppArmor` profile requires global system `root` (`CAP_MAC_ADMIN`)* [64]! An unprivileged binary (`git`, `tar`, `ffmpeg`, a browser helper, or a developer's AI coding CLI) could not ship its own fine-grained filesystem or TCP sandbox out of the box without begging a system administrator to maintain fragile distro-specific `SELinux` `.te` rules on Fedora and separate `AppArmor` profiles on Ubuntu [64, 65].

Modern Linux resolves both tensions inside a unified stacked `LSM` architecture (`security/security.c` [61]) against an adversary who exploits a vulnerable network daemon, escapes a container user namespace, or feeds malicious inputs into an unprivileged userspace parser: system administrators enforce host-wide non-bypassable boundaries via `SELinux` or `AppArmor`, while unprivileged applications and CLI sandboxes layer self-contained, monotonic `Landlock` (`ABI v1` through `v7`) restrictions directly onto their own `struct cred` with zero `root` privileges required [61, 64, 66].

## Kernel & Userspace Mechanics

### `LSM` Hook Stacking and `lsm_blob_sizes` Partitioning

How do six different Linux Security Modules (`landlock`, `lockdown`, `yama`, `ipe`, `selinux` or `apparmor`, and `bpf`) simultaneously attach state to `struct cred` and `struct inode` without overwriting one another? During early kernel boot (`security_init()` in `security/security.c` [61]), the kernel parses the ordered `CONFIG_LSM` / `lsm=` list and collects each module's `struct lsm_blob_sizes` request (`lbs_cred`, `lbs_file`, `lbs_inode`, `lbs_ipc`, `lbs_msg_msg`, `lbs_sock`, `lbs_superblock`, `lbs_task`):

```c
struct lsm_blob_sizes {
    int lbs_cred;
    int lbs_file;
    int lbs_inode;
    int lbs_sock;
    int lbs_superblock;
    int lbs_task;
};
```

The framework sums all requested sizes into a single contiguous allocation per kernel object and writes back each LSM's private byte offset (`blob_sizes.lbs_cred` becomes `selinux_blob_sizes.lbs_cred = 0`, `apparmor_blob_sizes.lbs_cred = 16`, `landlock_blob_sizes.lbs_cred = 32`, and so on) [61]! Every LSM accesses its slice exclusively via `cred->security + my_blob_sizes.lbs_cred`, completely isolated from sibling modules. Meanwhile, hook callbacks are appended to `security_hook_heads` (marked `__ro_after_init` so post-boot kernel writes cannot unhook an LSM without tampering with page tables [51, 61]). When VFS invokes `security_file_open(file)`, the `call_int_hook` macro evaluates every registered callback sequentially:

$$\operatorname{Allow}(\text{op}) \iff \operatorname{DAC}(\text{op}) = 0 \;\land\; \bigwedge_{m \in \mathcal{M}_{\text{active}}} h_m(\text{op}) = 0$$

Any non-zero return (`-EACCES` or `-EPERM`) short-circuits immediately; no stacked LSM can ever *grant* access that POSIX `DAC` or an earlier LSM denied [61].

![Figure: Architectural comparison matrix across SELinux (inode label MAC + MCS), AppArmor (VFS path profile MAC), and Landlock (unprivileged fd-hierarchy and TCP/IPC self-sandboxing) composed under stacked LSM hook evaluation.](diagrams/07-lsm-hook-stacking-matrix.svg)

### Label-Based `SELinux` (`TE` + `MCS`) vs. Pathname-Based `AppArmor`

Although `SELinux` and `AppArmor` hook the exact same `security_*` functions, they represent objects through fundamentally different mathematical models [62, 63, 67]:

`SELinux` (`security/selinux/` [62]) implements the Flux Advanced Security Kernel (`FLASK`) architecture over persistent *object labels* (`user:role:type:level`, such as `system_u:object_r:sshd_key_t:s0`) stored on disk inside each inode's `security.selinux` extended attribute (or synthesized via `genfscon` / `fs_use_trans` for pseudo-filesystems like `procfs` and `tmpfs`). Policy is a compiled binary graph of *Type Enforcement* (`TE`) rules (`allow httpd_t httpd_sys_content_t : file { open read getattr };`), evaluated in nanoseconds through a lockless hash-indexed Access Vector Cache (`AVC`) [62]. Because labels live on the *inode*, `SELinux` is completely immune to hardlink and rename aliasing: if an attacker creates a hardlink `/tmp/harmless_link` pointing to `/etc/shadow` (`shadow_t`), `httpd_t` opening `/tmp/harmless_link` still hits the `shadow_t` inode label and is denied `-EACCES` [62, 67]! Furthermore, `SELinux` *Multi-Category Security* (`MCS` [68]) underpins Red Hat/OpenShift/Fedora container and `KVM` isolation (`sVirt`): the container runtime (`podman`, `CRI-O`, `containerd`) assigns every container a shared `container_t` domain paired with a *unique* random pair of MCS categories (e.g., `s0:c104,c589` vs. `s0:c211,c802` out of $1024 \choose 2 = 523{,}776$ pairs) and labels its writable rootfs volume identically. Even if a containerized `UID 0` process breaks out of `chroot` or mounts a host path via a runtime bug, `SELinux` `MCS` enforces *category dominance* ($\text{cat}(\text{subj}) \supseteq \text{cat}(\text{obj})$), blocking Container A from reading Container B's volumes or touching `etc_t` / `var_lib_t` host files unless someone recklessly launched the pod with `--security-opt label=disable` (`spc_t`) [68]!

`AppArmor` (`security/apparmor/` [63]) trades inode extended-attribute labeling for *pathname mediation* compiled into compact Deterministic Finite Automata (`DFA` state tables in `/etc/apparmor.d/`). When a confined task (`usr.sbin.nginx`) opens a file, `AppArmor` reconstructs the canonical namespace-relative path string from the VFS `(struct vfsmount *, struct dentry *)` pair via `d_namespace_path()` and steps the profile's `DFA` over that string [63]. Operating on paths eliminates filesystem `relabel` passes entirely (`cp` or `tar` works with zero xattr awareness!), at a well-known structural cost analyzed by Watson [67]: if sensitive file `/etc/secret` has two hardlinks (`/etc/secret` and `/var/www/public_alias`), pure path mediation on open would allow reading `/var/www/public_alias` unless `AppArmor` *also* mediates hardlink creation (`security_path_link` requiring the caller to hold target permissions before linking), `rename()`, and mount propagation. Modern `AppArmor` (`4.0+` in Ubuntu `24.04 LTS`) extends its `DFA` engine far beyond files to mediate `AF_UNIX` abstract/pathname sockets, `D-Bus` method calls, signals, `ptrace`, `io_uring` (`allow io_uring sqpoll`), and crucially *unprivileged user-namespace creation* (`abi <abi/4.0>`, blocking `CLONE_NEWUSER` globally unless an application carries an explicit `userns,` AppArmor profile, analyzed in [Chapter 9](09-capabilities-userns.md)) [63, 85].

### Unprivileged Self-Sandboxing with `Landlock` (`ABI v1` Through `v7`)

Designed by Mickael Salaun and merged beginning in Linux 5.13 (`security/landlock/` [64, 65, 66]), `Landlock` empowers *any unprivileged process* to construct and irreversibly enter a least-privilege sandbox tailored to its own runtime state (for example confining an archive extractor purely to `./output/`, or confining an AI coding agent in [Chapter 17](17-ai-agent-sandboxes.md) to read-only `/usr`, read-write `./repo`, and outbound TCP port `443`).

![Figure: Four-step unprivileged self-confinement workflow in Landlock (ABI v1 through v7), requiring PR_SET_NO_NEW_PRIVS before attaching an immutable ruleset domain across filesystems, TCP ports, device ioctls, and IPC scopes.](diagrams/07-landlock-abi-self-sandbox.svg)

First, why wouldn't letting an unprivileged attacker restrict a process *create* a confused-deputy vulnerability (like old `sendmail` `setuid` capability-dropping bugs, where starving a `SUID-root` child of permissions caused `setuid()` error checks to fail open)? `landlock_restrict_self(2)` unconditionally requires that the calling thread first set the irreversible `no_new_privs` bit via `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` (unless holding `CAP_SYS_ADMIN`), guaranteeing that no subsequent `execve()` can ever acquire `SUID`, `SGID`, or file capabilities [64, 65, 93]! Next, the process invokes three dedicated syscalls:

```c
struct landlock_ruleset_attr attr = {
    .handled_access_fs  = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REFER |
                          LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
    .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
    .scoped             = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
};
int ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
/* Add allowlist rules (PATH_BENEATH on O_PATH dir fds, NET_PORT on TCP ports)... */
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
syscall(__NR_landlock_restrict_self, ruleset_fd, 0);
```

Notice the forward-compatible *handled-access mask* design [64, 65]: any access bit set in `.handled_access_fs`, `.handled_access_net`, or `.scoped` becomes default-deny across the entire system *except* where explicitly allowlisted via `landlock_add_rule()`, while future ABI flags unknown to an older binary remain unhandled so upgrading the host kernel never breaks existing apps! Querying `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns the running kernel's supported ABI integer (`1` through `7`), allowing libraries (`rust-landlock`, `go-landlock`) to gracefully mask flags down to older kernels:

Across five years of rapid upstream engineering, `Landlock` evolved into a comprehensive application sandbox [64, 66]: `ABI v1` (Linux 5.13) introduced directory-hierarchy rules (`LANDLOCK_RULE_PATH_BENEATH`, anchored to kernel `inode` references via `O_PATH` file descriptors rather than fragile strings, walking `dentry->d_parent` upward to the mount root at check time); `ABI v2` (Linux 5.19) added `LANDLOCK_ACCESS_FS_REFER` so cross-directory `rename()` or `link()` can never move a file into a directory granting *broader* permissions than its source; `ABI v3` (Linux 6.2) added `LANDLOCK_ACCESS_FS_TRUNCATE`; `ABI v4` (Linux 6.7) added `LANDLOCK_RULE_NET_PORT` mediating `bind(2)` and `connect(2)` on IPv4/IPv6 TCP ports; `ABI v5` (Linux 6.10) added `LANDLOCK_ACCESS_FS_IOCTL_DEV`, blocking arbitrary `ioctl(2)` commands on character and block devices (defeating terminal-escape attacks such as `TIOCSTI` on inherited `/dev/pts/*` descriptors unless explicitly granted!); `ABI v6` (Linux 6.12) added IPC scoping (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` and `LANDLOCK_SCOPE_SIGNAL`), preventing a sandboxed child from connecting to host abstract `AF_UNIX` sockets (`@dbus-...`, `@X11-...`) or signaling parent processes outside its Landlock domain; and `ABI v7` (Linux 6.15) introduced fine-grained audit control flags so operators can log unexpected denials cleanly without flooding `dmesg` on intentional probes [66]. Up to `16` Landlock domains can stack monotonically inside `cred->security`: a container runtime applies Layer 1, a coding agent applies Layer 2, and a child sub-tool applies Layer 3, enforcing the strict intersection of all layers!

## Distro, Immutable-OS, & Cloud Trade-Offs

Because `SELinux` and `AppArmor` remain mutually exclusive "major" networking/XFRM label users until full networking blob-sharing completes, distributions pick one system-wide MAC (`SELinux` on `RHEL`, `Fedora`, `Amazon Linux 2023`, `Bottlerocket`; `AppArmor` on `Ubuntu`, `Debian`, `SUSE`; `Talos` keeps surface minimal with seccomp/capabilities and optional SELinux) while *almost universally enabling `CONFIG_SECURITY_LANDLOCK=y` alongside it* (`lsm=landlock,lockdown,yama,integrity,apparmor` on Ubuntu 24.04; `lsm=lockdown,capability,yama,selinux,bpf,landlock` on Fedora) [61, 63, 68]. That division of labor is ideal: operators rely on `SELinux` `sVirt` or `AppArmor` to isolate pods and system services externally, while portable cross-distro binaries (`pacman`, `systemd`, `Bubblewrap`/agent CLIs, game servers, document converters) invoke `Landlock` internally so the exact same binary enforces identical confinement on Fedora, Ubuntu, Arch, and Alpine!

## Seam Failures, CVEs, & Structural Bounds

Mandatory Access Control failures rarely stem from bugs in `call_int_hook()`; they occur when admins flip `SELinux` to `Permissive`, leave `unconfined_t` / `spc_t` escape hatches wide open, overlook inherited open file descriptors, or assume `Landlock` replaces `seccomp` Ring 0 attack-surface reduction.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `SELinux` `unconfined_service_t` / `spc_t` Bypass | 2018-2025 | Distro `targeted` policy & `--privileged` pods | `getenforce == Enforcing` means all root processes are confined | Custom systemd service without a `.te` transition runs as `unconfined_service_t`, or `--privileged` pod runs as `spc_t`, bypassing MAC | Author explicit service domains (`udica` / `systemd` sandboxing) and block `spc_t` in Kubernetes admission [62, 68] |
| Pathname Hardlink / Mount Aliasing | 2007-2022 | Naive path-based wrappers (`AppArmor` pre-link rules) | Checking opened path string mediates underlying `inode` | Attacker hardlinks or bind-mounts protected file under an allowed `/tmp` path | Mediate `link`/`rename`/`mount` in `AppArmor` or anchor rules to `inode` labels (`SELinux` / `Landlock`) [62, 63, 64, 67] |
| Pre-Opened File Descriptor Inheritance | Architectural | `Landlock` (`ABI v1..v4`) & `AppArmor` | Restricting `open()` revokes access to already-open `fd`s | Sandboxed child inherits open `O_RDWR` host directory `fd` or TTY `fd` (`ioctl`) from sloppy parent | Close stray descriptors via `close_range(3, ~0U, 0)` before `landlock_restrict_self` and enable `ABI v5` `IOCTL_DEV` [64, 66, 118] |
| `UDP` / Raw Socket & Kernel Syscall Reachability | Architectural | `Landlock` (`ABI v1..v7`) | `Landlock` alone isolates untrusted code from kernel exploits | `Landlock` `ABI v4` mediates TCP `bind`/`connect` (not UDP/ICMP or `io_uring` / `nf_tables` Ring 0 bugs!) | Pair `Landlock` object confinement with `seccomp-BPF` syscall filtering and `network_namespaces` [64, 116] |

Row 3 and Row 4 crystallize two essential invariants when engineering `Landlock` sandboxes [64, 65]. First, *`Landlock` mediates newly requested VFS path walks and connects, plus `ABI v5` device `ioctl`s, but read/write calls on an already-open regular-file `fd` intentionally check `file->f_mode` captured at `open()` time* (standard Unix capability-passing semantics); any sandbox launcher *must* purge unintended open descriptors via `close_range(2)` prior to entering the sandbox! Second, `Landlock`, `SELinux`, and `AppArmor` are *static or semi-static policy engines*: observing process ancestry dynamically or enforcing context-aware runtime telemetry rules calls for `eBPF`, whose dual role as enforcer and attack surface occupies [Chapter 8](08-ebpf-dual-edge.md).

## Inspecting on a Live Linux Host

Inspect the exact ordered list of stacked Linux Security Modules active in the running kernel and check `SELinux` or `AppArmor` enforcement status:

```bash
cat /sys/kernel/security/lsm; echo
getenforce 2>/dev/null || aa-status --summary 2>/dev/null || true
```

Examine the `SELinux` or `AppArmor` security context of your current shell, `PID 1`, and `/etc/shadow`:

```bash
id -Z 2>/dev/null || cat /proc/self/attr/current 2>/dev/null; echo
ls -lZ /etc/shadow 2>/dev/null
```

Query the highest `Landlock` ABI version (`1` through `7`) supported by the running Linux kernel using a one-line Python `syscall` probe (requires zero privileges):

```bash
python3 -c 'import ctypes; c=ctypes.CDLL(None); print("Landlock ABI:", c.syscall(444, None, 0, 1))'
```
