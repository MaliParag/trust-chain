# Stacked Linux Security Modules: SELinux, AppArmor, and Landlock

## Overview

* **Link in the Chain:** Enforces mandatory object-level access control (`SELinux`, `AppArmor`) and unprivileged application self-sandboxing (`Landlock`) across VFS, IPC, device `ioctl`, and socket paths atop the hardened Ring 0 substrate of [Chapters 5](05-kernel-lockdown-modules.md) and [6](06-kernel-memory-rust.md).
* **Core Security Invariant:** Every VFS, socket, IPC, and execution hook dispatched through `lsm_static_calls_table` succeeds only if POSIX Discretionary Access Control (`DAC`) *and* every stacked Linux Security Module (`SELinux` or `AppArmor`, `Landlock`, `IPE`, `Lockdown`, `Yama`, `LSM-BPF`) all return `0`, operating on pinned kernel `inode`, `dentry`, `file`, and `sock` structs partitioned via `lsm_blob_sizes`.
* **Deployment Profile Matrix:** Red Hat ecosystems (`RHEL 9/10`, `Fedora`, `CoreOS`, `Bottlerocket`) enforce `SELinux` (`targeted` Type Enforcement plus `MCS` `sVirt` pod categories); Debian, Ubuntu, and SUSE enforce `AppArmor` packed `DFA` profiles; `Landlock` (`ABI v1` through `v7`+) runs stacked alongside *both* `SELinux` and `AppArmor` so unprivileged daemons, package managers, and AI CLI agents self-sandbox without `root`.
* **Trusted Computing Base (TCB):** Linux `security/security.c` and `include/linux/lsm_hooks.h` (`lsm_blob_sizes`, `lsm_static_calls_table`), `security/selinux/avc.c` and `ss/services.c`, `security/apparmor/match.c` (`struct aa_dfa`), `security/landlock/` ruleset evaluators, VFS `dentry`/`inode` resolution, and `CAP_MAC_ADMIN` policy loaders.
* **Integration Seam & Handoff:** Confines compromised `UID 0` daemons and container pods (`SELinux` `MCS` / `AppArmor`) alongside unprivileged parsers (`Landlock`) to explicit files, TCP ports, device `ioctl`s, and IPC scopes; pairs with programmable `LSM-BPF` enforcement in [Chapter 8](08-ebpf-dual-edge.md) and capability/daemon isolation in [Chapters 9](09-capabilities-userns.md) through [11](11-systemd-dbus-sandboxing.md).

## Problem Statement & Threat Model

Classical Unix Discretionary Access Control (`DAC`) suffers from two congenital flaws that no combination of `chmod` mode bits or POSIX ACLs can cure [13, 56, 251]. First, ownership is *discretionary and ambient*: whichever `UID` owns an inode (`inode->i_uid == cred->fsuid`) may freely relax its permissions, and every program spawned under `UID 1000` (whether an SSH agent, a browser helper, a PDF thumbnailer, or an autonomous coding CLI running `npm install`) inherits `UID 1000`'s *entire* authority over `~/.ssh`, `~/.aws`, browser cookies, and local sockets. Second, `DAC` treats `UID 0` (`CAP_DAC_OVERRIDE`) as omnipotent: if a network-facing service or misconfigured container running as `UID 0` suffers remote code execution, `DAC` interposes zero separation between that process and `/etc/shadow` or `/var/lib/kubelet` [56, 252].

Linux Mandatory Access Control (`MAC`) modules, introduced via the 2002 Linux Security Modules (`LSM`) hook framework (`Wright et al.` [13]) and led by `SELinux` [56, 253] and `AppArmor` [57, 254], closed the `UID 0` omnipotence gap for system daemons and containers while leaving two painful architectural limitations for nearly two decades [10, 47, 255]. First, kernel objects (`struct cred`, `struct inode`, `struct file`, `struct sock`) historically exposed a single raw `void *security` pointer claimed exclusively by one "major" LSM at boot, preventing operators from composing multiple stateful security models simultaneously [47, 255]. Second, authoring and loading `SELinux` policies or `AppArmor` profiles requires global `root` (`CAP_MAC_ADMIN`) [10]. An unprivileged binary (`tar`, `git`, `ffmpeg`, `pacman`, or an AI coding CLI) could not ship portable built-in sandboxing without asking administrators to maintain distro-divergent `.te` policy modules on Fedora and `/etc/apparmor.d/` profiles on Ubuntu [10, 256].

Modern Linux resolves both barriers inside Casey Schaufler's infrastructure-managed LSM stacking architecture (`security/security.c` [47, 255, 257]). Against an adversary exploiting a privileged daemon, breaking out of a container runtime, or feeding weaponized inputs into an unprivileged parser, host administrators enforce non-bypassable system boundaries via `SELinux` (Type Enforcement plus `MCS` pod categories [252, 258]) or `AppArmor` (`DFA` path, IPC, and `userns` mediation [57, 259]), while unprivileged applications layer up to `16` monotonic `Landlock` (`ABI v1` through `v7`+) self-sandboxes directly onto their own `struct cred` with zero `root` privileges [10, 260, 261].

## Kernel & Userspace Mechanics

### Infrastructure-Managed Security Blobs (`lsm_blob_sizes`) and Static Call Dispatch

Enabling `SELinux` or `AppArmor` alongside `Landlock`, `Lockdown`, `Yama`, `IPE`, and `LSM-BPF` required refactoring who owns the `security` pointer on kernel structures [47, 255, 257]. Rather than letting one LSM write its private struct pointer directly into `cred->security`, every LSM declares a `DEFINE_LSM()` descriptor (`include/linux/lsm_hooks.h` [257]) specifying its `struct lsm_id` (`uapi/linux/lsm.h`, such as `LSM_ID_SELINUX = 100`, `LSM_ID_APPARMOR = 102`, `LSM_ID_LANDLOCK = 105` [262]), `enum lsm_order` (`LSM_ORDER_FIRST` reserved for `capability`, `LSM_ORDER_MUTABLE` for MAC/sandbox modules, `LSM_ORDER_LAST`), and a `struct lsm_blob_sizes` reservation:

```c
/* include/linux/lsm_hooks.h: Size requested pre-init -> byte offset post-init! */
struct lsm_blob_sizes {
    unsigned int lbs_cred, lbs_file, lbs_inode, lbs_sock, lbs_superblock;
    unsigned int lbs_ipc, lbs_msg_msg, lbs_task, lbs_xattr_count;
    unsigned int lbs_bpf_map, lbs_bpf_prog, lbs_bpf_token;
};
```

During early boot (`ordered_lsm_init()` in `security/security.c` [47, 257]), the kernel parses `CONFIG_LSM` (or the boot `lsm=` parameter), sums each active module's requested byte count into a global `blob_sizes` total, and *overwrites each module's `lbs_*` field in-place with its assigned starting byte offset* inside the shared blob! When `prepare_creds()` allocates `cred->security` from `lsm_cred_cache`, `SELinux` reads `cred->security + selinux_blob_sizes.lbs_cred` (e.g., offset `0`), `Landlock` reads `cred->security + landlock_blob_sizes.lbs_cred` (e.g., offset `16`), and `BPF` reads `cred->security + bpf_lsm_blob_sizes.lbs_cred` (offset `32`) with zero pointer collisions [47, 257]. Similarly, Linux 6.8+ introduced dedicated LSM syscalls (`lsm_list_modules(2)`, `lsm_get_self_attr(2)`, and `lsm_set_self_attr(2)` [262]) returning packed arrays of `struct lsm_ctx` tagged by `LSM_ID_*`, retiring the old single-tenant `/proc/self/attr/current` bottleneck.

To eliminate indirect-call (`retpoline` and `KCFI`) latency across 200+ VFS and socket hooks, Linux 6.12+ replaced linked-list hook iteration (`hlist_for_each_entry` over `security_hook_heads`) with KP Singh and Brendan Jackman's `lsm_static_calls_table` (`__ro_after_init` [263]). At boot, active LSM callbacks are patched into direct architecture `static_call` instructions (`call selinux_file_open`, `call landlock_file_open`, `call bpf_lsm_file_open`) sealed read-only in page tables. Every integer hook enforces strict restrictive conjunction:

$$\operatorname{Allow}(\text{op}) \iff \operatorname{DAC}(\text{op}) = 0 \;\land\; \bigwedge_{m \in \mathcal{M}_{\text{active}}} h_m(\text{op}) = 0$$

The first module returning `-EACCES` or `-EPERM` aborts the operation immediately; no stacked LSM can ever *widen* privileges denied by `DAC` or a peer module [47, 257].

![Figure: Architectural comparison matrix across SELinux (inode label MAC + MCS), AppArmor (VFS path profile MAC), and Landlock (unprivileged fd-hierarchy and TCP/IPC self-sandboxing) composed under stacked LSM hook evaluation.](diagrams/07-lsm-hook-stacking-matrix.svg)

### `SELinux` Flask Architecture: Lockless `AVC`, Type Enforcement, and `MCS` Pod Isolation

Originating in the NSA/SCC Flux Advanced Security Kernel (`Flask` architecture by Spencer et al. [251] and Loscocco & Smalley [253]), `SELinux` (`security/selinux/` [56]) cleanly separates *policy enforcement* inside kernel object managers from *policy decisions* inside the Security Server (`security/selinux/ss/services.c` [258]). Every subject (`task_struct` `cred`) and every kernel object (`inode`, `file`, `sock`, `ipc`, network port) carries a structured security context `user:role:type:level` (for example `system_u:object_r:shadow_t:s0`), interned inside the kernel's `sidtab` hash table as a compact 32-bit integer Security Identifier (`SID`) [56, 258]. On disk-backed filesystems (`ext4`, `xfs`, `btrfs`, `overlayfs`), labels persist atomically inside the `security.selinux` extended attribute written during inode creation (`security_inode_init_security()` via `lsm_get_xattr_slot()` [257]), while pseudo-filesystems synthesize `SID`s deterministically via `genfscon` (`procfs`, `sysfs`) or `fs_use_trans` (`devpts`, `tmpfs`, `mqueue`).

Evaluating binary policy rules on every `read(2)` or `openat(2)` would cripple VFS throughput, so `security/selinux/avc.c` interposes an RCU-protected, lockless *Access Vector Cache* (`AVC` [264]):

![Figure: SELinux Flask Access Vector Cache (AVC) fast-path lookup on (ssid, tsid, tclass) paired with Security Server Type Enforcement (TE) avtab lookup and Multi-Category Security (MCS) ebitmap dominance isolating Kubernetes pods and sVirt VMs.](diagrams/07-extra-selinux-mcs-avc-flow.svg)

When VFS invokes `selinux_file_open()`, `avc_has_perm_noaudit(ssid, tsid, SECCLASS_FILE, requested, ...)` hashes the `(ssid, tsid, tclass)` triple across `512` RCU hash buckets (`AVC_CACHE_SLOTS`) [264]. On the $>99.9\%$ hit path, the CPU tests `(requested & node->ae.avd.allowed) == requested` in nanoseconds without acquiring a single spinlock! When fine-grained device or socket `ioctl(2)` filtering is active in policy (`allowxperm`), `avc.c` additionally evaluates 256-bit `extended_perms_data` bitmaps (`avc_xperms_has_perm()` [264]), splitting the 16-bit `ioctl` command integer into its high 8-bit driver type and low 8-bit function number so `SELinux` (most visibly on Android and hardened `RHEL` appliances) can permit benign `TIOCGWINSZ` window-size queries while denying dangerous driver-specific `ioctl` numbers on the exact same character device! Only on an `AVC` miss does control enter `security_compute_av()` in `ss/services.c` [258] to query the compiled Type Enforcement (`TE`) `avtab` (`allow httpd_t httpd_sys_content_t : file { open read getattr map };`) before caching the resulting `av_decision` node under RCU. Because `SELinux` mediates the underlying `inode`'s `tsid` rather than its string path, hardlink and bind-mount aliasing fail unconditionally: hardlinking `/etc/shadow` (`shadow_t`) to `/var/www/html/index.html` leaves the inode's `shadow_t` xattr untouched, denying `httpd_t` with `-EACCES` [56, 105].

How does `SELinux` isolate hundreds of Kubernetes pods or `KVM` virtual machines on a single node without compiling hundreds of bespoke `.te` policy modules? Through *Multi-Category Security* (`MCS` in `security/selinux/ss/mls.c` [258]), pioneered by James Morris and Daniel Walsh for `sVirt` [252] and enforced across `OpenShift`, `RHEL`, `Fedora`, and `Bottlerocket` container runtimes (`CRI-O`, `Podman`, `containerd`) [265, 266]. Every unprivileged container runs under the *same* `container_t` Type Enforcement domain (which allows reading shared `usr_t` / `container_ro_file_t` image layers while forbidding writes to host `etc_t`, `var_lib_t`, or `shadow_t`), paired with a *unique* randomly chosen 2-category `MCS` label `s0:cX,cY` drawn from `1,024` categories (`c0` through `c1023`), yielding:

$$\binom{1024}{2} = \frac{1024 \times 1023}{2} = 523{,}776 \text{ mutually isolated category pairs}$$

The container runtime labels Pod A's private writable volumes `container_file_t:s0:c12,c45` (accelerated on Kubernetes `1.32+` via `SELinuxMount` `ReadWriteOncePod` mount options `-o context=...` so terabyte persistent volumes mount instantaneously without recursive `chcon` walks [266]) and Pod B's volumes `container_file_t:s0:c88,c209`. Inside `mls.c`, `ebitmap_contains(&subj_cat, &obj_cat)` enforces strict category dominance ($\text{cat}(\text{subj}) \supseteq \text{cat}(\text{obj})$) [258]: even if an attacker achieves `UID 0` code execution inside Pod A and exploits a `runc` descriptor leak or symlink race (`CVE-2024-21626` in [Chapter 14](14-containers-escapes.md)), Pod A's `s0:c12,c45` subject fails dominance against both host `s0` `etc_t` TE rules and Pod B's `s0:c88,c209` volumes! Only pods recklessly launched with `--privileged` or `securityContext.seLinuxOptions.type: spc_t` (`Super Privileged Container`) bypass `MCS` containment, which is why production clusters generate narrower custom domains via `udica` [267] and ban `spc_t` in admission controllers [265, 266].

### `AppArmor` Packed `DFA` State Machines, Hardlinks, and Mount Namespaces

Evolving from WireX's `SubDomain` (`Cowan et al.` [254]) into mainline `security/apparmor/` (`Johansen` [57, 259]), `AppArmor` deliberately eschews on-disk `security.*` extended attributes in favor of *pathname- and IPC-profile mediation*. Administrators write readable profiles in `/etc/apparmor.d/` (`abi <abi/4.0>,`, `/usr/sbin/nginx { /var/www/** r, network inet stream, }`), which userspace `apparmor_parser` compiles into binary *Deterministic Finite Automata* (`struct aa_dfa` in `security/apparmor/include/match.h`, header magic `YYTH_MAGIC = 0x1B5E783D` [259]). Inside Ring 0, `struct aa_dfa` stores GNU `flex`-style compressed sparse transition arrays (`BASE`, `NEXT`, `CHECK`, `DEFAULT`, byte-equivalence classes `EQUIV`, and `ACCEPT` permission tables with differential state encoding `YYTH_FLAG_DIFF_ENCODE`). When a confined task opens a file, `AppArmor` reconstructs the canonical namespace-relative path string from VFS `(struct vfsmount *, struct dentry *)` via `d_namespace_path()` and steps `aa_dfa_match()` over that string in a single $O(|\text{path}|)$ pass with zero regex backtracking [57, 259].

Trading inode labels for VFS path strings eliminates filesystem relabeling entirely (`tar`, `rsync`, and `NFS` work out of the box), while introducing two subtle structural edge cases analyzed by Andreas Gruenbacher, John Johansen [268], and Robert Watson [105]:
First, *hardlink aliasing*: because POSIX permits multiple directory entries (`dentry`s) on the same filesystem to reference one `inode`, a naive path filter allowing `/tmp/** r` while denying `/etc/secret` would fail if an attacker executed `link("/etc/secret", "/tmp/public_copy")`. `AppArmor` closes this gap by hooking `security_path_link()` (`aa_path_link()`): creating a hardlink is permitted only if the confined caller's `DFA` already grants equivalent subset permissions on the *existing target path* as on the proposed link path, paired with kernel `fs.protected_hardlinks = 1` blocking unprivileged users from hardlinking files they do not own [57, 268].
Second, *mount namespaces, `pivot_root()`, and deleted files*: two tasks in different `mnt_namespace` instances resolve `/etc/passwd` to completely different underlying `vfsmount` trees. `AppArmor` handles namespace roots via `PATH_CHROOT_REL` flags inside `d_namespace_path()` and mediates `mount(2)`/`pivot_root(2)` rules explicitly inside the profile's `DFA`, while `PATH_MEDIATE_DELETED` ensures unlinked open files re-opened through `/proc/self/fd/N` remain bound to their original mediated path permissions [57, 259]. In `AppArmor 4.0+` (`Ubuntu 24.04 LTS+`), the exact same `aa_dfa` engine mediates `AF_UNIX` abstract sockets, `D-Bus` bus/interface/member tuples, `io_uring` (`allow io_uring sqpoll`), and unprivileged `CLONE_NEWUSER` creation (`userns,` profiles dissected in [Chapter 9](09-capabilities-userns.md)) [57].

### Unprivileged Self-Sandboxing with `Landlock` (`ABI v1` Through `v7`+)

Authored by Mickael Salaun (`security/landlock/` [10, 260]), `Landlock` solves the developer's dilemma: *unprivileged, stackable, cross-distro application self-sandboxing*. Unlike `AppArmor` strings or `SELinux` on-disk xattrs, `Landlock` anchors filesystem rules to live kernel `struct inode` objects (`struct landlock_object`) referenced via `O_PATH` file descriptors (`LANDLOCK_RULE_PATH_BENEATH`) and stores compiled rulesets inside balanced red-black trees (`struct rb_root root_inode`, `root_net_port` in `security/landlock/ruleset.c` [260]).

![Figure: Four-step unprivileged self-confinement workflow in Landlock (ABI v1 through v7), requiring PR_SET_NO_NEW_PRIVS before attaching an immutable ruleset domain across filesystems, TCP ports, device ioctls, and IPC scopes.](diagrams/07-landlock-abi-self-sandbox.svg)

To prevent an unprivileged attacker from weaponizing partial restrictions against a `SUID-root` child (the classic confused-deputy attack where denying a resource causes privileged error handling to fail open), `landlock_restrict_self(2)` mandates that the caller first set `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` unless holding `CAP_SYS_ADMIN` [10, 260]. Moreover, `Landlock` guarantees strict forward and backward kernel compatibility through explicit *handled-access bitmasks* [10]: setting a bit in `.handled_access_fs`, `.handled_access_net`, or `.scoped` switches that specific right to *default-deny* across the entire task subtree unless exempted via `landlock_add_rule(2)`, whereas newer kernel rights omitted by an older binary remain untouched. Applications query `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` and mask unsupported flags cleanly via fallthrough switches [10]:

```c
int abi = syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
struct landlock_ruleset_attr attr = {
    .handled_access_fs  = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                          LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REFER |
                          LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV,
    .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
    .scoped             = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL,
};
if (abi < 6) attr.scoped = 0;
if (abi < 5) attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;
if (abi < 4) attr.handled_access_net = 0;
```

Tracing `Landlock`'s seven foundational ABI releases (plus its `Linux 7.x` extensions) illustrates systematic closure of sandbox escape vectors [10, 260, 261, 269, 270, 271, 272]:
`ABI v1` (`Linux 5.13`) introduced 13 directory-hierarchy rights (`EXECUTE`, `READ_FILE`, `WRITE_FILE`, `READ_DIR`, `REMOVE_*`, `MAKE_*`), evaluated in `security/landlock/fs.c` by walking `dentry->d_parent` upward across mount boundaries to the root while tracking up to `LANDLOCK_MAX_NUM_LAYERS = 16` nested domains using compact 16-bit `layer_masks_t` bitmasks [260].
`ABI v2` (`Linux 5.19`) added `LANDLOCK_ACCESS_FS_REFER` (`Gunther Noack` and `Salaun` [269]), blocking cross-directory `renameat2()` or `linkat()` by default and allowing file reparenting only when *both* directories carry `REFER` and the destination grants no broader access rights than the source!
`ABI v3` (`Linux 6.2`) added `LANDLOCK_ACCESS_FS_TRUNCATE` mediating `truncate(2)`, `ftruncate(2)`, and `open(O_TRUNC)` [269].
`ABI v4` (`Linux 6.7`) added `LANDLOCK_RULE_NET_PORT` (`security/landlock/net.c` by `Konstantin Meskhidze` [270]), mediating IPv4/IPv6 TCP `bind(2)` (`NET_BIND_TCP`) and `connect(2)` (`NET_CONNECT_TCP`) per port (e.g., restricting an AI agent CLI strictly to outbound port `443`).
`ABI v5` (`Linux 6.10`) added `LANDLOCK_ACCESS_FS_IOCTL_DEV` (`Gunther Noack` [271]), blocking arbitrary device-driver `ioctl(2)` commands on character and block special files (neutralizing terminal pushback `TIOCSTI` or GPU `/dev/dri/renderD128` `ioctl` exploits on inherited descriptors while still permitting safe generic `FIOCLEX`/`FIONBIO` descriptor operations).
`ABI v6` (`Linux 6.12`) added `.scoped` IPC isolation (`Tahera Fahimi` and `Salaun` [272]): `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` blocks a sandboxed task from connecting to host abstract `AF_UNIX` sockets (`\0/tmp/.X11-unix/...`, `@dbus-...`) created outside its Landlock domain, while `LANDLOCK_SCOPE_SIGNAL` blocks `kill(2)`, `tgkill(2)`, and `sigqueue(3)` targeting processes in ancestor domains.
`ABI v7` (`Linux 6.15`) introduced structured kernel audit records (`AUDIT_LANDLOCK_ACCESS` and `AUDIT_LANDLOCK_DOMAIN` [261]) controlled by `landlock_restrict_self` flags (`LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`, `LOG_NEW_EXEC_ON`, `LOG_SUBDOMAINS_OFF`) so self-sandboxing binaries silence expected denials in their own code while logging unexpected post-`execve()` exploit attempts, followed in `Linux 7.0+` (`ABI v8`..`v10`) by multithreaded `LANDLOCK_RESTRICT_SELF_TSYNC`, named UNIX socket connect control, and UDP port mediation [10]. Internally, whenever a thread calls `landlock_restrict_self(ruleset_fd, flags)`, `landlock_merge_ruleset()` inside `security/landlock/ruleset.c` clones the caller's existing multi-layer domain (if already sandboxed), increments the hierarchy depth counter (rejecting depth $> 16$ with `-E2BIG`), and attaches an immutable reference-counted `landlock_ruleset` snapshot into a newly prepared `struct cred` via `commit_creds()` [260]. Because stacked rulesets are strictly copy-on-restrict and immutable once committed, rule evaluation during `openat()` or `connect()` reads the red-black trees completely locklessly, scaling across hundred-core servers without cache-line contention across sibling processes [260].

## Distro, Immutable-OS, & Cloud Trade-Offs

Because `SELinux` and `AppArmor` still carry `LSM_FLAG_LEGACY_MAJOR` over networking `sk_buff` / `secmark` peer labeling until networking blob-sharing completes upstream [255, 257], distributions select one host-wide MAC (`SELinux` across `RHEL 9/10`, `Fedora 41+`, `CoreOS`, `Amazon Linux 2023`, and `Bottlerocket`; `AppArmor` across `Ubuntu 24.04+`, `Debian`, and `SUSE`) while *universally stacking `Landlock`, `Yama`, `Lockdown`, and `BPF` alongside it*:

| Attribute | `SELinux` (`TE` + `MCS`) | `AppArmor` (`4.0+` `DFA`) | `Landlock` (`ABI v1..v7+`) |
|---|---|---|---|
| Object Anchor | Persistent `inode` xattr (`SID`) | Namespace VFS path string (`DFA`) | Kernel `inode` hierarchy + TCP/IPC |
| Privilege to Load Policy | Host `root` (`CAP_MAC_ADMIN`) | Host `root` (`CAP_MAC_ADMIN`) | Unprivileged (`PR_SET_NO_NEW_PRIVS`) |
| Hardlink / Rename Immunity | Native (`inode`-bound `tsid`) | Requires `security_path_link` rules | Native + `ABI v2` `FS_REFER` check |
| Container / Pod Multi-Tenancy | `sVirt` `MCS` ($523{,}776$ pairs) | Per-container `AppArmor` profile | Up to `16` nested ruleset layers |
| Cross-Distro Binary Portability | Host policy-dependent | Host policy-dependent | 100% self-contained inside app binary |

This architectural division of labor lets platform engineers enforce outer host/pod isolation via `SELinux` `MCS` or `AppArmor` while application authors (`systemd`, `pacman`, `tar`, Justine Tunney's cross-platform `pledge()`/`unveil()` library [256], and coding agent sandboxes in [Chapter 17](17-ai-agent-sandboxes.md)) embed `Landlock` directly inside their binaries so identical least-privilege rules execute on Fedora, Ubuntu, Alpine, and Arch alike. Across immutable cloud operating systems, MAC design couples tightly with verified root filesystems ([Chapter 3](03-luks2-verity.md)): `Fedora CoreOS`, `RHEL Image Mode` (`bootc`), and AWS `Bottlerocket` bake `security.selinux` extended attributes directly into immutable `composefs` or `dm-verity` root images at build time [265]. In `Bottlerocket`, `SELinux` runs in strict `Enforcing` mode with zero `unconfined_t` login shells, partitioning administrative debugging into a dedicated `control` container (`control_t`) and host break-glass into an `admin` container while locking tenant Kubernetes pods inside `container_t` `MCS` categories [252, 265]. On `Ubuntu 24.04 LTS+` cloud nodes, `systemd` pre-loads pre-compiled binary `AppArmor` `DFA` blobs from `/var/cache/apparmor/` during early boot so confining `containerd`, `chronyd`, and unprivileged `userns` boundaries adds zero policy-compilation jitter to instance launch times [57, 259].

## Seam Failures, CVEs, & Structural Bounds

Stacked LSM compromises almost never stem from flaws in `security.c` conjunction logic; instead, adversaries exploit unconfined policy domains, inherited pre-opened file descriptors, multithreaded `restrict_self` gaps on older kernels, or raw Ring 0 syscalls untouched by VFS/TCP object hooks.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `SELinux` `unconfined_service_t` Escape | 2018-2025 | Distro `targeted` `.te` policy | `Enforcing` mode confines every `root` daemon automatically | Custom systemd unit lacking an `init_daemon_domain` transition executes as `unconfined_service_t`, bypassing TE | Generate explicit service/container policies (`udica`) and audit `ps -eZ | grep unconfined` [56, 267] |
| `--privileged` / `spc_t` Pod Breakout | 2019-2025 | Kubernetes / `CRI-O` `sVirt` | Node `SELinux` blocks container-escape file writes | Pod launched with `spc_t` (`label=disable`) holds `MCS` exemption, overwriting host `/etc/crontab` on escape | Enforce Kubernetes Pod Security Admission banning `privileged: true` and `spc_t` [252, 265, 266] |
| Pathname Hardlink & `TOCTOU` Aliasing | 2007-2022 | Naive path wrappers & early path MAC | Checking `open()` path string protects underlying `inode` | Attacker hardlinks restricted file into allowed `/tmp` path or swaps user-memory path pointer mid-syscall | Evaluate hooks on kernel `dentry`/`inode` structs, mediate `path_link`, and set `fs.protected_hardlinks=1` [105, 268] |
| `AppArmor` Unprofiled Helper Bypass | 2024 | Ubuntu `userns` `AppArmor` profiles | Blocking unprofiled `CLONE_NEWUSER` stops local exploit chains | Unprivileged user invokes a broadly profiled helper (`bwrap` or `aa-exec` transitions) to enter a `user_ns` | Tighten child `px`/`cx` transition rules in `/etc/apparmor.d/` (`Ubuntu 24.04.1+`) [57, 259] |
| Inherited Open `fd` Sandbox Escape | Architectural | `Landlock` (`ABI v1..v4`) & `AppArmor` | Restricting `openat()` revokes pre-existing `struct file` handles | Child inherits open read-write directory `fd` (`openat(dir_fd, ...)` outside hierarchy) or `/dev/pts/0` `TIOCSTI` | Call `close_range(3, ~0U, CLOSE_RANGE_UNSHARE)` before `landlock_restrict_self` and enable `ABI v5` `IOCTL_DEV` [10, 271] |
| Abstract `AF_UNIX` Host Bus Pivot | 2021-2024 | `Landlock` pre-`ABI v6` (`< 6.12`) | Filesystem rules block all UNIX domain sockets | Abstract sockets (`sun_path[0] == '\0'`) live in `net_ns` memory outside VFS, reaching host `@dbus` or X11 | Enforce `ABI v6` `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` or unshare `CLONE_NEWNET` [272] |
| Per-Thread `landlock_restrict_self` Gap | 2021-2025 | Multithreaded Go/JVM runtimes (`< ABI v8`) | Calling `landlock_restrict_self` in `main` confines sibling OS threads | POSIX threads created prior to `restrict_self` retain the parent's un-sandboxed `struct cred` | Apply `Landlock` prior to spawning runtime threads or pass `LANDLOCK_RESTRICT_SELF_TSYNC` (`ABI v8+`) [10, 260] |
| Non-TCP & Syscall Surface Reachability | Architectural | `Landlock` (`ABI v1..v7`) | Object sandboxing prevents Ring 0 exploitation | Sandboxed parser still reaches `io_uring`, `keyctl`, `bpf`, or `UDP`/raw sockets (`pre-ABI v10`) | Always pair `Landlock` with `seccomp-BPF` syscall allowlists ([Chapter 14](14-containers-escapes.md)) [10, 256] |

### Structural Bounds of Static LSM Policies

Rows 5 through 8 underscore three deep architectural subtleties when composing `SELinux`, `AppArmor`, and `Landlock` [10, 256, 260, 264]. First, `SELinux` and `Landlock` diverge deliberately on *post-`open()` revocation semantics*: `SELinux` hooks `security_file_permission()` on `read(2)` and `write(2)` so if a `struct file` is passed across `execve()` or `SCM_RIGHTS` into a more restricted `SELinux` domain (or if a policy reload increments `latest_notif` in `avc.c` [264]), subsequent reads on the already-open `fd` are re-checked and denied `-EACCES`. By contrast, `Landlock` intentionally follows object-capability (`Capsicum`-style) descriptor semantics for regular files: once a trusted parent opens a file for reading and passes that `fd` to a `Landlock`-restricted worker, `read(fd)` succeeds, whereas `openat(dir_fd, "escape", ...)` and `ABI v5` device `ioctl(tty_fd, ...)` are actively mediated [10, 271]. Consequently, any `Landlock` sandbox launcher *must* purge unintended descriptors (`close_range(3, ~0U, CLOSE_RANGE_UNSHARE)`) and lock rules *before* spawning worker threads (or pass `LANDLOCK_RESTRICT_SELF_TSYNC` on `ABI v8+`) [10, 260].

Second, `Landlock`'s upward `dentry->d_parent` walk in `security/landlock/fs.c` (`collect_domain_accesses()`) carefully respects mount topology: bind-mounting `/etc` underneath `/sandbox/allowed/etc` does *not* accidentally inherit `/sandbox/allowed`'s permissions across mount-point transitions unless the ruleset explicitly granted rights on the mounted hierarchy or its ancestor mount before restriction, and `ABI v2` `LANDLOCK_ACCESS_FS_REFER` blocks exfiltrating or planting files via cross-directory `renameat2()` [260, 269]. Third, `SELinux`, `AppArmor`, and `Landlock` remain *declarative object-mediation engines*: none of them can inspect arbitrary syscall arguments, correlate multi-process parent-child execution chains (`nginx` spawning `sh` spawning `curl`), or update threat rules dynamically across a 10,000-node cluster without recompiling host policy. Enforcing programmable, context-aware runtime security inside Ring 0 requires `eBPF` and `LSM-BPF`, whose dual nature as inline defender and verifier attack surface defines [Chapter 8](08-ebpf-dual-edge.md).

## Inspecting on a Live Linux Host

Live LSM verification inspects the active boot stacking order, `SELinux` `AVC` and `MCS` container labels (or `AppArmor` `DFA` profile counts), and the kernel's `Landlock` ABI level.

Inspect the exact ordered list of stacked Linux Security Modules active in `security/security.c` and check `SELinux` or `AppArmor` enforcement state:

```bash
cat /sys/kernel/security/lsm; echo
getenforce 2>/dev/null || aa-status --summary 2>/dev/null | head -n 6 || true
```

Representative output on `Fedora 41+` (`SELinux` + `Landlock` + `BPF`) vs. `Ubuntu 24.04+` (`AppArmor` + `Landlock`):

```text
lockdown,capability,yama,selinux,bpf,landlock,ipe
Enforcing
```

Inspect `SELinux` subject/object labels (`MCS` categories on running containers and `shadow_t` on `/etc/shadow`) plus live lockless `AVC` hash statistics:

```bash
id -Z 2>/dev/null || cat /proc/self/attr/current 2>/dev/null; echo
ls -lZ /etc/shadow 2>/dev/null
cat /sys/fs/selinux/avc/hash_stats 2>/dev/null || true
```

Representative output showing `shadow_t` inode isolation and `512`-bucket `AVC` occupancy:

```text
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
-rw-------. 1 root root system_u:object_r:shadow_t:s0 1248 Oct 14 09:12 /etc/shadow
entries: 508
buckets used: 284/512
longest chain: 6
```

Query the highest `Landlock` ABI version (`1` through `7`+) supported by the running kernel via `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` (requires zero privileges) and check kernel boot logs:

```bash
python3 -c 'import ctypes, platform; sc = 444 if platform.machine()=="x86_64" else 276; print("Landlock ABI:", ctypes.CDLL(None).syscall(sc, None, 0, 1))'
journalctl -kb -g "landlock: Up and running" --no-pager 2>/dev/null | tail -n 2 || true
```

An output of `Landlock ABI: 6` or `7` (on `Linux 6.12` through `6.15+`) confirms support for filesystem hierarchies (`v1`), `FS_REFER` (`v2`), `TRUNCATE` (`v3`), TCP port control (`v4`), `IOCTL_DEV` (`v5`), abstract UNIX/signal scoping (`v6`), and audit control flags (`v7`).

Enumerate the numeric `LSM_ID_*` identifiers active on `Linux 6.8+` via `lsm_list_modules(2)` (`syscall 459` on `x86_64`) and audit unconfined `root` daemons:

```bash
ps -eZ 2>/dev/null | awk '$1 ~ /unconfined_service_t/ {print $1, $4, $5}' | head -n 8 || true
sysctl fs.protected_hardlinks fs.protected_symlinks 2>/dev/null
```

Any long-running network daemon appearing under `unconfined_service_t` bypasses `SELinux` Type Enforcement and should be transitioned into a dedicated service policy or `systemd` sandbox, while `fs.protected_hardlinks = 1` blocks unprivileged cross-owner hardlink aliasing across both `SELinux` and `AppArmor` hosts.

