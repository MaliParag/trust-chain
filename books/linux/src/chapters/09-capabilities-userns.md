# POSIX Capabilities and the Unprivileged User Namespace Surface

## Overview

* **Link in the Chain:** Opens Part III by governing how userspace processes hold and transform fine-grained kernel privileges (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`) and how unprivileged user namespaces (`CLONE_NEWUSER`) remap those capabilities across container and sandbox boundaries.
* **Core Security Invariant:** Across every `execve()` and `capset()` transition, a thread's effective capabilities remain bounded by its permitted set ($P_E \subseteq P_P$) and ambient inheritance invariants ($P_A \subseteq P_P \cap P_I$), while global Ring 0 operations verify `capable(cap)` against `init_user_ns` rather than trusting `ns_capable(child_ns, cap)` on shared kernel memory allocators.
* **Deployment Profile Matrix:** Traditional distros historically enabled unrestricted unprivileged `CLONE_NEWUSER` (`Ubuntu 24.04+` now gates `CLONE_NEWUSER` behind `AppArmor` `apparmor_restrict_unprivileged_userns=1`, while `RHEL 8/9/10` supports `user.max_user_namespaces`); immutable Kubernetes OSes (`Talos`, `Bottlerocket`) drop container `CapBnd` to a minimal set (or zero!) and disable `io_uring`/unused `netfilter` modules.
* **Trusted Computing Base (TCB):** Linux `security/commoncap.c` capability transition engine, `kernel/user_namespace.c` UID/GID extent mapper, `ns_capable()` vs. `capable()` checks across every subsystem (`net/netfilter/nf_tables_api.c`, `fs/overlayfs/`), and `AppArmor` / `sysctl` `userns` admission gates.
* **Integration Seam & Handoff:** Explains why coarse root-equivalent capabilities (`CAP_SYS_ADMIN`) and unprivileged `CLONE_NEWUSER` became the primary Ring 0 LPE trampoline; hands off clean-room privilege elevation without `SUID` to [Chapter 10](10-suid-to-run0.md) and service/container confinement to [Chapters 11](11-systemd-dbus-sandboxing.md) and [14](14-containers-escapes.md).

## Problem Statement & Threat Model

Classical Unix knew only two security levels in userspace: omnipotent `UID 0` (`root`), which bypassed every permission check in the kernel, and everyone else (`UID > 0`) [78]. Whenever a utility needed a single narrow privilege: `ping` opening an `ICMP` socket, `chronyd` adjusting the system clock, or `dnsmasq` binding UDP port `53`: designers had to either run the entire daemon as `UID 0` or stamp the `SUID-root` bit (`chmod u+s`) onto the executable, handing an attacker complete machine control if a single buffer overflow occurred anywhere in the binary.

POSIX.1e draft capabilities (implemented in Linux starting in 2.2 and extended with filesystem xattrs and ambient sets in `security/commoncap.c` [78]) sought to fracture `root` into orthogonal least-privilege bits (`CAP_NET_RAW`, `CAP_SYS_TIME`, `CAP_NET_BIND_SERVICE`, now numbering 41 capabilities from `0` through `40`). Two decades of real-world deployment and kernel exploitation exposed two severe architectural traps in how Linux capabilities compose with the rest of the kernel [79, 80, 81]. First, as `grsecurity` author Brad Spengler demonstrated [79], nearly half of Linux's capabilities (`CAP_SYS_ADMIN`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, `CAP_BPF`, `CAP_SETUID`, `CAP_FOWNER`) are *trivially root-equivalent* on a standard Linux host: granting a service `CAP_DAC_READ_SEARCH` lets it read `/etc/shadow` or escape container `chroot`s via `open_by_handle_at(2)`, while `CAP_SYS_ADMIN` became a catch-all dumping ground gating over a third of all privileged kernel calls (`mount`, `swapon`, `quotactl`, `ioctl`s) [78, 79]!

Second, and far more pervasively, Linux 3.8 introduced *unprivileged user namespaces* (`CLONE_NEWUSER` [80]) so non-root users could run rootless containers (`Podman`), Flatpak desktop apps, and Chromium/Firefox browser sandboxes without `SUID` helpers. Inside a freshly unshared `user_namespace` paired with a network or mount namespace (`unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)`), an unprivileged `UID 1000` attacker instantaneously receives all 41 capabilities (`CapEff = 0x1ffffffffff`) scoped to that child namespace, including `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` [80]! Suddenly, millions of lines of complex Ring 0 C code: `nf_tables` packet-filtering bytecode (`CVE-2024-1086` [81]), Linux Traffic Control `tc` qdiscs, raw packet sockets, `OverlayFS` mounts (`CVE-2023-0386` [82]), and filesystem drivers: which for twenty years had been reachable *only* by trusted host `root` administrators behind `ns_capable(net->user_ns, CAP_NET_ADMIN)` became directly reachable by any unprivileged local user or compromised web worker! Because namespaces partition *logical visibility* while sharing a *single Ring 0 heap and page cache* (dramatically illustrated alongside unconditional VFS flaws like `Dirty Pipe` `CVE-2022-0847` [84]), `CLONE_NEWUSER` became the launchpad for over 60% of modern Linux local privilege-escalation exploits [83, 85].

## Kernel & Userspace Mechanics

### The Five Capability Vectors and `execve()` Transition Algebra

Inside `struct cred` (`include/linux/cred.h`), every Linux thread carries five 64-bit capability masks (`kernel_cap_t`), visible in hexadecimal inside `/proc/<pid>/status` [5, 78]: `CapInh` ($P_I$, inheritable across `execve` when matched by file masks), `CapPrm` ($P_P$, upper ceiling of capabilities the thread may assume), `CapEff` ($P_E \subseteq P_P$, bits actually checked by the kernel on syscalls), `CapBnd` ($P_B$, bounding set masking file capabilities; bits dropped from $P_B$ can never be re-added by the process or its descendants), and `CapAmb` ($P_A$, ambient capabilities added in Linux 4.3 so non-root daemons can pass privileges across normal `execve` calls without stamping xattrs onto `/usr/bin/python3`) [78].

![Figure: Exact POSIX capability transformation equations across execve() in security/commoncap.c, pairing the five thread capability vectors with VFS security.capability xattrs and highlighting root-equivalent capability traps.](diagrams/09-capability-execve-algebra.svg)

On disk, an executable file may optionally carry a `security.capability` extended attribute (`VFS_CAP_REVISION_3` `struct vfs_ns_cap_data`, automatically wiped by the VFS whenever any writer modifies the file!) specifying Permitted ($F_P$), Inheritable ($F_I$), a single Effective boolean bit ($F_E$), and a namespace `rootid` [78]. When a thread invokes `execve(2)`, `cap_bprm_creds_for_exec()` in `security/commoncap.c` computes the post-`execve` vectors $(P'_I, P'_P, P'_E, P'_B, P'_A)$ according to four exact equations [78]:

$$\begin{aligned}
P'_A &= \begin{cases} \emptyset & \text{if binary is SUID, SGID, or has } F_P \neq \emptyset \text{ or } F_I \neq \emptyset \\ P_A & \text{otherwise} \end{cases} \\
P'_I &= P_I \\
P'_P &= (P_I \cap F_I) \;\cup\; (F_P \cap P_B) \;\cup\; P'_A \\
P'_E &= \begin{cases} P'_P & \text{if } F_E = 1 \text{ (or legacy root fixup applies)} \\ P'_A & \text{otherwise} \end{cases}
\end{aligned}$$

With the bounding set preserved unchanged ($P'_B = P_B$) and the invariant $P_A \subseteq (P_P \cap P_I)$ strictly enforced whenever `prctl(PR_CAP_AMBIENT)` or `capset(2)` runs [78]. Look closely at the security elegance of the $P'_A$ clearing rule: if an unprivileged service holds `CAP_NET_BIND_SERVICE` in `CapAmb` ($P_A$) so child worker binaries inherit port-80 binding naturally, and an attacker tricks that service into invoking a `SUID-root` or file-capability binary, the kernel *immediately zeroes $P'_A$* so ambient bits never mingle unexpectedly with privileged binaries! Furthermore, if the thread previously set `PR_SET_NO_NEW_PRIVS` (`no_new_privs = 1` [93]), `cap_bprm_creds_for_exec()` clamps $P'_P$ so it cannot exceed the caller's pre-exec $P_P$, neutralizing both `SUID` and $F_P$ file-capability escalation across the entire process subtree.

Why, then, does `UID 0` still appear to retain capabilities automatically on standard Linux? Because unless a daemon explicitly sets `SECBIT_NOROOT` (`prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED)`), `commoncap.c` emulates historic Unix `root` semantics via a special rule: *executing any file when `euid == 0` or `uid == 0` automatically treats $F_I$ and $F_P$ as all-ones ($\mathbf{1}$), setting $P'_P = P_B$ and $P'_E = P'_P$* [78]! Dropping privileges cleanly from `UID 0` without `systemd` (`User=` / `AmbientCapabilities=`) therefore requires keeping `SECBIT_KEEP_CAPS` across `setresuid()`, populating `CapAmb`, and setting `PR_SET_NO_NEW_PRIVS`: a delicate multi-step dance whose historical misuse bred dozens of daemon vulnerabilities.

### `CLONE_NEWUSER`, `ns_capable()`, and the Kernel Attack-Surface Multiplier

When an unprivileged process (`kuid = 1000`, $P_E = \emptyset$) calls `unshare(CLONE_NEWUSER)`, `create_user_ns()` in `kernel/user_namespace.c` allocates a child `struct user_namespace` recording `ns->owner = 1000` and grants the calling task full capabilities ($P_P = P_E = \text{all ones}$) *inside `ns`* [80]. Next, the process writes `"deny"` to `/proc/self/setgroups` (a mandatory security fix introduced after `CVE-2014-8989`, because allowing unprivileged `setgroups(0, NULL)` to drop supplementary groups let a user bypass negative group-deny POSIX ACLs `---rwx---` on host files!) and writes single-line identity extents (`"0 1000 1\n"`) to `/proc/self/uid_map` and `/proc/self/gid_map`, mapping namespace `UID 0` to host `kuid 1000` [80].

![Figure: How unprivileged CLONE_NEWUSER + CLONE_NEWNET grants namespace-local CAP_NET_ADMIN (passing ns_capable checks) to reach complex Ring 0 subsystems such as nf_tables (CVE-2024-1086) and OverlayFS (CVE-2023-0386), and how Ubuntu 24.04+'s AppArmor userns gate blocks unprofiled unshare() calls.](diagrams/09-userns-kernel-exploit-chain.svg)

How does the kernel prevent namespace `UID 0` from reading host `/etc/shadow` (`i_uid = 0` in `init_user_ns`) or loading a `.ko` module? Every global operation (`finit_module`, `/dev/mem`, global `reboot`) calls `capable(CAP_SYS_MODULE)`, which expands to `ns_capable(&init_user_ns, CAP_SYS_MODULE)` and returns `false` because the child namespace's `owner` is `kuid 1000`, not `init_user_ns`! Likewise, VFS maps host `kuid 0` into the child namespace as `65534` (`nobody` / `overflowuid`), so `CAP_DAC_OVERRIDE` inside the child `user_ns` only overrides permissions on inodes whose `i_uid` is mapped inside that child namespace (`ns_capable_inode`) [80].

Where the model breaks catastrophically is when the process immediately unshares a *network* or *mount* namespace (`unshare(CLONE_NEWNET | CLONE_NEWNS)`): the new `struct net` records `net->user_ns = child_user_ns`! When the unprivileged user sends a `NETLINK_NETFILTER` message configuring `nf_tables` firewall bytecode, `nfnetlink_rcv()` checks `ns_capable(net->user_ns, CAP_NET_ADMIN)`: which returns `true` [80, 81]! In January 2024, `CVE-2024-1086` (`Flipping Pages` [81]) demonstrated the devastating consequence: `nft_verdict_init()` inside `net/netfilter/nf_tables_api.c` failed to reject crafted positive drop error codes (`0xFFFF0000 | NF_DROP`), tricking the network hook loop into interpreting `NF_DROP` (after freeing `struct sk_buff`!) as `NF_ACCEPT` (continuing to route and *freeing the exact same `sk_buff` a second time*!). Using that double-free in shared Ring 0 slab/page memory, an unprivileged `UID 1000` user allocated page tables over the freed physical buffer and overwrote host `/sbin/modprobe` or `struct cred` for universal host `root` across Debian, Ubuntu, Fedora, and KernelCTF [81]. Similarly, `CVE-2023-0386` [82] exploited `OverlayFS` mounted inside `CLONE_NEWUSER | CLONE_NEWNS`: mounting a FUSE filesystem owning a fake `UID 0` `SUID` binary as the lower layer and copying it up (`copy_up`) to a host-visible upper directory bypassed `kuid` mapping validation, minting a real host `SUID-root` shell on Ubuntu! Even outside `CLONE_NEWUSER`, subtle VFS state-flag omissions such as Max Kellermann's `Dirty Pipe` (`CVE-2022-0847` [84], where `copy_page_to_iter_pipe()` forgot to zero `pipe_buffer.flags`, leaving `PIPE_BUF_FLAG_CAN_MERGE` set on a spliced read-only page-cache folio so an unprivileged `write()` overwrote `/etc/passwd` directly in RAM!) reinforce why Ring 0 attack-surface minimization is paramount.

## Distro, Immutable-OS, & Cloud Trade-Offs

For years, distributions agonized over a painful dilemma: setting `sysctl kernel.unprivileged_userns_clone = 0` (Debian/Arch patch) or `user.max_user_namespaces = 0` instantaneously kills 60%+ of kernel LPE chains, *but breaks Chromium, Firefox, Electron, Flatpak, Bubblewrap, and rootless Podman* if they lack `SUID` sandboxes [85]! Starting in `Ubuntu 23.10` and `24.04 LTS`, Canonical deployed a surgical architectural compromise (`kernel.apparmor_restrict_unprivileged_userns = 1` [85]): `CLONE_NEWUSER` succeeds unconditionally, *but* attempting to retain capabilities inside that new `user_ns` is denied (`-EPERM`) by `AppArmor` unless the calling binary (`chrome`, `firefox`, `bwrap`, `rootlesskit`) has an explicit administrator-installed `AppArmor` profile granting `userns,`! Thus an arbitrary exploit binary dropped in `/tmp/exploit` gets `-EPERM` on `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, while browsers and `bwrap` continue running rootlessly [85]. Meanwhile, Google's production fleet and `Container-Optimized OS` (`COS`), followed by `Android` and hardened Kubernetes distros (`Talos`), took an equally decisive step against `io_uring`: after observing that 60% of `kCTF` exploit submissions targeted `io_uring` async ring buffers, Google set `kernel.io_uring_disabled = 2` (`sysctl`, upstreamed in Linux 6.6) so `io_uring_setup(2)` is blocked globally unless explicitly granted via `CAP_SYS_ADMIN` or group policy [83].

## Seam Failures, CVEs, & Structural Bounds

Capability and namespace boundary failures consistently trace back to root-equivalent capabilities granted under the illusion of least privilege or complex Ring 0 subsystems exposed via `ns_capable()`.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `Shocker` (`open_by_handle_at` Escape) | 2014-2024 | `CAP_DAC_READ_SEARCH` in containers | `CAP_DAC_READ_SEARCH` only grants read-only backup access inside `chroot`/container | Brute-forces 64-bit host inode file handles via `open_by_handle_at(2)` to open host `/etc/shadow` outside container rootfs | Drop `CAP_DAC_READ_SEARCH` from all container bounding sets (`CapBnd`) [79, 114] |
| Dirty Pipe (`CVE-2022-0847`) | 2022 | `lib/iov_iter.c` pipe page splicing | Read-only file descriptors (`O_RDONLY`) can never mutate backing page cache | `splice()` reuses `pipe_buffer` with uninitialized `PIPE_BUF_FLAG_CAN_MERGE`, letting `write()` overwrite `/etc/passwd` or SUID ELF in RAM | Explicitly zero `buf->flags = 0` on pipe page insertion (`Linux 5.16.11+`) and back `/usr` with `dm-verity`/`IPE` [30, 84] |
| `OverlayFS` `SUID` Copy-Up (`CVE-2023-0386`) | 2023 | `fs/overlayfs/` + `CLONE_NEWUSER` | Unprivileged `OverlayFS` mount cannot create host-mapped `UID 0` files | Copies `SUID` file from FUSE lowerdir (`kuid` unmapped) to host upperdir without checking `kuid_has_mapping()` | Reject copy-up of unmapped `i_uid`/`i_gid` inodes and gate `userns` via `AppArmor` [82, 85] |
| Flipping Pages (`CVE-2024-1086`) | 2024 | `net/netfilter/nf_tables` + `CLONE_NEWUSER` | `ns_capable(CAP_NET_ADMIN)` inside isolated `net_ns` cannot affect host Ring 0 | Malformed `NF_DROP` verdict triggers `sk_buff` double-free in shared slab/page allocator, overwriting host page tables | Validate `nft` verdict masks strictly, blacklist unused `nf_tables` autoload, and restrict unprivileged `userns` [81, 85] |
| `io_uring` Ring 0 Exploit Wave | 2021-2024 | `io_uring/` async shared-memory rings | Complex async file/socket worker threads safely track reference counts | Races across fixed files, `IOSQE_ASYNC`, and buffer rings yield Ring 0 UAFs without needing `userns` | Set `sysctl kernel.io_uring_disabled=2` across multi-tenant hosts and container `seccomp` profiles [83, 121] |

Even if `user_namespaces` and `io_uring` are tightly gated, how should legitimate users and administrators acquire privileges when they *do* need to perform administrative actions? For fifty years, Unix answered with `SUID-root` binaries (`sudo`, `su`, `pkexec`), a mechanism whose unbroken chain of local root vulnerabilities finally drove `systemd` to engineer its replacement in [Chapter 10](10-suid-to-run0.md).

## Inspecting on a Live Linux Host

Decode the five 64-bit capability masks (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`) and `NoNewPrivs` status of your current shell process:

```bash
grep -E "^(Cap|NoNewPrivs|Secbits)" /proc/self/status
capsh --decode=$(awk '/^CapBnd:/{print $2}' /proc/self/status) 2>/dev/null | fold -s -w 80 | head -n 4
```

Audit the filesystem for binaries carrying `VFS` file capabilities (`security.capability`) instead of `SUID` bits:

```bash
getcap -r /usr/bin /usr/sbin 2>/dev/null | head -n 15
```

Check unprivileged `user_namespaces` and `io_uring` kernel hardening `sysctl` settings on the live host:

```bash
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.io_uring_disabled 2>/dev/null || true
```
