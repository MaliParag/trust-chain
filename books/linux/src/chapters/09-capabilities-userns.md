# POSIX Capabilities and the Unprivileged User Namespace Surface

## Overview

* **Link in the Chain:** Opens Part III by governing how userspace threads hold and transform kernel privileges (`CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`) across `execve(2)` and how unprivileged user namespaces (`CLONE_NEWUSER`) remap those capabilities across container and sandbox boundaries.
* **Core Security Invariant:** Across every `execve()` and `capset()` transition in `security/commoncap.c`, effective capabilities stay bounded by permitted sets ($E \subseteq P$) and ambient invariants ($A \subseteq P \cap I$, cleared automatically on `SUID`/file-capability binaries), while global Ring 0 operations check `capable(cap)` against `init_user_ns` rather than trusting `ns_capable(child_ns, cap)` over shared kernel memory.
* **Deployment Profile Matrix:** `Ubuntu 23.10+` and `24.04 LTS+` gate unprivileged `CLONE_NEWUSER` capability retention behind `AppArmor` (`kernel.apparmor_restrict_unprivileged_userns=1`), `RHEL 9/10` bounds `user.max_user_namespaces`, `Google COS`/`Android`/`Talos` set `kernel.io_uring_disabled=2`, and `Kubernetes 1.33+` isolates pod `UID 0` via `hostUsers: false` with minimal `CapBnd`.
* **Trusted Computing Base (TCB):** Linux `security/commoncap.c` capability transition engine (`VFS_CAP_REVISION_3` xattrs and `PR_CAP_AMBIENT`), `kernel/user_namespace.c` extent mapper (`map_id_up`/`map_id_down`), `ns_capable()` vs. `capable()` gates across `nf_tables`/`OverlayFS`/`io_uring`, and `AppArmor` / `sysctl` admission controls.
* **Integration Seam & Handoff:** Explains why 21+ root-equivalent capabilities and unprivileged `CLONE_NEWUSER` became the #1 Linux local privilege-escalation (`LPE`) amplifier; hands off `SUID`-free interactive elevation (`run0`) to [Chapter 10](10-suid-to-run0.md) and daemon/container sandboxing to [Chapters 11](11-systemd-dbus-sandboxing.md) and [14](14-containers-escapes.md).

## Problem Statement & Threat Model

For its first twenty-five years, Unix recognized only a binary privilege split in userspace: omnipotent `UID 0` (`root`), which bypassed nearly every kernel permission check, and unprivileged `UID > 0` [62, 295]. Whenever a network utility or system daemon needed a single narrow privilege (`ping` opening `AF_INET` `SOCK_RAW`, `chronyd` disciplining the clock, or `dnsmasq` binding port `53`), engineers had to either run the entire C process as `UID 0` or mark the binary `SUID-root`, turning any parser bug into total host compromise.

POSIX.1e draft capabilities (merged in Linux 2.2 and extended with VFS extended attributes and ambient sets inside `security/commoncap.c` [62, 296]) partitioned superuser authority into discrete bitflags (`0` through `40`, currently `41` capabilities up to `CAP_CHECKPOINT_RESTORE`). Yet two decades of deployment and offensive kernel research exposed two structural flaws in how capabilities interact with Linux's monolithic Ring 0 [22, 23, 63, 297]:
First, *coarse capability granularity collapses back to `root`*. As `grsecurity` architect Brad Spengler cataloged [297], more than twenty Linux capabilities (`CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, `CAP_BPF`, `CAP_PERFMON`, `CAP_SETUID`, `CAP_SETFCAP`, `CAP_FOWNER`, `CAP_CHOWN`, `CAP_NET_ADMIN`) grant trivial equivalents to full `UID 0` on a standard system [297, 298]. Granting a container or backup daemon "read-only" `CAP_DAC_READ_SEARCH` lets Sebastian Krahmer's `shocker` exploit invoke `open_by_handle_at(2)` to brute-force 64-bit host filesystem inode handles and read `/etc/shadow` right across `chroot` and mount-namespace walls [299]! Meanwhile, `CAP_SYS_ADMIN` became an overloaded catch-all gating hundreds of unrelated `mount`, `ioctl`, namespace, and driver paths [62, 297].

Second, Linux 3.8 introduced *unprivileged user namespaces* (`CLONE_NEWUSER` in `kernel/user_namespace.c` [22, 300]) so non-root users could build rootless containers (`Podman`), desktop sandboxes (`Flatpak` / `Bubblewrap`), and browser renderers without `SUID-root` helpers. Calling `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)` grants any unprivileged `UID 1000` process *all 41 capabilities* (`CapEff = 0x1ffffffffff`) inside its new child namespace! Overnight, sprawling legacy C subsystems (`net/netfilter/nf_tables` in `CVE-2022-1015` [301] and `CVE-2024-1086` [23], `fs/overlayfs` in `CVE-2023-0386` [24] and `GameOver(lay)` [302], `tc` packet schedulers, and raw sockets) that for decades sat unreachable behind `CAP_NET_ADMIN` or `CAP_SYS_ADMIN` became reachable by any unprivileged local process via `ns_capable(net->user_ns, CAP_NET_ADMIN)` [22, 300]. Paired with unconditional shared-kernel surfaces such as `io_uring` async worker rings [303, 304, 305] and VFS pipe-splicing flaws (`Dirty Pipe`, `CVE-2022-0847` [306, 307]), `CLONE_NEWUSER` became the primary Ring 0 LPE multiplier across modern Linux fleets.

## Kernel & Userspace Mechanics

### The Five Capability Sets, `execve()` Transition Algebra, and Root-Equivalent Traps

Inside `struct cred` (`include/linux/cred.h` and `security/commoncap.c` [62, 296]), every Linux thread carries five 64-bit capability bitmasks (`kernel_cap_t`), exposed in hexadecimal inside `/proc/<pid>/status`: `Permitted` ($P$, maximum superset the thread may activate), `Effective` ($E \subseteq P$, bits actually consulted by kernel `capable()` checks), `Inheritable` ($I$, bits eligible to cross `execve()` when matched by file masks), `Bounding` ($B$, per-subtree ceiling masking file capabilities; dropping a bit from $B$ via `PR_CAPBSET_DROP` is irreversible), and `Ambient` ($A$, added in Linux 4.3 by Christoph Lameter and Andy Lutomirski [308]).

![Figure: Exact POSIX capability transformation equations across execve() in security/commoncap.c, pairing the five thread capability vectors with VFS security.capability xattrs and highlighting root-equivalent capability traps.](diagrams/09-capability-execve-algebra.svg)

Why did POSIX.1e's original three sets ($P, I, E$) fail non-root service wrappers for fifteen years prior to Linux 4.3 [295, 308]? On disk, an executable carries optional file capabilities (`F_P` Permitted, `F_I` Inheritable, and boolean `F_E` Effective) inside its `security.capability` extended attribute. Since Linux 4.14 (`VFS_CAP_REVISION_3` `struct vfs_ns_cap_data` in `security/commoncap.c` [296]), that xattr encodes a 24-byte little-endian structure (`magic_etc` version/effective header, two 32-bit `(permitted, inheritable)` words forming 64-bit masks, plus a 32-bit `rootid` recording the owning `kuid` so a container `UID 0` user stamping `CAP_NET_ADMIN` inside a user-namespaced or idmapped mount [309] can never execute that binary to gain host `init_user_ns` capabilities!). Furthermore, `cap_inode_need_killpriv()` hooks VFS `notify_change()` and `file_remove_privs()` so any `write(2)`, `truncate(2)`, or `chown(2)` on a capability-bearing file unconditionally deletes `security.capability` before modifying a single byte [296]. Under pure POSIX.1e (`A = 0`), however, executing any normal helper binary lacking file xattrs (`F_P = F_I = 0`, such as `/usr/bin/python3` or `/bin/sh`) yielded $P' = (I \cap 0) \cup (0 \cap B) = \emptyset$: *every privilege vanished across `execve()`* unless administrators recklessly stamped `F_I` onto `/usr/bin/python3` system-wide [308]!

Linux 4.3 solved non-SUID inheritance cleanly by adding the `Ambient` set $A$ (`prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)`), governed by `cap_capset()` and `bprm_caps_from_vfs_caps()` in `security/commoncap.c` [62, 296, 308]. First, raising or retaining any bit in $A$ enforces the strict invariant $A \subseteq (P \cap I)$ (dropping a bit from $P$ or $I$ automatically masks it out of $A$). Second, across `execve(2)`, the new credential sets $(A', I', P', E', B')$ obey four exact equations [62, 296]:

$$\begin{aligned}
A' &= \begin{cases} \emptyset & \text{if target is SUID, SGID, or carries } F_P \neq \emptyset \lor F_I \neq \emptyset \\ A & \text{otherwise} \end{cases} \\
I' &= I, \qquad B' = B \\
P' &= (P_{\text{inh\_ok}} \cap I \cap F_I) \;\cup\; (F_P \cap B) \;\cup\; A' \quad \text{specifically } (I \cap F_I) \cup (F_P \cap B) \cup A' \\
E' &= \begin{cases} P' & \text{if } F_E = 1 \text{ (or legacy } \text{UID } 0 \text{ fixup applies)} \\ A' & \text{otherwise} \end{cases}
\end{aligned}$$

Notice two vital safety interlocks embedded in `commoncap.c` [296, 308]. First, if a service wrapper running as `UID 995` (`chrony` or a web proxy) holds `CAP_NET_BIND_SERVICE` in `CapAmb` ($A$) so worker children inherit port-443 binding across `execve()`, and an attacker coerces that service into executing a `SUID-root` or file-capability binary, *`A'` immediately resets to $\emptyset$* so ambient privileges never combine with privileged on-disk executables! Second, if the task previously called `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` (`no_new_privs`), `execve()` clamps $P'$ and `euid` so neither `SUID` nor $F_P$ can ever expand privileges beyond the caller's existing `Permitted` set. Meanwhile, `handle_privileged_root()` in `commoncap.c` explains why traditional `UID 0` shells still appear omnipotent unless locked with `SECBIT_NOROOT`: whenever `euid == 0` or `uid == 0` executes a file without `SECBIT_NOROOT`, the kernel synthesizes virtual all-ones file masks ($F_P = F_I = \mathbf{1}$), setting $P' = B \cup I$ and $E' = P'$ [296]. Equally treacherous is `cap_task_fix_setuid()`, which runs whenever a daemon drops privilege via `setresuid(1000, 1000, 1000)`: if the thread had `uid == 0` or `euid == 0` beforehand and transitions all three real, effective, and saved UIDs to non-zero *without* setting `SECBIT_KEEP_CAPS` (`prctl(PR_SET_KEEPCAPS, 1)`), the kernel wipes both `CapPrm` and `CapEff` completely; even *with* `SECBIT_KEEP_CAPS` set, `setresuid()` still clears `CapEff` (`E = 0`), forcing the daemon to explicitly re-raise `CapEff` via `capset(2)`, populate `CapAmb`, and clear `SECBIT_KEEP_CAPS` before `execve()` [62, 296]! Modern `systemd` service units (`User=`, `CapabilityBoundingSet=`, `AmbientCapabilities=` in [Chapter 11](11-systemd-dbus-sandboxing.md)) perform this exact six-step `prctl`/`capset` sequence inside `PID 1`'s spawn helper so application C code never hand-rolls privilege drops.

Even when `UID 0` is shed cleanly, defenders must recognize that *capabilities are not symmetric least-privilege compartments* [297, 298, 299]. At least 21 capabilities collapse directly to host `root` unless constrained by `SELinux`/`AppArmor`, `seccomp`, and namespaces: `CAP_SYS_MODULE` loads Ring 0 `.ko` code; `CAP_SYS_RAWIO` opens `/dev/mem` and `ioperm`; `CAP_SYS_PTRACE` injects shellcode into `PID 1` or `sshd` via `PTRACE_POKETEXT` (`cap_ptrace_access_check()` in `commoncap.c` checks that the tracer holds a superset of target `CapPrm` or `CAP_SYS_PTRACE` [296]); `CAP_DAC_OVERRIDE` overwrites `/etc/passwd` or `/etc/sudoers`; `CAP_DAC_READ_SEARCH` escapes container `chroot`s via `open_by_handle_at(2)` (`shocker.c` [299]); `CAP_FOWNER` modifies arbitrary file ACLs and `chmod` bits; `CAP_SETUID`/`CAP_SETFCAP` mint `UID 0` or `F_P = all` binaries; `CAP_BPF` + `CAP_PERFMON` read arbitrary kernel memory; and `CAP_SYS_ADMIN` mounts filesystems, invokes `swapon`, or triggers `cgroup` v1 `release_agent` host execution [297, 298].

### `CLONE_NEWUSER`, `uid_map` Extents, and `ns_capable()` Kernel Exploitation

How do unprivileged user namespaces (`kernel/user_namespace.c` [22, 300, 310]) interact with these 41 capabilities? When an unprivileged task (`kuid = 1000`, $E = \emptyset$) invokes `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER, ...)`, `create_user_ns()` verifies `parent_ns->level <= 32` and `!current_chrooted()` (preventing `chroot`-confined processes from creating user namespaces to escape!), charges hierarchical per-`(user_ns, kuid)` `struct ucounts` quotas (`UCOUNT_USER_NAMESPACES`, paired with `max_mnt_namespaces` and `max_net_namespaces` to prevent kernel memory exhaustion), invokes the `security_create_user_ns()` LSM hook, records `ns->owner = kuid 1000`, and calls `set_cred_user_ns()`, which sets `cred->cap_permitted = cred->cap_effective = CAP_FULL_SET` (`0x1ffffffffff`) *bound to `cred->user_ns = ns`* [300]!

Next, the process establishes bidirectional translations between internal namespace UIDs/GIDs and global kernel `kuid_t`/`kgid_t` values by writing up to `5` inline base extents (expandable up to `340` binary-searched `struct uid_gid_extent` entries in `map_id_range_down_max()` for rootless container runtimes aided by privileged `newuidmap` / `systemd-nsresourced` helpers [300, 311]) into `/proc/self/uid_map` and `/proc/self/gid_map`. Alongside `VFS_CAP_REVISION_3` xattrs, Linux 5.12+ added *idmapped mounts* (`mount_setattr(2)` with `MOUNT_ATTR_IDMAP` by Christian Brauner [309]), allowing container engines to shift `vfsuid_t` ownership per `vfsmount` dynamically at VFS lookup time without running slow recursive `chown -R` passes across gigabyte container layers. Without `CAP_SETUID` in the *parent* namespace, however, `new_idmap_permitted()` enforces two strict rules on unprivileged callers: (1) the caller may map only its *own* single `kuid` (`"0 1000 1\n"`, translating internal `UID 0` to host `kuid 1000`), and (2) before writing `gid_map`, the caller *must* write `"deny"` to `/proc/self/setgroups` (added after Andy Lutomirski's `CVE-2014-8989` [312], where calling `setgroups(0, NULL)` inside a `user_ns` stripped supplementary groups and allowed users excluded by group `---` permissions on a `0604` host file to read it as "other"!).

![Figure: How unprivileged CLONE_NEWUSER + CLONE_NEWNET grants namespace-local CAP_NET_ADMIN (passing ns_capable checks) to reach complex Ring 0 subsystems such as nf_tables (CVE-2024-1086) and OverlayFS (CVE-2023-0386), and how Ubuntu 24.04+'s AppArmor userns gate blocks unprofiled unshare() calls.](diagrams/09-userns-kernel-exploit-chain.svg)

Look at `cap_capable_helper()` in `security/commoncap.c` [296] to see both why `CLONE_NEWUSER` protects host files properly at the VFS layer and why it catastrophically widened Ring 0 attack surface:

```c
/* security/commoncap.c: Walks target_ns upward to cred_ns or owner parent */
for (struct user_namespace *ns = target_ns; ; ns = ns->parent) {
    if (ns == cred_ns)
        return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;
    if (ns->level <= cred_ns->level)
        return -EPERM; /* Child user_ns NEVER holds caps in init_user_ns! */
    if (ns->parent == cred_ns && uid_eq(ns->owner, cred->euid))
        return 0;
}
```

Whenever a subsystem checks global `capable(CAP_SYS_MODULE)` (which passes `target_ns = &init_user_ns`), `ns->level` (`0`) is less than `cred_ns->level` (`1`), returning `-EPERM` deterministically. Likewise, host `/etc/shadow` (`i_uid = kuid 0`) has no mapping inside `child_ns` (appearing as `overflowuid = 65534`), so `capable_wrt_inode_uidgid()` denies `CAP_DAC_OVERRIDE`. *However*, the instant the unprivileged attacker calls `unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)`, the newly allocated `struct net` and `struct mnt_namespace` record `user_ns = child_ns`! Every kernel path gated by `ns_capable(net->user_ns, CAP_NET_ADMIN)` or `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` now evaluates `target_ns == cred_ns` and returns `0` (allowed) [296, 300]!

Three landmark exploit waves prove the cost of exposing legacy C subsystems via `ns_capable()`:
In `nf_tables` (`CVE-2022-1015` analyzed by Jann Horn [301] and `Flipping Pages` `CVE-2024-1086` by Notselwyn [23]), `nfnetlink_rcv()` admitted complex register-machine firewall bytecode from any `CLONE_NEWUSER | CLONE_NEWNET` task. Because `nf_tables` implements an in-kernel expression virtual machine (`nft_Immediate`, `nft_payload`, `nft_bitwise`, dynamic sets, and transactional generation commits) whose data structures allocate out of the exact same global `SLUB` and buddy page allocators as `init_user_ns` kernel tasks, any bounds or lifecycle bug inside `net/netfilter/` immediately compromises the entire physical host. In `CVE-2024-1086`, `nft_verdict_init()` accepted positive upper bits on `NF_DROP` (`0xFFFF0000 | NF_DROP`); `nf_hook_slow()` freed the `struct sk_buff` packet on `NF_DROP` and then misinterpreted the upper bits as `NF_ACCEPT`, routing and freeing the *exact same `sk_buff` a second time* in shared Ring 0 slab/page memory to overwrite host page tables (`Dirty Pagetable`) for universal root [23]!
In `OverlayFS` (`CVE-2023-0386` [24] and Ubuntu's custom OverlayFS patches in `GameOver(lay)` `CVE-2023-2640` / `CVE-2023-32629` [302]), unprivileged `CLONE_NEWUSER | CLONE_NEWNS` mounts overlaid a FUSE lower filesystem presenting a fake `UID 0` `SUID` executable onto a host-writable upper directory; triggering `OverlayFS` `copy_up` copied the `SUID` inode or `security.capability` xattrs into the host filesystem without verifying `kuid_has_mapping()` in the mounting namespace, minting an instant host `SUID-root` shell! Alongside `nf_tables` and `OverlayFS`, unprivileged `CLONE_NEWUSER | CLONE_NEWNET` repeatedly exposed legacy Linux Traffic Control (`net/sched/` `cls_route`, `cls_fw`, `sch_hfsc`), `AF_PACKET` raw ring buffers (`TPACKET_V3`), and obscure socket families (`TIPC`, `RDS`, `NetROM`) whose original 1990s/2000s authors naturally assumed `CAP_NET_ADMIN` implied a trusted human system administrator rather than an untrusted sandboxed browser tab or container tenant [300, 301, 313].

### Shared-Kernel Surfaces Beyond `userns`: `io_uring` and `Dirty Pipe` (`CVE-2022-0847`)

Crucially, two of the highest-impact Ring 0 exploit surfaces of the 2020s required *zero capabilities and zero user namespaces*, proving that attack-surface reduction must extend beyond `CLONE_NEWUSER` alone [303, 306, 307]:

![Figure: Four-stage VFS page-cache corruption mechanics of Dirty Pipe (CVE-2022-0847), where an uninitialized PIPE_BUF_FLAG_CAN_MERGE bit left on a pipe_buffer ring slot allowed splice() + write() to overwrite read-only /etc/passwd and SUID binaries directly in shared RAM.](diagrams/09-extra-dirty-pipe-pagecache-splice.svg)

First, Max Kellermann's `Dirty Pipe` (`CVE-2022-0847`, Linux 5.8 through 5.16.10 [306, 307]) turned a one-line missing struct initialization in `lib/iov_iter.c` into universal, crashless instant `root`. Linux pipes maintain a 16-slot ring of `struct pipe_buffer` entries; writing normal anonymous data sets `PIPE_BUF_FLAG_CAN_MERGE` (`0x10`) so subsequent small `write()` calls append into the same $4\text{ KiB}$ pipe page. When an unprivileged process filled and drained all 16 pipe slots, `PIPE_BUF_FLAG_CAN_MERGE` remained set in every `buf->flags` field. Opening `/etc/passwd` (or any `SUID-root` ELF binary) `O_RDONLY` and calling `splice(fd_ro, &off, pipe_w, NULL, 1, 0)` invoked `copy_page_to_iter_pipe()`, which pointed `buf->page` directly at the live *shared VFS page-cache folio* and switched `buf->ops = &page_cache_pipe_buf_ops`, *forgetting to clear `buf->flags = 0`*! Calling `write(pipe_w, "root::0:0:...", len)` saw stale `PIPE_BUF_FLAG_CAN_MERGE` and copied attacker bytes straight into `/etc/passwd`'s read-only RAM folio, bypassing `O_RDONLY`, POSIX `DAC`, `SELinux`, and read-only mounts without even marking the page dirty on disk (fixed in commit `9d2231c5d74e` [307]; note that only byte offset `0` of each $4\text{ KiB}$ page remained un-overwritable because `splice` required at least 1 byte prior to merging!).

Second, Jens Axboe's `io_uring` subsystem (`io_uring/io_uring.c` [314]) exposed shared-memory Ring 3/Ring 0 Submission and Completion Queues, registered file tables, provided buffer rings, and asynchronous `io-wq` kernel threads to every unprivileged process. Complex lockless refcounting across async cancellation and buffer rings yielded a torrent of zero-`userns` UAFs, including `CVE-2022-29582` (`IORING_OP_LINK_TIMEOUT` async worker race analyzed by Valentina Palmiotti [304]) and Jann Horn's `CVE-2024-0582` [305]. In `CVE-2024-0582`, allocating a kernel-managed provided buffer ring (`IORING_REGISTER_PBUF_RING` with `IOU_PBUF_RING_MMAP`), mapping it into Ring 3 via `mmap()`, and calling `IORING_UNREGISTER_PBUF_RING` returned the underlying physical pages straight to the kernel buddy page allocator *while leaving the Ring 3 `VMA` PTEs mapped read-write*! Without needing `CLONE_NEWUSER` or `Dirty Pagetable` heap drains, an unprivileged process simply waited for the kernel to reuse those freed physical pages for `struct cred` or slab caches and edited Ring 0 structures directly from userspace memory [305]! After `60%` of all `kCTF` exploit submissions targeted `io_uring` ($>1\text{ million USD}$ in bounties), Google disabled unprivileged `io_uring` across Google production servers, `Container-Optimized OS`, and `Android` (`sysctl kernel.io_uring_disabled = 2`, or `1` restricting `io_uring_setup(2)` to `sysctl kernel.io_uring_group` GIDs in Linux 6.6+ [303]).

## Distro, Immutable-OS, & Cloud Trade-Offs

Restricting `CLONE_NEWUSER` without breaking modern desktop and container ecosystems forced distributions to invent finer-grained admission gates [311, 313, 315, 316, 317]:

| Platform / Distro | `CLONE_NEWUSER` Policy | `io_uring` & `CapBnd` Posture | Operational Trade-Off |
|---|---|---|---|
| `Ubuntu 24.04 LTS+` | `apparmor_restrict_unprivileged_userns = 1` | `io_uring` mediated in `AppArmor 4.0` | Blocks `/tmp/exploit` `unshare()` while allowing profiled `chrome`, `firefox`, `bwrap` [315] |
| `RHEL 9/10` & `Fedora` | Enabled (`user.max_user_namespaces` tunable) | `SELinux` `MCS` confines pods | Supports rootless `Podman` (`subuid`/`subgid`); high-security hosts set `max_user_namespaces=0` [311] |
| `Google COS` & `Android` | Restricted (`seccomp` / `SELinux` gated) | `kernel.io_uring_disabled = 2` | Eliminates #1 `kCTF` Ring 0 exploit surface across multi-tenant nodes [303] |
| `Kubernetes 1.33+` (`Talos`) | `hostUsers: false` Pod User Namespaces | Drops `NET_RAW` + `ALL` caps; blocks `io_uring` | Maps container `UID 0` to host `kuid 65536+`, neutralizing `CAP_DAC_*` on breakout [317] |

Look closely at Canonical's `Ubuntu 23.10+` / `24.04 LTS` architecture (`John Johansen` and `Alex Murray` [315]): rather than setting Debian's blunt `kernel.unprivileged_userns_clone = 0` (which breaks Chromium, Electron, Flatpak, and rootless Podman), `AppArmor` intercepts `security_create_user_ns()` and denies retaining capabilities inside a new `user_ns` (`-EPERM`) unless the binary carries an administrator-installed `AppArmor` profile containing `userns,`. As Qualys demonstrated in April 2024 [316], however, this boundary is only as tight as the confined helpers on disk: early profiles allowing unconfined users to invoke `aa-exec` or pass arbitrary host mounts through `bwrap` let exploits piggyback into an allowed `userns` context until Canonical locked profile transitions (`px`/`cx`) and disabled unprivileged `aa-exec` transitions [315, 316]. Conversely, in `Kubernetes 1.33+` (`hostUsers: false` [317]), the *kubelet* creates the pod's `user_namespace` from privileged host space (mapping pod `UID 0..65535` to unique host `kuid` slices `65536*N`), while container `seccomp` blocks nested `unshare(CLONE_NEWUSER)`, `bpf(2)`, and `io_uring_setup(2)` inside the pod: giving defenders `kuid` isolation *without* exposing nested `ns_capable()` Ring 0 surfaces to the workload!

## Seam Failures, CVEs, & Structural Bounds

Decades of capability and namespace CVEs demonstrate that logical UID/capability remapping never isolates a shared monolithic C kernel heap or page cache.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2014-8989` (`setgroups` ACL) | 2014 | `kernel/user_namespace.c` | Dropping supplementary GIDs is purely privilege-reducing | Unprivileged `user_ns` `setgroups(0, NULL)` sheds group-deny POSIX permissions (`0604`) on host files | Require writing `"deny"` to `/proc/pid/setgroups` before unprivileged `gid_map` [300, 312] |
| `Shocker` (`open_by_handle_at`) | 2014-2024 | `fs/fhandle.c` + `CAP_DAC_READ_SEARCH` | `CAP_DAC_READ_SEARCH` grants only read access inside container `chroot` | Brute-forces 64-bit host `ext4` inode handles via `open_by_handle_at(2)` to open host `/etc/shadow` | Drop `CAP_DAC_READ_SEARCH` from container `CapBnd` and map pods via `hostUsers: false` [297, 299, 317] |
| Dirty Pipe (`CVE-2022-0847`) | 2022 | `lib/iov_iter.c` pipe splice | `O_RDONLY` descriptors can never mutate backing page-cache folios | Uninitialized `PIPE_BUF_FLAG_CAN_MERGE` survives `splice()`, letting `write()` overwrite `/etc/passwd` in RAM | Zero `buf->flags = 0` on pipe insertion (`9d2231c5d74e`) and protect `/usr` with `dm-verity`/`IPE` [306, 307] |
| `CVE-2022-29582` & `CVE-2024-0582` | 2022-2024 | `io_uring/` async & `pbuf_ring` | Shared-memory async rings safely track page/request lifetimes | `LINK_TIMEOUT` worker race and `mmap`ed `PBUF_RING` page UAF grant zero-`userns` Ring 0 R/W | Set `sysctl kernel.io_uring_disabled=2` and block `io_uring_*` in `seccomp` [303, 304, 305] |
| `CVE-2022-1015` (`nf_tables` OOB) | 2022 | `net/netfilter/nf_tables` + `userns` | `nf_tables` register indices validate bounds accurately | Out-of-bounds register index via `CLONE_NEWUSER | CLONE_NEWNET` corrupts kernel stack/slab | Harden `nft_parse_register_store` bounds and restrict unprivileged `userns` [301, 315] |
| `OverlayFS` Copy-Up (`CVE-2023-0386`) | 2023 | `fs/overlayfs/` + `CLONE_NEWUSER` | Unprivileged `OverlayFS` cannot mint host-mapped `SUID-root` files | Copies `SUID` binary from FUSE lowerdir (`kuid` unmapped) to host upperdir without `kuid_has_mapping` check | Enforce `kuid_has_mapping` on `copy_up` and gate `userns` via `AppArmor` [24, 315] |
| GameOver(lay) (`CVE-2023-2640`) | 2023 | Ubuntu `OverlayFS` xattr patch | Custom distro xattr copy helpers preserve upstream `userns` invariants | Sets privileged `security.capability` xattrs inside `CLONE_NEWUSER` `OverlayFS` without namespace mapping check | Drop divergent Ubuntu `OverlayFS` xattr wrappers in favor of upstream `commoncap.c` [296, 302] |
| Flipping Pages (`CVE-2024-1086`) | 2024 | `nf_tables` `nft_verdict_init` | `ns_capable(CAP_NET_ADMIN)` in child `net_ns` cannot corrupt host RAM | Crafted `0xFFFF0000 | NF_DROP` verdict double-frees `sk_buff`, enabling `Dirty Pagetable` host root | Reject malformed verdict masks, disable autoload of unused `nf_tables`, and gate `userns` [23, 313] |

### Structural Bounds of Capabilities and Namespace Admission

Three architectural lessons govern Part III moving forward [297, 313, 316]. First, *capabilities and `user_namespaces` partition authorization metadata (`struct cred`), never Ring 0 memory*: whenever multi-tenant untrusted code requires hard isolation from kernel C bugs, shared-kernel namespaces must be paired with `seccomp-BPF`, `AppArmor`/`SELinux`, or isolated behind user-space kernels and KVM micro-VMs (`gVisor`, `Firecracker`, `Kata` in [Chapter 15](15-gvisor-microvms.md)). Second, as Openwall `oss-security` discussions by Solar Designer and kernel maintainers emphasize [313], piecemeal `Autoload` blacklisting of `nf_tables` or `tipc` modules only Whac-A-Moles individual CVEs; sustainable host hardening requires *denying unprivileged `CLONE_NEWUSER` capability retention by default* (`apparmor_restrict_unprivileged_userns=1` or `max_user_namespaces=0`) except for explicitly audited sandbox binaries. Third, when legitimate human operators or automation *do* need elevated capabilities on a host, how can they acquire them without leaving `SUID-root` binaries scattered across `/usr/bin`? That fifty-year transition from `sudo` and `pkexec` to `systemd` `run0` is the subject of [Chapter 10](10-suid-to-run0.md).

## Inspecting on a Live Linux Host

Live auditing inspects current thread capability vectors (`CapInh`..`CapAmb`), filesystem `VFS_CAP_REVISION_2/3` extended attributes (`security.capability`), and kernel `user_namespaces` / `io_uring` `sysctl` admission gates.

Inspect the five hexadecimal capability vectors, `NoNewPrivs` bit, and `Secbits` flags of your current shell, decoding the `CapBnd` bounding mask:

```bash
grep -E "^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Secbits):" /proc/self/status
capsh --decode=$(awk '/^CapBnd:/{print $2}' /proc/self/status) 2>/dev/null | fold -s -w 84 | head -n 3
```

Representative output for an unprivileged login shell (`CapEff = 0`, full 41-bit `CapBnd = 000001ffffffffff`):

```text
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs:     0
Secbits:        00
0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,...
```

Enumerate executables on `/usr/bin` and `/usr/sbin` carrying `security.capability` VFS extended attributes instead of full `SUID-root` bits:

```bash
getcap -r /usr/bin /usr/sbin 2>/dev/null | head -n 12
```

Typical output showing narrow `cap_net_raw` or `cap_net_bind_service` file capabilities (audit carefully for any root-equivalent `cap_dac_read_search` or `cap_sys_admin` entries!):

```text
/usr/bin/ping cap_net_raw=ep
/usr/bin/arping cap_net_raw=p
/usr/sbin/mtr-packet cap_net_raw=ep
```

Verify live kernel `user_namespaces` and `io_uring` attack-surface restriction `sysctl` controls:

```bash
sysctl user.max_user_namespaces kernel.apparmor_restrict_unprivileged_userns kernel.io_uring_disabled 2>/dev/null || true
```

On hardened `Ubuntu 24.04 LTS+` or cloud hosts, `kernel.apparmor_restrict_unprivileged_userns = 1` and `kernel.io_uring_disabled = 2` confirm that unprofiled exploit binaries in `/tmp` can reach neither `CLONE_NEWUSER` `ns_capable()` subsystems nor `io_uring` ring buffers.

Inspect your current process's `user_namespace` UID/GID extent mapping (`/proc/self/uid_map`), `/proc/self/setgroups` policy, and hierarchical `ucounts` namespace quotas:

```bash
cat /proc/self/uid_map /proc/self/setgroups
head -n 1 /proc/sys/user/max_user_namespaces /proc/sys/user/max_mnt_namespaces /proc/sys/user/max_net_namespaces 2>/dev/null
```

Representative output inside `init_user_ns` (`0 0 4294967295` identity mapping across all 32-bit UIDs with `setgroups` `"allow"`), whereas inside an unprivileged sandbox `uid_map` narrows to a single `0 1000 1` extent and `setgroups` locks permanently to `"deny"`:

```text
         0          0 4294967295
allow
==> /proc/sys/user/max_user_namespaces <==
63442
==> /proc/sys/user/max_mnt_namespaces <==
63442
==> /proc/sys/user/max_net_namespaces <==
63442
```

