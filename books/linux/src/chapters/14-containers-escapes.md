# Shared-Kernel Containers: Namespaces, cgroups v2, seccomp, and Escapes

## Overview

* **Link in the Chain:** Opens Part IV by deconstructing standard Open Container Initiative (`OCI`) Linux containers (`Docker`, `containerd`, `CRI-O`, `Podman` backed by `runc` or `crun`), showing how host kernel primitives compose into lightweight workload boundaries and exactly where shared-kernel assumptions break.
* **Core Security Invariant:** A containerized process executes inside isolated visibility namespaces (`mnt`, `pid`, `net`, `ipc`, `uts`, `user`, `cgroup`, `time`), a `pivot_root(2)` filesystem root, `cgroups v2` resource ceilings, dropped POSIX capabilities, stacked `SELinux`/`AppArmor` labels, and a `seccomp-BPF` syscall filter, while runtime setup opens container paths strictly via `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` with sealed `memfd` binaries and zero leaked host file descriptors.
* **Deployment Profile Matrix:** Default Docker/`containerd` runs containers as host-mapped `UID 0` (`root` without `userns`) retaining 14 capabilities and ~300+ open syscalls; hardened Kubernetes (`PodSecurityStandards = restricted`) mandates `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `readOnlyRootFilesystem: true`, and `RuntimeDefault` `seccomp`; rootless `Podman` / `Kubelet` `UserNamespacesSupport` maps container `UID 0` to unprivileged host `kuid`s.
* **Trusted Computing Base (TCB):** The *entire reachable host Linux kernel* (~300+ unfiltered syscalls, VFS, `OverlayFS`, network stack, slab allocator), container runtime (`runc` / `crun`), `containerd` / `CRI-O` shim, and host `SELinux` `sVirt` or `AppArmor` profile.
* **Integration Seam & Handoff:** Provides fast, dense application packaging for trusted or semi-trusted microservices, yet exposes the host kernel to single-bug Ring 0 escapes and runtime FD leaks; motivates user-space kernels (`gVisor`) and `KVM` micro-VMs (`Firecracker`, `Kata`) for untrusted workloads in [Chapter 15](15-gvisor-microvms.md).

## Problem Statement & Threat Model

Search the entire Linux kernel source tree for `struct container` and you will come up empty [114]. Unlike Solaris Zones, FreeBSD Jails, or hardware virtual machines, a Linux "container" is a userspace convention codified by the Open Container Initiative (`OCI` Runtime Specification [114]): an ordinary host `task_struct` launched by `runc` or `crun` after configuring five independent kernel subsystems (`namespaces`, `pivot_root`, `cgroups`, `capabilities`/`LSMs`, and `seccomp-BPF`). Because every container on a Kubernetes worker node executes system calls directly against the exact same Ring 0 host Linux kernel, the famous dictum *containers do not contain* captures a literal architectural truth whenever a workload is untrusted [83, 114, 122].

Under a multi-tenant or post-RCE container threat model, an attacker who compromises a containerized microservice (or supplies a malicious `Dockerfile` / OCI image to a build service) attacks three distinct seams to take over the underlying worker node [117, 118, 119]:
First, *configuration anti-patterns* (`--privileged`, `CAP_SYS_ADMIN`, host `/var/run/docker.sock` or `/` bind mounts, `hostPID: true`, `hostNetwork: true`), which intentionally tear down the container walls and hand the tenant trivial one-line host root access. Second, *shared-kernel Ring 0 vulnerabilities*: even under Docker/`containerd`'s default `seccomp` profile (which blocks roughly 44 dangerous syscalls such as `kexec_load`, `init_module`, `mount`, `bpf`, and `keyctl` [121]), over 300 Linux system calls remain directly exposed to every container thread! Any memory-corruption flaw in `pipe` splicing (`Dirty Pipe` `CVE-2022-0847` [84]), `OverlayFS`, sockets, `io_uring`, or `cgroup` pseudo-filesystems (`CVE-2022-0492` [119]) elevates the container straight to host Ring 0. Third, *container runtime boundary leaks* (`runc` `CVE-2019-5736` [117] and `Leaky Vessels` `CVE-2024-21626` [118]): during `docker run` or `kubectl exec`, a host-privileged runtime process (`runc`) must temporarily enter the container's namespaces while still holding references to host binaries or host file descriptors: creating a razor-sharp cross-domain seam where `/proc/self/exe` or `/proc/self/fd/<N>` magic links allow the container to reach back out and overwrite the host OS!

## Kernel & Userspace Mechanics

### Deconstructing an OCI Container: Namespaces, `pivot_root`, `cgroups v2`, and `seccomp-BPF`

When `containerd-shim` invokes `runc create` against an OCI bundle (`rootfs/` directory + `config.json` [114]), `runc` constructs the container boundary across five sequential kernel phases prior to `execve()`ing the container entrypoint:

![Figure: Internal composition of a shared-kernel OCI container across 8 Linux namespaces, pivot_root, cgroups v2, dropped capabilities, and seccomp-BPF above a single shared host Ring 0 kernel.](diagrams/14-oci-container-primitives.svg)

First, *8 Linux Namespaces (`struct nsproxy`)* partition what system identifiers the task can *see* [80, 114]: `CLONE_NEWNS` isolates the VFS mount table; `CLONE_NEWPID` gives the container its own PID `1` hierarchy; `CLONE_NEWNET` creates an isolated network stack (`lo` + `veth` pair bridged/routed by CNI such as Cilium); `CLONE_NEWIPC` isolates POSIX message queues and SysV shared memory; `CLONE_NEWUTS` isolates hostname; `CLONE_NEWCGROUP` virtualizes `/proc/self/cgroup` paths; `CLONE_NEWTIME` isolates monotonic/boottime clock offsets; and optionally `CLONE_NEWUSER` maps container `UID 0` (`root` inside the image) to an unprivileged high host `kuid` (e.g., `165536` via Kubernetes `hostUsers: false` User Namespaces!) so a container breakout lands as unprivileged `UID 165536` on the host rather than host `UID 0` [80, 114]!

Second, *`pivot_root(2)` vs. `chroot(2)`* [114]. Legacy `chroot()` only changes a single task's root dentry pointer without unmounting the outer filesystem (historically trivial for `UID 0` to escape by opening `.`, calling a nested `chroot("sub")`, and walking `chdir("../../..")` above the unmoved `cwd`!). Container runtimes instead bind-mount the `OverlayFS` `rootfs`, call `pivot_root(new_root, put_old)` inside the private `CLONE_NEWNS` mount namespace to swap the mount namespace's actual root mount, and immediately call `umount2(put_old, MNT_DETACH)` so the host's `/` mount tree is completely detached from the container's mount graph [114]! Inside the new root, `runc` masks sensitive pseudo-paths (`/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/sched_debug`, `/sys/firmware`) by bind-mounting `/dev/null` over files and read-only empty `tmpfs` over directories.

Third, *`cgroups v2` Unified Resource Control (`Documentation/admin-guide/cgroup-v2.rst` [115])*. Unlike `cgroup` v1 (which split controllers across a dozen chaotic hierarchies and included dangerous root-command execution hooks like `release_agent` exploited in `CVE-2022-0492` [119]!), `cgroups v2` organizes every pod and container into a single strict tree under `/sys/fs/cgroup/kubepods.slice/...`, enforcing hard `memory.max` + `memory.swap.max` OOM limits, `cpu.max` bandwidth quotas, `io.max` IOPS caps, `pids.max` fork-bomb ceilings (preventing `:(){ :|:& };:` inside one pod from exhausting global host `pid_max`!), and `BPF_PROG_TYPE_CGROUP_DEVICE` eBPF device access programs blocking `mknod`/open of raw host block/char majors [115].

Fourth, *Capabilities, LSM Labels, and `seccomp-BPF`* [68, 116, 121]. After setting `SELinux` `container_t:s0:cX,cY` MCS labels or the `docker-default` `AppArmor` profile ([Chapter 7](07-stacked-lsms-landlock.md)) and dropping capabilities down to the OCI allowlist (or `drop: ["ALL"]` + `PR_SET_NO_NEW_PRIVS` under hardened Kubernetes specs), `runc` loads a compiled `cBPF` filter via `seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)` [116, 121]. Every syscall checks `struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }`: first verifying `arch == AUDIT_ARCH_X86_64` (or `AARCH64`) so 32-bit `int 0x80` calls die instantly, then blocking `reboot`, `swapon`, `mount`, `umount2`, `pivot_root`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `acct`, `bpf`, `keyctl`, `add_key`, `request_key`, `userfaultfd` (a favorite exploit helper used to pause kernel `copy_from_user()` mid-flight during UAF heap sprays!), `perf_event_open`, and `io_uring_setup` (blocked in modern containerd/Docker profiles after Google's `kCTF` findings [83, 121]). Where runtimes use `SECCOMP_RET_USER_NOTIF` (`seccomp_unotify` [116]) to emulate privileged syscalls such as `mount` or `mknod` safely inside a userspace manager (`Sysbox`, `LXD`), `Documentation/userspace-api/seccomp_filter.rst` warns explicitly: reading a user-space pointer from `/proc/<target>/mem` inside the supervisor is fatally vulnerable to sibling-thread `TOCTOU`; safe supervisors only inject kernel-verified descriptors back via `SECCOMP_IOCTL_NOTIF_ADDFD` without trusting mutable guest pointers [116]!

### Forensic Anatomy of `runc` Escapes: `CVE-2019-5736` and `Leaky Vessels` (`CVE-2024-21626`)

Even when the Linux kernel itself has zero bugs, the userspace C/Go runtime (`runc`) straddles the exact boundary between host and container namespaces [117, 118]:

![Figure: Forensic comparison of runc container breakouts via /proc/self/exe (CVE-2019-5736) and leaked /sys/fs/cgroup file descriptors (Leaky Vessels CVE-2024-21626) alongside their kernel-enforced cures: F_SEAL_WRITE memfd cloning, close_range(), and openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS).](diagrams/14-runc-fd-escape-mechanics.svg)

In `CVE-2019-5736` [117], an attacker replaced `/bin/sh` (or `ld-linux-x86-64.so.2`) inside a container image with a symbolic link `#!/proc/self/exe`! When an administrator ran `docker exec -it <pod> /bin/sh` (or when the malicious image booted), `runc init` joined the container's namespaces and called `execve("/bin/sh")`, which followed `#!/proc/self/exe`: re-executing the host's own `/usr/bin/runc` binary *inside* the container! While `/usr/bin/runc` was still running, Linux's `ETXTBSY` lock prevented overwriting it directly; instead, the attacker's payload inside the container opened `/proc/<runc-pid>/exe` `O_PATH`, waited in a tight loop for `runc` to exit, and the microsecond `ETXTBSY` cleared, reopened `/proc/self/fd/<path_fd>` `O_WRONLY | O_TRUNC`, overwriting `/usr/bin/runc` on the host root filesystem so the next `kubectl`/`docker` command on the node ran attacker code as host `UID 0` [117]! Upstream `runc` closed `CVE-2019-5736` by copying its own binary into an anonymous RAM descriptor (`memfd_create("runc_cloned:/proc/self/exe", MFD_CLOEXEC | MFD_ALLOW_SEALING)`), sealing it irreversibly read-only with `fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE)`, and re-execing from that RAM clone (or using `overlay`/`ro` `/usr` `dm-verity` from [Chapter 3](03-luks2-verity.md), where `/usr/bin/runc` is read-only at the block layer!) [30, 117].

Five years later, Snyk disclosed `Leaky Vessels` (`CVE-2024-21626` [118]): during setup, `runc` opened `/sys/fs/cgroup` on the *host* mount namespace (`fd = 7` or `8`) without preserving `O_CLOEXEC` across internal helpers before `pivot_root`! A malicious `Dockerfile` simply declared `WORKDIR /proc/self/fd/7`: `runc` `chdir()`ed into `fd 7` (placing the container's current working directory on the host mount tree!), `execve()` closed `fd 7`, *yet `/proc/self/cwd` remained alive on the host filesystem*, letting the container process walk `open("../../../../etc/shadow")` straight onto the host node [118]! Today, `runc` and `crun` combine `close_range(3, ~0U, CLOSE_RANGE_CLOEXEC)` with verifying that `/proc/self/cwd` resides inside the container rootfs, while using Linux 5.6+'s `openat2(2)` syscall [120] for all host-to-container file operations:

```c
/* Kernel-enforced root confinement for container runtimes (include/uapi/linux/openat2.h) */
struct open_how how = {
    .flags   = O_RDONLY | O_CLOEXEC,
    .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
};
int fd = syscall(__NR_openat2, rootfs_dfd, untrusted_container_path, &how, sizeof(how));
```

Prior to `openat2(2)`, container runtimes (`Docker`, `runc`, `kubectl cp` `CVE-2019-1002101`) had to resolve symlinks inside untrusted container filesystems entirely in userspace (`filepath-securejoin`), creating an unavoidable `TOCTOU` window where a malicious container process swapped an ordinary directory for a symlink pointing to `/` between the runtime's `readlink()` check and its subsequent `openat()` call [120]! Passing `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` pushes the entire path walk atomically into Ring 0 (`fs/namei.c`): VFS treats `rootfs_dfd` as the filesystem root for every absolute symlink and `..` component inside `link_path_walk()` while rejecting `/proc/<pid>/fd/*` and `/proc/<pid>/exe` magic procfs jumps outright with `-ELOOP`, closing host-to-container symlink races structurally [118, 120].

## Distro, Immutable-OS, & Cloud Trade-Offs

Hardening shared-kernel OCI containers on Kubernetes requires defense in depth across every layer we have covered so far: running nodes on an immutable `dm-verity` OS (`Talos`, `Bottlerocket`, `Flatcar`, `CoreOS`: notice that on `dm-verity` `/usr`, `CVE-2019-5736` overwriting `/usr/bin/runc` fails immediately with `EROFS`! [30, 34]), enforcing `SELinux` `sVirt` MCS labels (`container_t` catches `CVE-2024-21626` `../../etc/shadow` reads immediately with `AVC` denial! [68]), enabling Kubernetes `PodSecurity` `restricted` admission (`runAsNonRoot`, `drop: ["ALL"]`, `RuntimeDefault` `seccomp`), and enabling Kubernetes `hostUsers: false` (`CLONE_NEWUSER` per-pod UID mapping on `Linux 6.3+` `idmapped` mounts). Yet whenever tenants submit genuinely untrusted code: public SaaS build farms, serverless functions, or autonomous AI code interpreters: sharing one host Ring 0 across tenants remains an unacceptable single point of failure, requiring the de-privileged runtimes of [Chapter 15](15-gvisor-microvms.md).

## Seam Failures, CVEs, & Structural Bounds

Container breakouts consistently fall into four architectural categories: dangerous operator flags, `runc` setup leaks, `cgroup` v1 hooks, and shared-kernel Ring 0 CVEs.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `runc` `/proc/self/exe` Overwrite (`CVE-2019-5736`) | 2019 | `runc` binary execution inside container ns | Container cannot write to host `/usr/bin/runc` binary | Symlinks entrypoint to `/proc/self/exe` and reopens host `runc` inode `O_WRONLY` via `/proc/self/fd` on exit | Clone `runc` into `F_SEAL_WRITE` `memfd` + mount host `/usr` on read-only `dm-verity` [30, 117] |
| `cgroup` v1 `release_agent` Escape (`CVE-2022-0492`) | 2022 | Linux `cgroup` v1 `notify_on_release` | `release_agent` requires global host `CAP_SYS_ADMIN` | Missing `init_user_ns` check let `--privileged` or `unshare(CLONE_NEWUSER|CLONE_NEWCGROUP)` write host-root command path to `release_agent` | Migrate completely to unified `cgroups v2` (removes `release_agent` by design!) + keep `seccomp`/`AppArmor` active [115, 119] |
| `--privileged` / `docker.sock` Misconfigurations | Recurring | Container operator deployment manifests | Convenience flags only grant hardware or build access | `--privileged` exposes `/dev/nvme0n1` (`mount /dev/nvme0n1p2 /mnt`); `docker.sock` spawns root host-ns container | Enforce Kubernetes `PodSecurity` `restricted` policy and build images rootlessly (`BuildKit` / `Kaniko`) [114] |
| `Leaky Vessels` (`CVE-2024-21626`) | 2024 | `runc` leaked `/sys/fs/cgroup` dir `fd` | Internal `runc` descriptors are closed before `WORKDIR` `chdir` | `WORKDIR /proc/self/fd/7` anchors container `cwd` onto host mount namespace before `execve`, traversing `../..` to host `/` | Purge descriptors via `close_range(CLOSE_RANGE_CLOEXEC)`, enforce `SELinux` `MCS`, and use `openat2(RESOLVE_NO_MAGICLINKS)` [68, 118, 120] |

## Inspecting on a Live Linux Host

Verify that the host uses unified `cgroups v2` (`cgroup2fs`) rather than legacy `cgroup` v1 and inspect `runc` / `crun` patch versions (`runc >= 1.1.12` closes `CVE-2024-21626`):

```bash
stat -fc %T /sys/fs/cgroup
runc --version 2>/dev/null || crun --version 2>/dev/null || containerd --version 2>/dev/null || true
```

Inspect namespace inode links, `Seccomp` mode (`2` = `SECCOMP_MODE_FILTER`), `NoNewPrivs`, and `CapEff` of any running process (or container PID):

```bash
ls -l /proc/self/ns/
grep -E "^(Name|NoNewPrivs|Seccomp|CapEff):" /proc/self/status
```
