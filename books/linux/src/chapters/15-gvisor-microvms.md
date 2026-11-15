# De-Privileged Runtimes: gVisor User-Space Kernels and KVM Micro-VMs

## Overview

* **Link in the Chain:** Inserts a dedicated memory-safe user-space kernel (`gVisor` `Sentry`) or hardware-virtualized `KVM` micro-VM boundary (`Firecracker`, `Kata Containers`, `Cloud Hypervisor`, `libkrun`) between untrusted OCI containers ([Chapter 14](14-containers-escapes.md)) and the host Linux Ring 0 kernel.
* **Core Security Invariant:** Untrusted tenant machine code never invokes general-purpose host Linux system calls directly; either `gVisor` intercepts all guest syscalls via `systrap`/KVM and services them in memory-safe Go behind a ~53-syscall host `seccomp` filter, or hardware `VT-x`/`SVM` (`EPT`/`NPT`) and `ARM64` `EL2` (`Stage-2`) trap guest execution inside a dedicated per-pod Linux kernel backed by a minimal jailed Rust VMM (~35 host syscalls).
* **Deployment Profile Matrix:** Standard internal microservices run on `runc`/`crun` for zero overhead; multi-tenant SaaS, serverless functions (`AWS Lambda`/`Fargate`, `Cloud Run`, `Fly.io`), and untrusted AI code sandboxes ([Chapter 17](17-ai-agent-sandboxes.md)) deploy Kubernetes `RuntimeClass` `gvisor` (`runsc`) or `kata` (`Firecracker` / `Cloud Hypervisor` / `Dragonball`); developer laptops use `libkrun` (`Podman` / `krunvm`).
* **Trusted Computing Base (TCB):** For `gVisor`: Go `Sentry` + `Gofer` processes and ~53 host syscalls (`futex`, `mmap`, `epoll`); for micro-VMs: CPU `EPT`/`Stage-2` silicon, host `KVM` (`arch/*/kvm/`), jailed Rust VMM (`Firecracker` / `Cloud Hypervisor`), and isolated `virtiofsd` file daemon.
* **Integration Seam & Handoff:** Slashes host Ring 0 syscall exposure by ~85-90% and contains guest kernel zero-days inside single-pod boundaries; hands off cryptographic cloud workload identity (`OIDC`, `IMDSv2`, `SPIFFE`) to [Chapter 16](16-workload-identity-spiffe.md) and AI agent network/secret isolation to [Chapter 17](17-ai-agent-sandboxes.md).

## Problem Statement & Threat Model

In [Chapter 14](14-containers-escapes.md), we saw why shared-kernel `runc` containers cannot safely isolate adversarial tenants: even with `CAP_SYS_ADMIN` dropped and 44 dangerous syscalls filtered by `seccomp-BPF`, over 300 complex C system calls (`epoll`, `futex`, `splice`, `socket`, `setsockopt`, `sendmsg`, `mmap`, VFS filesystems, TCP/IP stacks) execute directly inside the host's single Ring 0 address space [121, 122]. One Use-After-Free in any reachable host syscall compromises every sibling pod on the 128-core Kubernetes node simultaneously! Conversely, traditional heavyweight Infrastructure-as-a-Service virtual machines (`QEMU` emulating legacy 1990s `i440fx`/`Q35` motherboards, `BIOS`, `IDE`, `floppy`, `USB`, `VGA`, and 1.5+ million lines of C device models booting a multi-second distro VM per container) sacrificed the millisecond startup, sub-10 MiB memory density, and OCI image workflow that made containers transformative [123, 124].

Platform engineers isolating serverless functions (`AWS Lambda`), multi-tenant Kubernetes pods (`GKE Sandbox`, `AKS` Sandboxed Containers), CI build jobs, or LLM-generated Python/Bash execution ([Chapter 17](17-ai-agent-sandboxes.md)) face a hostile-code threat model: assume the tenant starts with *arbitrary machine-code execution inside the container* and actively fuzzes every syscall, `/proc` file, network packet, and filesystem operation to escape onto the host worker node. Meeting container density and OCI compatibility while severing direct access to host Ring 0 produced two complementary architectural lineages on Linux: User-Space Application Kernels (`Google gVisor` [122]) and Minimalist Rust `KVM` Micro-VMs (`AWS Firecracker`, `Kata Containers`, `Cloud Hypervisor`, and `libkrun` [123, 124, 125, 126]).

## Kernel & Userspace Mechanics

### User-Space Syscall Reimplementation: `gVisor` (`Sentry`, `systrap`, and `Gofer`)

Implemented as an OCI-compliant runtime (`runsc`, selectable per pod in Kubernetes via `runtimeClassName: gvisor`), Google `gVisor` [122] asks a radical question: *instead of passing application syscalls through to the host Linux kernel in C, what if a dedicated per-pod process written in memory-safe, garbage-collected Go implemented the Linux syscall ABI (`mm`, `vfs2`, `tcpip` `netstack`, `ipc`, signals, `/proc`) in Ring 3 userspace?*

![Figure: Architectural trade-off matrix comparing shared-kernel OCI containers (runc/crun), memory-safe Go user-space kernels (gVisor Sentry + Gofer), and hardware-virtualized KVM micro-VMs (Firecracker, Kata Containers, Cloud Hypervisor).](diagrams/15-shared-kernel-vs-gvisor-microvm.svg)

Trace what happens when an untrusted Python binary inside a `gVisor` pod executes `syscall` (`openat`, `socket`, or `connect`) [122]:
First, *Syscall Interception (`systrap`)*: the untrusted process must *never* be allowed to execute a real host syscall! Early `gVisor` used Linux `PTRACE_SYSEMU` (portable anywhere, even inside nested VMs lacking `/dev/kvm`, at high context-switch latency) or `KVM` ring transitions. Since 2023, `gVisor`'s default `systrap` platform combines `seccomp-BPF` (`SECCOMP_RET_TRAP` delivering `SIGSYS` on the first `syscall` instruction at any address) with dynamic binary hot-patching: on the first trap, `Sentry` replaces the 2-byte `syscall` (`0f 05`) opcode with a relative `jmp` into a shared-memory trampoline that switches stacks and wakes a `Sentry` worker thread *entirely in userspace* via shared-memory polling (`futex` fallback), cutting syscall interception overhead from microseconds down to sub-hundreds of nanoseconds without requiring `/dev/kvm` hardware virtualization [122]!

Second, *Memory-Safe Syscall Execution (`Sentry`) & Least-Privilege File Proxy (`Gofer`)* [122]: inside `Sentry`, the guest's `socket()` and `connect()` calls never touch the host Linux TCP/IP stack (`net/ipv4` or `nf_tables`)! Instead, `Sentry` runs its own Go TCP/IP stack (`netstack`) over raw Layer-2/3 frames read from the pod's `veth` device. What if an attacker triggers a bug in `Sentry` itself? Because `Sentry` is written in bounds-checked Go, classic C buffer overflows and slab UAFs panic cleanly (`recover` / pod crash) rather than yielding RCE; *and even if an attacker somehow achieved RCE inside `Sentry`*, `Sentry` runs inside an empty `pivot_root` + user/mount/net/ipc/pid namespaces with zero direct access to the host filesystem and a tight ~53-syscall host `seccomp-BPF` filter (`mmap`, `munmap`, `futex`, `epoll_pwait`, `read`/`write` on pre-opened FDs: blocking `openat` completely!) [122]! All container filesystem operations (`vfs2`) are serialized over `AF_UNIX` using `gVisor`'s minimal `lisafs` protocol to a separate, heavily sandboxed `Gofer` process locked inside the pod's rootfs directory via `O_NOFOLLOW` / capability-dropped descriptors [122]. An attacker must chain a bug in Go `Sentry` *plus* a second bug in `Gofer` or one of ~53 core host syscalls to reach the host!

### Hardware-Virtualized `KVM` Micro-VMs: `Firecracker`, `Kata`, `Cloud Hypervisor`, and `libkrun`

Where `gVisor` emulates the Linux ABI in Go (occasionally diverging on bleeding-edge Linux syscalls, raw `io_uring`, eBPF inside pods, or direct `NVIDIA` GPU `VFIO` passthrough), KVM Micro-VMs execute an unmodified, stripped *real Linux guest kernel* inside hardware-enforced CPU virtualization (`Intel VT-x` + `EPT`, `AMD-V` + `NPT`, `ARM64 EL2` + `Stage-2`) while stripping 95% of legacy `QEMU` VMM attack surface [123, 124, 125]:

![Figure: End-to-end execution and I/O datapath of a KVM micro-VM container (Kata Containers, Firecracker, Cloud Hypervisor), isolating untrusted guest Ring 3 and guest Ring 0 behind hardware EPT/Stage-2 page tables and a seccomp-jailed Rust VMM.](diagrams/15-firecracker-kata-datapath.svg)

Pioneered by Amazon Web Services in Rust (`rust-vmm`) to power `AWS Lambda` and `AWS Fargate` (`NSDI '20` [123]), `Firecracker` strips virtual hardware down to five minimal `virtio` / serial devices: `virtio-net`, `virtio-blk`, `virtio-vsock`, a minimal `virtio-balloon`/entropy device, and a 1-button `i8042` reset controller (`~50,000` lines of memory-safe Rust vs. `> 1.5M` lines of C in `QEMU`, zero BIOS/UEFI needed when booting uncompressed `vmlinux` directly via the x86/ARM64 direct boot protocol!). Every `Firecracker` micro-VM adds `< 5 MiB` of VMM memory overhead, cold-boots a minimal Linux guest in `~125 ms`, or restores from a pre-warmed memory snapshot in `< 5 ms` [123]!

> **Warning.**
> Restoring dozens of `Firecracker` micro-VMs from an identical memory snapshot clones the guest kernel's CSPRNG entropy pool (`/dev/urandom` ChaCha20 state) and TLS/TCP sequence states identically across every clone ("Virtual Machine Forking Nonce Reuse", breaking AES-GCM and ECDSA instantly if two clones generate identical nonces!). Production snapshot-restore pipelines *must* enable Virtual Machine Generation ID (`VMGENID` ACPI notification integrated in Linux `5.18+` `drivers/char/random.c`), which triggers an immediate synchronous `crng_reseed()` from hardware `RDRAND`/`virtio-rng` inside guest Ring 0 before guest Ring 3 executes a single post-restore instruction [123]!

Outside the guest, `Firecracker`'s companion `jailer` wrapper drops the VMM into a unique unprivileged `UID`/`GID`, `chroot`s into an empty per-VM directory, places it in dedicated `cgroups v2` + `netns`, and installs per-thread `seccomp-BPF` allowlists (~35 host syscalls: `ioctl` restricted strictly to exact `KVM_*` request codes, `read`/`write`, `epoll`, `futex`) [123].

To expose micro-VMs seamlessly as standard Kubernetes pods (`runtimeClassName: kata`) supporting multi-container pods, OCI layer sharing, and hotplugged GPUs/PCIe `VFIO`, `Kata Containers 3.x` [124] pairs a Rust `containerd-shim-kata-v2` (including an embedded `Dragonball` Rust VMM or external `Cloud Hypervisor` [125] / `Firecracker`) with an in-guest Rust `kata-agent` reached over `AF_VSOCK` `ttrpc`! How do OCI container filesystem layers enter the micro-VM? Either as block-mapped `dm-verity` / `EROFS` `virtio-blk` devices (fastest and lowest host attack surface, used by `Firecracker` snapshotter and Confidential Containers in [Chapter 19](19-confidential-containers.md)!) or via `virtio-fs` [127], where a host Rust daemon (`virtiofsd`) serves `FUSE` opcodes across a shared `virtqueue` ring buffer (hardened inside its own `pivot_root` + `Landlock` + `seccomp` + capability-dropped sandbox so a rogue guest kernel sending crafted `FUSE` messages cannot traverse outside the container rootfs!). Finally, on developer workstations and edge nodes, `libkrun` (`containers/libkrun`, integrated directly into `crun --krun` and `Podman` [126]) packages a complete `KVM` micro-VM monitor as a tiny dynamic library (`libkrun.so`) with Transparent Socket Impersonation (`TSI`), turning any OCI container into an instant hardware-isolated micro-VM with zero root daemons!

## Distro, Immutable-OS, & Cloud Trade-Offs

Choosing among hardened `runc`/`crun`, `gVisor` (`runsc`), and `KVM` micro-VMs (`Firecracker` / `Kata` / `Cloud Hypervisor`) reduces to three concrete workload constraints [122, 123, 124]:
First, *hardware availability*: `Firecracker`, `Kata`, and `libkrun` require bare-metal `/dev/kvm` or cloud instances with *nested virtualization* enabled (`AWS .metal` or Nitro nested-virt instances, `Azure Dv5/Ev5`, `GCP C3/N2` nested virt), whereas `gVisor` `systrap` runs anywhere in pure userspace: including inside non-nested cloud VMs! Second, *I/O vs. CPU profile*: pure compute (`Python`/LLM data processing, crypto, compilation) runs at near-100% native speed inside `KVM` micro-VMs (since guest Ring 3 instructions run directly on the physical CPU with `EPT` TLB caching) while `gVisor` adds modest overhead on heavy `mmap`/filesystem-metadata storms (`npm install` / `git checkout` over `Gofer`). Third, *kernel ABI fidelity*: workloads requiring exact Linux `6.x` kernel semantics, custom guest `eBPF`, or PCIe `VFIO` GPU passthrough (`Cloud Hypervisor` + `Kata`) choose `KVM` micro-VMs, whereas dense HTTP/gRPC stateless microservices without `/dev/kvm` thrive on `gVisor`.

## Seam Failures, CVEs, & Structural Bounds

Even inside `gVisor` or `KVM` micro-VMs, attackers target the narrow remaining bridges back to the host: `virtio` device ring parsers, `virtiofsd` FUSE handlers, snapshot RNG cloning, and CPU microarchitectural side channels (`L1TF` / `MDS` / `Cross-HT`).

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `virtiofsd` / Host-Share Symlink & FUSE Bugs (`CVE-2020-35517` class) | 2020-2023 | Early C `virtiofsd` (`CAP_DAC_READ_SEARCH`) | Malicious guest Ring 0 cannot escape shared directory via `FUSE` | Rogue guest kernel crafts `FUSE` device/handle requests to open host inodes outside shared rootfs | Rewrite `virtiofsd` in Rust, drop `CAP_DAC_READ_SEARCH`, confine with `pivot_root` + `openat2(RESOLVE_IN_ROOT)`, or use `virtio-blk` `dm-verity` [120, 124, 127] |
| Hyper-Threading Microarchitectural Leaks (`L1TF`, `MDS`, `Retbleed`) | 2018-2024 | Shared physical CPU SMT siblings under `KVM` | `EPT` page tables block cross-VM cache/buffer reads on sibling hyperthreads | Malicious micro-VM samples L1D / CPU fill buffers concurrently with victim micro-VM on sibling SMT thread | Enable Linux Core Scheduling (`PR_SCHED_CORE` / `Firecracker` core tagging) or disable SMT on multi-tenant bare metal [51, 123] |
| Micro-VM Snapshot CSPRNG Nonce Reuse | 2020-2023 | Cloned `Firecracker` / `QEMU` VM snapshots | Restored VM snapshots generate unique random TLS/key nonces | Two restored clones inherit identical guest `/dev/urandom` pool and emit colliding ECDSA/GCM nonces | Mandate `VMGENID` + `virtio-rng` synchronous guest `crng` reseeding prior to network unblock [123] |
| `gVisor` `Sentry` Logic Bugs (`CVE-2024-21626`-style netstack/fs) | 2021-2024 | `gVisor` Go `Sentry` | Application kernel has zero bugs | Logic flaw inside `Sentry` VFS/socket state machine | Contained by Go memory safety + `Sentry`'s 53-syscall `seccomp` jail + separate `Gofer` boundary [122] |

Isolating compute inside a `runc`, `gVisor`, or `Firecracker` boundary solves only half of cloud workload security: once that isolated workload boots, how does it authenticate to S3, databases, or peer microservices *without* baking static cloud API keys into the image or exposing the worker node's IAM role to Server-Side Request Forgery (`SSRF`)? [Chapter 16](16-workload-identity-spiffe.md) builds cryptographic cloud workload identity.

## Inspecting on a Live Linux Host

Check whether hardware virtualization (`/dev/kvm` with `vmx` on Intel or `svm` on AMD) is available to host `Firecracker`, `Kata`, `Cloud Hypervisor`, or `libkrun` micro-VMs:

```bash
ls -la /dev/kvm 2>/dev/null || echo "/dev/kvm not exposed on this host"
grep -Ec '(vmx|svm)' /proc/cpuinfo 2>/dev/null || true
```

Inspect installed de-privileged container runtimes (`runsc` for `gVisor`, `firecracker`, `kata-runtime`, `krun`) and verify `containerd` `RuntimeClass` shims:

```bash
for bin in runsc firecracker kata-runtime cloud-hypervisor krunvm; do command -v "$bin" 2>/dev/null; done
grep -rn "runtime_type" /etc/containerd/ 2>/dev/null | head -n 10 || true
```
