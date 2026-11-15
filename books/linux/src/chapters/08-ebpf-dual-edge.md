# The eBPF Dual Edge: Runtime Security Enforcement vs. Verifier Escapes

## Overview

* **Link in the Chain:** Cross-cutting Interlude spanning Ring 0 ([Part II](05-kernel-lockdown-modules.md)), userspace daemons ([Part III](09-capabilities-userns.md)), and cloud container fleets ([Part IV](14-containers-escapes.md)): executes verified event-driven bytecode directly inside Ring 0 to observe and enforce security invariants, while simultaneously exposing the verifier itself as a critical Ring 0 boundary.
* **Core Security Invariant:** `bpf(BPF_PROG_LOAD)` admits an `eBPF` program for native JIT execution in Ring 0 if and only if static abstract interpretation over all Control-Flow Graph paths proves bounded termination, valid BTF/helper types, and in-bounds pointer arithmetic; once attached to `LSM-BPF` hooks, synchronous programs can atomically veto (`-EPERM`) or terminate (`SIGKILL`) policy-violating tasks on pinned kernel objects.
* **Deployment Profile Matrix:** Cloud-native Kubernetes fleets (`Cilium Tetragon`, `Falco`, `Tracee`, `Datadog`) rely heavily on `eBPF` with `kernel.unprivileged_bpf_disabled=2` so only privileged `CAP_BPF`+`CAP_PERFMON`/`CAP_MAC_ADMIN` pods load programs; regulated enterprise servers migrate from `auditd` to `eBPF` to eliminate netlink drops; hardened sandboxes block `bpf(2)` unconditionally via `seccomp`.
* **Trusted Computing Base (TCB):** `kernel/bpf/verifier.c` abstract interpreter (`tnum` and 32/64-bit interval algebra, state-equivalence pruner), architecture JIT compilers (`arch/x86/net/bpf_jit_comp.c`, `arch/arm64/net/bpf_jit_comp.c`), `BTF` type tables, `LSM-BPF` trampoline hooks, and privileged security agents holding `CAP_BPF` / `CAP_SYS_ADMIN`.
* **Integration Seam & Handoff:** Equips defenders with programmable, race-free `LSM-BPF` inline policy enforcement where static `SELinux`/`AppArmor` profiles lack process-tree or network context, while illustrating why unprivileged `bpf(2)` and excessive Ring 0 capabilities had to be locked down heading into Part III ([Chapter 9](09-capabilities-userns.md)).

## Problem Statement & Threat Model

Every platform trust chain requires an observability and runtime-enforcement nervous system: Windows relies on Event Tracing for Windows (`ETW`) and kernel callbacks; macOS relies on the `EndpointSecurity` (`ES`) framework. Historically, Linux lacked a unified, high-throughput, race-free equivalent [70, 72, 73]. For two decades, defenders chose between two flawed mechanisms: the Linux Audit subsystem (`auditd` [73]), which serializes text-heavy records across a multicast Netlink socket (`NETLINK_AUDIT`) whose kernel backlog (`audit_backlog_limit`) either drops forensic events silently under fork/syscall storms or freezes the entire server when configured to panic on overflow; or out-of-tree `.ko` kernel modules hooking the syscall table (`sys_call_table`), which broke ABI stability on every kernel upgrade, panicked production fleets, and bypassed `UEFI Secure Boot` unless custom-signed [71, 72].

Extended Berkeley Packet Filter (`eBPF`) transformed Linux runtime security by embedding a statically verified, JIT-compiled register virtual machine inside Ring 0 capable of attaching cleanly to `tracepoints`, `kprobes`, `fentry`/`fexit` BTF trampolines, `cgroups`, sockets, and `Linux Security Module` hooks (`LSM-BPF`, formerly `KRSI` [70]) without loading a single `.ko` module! Yet `eBPF` introduces a profound architectural paradox that justifies dedicating this Interlude to its dual nature [69, 74, 75, 76]. Unlike WebAssembly or JVM sandboxes that insert runtime bounds checks before memory loads, `eBPF` relies almost entirely on *compile/load-time static verification* (`kernel/bpf/verifier.c`) so JIT-emitted machine instructions execute at bare-metal Ring 0 speed with *zero* software fault isolation at runtime [69]!

Consider the consequence of that design under two distinct threat models. First, *for the defender* building an Endpoint Detection and Response (`EDR`) or Kubernetes runtime security sensor (`Tetragon` [71], `Falco`, `Tracee` [72]) against an active post-compromise attacker: attaching `eBPF` to the wrong hook layer (`kprobe` on raw syscall entry vs. `LSM-BPF` on resolved kernel structs) reintroduces user-pointer `TOCTOU` races and asynchronous ring-buffer kill lag that let one-shot exploits succeed before `SIGKILL` arrives [70, 71]. Second, *for the attacker* hunting Ring 0 privilege escalation or stealthy post-compromise persistence: a single logical bug in the verifier's 20,000-line abstract interpreter (`ALU32` interval arithmetic or path-pruning equivalence) allows a crafted `eBPF` program that *looks* safe statically to execute arbitrary out-of-bounds Ring 0 memory reads and writes natively on the CPU, while legitimate `eBPF` helpers like `bpf_probe_write_user()` turn `CAP_SYS_ADMIN` / `BPF` access into a fileless user-space code-injection engine [74, 75, 76, 77].

## Kernel & Userspace Mechanics

### The `eBPF` ISA, Verifier Abstract Interpretation (`tnum`), and JIT Compilation

An `eBPF` program consists of 64-bit instructions operating over eleven 64-bit registers (`R0` return value, `R1..R5` function/helper arguments, `R6..R9` callee-saved registers, `R10` read-only frame pointer to a 512-byte stack) and communicating with userspace through typed kernel `BPF` maps (`BPF_MAP_TYPE_HASH`, `ARRAY`, `RINGBUF`, `LRU_HASH`) [69]. When userspace invokes `bpf(BPF_PROG_LOAD, &attr, sizeof(attr))`, `bpf_check()` in `kernel/bpf/verifier.c` must mathematically prove termination and memory safety across all feasible execution paths (up to `BPF_COMPLEXITY_LIMIT_INSNS = 1,000,000` verified dynamic instruction states, supporting bounded loops `bpf_loop` and open-coded iterators) before the architecture JIT (`arch/x86/net/bpf_jit_comp.c`) translates `eBPF` opcodes 1-to-1 into native `x86_64` or `ARM64` Ring 0 instructions [69].

To verify pointer arithmetic without running the program, the verifier performs *path-sensitive abstract interpretation*, maintaining a `struct bpf_reg_state` for every register at every program point [69]. Each scalar register tracks *five simultaneous mathematical domains*: signed 64-bit bounds $[s_{\min}, s_{\max}]$, unsigned 64-bit bounds $[u_{\min}, u_{\max}]$, signed 32-bit sub-register bounds $[s32_{\min}, s32_{\max}]$, unsigned 32-bit bounds $[u32_{\min}, u32_{\max}]$, and a 64-bit *tristate number* (`struct tnum { u64 value; u64 mask; }`) tracking bitwise certainty (`mask` bit $i = 1$ means bit $i$ is unknown; `mask` bit $i = 0$ means bit $i$ is known to equal bit $i$ of `value`, preserving the invariant $(\text{value} \mathbin{\&} \text{mask}) = 0$) [69, 75]:

$$\gamma(\text{reg}) = \left\{\, x \in \{0,1\}^{64} \;\middle|\; (x \mathbin{\&} \neg\text{mask}) = \text{value} \;\land\; x \in [u_{\min}, u_{\max}] \;\land\; \operatorname{sext}_{64}(x) \in [s_{\min}, s_{\max}] \,\right\}$$

After every arithmetic (`BPF_ADD`, `BPF_RSH`, `BPF_AND`) or conditional branch (`BPF_JGE` splitting state into true/false child paths), `__reg_deduce_bounds()` and `__reg_bound_offset()` cross-tighten intervals against `tnum` masks. Whenever the program adds scalar register `R6` to a `PTR_TO_MAP_VALUE` pointer `R0` (`map_value` of size $S$) and dereferences `*(u64 *)(R0 + 0)`, the verifier requires $u_{\max}(\text{R6}) + 8 \le S$ and $s_{\min}(\text{R6}) \ge 0$ [69]. To avoid exponential path explosion on diamond branches, `is_state_visited()` compares the current abstract state $A_{\text{cur}}$ against previously verified states $A_{\text{old}}$ at the same instruction index using `regsafe()`: if every *live* register (registers actually read downstream before being overwritten!) in $A_{\text{cur}}$ has bounds contained within $A_{\text{old}}$ ($\gamma(A_{\text{cur}}) \subseteq \gamma(A_{\text{old}})$), the verifier prunes the path immediately as already proven safe [69, 76].

### Observability vs. Inline Enforcement: `auditd` vs. Ring Buffers vs. `LSM-BPF`

Where an `eBPF` security agent attaches inside the kernel determines whether it acts as a forensic camera or an unbypassable security gate [70, 71, 72]:

![Figure: Architectural trade-offs across legacy Linux Audit (auditd netlink queues), asynchronous tracepoint/kprobe BPF ring-buffer monitors (Falco, Tracee), and synchronous inline LSM-BPF security enforcement (Cilium Tetragon).](diagrams/08-ebpf-lsm-vs-ringbuf-auditd.svg)

First, *asynchronous syscall telemetry* (`CNCF Falco` modern `ebpf` probe, `Aqua Tracee` [72]) attaches `raw_tracepoint/sys_enter` and `sys_exit` (or `fentry` hooks), copies event context into a lockless multi-producer single-consumer `BPF_MAP_TYPE_RINGBUF`, and wakes a userspace Go/C++ rules engine. While orders of magnitude faster and lower-drop than `auditd` netlink sockets [72, 73], asynchronous userspace detection faces two hard physical limits: (1) reading user-space `char __user *` path pointers at `sys_enter` is vulnerable to sibling-thread `TOCTOU` memory swaps unless captured inside VFS, and (2) by the time the userspace daemon parses the ring-buffer event and issues `kill(pid, SIGKILL)`, tens or hundreds of microseconds have elapsed: *more than enough time for a single `write()`, `connect()`, `ioctl()`, or `execve()` syscall to complete its damage* [70, 71]!

Second, `LSM-BPF` (`BPF_PROG_TYPE_LSM`, merged in Linux 5.7 as `CONFIG_BPF_LSM` when `bpf` appears in the boot `lsm=` list [70]) eliminates both flaws simultaneously. Using Compile-Once Run-Everywhere (`CO-RE`) `BTF` type metadata, an `eBPF` program attaches directly as a native callback on any of the 200+ kernel `security_*` LSM hooks (`SEC("lsm/file_open")`, `SEC("lsm/bprm_check_security")`, `SEC("lsm/socket_connect")`, `SEC("lsm/bpf")`) [70]! Inside `SEC("lsm/file_open")`, the verifier gives the `eBPF` program a trusted BTF pointer to the already-resolved `struct file *`: no user-space pointer `TOCTOU` is possible, and returning `-EPERM` directly from the `eBPF` program aborts the `openat()` syscall *synchronously in Ring 0 before a single byte of `/etc/shadow` or a Kubernetes ServiceAccount token is read*! Tools like Cilium `Tetragon` [71] pair `LSM-BPF` return-code blocking (`Override` / `-EPERM`) with synchronous in-kernel `bpf_send_signal(SIGKILL)` wired across process-ancestry, container `cgroup_id`, binary `IMA`/build-id digest, and socket state maps maintained entirely inside Ring 0 BPF maps, stopping container escapes or unexpected `curl`/`bash` spawns on their very first offending instruction with zero userspace round-trip latency [71].

### Verifier Soundness Bugs and Offensive `eBPF` Abuse

Now flip to the attacker's perspective [74, 75, 76]. Why did `kernel/bpf/verifier.c` produce a steady stream of Pwn2Own and `kCTF` Ring 0 exploits between 2020 and 2024? Because abstract interpretation over `64`-bit + `32`-bit + `tnum` domains coupled with liveness-based state pruning is razor-thin: if *any* transfer function under-approximates the concrete values a register can hold ($\exists x_{\text{concrete}} \notin \gamma(\text{reg})$), an attacker constructs a "oracle register" `R6` where the verifier *proves* `R6 == 0`, while on silicon `R6 == 1` [74, 75]!

![Figure: Four-stage exploit mechanics of an eBPF verifier bounds-tracking escape (CVE-2020-8835, CVE-2021-3490, CVE-2023-2163), turning a 1-bit abstract-interpretation divergence into arbitrary Ring 0 memory read/write.](diagrams/08-ebpf-verifier-bounds-escape.svg)

Once the verifier believes `R6 == 0` (`umin = umax = 0`), multiplying `R6 *= 0x1000` still looks like `0` statically (`0 * 0x1000 == 0`), so adding `R6` to a BPF map pointer `R0` passes every bounds check cleanly (`0 + 8 <= map_size`): and the JIT compiler emits raw `imul $0x1000, %rbx; add %rbx, %rax` with *no runtime bounds check*, handing the attacker arbitrary out-of-bounds Ring 0 slab read/write (`KASLR` leak $\to$ fake `bpf_map_ops` vtable or direct `task->cred` overwrite) [74, 75, 76]! Even without a verifier bug, if an attacker compromises a privileged container or monitoring pod holding `CAP_SYS_ADMIN` / `CAP_BPF` + `CAP_PERFMON` on a host lacking `lockdown=confidentiality`, standard tracing helpers become potent post-exploitation weapons [77]: `bpf_probe_read_kernel()` scrapes plaintext `sshd` passwords and TLS session keys from kernel/user memory, while `bpf_probe_write_user()` injects arbitrary bytes directly into the virtual memory of *other* Ring 3 processes (`sshd`, `sudo`, `kubelet`), creating fileless Ring 0-resident rootkits invisible to traditional `ps` and filesystem scanners unless `bpftool prog show` is actively audited [77]!

## Distro, Immutable-OS, & Cloud Trade-Offs

Prior to 2021, many Linux distributions left `kernel.unprivileged_bpf_disabled = 0`, allowing *any* `UID 1000` user to load socket-filter `eBPF` programs and reach the verifier! Today, virtually every mainstream distribution (`Ubuntu`, `Debian`, `RHEL`, `Fedora`, `SUSE`), immutable OS (`Talos`, `Flatcar`, `Bottlerocket`), and hyperscale Kubernetes node sets `kernel.unprivileged_bpf_disabled = 2` (blocking unprivileged `bpf(2)` permanently unless holding `CAP_BPF` or `CAP_SYS_ADMIN` in `init_user_ns`, because `CAP_BPF` is *not* user-namespace-scoped!) [69, 78]. In Kubernetes clusters running `Cilium` and `Tetragon`, only the trusted node-level DaemonSet holds `CAP_BPF` + `CAP_PERFMON` + `CAP_MAC_ADMIN` (`BPF_PROG_TYPE_LSM` requires `CAP_MAC_ADMIN`), while all tenant pods have `bpf(2)` blocked by their default `seccomp` profile ([Chapter 14](14-containers-escapes.md)) [71, 121].

## Seam Failures, CVEs, & Structural Bounds

Landmark `eBPF` failures span 32-bit bounds-tracking defects, bitwise `tnum` bugs, liveness-pruning flaws, `BPF` ring-buffer races, and offensive rootkit abuse of tracing helpers.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2020-8835` (`Pwn2Own`) | 2020 | `verifier.c` `__reg_bound_offset32` | 32-bit `JMP32` bounds sync cleanly with 64-bit `tnum` | Crafted 64/32-bit shift/branch sequence produces `R6` believed `0` (`u32`) while `1` at runtime for OOB R/W | Unify 32/64-bit `reg_bounds_sync()` cross-domain invariants and disable unprivileged `bpf()` [69, 74] |
| `CVE-2021-3490` | 2021 | `verifier.c` `ALU32` bitwise ops (`AND`/`OR`/`XOR`) | `scalar32_min_max_*` updates 32-bit bounds even when `tnum` lower 32 bits are known | Early return skipped `u32_min/max` update when `subreg_def` bitmask was completely known, yielding OOB map R/W | Always compute 32-bit min/max bounds from `tnum` and set `unprivileged_bpf_disabled=2` [75] |
| `CVE-2023-2163` | 2023 | `verifier.c` register parent liveness pruning | Pruned branch correctly marks registers read downstream as `REG_LIVE_READ` | Faulty `mark_chain_precision` parent linkage caused unsafe state equivalence pruning, leaking Ring 0 R/W | Fix precision back-propagation across jump history chains; block `bpf` syscall in containers [76, 121] |
| Async `kprobe` Pathname `TOCTOU` & Kill Lag | 2019-2025 | `kprobe`/`tracepoint` EDR sensors | Reading `sys_enter_openat` user string + async `SIGKILL` stops exploits | Sibling thread swaps user `char *` after `kprobe` fires, or single syscall finishes before userspace reads ringbuf | Enforce synchronous policy on pinned kernel objects via `LSM-BPF` (`BPF_PROG_TYPE_LSM`) [70, 71] |
| Offensive `eBPF` Rootkits (`ebpfkit` / `TripleCross`) | 2021-2024 | `bpf_probe_write_user` & `kprobe` | Loaded `eBPF` programs are exclusively benign observability tools | Post-compromise root loads persistent `BPF` program overwriting `sudo`/`sshd` memory and hiding via `getdents64` | Enable `lockdown=confidentiality` (blocks `bpf_probe_write_user`), sign BPF programs (`fs-verity` `BPF` token/sig), and audit `bpftool` [44, 77] |

Notice the deeper lesson linking `CVE-2020-8835`, `CVE-2021-3490`, and `CVE-2023-2163` straight into Part III: *in-kernel complexity gated only by coarse privilege bits turns any mis-scoped capability into full Ring 0 compromise*. Even after `CAP_BPF` remained restricted to `init_user_ns`, dozens of *other* complex kernel subsystems (`nf_tables`, `OverlayFS`, traffic control) were exposed to unprivileged local users through `POSIX` capabilities and `user_namespaces`, which we examine next in [Chapter 9](09-capabilities-userns.md).

## Inspecting on a Live Linux Host

Check whether unprivileged `eBPF` loading is disabled (`2` = permanently disabled without `CAP_BPF`, `1` = disabled) and whether the `BPF` JIT hardening flag is enabled:

```bash
sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_enable net.core.bpf_jit_harden 2>/dev/null
grep -w "bpf" /sys/kernel/security/lsm 2>/dev/null || echo "LSM-BPF not in active lsm= list"
```

Enumerate every currently loaded `eBPF` program and map in Ring 0 (essential for both verifying `Tetragon`/`Cilium` hooks and hunting `eBPF` rootkits!):

```bash
# Requires CAP_BPF + CAP_PERFMON or root / run0
bpftool prog show 2>/dev/null | head -n 20
bpftool map show 2>/dev/null | head -n 16
```

Inspect whether any loaded `eBPF` program calls dangerous memory-mutation helpers such as `bpf_probe_write_user` or `bpf_override_return`:

```bash
bpftool prog dump xlated id $(bpftool prog list 2>/dev/null | awk -F: 'NR==1{print $1}') 2>/dev/null | grep -E "probe_write_user|override_return" || true
```
