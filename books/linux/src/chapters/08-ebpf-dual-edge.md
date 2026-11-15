# The eBPF Dual Edge: Runtime Security Enforcement vs. Verifier Escapes

## Overview

* **Link in the Chain:** Cross-cutting Interlude spanning Ring 0 ([Part II](05-kernel-lockdown-modules.md)), userspace daemons ([Part III](09-capabilities-userns.md)), and cloud container fleets ([Part IV](14-containers-escapes.md)): executes statically verified event-driven bytecode natively inside Ring 0 to observe and enforce security policy, while exposing `kernel/bpf/verifier.c` itself as a high-value Ring 0 boundary.
* **Core Security Invariant:** `bpf(BPF_PROG_LOAD)` admits an `eBPF` program for native JIT execution in Ring 0 if and only if abstract interpretation across all Control-Flow Graph paths proves bounded termination, valid `BTF` pointer types, Spectre-clamped pointer offsets (`alu_limit`), and sound multi-domain bounds (`tnum` plus 32/64-bit intervals); attached to `LSM-BPF`, programs synchronously veto (`-EPERM`) or terminate (`SIGKILL`) offending tasks on pinned kernel structs.
* **Deployment Profile Matrix:** Cloud-native Kubernetes fleets (`Cilium Tetragon`, `Falco`, `Tracee`) run `eBPF` node agents with `kernel.unprivileged_bpf_disabled=2` so only `init_user_ns` `CAP_BPF`+`CAP_PERFMON`/`CAP_MAC_ADMIN` pods (or scoped `BPF_TOKEN` mounts) load programs; enterprise hosts enable `lockdown=confidentiality` and `fs-verity` signed BPF policies; tenant containers block `bpf(2)` unconditionally via `seccomp`.
* **Trusted Computing Base (TCB):** `kernel/bpf/verifier.c` and `include/linux/bpf_verifier.h` (`struct bpf_reg_state`, `struct tnum`, `reg_bounds_sync`, `mark_chain_precision`), architecture JITs (`arch/x86/net/bpf_jit_comp.c`, `arch/arm64/net/bpf_jit_comp.c`), `BTF` kernel metadata, `LSM-BPF` trampolines, and `CAP_BPF`/`CAP_SYS_ADMIN` loaders.
* **Integration Seam & Handoff:** Supplies programmable, race-free `LSM-BPF` inline enforcement where static `SELinux`/`AppArmor`/`Landlock` profiles ([Chapter 7](07-stacked-lsms-landlock.md)) lack process-ancestry or socket context, while proving why unprivileged Ring 0 bytecode and coarse capabilities had to be gated heading into Part III ([Chapter 9](09-capabilities-userns.md)).

## Problem Statement & Threat Model

Every operating-system trust chain requires a high-throughput runtime telemetry and inline enforcement subsystem: Windows pairs Event Tracing for Windows (`ETW`) with kernel object/process callbacks, and macOS provides the `EndpointSecurity` (`ES`) framework. For two decades, Linux forced defenders into an untenable trade-off between two flawed architectures [34, 273, 274]. On one side stood the Linux Audit subsystem (`auditd` and `kernel/audit.c` [274]), which formats text-heavy syscall records onto a multicast Netlink queue (`NETLINK_AUDIT`). Under high-rate container fork/exec bursts or deliberate attacker syscall floods, `kauditd`'s bounded `audit_backlog_limit` queue either silently drops forensic evidence (`audit_log_lost()`) or intentionally panics the entire server when configured for strict compliance (`audit=2` / `-f 2`), while providing zero ability to block an attack inline [274]. On the other side stood out-of-tree `.ko` kernel modules hooking `sys_call_table` or unstable internal symbols: a brittle model that crashed production nodes across minor kernel updates and collided head-on with `UEFI Secure Boot` and `Kernel Lockdown` ([Chapter 5](05-kernel-lockdown-modules.md)) [5, 35].

Extended Berkeley Packet Filter (`eBPF`, standardized in `RFC 9669` [275]) broke this deadlock by embedding a register-based virtual machine and native Just-In-Time (`JIT`) compiler directly inside Ring 0, capable of attaching ABI-portably via `BTF` Compile-Once Run-Everywhere (`CO-RE`) metadata to `tracepoints`, `kprobes`, `fentry`/`fexit` trampolines, `XDP` network drivers, `cgroups`, and `Linux Security Module` hooks (`LSM-BPF` [34]) without loading a single `.ko` module. Yet `eBPF` introduces a sharp architectural duality that makes it simultaneously Linux's strongest runtime defense and one of its most fiercely contested Ring 0 attack surfaces [58, 59, 60, 276]. Unlike WebAssembly or JVM runtimes that emit dynamic bounds checks before memory dereferences, `eBPF` achieves bare-metal Ring 0 speed by relying almost exclusively on *load-time static abstract interpretation* (`kernel/bpf/verifier.c` [277]): once `bpf_check()` certifies a program safe, the `x86_64` or `ARM64` JIT emits raw native machine loads and stores with *zero runtime Software Fault Isolation (`SFI`)*!

That single design choice creates symmetric high-stakes engineering problems for both defenders and attackers:
For the *defender* deploying `Cilium Tetragon` [35, 278], `CNCF Falco`, or `Aqua Tracee` [273] against a post-compromise container adversary, hooking at the wrong kernel seam (`raw_tracepoint/sys_enter` with asynchronous `BPF_MAP_TYPE_RINGBUF` userspace alerts vs. synchronous `LSM-BPF` hooks on resolved VFS objects) reintroduces user-memory `TOCTOU` path swaps and microsecond `SIGKILL` delivery races that allow single-syscall exploits to finish before userspace reacts [34, 35, 279].
Conversely, for the *attacker*, a subtle 1-bit soundness bug anywhere inside `verifier.c`'s 25,000+ lines of multi-domain interval arithmetic, `tnum` bitwise tracking, or state-equivalence pruning turns a verification mismatch into arbitrary native Ring 0 read/write (`CVE-2017-16995` [280], `CVE-2020-8835` [59], `CVE-2021-3490` [60], `CVE-2023-2163` [281]), while legitimate tracing helpers such as `bpf_probe_write_user()` and `fexit` hooks enable stealthy Ring 0-resident rootkits (`ebpfkit` [282], `TripleCross` [283]) if `CAP_BPF`/`CAP_SYS_ADMIN` and `Lockdown` are misconfigured.

## Kernel & Userspace Mechanics

### `kernel/bpf/verifier.c`: `struct bpf_reg_state`, `tnum` Algebra, Pruning, and Spectre `alu_limit`

An `eBPF` program (`RFC 9669` [275]) executes 64-bit RISC instructions over eleven 64-bit registers (`R0` return value, `R1..R5` scratch caller arguments, `R6..R9` callee-saved registers, and `R10` read-only frame pointer addressing a `512`-byte stack) while exchanging persistent state through typed `BPF` maps. When userspace invokes `bpf(BPF_PROG_LOAD, &attr, sizeof(attr))`, `bpf_check()` in `kernel/bpf/verifier.c` [58, 277] validates Control-Flow Graph structure and walks every feasible execution path up to `BPF_COMPLEXITY_LIMIT_INSNS = 1,000,000` dynamic instruction states (verifying bounded loops `bpf_loop` and open-coded `bpf_iter_*` iterators). Every 8-byte stack slot is tracked via `struct bpf_stack_state` (`STACK_INVALID`, `STACK_SPILL` preserving full spilled register metadata, `STACK_MISC`, `STACK_ZERO`, `STACK_DYNPTR`, `STACK_ITER`), and every register carries a `struct bpf_reg_state` (`include/linux/bpf_verifier.h` [277]) encoding its static type (`NOT_INIT`, `SCALAR_VALUE`, `PTR_TO_CTX`, `PTR_TO_MAP_VALUE`, `PTR_TO_MAP_VALUE_OR_NULL`, `PTR_TO_STACK`, `PTR_TO_BTF_ID`, `PTR_TO_MEM`) plus its offset/value abstract domains.

![Figure: Internal five-domain abstract register lattice in kernel/bpf/verifier.c (struct tnum bitwise certainty plus 64-bit and 32-bit signed/unsigned intervals), synchronized via reg_bounds_sync() and sanitize_ptr_alu() against Spectre v1 and soundness escapes.](diagrams/08-extra-tnum-bounds-divergence.svg)

Why does `struct bpf_reg_state` track *five simultaneous numerical domains* on every `SCALAR_VALUE` and variable pointer offset [58, 277, 284, 285]? Because real BPF programs interleave 64-bit shifts, 32-bit sub-register operations (`ALU32` on `w0..w9`, which zero-extend upper bits `32..63`), bitwise masks (`BPF_AND`, `BPF_OR`, `BPF_XOR`), and signed/unsigned conditional jumps (`BPF_JGT` vs. `BPF_JSGE`). No single interval domain captures both range inequalities and individual bit masks accurately! Linux therefore pairs signed 64-bit bounds $[s_{\min}, s_{\max}]$, unsigned 64-bit bounds $[u_{\min}, u_{\max}]$ (unified as circular range `struct cnum64 r64` in recent mainline `bpf_verifier.h` [277]), signed 32-bit bounds $[s32_{\min}, s32_{\max}]$, and unsigned 32-bit bounds $[u32_{\min}, u32_{\max}]$ (`struct cnum32 r32`) with Edward Cree's *tracked tristate number* (`struct tnum` in `include/linux/tnum.h` [285], formally analyzed by Vishwanathan et al. at CGO 2022 [284]):

```c
/* include/linux/tnum.h & bpf_verifier.h: Bitwise tristate + interval state */
struct tnum {
    u64 value; /* Known 1 bits: bit i == 1 means concrete bit i is 1       */
    u64 mask;  /* Unknown bits: bit i == 1 means bit i is unknown ('x')    */
};             /* Soundness invariant: (value & mask) == 0 at every step!  */
```

In `struct tnum`, any bit position $i \in \{0..63\}$ has `(value_i, mask_i) = (0, 0)` (known `0`), `(1, 0)` (known `1`), or `(0, 1)` (unknown `x`); `(1, 1)` is illegal (`(value & mask) == 0`) [284, 285]. Arithmetic operators propagate carries conservatively across unknown bits: for instance, `tnum_add(a, b)` computes minimum sum `sv = a.value + b.value`, maximum possible carry propagation `sigma = sv + a.mask + b.mask`, and uncertain carry bits `chi = sigma ^ sv`, setting `mu = chi | a.mask | b.mask` and returning `{ .value = sv & ~mu, .mask = mu }` [284, 285]. A register's concrete value set $\gamma(\text{reg})$ is the exact intersection of all five domains:

$$\gamma(\text{reg}) = \left\{\, x \in \{0,1\}^{64} \;\middle|\; (x \mathbin{\&} \neg\text{mask}) = \text{value} \;\land\; x \in [u_{\min}, u_{\max}] \;\land\; \operatorname{sext}_{64}(x) \in [s_{\min}, s_{\max}] \;\land\; x_{31:0} \in [u32_{\min}, u32_{\max}] \;\land\; \operatorname{sext}_{32}(x_{31:0}) \in [s32_{\min}, s32_{\max}] \,\right\}$$

After every `ALU` instruction or conditional branch (which forks verification into fallthrough and target `bpf_verifier_state` states with complementary interval constraints), `reg_bounds_sync()` cross-tightens all five domains (`__reg_deduce_bounds()`, `__reg_bound_offset()`) so bits newly fixed in `var_off` shrink `[umin, umax]` and vice versa [277, 284]. When a program adds scalar `R6` to `PTR_TO_MAP_VALUE` `R0` (pointing into a map value of size $S$) and accesses $k$ bytes at fixed offset `off`, `check_mem_region_access()` requires $s_{\min}(\text{R6}) + \text{off} \ge 0$ and $u_{\max}(\text{R6}) + \text{off} + k \le S$ [58, 277].

Two additional verifier passes directly govern both scalability and microarchitectural safety [286, 287, 288]:
First, *State Equivalence Pruning and Precision Backtracking* (`is_state_visited()`, `regsafe()`, and `mark_chain_precision()` [277, 286]). Without path merging, 30 sequential `if` diamonds yield $2^{30}$ paths. At prune points, the verifier checks whether the current state $A_{\text{cur}}$ is subsumed by an already-verified state $A_{\text{old}}$ at the same instruction index (`regsafe()`). Crucially, exact scalar bounds matter *only* if that scalar later influences a pointer dereference, helper call, or branch condition (`reg->precise == 1`)! Scalars initially remain imprecise (`precise = 0`, matching any `SCALAR_VALUE` in `A_old` for fast pruning); the moment a scalar is added to a pointer, `mark_chain_precision()` walks backward through the parent jump history (`st->parent`) marking all ancestor registers that contributed to that value `precise = 1` [286].
Second, *Spectre v1 Speculative Bounds Clamping* (`sanitize_ptr_alu()`, introduced after Jann Horn's `CVE-2019-7308` [287] and hardened after `CVE-2021-33624` [288]). Even when `if (R6 < 64)` proves `R0 + R6` stays in-bounds architecturally, CPU branch predictors can mispredict the branch and speculatively dereference `*(R0 + R6)` with an attacker-chosen out-of-bounds `R6`, leaking arbitrary Ring 0 secrets into CPU cache lines (`Spectre v1`)! Under unprivileged or hardened verification, `sanitize_ptr_alu()` calculates the maximum safe offset `alu_limit` and patches branchless masking arithmetic (`aux->alu_limit`) directly into the instruction stream so even transient speculative execution stays strictly inside `[R0, R0 + S)` [287, 288].

Once `bpf_check()` certifies every CFG path, `bpf_int_jit_compile()` (`arch/x86/net/bpf_jit_comp.c` and `arch/arm64/net/bpf_jit_comp.c`) maps BPF virtual registers `R0..R10` one-to-one onto hardware registers (`%rax`, `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%rbx`, `%r13..%r15`, and `%rbp` on `x86_64`), seals the resulting machine page read-execute (`set_memory_rox()`), and wires the entry point into a `BTF` direct-call trampoline (`bpf_trampoline`) [58, 277]. Unlike legacy `kprobes` that overwrite kernel instructions with `int3` (`0xcc`) breakpoint traps triggering expensive hardware debug exceptions on every hit, `fentry`, `fexit`, and `LSM-BPF` trampolines patch a 5-byte `call` directly into the `ftrace` NOP sled at function entry, executing verified BPF logic with single-digit nanosecond overhead.

### Telemetry vs. Synchronous Enforcement: `kauditd` vs. `RINGBUF` vs. `LSM-BPF`

Where a defender anchors `eBPF` inside Ring 0 determines whether the sensor is merely a post-mortem flight recorder or a race-free security boundary [34, 35, 273, 279]:

![Figure: Architectural trade-offs across legacy Linux Audit (auditd netlink queues), asynchronous tracepoint/kprobe BPF ring-buffer monitors (Falco, Tracee), and synchronous inline LSM-BPF security enforcement (Cilium Tetragon).](diagrams/08-ebpf-lsm-vs-ringbuf-auditd.svg)

Legacy `auditd` (`kernel/audit.c` [274]) allocates a fresh `struct sk_buff` per syscall audit record, formats key-value ASCII strings inside Ring 0, and wakes `kauditd_thread` to multicast packets over `NETLINK_AUDIT`. By contrast, Andrii Nakryiko's `BPF_MAP_TYPE_RINGBUF` (`kernel/bpf/ringbuf.c` [279]) exposes a single shared, page-mapped lockless multi-producer single-consumer (`MPSC`) ring buffer across all CPUs using a two-phase `bpf_ringbuf_reserve()` / `bpf_ringbuf_submit()` protocol: producers atomically advance a reservation counter via `cmpxchg`, write binary struct fields directly into the shared page without extra copies, and flip a length-header busy bit so userspace `epoll` readers consume events strictly in-order across CPUs.

Yet even with `BPF_MAP_TYPE_RINGBUF`'s millions-of-events-per-second throughput, *asynchronous `tracepoint` and `kprobe` sensors* (`CNCF Falco` modern eBPF driver and `Aqua Tracee` [273]) cannot serve as hard inline prevention gates for two fundamental reasons:
First, *user-memory `TOCTOU` races at syscall entry*: attaching to `raw_tracepoint/sys_enter` (`sys_enter_openat` or `sys_enter_execve`) exposes raw syscall register arguments (`const char __user *filename` living in mutable Ring 3 memory!). When the BPF program calls `bpf_probe_read_user_str()` to inspect `filename`, the kernel VFS has *not yet copied* that string into kernel space (`getname_flags()`). A sibling attacker thread sharing `CLONE_VM` can flip the user buffer between `"/tmp/safe"` and `"/etc/shadow"` in the nanoseconds between `sys_enter` and VFS lookup, blinding the sensor completely [34]!
Second, *asynchronous kill latency*: even when an async sensor hooks deeper `fentry/security_file_open` functions to read kernel structs, streaming the event through `BPF_MAP_TYPE_RINGBUF` to a Ring 3 Go/C++ policy engine that evaluates rules and calls `kill(pid, SIGKILL)` incurs $20\text{ to }500\;\mu\text{s}$ of wakeup and scheduling delay. By the time `SIGKILL` lands, a single offending syscall (`openat` + `read` on a Kubernetes `ServiceAccount` JWT, `connect` exfiltrating an env var, or `write` into `/proc/sysrq-trigger`) has already returned to Ring 3 and transmitted the secret [34, 35]!

Merged in Linux 5.7 (`CONFIG_BPF_LSM=y`, active when `bpf` is listed in `CONFIG_LSM` / `lsm=` [34, 289]), `LSM-BPF` (`BPF_PROG_TYPE_LSM`) closes both flaws structurally. Using `BTF` type signatures, `SEC("lsm/file_open")`, `SEC("lsm/bprm_check_security")`, `SEC("lsm/socket_connect")`, or sleepable `SEC("lsm.s/bprm_committed_creds")` (`BPF_F_SLEEPABLE` [289], permitted to fault in user memory and compute `IMA` / `fs-verity` digests under SRCU!) attaches directly into `lsm_static_calls_table` ([Chapter 7](07-stacked-lsms-landlock.md)) [34, 289]:

```c
SEC("lsm/file_open")
int BPF_PROG(enforce_shadow_guard, struct file *file)
{
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != 0 && file->f_inode->i_ino == shadow_ino_from_map()) {
        bpf_send_signal(SIGKILL); /* Immediate in-kernel task termination! */
        return -EPERM;            /* Synchronously aborts openat() in Ring 0 */
    }
    return 0;
}
```

Inside `SEC("lsm/file_open")`, `struct file *file` points to the pinned kernel `dentry` and `inode` *after* VFS path resolution (`TOCTOU`-impossible!), returning `-EPERM` aborts `do_filp_open()` *before* file contents can be read, and Cilium `Tetragon` (`TracingPolicy` `Sigkill` and `Override` actions [35, 278]) maintains an in-kernel `execve_map` keyed by monotonic `exec_id` (`ktime_ns` + CPU generation, immune to 32-bit `PID` wraparound races!). Correlating full process-ancestry lineages, `cgroup` pod UIDs, binary digests, and TCP socket states entirely inside Ring 0 BPF maps allows `Tetragon` to kill container breakouts or unexpected reverse shells synchronously on their very first forbidden syscall [35, 278].

### Verifier Soundness Bugs and Offensive `eBPF` Rootkits

Now examine the reverse edge of `eBPF` [59, 60, 276, 280, 281]. Because the JIT compiler emits native Ring 0 machine instructions trusting `verifier.c`'s static proof unconditionally, *any* soundness defect where concrete execution produces a value $x_{\text{runtime}} \notin \gamma(\text{reg})$ lets an attacker construct an *oracle scalar register* `R6` whose verifier state satisfies $u_{\min} = u_{\max} = 0$ (`tnum_const(0)`), while at runtime on silicon `R6 == 1` [59, 60]!

![Figure: Four-stage exploit mechanics of an eBPF verifier bounds-tracking escape (CVE-2020-8835, CVE-2021-3490, CVE-2023-2163), turning a 1-bit abstract-interpretation divergence into arbitrary Ring 0 memory read/write.](diagrams/08-ebpf-verifier-bounds-escape.svg)

Three celebrated CVEs expose how fragile cross-domain synchronization and pruning are in C:
In `CVE-2020-8835` (discovered by Manfred Paul at Pwn2Own 2020 [59]), `__reg_bound_offset32()` updated `var_off` from 32-bit bounds on `BPF_JMP32` branches without fully reconciling 64-bit `smin`/`umin` bounds; chaining 64-bit bounds checks with a 32-bit `BPF_JNE` tricked `verifier.c` into collapsing `R6` to constant `0` statically while concrete `R6` held `1`. Months later, Simon Scannell discovered `CVE-2020-27194` [290] inside `scalar32_min_max_or()`, which mistakenly assigned 64-bit signed bounds (`smin_val`, `smax_val`) straight into 32-bit signed/unsigned subregister fields instead of reading `s32_min_value`, truncating a multi-gigabyte range down to constant `0`!
In `CVE-2021-3490` (analyzed by Valentina Palmiotti [60]), the 32-bit bitwise transfer functions `scalar32_min_max_and()`, `scalar32_min_max_or()`, and `scalar32_min_max_xor()` contained an early-return optimization:

```c
/* Vulnerable pattern in kernel/bpf/verifier.c (CVE-2021-3490): */
if (tnum_subreg_is_const(dst_reg->var_off))
    return; /* BUG: Skips updating s32_min_value..u32_max_value from var_off! */
```

Crafting a register whose lower 32 bits were completely known in `var_off` (`mask_32 == 0`) while its upper 32 bits remained unknown caused `BPF_ALU | BPF_AND` to return early, leaving stale prior `u32_min_value` / `u32_max_value` intervals intact that contradicted `var_off` and poisoned subsequent `reg_bounds_sync()` steps into proving `R6 == 0` when `R6 == 1` [60]!
In `CVE-2023-2163` (discovered by Google researchers and dissected by Billy Jheng [281]), `mark_chain_precision()` failed to propagate `precise = 1` across specific jump-history parent pointers (`st->parent`), tricking `is_state_visited()` (`regsafe()`) into pruning an unverified branch where `R6` held an arbitrary offset because an earlier visited state at that instruction had `R6 == 0` marked imprecise!

In every case, once `verifier.c` believes `R6 == 0`, executing `R6 *= 0x1000` still verifies as `0 * 0x1000 == 0` (even neutralizing `sanitize_ptr_alu()` because `alu_limit` sees a constant scalar!), so `*(u64 *)(map_val_ptr + R6)` compiles to an unchecked Ring 0 out-of-bounds slab load/store. Attackers leak adjacent `struct bpf_array` pointers (`KASLR` bypass), forge a counterfeit `struct bpf_map_ops` vtable (`map_get_next_key` / `map_push_elem`) or corrupt `btf` IDs for arbitrary kernel read/write, and overwrite `current->cred` to `UID 0` [59, 60, 281]. Beyond scalar arithmetic, `verifier.c` must also track object reference lifetimes (`struct bpf_reference_state` with `REF_TYPE_PTR` and `REF_TYPE_LOCK` in `include/linux/bpf_verifier.h` [277]) across `kfunc` and socket-lookup helpers (`bpf_sk_lookup_tcp()` paired with `bpf_sk_release()`), rejecting any CFG exit path that leaks an acquired refcount or spinlock! Similarly, `STACK_DYNPTR` (`16`-byte bounded dynamic pointers occupying two consecutive 8-byte stack slots) tracks `first_slot` alignment and `parent_id` cascading invalidation so releasing a backing ringbuf or skb buffer immediately invalidates every derived slice register across the frame [277]. When incident responders inspect `/sys/fs/bpf/` during live triage, any unexpected pinned `bpf_link` or anonymous `tracing`/`lsm` program lacking a matching `Tetragon`, `Cilium`, or `systemd` owner process should be dumped immediately via `bpftool prog dump xlated` before detaching, preserving forensic evidence of in-memory Ring 0 tampering [282, 291].

Even with zero verifier bugs, granting untrusted or post-compromise processes `CAP_BPF` + `CAP_PERFMON` (or `CAP_SYS_ADMIN`) on a host without `Kernel Lockdown` (`confidentiality` mode [5]) unlocks potent Ring 0 rootkit primitives demonstrated by Guillaume Fournier's `ebpfkit` [282], `TripleCross` [283], and wild malware families (`Symbiote` and `BPFDoor` [292]). Tracing programs invoking `bpf_probe_read_kernel()` and `bpf_probe_read_user()` siphon cleartext `sshd` passwords and TLS keys across all containers; `bpf_probe_write_user()` (`ebpfkit` [282]) overwrites Ring 3 virtual memory inside `sudo`, `sshd`, or `systemd` (injecting rogue `LD_PRELOAD` paths or patching authentication branches without touching disk!); `fexit/__x64_sys_getdents64` strips malicious filenames and `/proc/<pid>` entries from `ls` and `ps` directory buffers; and `XDP` hooks intercept magic covert C2 packets before `iptables`, `nftables`, or `tcpdump` ever see the frame [282, 283]. Worse, because `BPF` programs and links are kernel-refcounted objects that can be *pinned* onto `bpffs` (`/sys/fs/bpf/`) or detached `bpf_link` descriptors, an `eBPF` rootkit continues executing inside Ring 0 long after its userspace loader binary has deleted itself and exited, making live `bpftool prog show` inspection mandatory during incident response [282, 291]!

## Distro, Immutable-OS, & Cloud Trade-Offs

To preserve defensive `eBPF` (`Cilium`, `Tetragon`, `Falco`) while locking out verifier exploits and `eBPF` rootkits, modern distributions layer four controls [5, 58, 293, 294]:

| Security Control | Kernel Mechanism | Effect on Attackers vs. Defenders |
|---|---|---|
| `kernel.unprivileged_bpf_disabled = 2` | Blocks `bpf(2)` without `CAP_BPF` / `CAP_SYS_ADMIN` in `init_user_ns` | Cuts off unprivileged users and `CLONE_NEWUSER` sandboxes (`CAP_BPF` is *not* userns-scoped!) from `verifier.c` [58] |
| `net.core.bpf_jit_harden = 2` | Blinds constants in JIT code & randomizes JIT pages | Defeats JIT-spray shellcode embedding inside compiled BPF instructions |
| `lockdown=confidentiality` ([Ch. 5](05-kernel-lockdown-modules.md)) | Blocks `bpf_probe_read_kernel` & `bpf_probe_write_user` | Prevents even compromised `root` pods from reading Ring 0 secrets or injecting Ring 3 memory via BPF [5, 282] |
| `BPF_TOKEN_CREATE` & Signed `BPF` (`6.9+`) | `bpffs` `delegate_*` tokens + `fs-verity` + `IPE`/`LSM-BPF` | Allows vetted system containers to load only `fs-verity`-signed BPF programs without host `CAP_SYS_ADMIN` [293, 294] |

Across `Ubuntu 24.04+`, `RHEL 9/10`, `Fedora`, `Google COS`, `Bottlerocket`, and `Talos`, `unprivileged_bpf_disabled = 2` is now the universal default, and standard container `seccomp` profiles block `bpf(2)` for all tenant workloads while dedicating a single node-level `Tetragon`/`Cilium` DaemonSet with `CAP_BPF` + `CAP_PERFMON` + `CAP_MAC_ADMIN` to runtime enforcement [35, 278]. Where unprivileged or user-namespaced system containers legitimately need `BPF` (`systemd` inside system containers), Linux 6.9+ introduced *BPF Tokens* (`BPF_TOKEN_CREATE` by Andrii Nakryiko [293]), letting a host administrator mount a `bpffs` instance configured with explicit `delegate_cmds`, `delegate_progs`, and `delegate_maps` bitmasks inside the container, paired with `LSM-BPF` / `IPE` hooks verifying an `fs-verity` signature on the BPF bytecode blob before `BPF_PROG_LOAD` proceeds [294].

## Seam Failures, CVEs, & Structural Bounds

Eight years of `eBPF` security incidents span `ALU32`/`tnum` domain desynchronizations, speculative pointer leaks, precision-pruning bugs, async `TOCTOU` blind spots, and post-exploitation tracing rootkits.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2017-16995` (Project Zero) | 2017 | `verifier.c` `check_alu_op` | 32-bit `BPF_MOV` immediate sign-extends identically in verifier and JIT | Sign-extension mismatch between 64-bit verifier tracking and 32-bit execution grants Ring 0 OOB map R/W | Track explicit 32-bit subregister state and disable unprivileged `bpf(2)` [280] |
| `CVE-2019-7308` & `CVE-2021-33624` | 2019-2021 | `verifier.c` `sanitize_ptr_alu` | Architecturally verified branch bounds prevent speculative OOB reads | Mispredicted branch speculatively adds unbounded scalar to `PTR_TO_MAP_VALUE`, leaking Ring 0 RAM via Spectre v1 | Compute worst-case speculative `alu_limit` and emit branchless bitmask clamps [287, 288] |
| `CVE-2020-8835` (`Pwn2Own`) | 2020 | `verifier.c` `__reg_bound_offset32` | `JMP32` 32-bit bounds sync soundly with 64-bit `var_off` `tnum` | Crafted 64/32-bit shift/branch sequence produces `R6` proven `0` statically while `1` on CPU for Ring 0 R/W | Unify `reg_bounds_sync()` cross-domain tightening after every ALU/JMP op [59, 277] |
| `CVE-2020-27194` (`OR` Truncation) | 2020 | `verifier.c` `scalar32_min_max_or` | Assigning 64-bit `smin`/`smax` into 32-bit bounds preserves range | 64-to-32-bit truncation in bitwise `OR` collapses register range to `0` for OOB kernel escalation | Compute 32-bit `OR` bounds strictly from `u32`/`s32` + `tnum_subreg` [285, 290] |
| `CVE-2021-3490` (`ALU32` Bitwise) | 2021 | `verifier.c` `scalar32_min_max_and` | Constant `tnum` subreg needs no `s32`/`u32` interval update | Early return when `tnum_subreg_is_const()` left contradictory `u32` bounds, poisoning `reg_bounds_sync()` | Remove early return; enforce `unprivileged_bpf_disabled=2` across distros [60, 284] |
| `CVE-2023-2163` (`precise` Pruning) | 2023 | `verifier.c` `mark_chain_precision` | Jump-history parent pointers trace all live scalar dependencies | Faulty parent chain left pointer-indexing scalar `precise=0`, causing `regsafe()` to prune an OOB path | Fix jump-history precision propagation; block `bpf(2)` via container `seccomp` [281, 286] |
| Async `kprobe` `TOCTOU` & Kill Lag | 2019-2026 | `sys_enter` + `RINGBUF` EDRs | Reading `char __user *` + async userspace `SIGKILL` blocks exploits | Co-scheduled thread swaps user path after `sys_enter`, or one-shot exploit finishes before daemon wakes | Enforce inline `-EPERM` and `bpf_send_signal(SIGKILL)` inside `LSM-BPF` hooks [34, 35, 278] |
| `ebpfkit`, `TripleCross` & `BPFDoor` | 2021-2025 | `bpf_probe_write_user` & `fexit` | Loaded BPF programs are exclusively benign observability probes | Rootkit injects Ring 3 `sshd`/`sudo` memory, hides files in `getdents64`, and intercepts C2 via `XDP` | Enable `lockdown=confidentiality`, require `fs-verity` BPF signatures, and audit `bpftool` [5, 282, 283, 294] |

### Structural Bounds of In-Kernel Static Verification

Differential fuzzing studies (`Sun et al.` [276]) highlight an inescapable theoretical tension inside `kernel/bpf/verifier.c`: because exact reachability is undecidable (`Rice's Theorem`), every new feature added to keep `eBPF` expressive (`ALU32`, bounded loops, `bpf_dynptr`, open-coded iterators, arena memory) multiplies cross-domain interactions across `r64`, `r32`, `tnum`, and `regsafe()` state pruning [276, 277, 284]. Furthermore, verifier complexity limits (`1,000,000` dynamic states) force large defensive programs (`Cilium` datapath or deep `Tetragon` string parsers) to split logic across tail-call arrays (`bpf_tail_call`, capped at `33` chained hops) and carefully place compiler barriers so Clang's LLVM optimizer does not transform valid C bounds checks into register-spill patterns that `verifier.c` fails to prove safe [58, 286]. Exposing a 25,000-line abstract interpreter to unprivileged threads was therefore an architectural mistake now corrected by `unprivileged_bpf_disabled = 2`. Yet locking `CAP_BPF` to `init_user_ns` raises the broader question that opens Part III: what *other* massive Ring 0 C subsystems remained exposed to unprivileged users through POSIX capabilities and `CLONE_NEWUSER`? We dissect that exact surface in [Chapter 9](09-capabilities-userns.md).

## Inspecting on a Live Linux Host

Live `eBPF` verification checks four invariants: unprivileged `bpf(2)` and JIT-hardening `sysctl` gates, `LSM-BPF` activation in `/sys/kernel/security/lsm`, active Ring 0 programs/maps via `bpftool` [291], and dangerous memory-writing helpers.

Verify that unprivileged `eBPF` is disabled (`2` = permanently disabled without `CAP_BPF`), JIT constant blinding is active, and `bpf` is registered in the `LSM` hook list:

```bash
sysctl kernel.unprivileged_bpf_disabled net.core.bpf_jit_enable net.core.bpf_jit_harden 2>/dev/null
grep -w "bpf" /sys/kernel/security/lsm 2>/dev/null || echo "LSM-BPF inactive (add bpf to lsm= cmdline)"
```

Expected output on a hardened cloud or enterprise host:

```text
kernel.unprivileged_bpf_disabled = 2
net.core.bpf_jit_enable = 1
net.core.bpf_jit_harden = 2
lockdown,capability,yama,selinux,bpf,landlock
```

Enumerate all loaded `eBPF` programs (`lsm`, `kprobe`, `tracing`, `xdp`, `cgroup_skb`) and active `RINGBUF`/hash maps in Ring 0 (`bpftool` [291]):

```bash
# Requires CAP_BPF + CAP_PERFMON or root / run0
bpftool prog show 2>/dev/null | head -n 16
bpftool map show 2>/dev/null | head -n 12
```

Representative output showing an inline `LSM-BPF` hook alongside a `ringbuf` telemetry map:

```text
42: lsm  name enforce_shadow_  tag a1b2c3d4e5f60718  gpl
    loaded_at 2026-11-10T08:14:22+0000  uid 0
    xlated 296B  jited 184B  memlock 4096B  map_ids 15,18  btf_id 112
18: ringbuf  name events_rb  flags 0x0
    key 0B  value 0B  max_entries 16777216  memlock 16781312B
```

Audit translated bytecode across loaded programs for offensive user-memory mutation (`bpf_probe_write_user`) or return-code tampering (`bpf_override_return`) helpers:

```bash
# Non-empty output outside known fault-injection tests warrants immediate rootkit triage!
for id in $(bpftool -j prog list 2>/dev/null | grep -oE '"id":[0-9]+' | cut -d: -f2); do
    bpftool prog dump xlated id "$id" 2>/dev/null | grep -H --label="prog:$id" -E "probe_write_user|override_return"
done
```

