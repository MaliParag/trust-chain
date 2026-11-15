# Kernel Memory Hardening, Control-Flow Integrity, and Rust

## Overview

* **Link in the Chain:** Defends Ring 0 internally when an unprivileged thread, network packet, or rogue hypervisor/PCIe device triggers a memory-safety flaw inside verified kernel code, preserving the `Lockdown` ([Chapter 5](05-kernel-lockdown-modules.md)) and `LSM` ([Chapter 7](07-stacked-lsms-landlock.md)) boundaries.
* **Core Security Invariant:** Spatial and privilege hardware flags (`SMEP`/`PXN`, `SMAP`/`PAN`, `W^X`), forward- and backward-edge Control-Flow Integrity (`KCFI`/`FineIBT` paired with hardware `CET` Shadow Stacks and `ARM64` `PAC`/`GCS`), virtual-address-isolated slab allocators (`RANDOM_KMALLOC_CACHES`, `SLAB_VIRTUAL`), and compile-time-verified `Rust-for-Linux` safe driver abstractions prevent memory bugs from hijacking `%rip`/`PC` or deterministically aliasing `struct cred` and user page tables.
* **Deployment Profile Matrix:** Mainstream distributions (`Ubuntu 24.04+`, `Fedora 41+`, `RHEL 9/10`) enable `KASLR`, `SMEP`/`SMAP`, `SLAB_FREELIST_RANDOM`, `SLAB_FREELIST_HARDENED`, `INIT_STACK_ALL_ZERO`, `FORTIFY_SOURCE` (`__bdos`), `KFENCE`, and `KCFI`/`FineIBT` with `RANDOM_KMALLOC_CACHES`; hardened cloud and mobile kernels (`Google COS`/`kCTF`, `Android GKI`, `Talos`) add Clang `KCFI`, `SLAB_VIRTUAL`, and mainline Rust drivers (`CONFIG_RUST=y`).
* **Trusted Computing Base (TCB):** CPU MMU and control registers (`CR4.SMEP`, `CR4.SMAP`, `CR4.CET`, `ARM64` `SCTLR_EL1` `PAN`/`PXN`/`PAC`/`GCS`), `LLVM`/`Clang` or `GCC` plus `rustc` compiler toolchains, `mm/slub.c`, `arch/x86/kernel/alternative.c`, and audited `unsafe` FFI wrapper blocks inside `rust/kernel/` and `rust/pin-init/`.
* **Integration Seam & Handoff:** Contains C memory-corruption primitives and eliminates spatial, temporal, and concurrency bugs in safe Rust modules (`Binder`, `Asahi`, `rnull`, `Nova`) so `struct cred` and `lsm_static_calls_table` cannot be silently overwritten; hands off intact Ring 0 enforcement to stacked `LSM` policies in [Chapter 7](07-stacked-lsms-landlock.md).

## Problem Statement & Threat Model

Every cryptographic control examined across Part I and [Chapter 5](05-kernel-lockdown-modules.md) (`UEFI Secure Boot`, `UKI`, `dm-verity`, `IPE`, and `Kernel Lockdown`) verifies *who authored* a kernel image or loadable `.ko` module before its instructions enter Ring 0. None of those gates help if a legitimately signed `vmlinux` binary contains an out-of-bounds write, integer truncation, data race, or Use-After-Free (`UAF`) inside its 35+ million lines of C code [32, 33, 229]. Because Linux is a monolithic kernel, filesystems (`ext4`, `btrfs`, `xfs`, `OverlayFS`), packet filters (`nf_tables`), socket families (`TLS`, `TIPC`, `AF_PACKET`), asynchronous I/O (`io_uring`), and peripheral drivers share one privileged Ring 0 virtual address space with the scheduler, page tables, and RCU `struct cred` credentials [229, 230].

Over fifteen years, kernel exploitation evolved in lockstep with incremental mitigations [32, 229, 231]. Before 2013, triggering a `NULL` dereference or function-pointer overwrite let Ring 0 execute `commit_creds(prepare_kernel_cred(NULL))` shellcode mapped directly inside Ring 3 pages. Once silicon blocked supervisor execution of user pages (`CR4.SMEP`, `ARM64` `PXN`) and supervisor dereferences of user memory (`CR4.SMAP`, `ARM64` `PAN`) [88, 89, 232], adversaries pivoted to Return-Oriented and Jump-Oriented Programming (`ROP`/`JOP`) inside `.text`, defeating Kernel Address Space Layout Randomization (`KASLR`) via slab pointer leaks or prefetch timing side channels (`EntryBleed`, `CVE-2022-4543` [97, 233]).

As Clang Kernel Control-Flow Integrity (`KCFI` [234]), x86 `FineIBT` [235], and hardware Shadow Stacks (`Intel CET` and `ARM64 GCS` [236, 237]) sealed code pointers, offensive research shifted overwhelmingly toward *data-only heap and page-table attacks* [32, 231, 238, 239]. Attackers either overlap freed slots in generic `kmalloc-*` slabs with elastic `struct msg_msg` or `struct pipe_buffer` payloads [238, 240], or drain a victim slab page back to the buddy allocator and reclaim that physical frame as a *Ring 3 last-level Page Table (`PTE`) page* (`Dirty Pagetable` [231] and `SLUBStick` [239]). Mutating 8 bytes in a reclaimed `PTE` shifts its Physical Frame Number (`PFN`) to map kernel physical memory read-write into userspace, bypassing `KCFI`, `FineIBT`, Shadow Stacks, `SMAP`, and `KASLR` without taking one anomalous branch.

Defending Ring 0 against local unprivileged threads, network peers, or untrusted hypervisors ([Chapter 18](18-confidential-vms-svsm.md)) requires the two-pronged architecture of the *Kernel Self Protection Project* (`KSPP` [229]) and *Rust for Linux* [33]: containing C defects via MMU gates, compiler bounds passes, hardware `CFI`, and virtual-address-isolated slab arenas (`SLAB_VIRTUAL` [241]), while writing new subsystems (`Android Binder`, `Nova`, `Asahi`, `rnull`) in safe Rust so spatial, temporal, and race bugs fail at compile time [242, 243, 244, 245].

## Kernel & Userspace Mechanics

### MMU Privilege Barriers (`SMEP`/`SMAP`, `PXN`/`PAN`), Compiler Hardening, and `EntryBleed`

Ring 0 self-protection starts at page-table permission bits [88, 89, 229]. With `CONFIG_STRICT_KERNEL_RWX=y` and `CONFIG_STRICT_MODULE_RWX=y`, Linux enforces `W^X` across kernel mappings: `.text` is read-only executable (`RW = 0, NX = 0`), `.data` and heaps are non-executable (`RW = 1, NX = 1`), and write-once structures (`lsm_static_calls_table`, syscall tables, core ops structures) reside in `__ro_after_init` so `mark_rodata_ro()` strips PTE write bits before `/sbin/init` runs [229].

To isolate Ring 0 from Ring 3 pages, x86_64 sets `CR4.SMEP` (bit 20) and `CR4.SMAP` (bit 21) during CPU bring-up, while ARM64 sets `SCTLR_EL1.WXN`, `PXN` (Privileged Execute-Never), and `PSTATE.PAN` (Privileged Access-Never) [88, 89, 232]. Under `SMEP`/`PXN`, fetching any instruction from a user page (`U/S = 1`) raises an immediate fatal fault at `CPL = 0` / `EL1`. Under `SMAP`/`PAN`, Ring 0 loads or stores to `U/S = 1` addresses fault outside explicit `arch/x86/include/asm/smap.h` copy helpers (`_copy_from_user()`, `_copy_to_user()`) bracketed by `STAC` (`EFLAGS.AC = 1`) and `CLAC` (`EFLAGS.AC = 0`), or ARM64 `LDTR`/`STTR` unprivileged instructions [232]. Hardware exception entry saves `RFLAGS`/`SPSR_EL1` and clears `AC = 0` (`PAN = 1`), ensuring nested interrupts arriving mid-copy never execute with `SMAP` disabled [88, 232].

Compiler and stack mitigations scrub spatial and uninitialized-memory primitives [229, 246, 247]. `CONFIG_VMAP_STACK=y` places each 16 KiB kernel stack in `vmalloc` space bookended by unmapped guard pages, converting stack exhaustion into a clean `#PF` oops rather than trampling adjacent `task_struct` allocations [229]. `CONFIG_INIT_STACK_ALL_ZERO=y` (`-ftrivial-auto-var-init=zero`) zeroes every local stack variable and struct-padding byte on entry at $<1\%$ CPU cost [247], while `CONFIG_ZERO_CALL_USED_REGS=y` clears caller-saved registers before `RET`, starving speculative gadgets and cutting usable ROP state [229]. For spatial bounds, Kees Cook modernized `CONFIG_FORTIFY_SOURCE=y` (`include/linux/fortify-string.h`) around `__builtin_dynamic_object_size(ptr, 1)` (`__bdos`) and the `__counted_by(len_field)` C attribute on flexible-array members [246]:

```c
struct msg_blob {
    u32 flags;
    size_t count;
    u8 payload[] __counted_by(count); /* Runtime bound tracked by __bdos! */
};
```

Whereas legacy `__builtin_object_size(ptr, 0)` knew only compile-time constant sizes and silently passed trailing flexible arrays, `__bdos(..., 1)` evaluates `blob->count * sizeof(u8)` dynamically and enforces intra-struct field bounds across `memcpy()`, `memmove()`, and `strscpy()`, calling `fortify_panic()` on overflow [246].

Why can `KASLR` (`CONFIG_RANDOMIZE_BASE=y`) never stand alone? On x86_64, `KASLR` slides `.text` across $512 = 2^9$ slots of $2\text{ MiB}$ inside a $1\text{ GiB}$ window [97, 229]. Building on Daniel Gruss et al.'s discovery that x86 `PREFETCH` instructions leak TLB state without faulting on supervisor addresses [233], Will Liu demonstrated `EntryBleed` (`CVE-2022-4543` [97]). Even under Meltdown-era Kernel Page Table Isolation (`KPTI`), the `entry_SYSCALL_64` trampoline must remain mapped in user `%cr3` (`_PAGE_GLOBAL`) to handle `SYSCALL`. Timing `PREFETCHT0` with `RDTSC` across all 512 candidate $2\text{ MiB}$ slots pinpointed the cached `entry_SYSCALL_64` TLB hit and leaked the exact `KASLR` slide in $<10\text{ ms}$ on Intel CPUs [97].

### Forward-Edge `KCFI` / `FineIBT` and Backward-Edge Hardware Shadow Stacks (`CET` & `GCS`)

Control-flow hijacking splits into *forward-edge* indirect calls (`call *%rax` via `file_operations`, `proto_ops`, or `bpf_map_ops`) and *backward-edge* returns (`ret` popping saved return pointers) [234, 235, 237].

![Figure: Pairing forward-edge type-hash Control-Flow Integrity (Clang KCFI and x86_64 FineIBT landing pads) with backward-edge hardware Supervisor Shadow Stacks (Intel CET) and ARM64 Pointer Authentication (PAC).](diagrams/06-kernel-cfi-shadow-stack.svg)

Merged in Linux 6.1, Clang `KCFI` (`CONFIG_CFI_CLANG=y`, `-fsanitize=kcfi` [234]) enforces prototype-level forward-edge integrity without writable tables. For each C function prototype $T$, Clang computes a 32-bit `xxHash` (`__kcfi_typeid_<fn> = H(T)`) emitted four bytes *immediately before* the function prologue in read-only `.text` (`*(u32 *)(fn - 4) == H(T)`), verifying it inline before every indirect call [234]:

```c
movl   $-H_expected, %r10d       /* Load negated 32-bit prototype xxHash     */
addl   -4(%rax), %r10d           /* Compare against 4-byte prefix before fn  */
je     .Lvalid_target            /* Zero iff *(u32*)(%rax - 4) == H_expected */
ud2                              /* Trap -> #UD -> handle_cfi_failure()      */
.Lvalid_target:
call   *%rax
```

Pointing `%rax` mid-instruction or at a mismatched prototype executes `ud2`, trapping into `handle_cfi_failure()` [234]. On Intel Tiger Lake+ and AMD Zen 4+ CPUs supporting Indirect Branch Tracking (`CR4.CET` `MSR_IA32_S_CET.ENDBR_EN`), `CONFIG_X86_KERNEL_IBT=y` places `ENDBR64` (`f3 0f 1e fa`) at indirect targets and runs `objtool --ibt` at link time to seal non-address-taken functions into `NOP4` [237]. Linux 6.2+ then applies `FineIBT` (`apply_fineibt()` in `arch/x86/kernel/alternative.c` [235]), patching caller sites to `movl $H_expected, %r10d; call *%rax` and verifying `subl $H_expected, %r10d; je +2; ud2` right after `ENDBR64` in a 16-byte callee preamble, fusing hardware `#CP` landing pads with 32-bit type hashes without reading `.text` as data [235].

On the backward edge, `ARM64` `CONFIG_ARM64_PTR_AUTH_KERNEL=y` executes `PACIASP`/`AUTIASP` (`QARMA` MACs over `(X30, SP)` keyed by `APIAKey_EL1` in upper `X30` bits) and pairs on ARMv9.3 silicon with *Guarded Control Stack* (`GCS`, `Documentation/arch/arm64/gcs.rst` [89, 236]), maintaining `GCSPR_EL1`/`GCSPR_EL0` shadow pages writable solely by `BL` and `GCSPUSHM`. On `x86_64`, Intel `CET` and AMD Shadow Stack enforce *Supervisor Shadow Stacks* (`CR4.CET`, `MSR_IA32_PL0_SSP`, `MSR_IA32_INTERRUPT_SSP_TABLE_ADDR`) using `RW = 0, Dirty = 1` PTEs: `CALL` pushes `%rip` to both `%rsp` and `%ssp`, and `RET` raises `#CP` on any mismatch [88, 237].

### `SLUB` Internals, Elastic/Page-Table Heap Attacks, and `SLAB_VIRTUAL`

With code pointers sealed, attackers target object lifecycles in `mm/slub.c` [230]. Each `struct kmem_cache` serves fast-path requests from lockless per-CPU object arrays (`slub_percpu_sheaves` / `kmem_cache_cpu`) backed by per-node `node_barn` pools and `kmem_cache_node` `partial` slab lists [230]. Within a slab folio, free slots form an intrusive singly linked list storing `freeptr_t` at `object + s->offset`.

`KSPP` hardens `mm/slub.c` with two baseline freelist defenses [229, 230]: `CONFIG_SLAB_FREELIST_RANDOM=y` Fisher-Yates shuffles initial slot order (`init_cache_random_seq()`), and `CONFIG_SLAB_FREELIST_HARDENED=y` mangles pointers via `freelist_ptr_encode()` while trapping consecutive double-frees (`BUG_ON(object == fp)`):

```c
static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
                                            void *ptr, unsigned long ptr_addr)
{
    unsigned long encoded = (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
    return (freeptr_t){ .v = encoded };
}
```

Byte-reversing `ptr_addr` via `swab()` shifts low intra-page offset bits (`0..11`) into the top byte (`56..63`), ensuring partial 1- or 2-byte little-endian overflows corrupt upper canonical address bits unless the attacker leaks both `s->random` and exact `ptr_addr` [230]. Complementing freelist mangling, `init_on_alloc=1` zeroes allocations before return, and `CONFIG_KFENCE=y` samples live allocations adjacent to unmapped MMU guard pages at $\approx 0.1\%$ CPU cost [229].

Adversaries bypassed baseline `SLUB` hardening in two waves. First, *same-cache elastic sprays* (`CVE-2021-26708` [240] and `CVE-2021-22555` [238]) exploited subsystems sharing generic `kmalloc-64`..`kmalloc-4k` caches with `msgsnd(2)`'s `struct msg_msg` (`48`-byte header plus arbitrary payload up to $4048$ bytes) and `pipe_buffer`. Linux 6.6 answered with `CONFIG_RANDOM_KMALLOC_CACHES=y` [32], partitioning each size class into `16` caches (`kmalloc-rnd-01-*` .. `kmalloc-rnd-16-*`) keyed by caller `_RET_IP_` and a per-boot `random_kmalloc_seed`, paired with `CONFIG_SLAB_BUCKETS` isolating dynamic `msg_msg`/`memdup_user` allocations:

$$\text{bucket}(\text{callsite}) = \operatorname{Hash}_{64}\!\left(\texttt{\_RET\_IP\_},\; K_{\text{boot}}\right) \bmod 16$$

Second, attackers defeated dedicated caches (`filp`, `cred_jar`) and `RANDOM_KMALLOC_CACHES` via *cross-cache buddy reclamation* and *Dirty Pagetable* (`CVE-2023-21400` by Nicolas Wu and Ye Zhang [231], Seth Jenkins's `CVE-2022-42703` [248], and Lukas Maar et al.'s `SLUBStick` [239]):

![Figure: Contrasting Dirty Pagetable cross-cache physical frame reclamation (where a freed struct file slab page returns to the buddy allocator and is reclaimed as a user last-level PTE table at the identical linear direct-map virtual address) against SLAB_VIRTUAL permanent virtual-address quarantine.](diagrams/06-extra-dirty-pagetable-vs-slab-virtual.svg)

In standard Linux, slab pages use virtual addresses inside the global linear direct map (`physmap`). When an attacker holds a dangling `struct file *` UAF, drains sibling `filp` slots (assisted to $>99\%$ success by `SLUBStick` fastpath/slowpath timing oracles [239]) so `discard_slab()` frees physical frame $P$ to the buddy allocator, and faults dense `mmap()` regions, `pte_alloc_one()` reclaims frame $P$ as a *Ring 3 last-level `PTE` page* at the *identical `physmap` virtual address* [231]! A stale `f_count` atomic increment or field write on the dangling `struct file *` directly modifies an 8-byte `PTE` entry, shifting its `PFN` bits so userspace maps physical kernel `.text` or `struct cred` read-write [231, 239].

Google's `SLAB_VIRTUAL` (`CONFIG_SLAB_VIRTUAL=y` by Matteo Rizzo and Jann Horn [32, 241]) severs this aliasing permanently: slabs allocate from a dedicated multi-terabyte virtual arena outside `physmap` where each virtual page $V_c$ is *bound to a single `kmem_cache` for the entire system uptime*. Freeing an empty slab unmaps $V_{\text{filp}}$'s PTE before returning physical frame $P$ to the buddy allocator; even if frame $P$ becomes a user `PTE` page elsewhere, dereferencing $V_{\text{filp}}$ hits either an unmapped `#PF` trap or exclusively another genuine `struct file` [32, 241].

![Figure: Defending kernel heap lifecycles through RANDOM_KMALLOC_CACHES, SLAB_VIRTUAL virtual-address quarantine against cross-cache page reuse, and compile-time-verified Rust-for-Linux driver boundaries.](diagrams/06-slab-hardening-rust-boundary.svg)

### Rust-for-Linux: Pinned Initialization (`PinInit`), Lock-Bound State, and Mainline Drivers

While `SLAB_VIRTUAL` contains C bugs post-trigger, `Rust-for-Linux` (`CONFIG_RUST=y` [33]) prevents spatial, temporal, and data-race bugs at compile time across device drivers and leaf subsystems (which represent $>65\%$ of kernel source lines and most Ring 0 CVEs [33, 242]).

Adapting Rust to Ring 0 required solving three foundational kernel constraints [33, 249, 250]. First, because OOM panics in Ring 0 cause Denial-of-Service, `rust/kernel/alloc/` enforces fallible allocation (`KBox::new(v, GFP_KERNEL)?`, `KVec::push(v, GFP_ATOMIC)?`, `Arc::new(v, GFP_KERNEL)?`) returning `Result<T, AllocError>`. Second, C kernel primitives (`struct mutex`, `raw_spinlock_t`, intrusive `struct list_head`) contain self-referential internal pointers that corrupt if moved in memory from stack to heap. Benno Lossin's `pin-init` crate (`rust/pin-init/` [249]) enforces *pinned in-place construction* (`#[pin_data]`, `PinInit<Self, Error>`, `try_pin_init!`), initializing locks directly inside their final heap slot:

```rust
use kernel::{prelude::*, sync::{Arc, SpinLock}, new_spinlock};

#[pin_data]
struct DeviceChannel {
    #[pin]
    state: SpinLock<ChannelRing>, /* Protected data owned INSIDE SpinLock! */
    irq_line: u32,
}

impl DeviceChannel {
    fn try_create(irq: u32) -> Result<Arc<Self>> {
        Arc::pin_init(try_pin_init!(Self {
            state <- new_spinlock!(ChannelRing::empty(), "dev_chan_lock"),
            irq_line: irq,
        }), GFP_KERNEL)
    }
}
```

Third, `rust/kernel/sync/lock.rs` (`Lock<T, B>` [250]) wraps protected state *inside* `UnsafeCell<T>` rather than beside a bare C `spinlock_t`: `#![forbid(unsafe_code)]` drivers cannot read or mutate `ChannelRing` without acquiring `Guard<'a, T, B>` via `self.state.lock()`, and `Send`/`Sync` bounds statically reject unlocked cross-CPU aliasing [250].

Four mainline Rust subsystems demonstrate these guarantees in production [242, 243, 244, 245]. In `drivers/android/binder/` (`Wedson Almeida Filho` and `Alice Ryhl` [242]), Google rewrote Android's heavily exploited C Binder IPC driver using intrusive `ListArc<T>` and `ListLinksSelfPtr` smart pointers that statically prevent work-queue double-insertion and UAFs at full throughput. Equally important, `rust_binder` replaces manual C `_copy_from_user()` pointer arithmetic with `kernel::uaccess::UserSliceReader` and `UserSliceWriter` [242]: reading untrusted Ring 3 payloads into owned or single-pass slices prevents classic *double-fetch* `TOCTOU` vulnerabilities where C kernel code validates a user-memory header field on the first read and trusts a mutated value on the second read! In the `Asahi` Apple AGX DRM driver [243], Asahi Lina bound GPU firmware buffer lifetimes to hardware completion fences, eliminating host kernel UAFs even when Ring 3 clients crash mid-render. Meanwhile, `drivers/block/rnull/` (`Andreas Hindborg` [244]) wraps multi-queue `blk-mq` `GenDisk`, `TagSet`, and `ARef<mq::Request<Self>>` ownership safely, and Red Hat's `Nova` GPU driver (`drivers/gpu/nova-core/` by `Danilo Krummrich` [245]) drives NVIDIA GSP-based (`Turing` through `Blackwell`) GPUs using `CoherentAllocation` DMA wrappers (statically enforcing device `DmaMask` bounds and index safety on shared PCIe rings) plus deterministic reverse-declaration-order `Drop` teardown replacing fragile C `goto err_*` unwind chains.

## Distro, Immutable-OS, & Cloud Trade-Offs

Deploying Ring 0 memory and control-flow mitigations requires balancing CPU latency, compiler toolchain standardization (`GCC` vs. `LLVM/Clang` + `rustc`/`bindgen`), and out-of-tree `.ko` module compatibility across distinct Linux operating profiles [32, 33, 229, 241]:

| Mitigation / Mechanism | Overhead & Build Requirement | Enterprise (`RHEL 9/10`, `Ubuntu 24.04+`) | Hardened Cloud / Mobile (`COS`, `Android GKI`, `Talos`) |
|---|---|---|---|
| `SMEP`/`SMAP` (`PXN`/`PAN`) + `VMAP_STACK` | Near-zero ($<0.3\%$); CPU + MMU baseline | Enabled unconditionally | Enabled unconditionally |
| `INIT_STACK_ALL_ZERO` + `init_on_alloc=1` | $\approx 0.5\text{ to }1.5\%$ CPU; zeros stack & heap allocs | Enabled by default (`init_on_free=0` for perf) | Enabled (`Talos` additionally sets `init_on_free=1`) |
| `FORTIFY_SOURCE` (`__bdos` + `__counted_by`) | $<0.2\%$; compile + dynamic sub-object traps | Enabled across mainline `6.8+` kernels | Enabled with panic-on-warn (`oops=panic`) |
| `KCFI` / `FineIBT` + `CET` / `PAC` / `GCS` | $\approx 0.5\text{ to }1.5\%$; `KCFI` requires `LLVM=1` Clang build | `IBT` + `PAC` enabled; `FineIBT`/`KCFI` rolling out | `Clang KCFI` + `FineIBT`/`PAC` strictly enforced |
| `RANDOM_KMALLOC_CACHES` + `SLAB_BUCKETS` | Negligible CPU; slight slab memory footprint increase | Enabled in `Ubuntu 24.04+` and `Fedora 40+` (`6.6+`) | Enabled alongside `SLAB_VIRTUAL` quarantine |
| `Rust-for-Linux` (`CONFIG_RUST=y`) | Zero runtime tax; pins `rustc` + `bindgen` at build | Enabled in `Ubuntu 24.04+`, `Fedora`, `Debian` | Production `rust_binder` (`Android`), `Nova`/`rnull` |

Notice three recurring operational trade-offs in this matrix [229, 234, 241]. First, enterprise servers running high-packet-rate workloads enable `init_on_alloc=1` (which zeroes freed bytes right before reuse while keeping CPU L1/L2 caches warm for the new caller) rather than `init_on_free=1` ($3\%$ to $7\%$ overhead on network benchmarks), whereas zero-trust immutable OSes (`Talos` [45]) accept `init_on_free=1` plus `slab_nomerge` so freed cryptographic keys or session structures never linger in physical RAM waiting for future allocation. Second, Clang `KCFI` (`CONFIG_CFI_CLANG=y`) requires compiling `vmlinux` and every loadable `.ko` module with `LLVM=1` (`Clang`, `LLD`, and `CONFIG_CALL_PADDING`) so 32-bit `__kcfi_typeid_*` hashes match across module boundaries; distributions historically standardized on `GCC` (`RHEL`, `SUSE`) leaned first on hardware `CONFIG_X86_KERNEL_IBT` (`ENDBR64`) while cloud and mobile kernels (`Android GKI`, `Google COS`) moved straight to `LLVM=1` `KCFI` + `FineIBT` [234, 235, 237]. Third, on `ARM64` silicon supporting ARMv8.5-A Memory Tagging Extension (`MTE`), production Android devices pair `KFENCE` with hardware-assisted `CONFIG_KASAN_HW_TAGS`, storing 4-bit probabilistic allocation tags inside upper pointer bits (`TBI`) and physical DRAM tag granules to trap spatial and temporal slab bugs synchronously in silicon, albeit with a `16`-tag ($6.25\%$ false-negative) entropy bound that still benefits from deterministic `SLAB_VIRTUAL` type quarantine [89, 241].

## Seam Failures, CVEs, & Structural Bounds

Even on a modern kernel armed with `SMAP`, `FineIBT`, `CET` Shadow Stacks, `SLAB_FREELIST_HARDENED`, and `CONFIG_RUST=y`, real-world exploitation probes four narrow architectural seams: microarchitectural `KASLR` leaks, cross-cache `PTE` reclamation where `SLAB_VIRTUAL` is absent, valid-prototype callback bending, and unsound preconditions inside `unsafe` C-to-Rust FFI wrappers.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2021-26708` (`vsock` Race) | 2021 | `net/vmw_vsock/` + `SLUB` | `SLAB_FREELIST_HARDENED` stops heap UAF exploitation | Lock-Drop race in `vsock` reclaimed via `struct msg_msg` in shared `kmalloc-64` for KASLR leak and arb write | Fix `vsock` socket locking; isolate `msg_msg` via `SLAB_BUCKETS` and `RANDOM_KMALLOC_CACHES` [32, 240] |
| `CVE-2021-22555` (`Netfilter` OOB) | 2021 | `net/netfilter/x_tables.c` | 2-byte zero write (`\x00\x00`) in `kmalloc-4k` is unexploitable | Redirects `msg_msg->m_list.next` to overlap secondary `msg_msg` with `pipe_buffer` ops vtable | Deploy `RANDOM_KMALLOC_CACHES`, `FineIBT`/`KCFI`, and restrict `CLONE_NEWUSER` [32, 235, 238] |
| EntryBleed (`CVE-2022-4543`) | 2022 | x86 `KPTI` + `KASLR` | Unmapping kernel pages under `KPTI` hides `KASLR` slide from Ring 3 | Unprivileged `PREFETCHT0` + `RDTSC` timing locates global `entry_SYSCALL_64` TLB entry in $<10\text{ ms}$ | Treat `KASLR` as speed-bump only; rely on deterministic `FineIBT`/`KCFI` + `SLAB_VIRTUAL` [97, 233, 241] |
| `CVE-2022-42703` (`anon_vma` Reuse) | 2022 | `mm/rmap.c` + Page Tables | Dedicated `anon_vma` slab cache isolates lifecycle bugs | Cross-cache physical page reuse turns pointer/stack corruption into deterministic page-table control | Fix `anon_vma` leaf tracking and quarantine virtual slab ranges via `SLAB_VIRTUAL` [241, 248] |
| Dirty Pagetable (`CVE-2023-21400`) | 2023 | `io_uring` + Buddy `PTE` | `KCFI`, `PAC`, and `PAN` on Pixel 7 prevent UAF-to-root | Drains freed slab page to buddy allocator, reclaims as user `PTE` table, and mutates `PFN` bits for physical R/W | Enable `SLAB_VIRTUAL` virtual-address quarantine and restrict `io_uring` [32, 231, 241] |
| `SLUBStick` Cross-Cache Side Channel | 2024 | `mm/slub.c` + `PTE` Spray | Cross-cache buddy reclamation is noisy and crashes targets | Uses `SLUB` fastpath vs. slowpath timing oracle to hit $>99\%$ slab-drain precision for `PTE` overwrite | Sever slab virtual addresses from linear direct map via `SLAB_VIRTUAL` [239, 241] |
| Coarse-Prototype `KCFI` Bending | 2023-2025 | `KCFI` `work_func_t` / `file_operations` | 32-bit prototype hash uniquely identifies intended callee | Thousands of `void (*)(struct work_struct *)` callbacks share identical `KCFI` hash (`run_cmd` gadgets) | Pair `KCFI` with `SLAB_VIRTUAL` heap integrity and strongly typed Rust closures [33, 234, 241] |
| C/Rust FFI Boundary Bug (`CVE-2025-68260` class) | 2025 | C-to-Rust `unsafe` wrapper | `CONFIG_RUST=y` prevents memory bugs across raw C callbacks | Violated concurrency/aliasing precondition inside `unsafe` C list wrapper broke Rust `&mut T` exclusivity | Keep `rust/kernel/` `unsafe` surface minimal and formally audited; enforce `#![forbid(unsafe_code)]` in drivers [33, 250] |

### Theoretical Bounds of Ring 0 Mitigations and `unsafe` FFI Soundness

Rows 5 through 8 crystallize four hard mathematical limits governing all Ring 0 memory defenses [33, 231, 234, 241]. First, *Control-Flow Integrity (`KCFI`, `FineIBT`, `CET`, `PAC`, `GCS`) is completely blind to pure non-control-data corruption*: overwriting `cred->uid = cred->euid = 0`, flipping `selinux_state.enforcing`, zeroing `addr_limit` on legacy kernels, or altering a user `PTE`'s Physical Frame Number (`Dirty Pagetable` [231]) executes $100\%$ legitimate kernel instruction streams with balanced `CALL`/`RET` shadow-stack frames. Even under `SLAB_VIRTUAL`, defenders must also protect the linear direct map (`physmap`) against stray physical/direct-map write primitives so an attacker cannot bypass virtual slab quarantine by computing a target page's `physmap` alias [241].

Second, *type-based forward-edge CFI is bounded by static equivalence-class width*: in the Linux C kernel, generic callback typedefs such as `work_func_t` (`void (*)(struct work_struct *)`), `timer_list` callbacks, and `rcu_callback_t` collapse thousands of distinct functions across subsystems into a single shared 32-bit `__kcfi_typeid` hash [234]. Notably, `call_usermodehelper_exec_work()` (which spawns Ring 3 root binaries from `struct subprocess_info`) carries the exact `void (*)(struct work_struct *)` signature, turning any corruptible `work_struct` adjacent to controllable arguments into a valid-prototype `KCFI`/`FineIBT` gadget unless heap isolation (`SLAB_VIRTUAL` and `RANDOM_KMALLOC_CACHES`) blocks object overlap first [32, 234].

Third, *Rust's compile-time memory safety holds strictly up to the soundness of its `unsafe` C FFI contracts* [33, 249, 250]. Whenever a C subsystem invokes a Rust `extern "C"` vtable callback (`file_operations`, `blk_mq_ops`, or `drm_driver`) while another CPU mutates the underlying C struct without synchronization, or frees a refcounted C object prematurely before Rust's `ARef<T>` or RCU read-side critical section (`rust/kernel/sync/rcu.rs`) drops, Rust's aliasing model (`&mut T` uniqueness and `&T` immutability outside `UnsafeCell` / `Opaque<T>`) is violated across the language seam [33, 250]. Wrapping every raw C struct inside `kernel::types::Opaque<bindings::foo>` (which disables Rust's `noalias` compiler assumptions on C-owned bytes) and concentrating `unsafe` blocks inside heavily reviewed `rust/kernel/` core abstractions ensures that leaf driver authors cannot accidentally introduce FFI UB. Fourth, even a $100\%$ memory-safe kernel willingly executes destructive actions if an untrusted process holds excessive ambient object access; confining *which* files, sockets, `ioctl`s, and IPC channels a process can name or open is the job of stacked `Linux Security Modules` in [Chapter 7](07-stacked-lsms-landlock.md).

## Inspecting on a Live Linux Host

Operational verification of Ring 0 self-protection audits four layers: active CPU silicon features, compile-time kernel hardening flags (`CFI`, `FORTIFY`, zeroing, Rust), live `SLUB` cache randomization (`kmalloc-rnd-*`), and `KFENCE` production guard-page sampling.

Verify active hardware privilege barriers (`smep`, `smap`, `ibt`, `shstk` on `x86_64`; `pan`, `paca`, `gcs` on `ARM64`) and CPU side-channel mitigations:

```bash
grep -m 1 -E "flags|Features" /proc/cpuinfo | tr ' ' '\n' | grep -E "^(smep|smap|ibt|shstk|pan|paca|gcs)$" | sort -u
head -n 6 /sys/devices/system/cpu/vulnerabilities/* 2>/dev/null | head -n 12
```

Representative output on a modern Intel/AMD `x86_64` server with `CET` silicon:

```text
ibt
shstk
smap
smep
==> /sys/devices/system/cpu/vulnerabilities/meltdown <==
Not affected
```

Audit compile-time Control-Flow Integrity (`CFI_CLANG`, `FINEIBT`, `X86_KERNEL_IBT`), stack/heap zeroing (`INIT_STACK_ALL_ZERO`, `INIT_ON_ALLOC`), `FORTIFY_SOURCE`, `SLUB` hardening, and `CONFIG_RUST` in the running kernel's config:

```bash
grep -E "CONFIG_(STRICT_KERNEL_RWX|VMAP_STACK|INIT_STACK_ALL_ZERO|INIT_ON_ALLOC_DEFAULT_ON|FORTIFY_SOURCE)=" /boot/config-$(uname -r) 2>/dev/null
grep -E "CONFIG_(CFI_CLANG|FINEIBT|X86_KERNEL_IBT|ARM64_PTR_AUTH_KERNEL|RUST)=" /boot/config-$(uname -r) 2>/dev/null
grep -E "CONFIG_(SLAB_FREELIST_RANDOM|SLAB_FREELIST_HARDENED|RANDOM_KMALLOC_CACHES|SLAB_BUCKETS|SLAB_VIRTUAL|KFENCE)=" /boot/config-$(uname -r) 2>/dev/null
```

Expected output on a hardened `6.12+` distribution kernel:

```text
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_VMAP_STACK=y
CONFIG_INIT_STACK_ALL_ZERO=y
CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_X86_KERNEL_IBT=y
CONFIG_RUST=y
CONFIG_SLAB_FREELIST_RANDOM=y
CONFIG_SLAB_FREELIST_HARDENED=y
CONFIG_RANDOM_KMALLOC_CACHES=y
CONFIG_SLAB_BUCKETS=y
CONFIG_KFENCE=y
```

Confirm at runtime that `CONFIG_RANDOM_KMALLOC_CACHES` instantiated `16` distinct `kmalloc-rnd-*` buckets per size class and check `KFENCE` guard-page sampling statistics:

```bash
# Reading /proc/slabinfo and /sys/kernel/debug/kfence requires root or run0
grep -E "^kmalloc-rnd-[0-9]+-128 " /proc/slabinfo 2>/dev/null | wc -l
cat /sys/module/kfence/parameters/sample_interval 2>/dev/null || true
grep -E "total_allocs|currently allocated" /sys/kernel/debug/kfence/stats 2>/dev/null || true
```

When `RANDOM_KMALLOC_CACHES` is active, counting `kmalloc-rnd-*-128` returns `16` (`kmalloc-rnd-01-128` through `kmalloc-rnd-16-128`), confirming per-callsite hash partitioning against generic `msg_msg` overlap; a non-zero `sample_interval` (typically `100` milliseconds on distro builds) confirms live fleet guard-page UAF detection.

Verify boot-time `FineIBT` / `KCFI` alternative patching and inspect compiled `Rust-for-Linux` module metadata (`rnull_mod`, `nova_core`, or `rust_binder`) when present:

```bash
# Inspecting early boot alternative-patching logs requires root or adm group
journalctl -kb -g "FineIBT|KCFI|CET|Shadow Stack" --no-pager 2>/dev/null | head -n 6 || true
modinfo rnull_mod nova_core 2>/dev/null | grep -E "^(filename|description|author|intree):" || true
```

On `LLVM=1` `x86_64` hosts with `CET` silicon, `journalctl` records `Last level dTLB entries` alongside `FineIBT: enabled` (`arch/x86/kernel/alternative.c`), confirming that caller/callee prototype-hash checks were patched over `ENDBR64` landing pads before userspace started. When auditing custom cloud or appliance kernels, confirming `CONFIG_SLAB_VIRTUAL=y` (or out-of-line `SLAB_BUCKETS` usercopy isolation) alongside `CONFIG_CFI_CLANG=y` and `CONFIG_RUST=y` verifies that both forward-edge code pointers and cross-cache page lifecycles are deterministically hardened inside Ring 0.

