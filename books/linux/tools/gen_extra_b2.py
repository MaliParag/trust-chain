#!/usr/bin/env python3
"""Extra collision-verified SVG diagrams for Batch 2 (Chapters 6..10) of The Linux Trust Chain."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def gen_06():
    build_split_domains(
        P("06-extra-dirty-pagetable-vs-slab-virtual.svg"),
        "Dirty Pagetable Cross-Cache PTE Reuse vs. SLAB_VIRTUAL Quarantine",
        left={
            "label": "Linear Direct Map (Dirty Pagetable Attack)",
            "theme": "red",
            "dashed": True,
            "cards": [
                {
                    "tag": "Step 1 · Slab Drain",
                    "title": "Free Victim & Drain Sibling Slots",
                    "body": "UAF leaves dangling struct file pointer; freeing remaining objects returns order-0 physical frame P to buddy allocator",
                    "theme": "white",
                },
                {
                    "tag": "Step 2 · PTE Spray",
                    "title": "User Page Table Reclaims Frame P",
                    "body": "Dense mmap() faults allocate last-level PTE page on exact physical frame P at identical linear direct-map VA",
                    "theme": "white",
                    "in_edge": "buddy page_alloc()",
                },
                {
                    "tag": "Step 3 · Data-Only Root",
                    "title": "Dangling Write Corrupts PTE PFN",
                    "body": "Stale f_count increment or field write alters PTE physical frame bits; Ring 3 maps kernel .text/cred RW",
                    "theme": "red",
                    "dashed": True,
                    "in_edge": "UAF write/inc",
                },
            ],
        },
        right={
            "label": "SLAB_VIRTUAL (Permanent Virtual Arena)",
            "theme": "green",
            "cards": [
                {
                    "tag": "Step 1 · Dedicated VA",
                    "title": "Type-Pinned Virtual Slab Page",
                    "body": "kmem_cache allocates virtual page V_filp outside direct map, bound exclusively to filp for system uptime",
                    "theme": "white",
                },
                {
                    "tag": "Step 2 · Unmap on Free",
                    "title": "Physical Frame P Unmapped from V_filp",
                    "body": "Buddy allocator recycles physical frame P for user PTEs at a disjoint VA while V_filp PTE stays unmapped",
                    "theme": "white",
                    "in_edge": "unmap V_filp PTE",
                },
                {
                    "tag": "Step 3 · Contained Fault",
                    "title": "#PF Trap or Same-Cache Object Only",
                    "body": "Dereferencing stale V_filp hits unmapped #PF or another genuine struct file; PTE cross-cache alias impossible",
                    "theme": "green",
                    "in_edge": "UAF deref trapped",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "same physical P", "slate"),
            (1, 1, "lr", "severed VA alias", "teal"),
            (2, 2, "lr", "PTE spray blocked", "green"),
        ],
        boundary_label="Virtual-to-Physical Aliasing Seam",
        footer="SLAB_VIRTUAL severs linear direct-map aliasing so buddy-allocator physical recycling never overlaps disjoint types.",
    )


def gen_07():
    build_vertical_flow(
        P("07-extra-selinux-mcs-avc-flow.svg"),
        "SELinux Flask Access Vector Cache (AVC) and MCS Pod Category Dominance",
        steps=[
            {
                "tag": "Ring 0 VFS Hook · Subject Context",
                "title": "Pod A Task Invokes security_file_open(file)",
                "body": "Reads Subject SID (container_t:s0:c12,c45) at cred->security + selinux_blob_sizes.lbs_cred and Inode Target SID (tsid)",
                "theme": "slate",
            },
            {
                "tag": "Fast Path · security/selinux/avc.c",
                "title": "Lockless RCU Lookup in 512-Slot AVC Hash Table",
                "body": "avc_has_perm_noaudit() hashes (ssid, tsid, SECCLASS_FILE) and checks av_decision allowed bitmask plus ioctl xperms",
                "theme": "teal",
                "edge_label": "avc_lookup()",
            },
            {
                "tag": "Slow Path · security/selinux/ss/services.c",
                "title": "Type Enforcement (TE) Policy avtab Evaluation",
                "body": "On AVC miss, security_compute_av() queries binary policydb rules: allow container_t container_file_t : file { open read }",
                "theme": "teal",
                "edge_label": "AVC cache miss",
            },
            {
                "tag": "Category Lattice · security/selinux/ss/mls.c",
                "title": "Multi-Category Security (MCS) ebitmap Dominance",
                "body": "mls_compute_av() verifies ebitmap_contains(&subj_cat, &obj_cat): subject {c12,c45} must dominate volume xattr categories",
                "theme": "amber",
                "edge_label": "constraint check",
            },
            {
                "tag": "Stacked Continuation · security/security.c",
                "title": "AVC Node Cached & Next Stacked LSM Invoked",
                "body": "Inserts RCU avc_node and proceeds sequentially to Landlock (16-layer ruleset), IPE, and LSM-BPF callbacks",
                "theme": "green",
                "edge_label": "return 0 (allow)",
            },
        ],
        side_notes={
            1: {
                "tag": "Nanosecond Hit",
                "title": "99.9% RCU Fast Path",
                "body": "Cached (ssid, tsid, tclass) avoids policydb locks on hot VFS reads/writes",
                "theme": "green",
                "dashed": False,
                "reverse": True,
                "edge_color": "#2b6a4c",
                "edge_label": "O(1) hit",
            },
            3: {
                "tag": "sVirt Containment",
                "title": "Cross-Pod Escape Denied",
                "body": "Touching Pod B volume (s0:c88,c209) or host shadow_t fails dominance (-EACCES)",
                "theme": "red",
                "dashed": True,
                "edge_color": "#8d2d3b",
                "edge_label": "MCS mismatch",
            },
        },
        footer="523,776 unique 2-category MCS pairs isolate sVirt VMs and Kubernetes pods sharing the single container_t domain.",
    )


def gen_08():
    build_fan_bands(
        P("08-extra-tnum-bounds-divergence.svg"),
        "eBPF Verifier Five-Domain Register Lattice (tnum + Intervals) and Escape Seam",
        bands=[
            [
                {
                    "id": "b0",
                    "tag": "Abstract State · include/linux/bpf_verifier.h",
                    "title": "struct bpf_reg_state Path-Sensitive Tracking Across R0..R10",
                    "body": "bpf_check() tracks SCALAR_VALUE and pointer offsets across CFG paths up to 1,000,000 verified dynamic states",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "n_tnum",
                    "tag": "Bitwise Lattice",
                    "title": "struct tnum var_off",
                    "body": "(value, mask) with (value & mask) == 0 tracks known 0/1 bits vs unknown x bits across shifts and XOR/OR/AND",
                    "theme": "teal",
                },
                {
                    "id": "n_r64",
                    "tag": "64-Bit Intervals",
                    "title": "smin..smax & umin..umax",
                    "body": "Signed and unsigned 64-bit bounds (cnum64 r64) tightened on 64-bit ALU ops and BPF_JGT / BPF_JSGE branches",
                    "theme": "teal",
                },
                {
                    "id": "n_r32",
                    "tag": "32-Bit Subregister",
                    "title": "s32_min..u32_max",
                    "body": "Signed and unsigned 32-bit bounds (cnum32 r32) tracking low w0..w9 ALU32 and JMP32 subregister operations",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "b2",
                    "tag": "Mutual Domain Reduction · kernel/bpf/verifier.c",
                    "title": "reg_bounds_sync(): Cross-Tightening Intervals Against tnum Bitmasks",
                    "body": "Propagates tighter bounds bidirectionally between r64, r32, and var_off while marking downstream live scalars precise",
                    "theme": "amber",
                }
            ],
            [
                {
                    "id": "n_ok",
                    "tag": "Verified Native JIT + Spectre Clamp",
                    "title": "Sound Proof & sanitize_ptr_alu(alu_limit)",
                    "body": "Proves umax + access_size <= map_size and emits branchless alu_limit masking to block Spectre v1 OOB speculation",
                    "theme": "green",
                },
                {
                    "id": "n_bug",
                    "tag": "Soundness Escape (CVE-2020-8835 / CVE-2021-3490 / CVE-2023-2163)",
                    "title": "Oracle Register Divergence (Static 0 vs Runtime 1)",
                    "body": "Skipped ALU32 bound sync or faulty parent precision pruning yields R6 believed 0; R6 *= 0x1000 bypasses map bounds",
                    "theme": "red",
                    "dashed": True,
                },
            ],
        ],
        edges=[
            ("b0", "n_tnum", "known bits", "slate", False),
            ("b0", "n_r64", "64-bit range", "slate", False),
            ("b0", "n_r32", "32-bit range", "slate", False),
            ("n_tnum", "b2", None, "teal", False),
            ("n_r64", "b2", "intersect domains", "teal", False),
            ("n_r32", "b2", None, "teal", False),
            ("b2", "n_ok", "sound invariant", "green", False),
            ("b2", "n_bug", "under-approx bug", "red", True),
        ],
        footer="Because eBPF emits native Ring 0 machine code without runtime SFI checks, a 1-bit domain bug grants kernel R/W.",
    )


def gen_09():
    build_vertical_flow(
        P("09-extra-dirty-pipe-pagecache-splice.svg"),
        "Dirty Pipe (CVE-2022-0847): Uninitialized pipe_buffer Flags Corrupting Page Cache",
        steps=[
            {
                "tag": "Step 1 · Prime Pipe Ring (fs/pipe.c)",
                "title": "Fill & Drain All 16 struct pipe_buffer Ring Slots",
                "body": "Unprivileged task writes and drains anonymous pipe pages so anon_pipe_buf_ops leaves PIPE_BUF_FLAG_CAN_MERGE set on every slot",
                "theme": "slate",
            },
            {
                "tag": "Step 2 · Zero-Copy Splice (lib/iov_iter.c)",
                "title": "open(\"/etc/passwd\", O_RDONLY) -> splice() 1 Byte into Pipe",
                "body": "copy_page_to_iter_pipe() points buf->page at the live read-only page-cache folio and sets buf->ops = page_cache_pipe_buf_ops",
                "theme": "amber",
                "edge_label": "splice(fd_ro, pipe_w)",
            },
            {
                "tag": "Step 3 · Page-Cache Overwrite",
                "title": "write(pipe_w, \"root::0:0:...\", len) Merges Into Backing Folio",
                "body": "pipe_write() sees stale PIPE_BUF_FLAG_CAN_MERGE and copies bytes directly into shared RAM page cache, bypassing O_RDONLY & DAC",
                "theme": "red",
                "dashed": True,
                "edge_label": "unchecked merge",
            },
            {
                "tag": "Step 4 · Kernel Fix & Immutable Defense",
                "title": "Explicit buf->flags = 0 (Linux 5.16.11+) & dm-verity / fs-verity",
                "body": "Commit 9d2231c5d74e zeroes flags in copy_page_to_iter_pipe() and push_pipe(); IPE + fs-verity protect immutable binaries",
                "theme": "green",
                "edge_label": "architectural fix",
            },
        ],
        side_notes={
            1: {
                "tag": "Missing Init",
                "title": "Stale Flag Retained",
                "body": "copy_page_to_iter_pipe() initialized page, offset, and len while forgetting buf->flags = 0",
                "theme": "red",
                "dashed": True,
                "edge_color": "#8d2d3b",
                "edge_label": "missing init",
            },
            2: {
                "tag": "Silent Mutation",
                "title": "Dirty Without Writeback",
                "body": "Overwrites /etc/passwd or SUID ELF in RAM without marking inode dirty or requiring userns",
                "theme": "amber",
                "dashed": True,
                "edge_color": "#b07926",
                "edge_label": "UID 0 hijack",
            },
        },
        footer="Dirty Pipe required zero capabilities or namespaces, proving why Ring 0 state initialization and immutable /usr matter.",
    )


def gen_10():
    build_fan_bands(
        P("10-extra-pwnkit-looney-envp-hazard.svg"),
        "Anatomy of SUID Stack, Linker, and chroot Attacks vs. Clean-Room Broker Spawning",
        bands=[
            [
                {
                    "id": "b0",
                    "tag": "Hostile In-Place Transition · fs/exec.c & fs/binfmt_elf.c",
                    "title": "Untrusted Caller Invokes SUID-Root Binary: execve(path, argv, envp)",
                    "body": "Kernel mutates cred->euid = 0 inside caller's task and pushes [argc | argv[] | NULL | envp[] | NULL | auxv(AT_SECURE=1)]",
                    "theme": "red",
                }
            ],
            [
                {
                    "id": "c_tun",
                    "tag": "Dynamic Linker · CVE-2023-4911",
                    "title": "Looney Tunables (ld.so)",
                    "body": "__tunables_init() parses hostile GLIBC_TUNABLES before main(); overflow corrupts link_map DT_RPATH to load ./libc.so.6 as UID 0",
                    "theme": "red",
                    "dashed": True,
                },
                {
                    "id": "c_pwn",
                    "tag": "Empty argv{} · CVE-2021-4034",
                    "title": "PwnKit (pkexec argc == 0)",
                    "body": "Loop for(n=1; n<argc) skips; argv[1] reads/writes OOB across NULL into envp[0], re-injecting GCONV_PATH=. post-scrub",
                    "theme": "red",
                    "dashed": True,
                },
                {
                    "id": "c_chr",
                    "tag": "NSS Plugin · CVE-2025-32463",
                    "title": "sudo --chroot (-R) Escape",
                    "body": "sudo chroots into user directory prior to sudoers rejection; glibc NSS parses fake nsswitch.conf and dlopen()s root .so",
                    "theme": "red",
                    "dashed": True,
                },
            ],
            [
                {
                    "id": "b2",
                    "tag": "Architectural Cure · Linux 5.18+, PR_SET_NO_NEW_PRIVS, & systemd v256-v259",
                    "title": "NoNewPrivileges=yes + systemd run0 / run0 --empower Clean-Room Spawning",
                    "body": "PID 1 authenticates via Polkit and forks transient unit with synthetic envp, isolated ptybrokerd PTY, and non-root CapAmb",
                    "theme": "green",
                }
            ],
        ],
        edges=[
            ("b0", "c_tun", "envp[] to ld.so", "red", False),
            ("b0", "c_pwn", "argc == 0 stack", "red", False),
            ("b0", "c_chr", "pre-auth chroot", "red", False),
            ("c_tun", "b2", None, "green", False),
            ("c_pwn", "b2", "abolishes SUID vector", "green", False),
            ("c_chr", "b2", None, "green", False),
        ],
        footer="Every SUID vulnerability exploits state inherited from the unprivileged parent; run0 inverts process creation to PID 1.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_06()
    gen_07()
    gen_08()
    gen_09()
    gen_10()
    print("SUCCESS: Generated and collision-verified 5 extra Batch 2 diagrams (06..10).")


if __name__ == "__main__":
    main()
