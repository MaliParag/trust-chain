#!/usr/bin/env python3
"""Diagram generator for The Linux Trust Chain (Volume III), backed by shared tools/diagram_lib.py.

Generates 43 collision- and orthogonality-verified architectural SVG diagrams:
- 1 in 00-prologue.md (trust-chain-map.svg)
- 2 in 00b-foundations.md (00b-linux-privilege-rings-lsm.svg, 00b-mutable-vs-immutable-boot.svg)
- 40 across Chapters 01..20 (2 per chapter)
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    SvgCanvas,
    build_dual_rail_timeline,
    build_fan_bands,
    build_horizontal_pipeline,
    build_matrix,
    build_sequence,
    build_split_domains,
    build_timeline_spine,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def generate_opening():
    # 1. trust-chain-map.svg (Prologue)
    c = SvgCanvas(890, 580)
    y = c.add_header(
        "The 20-Chapter Linux Trust Chain",
        "Composable hardware, kernel, IPC, container, and confidential-cloud links; security fails at the unverified seam",
    ) + 14.0
    main_x, main_w = 56.0, 548.0
    side_x, side_w = 648.0, 206.0

    tiers = [
        (
            "Finale · Chapter 20",
            "Open-Source Supply-Chain Provenance",
            "20. XZ Utils (CVE-2024-3094) · systemd dlopen() · Reproducible Builds · SLSA · Sigstore Rekor",
            "red",
            "subverts upstream before signing",
        ),
        (
            "Part IV · Chapters 14 to 19",
            "Containers, Agentic AI Sandboxes, & Confidential Cloud",
            "14. OCI & Escapes · 15. gVisor & Micro-VMs · 16. OIDC & SPIFFE · 17. AI Agent Sandboxes · 18. SEV-SNP & SVSM · 19. CoCo",
            "amber",
            "inherits host kernel & identity",
        ),
        (
            "Part III · Chapters 9 to 13",
            "Userspace Privilege, Secrets, & Identity",
            "9. Capabilities & userns · 10. Killing SUID & run0 · 11. systemd & D-Bus · 12. Keyrings & systemd-creds · 13. PAM, SSH & FIDO2",
            "green",
            "inherits MAC & Ring 0 integrity",
        ),
        (
            "Part II · Chapters 5 to 7",
            "Kernel Self-Protection & Stacked LSMs",
            "5. Kernel Lockdown, Signed Modules & kexec · 6. KCFI, FineIBT, CET, SLAB_VIRTUAL & Rust · 7. SELinux, AppArmor & Landlock",
            "teal",
            "inherits verified boot & root_hash",
        ),
        (
            "Part I · Chapters 1 to 4",
            "Verified Boot & Immutable Root",
            "1. UEFI, shim, MOK & SBAT · 2. UKI, systemd-stub & pcrlock · 3. LUKS2, dm-verity & fs-verity · 4. IMA, IPE & Keylime",
            "slate",
            None,
        ),
    ]
    ys = []
    cur_y = y
    for idx, (tag, ti, bo, th, edge_lbl) in enumerate(tiers):
        h = c.add_card(main_x, cur_y, main_w, tag=tag, title=ti, body=bo, theme=th)
        ys.append((cur_y, h, edge_lbl))
        cur_y += h + (58.0 if idx < len(tiers) - 1 else 0.0)

    for idx in range(len(ys) - 1):
        upper_top, upper_h, lbl = ys[idx]
        lower_top, _, _ = ys[idx + 1]
        col = "#8d2d3b" if idx == 0 else "#b07926"
        c.add_line(
            main_x + main_w / 2,
            lower_top,
            main_x + main_w / 2,
            upper_top + upper_h,
            color=col,
            width=1.8,
            arrow_end=True,
            label=lbl,
            label_pos=0.44,
            label_color=col,
        )

    rail_top = ys[1][0]
    rail_bot = ys[4][0] + ys[4][1]
    c.add_rect(side_x, rail_top, side_w, rail_bot - rail_top, fill="#f4f1ea",
               stroke="#524c44", stroke_width=1.3, rx=8, dash="5,3", layer="bg")
    c.add_card(
        side_x + 12,
        rail_top + 22,
        side_w - 24,
        tag="Interlude · Chapter 8",
        title="The eBPF Dual Edge",
        body="LSM-BPF inline enforcement (Tetragon) and ring-buffer telemetry (Falco/Tracee) vs. verifier LPEs",
        theme="white",
        align="center",
        title_size=11.5,
        body_size=10.0,
    )
    c.add_text(side_x + side_w / 2, rail_bot - 42, "Hooks VFS, LSM & syscalls:", size=9.8,
               fill="#524c44", bold=True, anchor="middle")
    c.add_text(side_x + side_w / 2, rail_bot - 26, "enforces or escapes Ring 0", size=9.8,
               fill="#524c44", italic=True, anchor="middle")
    for idx in (1, 2, 3, 4):
        mid = ys[idx][0] + ys[idx][1] / 2
        c.add_line(main_x + main_w, mid, side_x, mid, color="#787167", width=1.2, dash="3,3", arrow_end=True)

    c.height = cur_y + 20.0
    c.save(P("trust-chain-map.svg"))

    # 2. 00b-linux-privilege-rings-lsm.svg (Foundations)
    build_vertical_flow(
        P("00b-linux-privilege-rings-lsm.svg"),
        "Hardware Privilege Levels and VFS / LSM Security Hook Placement",
        [
            {
                "tag": "Ring 3 / EL0 · Userspace",
                "title": "Process Executing with RCU struct cred",
                "body": "Holds uid/euid, gid, CapEff/CapPrm/CapBnd, and LSM security blob pointer",
                "theme": "slate",
            },
            {
                "tag": "Syscall Entry · Ring 0 / EL1",
                "title": "entry_SYSCALL_64 -> seccomp-BPF Filter Gate",
                "body": "Evaluates cBPF filter over syscall_nr and register args before VFS path resolution",
                "theme": "teal",
                "edge_label": "syscall instruction",
            },
            {
                "tag": "VFS Path Walk & DAC",
                "title": "filename_lookup() -> generic_permission()",
                "body": "Resolves path to kernel dentry + inode; enforces POSIX mode bits, ACLs, and capabilities",
                "theme": "teal",
                "edge_label": "SECCOMP_RET_ALLOW",
            },
            {
                "tag": "Mandatory Access Control",
                "title": "security_inode_permission() / security_file_open()",
                "body": "Invokes stacked LSM callbacks (SELinux, AppArmor, Landlock, IPE, LSM-BPF) on resolved kernel objects",
                "theme": "green",
                "edge_label": "race-free object check",
            },
            {
                "tag": "Below Ring 0 · Hypervisor & Firmware",
                "title": "VMX Root / EL2 KVM & SEV-SNP RMP / Intel TDX SEAM",
                "body": "EPT / Stage-2 page tables and CPU memory controllers isolate guest physical pages beneath EL1/Ring 0",
                "theme": "purple",
                "edge_label": "hardware memory enforcement",
            },
        ],
        side_notes={
            1: {
                "tag": "TOCTOU Trap",
                "title": "User-Space Pointer Dereference",
                "body": "Inspecting user char* paths in seccomp or kprobes races sibling threads",
                "theme": "red",
                "edge_label": "raw pointer hazard",
            },
            3: {
                "tag": "Key Guarantee",
                "title": "Object-Level Mediation",
                "body": "LSM hooks inspect pinned kernel inode/file structs after VFS copy-in",
                "theme": "amber",
                "edge_label": "pinned struct",
            },
        },
        footer="Placing LSM hooks inside VFS after kernel object lookup prevents user-memory path-swap races between check and use.",
    )

    # 3. 00b-mutable-vs-immutable-boot.svg (Foundations)
    build_split_domains(
        P("00b-mutable-vs-immutable-boot.svg"),
        "Mutable Package-Managed Distro vs. Image-Based Verified Linux",
        left={
            "label": "Mutable Package Distro",
            "theme": "amber",
            "cards": [
                {
                    "tag": "Boot Artifacts",
                    "title": "shim -> GRUB2 -> vmlinuz + Unsigned initramfs",
                    "body": "initramfs generated locally by dracut/mkinitramfs on unencrypted /boot",
                    "theme": "white",
                },
                {
                    "tag": "Root Filesystem",
                    "title": "Read-Write ext4 / XFS on Raw LUKS2",
                    "body": "apt/dnf mutates /usr and /etc in place; no cryptographic tree digest",
                    "theme": "white",
                    "in_edge": "unverified pivot_root",
                },
                {
                    "tag": "Privilege & Services",
                    "title": "SUID-root Binaries & Ambient Root Daemons",
                    "body": "sudo, pkexec, and mutable /etc configs broaden post-boot persistence",
                    "theme": "white",
                    "in_edge": "executes /sbin/init",
                },
            ],
        },
        right={
            "label": "Immutable Verified Linux",
            "theme": "green",
            "cards": [
                {
                    "tag": "Boot Artifacts",
                    "title": "UEFI -> Signed UKI (systemd-stub + PCR[11])",
                    "body": "Single PE Authenticode signature binds kernel, initrd, cmdline, and roothash",
                    "theme": "white",
                },
                {
                    "tag": "Root Filesystem",
                    "title": "Read-Only dm-verity / composefs (/usr)",
                    "body": "Every 4 KiB block verified against Merkle root_hash; IPE enforces execution",
                    "theme": "white",
                    "in_edge": "pinned roothash=",
                },
                {
                    "tag": "Privilege & Services",
                    "title": "SUID-Free (NoNewPrivileges / run0) + API Config",
                    "body": "Ephemeral /etc, TPM2-sealed systemd-creds, and locked-down Ring 0",
                    "theme": "white",
                    "in_edge": "attested userspace",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "eliminates initrd gap", "teal"),
            (1, 1, "lr", "pins /usr to Merkle root", "green"),
            (2, 2, "lr", "removes SUID & drift", "slate"),
        ],
        boundary_label="Architectural Trust Posture",
        footer="Mutable distributions stop cryptographic verification at vmlinuz; immutable Linux carries verification continuously into /usr.",
    )


def generate_part1():
    # Ch 1 Diagram 1
    build_vertical_flow(
        P("01-shim-mok-trust-chain.svg"),
        "UEFI Secure Boot Delegation Through shim and Machine Owner Keys",
        [
            {
                "tag": "UEFI NVRAM Authorities",
                "title": "Firmware LoadImage() Evaluates dbx Then db",
                "body": "Checks Microsoft Corporation UEFI CA (2011 / 2023) and UEFI revocation list",
                "theme": "slate",
            },
            {
                "tag": "First-Stage Bridge",
                "title": "shimx64.efi (Signed by Microsoft UEFI CA)",
                "body": "Embeds distro X.509 certificate, enforces SbatLevel, and installs SHIM_LOCK protocol",
                "theme": "teal",
                "edge_label": "Authenticode valid",
            },
            {
                "tag": "Local Key Store",
                "title": "MokList -> Boot-Services-Only MokListRT Mirror",
                "body": "Imports operator MOK keys for custom kernels/DKMS while MokListX enforces MOK revocations",
                "theme": "amber",
                "edge_label": "mirrors to RT var",
            },
            {
                "tag": "Second-Stage Loader",
                "title": "Vendor GRUB2 (grubx64.efi) or Direct systemd-boot / UKI",
                "body": "Verified against embedded vendor CA or MokList; GRUB registers shim_lock verifier on kernel",
                "theme": "green",
                "edge_label": "verify_buffer()",
            },
            {
                "tag": "Ring 0 Handoff",
                "title": "vmlinuz EFI Handover + MokListRT Keyring Import",
                "body": "Kernel imports db and MokListRT into .platform/.machine keyrings and activates Lockdown",
                "theme": "green",
                "edge_label": "ExitBootServices()",
            },
        ],
        side_notes={
            2: {
                "tag": "Physical Presence Gate",
                "title": "MokManager.efi",
                "body": "Requires interactive console password confirmation before persisting new MOK keys",
                "theme": "purple",
                "edge_label": "enrollment UI",
            },
        },
        footer="shim decouples hundreds of Linux distributions from per-kernel Microsoft signing while preserving UEFI Secure Boot.",
    )

    # Ch 1 Diagram 2
    build_split_domains(
        P("01-sbat-vs-dbx-revocation.svg"),
        "Hash-Based UEFI dbx Exhaustion vs. SBAT Generation Revocation",
        left={
            "label": "Legacy SHA-256 dbx List",
            "theme": "red",
            "cards": [
                {
                    "tag": "Upstream Bug",
                    "title": "Single Flaw in Shared Source (GRUB2 CVE-2020-10713)",
                    "body": "Every distro compiles and signs dozens of distinct grubx64.efi binaries",
                    "theme": "white",
                },
                {
                    "tag": "Combinatorial Explosion",
                    "title": "Hundreds of Unique Authenticode Digests",
                    "body": "Revoking vendor CA would brick install media; must list every SHA-256 hash",
                    "theme": "white",
                    "in_edge": "per-distro builds",
                },
                {
                    "tag": "NVRAM Ceiling",
                    "title": "32-64 KiB SPI Flash Variable Exhaustion",
                    "body": "SetVariable(dbx) fails or bricks boards when EFI_SIGNATURE_LIST overflows flash",
                    "theme": "white",
                    "in_edge": "bloats dbx",
                },
            ],
        },
        right={
            "label": "SBAT Generation Policy",
            "theme": "green",
            "cards": [
                {
                    "tag": "Embedded Metadata",
                    "title": "PE .sbat Section Inside Signed Binary",
                    "body": "CSV rows declare component generations: grub,4 and shim,4 and grub.fedora,3",
                    "theme": "white",
                },
                {
                    "tag": "Compact Policy",
                    "title": "Tiny SbatLevel UEFI Variable (~100 Bytes)",
                    "body": "Single string grub,4 revokes all pre-generation-4 GRUB binaries across all distros",
                    "theme": "white",
                    "in_edge": "parsed by shim",
                },
                {
                    "tag": "Constant-Space Gate",
                    "title": "Monotonic Generation Comparison (gen < min_gen)",
                    "body": "O(components) flash footprint regardless of how many vendor builds exist",
                    "theme": "white",
                    "in_edge": "blocks old gen",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "adds component CSV", "teal"),
            (1, 1, "lr", "replaces N hashes with 1 int", "green"),
            (2, 2, "lr", "preserves NVRAM space", "green"),
        ],
        boundary_label="Revocation Scaling Model",
        footer="SBAT turns revocation complexity from O(signed binaries) into O(upstream component families).",
    )

    # Ch 2 Diagram 1
    build_fan_bands(
        P("02-uki-pe-sections-pcr11.svg"),
        "Unified Kernel Image (UKI) PE Layout and systemd-stub PCR[11] Extensions",
        [
            [
                {
                    "id": "uki",
                    "tag": "Single Authenticode-Signed PE/COFF Binary",
                    "title": "Unified Kernel Image (linux-6.12.efi) Verified Atomically by UEFI + shim",
                    "body": "Eliminates unauthenticated /boot initramfs CPIO and mutable GRUB kernel command-line edits",
                    "theme": "slate",
                }
            ],
            [
                {"id": "s_stub", "tag": "PE Code", "title": "systemd-stub", "body": "EFI entry point & measurer", "theme": "teal"},
                {"id": "s_lin", "tag": ".linux", "title": "vmlinuz Image", "body": "Compressed kernel payload", "theme": "white"},
                {"id": "s_ini", "tag": ".initrd", "title": "Initramfs CPIO", "body": "Early userspace & cryptsetup", "theme": "white"},
                {"id": "s_cmd", "tag": ".cmdline", "title": "Kernel Cmdline", "body": "roothash= & lockdown=integrity", "theme": "white"},
                {"id": "s_key", "tag": ".pcrpkey / .pcrsig", "title": "PCR Policy Key", "body": "Public key & signed PCR[11] JSON", "theme": "amber"},
            ],
            [
                {
                    "id": "pcr11",
                    "tag": "TPM 2.0 Measurement & Phase Binding",
                    "title": "PCR[11] Receives Section Digests + Boot-Phase Strings (enter-initrd -> leave-initrd -> sysinit -> ready)",
                    "body": "LUKS2 volume keys sealed to enter-initrd become cryptographically unreachable before untrusted workloads start",
                    "theme": "green",
                }
            ],
        ],
        [
            ("uki", "s_stub", None, "slate", False),
            ("uki", "s_lin", None, "slate", False),
            ("uki", "s_ini", None, "slate", False),
            ("uki", "s_cmd", None, "slate", False),
            ("uki", "s_key", None, "amber", False),
            ("s_stub", "pcr11", "extends sections", "teal", False),
            ("s_ini", "pcr11", "phase barriers", "green", False),
            ("s_key", "pcr11", "authorizes policy", "amber", False),
        ],
        footer="Extending boot-phase transitions into PCR[11] time-bounds secret availability strictly to early initrd execution.",
    )

    # Ch 2 Diagram 2
    build_sequence(
        P("02-pcrlock-signed-policy.svg"),
        "TPM2_PolicyAuthorize & systemd-pcrlock: Avoiding Brittle PCR Lockouts",
        [
            {"title": "Distro / ukify", "sub": "Build Signer", "theme": "purple"},
            {"title": "systemd-pcrlock", "sub": "Local Event Predictor", "theme": "teal"},
            {"title": "systemd-stub & initrd", "sub": "Boot Measurer", "theme": "slate"},
            {"title": "TPM 2.0 Engine", "sub": "Policy Evaluator", "theme": "green"},
        ],
        [
            (0, 2, "Sign expected PCR[11] digest -> .pcrsig", "purple", False),
            (1, 1, "Parse TCG event log & NV index -> PolicyOR tree", "teal", False),
            (2, 3, "TPM2_PCR_Extend(PCR[11], UKI sections + enter-initrd)", "slate", False),
            (2, 3, "TPM2_VerifySignature(.pcrpkey, .pcrsig) -> VerifiedTicket", "amber", False),
            (2, 3, "TPM2_PolicyAuthorize(PCR[11]) + pcrlock NV pin", "teal", False),
            (3, 2, "Unseal LUKS2 Volume Key (only in enter-initrd phase)", "green", False),
            (2, 3, "Extend PCR[11] with 'leave-initrd' before root pivot", "red", True),
        ],
        footer="Combining vendor-signed PCR[11] policies with local systemd-pcrlock predictions survives kernel upgrades without raw-PCR bricking.",
    )

    # Ch 3 Diagram 1
    build_split_domains(
        P("03-luks2-aead-vs-xts.svg"),
        "Standard LUKS2 AES-XTS Confidentiality vs. Authenticated LUKS2 + dm-integrity",
        left={
            "label": "Plain dm-crypt (AES-XTS)",
            "theme": "amber",
            "cards": [
                {
                    "tag": "Key Derivation",
                    "title": "LUKS2 JSON Header + Argon2id KDF",
                    "body": "Memory-hard KDF protects master volume key against GPU brute force",
                    "theme": "white",
                },
                {
                    "tag": "Sector Transform",
                    "title": "Unauthenticated XTS Tweakable Block Cipher",
                    "body": "No per-sector MAC tag; 16-byte ciphertext edit scrambles 1 plaintext block cleanly",
                    "theme": "white",
                    "in_edge": "unlocks master key",
                },
                {
                    "tag": "Evil-Maid Exposure",
                    "title": "Silent Offline Ciphertext Malleability",
                    "body": "Attacker replays old sectors or flips bits without dm-crypt raising EIO",
                    "theme": "white",
                    "in_edge": "no integrity tag",
                },
            ],
        },
        right={
            "label": "AEAD LUKS2 + dm-integrity",
            "theme": "green",
            "cards": [
                {
                    "tag": "Key Derivation",
                    "title": "LUKS2 Argon2id + TPM2 Sealed Keyslot",
                    "body": "Derives separate encryption and authentication keys inside kernel keyring",
                    "theme": "white",
                },
                {
                    "tag": "Sector Transform",
                    "title": "AEAD (chacha20-poly1305 / aes-gcm) or dm-verity",
                    "body": "Binds sector number + 128-bit authentication tag in journaled metadata area",
                    "theme": "white",
                    "in_edge": "integrity-bound",
                },
                {
                    "tag": "Deterministic Fault",
                    "title": "Immediate -EBADMSG / -EIO on Any Bit Flip",
                    "body": "Detects sector splicing, rollback, and offline bit corruption before VFS read",
                    "theme": "white",
                    "in_edge": "verifies tag",
                },
            ],
        },
        bridges=[
            (1, 1, "lr", "adds per-sector MAC", "teal"),
            (2, 2, "lr", "blocks silent tamper", "green"),
        ],
        boundary_label="Disk Tamper Resistance",
        footer="Encryption without authentication hides data at rest but never proves ciphertext on disk is unmodified.",
    )

    # Ch 3 Diagram 2
    build_fan_bands(
        P("03-dm-verity-sysext-tree.svg"),
        "Cryptographic Storage Composition: UKI Roothash, dm-verity, sysext, and fs-verity",
        [
            [
                {
                    "id": "root_anchor",
                    "tag": "Trusted Anchor Inside Signed UKI",
                    "title": "Kernel Command Line roothash=<256-bit SHA-256 Digest> + Verity Signature Keyring",
                    "body": "Pinned in Authenticode-signed .cmdline section or verified PKCS#7 dm-verity root-hash signature",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "usr_verity",
                    "tag": "Block Merkle Tree",
                    "title": "dm-verity Read-Only /usr",
                    "body": "Verifies every 4 KiB page fault on demand in O(log N) hashes",
                    "theme": "teal",
                },
                {
                    "id": "sysext",
                    "tag": "Composable Overlay",
                    "title": "systemd-sysext / confext",
                    "body": "Signed EROFS/SquashFS images merged via read-only OverlayFS",
                    "theme": "purple",
                },
                {
                    "id": "fsverity",
                    "tag": "File Merkle Tree",
                    "title": "fs-verity on Writable ext4/btrfs",
                    "body": "Per-inode read-only SHA-256/512 Merkle tree for packages & composefs",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "vfs_enforce",
                    "tag": "Kernel Page-Cache Invariant",
                    "title": "Corrupted Disk Blocks Trigger Immediate I/O Fault (DM_VERITY_MODE_RESTART / PANIC / EIO)",
                    "body": "Zero unverified bytes reach userspace mmap(PROT_EXEC) or kernel execve() loaders",
                    "theme": "amber",
                }
            ],
        ],
        [
            ("root_anchor", "usr_verity", "pins root_hash", "slate", False),
            ("root_anchor", "sysext", "verifies PKCS#7", "purple", False),
            ("root_anchor", "fsverity", "certifies digest", "green", False),
            ("usr_verity", "vfs_enforce", "page check", "teal", False),
            ("sysext", "vfs_enforce", "overlay mount", "purple", False),
            ("fsverity", "vfs_enforce", "bio verify", "green", False),
        ],
        footer="dm-verity protects immutable partitions at block granularity while fs-verity brings identical Merkle guarantees to individual files.",
    )

    # Ch 4 Diagram 1
    build_split_domains(
        P("04-ima-vs-ipe-enforcement.svg"),
        "Legacy IMA-Appraisal xattr Complexity vs. Linux 6.12+ Integrity Policy Enforcement (IPE)",
        left={
            "label": "IMA-Appraisal (xattrs)",
            "theme": "amber",
            "cards": [
                {
                    "tag": "Metadata Storage",
                    "title": "Per-File security.ima & security.evm xattrs",
                    "body": "Every binary and script on disk must carry signed xattrs maintained across updates",
                    "theme": "white",
                },
                {
                    "tag": "Whole-File Read",
                    "title": "Linear Full-File Hash on Open / Exec",
                    "body": "Hashes entire file sequentially; vulnerable to mmap shared-write TOCTOU (ToMToU)",
                    "theme": "white",
                    "in_edge": "reads full inode",
                },
                {
                    "tag": "Log Scaling",
                    "title": "Unbounded PCR[10] ASCII/Binary Event Log",
                    "body": "Long-lived servers accumulate hundreds of thousands of IMA entries, slowing quotes",
                    "theme": "white",
                    "in_edge": "extends PCR[10]",
                },
            ],
        },
        right={
            "label": "IPE LSM (Verity Policy)",
            "theme": "green",
            "cards": [
                {
                    "tag": "Cryptographic Properties",
                    "title": "Evaluates Backing dm-verity / fs-verity State",
                    "body": "Zero per-file xattr churn; trusts volume root_hash or PKCS#7 verity signature",
                    "theme": "white",
                },
                {
                    "tag": "Demand-Paged Check",
                    "title": "Hooks bprm_check, mmap, and kernel_read_file",
                    "body": "O(log N) Merkle page verification prevents post-open tampering automatically",
                    "theme": "white",
                    "in_edge": "queries block/inode",
                },
                {
                    "tag": "Readable Policy",
                    "title": "Concise Auditable Policy in securityfs",
                    "body": "op=EXECUTE boot_verified=TRUE action=ALLOW; default_action=DENY",
                    "theme": "white",
                    "in_edge": "atomic PKCS#7 update",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "uses Merkle roots", "teal"),
            (1, 1, "lr", "stops scan & TOCTOU", "green"),
        ],
        boundary_label="Execution Appraisal Architecture",
        footer="IPE turns dm-verity and fs-verity from passive storage primitives into a system-wide mandatory code-integrity policy.",
    )

    # Ch 4 Diagram 2
    build_sequence(
        P("04-keylime-rats-attestation.svg"),
        "Continuous Remote Attestation with Keylime and IETF RATS (RFC 9334)",
        [
            {"title": "Linux Attester", "sub": "TPM 2.0 + Rust Keylime Agent", "theme": "slate"},
            {"title": "Keylime Registrar", "sub": "EK / AK Identity Directory", "theme": "purple"},
            {"title": "Keylime Verifier", "sub": "RATS Policy & IMA Engine", "theme": "teal"},
            {"title": "Relying Party", "sub": "Workload / Secret Orchestrator", "theme": "green"},
        ],
        [
            (0, 1, "Register EK cert + Attestation Key (AK) pubkey", "purple", False),
            (1, 0, "TPM2_MakeCredential encrypted challenge to EK", "purple", False),
            (0, 1, "TPM2_ActivateCredential proves AK resides in TPM", "purple", False),
            (2, 0, "Send fresh cryptographic nonce for periodic quote", "teal", False),
            (0, 2, "Signed TPM2_Quote(PCR[0..11], PCR[10]) + IMA delta log", "slate", False),
            (2, 2, "Replay TCG & IMA logs against reference values", "teal", False),
            (2, 3, "Emit Attestation Result / trigger revocation webhook", "green", False),
        ],
        footer="Hardware MakeCredential/ActivateCredential binds the signing AK to genuine TPM silicon before any PCR[10] runtime quote is trusted.",
    )


def generate_part2_and_interlude():
    # Ch 5 Diagram 1
    build_split_domains(
        P("05-uid0-ring0-lockdown-boundary.svg"),
        "Closing the UID 0 to Ring 0 Gap with Linux Kernel Lockdown",
        left={
            "label": "Unconstrained UID 0",
            "theme": "red",
            "cards": [
                {
                    "tag": "Direct Memory",
                    "title": "/dev/mem, /dev/kmem, /dev/port & iopl()",
                    "body": "UID 0 maps physical RAM or PCIe BARs to overwrite kernel text and cred structs",
                    "theme": "white",
                },
                {
                    "tag": "Unverified Code",
                    "title": "Unsigned insmod & Legacy kexec_load()",
                    "body": "Root loads arbitrary .ko rootkits or boots an unsigned replacement kernel",
                    "theme": "white",
                    "in_edge": "arbitrary ring 0",
                },
                {
                    "tag": "Kernel Introspection",
                    "title": "kprobes, bpf_probe_read_kernel & /proc/kcore",
                    "body": "Extracts LUKS volume keys and signing secrets directly from kernel heap",
                    "theme": "white",
                    "in_edge": "reads ring 0 secrets",
                },
            ],
        },
        right={
            "label": "Kernel Lockdown Active",
            "theme": "green",
            "cards": [
                {
                    "tag": "lockdown=integrity",
                    "title": "Blocks Raw Memory, Port I/O, ACPI & MSR Writes",
                    "body": "Denies /dev/mem, PCI BAR mmap, unverified initrd ACPI tables, and hibernation",
                    "theme": "white",
                },
                {
                    "tag": "lockdown=integrity",
                    "title": "Enforces Signed .ko & Signed kexec_file_load()",
                    "body": "Every Ring 0 code path must chain to .builtin or .secondary_trusted_keys",
                    "theme": "white",
                    "in_edge": "preserves Secure Boot",
                },
                {
                    "tag": "lockdown=confidentiality",
                    "title": "Seals Kernel Memory Against Root Extraction",
                    "body": "Restricts kprobes, arbitrary eBPF kernel reads, debugfs, and /proc/kcore",
                    "theme": "white",
                    "in_edge": "protects Ring 0 secrets",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "-EPERM lockdown gate", "teal"),
            (1, 1, "lr", "mandates PKCS#7 / PE sig", "green"),
            (2, 2, "lr", "blocks secret exfiltration", "purple"),
        ],
        boundary_label="UID 0 / Ring 0 Boundary",
        footer="Without Kernel Lockdown, UEFI Secure Boot guarantees evaporate the moment any root process touches /dev/mem or kexec_load.",
    )

    # Ch 5 Diagram 2
    build_horizontal_pipeline(
        P("05-module-sig-kexec-pipeline.svg"),
        "Kernel Keyring Hierarchy for Module PKCS#7 and kexec_file_load Verification",
        [
            {
                "tag": "UEFI / MOK Import",
                "title": ".platform & .machine",
                "body": "Populated at boot from UEFI db and shim MokListRT",
                "theme": "slate",
            },
            {
                "tag": "Compiled-In Root",
                "title": "Builtin Trusted Keys",
                "body": "X.509 certs baked into vmlinuz rodata at build time",
                "theme": "teal",
            },
            {
                "tag": "Runtime Trust Ring",
                "title": "Secondary Trusted Keys",
                "body": "Accepts new CAs only if signed by builtin or machine keys",
                "theme": "purple",
            },
            {
                "tag": "Admission Gate",
                "title": "Module & kexec Gate",
                "body": "finit_module (.ko PKCS#7) & kexec_file_load (PE sig)",
                "theme": "green",
            },
        ],
        under_anchor={
            "target_idx": 0,
            "tag": "Revocation Gate",
            "title": ".blacklist Keyring (UEFI dbx & MokListX)",
            "body": "Unconditionally rejects revoked certificate hashes and binary digests before trust evaluation",
            "theme": "red",
            "edge_label": "checked first",
        },
        footer="Separating .platform from .machine lets distributions permit UEFI boot without automatically trusting third-party UEFI CAs for kernel modules.",
    )

    # Ch 6 Diagram 1
    build_split_domains(
        P("06-kernel-cfi-shadow-stack.svg"),
        "Kernel Control-Flow Integrity: Forward-Edge KCFI/FineIBT + Backward-Edge Shadow Stacks",
        left={
            "label": "Forward-Edge (KCFI / FineIBT)",
            "theme": "teal",
            "cards": [
                {
                    "tag": "Exploit Primitive",
                    "title": "Corrupted ops->ioctl Function Pointer",
                    "body": "Heap UAF overwrites vtable slot to pivot RIP into ROP/JOP gadget",
                    "theme": "white",
                },
                {
                    "tag": "KCFI / FineIBT Prologue",
                    "title": "32-Bit Prototype Hash + ENDBR64 Landing Pad",
                    "body": "Caller loads type hash into R10; callee checks ENDBR64 + subl $hash, %r10d",
                    "theme": "white",
                    "in_edge": "indirect call",
                },
                {
                    "tag": "Deterministic Trap",
                    "title": "#CP (Missing ENDBR64) or ud2 CFI Panic",
                    "body": "Restricts indirect targets strictly to valid functions matching exact C signature",
                    "theme": "white",
                    "in_edge": "mismatch traps",
                },
            ],
        },
        right={
            "label": "Backward-Edge (Shadow Stack)",
            "theme": "purple",
            "cards": [
                {
                    "tag": "Exploit Primitive",
                    "title": "Kernel Stack Buffer Overflow / Stack Pivot",
                    "body": "Overwrites saved return address on data stack or pivots RSP into heap",
                    "theme": "white",
                },
                {
                    "tag": "Hardware Shadow Stack",
                    "title": "Intel CET Supervisor Shadow Stack / ARM64 PAC",
                    "body": "CPU pushes protected copy of RIP onto non-writable shadow-stack PTEs (or signs LR)",
                    "theme": "white",
                    "in_edge": "call / ret",
                },
                {
                    "tag": "Deterministic Trap",
                    "title": "#CP Control-Protection Fault on Return Mismatch",
                    "body": "Hardware compares data-stack RIP against shadow-stack RIP before retiring ret",
                    "theme": "white",
                    "in_edge": "tamper traps",
                },
            ],
        },
        bridges=[
            (0, 0, "both", "SMEP + SMAP / PAN", "slate"),
            (2, 2, "both", "seals call & return", "green"),
        ],
        boundary_label="Control-Flow Direction",
        footer="Pairing FineIBT/KCFI on indirect calls with CET/PAC on returns forces attackers toward pure data-only corruption.",
    )

    # Ch 6 Diagram 2
    build_fan_bands(
        P("06-slab-hardening-rust-boundary.svg"),
        "Defending Kernel Heap Lifecycles: SLAB_VIRTUAL Isolation and Rust Safe Abstractions",
        [
            [
                {
                    "id": "uaf",
                    "tag": "Dominant C Kernel Vulnerability Class",
                    "title": "Use-After-Free (UAF) & Cross-Cache Page Reuse (cred / msg_msg / pipe_buffer)",
                    "body": "Dangling pointer in Subsystem A overlaps freed slab page reallocated to attacker-controlled object in Subsystem B",
                    "theme": "red",
                }
            ],
            [
                {
                    "id": "rand_km",
                    "tag": "Allocator Partitioning",
                    "title": "RANDOM_KMALLOC_CACHES",
                    "body": "Splits generic kmalloc into 16 hash-selected pools per callsite",
                    "theme": "teal",
                },
                {
                    "id": "slab_virt",
                    "tag": "Virtual Address Quarantine",
                    "title": "SLAB_VIRTUAL",
                    "body": "Never reuses virtual slab addresses across distinct object caches",
                    "theme": "purple",
                },
                {
                    "id": "rust_drv",
                    "tag": "Compile-Time Prevention",
                    "title": "Rust-for-Linux Drivers",
                    "body": "Ownership, lifetimes, Arc<T>, and Send/Sync forbid UAF and data races in safe code",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "c_subsys",
                    "tag": "Explicit Unsafe Invariant Boundary",
                    "title": "Thin Subsystem Maintainer Crates (kernel::sync, drm, binder, block) Encapsulate Raw C Pointers",
                    "body": "Hundred-line unsafe FFI wrappers audited once enable thousands of lines of safe, memory-checked driver logic",
                    "theme": "slate",
                }
            ],
        ],
        [
            ("uaf", "rand_km", "probabilistic split", "teal", False),
            ("uaf", "slab_virt", "deterministic VA pin", "purple", False),
            ("uaf", "rust_drv", "eliminates in safe code", "green", False),
            ("rand_km", "c_subsys", "hardens C core", "slate", False),
            ("slab_virt", "c_subsys", "blocks cross-cache", "slate", False),
            ("rust_drv", "c_subsys", "enforces FFI contract", "green", False),
        ],
        footer="Allocator mitigations contain C memory bugs after they trigger; Rust driver abstractions remove entire lifecycle bug classes at compile time.",
    )

    # Ch 7 Diagram 1
    build_matrix(
        P("07-lsm-hook-stacking-matrix.svg"),
        "Stacked Linux Security Modules: Architectural Comparison Across Four Dimensions",
        "All active LSMs execute sequentially via call_int_hook(); any single negative return (-EACCES/-EPERM) vetoes the operation",
        [
            ("Subject & Object Model", "How policy names entities"),
            ("Policy Authoring", "Who may load new rules"),
            ("Rename / Hardlink Invariant", "Behavior when paths change"),
            ("Container & Sandbox Fit", "Primary deployment niche"),
        ],
        [
            ("SELinux", "Label-Based MAC + MCS"),
            ("AppArmor", "Pathname + Profile MAC"),
            ("Landlock (ABI v1-v7)", "Unprivileged Self-Sandbox"),
        ],
        [
            [("security.selinux xattrs", "teal"), ("VFS dentry path strings", "slate"), ("Pinned inode/fd hierarchies", "green")],
            [("Privileged CAP_MAC_ADMIN", "amber"), ("Privileged CAP_MAC_ADMIN", "amber"), ("Any unprivileged thread", "green")],
            [("Label moves with inode", "green"), ("Re-evaluated by new path", "amber"), ("Follows fd-anchored dir tree", "green")],
            [("RHEL / Fedora / Android sVirt", "teal"), ("Ubuntu / SUSE / userns gate", "slate"), ("App self-confinement & AI CLI", "purple")],
        ],
        "Stacking rule (lsm=landlock,lockdown,yama,ipe,selinux/apparmor,bpf): Access is granted iff DAC AND every stacked LSM return 0.",
        footer="LSM stacking lets unprivileged Landlock sandboxes compose cleanly inside system-wide SELinux or AppArmor confinement.",
    )

    # Ch 7 Diagram 2
    build_vertical_flow(
        P("07-landlock-abi-self-sandbox.svg"),
        "Unprivileged Process Self-Confinement with Landlock (ABI v1 Through v7)",
        [
            {
                "tag": "Step 1 · Irreversible Privilege Ceiling",
                "title": "prctl(PR_SET_NO_NEW_PRIVS, 1)",
                "body": "Guarantees execve() can never gain SUID/SGID or file capabilities to confuse restricted helper binaries",
                "theme": "slate",
            },
            {
                "tag": "Step 2 · Handled Access Mask",
                "title": "landlock_create_ruleset(attr, size, 0) -> ruleset_fd",
                "body": "Declares handled FS actions (v1-v3), TCP bind/connect (v4), device ioctl (v5), IPC abstract/signal scope (v6), audit flags (v7)",
                "theme": "teal",
                "edge_label": "no root needed",
            },
            {
                "tag": "Step 3 · Explicit Allowlist Rules",
                "title": "landlock_add_rule(ruleset_fd, PATH_BENEATH | NET_PORT, ...)",
                "body": "Grants read-only /usr, read-write ./workspace fd, and outbound TCP 443; everything unhandled-or-omitted defaults to deny",
                "theme": "purple",
                "edge_label": "populate fd/port rules",
            },
            {
                "tag": "Step 4 · Monotonic Domain Commit",
                "title": "landlock_restrict_self(ruleset_fd, 0)",
                "body": "Attaches immutable merged ruleset tree (up to 16 stacked layers) to current task cred and all future children",
                "theme": "green",
                "edge_label": "irreversible commit",
            },
        ],
        footer="Because Landlock requires zero privileges and composes up to 16 nested domains, any application can sandbox itself before parsing untrusted input.",
    )

    # Ch 8 Diagram 1
    build_fan_bands(
        P("08-ebpf-lsm-vs-ringbuf-auditd.svg"),
        "Runtime Security Architectures: Synchronous LSM-BPF vs. Async Ring Buffers vs. auditd",
        [
            [
                {
                    "id": "syscall_ev",
                    "tag": "Kernel Execution Path",
                    "title": "System Call / VFS / Socket / Credential Event Inside Ring 0",
                    "body": "Task invokes execve(), openat2(), connect(), or bpf() on CPU core",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "auditd",
                    "tag": "Legacy Netlink Queue",
                    "title": "Linux Audit (auditd)",
                    "body": "Serializes text records over multicast netlink; bursts overflow audit_backlog_limit",
                    "theme": "amber",
                },
                {
                    "id": "ringbuf",
                    "tag": "Async Telemetry (Falco / Tracee)",
                    "title": "Tracepoint / kprobe + BPF Ringbuf",
                    "body": "Streams events to user daemon; fast, but SIGKILL arrives after syscall already ran",
                    "theme": "teal",
                },
                {
                    "id": "lsm_bpf",
                    "tag": "Inline Gate (Tetragon / KRSI)",
                    "title": "LSM-BPF Synchronous Hook",
                    "body": "Runs at security_* hook on pinned kernel structs; returns -EPERM or sends SIGKILL inline",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "verdict",
                    "tag": "Security Guarantee Comparison",
                    "title": "Only Inline LSM-BPF Prevents Single-Syscall Exfiltration or Exploit Execution Before Completion",
                    "body": "Asynchronous ring buffers excel at high-throughput forensics but lose the race against one-shot destructive syscalls",
                    "theme": "purple",
                }
            ],
        ],
        [
            ("syscall_ev", "auditd", "netlink skb", "amber", True),
            ("syscall_ev", "ringbuf", "async sample", "teal", False),
            ("syscall_ev", "lsm_bpf", "inline call", "green", False),
            ("auditd", "verdict", "drops under load", "amber", True),
            ("ringbuf", "verdict", "post-facto kill", "teal", False),
            ("lsm_bpf", "verdict", "atomic block", "green", False),
        ],
        footer="LSM-BPF unites the programmability of eBPF with the race-free object mediation of native Linux Security Modules.",
    )

    # Ch 8 Diagram 2
    build_vertical_flow(
        P("08-ebpf-verifier-bounds-escape.svg"),
        "Anatomy of an eBPF Verifier Escape (CVE-2020-8835 / CVE-2021-3490 / CVE-2023-2163)",
        [
            {
                "tag": "Stage 1 · Bytecode Load",
                "title": "bpf(BPF_PROG_LOAD) Submits Crafted Instruction Graph",
                "body": "Attacker reaches bpf() via CAP_BPF, unprivileged BPF (when enabled), or leaked privileges",
                "theme": "slate",
            },
            {
                "tag": "Stage 2 · Abstract Interpretation Bug",
                "title": "Verifier Bounds / Pruning State Diverges from CPU Reality",
                "body": "Flawed ALU32 tnum tracking or register-parent pruning convinces verifier R6 == 0 while runtime R6 == 1",
                "theme": "amber",
                "edge_label": "soundness bug",
            },
            {
                "tag": "Stage 3 · Dead-Code / Scale Exploitation",
                "title": "JIT Compiles Native Machine Code Without Runtime Bounds Checks",
                "body": "Program multiplies fake-zero register R6 by large offset and adds to BPF map value pointer",
                "theme": "red",
                "edge_label": "JIT emits x86_64/ARM64",
            },
            {
                "tag": "Stage 4 · Arbitrary Ring 0 Read/Write",
                "title": "Out-of-Bounds Map Pointer Leaks KASLR & Overwrites task->cred",
                "body": "Patches BPF map ops (btf_parse / map_push_elem) to gain arbitrary kernel R/W and zero uid/euid",
                "theme": "red",
                "edge_label": "escapes sandbox",
            },
        ],
        side_notes={
            0: {
                "tag": "Hardening Default",
                "title": "unprivileged_bpf_disabled=2",
                "body": "Blocks unprivileged BPF_PROG_LOAD across modern Linux fleets",
                "theme": "green",
                "edge_label": "blocks unpriv entry",
            },
        },
        footer="Because JIT-compiled eBPF runs natively inside Ring 0 without software fault isolation, verifier soundness is equivalent to kernel memory safety.",
    )


def generate_part3():
    # Ch 9 Diagram 1
    build_vertical_flow(
        P("09-capability-execve-algebra.svg"),
        "POSIX Capability Transformation Across execve() and Ambient Inheritance",
        [
            {
                "tag": "Pre-execve Task State",
                "title": "Caller Credential Vectors: CapInh (pI), CapPrm (pP), CapEff (pE), CapBnd (pB), CapAmb (pA)",
                "body": "Invariant enforced at all times: CapAmb is a subset of (CapPrm intersect CapInh); CapBnd masks file capabilities",
                "theme": "slate",
            },
            {
                "tag": "Filesystem xattr Input",
                "title": "security.capability Extended Attribute on Binary (fI, fP, fE)",
                "body": "Optional VFS V3 capability xattr (capable of rootid namespace scoping); cleared automatically on any file write",
                "theme": "teal",
                "edge_label": "bprm_caps_from_vfs_caps()",
            },
            {
                "tag": "Kernel execve() Transition Equations",
                "title": "pP' = (pI & fI) | (fP & CapBnd) | pA'   and   pE' = fE ? pP' : pA'",
                "body": "Executing any SUID/SGID or file-cap binary zeroes CapAmb (pA' = 0) so ambient privileges cannot hijack privileged binaries",
                "theme": "purple",
                "edge_label": "cap_bprm_creds_for_exec()",
            },
            {
                "tag": "False Privilege-Separation Trap",
                "title": "Root-Equivalent Capabilities Collapse Back to Full UID 0",
                "body": "CAP_SYS_ADMIN (mount), CAP_DAC_OVERRIDE (write /etc/shadow), CAP_SYS_MODULE (insmod), CAP_SYS_PTRACE, and CAP_BPF",
                "theme": "red",
                "edge_label": "escalation equivalences",
            },
        ],
        footer="Capabilities partition root only when paired with strict bounding sets, NoNewPrivileges, and exclusion of root-equivalent bits.",
    )

    # Ch 9 Diagram 2
    build_vertical_flow(
        P("09-userns-kernel-exploit-chain.svg"),
        "Unprivileged User Namespaces: How CLONE_NEWUSER Amplifies Dormant Kernel Bugs",
        [
            {
                "tag": "Step 1 · Unprivileged Entry",
                "title": "unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)",
                "body": "Regular UID 1000 process maps itself to UID 0 inside a fresh user_namespace without host privileges",
                "theme": "slate",
            },
            {
                "tag": "Step 2 · Namespace-Scoped Capability",
                "title": "ns_capable(net->user_ns, CAP_NET_ADMIN) Returns True",
                "body": "Grants access to complex kernel subsystems unreachable by normal UID 1000 (nf_tables, traffic control, OverlayFS)",
                "theme": "amber",
                "edge_label": "unlocks attack surface",
            },
            {
                "tag": "Step 3 · Ring 0 Memory Bug",
                "title": "Trigger Subsystem Flaw (nf_tables CVE-2024-1086 / OverlayFS CVE-2023-0386)",
                "body": "Namespaces isolate logical views, NOT the shared Ring 0 slab heap or physical page allocator",
                "theme": "red",
                "edge_label": "corrupts shared Ring 0",
            },
            {
                "tag": "Step 4 · Host Root Compromise",
                "title": "Overwrite init_user_ns Credential / Page-Cache Binary",
                "body": "Escapes user_namespace immediately to full host Ring 0 and init_ns UID 0",
                "theme": "red",
                "edge_label": "host takeover",
            },
        ],
        side_notes={
            0: {
                "tag": "Ubuntu 24.04+ Defense",
                "title": "AppArmor userns Gate",
                "body": "apparmor_restrict_unprivileged_userns=1 denies CLONE_NEWUSER unless profile permits userns",
                "theme": "green",
                "edge_label": "gates unshare()",
            },
        },
        footer="Over 60% of real-world Linux kernel LPEs (including kCTF entries) rely on CLONE_NEWUSER to reach privileged subsystem code paths.",
    )

    # Ch 10 Diagram 1
    build_fan_bands(
        P("10-suid-inherited-context-hazards.svg"),
        "Why SUID-Root Is Architecturally Broken: Inheriting Untrusted Process State Across execve()",
        [
            [
                {
                    "id": "caller",
                    "tag": "Unprivileged Attacker Process (UID 1000)",
                    "title": "Crafts Hostile Execution Context Before Calling execve('/usr/bin/sudo' or '/usr/bin/pkexec')",
                    "body": "Kernel elevates euid = 0 inside the SAME process tree, inheriting almost every attribute from the untrusted parent",
                    "theme": "red",
                }
            ],
            [
                {
                    "id": "h_argv",
                    "tag": "Inherited Vector 1",
                    "title": "argv[] & envp[]",
                    "body": "argc=0 OOB (PwnKit CVE-2021-4034), heap backslash (CVE-2021-3156), GLIBC_TUNABLES (CVE-2023-4911)",
                    "theme": "amber",
                },
                {
                    "id": "h_fs",
                    "tag": "Inherited Vector 2",
                    "title": "chroot, cwd & rlimits",
                    "body": "sudo -R chroot loads attacker nsswitch.conf shared object as root (CVE-2025-32463)",
                    "theme": "amber",
                },
                {
                    "id": "h_pty",
                    "tag": "Inherited Vector 3",
                    "title": "Open FDs, cgroups & PTY",
                    "body": "Shared controlling TTY permits TIOCSTI keystroke pushback when root drops to user",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "root_exec",
                    "tag": "Systemic Failure",
                    "title": "Dynamic Linker (ld.so) & Privileged C Parsers Run as UID 0 Inside Attacker-Shaped Environment",
                    "body": "Denylisting dangerous env vars in AT_SECURE plays perpetual catch-up against every new libc, NSS, and PAM feature",
                    "theme": "slate",
                }
            ],
        ],
        [
            ("caller", "h_argv", "passes strings", "red", False),
            ("caller", "h_fs", "shapes VFS/limits", "red", False),
            ("caller", "h_pty", "retains tty fd", "red", False),
            ("h_argv", "root_exec", "parsed as root", "amber", False),
            ("h_fs", "root_exec", "dlopen NSS", "amber", False),
            ("h_pty", "root_exec", "tty injection", "amber", False),
        ],
        footer="Elevating privilege inside an untrusted parent's execution context violates clean-room security boundaries.",
    )

    # Ch 10 Diagram 2
    build_sequence(
        P("10-systemd-run0-clean-broker.svg"),
        "SUID-Free Privilege Elevation with systemd run0 and --empower",
        [
            {"title": "run0 Client", "sub": "Unprivileged UID 1000 (No SUID)", "theme": "slate"},
            {"title": "Polkit Daemon", "sub": "Out-of-Band Auth Agent", "theme": "purple"},
            {"title": "systemd (PID 1)", "sub": "Clean-Room Service Manager", "theme": "teal"},
            {"title": "Transient Service", "sub": "Isolated PTY & Fresh Creds", "theme": "green"},
        ],
        [
            (0, 2, "Varlink / D-Bus StartTransientUnit request (zero env inheritance)", "slate", False),
            (2, 1, "Verify caller pidfd & request interactive Polkit authorization", "purple", False),
            (1, 2, "User authenticates on isolated Polkit agent -> Auth OK", "purple", False),
            (2, 3, "Fork clean child from PID 1 (fresh env, fresh cgroup, fresh mount ns)", "teal", False),
            (2, 3, "Allocate dedicated pseudo-terminal (PTY) & tint background", "teal", False),
            (3, 3, "Optional --empower: keep non-root UID + Ambient Capabilities only", "green", False),
            (0, 3, "Proxy pure byte I/O streams over IPC (no shared TTY fd)", "green", True),
        ],
        footer="Because PID 1 spawns the target from pristine state rather than mutating the caller, SUID environment/chroot attacks vanish.",
    )

    # Ch 11 Diagram 1
    build_vertical_flow(
        P("11-systemd-unit-sandbox-layers.svg"),
        "Defense-in-Depth Service Confinement in systemd.exec(5)",
        [
            {
                "tag": "Layer 1 · Ephemeral Identity",
                "title": "DynamicUser=yes + User=/Group= + CapabilityBoundingSet=",
                "body": "Allocates transient UID from 61184..65519 for unit lifetime; revokes SUID creation via NoNewPrivileges=yes",
                "theme": "slate",
            },
            {
                "tag": "Layer 2 · VFS Mount Namespace",
                "title": "ProtectSystem=strict + ProtectHome=yes + PrivateTmp=yes + PrivateDevices=yes",
                "body": "Mounts entire OS tree read-only inside private CLONE_NEWNS, hides /home, and replaces /dev with safe pseudo-devices",
                "theme": "teal",
                "edge_label": "per-service mount table",
            },
            {
                "tag": "Layer 3 · Kernel Attack-Surface Locks",
                "title": "ProtectKernelTunables=yes + ProtectKernelModules=yes + RestrictNamespaces=yes",
                "body": "Locks /proc/sys and /sys read-only, denies module loading, and blocks CLONE_NEWUSER exploitation",
                "theme": "purple",
                "edge_label": "blocks Ring 0 pivots",
            },
            {
                "tag": "Layer 4 · Syscall & Network Filter",
                "title": "SystemCallFilter=@system-service + SystemCallArchitectures=native + RestrictAddressFamilies=",
                "body": "Installs seccomp-BPF allowlist, blocks 32-bit IA32 compat syscalls, and confines socket families (AF_UNIX / AF_INET)",
                "theme": "green",
                "edge_label": "seccomp + socket gate",
            },
        ],
        footer="Declarative systemd unit directives turn every daemon into a bespoke mini-container audited via 'systemd-analyze security'.",
    )

    # Ch 11 Diagram 2
    build_split_domains(
        P("11-dbus-pidfd-vs-pid-toctou.svg"),
        "IPC Peer Authentication: Legacy Numeric PID TOCTOU vs. Kernel-Pinned pidfd",
        left={
            "label": "Legacy Numeric PID Lookup",
            "theme": "red",
            "cards": [
                {
                    "tag": "Step 1 · Bus Message",
                    "title": "Client Sends D-Bus Call & Disconnects Rapidly",
                    "body": "Unprivileged client triggers CreateUser() then kills/execs before UID lookup finishes",
                    "theme": "white",
                },
                {
                    "tag": "Step 2 · Stale PID Query",
                    "title": "Daemon Queries /proc/<pid>/status by Numeric PID",
                    "body": "PID disappears or wraps; sloppy error handler defaults missing UID to 0 (root)!",
                    "theme": "white",
                    "in_edge": "races /proc/<pid>",
                },
                {
                    "tag": "Step 3 · Broken Authorization",
                    "title": "Polkit Grants Root Action Without Password",
                    "body": "Time-of-check identity differs from time-of-connection socket peer",
                    "theme": "white",
                    "in_edge": "false UID == 0",
                },
            ],
        },
        right={
            "label": "Pinned SO_PEERCRED + pidfd",
            "theme": "green",
            "cards": [
                {
                    "tag": "Step 1 · Connect Time",
                    "title": "Kernel Captures Immutable struct cred on connect()",
                    "body": "AF_UNIX socket records exact peer uid, gid, LSM label, and struct pid reference",
                    "theme": "white",
                },
                {
                    "tag": "Step 2 · Unforgeable Handle",
                    "title": "getsockopt(SO_PEERPIDFD) / SCM_PIDFD (Varlink & D-Bus)",
                    "body": "Returns file descriptor pinned to exact kernel task struct; immune to PID wrap/exit",
                    "theme": "white",
                    "in_edge": "kernel-pinned fd",
                },
                {
                    "tag": "Step 3 · Sound Mediation",
                    "title": "Broker Verifies Pinned Creds Across Entire Request",
                    "body": "Process exit invalidates pidfd cleanly (-ESRCH) instead of aliasing a new process",
                    "theme": "white",
                    "in_edge": "zero TOCTOU",
                },
            ],
        },
        bridges=[
            (1, 1, "lr", "replaces int pid with pidfd", "teal"),
            (2, 2, "lr", "eliminates PID-reuse race", "green"),
        ],
        boundary_label="IPC Identity Primitive",
        footer="Numeric PIDs are ephemeral names subject to wraparound; pidfds and SO_PEERCRED bind authorization to immutable kernel objects.",
    )

    # Ch 12 Diagram 1
    build_fan_bands(
        P("12-kernel-keyring-scopes.svg"),
        "Linux Kernel Keyring Scopes, Possession Semantics, and Secret Isolation",
        [
            [
                {
                    "id": "kr_root",
                    "tag": "Non-Swappable Ring 0 Key Retention (add_key / keyctl)",
                    "title": "32-Bit Permission Mask Split Across Possessor [P] | User [U] | Group [G] | Other [O] (View, Read, Write, Search, Link, Setattr)",
                    "body": "Possession requires a live search path from the calling thread's active @t, @p, or @s keyrings",
                    "theme": "slate",
                }
            ],
            [
                {"id": "k_th", "tag": "@t · Thread", "title": "Thread Keyring", "body": "Cleared on thread exit or execve", "theme": "white"},
                {"id": "k_pr", "tag": "@p · Process", "title": "Process Keyring", "body": "Shared by POSIX threads; cleared on execve", "theme": "teal"},
                {"id": "k_se", "tag": "@s · Session", "title": "Session Keyring", "body": "Inherited across fork/exec inside login/unit", "theme": "purple"},
                {"id": "k_us", "tag": "@u · User", "title": "User Keyring", "body": "Shared by ALL processes of same UID!", "theme": "amber"},
            ],
            [
                {
                    "id": "k_warn",
                    "tag": "Key Isolation Invariant",
                    "title": "Store Service Secrets in Per-Unit @s Session Keyrings or Trusted/Encrypted Keys (Never Ambient @u User Keyrings)",
                    "body": "Trusted keys wrap payloads inside TPM 2.0 so raw key material never persists unencrypted on disk",
                    "theme": "green",
                }
            ],
        ],
        [
            ("kr_root", "k_th", "narrowest", "slate", False),
            ("kr_root", "k_pr", "thread-group", "teal", False),
            ("kr_root", "k_se", "session tree", "purple", False),
            ("kr_root", "k_us", "UID-wide risk", "amber", False),
            ("k_se", "k_warn", "recommended scope", "purple", False),
            ("k_us", "k_warn", "ambient exposure", "amber", True),
        ],
        footer="Possessor permissions prevent another process running under the same UID from reading secrets outside its session tree.",
    )

    # Ch 12 Diagram 2
    build_horizontal_pipeline(
        P("12-systemd-creds-tpm2-flow.svg"),
        "Zero-Plaintext-/etc Secret Custody with systemd-creds and TPM 2.0",
        [
            {
                "tag": "Provisioning",
                "title": "systemd-creds encrypt",
                "body": "Seals secret with AES-256-GCM bound to TPM2 PCRs + host key",
                "theme": "purple",
            },
            {
                "tag": "At Rest on Disk",
                "title": "Encrypted Cred Store",
                "body": "Opaque .cred blob in /etc safe on world-readable backups",
                "theme": "slate",
            },
            {
                "tag": "Service Start",
                "title": "PID 1 Credential Load",
                "body": "Unseals via TPM2 only when matching unit starts",
                "theme": "teal",
            },
            {
                "tag": "In-Memory Delivery",
                "title": "Isolated ramfs Mount",
                "body": "Exposed at /run/credentials/ (0400, non-swappable RAM)",
                "theme": "green",
            },
        ],
        footer="Unlike environment variables (leaked in /proc/<pid>/environ and crash dumps), ramfs credentials never swap to disk or leak to sibling units.",
    )

    # Ch 13 Diagram 1
    build_sequence(
        P("13-openssh-certs-fido2-handshake.svg"),
        "Fleet SSH Authentication: Short-Lived Certificates + FIDO2 Resident Keys",
        [
            {"title": "FIDO2 Token", "sub": "Hardware Key (UV + Touch)", "theme": "purple"},
            {"title": "Engineer Client", "sub": "ssh-keygen / OIDC Client", "theme": "slate"},
            {"title": "SSH CA + IdP", "sub": "OIDC + Cert Authority", "theme": "teal"},
            {"title": "Linux Host sshd", "sub": "TrustedUserCAKeys Only", "theme": "green"},
        ],
        [
            (1, 2, "Authenticate via OIDC + WebAuthn MFA & send sk-ssh-ed25519 pubkey", "teal", False),
            (2, 1, "Issue short-lived User Cert (TTL = 8h, principals, source-address)", "teal", False),
            (1, 3, "Connect & verify sshd Host Cert against @cert-authority (no TOFU)", "green", False),
            (3, 1, "Send session-bound challenge H over SSHv2 transport", "slate", False),
            (1, 0, "CTAP2 GetAssertion(app='ssh:', H, user-presence + PIN)", "purple", False),
            (0, 1, "Hardware Ed25519 signature + presence/UV counter flags", "purple", False),
            (1, 3, "Present User Cert + FIDO2 signature -> PAM/SSSD session open", "green", False),
        ],
        footer="Eliminates static ~/.ssh/authorized_keys sprawl, TOFU MITM prompts, and key theft (private key never leaves FIDO2 silicon).",
    )

    # Ch 13 Diagram 2
    build_split_domains(
        P("13-regresshion-privsep-split.svg"),
        "OpenSSH Pre-Auth Attack Surface: regreSSHion (CVE-2024-6387) and 9.8 Binary Split",
        left={
            "label": "Pre-9.8 Monolithic sshd",
            "theme": "red",
            "cards": [
                {
                    "tag": "Network Timer",
                    "title": "LoginGraceTime Expires -> SIGALRM Delivered",
                    "body": "Unauthenticated client stalls handshake while grooming glibc malloc heap",
                    "theme": "white",
                },
                {
                    "tag": "Signal Handler Bug",
                    "title": "grace_alarm_handler() Calls Async-Unsafe syslog()",
                    "body": "Interrupts mid-flight malloc()/free() inside root-privileged listener child",
                    "theme": "white",
                    "in_edge": "re-enters glibc heap",
                },
                {
                    "tag": "Catastrophic Impact",
                    "title": "Pre-Auth Root RCE Outside Privsep Sandbox",
                    "body": "Corrupts FILE / heap structures in privileged monitor before chroot/seccomp",
                    "theme": "white",
                    "in_edge": "overwrites fn ptr",
                },
            ],
        },
        right={
            "label": "OpenSSH 9.8+ Split Binary",
            "theme": "green",
            "cards": [
                {
                    "tag": "Signal Safety",
                    "title": "Pure Async-Signal-Safe Handler (_exit Only)",
                    "body": "Removes syslog() heap allocations from SIGALRM path completely",
                    "theme": "white",
                },
                {
                    "tag": "Process Isolation",
                    "title": "Separate sshd Listener vs. sshd-session Binary",
                    "body": "Fresh execve('sshd-session') re-randomizes ASLR per connection!",
                    "theme": "white",
                    "in_edge": "defeats fork() ASLR clone",
                },
                {
                    "tag": "Network Gate",
                    "title": "PerSourcePenalties + Strict Privsep Sandbox",
                    "body": "Throttles repeated pre-auth crashes (~10,000 tries needed to win glibc race)",
                    "theme": "white",
                    "in_edge": "blocks brute race",
                },
            ],
        },
        bridges=[
            (1, 0, "lr", "strips unsafe syslog()", "teal"),
            (2, 1, "lr", "per-conn ASLR execve", "green"),
        ],
        boundary_label="Daemon Privilege Architecture",
        footer="Forking network workers without execve() clones parent ASLR layouts across thousands of exploit attempts; OpenSSH 9.8 splits binaries to restore ASLR.",
    )


def generate_part4_and_finale():
    # Ch 14 Diagram 1
    build_fan_bands(
        P("14-oci-container-primitives.svg"),
        "Anatomy of a Shared-Kernel OCI Container: Illusion of Isolation Above One Ring 0",
        [
            [
                {
                    "id": "ctr_proc",
                    "tag": "Containerized Workload Process",
                    "title": "Normal Linux task_struct Bound to Namespace Proxies, cgroup_subsys_state, and seccomp Filter",
                    "body": "There is no 'container' object in Linux; isolation is an emergent composition of five orthogonal mechanisms",
                    "theme": "slate",
                }
            ],
            [
                {"id": "p_ns", "tag": "Visibility", "title": "8 Namespaces", "body": "mnt, pid, net, ipc, uts, user, cgroup, time", "theme": "teal"},
                {"id": "p_fs", "tag": "Root Tree", "title": "pivot_root(2)", "body": "Swaps OverlayFS rootfs & unmounts host /", "theme": "teal"},
                {"id": "p_cg", "tag": "Quotas", "title": "cgroups v2", "body": "Unified CPU, memory.max, pids.max & BPF dev", "theme": "purple"},
                {"id": "p_sc", "tag": "Syscalls", "title": "Caps + seccomp", "body": "Drops CAP_SYS_ADMIN & blocks ~44 syscalls", "theme": "green"},
            ],
            [
                {
                    "id": "shared_k",
                    "tag": "Shared Single Point of Failure",
                    "title": "Host Linux Kernel (~300+ Reachable Syscalls, VFS, Netfilter, Slab Heap, and Hardware Drivers)",
                    "body": "--privileged, host Docker socket mounts, or any Ring 0 memory bug collapses all container boundaries instantly",
                    "theme": "red",
                }
            ],
        ],
        [
            ("ctr_proc", "p_ns", None, "teal", False),
            ("ctr_proc", "p_fs", None, "teal", False),
            ("ctr_proc", "p_cg", None, "purple", False),
            ("ctr_proc", "p_sc", None, "green", False),
            ("p_ns", "shared_k", "same Ring 0", "red", False),
            ("p_fs", "shared_k", "same VFS", "red", False),
            ("p_cg", "shared_k", "same allocator", "red", False),
            ("p_sc", "shared_k", "300+ syscalls open", "red", False),
        ],
        footer="Namespaces hide host resources from view; only seccomp, LSMs, and capabilities reduce the reachable host Ring 0 code.",
    )

    # Ch 14 Diagram 2
    build_split_domains(
        P("14-runc-fd-escape-mechanics.svg"),
        "Runtime Boundary Leaks: runc /proc/self/exe (CVE-2019-5736) & Leaky Vessels (CVE-2024-21626)",
        left={
            "label": "Host-to-Container FD Leak",
            "theme": "red",
            "cards": [
                {
                    "tag": "CVE-2019-5736",
                    "title": "Container Symlinks Entrypoint to /proc/self/exe",
                    "body": "runc enters container namespaces while backed by host /usr/bin/runc inode",
                    "theme": "white",
                },
                {
                    "tag": "CVE-2024-21626",
                    "title": "Leaked Host /sys/fs/cgroup Dir FD + WORKDIR /proc/self/fd/7",
                    "body": "Missing O_CLOEXEC lets container chdir() onto host filesystem handle before exec",
                    "theme": "white",
                    "in_edge": "crosses mount ns",
                },
                {
                    "tag": "Host Root Takeover",
                    "title": "Overwrite Host runc Binary or Traverse ../.. to Host /etc",
                    "body": "Compromises entire Kubernetes worker node on next docker exec / pod start",
                    "theme": "white",
                    "in_edge": "writes host fs",
                },
            ],
        },
        right={
            "label": "Sealed memfd & openat2()",
            "theme": "green",
            "cards": [
                {
                    "tag": "Sealed Binary Clone",
                    "title": "memfd_create() + F_ADD_SEALS (F_SEAL_WRITE)",
                    "body": "runc re-executes from sealed anonymous RAM copy disconnected from host disk",
                    "theme": "white",
                },
                {
                    "tag": "FD Hygiene",
                    "title": "close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) + Verify cwd",
                    "body": "Atomically marks all internal runtime descriptors O_CLOEXEC and checks /proc/self/cwd",
                    "theme": "white",
                    "in_edge": "purges host fds",
                },
                {
                    "tag": "Confinement Syscall",
                    "title": "openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)",
                    "body": "Kernel blocks /proc/self/fd magic-link escapes and symlink breakouts atomically",
                    "theme": "white",
                    "in_edge": "VFS-enforced root",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "seals /proc/self/exe", "teal"),
            (1, 1, "lr", "closes leaked fds", "green"),
            (2, 2, "lr", "blocks magiclinks", "green"),
        ],
        boundary_label="Container Runtime Seam",
        footer="Every moment a host runtime process executes inside container namespaces is a bidirectional cross-domain hazard.",
    )

    # Ch 15 Diagram 1
    build_matrix(
        P("15-shared-kernel-vs-gvisor-microvm.svg"),
        "Container Isolation Spectrum: Shared Kernel vs. User-Space Kernel vs. KVM Micro-VM",
        "Trading thin syscall passthrough for dedicated syscall emulation or hardware Second-Level Address Translation (EPT/Stage-2)",
        [
            ("Primary Isolation Boundary", "What stops Ring 0 escape"),
            ("Host Syscall Exposure", "Reachable host kernel surface"),
            ("Memory & Boot Overhead", "Per-sandbox density cost"),
            ("Kernel-Module / GPU Compat", "Workload compatibility trade-off"),
        ],
        [
            ("runc / crun", "Shared Host Kernel"),
            ("gVisor (runsc)", "Go Sentry + Gofer"),
            ("Firecracker / Kata", "KVM Hardware Micro-VM"),
        ],
        [
            [("Namespaces + seccomp-BPF", "amber"), ("Go Sentry + systrap", "teal"), ("VT-x/SVM + EPT/Stage-2", "green")],
            [("~300+ host syscalls", "red"), ("~53 filtered syscalls", "green"), ("KVM + ~35 VMM syscalls", "green")],
            [("< 2 MiB / ~15 ms", "green"), ("~15-25 MiB / ~50 ms", "teal"), ("~5-30 MiB / ~125 ms", "teal")],
            [("Native host ABI", "amber"), ("Emulated Linux ABI", "amber"), ("Dedicated guest kernel", "green")],
        ],
        "Defense-in-depth rule: Untrusted multi-tenant code and autonomous AI sandboxes require gVisor or KVM micro-VM boundaries.",
        footer="Both gVisor and Firecracker wrap their host-facing monitor processes inside strict seccomp jails so even VMM bugs stay contained.",
    )

    # Ch 15 Diagram 2
    build_vertical_flow(
        P("15-firecracker-kata-datapath.svg"),
        "KVM Micro-VM Container Architecture (Kata Containers / Firecracker / libkrun)",
        [
            {
                "tag": "Guest Ring 3 (Isolated VM)",
                "title": "OCI Container Process + kata-agent Inside Dedicated Guest",
                "body": "Managed via AF_VSOCK RPC from containerd-shim-kata-v2; untrusted code never issues host syscalls",
                "theme": "slate",
            },
            {
                "tag": "Guest Ring 0 (Minimal Linux Kernel)",
                "title": "Stripped Guest Kernel Driving virtio-net, virtio-blk, and virtio-fs",
                "body": "A guest kernel zero-day compromises ONLY this single pod's ephemeral VM, not sibling pods",
                "theme": "teal",
                "edge_label": "guest syscalls",
            },
            {
                "tag": "Hardware Virtualization Barrier",
                "title": "CPU VMX Non-Root / EPT Second-Level Page Tables",
                "body": "Hardware traps privileged instructions and confines DMA/GPA strictly to guest-allocated RAM",
                "theme": "purple",
                "edge_label": "VMExit / virtqueue",
            },
            {
                "tag": "Host Jailer & Rust VMM",
                "title": "Firecracker / Cloud Hypervisor + virtiofsd in chroot + seccomp + cgroups",
                "body": "Minimal ~50k-LOC Rust device model omits legacy BIOS, PCI, USB, and QEMU device-emulation bloat",
                "theme": "green",
                "edge_label": "jailed host VMM",
            },
        ],
        footer="Replacing million-line legacy VMMs with jailed Rust micro-VMMs pairs hardware EPT isolation with container-speed startup.",
    )

    # Ch 16 Diagram 1
    build_split_domains(
        P("16-imdsv1-ssrf-vs-imdsv2.svg"),
        "Cloud Instance Metadata SSRF (169.254.169.254): IMDSv1 Collapse vs. IMDSv2 Defense",
        left={
            "label": "IMDSv1 (Plain GET)",
            "theme": "red",
            "cards": [
                {
                    "tag": "Web App Flaw",
                    "title": "Simple SSRF or Reverse Proxy",
                    "body": "Attacker supplies URL 169.254.169.254 /latest/meta-data/iam/",
                    "theme": "white",
                },
                {
                    "tag": "Zero Session Proof",
                    "title": "Single HTTP GET Returns Node IAM Credentials",
                    "body": "Forwarded packets from containers (TTL > 1) also reach host link-local endpoint",
                    "theme": "white",
                    "in_edge": "plain GET",
                },
                {
                    "tag": "Cloud Pivot",
                    "title": "Stolen STS Role Exfiltrates S3 / Cloud Control Plane",
                    "body": "Every pod on worker node inherits broad node-level IAM permissions",
                    "theme": "white",
                    "in_edge": "node token theft",
                },
            ],
        },
        right={
            "label": "IMDSv2 + Pod OIDC JWT",
            "theme": "green",
            "cards": [
                {
                    "tag": "Session Preflight",
                    "title": "Requires HTTP PUT + Token TTL Header",
                    "body": "Classic GET-only SSRF and open redirects cannot forge custom PUT headers",
                    "theme": "white",
                },
                {
                    "tag": "Network Hop Gate",
                    "title": "Default IP Hop-Limit = 1 Drops Routed Pod Packets",
                    "body": "NAT/bridge decrements TTL to 0 before IMDSv2 token response reaches container",
                    "theme": "white",
                    "in_edge": "TTL=1 bound",
                },
                {
                    "tag": "Least-Privilege Pod Identity",
                    "title": "Bound K8s OIDC JWT (1h TTL, Audience-Scoped)",
                    "body": "Pod exchanges projected TokenRequest JWT via STS WebIdentity API",
                    "theme": "white",
                    "in_edge": "blocks 169.254/16",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "mandates PUT token", "teal"),
            (1, 1, "lr", "enforces IP TTL=1 + netpol", "green"),
            (2, 2, "lr", "per-pod OIDC JWT", "green"),
        ],
        boundary_label="Metadata & Identity Architecture",
        footer="Hardened Kubernetes nodes block pod egress to 169.254.169.254 entirely and project per-pod short-lived OIDC tokens.",
    )

    # Ch 16 Diagram 2
    build_sequence(
        P("16-spiffe-spire-attestation.svg"),
        "Zero-Secret Workload mTLS Bootstrapping with SPIFFE and SPIRE",
        [
            {"title": "Linux Workload", "sub": "No Static Keys on Disk", "theme": "slate"},
            {"title": "SPIRE Agent", "sub": "Host UNIX Domain Socket", "theme": "teal"},
            {"title": "Linux Kernel & Kubelet", "sub": "SO_PEERCRED + cgroup + Pod", "theme": "purple"},
            {"title": "SPIRE Server", "sub": "Trust Domain CA", "theme": "green"},
        ],
        [
            (1, 3, "Node Attestation (TPM 2.0 DevID / Quote or Cloud IID)", "purple", False),
            (3, 1, "Issue Agent SVID & authorized registration entries for this node", "green", False),
            (0, 1, "Connect to agent.sock UNIX socket (FetchX509SVID)", "slate", False),
            (1, 2, "Inspect caller SO_PEERCRED/pidfd, binary hash, cgroup v2 & Pod UID", "purple", False),
            (2, 1, "Return verified kernel/orchestrator selectors", "purple", False),
            (1, 3, "Request CSR signature for spiffe://prod/ns/pay/sa/api", "teal", False),
            (1, 0, "Stream short-lived X.509-SVID + Trust Bundle (auto-rotated in RAM)", "green", False),
        ],
        footer="SPIRE solves the 'bottom turtle' problem by deriving cryptographic workload identity from hardware node attestation + kernel peer inspection.",
    )

    # Ch 17 Diagram 1
    build_fan_bands(
        P("17-ai-agent-xpia-threat-surface.svg"),
        "Threat Anatomy of Autonomous AI Coding Agents and MCP Servers on Linux",
        [
            [
                {
                    "id": "xpia",
                    "tag": "Untrusted Context Ingestion (Indirect Prompt Injection / XPIA)",
                    "title": "Agent Reads Poisoned PR Diff, Issue Comment, Web Page, Package README, or Malicious MCP Tool Schema",
                    "body": "LLM conflates untrusted data tokens with operator instructions inside a single context window",
                    "theme": "red",
                }
            ],
            [
                {
                    "id": "v_git",
                    "tag": "Persistence Seam",
                    "title": "Mutable Repo Hooks & Configs",
                    "body": "Writes .git/hooks/pre-commit, .git/config fsmonitor, .bashrc, or .mcp.json",
                    "theme": "amber",
                },
                {
                    "id": "v_env",
                    "tag": "Ambient Secret Theft",
                    "title": "Process Env & ~/.ssh / ~/.aws",
                    "body": "Reads ANTHROPIC_API_KEY, GITHUB_TOKEN, or SSH agent socket directly",
                    "theme": "amber",
                },
                {
                    "id": "v_net",
                    "tag": "Covert Exfiltration",
                    "title": "Unrestricted Egress & DNS",
                    "body": "Exfiltrates source code and tokens via curl, DNS labels, or image URLs",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "impact",
                    "tag": "Deterministic Security Principle",
                    "title": "Prompt Guardrails Are Probabilistic; Isolation Must Be Enforced by the Linux Kernel and Network Boundary Below the Agent",
                    "body": "Treat the LLM-driven shell and every third-party MCP server as untrusted code execution under adversarial control",
                    "theme": "slate",
                }
            ],
        ],
        [
            ("xpia", "v_git", "tool write", "red", False),
            ("xpia", "v_env", "bash read", "red", False),
            ("xpia", "v_net", "outbound req", "red", False),
            ("v_git", "impact", "host escape on git status", "amber", False),
            ("v_env", "impact", "raw token theft", "amber", False),
            ("v_net", "impact", "data loss", "amber", False),
        ],
        footer="Even if an agent never hits a kernel exploit, running unsandboxed in a developer home directory exposes every credential and dotfile.",
    )

    # Ch 17 Diagram 2
    build_horizontal_pipeline(
        P("17-agent-sandbox-cred-proxy.svg"),
        "Zero-Key AI Agent Sandbox: Landlock / Micro-VM + Credential-Injecting Proxy",
        [
            {
                "tag": "Compute Boundary",
                "title": "Agent Sandbox",
                "body": "Local Landlock + bwrap (RO .git/hooks) or cloud Firecracker VM",
                "theme": "slate",
            },
            {
                "tag": "Egress Firewall",
                "title": "Isolated NetNS / vsock",
                "body": "Default-deny outbound IP & DNS; routes only to host proxy",
                "theme": "teal",
            },
            {
                "tag": "Host Broker",
                "title": "Credential Proxy",
                "body": "Enforces domain/method policy & injects real Bearer token outside VM",
                "theme": "purple",
            },
            {
                "tag": "External API",
                "title": "GitHub / LLM / Registry",
                "body": "Receives authenticated TLS call; agent never saw raw secret",
                "theme": "green",
            },
        ],
        footer="Withholding raw credentials from the sandbox environment neutralizes prompt-injected key theft even under arbitrary guest RCE.",
    )

    # Ch 18 Diagram 1
    build_vertical_flow(
        P("18-sev-snp-tdx-coconut-svsm.svg"),
        "Confidential Linux VM Architecture with AMD SEV-SNP / Intel TDX and COCONUT-SVSM",
        [
            {
                "tag": "VMPL1 / TD Guest Ring 0 & 3",
                "title": "Confidential Linux Guest + Encrypted UKI & LUKS2/dm-verity Root",
                "body": "Measures boot into vTPM and establishes SPDM encrypted PCIe session with NVIDIA H100/B200 Confidential GPU",
                "theme": "green",
            },
            {
                "tag": "VMPL0 / Enclave Paravisor (Most Privileged Guest Ring)",
                "title": "COCONUT-SVSM (Open-Source Memory-Safe Rust Service Module)",
                "body": "Isolated from guest kernel via VMPL0 RMP permissions; hosts measured TPM 2.0 emulator (vTPM) and UEFI services",
                "theme": "purple",
                "edge_label": "SVSM_CALL protocol",
            },
            {
                "tag": "Silicon Trusted Execution Root",
                "title": "AMD Secure Processor + RMP   /   Intel TDX SEAM Module + MKTME",
                "body": "AES-XTS per-VM memory encryption + Reverse Map Table / TDMR prevents host hypervisor from reading, remapping, or replaying guest pages",
                "theme": "teal",
                "edge_label": "hardware page ownership",
            },
            {
                "tag": "Untrusted Host Hypervisor (Removed from TCB)",
                "title": "Cloud Provider KVM / QEMU Manages Scheduling and Encrypted Swap Only",
                "body": "Host root reading guest DRAM sees ciphertext; tampering with guest GPA mappings triggers immediate #PF / RMP fault",
                "theme": "amber",
                "dashed": True,
                "edge_label": "ciphertext + SWIOTLB bounce",
            },
        ],
        footer="COCONUT-SVSM gives Linux guests a hardware-measured vTPM inside encrypted memory without trusting the cloud host hypervisor.",
    )

    # Ch 18 Diagram 2
    build_split_domains(
        P("18-untrusted-vmm-vc-ve-surface.svg"),
        "Defending Linux Guests Against a Malicious Hypervisor (#VC / #VE & Device Filtering)",
        left={
            "label": "Malicious Host VMM Traps",
            "theme": "red",
            "cards": [
                {
                    "tag": "Exception Forgery",
                    "title": "Unsolicited #VC / #VE Trap Injection (WeSee)",
                    "body": "Host injects fake VMM Communication exception at arbitrary guest RIP to trick #VC handler",
                    "theme": "white",
                },
                {
                    "tag": "CPUID / MSR Lies",
                    "title": "Spoofed CPU Topology, RNG, or Clock Drift",
                    "body": "Hypervisor returns crafted register values on intercepted RDMSR / CPUID / MMIO reads",
                    "theme": "white",
                    "in_edge": "host-controlled regs",
                },
                {
                    "tag": "Driver Fuzzing",
                    "title": "Rogue Hotplugged PCI / ACPI / Virtio Devices",
                    "body": "Untrusted VMM enumerates buggy legacy Linux drivers via forged PCI IDs to corrupt guest Ring 0",
                    "theme": "white",
                    "in_edge": "corrupts SWIOTLB",
                },
            ],
        },
        right={
            "label": "Hardened Linux Guest (coco)",
            "theme": "green",
            "cards": [
                {
                    "tag": "Instruction Inspection",
                    "title": "Verify Faulting Guest RIP Before Handling #VC/#VE",
                    "body": "Handler decodes instruction at RIP and panics if trap did not come from genuine exit opcode",
                    "theme": "white",
                },
                {
                    "tag": "Hardware Tables",
                    "title": "SEV-SNP CPUID Page + Restricted MSR Allowlist",
                    "body": "PSP validates CPUID table at launch; guest blocks unexpected hypervisor MSR emulation",
                    "theme": "white",
                    "in_edge": "firmware-attested",
                },
                {
                    "tag": "Driver Allowlist",
                    "title": "Confidential Device Filter",
                    "body": "AUTHORIZED_DEFAULT=0 blocks legacy PCI/USB drivers not hardened for untrusted DMA",
                    "theme": "white",
                    "in_edge": "strict bounce copy",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "blocks WeSee trap", "teal"),
            (1, 1, "lr", "pins CPUID & MSRs", "green"),
            (2, 2, "lr", "denies untrusted drivers", "green"),
        ],
        boundary_label="Host VMM / Guest Kernel Seam",
        footer="Confidential computing flips the 30-year Linux assumption that hardware buses, ACPI tables, and hypervisors are benevolent.",
    )

    # Ch 19 Diagram 1
    build_sequence(
        P("19-coco-kata-trustee-flow.svg"),
        "Confidential Containers (CoCo): Enclave-Per-Pod Boot and Trustee Attestation",
        [
            {"title": "Untrusted Worker", "sub": "Kubelet + Kata Shim", "theme": "amber"},
            {"title": "Pod CVM Enclave", "sub": "Kata Agent + CDH + AA", "theme": "teal"},
            {"title": "Hardware TEE", "sub": "SEV-SNP / TDX Silicon", "theme": "purple"},
            {"title": "Trustee (KBS)", "sub": "Remote Verifier & Key Vault", "theme": "green"},
        ],
        [
            (0, 1, "Launch encrypted Kata VM with measured UKI + signed Initdata digest", "amber", False),
            (1, 3, "Attestation Agent (AA) requests RATS challenge over HTTPS", "teal", False),
            (3, 1, "Return fresh cryptographic nonce", "green", False),
            (1, 2, "Request hardware quote binding launch measurement + Initdata + nonce", "purple", False),
            (2, 1, "Return VCEK/PCK-signed SEV-SNP Report / TDX Quote", "purple", False),
            (1, 3, "Submit TEE Evidence; Trustee evaluates Reference Values + OPA policy", "teal", False),
            (3, 1, "Release wrapped OCI layer decryption key to Confidential Data Hub (CDH)", "green", False),
        ],
        boundary_after=0,
        boundary_label="Untrusted Host / Encrypted Pod TEE",
        footer="Container images are pulled and decrypted ONLY inside guest TEE memory; host Kubelet cannot inspect layers, env vars, or exec shells.",
    )

    # Ch 19 Diagram 2
    build_horizontal_pipeline(
        P("19-sealed-ai-inference-pipeline.svg"),
        "Sealing Proprietary AI Weights and Prompts with Confidential Containers + GPUs",
        [
            {
                "tag": "Encrypted Artifact",
                "title": "ocicrypt Model Image",
                "body": "AES-256-GCM encrypted weights stored in standard registry",
                "theme": "slate",
            },
            {
                "tag": "Joint Attestation",
                "title": "CVM + GPU SPDM Quote",
                "body": "Attests both CPU TEE (SEV-SNP/TDX) and H100/B200 CC-On state",
                "theme": "purple",
            },
            {
                "tag": "Key Release",
                "title": "Trustee KBS Unwrap",
                "body": "Releases weight key into enclave RAM; decrypts over encrypted PCIe",
                "theme": "teal",
            },
            {
                "tag": "Confidential Serving",
                "title": "Attested TLS Endpoint",
                "body": "Client verifies RA-TLS quote before sending private prompts",
                "theme": "green",
            },
        ],
        footer="Neither the cloud provider nor the Kubernetes cluster administrator ever gains plaintext access to model weights or user prompts.",
    )

    # Ch 20 Diagram 1
    build_vertical_flow(
        P("20-xz-backdoor-kill-chain.svg"),
        "Forensic Anatomy of the XZ Utils Backdoor (CVE-2024-3094): Subverting the Chain Upstream",
        [
            {
                "tag": "Stage 1 · Social Engineering & Tarball Split (2021-2024)",
                "title": "Attacker 'Jia Tan' Injects Modified m4/build-to-host.m4 Into Release Tarballs Only",
                "body": "Absent from public git tree; invisible to git commit review while ingested by Debian/Fedora/RPM tarball packaging",
                "theme": "amber",
            },
            {
                "tag": "Stage 2 · Obfuscated Build-Time Extraction",
                "title": "configure Script Carves Encrypted Payload Out of Binary Test Files",
                "body": "Extracts stage from bad-3-corrupt_lzma2.xz into liblzma crc64_fast.o on x86_64 glibc builds",
                "theme": "red",
                "edge_label": "mutates Makefile",
            },
            {
                "tag": "Stage 3 · Transitive Shared-Library Linkage",
                "title": "Distro Patches Link OpenSSH sshd -> libsystemd.so (sd_notify) -> liblzma.so.5",
                "body": "Distro build farm signs the contaminated binary package cleanly; Secure Boot, UKI, dm-verity, and SELinux all see valid vendor signatures!",
                "theme": "purple",
                "edge_label": "signed by distro CA",
            },
            {
                "tag": "Stage 4 · Dynamic Linker Hijack & Pre-Auth RCE",
                "title": "glibc GNU_IFUNC Resolver Redirects RSA_public_decrypt GOT Entry Inside sshd",
                "body": "Inspects SSH public-key certificate modulus for Ed448-signed payload; executes system() as root prior to authentication without logging",
                "theme": "red",
                "edge_label": "ld.so symbol hook",
            },
        ],
        side_notes={
            2: {
                "tag": "Architectural Fix",
                "title": "systemd On-Demand dlopen()",
                "body": "libsystemd drops hard ELF DT_NEEDED linkage on liblzma/libzstd so sshd never maps compression libs at startup",
                "theme": "green",
                "edge_label": "severs linkage",
            },
        },
        footer="Runtime verification only proves a binary matches what the vendor signed; XZ Utils attacked the trust seam BEFORE vendor signing.",
    )

    # Ch 20 Diagram 2
    build_horizontal_pipeline(
        P("20-slsa-sigstore-reproducible-pipeline.svg"),
        "Closing the Source-to-Binary Gap: Git Tree, SLSA Hermetic Builds, Reproducibility, and Sigstore",
        [
            {
                "tag": "Source Integrity",
                "title": "Signed Git Tag (No Tarballs)",
                "body": "Build directly from immutable git tree hash without pre-generated autotools blobs",
                "theme": "slate",
            },
            {
                "tag": "SLSA Build L3",
                "title": "Isolated Hermetic Builder",
                "body": "Ephemeral network-offline build emits signed in-toto SLSA provenance",
                "theme": "teal",
            },
            {
                "tag": "Independent Check",
                "title": "Reproducible Rebuild",
                "body": "Second builder with SOURCE_DATE_EPOCH verifies identical SHA-256 output",
                "theme": "purple",
            },
            {
                "tag": "Transparency Log",
                "title": "Sigstore Fulcio + Rekor",
                "body": "Short-lived OIDC cert + append-only Merkle log verified before OS install",
                "theme": "green",
            },
        ],
        footer="Eliminating bespoke release tarballs and requiring reproducible, Rekor-logged builds makes stealth build-script injection publicly detectable.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    generate_opening()
    generate_part1()
    generate_part2_and_interlude()
    generate_part3()
    generate_part4_and_finale()
    svgs = sorted(f for f in os.listdir(DIAG_DIR) if f.endswith(".svg"))
    print(f"Generated and verified {len(svgs)} SVG diagrams in {DIAG_DIR}")


if __name__ == "__main__":
    main()

