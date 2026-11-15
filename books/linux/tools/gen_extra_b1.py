#!/usr/bin/env python3
"""Extra Batch 1 diagram generator for The Linux Trust Chain (Volume III).

Generates 5 collision- and orthogonality-verified architectural SVG diagrams
(01-extra-*.svg through 05-extra-*.svg) into books/linux/src/diagrams/,
bringing Chapters 1 through 5 to 3 SVG figures each.
"""
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


def generate_extra_b1():
    # 1. Chapter 1 third SVG: 01-extra-grub-verifier-surface.svg
    build_split_domains(
        P("01-extra-grub-verifier-surface.svg"),
        "Pre-Verifier Parser Attack Surface vs. GRUB2 grub_file_verifier Gates",
        left={
            "label": "Pre-Verifier Untrusted Parsers",
            "theme": "red",
            "cards": [
                {
                    "tag": "Network & Firmware Stage",
                    "title": "UEFI DXE HiiImage & shim httpboot.c",
                    "body": "Parses boot logos (LogoFAIL) and chunked HTTP headers (CVE-2023-40547) before verify_buffer()",
                    "theme": "white",
                },
                {
                    "tag": "Config & CLI Lexer",
                    "title": "grub.cfg Script & Option Parsers",
                    "body": "Unauthenticated grub.cfg tokens trigger yyparse/option heap overflows (CVE-2020-10713, CVE-2021-20225)",
                    "theme": "white",
                    "in_edge": "loads ESP config",
                },
                {
                    "tag": "Graphical Theme Decoders",
                    "title": "PF2 Font & PNG/JPEG Asset Renderers",
                    "body": "Crafted glyph dimensions overflow grub_malloc in Ring 0 DXE mode (CVE-2022-2601, CVE-2022-3775)",
                    "theme": "white",
                    "in_edge": "loads boot theme",
                },
            ],
        },
        right={
            "label": "Hardened Verifier & UKI Posture",
            "theme": "green",
            "cards": [
                {
                    "tag": "First-Stage Hardening",
                    "title": "shim 15.8+ NX Memory Attributes & SbatLevel",
                    "body": "Enforces EFI_MEMORY_ATTRIBUTE_PROTOCOL W^X sections and rejects revoked SBAT generations",
                    "theme": "white",
                },
                {
                    "tag": "grub-core/kern/verifiers.c",
                    "title": "Monolithic grubx64.efi + grub_file_verifiers",
                    "body": "Forbids dynamic insmod, iorw/memrw, and ACPI overrides; routes kernel reads to shim_lock->Verify()",
                    "theme": "white",
                    "in_edge": "locks commands",
                },
                {
                    "tag": "Structural Parser Removal",
                    "title": "Direct shim / systemd-boot -> Signed UKI",
                    "body": "Eliminates script interpreters, font decoders, and custom FS drivers from pre-OS Ring 0 entirely",
                    "theme": "white",
                    "in_edge": "replaces GRUB2",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "bounds + W^X", "teal"),
            (1, 1, "lr", "verifies payloads", "slate"),
            (2, 2, "lr", "deletes parser TCB", "green"),
        ],
        boundary_label="Pre-OS TCB Boundary",
        footer="Every parser running in UEFI Boot Services before signature verification inherits adversarial ESP or network bytes at Ring 0.",
    )

    # 2. Chapter 2 third SVG: 02-extra-pcr11-boot-phases.svg
    build_vertical_flow(
        P("02-extra-pcr11-boot-phases.svg"),
        "Monotonic TPM 2.0 PCR[11] Boot-Phase Clock and Secret Unseal Windows",
        [
            {
                "tag": "Phase 0 · UEFI Pre-Kernel (systemd-stub)",
                "title": "Canonical UKI PE Section Sweep (.cmdline .. .uname)",
                "body": "Extends section names and SHA-256 digests into PCR[11]; measures UKI Addons into PCR[12]",
                "theme": "slate",
            },
            {
                "tag": "Phase 1 · Early RAM Rootfs (enter-initrd)",
                "title": "systemd-pcrphase-initrd Extends 'enter-initrd'",
                "body": "Active PCR[11] matches signed .pcrsig policy for LUKS2 root volume key unsealing",
                "theme": "green",
                "edge_label": "extend 'enter-initrd'",
                "edge_color": "#2b6a4c",
            },
            {
                "tag": "Phase 2 · Pre-Pivot Barrier (leave-initrd)",
                "title": "systemd-pcrphase-initrd Extends 'leave-initrd'",
                "body": "One-way SHA-256 extend permanently invalidates enter-initrd policy before switch-root",
                "theme": "amber",
                "edge_label": "extend 'leave-initrd'",
                "edge_color": "#b07926",
            },
            {
                "tag": "Phase 3 · Host Initialization (sysinit)",
                "title": "systemd-pcrphase-sysinit Extends 'sysinit'",
                "body": "Local filesystems mounted (PCR[15] bound); systemd-creds unseals host service credentials",
                "theme": "teal",
                "edge_label": "extend 'sysinit'",
            },
            {
                "tag": "Phase 4 · Multi-User & Teardown (ready -> shutdown -> final)",
                "title": "systemd-pcrphase Extends 'ready', 'shutdown', and 'final'",
                "body": "Unprivileged logins and network workloads start only after early boot keys are unreachable",
                "theme": "slate",
                "edge_label": "extend 'ready'",
            },
        ],
        side_notes={
            1: {
                "tag": "LUKS2 Unseal Window",
                "title": "Root Disk Master Key",
                "body": "Unsealed via encrypted HMAC session; wiped from RAM after dm-crypt table load",
                "theme": "green",
                "dashed": False,
                "edge_label": "TPM2_Unseal OK",
                "edge_color": "#2b6a4c",
            },
            2: {
                "tag": "Cryptographic Seal-Off",
                "title": "Post-Pivot UID 0 Blocked",
                "body": "Compromised runtime root cannot replay enter-initrd PCR[11] state without reboot",
                "theme": "red",
                "edge_label": "unseal denied",
                "edge_color": "#8d2d3b",
            },
        },
        footer="Treating PCR[11] as an irreversible state-machine clock isolates early disk decryption keys from post-pivot runtime compromise.",
    )

    # 3. Chapter 3 third SVG: 03-extra-dps-repart-boot-layout.svg
    build_fan_bands(
        P("03-extra-dps-repart-boot-layout.svg"),
        "UAPI Discoverable Partitions (DPS) and systemd-repart Cryptographic Disk Binding",
        [
            [
                {
                    "id": "esp",
                    "tag": "FAT32 EFI System Partition (Untrusted Storage, Cryptographically Signed Payloads)",
                    "title": "UKI /EFI/Linux/os-v2.efi (.cmdline: usrhash=H_hi||H_lo) + LoaderDevicePartUUID",
                    "body": "systemd-stub pins 256-bit dm-verity root digest and exports backing NVMe ESP origin via Boot Loader Interface",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "usr_d",
                    "tag": "GPT Type 8484680c.. (x86-64 /usr)",
                    "title": "_usr_b Read-Only EROFS",
                    "body": "PartUUID = first 128 bits of usrhash (H_hi); discovered without /etc/fstab",
                    "theme": "teal",
                },
                {
                    "id": "usr_v",
                    "tag": "GPT Type 77ff5f63.. (/usr-verity)",
                    "title": "_verity_b Merkle Tree",
                    "body": "PartUUID = last 128 bits of usrhash (H_lo) + optional FEC Reed-Solomon blocks",
                    "theme": "green",
                },
                {
                    "id": "var_rw",
                    "tag": "GPT Type 4d21b016.. (/var)",
                    "title": "systemd-repart LUKS2 + AEAD",
                    "body": "Created on first boot from machine-id seed; TPM2 keyslot + dm-integrity tags",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "vfs",
                    "tag": "Assembled Runtime Root Hierarchy (systemd-gpt-auto-generator + PCR[15])",
                    "title": "Immutable dm-verity /usr + Signed systemd-sysext OverlayFS + Noexec Authenticated /var",
                    "body": "Prevents partition-swap attacks across A/B slots and binds mounted volume identity into TPM 2.0 PCR[15]",
                    "theme": "green",
                }
            ],
        ],
        [
            ("esp", "usr_d", "matches H_hi", "teal", False),
            ("esp", "usr_v", "matches H_lo", "green", False),
            ("esp", "var_rw", "repart.d policy", "amber", False),
            ("usr_d", "vfs", "verified pages", "teal", False),
            ("usr_v", "vfs", "root_hash check", "green", False),
            ("var_rw", "vfs", "PCR[15] extend", "amber", False),
        ],
        footer="Encoding the 256-bit Merkle usrhash directly into paired GPT Partition UUIDs eliminates mutable /etc/fstab lookup spoofing.",
    )

    # 4. Chapter 4 third SVG: 04-extra-evm-inode-hmac-binding.svg
    build_fan_bands(
        P("04-extra-evm-inode-hmac-binding.svg"),
        "Extended Verification Module (EVM) Inode Metadata and Xattr HMAC Binding",
        [
            [
                {
                    "id": "ima_x",
                    "tag": "Content Digest / Sig",
                    "title": "security.ima",
                    "body": "RSA/ECDSA file sig or fs-verity digest",
                    "theme": "slate",
                },
                {
                    "id": "mac_x",
                    "tag": "MAC Security Label",
                    "title": "security.selinux / SMACK64",
                    "body": "Mandatory domain & type enforcement label",
                    "theme": "teal",
                },
                {
                    "id": "cap_x",
                    "tag": "File Capabilities & ACLs",
                    "title": "security.capability",
                    "body": "Permitted/effective file capability bitmasks",
                    "theme": "amber",
                },
                {
                    "id": "misc_x",
                    "tag": "struct h_misc Inode Tuple",
                    "title": "ino, gen, uid, gid, mode, s_uuid",
                    "body": "init_user_ns ownership, SUID bits & FS UUID",
                    "theme": "purple",
                },
            ],
            [
                {
                    "id": "evm_calc",
                    "tag": "Ring 0 Metadata Authenticator (security/integrity/evm/evm_crypto.c)",
                    "title": "evm_calc_hmac_or_hash() Keyed by TPM 2.0 Sealed Kernel Master Key (evm-key)",
                    "body": "Computes HMAC-SHA256 (mutable files) or verifies EVM_XATTR_PORTABLE_DIGSIG asymmetric vendor signature",
                    "theme": "green",
                }
            ],
            [
                {
                    "id": "evm_out",
                    "tag": "Offline Tamper Verdict (evm_verifyxattr -> security.evm)",
                    "title": "Blocks Offline chmod +s SUID Escalation, Label Stripping, and Cross-Inode Xattr Transplant",
                    "body": "Any offline disk edit to uid/gid/mode or protected xattrs invalidates security.evm and returns -EACCES / -EPERM",
                    "theme": "red",
                }
            ],
        ],
        [
            ("ima_x", "evm_calc", None, "slate", False),
            ("mac_x", "evm_calc", None, "teal", False),
            ("cap_x", "evm_calc", None, "amber", False),
            ("misc_x", "evm_calc", None, "purple", False),
            ("evm_calc", "evm_out", "verifies security.evm", "green", False),
        ],
        footer="Without EVM (or a read-only dm-verity Merkle tree), security.ima authenticates file bytes while leaving chmod +s and labels exposed.",
    )

    # 5. Chapter 5 third SVG: 05-extra-lockdown-reason-lattice.svg
    build_fan_bands(
        P("05-extra-lockdown-reason-lattice.svg"),
        "Monotonic Kernel Lockdown Reason Lattice (include/linux/security.h)",
        [
            [
                {
                    "id": "lvl0",
                    "tag": "Level 0 · LOCKDOWN_NONE (Legacy Root Equivalence)",
                    "title": "Unrestricted UID 0 Access to Ring 0 Memory, Hardware Buses, and Unverified kexec",
                    "body": "Only irreversible upward transitions permitted: none -> integrity -> confidentiality (never downward until reset)",
                    "theme": "stone",
                }
            ],
            [
                {
                    "id": "int_mod",
                    "tag": "Code & Boot Gates",
                    "title": "MODULE_SIGNATURE & KEXEC",
                    "body": "Blocks unsigned .ko modules, raw kexec_load(), and unverified swsusp hibernation",
                    "theme": "teal",
                },
                {
                    "id": "int_hw",
                    "tag": "Memory & Bus Gates",
                    "title": "DEV_MEM, PCI_ACCESS, IOPORT, MSR",
                    "body": "Blocks /dev/mem, /dev/port, iopl(), raw PCI BAR DMA mmap, and WRMSR Ring 0 hooks",
                    "theme": "teal",
                },
                {
                    "id": "int_fw",
                    "tag": "Firmware & Debug Gates",
                    "title": "ACPI_TABLES, DEVICE_TREE, BPF_WRITE",
                    "body": "Blocks custom AML SSDT tables, devicetree overrides, debugfs writes, and bpf_probe_write_user",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "lvl1",
                    "tag": "Barrier 1 · LOCKDOWN_INTEGRITY_MAX (Auto-Enabled Under UEFI Secure Boot)",
                    "title": "security_locked_down(reason) Denies All Reason Codes <= LOCKDOWN_INTEGRITY_MAX With -EPERM",
                    "body": "Prevents UID 0 (even holding CAP_SYS_ADMIN and CAP_SYS_RAWIO) from modifying running Ring 0 code or state",
                    "theme": "green",
                }
            ],
            [
                {
                    "id": "conf_mem",
                    "tag": "Core Dump & Secret Gates",
                    "title": "KCORE & XFRM_SECRET",
                    "body": "Blocks /proc/kcore physical RAM alias and IPsec cryptographic key extraction",
                    "theme": "purple",
                },
                {
                    "id": "conf_trc",
                    "tag": "Instrumentation Gates",
                    "title": "KPROBES, BPF_READ_KERNEL, PERF, TRACEFS",
                    "body": "Blocks kprobes, raw bpf_probe_read_kernel(), tracefs, and perf register sampling",
                    "theme": "purple",
                },
            ],
            [
                {
                    "id": "lvl2",
                    "tag": "Barrier 2 · LOCKDOWN_CONFIDENTIALITY_MAX (Appliance & Confidential-Host Posture)",
                    "title": "security_locked_down(reason) Denies Both Integrity and Confidentiality Reason Codes",
                    "body": "Prevents UID 0 from reading dm-crypt master keys, keyring material, or guest secrets out of Ring 0 memory",
                    "theme": "red",
                }
            ],
        ],
        [
            ("lvl0", "int_mod", None, "slate", False),
            ("lvl0", "int_hw", None, "slate", False),
            ("lvl0", "int_fw", None, "amber", False),
            ("int_mod", "lvl1", "enforces integrity", "teal", False),
            ("int_hw", "lvl1", "enforces integrity", "teal", False),
            ("int_fw", "lvl1", "enforces integrity", "amber", False),
            ("lvl1", "conf_mem", None, "purple", False),
            ("lvl1", "conf_trc", None, "purple", False),
            ("conf_mem", "lvl2", "enforces confidentiality", "purple", False),
            ("conf_trc", "lvl2", "enforces confidentiality", "purple", False),
        ],
        footer="Every privileged kernel interface passes an explicit enum lockdown_reason checked monotonically against kernel_locked_down.",
    )


if __name__ == "__main__":
    os.makedirs(DIAG_DIR, exist_ok=True)
    generate_extra_b1()
    print("Generated 5 collision-verified Batch 1 extra SVG diagrams in", DIAG_DIR)
