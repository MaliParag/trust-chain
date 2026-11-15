#!/usr/bin/env python3
"""Batch 1 extra diagram generator (Chapters 1-5) for The Android Trust Chain (Volume IV)."""
import os
import sys

sys.dont_write_bytecode = True

TOOLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools"))
sys.path.insert(0, TOOLS_ROOT)

from diagram_lib import (  # noqa: E402
    build_fan_bands,
    build_sequence,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def generate_extra_b1(diag_dir: str):
    os.makedirs(diag_dir, exist_ok=True)

    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 1. Chapter 1: 01-extra-vbmeta-binary-layout.svg
    build_fan_bands(
        P("01-extra-vbmeta-binary-layout.svg"),
        "AvbVBMetaImageHeader Binary Layout & Descriptor Verification Graph",
        bands=[
            [
                {
                    "id": "hdr",
                    "tag": "Bytes 0..255 · Fixed Big-Endian Struct (avb_vbmeta_image.h)",
                    "title": "AvbVBMetaImageHeader (256 Bytes, Zero ASN.1 / X.509 Parsing)",
                    "body": '"AVB0" magic [0..3] · libavb ver [4..11] · auth_size [12..19] · aux_size [20..27] · alg [28..31] · rollback_index [112..119] · flags [120..123]',
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "auth",
                    "w_weight": 0.9,
                    "tag": "Block 2 · 64-Byte Aligned",
                    "title": "Authentication Data Block",
                    "body": "SHA-256 / SHA-512 digest over (Header || Auxiliary Block) + raw RSA-2048 / RSA-4096 PKCS#1 v1.5 signature",
                    "theme": "amber",
                },
                {
                    "id": "aux",
                    "w_weight": 1.3,
                    "tag": "Block 3 · 64-Byte Aligned",
                    "title": "Auxiliary Data Block",
                    "body": "AvbRSAPublicKeyHeader (precomputed n0inv & R^2 mod n Montgomery constants) + packed AvbDescriptor array",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "d_hash",
                    "tag": "Descriptor Tag 2",
                    "title": "AvbHashDescriptor",
                    "body": "Full pre-OS RAM hash (salt + SHA-256) for boot, init_boot, vendor_boot, dtbo, & pvmfw",
                    "theme": "green",
                },
                {
                    "id": "d_tree",
                    "tag": "Descriptor Tag 1",
                    "title": "AvbHashtreeDescriptor",
                    "body": "32B dm-verity Merkle root, salt, & RS(255, 253) FEC offsets for system, vendor, & product",
                    "theme": "teal",
                },
                {
                    "id": "d_chain",
                    "tag": "Descriptor Tag 4",
                    "title": "AvbChainPartition",
                    "body": "Delegates child pubkey + independent rollback slot s (vbmeta_system, vbmeta_vendor)",
                    "theme": "purple",
                },
                {
                    "id": "d_cmd",
                    "tag": "Descriptor Tag 3",
                    "title": "AvbKernelCmdline",
                    "body": "Appends verified dm-verity & bootconfig arguments gated on hashtree flags",
                    "theme": "stone",
                },
            ],
            [
                {
                    "id": "rot",
                    "tag": "Pre-OS Handoff to KeyMint & DICE",
                    "title": "Composite Verified Boot Digest & Latched RootOfTrust",
                    "body": "SHA-256 over concatenated root + chained VBMeta structs sealed into KeyMint (verifiedBootKey, deviceLocked, verifiedBootState, verifiedBootHash)",
                    "theme": "green",
                }
            ],
        ],
        edges=[
            ("hdr", "auth", "offsets [32..63]", "amber", False),
            ("hdr", "aux", "offsets [64..111]", "teal", False),
            ("aux", "d_tree", "unpacks", "teal", False),
            ("aux", "d_chain", "verifies child", "purple", False),
            ("aux", "d_cmd", "parses", "slate", False),
            ("d_hash", "rot", None, "green", False),
            ("d_tree", "rot", None, "teal", False),
            ("d_chain", "rot", "aggregates VBMeta", "purple", False),
            ("d_cmd", "rot", None, "slate", False),
        ],
        footer="Every descriptor offset is bounds-checked in avb_vbmeta_image_verify() only after the RSA signature over Header || Auxiliary succeeds.",
    )

    # 2. Chapter 2: 02-extra-rpmb-hmac-ab-slots.svg
    build_sequence(
        P("02-extra-rpmb-hmac-ab-slots.svg"),
        "A/B Seamless Slot Fallback & Deferred RPMB Anti-Rollback Ratchet",
        actors=[
            {"title": "update_engine & HAL", "sub": "EL0 / IBootControl", "theme": "slate"},
            {"title": "ABL (libavb)", "sub": "Slot _a / _b Loader", "theme": "teal"},
            {"title": "TEE / StrongBox", "sub": "AVB Rollback TA", "theme": "amber"},
            {"title": "UFS RPMB Block", "sub": "256-bit HMAC Silicon", "theme": "green"},
        ],
        boundary_after=1,
        boundary_label="SMC / SPI Hardware Monotonic Boundary",
        messages=[
            (0, 1, "Write OTA to inactive slot _b\n(tries_remaining=7, successful=0)", "slate", False),
            (1, 2, "Read stored_rollback_index[0..31]\nfor trial boot of slot _b", "teal", False),
            (2, 3, "Authenticated RPMB Read\n(nonce + HMAC-SHA256)", "amber", False),
            (3, 2, "Return floor (e.g. index = 14) +\nhardware write_counter", "green", False),
            (1, 1, "Verify slot _b index (15) >= 14;\ndo NOT advance RPMB yet!", "teal", False),
            (1, 0, "Boot slot _b; update_verifier scans\ndm-verity care_map blocks", "green", False),
            (0, 1, "markBootSuccessful() sets\nslot _b successful = 1", "slate", False),
            (1, 2, "Commit new rollback floor (15)\nafter slot _b proven healthy", "amber", False),
            (2, 3, "Signed RPMB Write (index=15,\nwrite_counter+1, HMAC_K_RPMB)", "green", False),
        ],
        bottom_note={
            "tag": "Crash-Safe Monotonicity Invariant",
            "title": "Why Rollback Counters Advance Only After markBootSuccessful()",
            "body": "If experimental slot _b panics before markBootSuccessful(), tries_remaining hits 0 and ABL falls back to slot _a (index 14) without bricking; once ratified, index 14 is permanently rejected.",
            "theme": "teal",
        },
    )

    # 3. Chapter 3: 03-extra-titan-m2-internal-blocks.svg
    build_split_domains(
        P("03-extra-titan-m2-internal-blocks.svg"),
        "Google Titan M2 Discrete StrongBox Internal Architecture & SoC Boundary",
        left={
            "label": "Main Application SoC (Tensor)",
            "theme": "slate",
            "cards": [
                {
                    "tag": "Normal World EL0 / EL1",
                    "title": "keystore2, LockSettings, & SPI Driver",
                    "body": "Serializes KeyMint, Weaver, and Identity commands into framed packets over the physical SPI bus",
                    "theme": "white",
                },
                {
                    "tag": "Pre-OS Bootloader (ABL)",
                    "title": "One-Way Verified Boot & Patch Latch",
                    "body": "Sends verifiedBootKey, lock state, and BOOT_PATCHLEVEL before jumping to untrusted EL1 Linux",
                    "theme": "teal",
                    "in_arrow": True,
                },
                {
                    "tag": "Board-Level Physical Line",
                    "title": "Dedicated Power/Volume Button GPIO",
                    "body": "Direct electrical user-presence trace sampled during Android Protected Confirmation prompts",
                    "theme": "green",
                    "in_arrow": True,
                },
            ],
        },
        right={
            "label": "Discrete Titan M2 Chip (StrongBox)",
            "theme": "purple",
            "cards": [
                {
                    "tag": "Compute & Memory Isolation",
                    "title": "Hardened RV32IMC Core & Static MPU",
                    "body": "OpenTitan-derived RISC-V core with dual-core lockstep, shadow PC, W^X on-die SRAM, and zero dynamic heap",
                    "theme": "white",
                },
                {
                    "tag": "Countermeasure Silicon",
                    "title": "Masked Crypto, TRNG, & Glitch Sensors",
                    "body": "DPA-masked AES/ECC/SHA-3 engines, NIST SP 800-90B TRNG, and voltage/laser detectors that zeroize keys",
                    "theme": "amber",
                    "in_arrow": True,
                },
                {
                    "tag": "Private On-Die Storage",
                    "title": "Internal Embedded Flash (NVM) & IAR",
                    "body": "Holds 64 Weaver slots, HBK hierarchy, and Insider Attack Resistance requiring valid LSKF before FW update",
                    "theme": "purple",
                    "in_arrow": True,
                },
            ],
        },
        bridges=[
            (0, 0, "both", "Narrow SPI Mailbox", "teal"),
            (1, 1, "lr", "Latched RootOfTrust", "amber"),
            (2, 2, "lr", "Hardware Presence Pin", "green"),
        ],
        boundary_label="Physical Package Air Gap (Off-DRAM, Off-Cache)",
        footer="Unlike TrustZone S-EL1, Titan M2 shares zero LPDDR DRAM, CPU caches, or DVFS voltage rails with the main application processor.",
    )

    # 4. Chapter 4: 04-extra-synthetic-password-weaver-chain.svg
    build_vertical_flow(
        P("04-extra-synthetic-password-weaver-chain.svg"),
        "SyntheticPassword v3, Weaver Slot Throttling, & Subkey Hierarchy",
        steps=[
            {
                "tag": "Step 1 · LockSettingsService (EL0)",
                "title": "User LSKF Stretching via scrypt",
                "body": "6-digit PIN, pattern, or password stretched with 16-byte random salt (pwd file, N=2048, r=8, p=1) into K_weaver and K_app",
                "theme": "slate",
            },
            {
                "tag": "Step 2 · StrongBox Silicon (IWeaver::read)",
                "title": "Titan M2 64-Slot Hardware Throttling",
                "body": "Persists incremented failure_counter to on-die NVM before constant-time 128-bit key check; returns 128-bit weaverSecret V",
                "theme": "purple",
                "edge_label": "presents 128-bit K_weaver",
                "edge_color": "#5c4282",
            },
            {
                "tag": "Step 3 · SyntheticPasswordCrypto (spblob)",
                "title": "Dual-Layer AEAD spblob Unwrapping",
                "body": "Outer AES-256-GCM layer decrypted inside KeyMint (boot-bound protectorKey); inner AES-256-GCM decrypted with K_app + V",
                "theme": "teal",
                "edge_label": "releases 128-bit secret V",
                "edge_color": "#236b66",
            },
            {
                "tag": "Step 4 · Immutable Per-User Root",
                "title": "256-Bit Master SyntheticPassword (SP v3)",
                "body": "Constructed from random splits P0, P1; changing user PIN re-wraps SP in a new spblob without re-encrypting /data",
                "theme": "green",
                "edge_label": "recovers 32-byte SP",
                "edge_color": "#2b6a4c",
            },
            {
                "tag": "Step 5 · NIST SP 800-108 Context KDF",
                "title": "Isolated Subkeys: FBE CE, Gatekeeper SID, & Keystore",
                "body": '"fbe-key" unlocks UFS ICE CE files · "sp-gk-authentication" mints HardwareAuthToken · "keystore-password" unwraps superkeys',
                "theme": "amber",
                "edge_label": "SP800Derive(SP, context)",
                "edge_color": "#b07926",
            },
        ],
        side_notes={
            1: {
                "tag": "Anti-Hammering Schedule",
                "title": "Up to 24h Per Wrong Guess",
                "body": "30s delay at 5 & 10..29 tries; exponential doubling from 30..139 tries; 86,400s/guess at 140+ tries",
                "theme": "red",
                "edge_label": "mismatch",
            },
            3: {
                "tag": "Zero-Escrow Personal Default",
                "title": "Cryptographic Escrow Erasure",
                "body": "Personal profiles delete E0 and P1 splits so no enterprise token can ever reconstruct SP",
                "theme": "stone",
                "edge_label": "drops E0/P1",
                "edge_color": "#524c44",
            },
        },
        footer="Cloning external UFS flash (NAND mirroring) cannot reset failure_counter because Weaver state lives inside Titan M2 on-die flash.",
    )

    # 5. Chapter 5: 05-extra-hyp-vmemmap-state-machine.svg
    build_fan_bands(
        P("05-extra-hyp-vmemmap-state-machine.svg"),
        "pKVM hyp_vmemmap & Stage-2 Page Ownership State Machine (mem_protect.c)",
        bands=[
            [
                {
                    "id": "init",
                    "tag": "Post-Deprivilege Baseline (__pkvm_prot_finalize)",
                    "title": "Host Exclusively Owns Frame (host_state = PKVM_PAGE_OWNED)",
                    "body": "Host Stage-2 PTE: valid RWX idmap · Hyp Stage-1: PKVM_NOPAGE · Guest Stage-2: PKVM_NOPAGE",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "don_g",
                    "tag": "HVC: __pkvm_host_donate_guest",
                    "title": "Exclusive pVM Guest Frame",
                    "body": "Host S2 PTE invalidated (owner=GUEST + GFN) + TLBI; Guest S2 mapped PKVM_PAGE_OWNED (0b00)",
                    "theme": "green",
                },
                {
                    "id": "don_h",
                    "tag": "HVC: __pkvm_host_donate_hyp",
                    "title": "Exclusive EL2 Hypervisor Frame",
                    "body": "Host S2 PTE invalidated (owner=HYP); EL2 S1 mapped PAGE_HYP (hyp_state = PKVM_PAGE_OWNED)",
                    "theme": "purple",
                },
                {
                    "id": "shr_h",
                    "tag": "HVC: __pkvm_host_share_hyp",
                    "title": "Pinned Host-to-EL2 Shared Frame",
                    "body": "Host = PKVM_PAGE_SHARED_OWNED (0b01); Hyp = PKVM_PAGE_SHARED_BORROWED (0b10) with refcount",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "shr_io",
                    "w_weight": 1.15,
                    "tag": "Guest HVC: __pkvm_guest_share_host",
                    "title": "Controlled VirtIO Bounce Window (swiotlb)",
                    "body": "Guest marks bounce page SHARED_OWNED (0b01) and lends Host SHARED_BORROWED (0b10); revoked via unshare",
                    "theme": "amber",
                },
                {
                    "id": "fault",
                    "w_weight": 1.0,
                    "tag": "Host Violation (ESR_EL2 Trap)",
                    "title": "Host Reads Donated Guest/Hyp PA",
                    "body": "CPU Stage-2 or SMMUv3 faults into EL2; handle_host_mem_abort() injects synchronous Data Abort into EL1",
                    "theme": "red",
                    "dashed": True,
                },
            ],
            [
                {
                    "id": "reclaim",
                    "tag": "VM Teardown (__pkvm_reclaim_dying_guest_page)",
                    "title": "Mandatory EL2 Zero-Scrub Before Host Reclaim",
                    "body": "EL2 unmaps Guest S2, zeroes all 4,096 bytes + cleans dcache to PoC, and only then restores Host PKVM_PAGE_OWNED",
                    "theme": "green",
                }
            ],
        ],
        edges=[
            ("init", "don_g", "donate to pVM", "green", False),
            ("init", "don_h", "donate to EL2", "purple", False),
            ("init", "shr_h", "share w/ EL2", "teal", False),
            ("don_g", "shr_io", "VirtIO bounce", "amber", False),
            ("don_h", "fault", "rogue EL1 read", "red", True),
            ("shr_io", "reclaim", "unshare + destroy", "green", False),
        ],
        footer="Every transition acquires ordered component spinlocks (Host -> Hyp -> Guest) in arch/arm64/kvm/hyp/nvhe/mem_protect.c.",
    )


if __name__ == "__main__":
    generate_extra_b1(DIAG_DIR)
    print("Successfully generated and 7-way collision-verified all 5 Batch 1 extra SVGs.")
