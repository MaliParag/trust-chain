#!/usr/bin/env python3
"""Part 1 diagram definitions for The Android Trust Chain: Prologue, Foundations, and Chapters 1-10."""
import os
from diagram_lib import (
    SvgCanvas, build_vertical_flow, build_sequence, build_split_domains,
    build_horizontal_pipeline, build_fan_bands, build_matrix, build_timeline_spine,
)


def generate_part1(diag_dir: str):
    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 1. Prologue: trust-chain-map.svg
    c = SvgCanvas(900, 580)
    y = c.add_header(
        "The 20-Chapter Android Trust Chain",
        "Hardware roots, EL2 pKVM, mandatory SELinux, and RKP attestation across a multi-vendor ecosystem"
    ) + 14.0
    main_x, main_w = 52.0, 560.0
    side_x, side_w = 656.0, 212.0

    tiers = [
        ("Finale · Chapter 20", "Multi-Vendor Chain Breaks & The Patch Gap",
         "20. Mali & Adreno GPU Drivers, Exynos/Shannon Basebands, Trustlets, & OEM OTA Lag",
         "red", "multi-vendor seam snaps"),
        ("Part IV · Chapters 15 to 19", "Remote Attestation, Enterprise, & Agentic AI",
         "15. Key Attestation & RKP · 16. Play Integrity & Keyboxes · 17. Enterprise · 18. Agentic AI · 19. E2EE & TIE",
         "amber", "attests silicon & isolates cloud/AI"),
        ("Part III · Chapters 9 to 13", "App Sandbox, Storage, & Local Identity",
         "9. UID & Binder · 10. APK Signing & Storage · 11. Accessibility & Adv. Protection · 12. FBE & USB · 13. Passkeys",
         "green", "enforces per-app & CE/DE boundaries"),
        ("Part II · Chapters 5 to 8", "De-Privileging the Kernel: pKVM, SELinux, & MTE",
         "5. pKVM & AVF · 6. SELinux neverallow & seccomp · 7. Treble, GKI, KCFI, & Rust · 8. Arm MTE & Scudo",
         "teal", "contains Ring 0 & memory bugs"),
        ("Part I · Chapters 1 to 4", "Silicon, Verified Boot, & Hardware KeyMint",
         "1. Boot ROM & AVB VBMeta · 2. Rollback, dm-verity, & APEX · 3. TrustZone vs. StrongBox · 4. KeyMint & Weaver",
         "slate", None),
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
        col = "#8d2d3b" if idx == 0 else "#146c4e"
        c.add_line(main_x + main_w / 2, lower_top, main_x + main_w / 2, upper_top + upper_h,
                   color=col, width=1.8, arrow_end=True, label=lbl, label_pos=0.44, label_color=col)

    rail_top = ys[1][0]
    rail_bot = ys[4][0] + ys[4][1]
    c.add_rect(side_x, rail_top, side_w, rail_bot - rail_top, fill="#f4f1ea",
               stroke="#524c44", stroke_width=1.3, rx=8, dash="5,3", layer="bg")
    c.add_card(side_x + 12.0, rail_top + 22.0, side_w - 24.0,
               tag="Interlude · Chapter 14",
               title="Play Protect & E2EE Intrusion Logging",
               body="No 3rd-party kernel hooks: Dynamic Signal Monitoring, SecurityLog, and E2EE cloud forensic logs",
               theme="white", align="center", title_size=11.5, body_size=10.0)
    c.add_text(side_x + side_w / 2, rail_bot - 44.0, "Tamper-evident telemetry:",
               size=9.8, fill="#524c44", bold=True, anchor="middle")
    c.add_text(side_x + side_w / 2, rail_bot - 28.0, "survives post-compromise wipe",
               size=9.8, fill="#524c44", italic=True, anchor="middle")
    for idx in (1, 2, 3, 4):
        mid = ys[idx][0] + ys[idx][1] / 2
        c.add_line(main_x + main_w, mid, side_x, mid, color="#787167", width=1.2, dash="3,3", arrow_end=True)

    c.height = cur_y + 20.0
    c.save(P("trust-chain-map.svg"))

    # 2. Foundations: 00b-arm-worlds-pkvm-topology.svg
    build_split_domains(
        P("00b-arm-worlds-pkvm-topology.svg"),
        "ARMv8/ARMv9 Exception Levels, TrustZone Secure World, & Discrete StrongBox",
        left={
            "label": "Normal World (NS=1) & pKVM",
            "theme": "slate",
            "cards": [
                {"tag": "EL0 · Userspace", "title": "Android Apps & Microdroid pVM Userland",
                 "body": "Per-app UIDs (u0_a*), SELinux domains, Scudo + MTE, and isolated AVF guest workloads",
                 "theme": "white"},
                {"tag": "EL1 · Rich OS & Guest Kernels", "title": "GKI Linux Kernel & Microdroid Kernel",
                 "body": "Binder IPC, fscrypt FBE, LSM SELinux hooks; de-privileged from pVM RAM by Stage-2 MMU",
                 "theme": "teal", "in_arrow": True},
                {"tag": "EL2 · Protected Hypervisor", "title": "pKVM (arch/arm64/kvm/hyp/nvhe)",
                 "body": "Owns Stage-2 translation tables; strips host EL1 read/write access to donated pVM frames",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "Secure World (NS=0) & Silicon",
            "theme": "amber",
            "cards": [
                {"tag": "S-EL0 · Trustlets", "title": "KeyMint TA, Gatekeeper, & DRM Trustlets",
                 "body": "Trusted applications executing over TEE syscalls inside Secure World virtual memory",
                 "theme": "white"},
                {"tag": "S-EL1 · Trusted OS", "title": "Trusty / Qualcomm QTEE / Kinibi",
                 "body": "Secure World kernel sharing SoC DRAM controller & caches (partitioned via TZASC)",
                 "theme": "amber", "in_arrow": True},
                {"tag": "Off-SoC / Isolated Die", "title": "StrongBox (Titan M2 / Knox Vault)",
                 "body": "Dedicated RISC-V/Secure CPU, private SRAM/NVM, hardware TRNG, Weaver, & glitch sensors",
                 "theme": "purple", "in_arrow": True},
            ],
        },
        bridges=[
            (1, 1, "lr", "SMC via EL3 Monitor", "amber"),
            (2, 2, "lr", "SPI / Boot Root Binding", "teal"),
        ],
        boundary_label="NS Bit & Physical Die Boundary",
        foundation={
            "tag": "EL3 Secure Monitor & SoC Hardware Root",
            "title": "ARM Trusted Firmware (BL31) + Immutable Boot ROM & OTP Fuses",
            "body": "Context-switches NS=1 <-> NS=0 on SMC traps and anchors initial DICE / Verified Boot silicon measurements",
            "theme": "stone",
            "left_label": "hosts EL2/EL1",
            "right_label": "switches S-EL1",
        },
        footer="pKVM isolates workloads horizontally in Normal World EL2 without expanding the shared S-EL1 TrustZone TCB."
    )

    # 3. Foundations: 00b-android-vs-unix-uid-stack.svg
    build_split_domains(
        P("00b-android-vs-unix-uid-stack.svg"),
        "Ambient-User Desktop POSIX vs. Android Mutual-Distrust App Architecture",
        left={
            "label": "Desktop Unix (Human-per-UID)",
            "theme": "red",
            "cards": [
                {"tag": "Shared Principal", "title": "All User Apps Run as UID 1000",
                 "body": "Game, PDF viewer, terminal, and browser share one discretionary POSIX user identity",
                 "theme": "white"},
                {"tag": "Ambient File Access", "title": "Unmediated Home-Directory Read/Write",
                 "body": "Any compromised user binary reads ~/.ssh, browser cookies, and personal documents",
                 "theme": "white", "in_arrow": True},
                {"tag": "Discretionary Root", "title": "Unrestricted UID 0 Superuser",
                 "body": "Root processes commonly mount or modify /usr and kernel modules unless extra MAC is configured",
                 "theme": "red", "in_arrow": True},
            ],
        },
        right={
            "label": "Android Model (App-per-UID)",
            "theme": "green",
            "cards": [
                {"tag": "Isolated Principal", "title": "Distinct Kernel UID per App (u0_a* / u0_i*)",
                 "body": "PackageManager assigns unique AID at install; WebView renderers run in zero-permission u0_i* UIDs",
                 "theme": "white"},
                {"tag": "Mandatory Mediation", "title": "Enforcing SELinux + Binder + Scoped Storage",
                 "body": "CTS neverallow rules, kernel Binder caller-UID stamping, and fscrypt per-profile CE/DE keys",
                 "theme": "teal", "in_arrow": True},
                {"tag": "Constrained Root", "title": "AVB 2.0 dm-verity + Domain-Split Daemons",
                 "body": "UID 0 daemons carry zero ambient capabilities where unneeded and cannot mutate verified /system blocks",
                 "theme": "green", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "inverts UID semantics", "slate"),
            (1, 1, "lr", "replaces DAC with MAC+IPC", "green"),
        ],
        boundary_label="Architectural Inversion",
        footer="On Android, Linux UID isolation separates mutually distrusting applications belonging to the same human owner."
    )

    # 4. Ch 1: 01-bootloader-lock-states.svg
    build_matrix(
        P("01-bootloader-lock-states.svg"),
        "Android Verified Boot 2.0 Bootloader Lock & Verification State Matrix",
        "How Boot ROM fuse roots, custom avb_custom_key roots, and unlock state propagate into KeyMint and UI warnings",
        row_headers=[
            ("GREEN (Locked)", "OEM / SoC OTP Root Key"),
            ("YELLOW (Locked Custom)", "User avb_custom_key Root"),
            ("ORANGE (Unlocked)", "Verification Skipped"),
            ("RED (Corrupt / Failed)", "Hash or Signature Mismatch"),
        ],
        col_headers=[
            ("Bootloader Gate", "Signature Check"),
            ("Boot Warning UI", "Pre-OS Screen"),
            ("KeyMint Boot State", "RootOfTrust Claim"),
            ("Play vs. Direct Attest", "Relying-Party Policy"),
        ],
        cells=[
            [("Enforced (OTP Key)", "green"), ("Silent Normal Boot", "green"),
             ("VERIFIED (Locked)", "green"), ("Passes STRONG + Direct", "green")],
            [("Enforced (Custom Key)", "teal"), ("Yellow Key Fingerprint", "amber"),
             ("SELF_SIGNED (Locked)", "teal"), ("Fails Play; Passes Pinning", "amber")],
            [("Bypassed (Any Image)", "amber"), ("Orange Unlock Warning", "amber"),
             ("UNVERIFIED (Unlocked)", "red"), ("Fails Hardware Integrity", "red")],
            [("Halted / No Boot", "red"), ("Red Corruption Halt", "red"),
             ("FAILED (No OS Handoff)", "red"), ("OS Never Reached", "red")],
        ],
        legend="Transitioning Locked <-> Unlocked forces a mandatory hardware-gated userdata cryptographic wipe (blocked if FRP bit = 1).",
        footer="YELLOW preserves full cryptographic AVB + dm-verity + locked bootloader guarantees for custom OSes such as GrapheneOS."
    )

    # 5. Ch 1: 01-avb-vbmeta-descriptor-chain.svg
    build_fan_bands(
        P("01-avb-vbmeta-descriptor-chain.svg"),
        "AVB 2.0 Root VBMeta Struct & Chained Partition Verification Topology",
        bands=[
            [{"id": "rom", "tag": "Immutable Silicon Root",
              "title": "SoC Boot ROM (PBL) + OTP Public-Key Digest Fuses",
              "body": "Verifies early vendor loaders (SBL / XBL / ABL) in SRAM before DRAM or fastboot runs",
              "theme": "slate"}],
            [{"id": "vbmeta", "tag": "Central Signed Anchor · AvbVBMetaImageHeader",
              "title": "vbmeta Partition (RSA-4096 Signature + rollback_index + Descriptors)",
              "body": "Single OEM signature covers header, authentication block, and auxiliary partition descriptors",
              "theme": "green"}],
            [
                {"id": "hash_boot", "tag": "AvbHashDescriptor", "title": "boot & init_boot",
                 "body": "Whole-partition SHA-256 verified into RAM before Linux entry", "theme": "teal"},
                {"id": "ht_vendor", "tag": "AvbHashtreeDescriptor", "title": "vendor & product",
                 "body": "Root digest seeds kernel dm-verity Merkle tree on block reads", "theme": "teal"},
                {"id": "chain_sys", "tag": "AvbChainPartitionDescriptor", "title": "vbmeta_system",
                 "body": "Delegates /system & system_ext to Google GSI signing key + independent rollback slot", "theme": "purple"},
            ],
            [{"id": "sys_ht", "tag": "Delegated Hashtree Verification",
              "title": "system & system_ext Read-Only EROFS / ext4 Partitions",
              "body": "Updated independently of vendor firmware while preserving end-to-end cryptographic binding to vbmeta",
              "theme": "white"}],
        ],
        edges=[
            ("rom", "vbmeta", "verifies ABL -> vbmeta RSA key", "slate", False),
            ("vbmeta", "hash_boot", "whole-image digest", "green", False),
            ("vbmeta", "ht_vendor", "Merkle root hash", "green", False),
            ("vbmeta", "chain_sys", "delegated pubkey + slot", "purple", False),
            ("chain_sys", "sys_ht", "verifies /system hashtree", "purple", False),
        ],
        footer="Chained partitions let Google update /system (Project Treble) without possessing the OEM's root vbmeta private key."
    )

    # 6. Ch 2: 02-dm-verity-merkle-fec.svg
    build_vertical_flow(
        P("02-dm-verity-merkle-fec.svg"),
        "Runtime Block Verification: dm-verity SHA-256 Merkle Tree & Reed-Solomon FEC",
        steps=[
            {"tag": "Signed Anchor", "title": "AvbHashtreeDescriptor Root Digest in Kernel RAM",
             "body": "Authenticated by bootloader from vbmeta before mounting read-only EROFS/ext4 filesystems",
             "theme": "green"},
            {"tag": "Interior Nodes", "title": "4 KiB SHA-256 Hash Blocks (Logarithmic Path)",
             "body": "Each 4 KiB hash block stores 128 child digests; cached in kernel page cache after verification",
             "theme": "slate", "edge_label": "anchors level 0"},
            {"tag": "Leaf Read", "title": "4 KiB Partition Data Block Read from UFS Flash",
             "body": "Device-mapper computes SHA-256(salt || data_block) on page-in and compares to parent node",
             "theme": "teal", "edge_label": "verifies leaf"},
            {"tag": "Mismatch Handler", "title": "Reed-Solomon FEC Parity Decode (RS(255, 253))",
             "body": "Attempts algebraic repair of random flash bit-rot and re-checks SHA-256 against Merkle parent",
             "theme": "amber", "edge_label": "if digest mismatch"},
            {"tag": "Admitted Page", "title": "Verified Plaintext Mapped Read-Only into Page Cache",
             "body": "Returned to userspace only if direct hash or FEC-repaired block matches signed Merkle digest",
             "theme": "green", "edge_label": "hash valid"},
        ],
        side_notes={
            3: {"tag": "Tamper / Uncorrectable", "title": "VERITY_MODE_RESTART or EIO",
                "body": "Malicious modification exceeds RS parity; kernel triggers reboot/RED state or returns EIO",
                "theme": "red", "edge_label": "FEC fails"},
        },
        footer="FEC heals genuine UFS NAND bit flips so Android can enforce strict reboot-on-corruption without bricking aging flash."
    )

    # 7. Ch 2: 02-apex-mainline-mount-pipeline.svg
    build_horizontal_pipeline(
        P("02-apex-mainline-mount-pipeline.svg"),
        "Project Mainline APEX Verification, Anti-Rollback, & Loopback Mount Pipeline",
        stages=[
            {"tag": "Stage 1 · Package", "title": "Staged .apex File",
             "body": "Delivered via Play system update into active data dir", "theme": "slate"},
            {"tag": "Stage 2 · Outer Sign", "title": "APK v3 Signature",
             "body": "Matches pre-installed /system module public key", "theme": "teal"},
            {"tag": "Stage 3 · Inner AVB", "title": "AvbFooter & VBMeta",
             "body": "Extracts signed descriptor & Merkle root digest", "theme": "green"},
            {"tag": "Stage 4 · Block Gate", "title": "Loopback dm-verity",
             "body": "Wraps loop device in authenticated hashtree", "theme": "teal"},
            {"tag": "Stage 5 · Active", "title": "Bind-Mount /apex",
             "body": "Exposes patched ART, DNS, or Conscrypt runtime", "theme": "green"},
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Anti-Rollback Floor",
            "title": "Module Rollback Index & Keystore Floor",
            "body": "Blocks downgrade to older vulnerable Mainline APEX revisions across reboots",
            "theme": "amber",
            "edge_label": "enforces version",
        },
        footer="Even if root or physical write alters /data/apex, dm-verity verifies every 4 KiB page of apex_payload.img at runtime."
    )

    # 8. Ch 3: 03-trustzone-vs-strongbox.svg
    build_split_domains(
        P("03-trustzone-vs-strongbox.svg"),
        "Shared-Silicon Arm TrustZone TEE vs. Discrete StrongBox Security Processor",
        left={
            "label": "Arm TrustZone TEE (On-SoC)",
            "theme": "amber",
            "cards": [
                {"tag": "Shared Silicon Substrate", "title": "Same CPU Cores, Caches, & DRAM Bus",
                 "body": "Time-sliced via EL3 SMC; relies on TZASC address-space controller to partition external DRAM",
                 "theme": "white"},
                {"tag": "Wide Trustlet TCB", "title": "DRM, Widevine, HDCP, Sensor, & Biometric TAs",
                 "body": "Dozens of vendor C trustlets run inside S-EL0/S-EL1; CVE-2015-6639 & CVE-2019-10574 broke boundary",
                 "theme": "red", "in_arrow": True},
                {"tag": "Physical Fault Profile", "title": "Exposed to Shared-Cache & Voltage Glitching",
                 "body": "Lacks dedicated laser meshes or private NVM counters; relies on eMMC/UFS RPMB over host driver",
                 "theme": "amber", "in_arrow": True},
            ],
        },
        right={
            "label": "Discrete StrongBox (Titan M2)",
            "theme": "green",
            "cards": [
                {"tag": "Physically Isolated Die", "title": "Dedicated RISC-V / Secure Microcontroller",
                 "body": "Separate CPU, private on-die SRAM & flash NVM, internal clock, and narrow SPI command bus",
                 "theme": "white"},
                {"tag": "Minimal Fixed-Function TCB", "title": "KeyMint, Weaver, Insider Attack Resistance",
                 "body": "Hosts zero multimedia or third-party trustlets; firmware updates gated by owner LSKF consent",
                 "theme": "teal", "in_arrow": True},
                {"tag": "Physical Fault Countermeasures", "title": "Laser, EM, Voltage, & Side-Channel Shields",
                 "body": "Dual-rail/masked AES & SHA hardware, instruction jitter, active mesh detectors, & internal Weaver slots",
                 "theme": "green", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "shrinks hardware TCB", "green"),
            (2, 2, "lr", "adds physical tamper defense", "teal"),
        ],
        boundary_label="On-SoC Virtual Split vs. Air-Gapped Die",
        footer="StrongBox keeps LSKF Weaver throttling and high-value KeyMint keys off the main application processor die altogether."
    )

    # 9. Ch 3: 03-protected-confirmation-flow.svg
    build_sequence(
        P("03-protected-confirmation-flow.svg"),
        "Android Protected Confirmation: Hardware-Attested WYSIWYS Transaction Approval",
        actors=[
            {"title": "Relying App", "sub": "ConfirmationPrompt", "theme": "slate"},
            {"title": "Android OS", "sub": "keystore2 / HAL", "theme": "amber"},
            {"title": "Trusted UI / StrongBox", "sub": "Isolated Framebuffer + GPIO", "theme": "green"},
            {"title": "Remote Verifier", "sub": "Medical / Banking Backend", "theme": "purple"},
        ],
        messages=[
            (0, 1, "presentPrompt(promptText, extraData)", "slate", False),
            (1, 2, "Render prompt in hardware-locked surface", "teal", False),
            (2, 2, "User presses physical Power button (hardware GPIO)", "green", False),
            (2, 1, "HMAC_ConfirmationKey('confirmation token' || prompt || extra)", "green", False),
            (0, 1, "Signature.sign() using CONFIRMATION_REQUIRED KeyMint key", "slate", False),
            (1, 2, "Verify confirmationToken HMAC inside KeyMint", "teal", False),
            (2, 0, "ECDSA signature over payload + confirmationToken", "green", False),
            (0, 3, "Submit promptText + token + signature + Key Attestation", "purple", False),
        ],
        boundary_after=1,
        boundary_label="Compromised Host Kernel Cannot Forge",
        footer="Even with Ring 0 control or Accessibility malware, an attacker cannot mint a valid signature without physical button confirmation."
    )

    # 10. Ch 4: 04-keymint-authorization-binding.svg
    build_split_domains(
        P("04-keymint-authorization-binding.svg"),
        "KeyMint Hardware-Enforced vs. Keystore2 Daemon-Enforced Authorization Tags",
        left={
            "label": "keystore2 Daemon (EL0 Rust)",
            "theme": "slate",
            "cards": [
                {"tag": "Namespace & Caller ACL", "title": "App UID Ownership & Grant SQLite DB",
                 "body": "Maps (domain, namespace, alias) -> encrypted key_blob on /data/misc/keystore2; enforces Binder UID",
                 "theme": "white"},
                {"tag": "Software-Enforced Metadata", "title": "TAG_CREATION_DATETIME & App Attestation ID",
                 "body": "Recorded in softwareEnforced AuthorizationList because StrongBox/TEE lacks untrusted wall-clock trust",
                 "theme": "slate", "in_arrow": True},
                {"tag": "Ciphertext Custody Only", "title": "Holds AES-GCM Wrapped Key Blobs",
                 "body": "Never sees raw key material; compromise of host OS allows online use of NO_AUTH keys only",
                 "theme": "amber", "in_arrow": True},
            ],
        },
        right={
            "label": "KeyMint Hardware (TEE/Titan)",
            "theme": "green",
            "cards": [
                {"tag": "Cryptographic Usage Policy", "title": "PURPOSE, ALGORITHM, DIGEST, & PADDING",
                 "body": "Baked into AEAD Associated Data (AAD) of key blob; signing key can never be invoked to decrypt",
                 "theme": "white"},
                {"tag": "User Auth & Freshness Gate", "title": "USER_SECURE_ID & AUTH_TIMEOUT",
                 "body": "Requires fresh HMAC-verified HardwareAuthToken from Gatekeeper/Weaver or Class 3 Biometric",
                 "theme": "teal", "in_arrow": True},
                {"tag": "Boot & Version Sealing", "title": "RootOfTrust + OS / VENDOR / BOOT_PATCHLEVEL",
                 "body": "Derives KEK from HBK + VerifiedBootKey + Locked state; ORANGE unlock or patch downgrade refuses unwrap",
                 "theme": "green", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "begin(keyBlob, params)", "slate"),
            (2, 1, "lr", "passes HardwareAuthToken", "teal"),
        ],
        boundary_label="Binder/SPI KeyMint HAL Boundary",
        footer="Every tag in teeEnforced is cryptographically authenticated inside the AEAD key blob and attested via X.509 OID .17."
    )

    # 11. Ch 4: 04-gatekeeper-vs-weaver.svg
    build_sequence(
        P("04-gatekeeper-vs-weaver.svg"),
        "Synthetic Password Unwrap & StrongBox Weaver Anti-Brute-Force Throttling",
        actors=[
            {"title": "LockSettingsService", "sub": "system_server (LSKF Input)", "theme": "slate"},
            {"title": "Weaver StrongBox", "sub": "Titan M2 / Knox Vault", "theme": "green"},
            {"title": "KeyMint Hardware", "sub": "TEE / StrongBox", "theme": "teal"},
            {"title": "fscrypt / Keystore2", "sub": "CE Storage & App Keys", "theme": "purple"},
        ],
        messages=[
            (0, 0, "Stretch user PIN/password via scrypt/Argon2 -> stretched_lskf", "slate", False),
            (0, 1, "weaver.read(slot_id, weaver_key derived from stretched_lskf)", "teal", False),
            (1, 1, "Enforce hardware backoff timer & increment internal NVM counter", "green", False),
            (1, 0, "Return 16-byte high-entropy weaver_secret (only on exact match)", "green", False),
            (0, 2, "Unwrap SyntheticPassword (SP) via KeyMint bound to boot state", "teal", False),
            (2, 0, "Mint HMAC-signed HardwareAuthToken (user_id, timestamp)", "green", False),
            (0, 3, "Derive CE fscrypt master key & unlock auth-bound Keystore keys", "purple", False),
        ],
        boundary_after=0,
        boundary_label="Hardware Rate-Limited Boundary",
        footer="Cloning encrypted UFS flash (NAND mirroring) gains nothing: the 128-bit Weaver secret lives inside StrongBox NVM behind strict timers."
    )

    # 12. Ch 5: 05-pkvm-stage2-deprivation.svg
    build_fan_bands(
        P("05-pkvm-stage2-deprivation.svg"),
        "Protected KVM (pKVM): De-Privileging Host Linux via EL2 Stage-2 Page Ownership",
        bands=[
            [
                {"id": "host", "tag": "Untrusted Host Domain · EL1/EL0",
                 "title": "Host Android Linux Kernel + System Services",
                 "body": "Manages scheduling, VirtIO I/O queues, and memory allocation, but is excluded from pVM confidentiality TCB",
                 "theme": "amber"},
                {"id": "pvm1", "tag": "Protected VM · Guest EL1/EL0",
                 "title": "Microdroid pVM (Isolated Compilation / ML)",
                 "body": "Verified guest kernel + APEX payload running in donated physical frames",
                 "theme": "green"},
                {"id": "pvm2", "tag": "Protected VM · Guest EL1/EL0",
                 "title": "OEM / DRM / KeyMint Security pVM",
                 "body": "Replaces legacy S-EL1 TrustZone trustlets with memory-safe isolated VMs",
                 "theme": "teal"},
            ],
            [{"id": "pkvm", "tag": "Minimal Trusted Hypervisor · EL2 (arch/arm64/kvm/hyp/nvhe)",
              "title": "pKVM Hypervisor + Physical Page Ownership Tracking Table",
              "body": "Exclusively controls Host Stage-2 & Guest Stage-2 MMU page tables; unmaps donated pVM pages from Host Stage-2",
              "theme": "slate"}],
            [{"id": "dram", "tag": "Physical Memory & DMA Protection",
              "title": "System DRAM + pKVM-Managed SMMUv3 Stage-2 IOMMU Tables",
              "body": "Blocks both rogue host CPU loads/stores and malicious peripheral DMA against pVM-owned physical frames",
              "theme": "stone"}],
        ],
        edges=[
            ("host", "pkvm", "HVC donate / share hypercalls", "amber", False),
            ("pvm1", "pkvm", "Stage-2 isolated IPA->PA", "green", False),
            ("pvm2", "pkvm", "Stage-2 isolated IPA->PA", "teal", False),
            ("pkvm", "dram", "enforces CPU + SMMUv3 Stage-2", "slate", False),
        ],
        footer="Once Host EL1 donates a physical page to a pVM, pKVM strips it from the Host Stage-2 MMU; host kernel reads trigger an EL2 fault."
    )

    # 13. Ch 5: 05-pvmfw-dice-chain.svg
    build_horizontal_pipeline(
        P("05-pvmfw-dice-chain.svg"),
        "pvmfw & OpenProfile for DICE: Layered Secret Derivation for Protected VMs",
        stages=[
            {"tag": "Layer 0 · Silicon", "title": "Unique Device Secret",
             "body": "Immutable per-chip UDS read once by ROM/BL and latched offline", "theme": "slate"},
            {"tag": "Layer 1 · Boot", "title": "Bootloader DICE",
             "body": "HKDF mixes AVB boot state + pvmfw hash into CDI_Attest & Seal", "theme": "teal"},
            {"tag": "Layer 2 · Guest Gate", "title": "pvmfw (Rust in EL1)",
             "body": "Runs first inside pVM; verifies Microdroid + payload AVB hashes", "theme": "green"},
            {"tag": "Layer 3 · Workload", "title": "Microdroid Payload",
             "body": "Receives derived child BCC cert chain & stable sealing secret", "theme": "purple"},
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Zero-Knowledge Wipe Before Jump",
            "title": "pvmfw Scrubs Parent CDIs from RAM",
            "body": "Compromised guest payload cannot forge another pVM's identity or read parent secrets",
            "theme": "red",
            "edge_label": "zeroizes parent",
        },
        footer="CDI_Seal remains stable across authorized payload updates (via signer pubkey + rollback floor), while CDI_Attest binds exact code hashes."
    )

    # 14. Ch 6: 06-selinux-domain-mediation.svg
    build_fan_bands(
        P("06-selinux-domain-mediation.svg"),
        "Universal Enforcing SELinux: Domain Separation, ioctl xperms, & CTS neverallow Gates",
        bands=[
            [
                {"id": "uapp", "tag": "Domain: untrusted_app", "title": "Play & Sideloaded Apps",
                 "body": "Blocked from raw /dev nodes, /proc net leaks, and direct HAL sockets", "theme": "slate"},
                {"id": "papp", "tag": "Domain: priv_app", "title": "Preloaded Privileged Apps",
                 "body": "Constrained by strict neverallow rules forbidding kernel mem/module access", "theme": "teal"},
                {"id": "ssrv", "tag": "Domain: system_server", "title": "Android Framework Services",
                 "body": "Mediates Binder services; cannot directly touch raw vendor hardware", "theme": "green"},
                {"id": "vhal", "tag": "Domain: hal_*_server", "title": "Vendor Treble HAL Daemons",
                 "body": "Each HAL runs in its own domain (hal_camera, hal_bluetooth) with minimal /dev access", "theme": "amber"},
            ],
            [{"id": "lsm", "tag": "Kernel Mandatory Access Control · security/selinux",
              "title": "SELinux LSM Hook Engine (avc_has_perm + allowxperm 16-bit ioctl Command Filter)",
              "body": "Default-deny over (scontext, tcontext, tclass, perm); restricts reachable driver ioctl subcommands",
              "theme": "purple"}],
            [{"id": "cts", "tag": "Ecosystem Governance · system/sepolicy",
              "title": "Compile-Time checkpolicy neverallow Assertions + CTS SELinuxHostTest",
              "body": "Refuses to sign/certify any OEM image containing permissive domains or overly broad vendor allow rules",
              "theme": "red"}],
        ],
        edges=[
            ("uapp", "lsm", "Binder & VFS checks", "slate", False),
            ("papp", "lsm", "bounded priv checks", "teal", False),
            ("ssrv", "lsm", "HAL Binder calls", "green", False),
            ("vhal", "lsm", "scoped /dev ioctl", "amber", False),
            ("lsm", "cts", "governed by neverallow + CTS", "red", False),
        ],
        footer="Since Android 5.0, zero processes run unconfined; CTS verifies every shipping OEM policy satisfies all AOSP neverallow invariants."
    )

    # 15. Ch 6: 06-zygote-seccomp-pipeline.svg
    build_vertical_flow(
        P("06-zygote-seccomp-pipeline.svg"),
        "Defense-in-Depth App Confinement: Zygote Specialization & seccomp-BPF Filtering",
        steps=[
            {"tag": "Stage 1 · PID 1", "title": "init Loads Monolithic / Split Binary sepolicy",
             "body": "Transitions kernel to enforcing mode before spawning any network or application daemon",
             "theme": "slate"},
            {"tag": "Stage 2 · Pre-Fork", "title": "Zygote64 Preloads ART & Installs App seccomp-BPF",
             "body": "Compiles architecture-specific BPF program blocking ~130+ unused Linux syscalls (keyctl, bpf, io_uring, kexec)",
             "theme": "teal", "edge_label": "spawns Zygote"},
            {"tag": "Stage 3 · Credential Drop", "title": "forkAndSpecialize(): Drop CAP_* & Set UID/GIDs",
             "body": "Clears bounding/effective/permitted POSIX capabilities to 0 and calls setresuid(u0_aXYZ)",
             "theme": "green", "edge_label": "on app launch"},
            {"tag": "Stage 4 · Mount & MAC", "title": "Private Mount Namespace + selinux_android_setcontext()",
             "body": "Isolates /data/data view and locks process into untrusted_app or isolated_app_all SELinux domain",
             "theme": "purple", "edge_label": "locks MAC label"},
        ],
        side_notes={
            1: {"tag": "Syscall Trap", "title": "SIGSYS Kernel Kill",
                "body": "Disallowed syscall aborts immediately before buggy kernel subsystem code executes",
                "theme": "red", "edge_label": "blocked syscall"},
        },
        footer="SELinux restricts which kernel objects an app can reach; seccomp-BPF removes entire legacy syscall parsers from the reachable kernel TCB."
    )

    # 16. Ch 7: 07-treble-gki-split.svg
    build_split_domains(
        P("07-treble-gki-split.svg"),
        "Project Treble & Generic Kernel Image (GKI 2.0): Decoupling Google OS from Vendor BSPs",
        left={
            "label": "Google Generic OS & GKI",
            "theme": "green",
            "cards": [
                {"tag": "Userspace Framework", "title": "/system, /system_ext, & Mainline APEX",
                 "body": "AOSP framework, system_server, keystore2, ART, and media codecs updated independently of SoC vendor",
                 "theme": "white"},
                {"tag": "Binderized IPC Contract", "title": "Versioned Stable AIDL VINTF Manifests",
                 "body": "Typed cross-process Binder transactions replace in-process dlopen() of vendor shared libraries",
                 "theme": "teal", "in_arrow": True},
                {"tag": "Unified Core Kernel", "title": "GKI boot.img (Google-Signed vmlinux)",
                 "body": "Single upstream-tracked ARM64 kernel binary compiled with Clang LTO, KCFI, and SCS across all OEMs",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "SoC & OEM Vendor BSP",
            "theme": "amber",
            "cards": [
                {"tag": "Isolated HAL Daemons", "title": "/vendor/bin/hw/* HAL Processes",
                 "body": "Camera, GPU, RIL, and Sensor HALs run in restricted vendor SELinux domains; crash/RCE stays contained",
                 "theme": "white"},
                {"tag": "Vendor NDK Boundary", "title": "LL-NDK & VNDK ABI Isolation",
                 "body": "Prevents vendor binaries from linking unstable internal /system C++ symbols",
                 "theme": "amber", "in_arrow": True},
                {"tag": "Loadable SoC Drivers", "title": "vendor_boot & vendor_dlkm (.ko Modules)",
                 "body": "SoC peripherals link only against frozen KMI symbol allowlist verified at build and VTS time",
                 "theme": "slate", "in_arrow": True},
            ],
        },
        bridges=[
            (1, 0, "lr", "/dev/binder VINTF AIDL", "teal"),
            (2, 2, "rl", "Frozen KMI Symbol ABI", "slate"),
        ],
        boundary_label="Treble VINTF + GKI KMI Seam",
        footer="Before Treble & GKI, media/camera HALs ran inside system servers and SoC forks lagged LTS Linux by years."
    )

    # 17. Ch 7: 07-kcfi-scs-rust-defense.svg
    build_matrix(
        P("07-kcfi-scs-rust-defense.svg"),
        "Control-Flow Integrity & Memory-Safe Languages Across AOSP & GKI",
        "Layered mitigations eliminating or containing C/C++ memory corruption in userspace daemons and Ring 0",
        row_headers=[
            ("Rust in AOSP & GKI", "keystore2, UWB, Binder"),
            ("Clang KCFI", "Forward-Edge Type Hash"),
            ("Shadow Call Stack", "ARM64 x18 Return Stack"),
            ("Pointer Auth (PAC)", "ARMv8.3+ Crypto MAC"),
        ],
        col_headers=[
            ("Bug Class", "Primary Target"),
            ("Enforcement", "Compile vs. CPU"),
            ("Deterministic?", "Bypass Bound"),
            ("Residual Seam", "Attacker Pivot"),
        ],
        cells=[
            [("Spatial & Temporal", "green"), ("Compile-Time Check", "green"),
             ("Yes (Safe Rust)", "green"), ("C/C++ BSP Drivers", "amber")],
            [("Forward-Edge JOP", "teal"), ("Inline Type Hash", "teal"),
             ("Type-Class Bound", "amber"), ("Data-Only Attacks", "amber")],
            [("Backward-Edge ROP", "teal"), ("x18 Shadow Stack", "teal"),
             ("Yes (Isolated x18)", "green"), ("Heap Data Attacks", "amber")],
            [("ROP / JOP Pointers", "purple"), ("PACIASP CPU MAC", "purple"),
             ("Probabilistic MAC", "amber"), ("Signing Oracles", "red")],
        ],
        legend="Android's vulnerability telemetry shows memory-safety bugs dropped from 76% (2019) to ~24% (2024) as new code shifted to Rust.",
        footer="KCFI and SCS raise exploit cost in existing C code; Rust eliminates spatial and temporal memory bugs at compile time.",
        width=960.0,
    )

    # 18. Ch 8: 08-mte-pointer-granule-check.svg
    build_vertical_flow(
        P("08-mte-pointer-granule-check.svg"),
        "ARMv8.5-A Memory Tagging Extension (MTE): Lock-and-Key Pointer vs. Granule Check",
        steps=[
            {"tag": "Logical Pointer (Key)", "title": "64-Bit Address with 4-Bit Tag in Bits [59:56]",
             "body": "Scudo inserts pseudorandom tag (1..15) via IRG/ADDG using ARM Top-Byte-Ignore (TBI) address bits",
             "theme": "slate"},
            {"tag": "Allocation Granule (Lock)", "title": "16-Byte Physical Memory Granule + 4-Bit Tag RAM",
             "body": "STG / STZG instructions write matching 4-bit tag into dedicated tag storage (~3.125% DRAM overhead)",
             "theme": "teal", "edge_label": "paired at alloc/free"},
            {"tag": "CPU Load / Store Gate", "title": "Hardware Compares Pointer[59:56] == GranuleTag",
             "body": "Checked on every tagged memory access against spatial overflow into neighbor chunk or UAF after re-tag",
             "theme": "green", "edge_label": "every LDR / STR"},
            {"tag": "Tag Mismatch Mode", "title": "SYNC (Immediate SEGV_MTESERR) vs. ASYNC (TFSR_EL1)",
             "body": "SYNC stops offending instruction before corruption lands; ASYMM runs SYNC on reads and ASYNC on writes",
             "theme": "amber", "edge_label": "on mismatch"},
        ],
        side_notes={
            2: {"tag": "Entropy Ceiling", "title": "1/16 (6.25%) Guess Bound",
                "body": "4-bit tag space requires crash intolerance or speculative-oracle defenses (TIKTAG)",
                "theme": "red", "edge_label": "4-bit tag"},
        },
        footer="Advanced Protection enables MTE continuously across eligible apps; bootloader one-shot mode upgrades ASYNC->SYNC after a crash."
    )

    # 19. Ch 8: 08-scudo-mte-lifecycle.svg
    build_horizontal_pipeline(
        P("08-scudo-mte-lifecycle.svg"),
        "Scudo Hardened Allocator + Hardware MTE Spatial & Temporal Defense Lifecycle",
        stages=[
            {"tag": "1 · Allocate", "title": "malloc(48) -> Tag 0xA",
             "body": "Randomized chunk slot + 16B granules tagged 0xA; neighbor has Tag 0x3", "theme": "green"},
            {"tag": "2 · Overflow", "title": "ptr[52] -> Hits 0x3",
             "body": "Linear spatial overflow crosses 16B boundary into neighbor tag", "theme": "amber"},
            {"tag": "3 · Deallocate", "title": "free() -> Re-Tag 0x7",
             "body": "Scudo immediately re-tags freed granules & holds chunk in quarantine", "theme": "teal"},
            {"tag": "4 · Dangling Use", "title": "*ptr (0xA != 0x7)",
             "body": "Temporal UAF with old tag 0xA triggers CPU tag check fault", "theme": "red"},
        ],
        under_anchor={
            "target_idx": 3,
            "tag": "Telemetry & Escalation",
            "title": "Tombstone MTE Dump + Bootloader Sync Upgrade",
            "body": "Records exact alloc/free stack traces in crash report and arms temporary SYNC MTE on next boot",
            "theme": "purple",
            "edge_label": "triggers dump",
        },
        footer="Combining Scudo chunk randomization, CRC-protected headers, quarantine, and MTE defeats classic heap grooming."
    )

    # 20. Ch 9: 09-zygote-webview-uid-tree.svg
    build_fan_bands(
        P("09-zygote-webview-uid-tree.svg"),
        "Per-App UID Assignment, AppZygote, & Zero-Permission WebView Renderer Isolation",
        bands=[
            [{"id": "init", "tag": "System Bootstrap · UID 0 (init SELinux Domain)",
              "title": "init Spawns Primary Zygote64 & Secondary WebViewZygote",
              "body": "Establishes shared read-only ART runtime, framework classes, and Chromium library mappings for COW sharing",
              "theme": "slate"}],
            [
                {"id": "zyg", "tag": "App Fork Server", "title": "Zygote64",
                 "body": "Accepts socket requests from ActivityManagerService to spawn app sandboxes", "theme": "teal"},
                {"id": "wvz", "tag": "Isolated Fork Server", "title": "WebViewZygote",
                 "body": "Unprivileged intermediate zygote dedicated to untrusted web/renderer children", "theme": "purple"},
            ],
            [
                {"id": "app1", "tag": "UID u0_a214 · untrusted_app", "title": "Banking / Mail App",
                 "body": "Owns /data/user/0/<pkg> + granted runtime permissions", "theme": "green"},
                {"id": "azyg", "tag": "UID u0_i9000 · app_zygote", "title": "AppZygote Preloader",
                 "body": "App-specific pre-fork helper without network/storage writes", "theme": "amber"},
                {"id": "iso", "tag": "Ephemeral UID u0_i99042 · isolated_app", "title": "WebView Renderer",
                 "body": "Zero permissions, no filesystem, no network socket, ~2 Binder services only", "theme": "red"},
            ],
        ],
        edges=[
            ("init", "zyg", "spawns at boot", "slate", False),
            ("init", "wvz", "spawns restricted", "purple", False),
            ("zyg", "app1", "fork + setresuid(10214)", "green", False),
            ("zyg", "azyg", "fork app_zygote", "amber", False),
            ("wvz", "iso", "fork isolatedProcess", "red", False),
        ],
        footer="A renderer RCE in WebView lands inside an ephemeral u0_i* UID that cannot even open a TCP socket or read the host app's files."
    )

    # 21. Ch 9: 09-binder-capability-vs-intent.svg
    build_sequence(
        P("09-binder-capability-vs-intent.svg"),
        "Kernel Binder Capability Mediation vs. Exported Intent Redirection Confused Deputy",
        actors=[
            {"title": "Untrusted App", "sub": "UID u0_a250 (Attacker)", "theme": "red"},
            {"title": "Kernel /dev/binder", "sub": "binder_transaction()", "theme": "slate"},
            {"title": "Vulnerable Victim App", "sub": "UID u0_a180 (Exported)", "theme": "amber"},
            {"title": "Internal Private File", "sub": "FileProvider / Internal Activity", "theme": "purple"},
        ],
        messages=[
            (0, 1, "BC_TRANSACTION: outer Intent wrapping nested private Intent", "red", False),
            (1, 2, "BR_TRANSACTION stamped with unforgeable sender_euid = 10250", "slate", False),
            (2, 2, "Bug: extracts nested Intent without checking getCallingUid() or flags", "amber", False),
            (2, 3, "startActivity(nestedIntent) with FLAG_GRANT_READ_URI_PERMISSION", "red", False),
            (3, 0, "Victim unintentionally delegates read access to its own private file", "red", True),
        ],
        boundary_after=1,
        boundary_label="Kernel Identity Stamp vs. App Logic",
        bottom_note={
            "tag": "Android 12-16 Platform Hardening",
            "title": "Explicit android:exported, PendingIntent.FLAG_IMMUTABLE, & Strict Nested-Intent Sanitization",
            "body": "Android 15/16 SaFety checks block unverified nested-Intent launches and strip creator privileges unless explicitly opted in",
            "theme": "green",
        },
        footer="Kernel Binder never misidentifies the caller; confused-deputy bugs arise when a target app re-dispatches attacker-supplied Intents under its own UID."
    )

    # 22. Ch 10: 10-apk-signing-schemes-evolution.svg
    build_timeline_spine(
        P("10-apk-signing-schemes-evolution.svg"),
        "APK Cryptographic Integrity Evolution: From JAR v1 & Janus to v4 & Developer Verification",
        entries=[
            {"year": "2008 · v1", "tag": "META-INF/MANIFEST.MF (JAR Signing)",
             "title": "Per-Entry ZIP Signatures Leave Archive Framing Unsigned",
             "body": "ZIP parser reads from EOF Central Directory while ART DEX loader read from offset 0 -> Janus (CVE-2017-13156) prepended malicious DEX without invalidating v1",
             "theme": "red"},
            {"year": "2016 · v2", "tag": "Android 7.0 · APK Signing Block",
             "title": "Whole-File Merkle Signature Covering Every Byte Outside Signing Block",
             "body": "Inserts length-prefixed block immediately before ZIP Central Directory; hashes 1 MiB chunks across sections 1, 3, and 4 to eliminate Janus framing gaps",
             "theme": "teal"},
            {"year": "2018 · v3", "tag": "Android 9.0 · SigningCertificateLineage",
             "title": "Cryptographic Key Rotation Without Changing Package Identity",
             "body": "Old signing key signs rotation proof delegating update/sharedUserId capabilities to new key while bounding legacy key permissions",
             "theme": "green"},
            {"year": "2020 · v4", "tag": "Android 11 · fs-verity Streaming",
             "title": "4 KiB Page-Granular fs-verity Merkle Tree (.idsig)",
             "body": "Enables Incremental File System instant launch while kernel fs-verity verifies every paged-in APK block on demand",
             "theme": "purple"},
            {"year": "2026 · Identity", "tag": "Certified Android Devices · Ecosystem Accountability",
             "title": "Android Developer Verification Across Play & Sideloading",
             "body": "Binds package names and signing keys of sideloaded APKs on certified devices to verified developer identities to curb repeat banking-trojan re-signing",
             "theme": "amber"},
        ],
        footer="Modern Android enforces minimum signature scheme floors by targetSdkVersion, rejecting v1-only packages."
    )

    # 23. Ch 10: 10-scoped-storage-mediastore.svg
    build_split_domains(
        P("10-scoped-storage-mediastore.svg"),
        "Scoped Storage: App-Private POSIX Directories vs. Mediated Shared Media & Photo Picker",
        left={
            "label": "Unmediated App-Private Sandbox",
            "theme": "green",
            "cards": [
                {"tag": "Internal CE / DE Storage", "title": "/data/user/0/<pkg> & /data/user_de/0/<pkg>",
                 "body": "Protected by kernel DAC UID + SELinux app_data_file + fscrypt; auto-deleted on app uninstall",
                 "theme": "white"},
                {"tag": "External App-Scoped Dir", "title": "/sdcard/Android/data/<pkg>",
                 "body": "Mount-namespace & FUSE isolated since Android 11; invisible even to other apps holding media permissions",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "Mediated Shared Collections",
            "theme": "teal",
            "cards": [
                {"tag": "Zero-Permission Selection", "title": "System Photo Picker & SAF Document Provider",
                 "body": "Out-of-process system UI grants transient read URI to exact user-tapped items without broad gallery access",
                 "theme": "white"},
                {"tag": "Indexed Media Mediation", "title": "MediaStore SQLite + FUSE Daemon (EXIF Redaction)",
                 "body": "Strips GPS EXIF tags unless ACCESS_MEDIA_LOCATION is granted; blocks arbitrary filesystem crawling",
                 "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "rl", "transient content:// URI grant", "teal"),
            (1, 1, "lr", "FUSE passthrough for owned files", "green"),
        ],
        boundary_label="Mount Namespace + FUSE Enforcement",
        footer="Replacing legacy READ_EXTERNAL_STORAGE stopped random utilities from harvesting screenshots, downloads, and camera GPS metadata."
    )
