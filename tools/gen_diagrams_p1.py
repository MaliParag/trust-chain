#!/usr/bin/env python3
"""Part 1 diagram definitions: Foundations + Chapters 1-9 (Silicon + Kernel & Code)."""
import os
from diagram_lib import (
    SvgCanvas, THEMES, build_vertical_flow, build_sequence, build_split_domains,
    build_horizontal_pipeline, build_fan_bands, build_matrix, build_timeline_spine,
)


def generate_part1(diag_dir: str):
    def P(name):
        return os.path.join(diag_dir, name)

    # 1. trust-chain-map.svg (Foundations)
    c = SvgCanvas(880, 560)
    y = c.add_header("The 20-Chapter Windows Trust Chain", "Trust is inherited upward from immutable silicon; never self-asserted by higher layers") + 14
    main_x, main_w = 64.0, 540.0
    side_x, side_w = 646.0, 198.0

    tiers = [
        ("Finale · Chapter 20", "When the Chain Snaps: Storm-0558", "Stolen 2016 MSA key + omitted cross-tier iss/aud check forges enterprise mail tokens", "red", "the chain snaps"),
        ("Part IV · Chapters 17 to 19", "Cloud Control Plane & Confidential Compute", "17. Zero Trust (Conditional Access) · 18. Continuous Access Evaluation · 19. Confidential VMs", "amber", "inherits device & token signals"),
        ("Part III · Chapters 10 to 15", "Credentials & Access", "10. Access Control · 11. Credential Guard · 12. NTLM · 13. Kerberos · 14. PRT · 15. Hello & Passkeys", "green", "inherits VTL1 & kernel boundaries"),
        ("Part II · Chapters 6 to 9", "Kernel & Code Integrity", "6. Secure Kernel & VBS · 7. Code Integrity & App Control · 8. PPL · 9. Process Mitigations", "teal", "inherits measured pre-OS handoff"),
        ("Part I · Chapters 1 to 5", "Silicon & Firmware Roots", "1. Secure Boot · 2. The TPM · 3. Pluton · 4. Measured Boot · 5. Remote Attestation", "slate", None),
    ]
    ys = []
    cur_y = y
    for idx, (tag, ti, bo, th, edge_lbl) in enumerate(tiers):
        h = c.add_card(main_x, cur_y, main_w, tag=tag, title=ti, body=bo, theme=th)
        ys.append((cur_y, h, edge_lbl, th))
        if idx < len(tiers) - 1:
            cur_y += h + 38.0
        else:
            cur_y += h

    for idx in range(len(ys) - 1):
        upper_top, upper_h, lbl, uth = ys[idx]
        lower_top, _, _, _ = ys[idx + 1]
        col = "#8d2d3b" if idx == 0 else "#b07926"
        # Upward inheritance arrow from lower tier to upper tier!
        c.add_line(main_x + main_w / 2, lower_top, main_x + main_w / 2, upper_top + upper_h,
                   color=col, width=1.8, arrow_end=True, label=lbl, label_color=col)

    # Interlude side rail spanning Parts I-IV
    rail_top = ys[1][0]
    rail_bot = ys[4][0] + ys[4][1]
    c.add_rect(side_x, rail_top, side_w, rail_bot - rail_top, fill="#f4f1ea",
               stroke="#524c44", stroke_width=1.3, rx=8, dash="5,3", layer="bg")
    c.add_card(side_x + 12, rail_top + 24, side_w - 24, tag="Interlude · Chapter 16",
               title="ETW: The EDR Substrate", body="Per-CPU ring buffers, AMSI, Sysmon, and kernel EtwTi observe every host tier",
               theme="white", align="center", title_size=11.5, body_size=10.0)
    c.add_text(side_x + side_w / 2, rail_bot - 42, "Observation, not enforcement:", size=9.8,
               fill="#524c44", bold=True, anchor="middle")
    c.add_text(side_x + side_w / 2, rail_bot - 26, "feeds risk into Part IV", size=9.8,
               fill="#524c44", italic=True, anchor="middle")
    for idx in (1, 2, 3, 4):
        mid = ys[idx][0] + ys[idx][1] / 2
        c.add_line(main_x + main_w, mid, side_x, mid, color="#787167", width=1.2, dash="3,3", arrow_end=True)

    c.height = cur_y + 20.0
    c.save(P("trust-chain-map.svg"))

    # 2. Ch 1: 16-secure-boot-firmware-pipeline.svg
    build_horizontal_pipeline(
        P("16-secure-boot-firmware-pipeline.svg"),
        "UEFI Platform Initialization & Hardware Root Anchor",
        [
            {"tag": "Phase 1", "title": "SEC", "body": "Reset vector & CPU cache-as-RAM", "theme": "slate"},
            {"tag": "Phase 2", "title": "PEI", "body": "DRAM init & early hob handoff", "theme": "slate"},
            {"tag": "Phase 3 · Verifier", "title": "DXE", "body": "Secure Boot LoadImage() checks PK/KEK/DB/DBX", "theme": "teal"},
            {"tag": "Phase 4", "title": "BDS", "body": "Reads BootOrder NVRAM policy", "theme": "slate"},
            {"tag": "OS Handoff", "title": "bootmgfw.efi", "body": "Verifies winload.efi via bootlib", "theme": "green"},
        ],
        under_anchor={
            "target_idx": 0,
            "tag": "Silicon Fuse Anchor",
            "title": "Intel Boot Guard / AMD HVB",
            "body": "OTP-fused public key hash verifies IBB / ACM before SEC executes",
            "theme": "red",
            "edge_label": "verifies pre-SEC",
        },
        footer="UEFI Secure Boot starts in DXE; only fused Boot Guard / AMD HVB anchors the SPI flash stages beneath DXE."
    )

    # 3. Ch 1: 16-secure-boot-loadimage-decision.svg
    build_vertical_flow(
        P("16-secure-boot-loadimage-decision.svg"),
        "UEFI LoadImage() Signature Evaluation Order (DBX Precedes DB)",
        [
            {"tag": "Input", "title": "LoadImage(PE/COFF EFI Binary)", "body": "Bootloader, UEFI driver, or PCIe Option ROM image", "theme": "slate"},
            {"tag": "Step 1 · Digest", "title": "Compute PE Authenticode Hash", "body": "SHA-256 excluding Optional Header Checksum & Attribute Certificate Table", "theme": "slate"},
            {"tag": "Step 2 · Denylist Hash", "title": "Image SHA-256 Present in DBX?", "body": "Unconditional revocation check runs before any allowlist trust", "theme": "amber", "edge_label": "check DBX first"},
            {"tag": "Step 3 · Denylist Signer", "title": "Signing Certificate or Root in DBX?", "body": "Blocks entire compromised or retired CA subtrees", "theme": "amber", "edge_label": "no"},
            {"tag": "Step 4 · Allowlist", "title": "Image Hash in DB or Signer Chains to DB?", "body": "Evaluates Microsoft Windows Production PCA / 2023 CA or Third-Party UEFI CA", "theme": "amber", "edge_label": "no"},
            {"tag": "Outcome", "title": "EFI_SUCCESS: Image Admitted", "body": "Firmware transfers control or links UEFI driver into DXE", "theme": "green", "edge_label": "yes (valid)"},
        ],
        side_notes={
            2: {"tag": "Blocked", "title": "EFI_SECURITY_VIOLATION", "body": "Revoked binary hash denied immediately", "theme": "red", "edge_label": "yes"},
            3: {"tag": "Blocked", "title": "EFI_SECURITY_VIOLATION", "body": "Revoked certificate chain denied", "theme": "red", "edge_label": "yes"},
            4: {"tag": "Blocked", "title": "EFI_SECURITY_VIOLATION", "body": "Unsigned or untrusted signer rejected", "theme": "red", "edge_label": "no"},
        },
        footer="Because DBX is evaluated before DB, a revoked hash in DBX can never be rescued by chaining to an active DB CA."
    )

    # 4. Ch 1: 16-secure-boot-blacklotus-chain.svg
    build_vertical_flow(
        P("16-secure-boot-blacklotus-chain.svg"),
        "BlackLotus (CVE-2022-21894): Signed-Downgrade Exploitation",
        [
            {"tag": "Stage 1 · ESP Staging", "title": "Plant Vulnerable Signed bootmgfw.efi on ESP", "body": "System-privileged attacker writes older Microsoft-signed bootloader to FAT32 EFI System Partition", "theme": "amber"},
            {"tag": "Stage 2 · Firmware Gate", "title": "DXE LoadImage() Accepts the Binary", "body": "RSA-2048 Authenticode signature is genuine and pre-KB5025885 DBX lacks the revoked hash", "theme": "slate", "edge_label": "valid signature; unrevoked in DBX", "edge_color": "#8d2d3b"},
            {"tag": "Stage 3 · Baton Drop", "title": "Trigger CVE-2022-21894 (BCD truncatememory)", "body": "Carves bootlib security metadata out of protected range to gain arbitrary pre-OS code execution", "theme": "red", "edge_label": "executes inside bootlib"},
            {"tag": "Stage 4 · Persistence", "title": "Enroll Attacker Key or Patch HVCI / BitLocker", "body": "Writes custom MOK / bootkit stage and hooks winload.efi before VBS or OS kernel starts", "theme": "red"},
            {"tag": "Stage 5 · Impact", "title": "Unsigned Kernel Payload Running Under Active Secure Boot", "body": "Confirm-SecureBootUEFI still reports True while Defender, HVCI, and BitLocker are neutralized", "theme": "red"},
        ],
        footer="Every enforced cryptographic check succeeded; the failure lay in the revocation lag between patching and fleet-wide DBX enforcement."
    )

    # 5. Ch 2: 01-tpm-1x-hierarchy.svg
    build_fan_bands(
        P("01-tpm-1x-hierarchy.svg"),
        "TPM 1.2 Architecture: Single Storage Root & Privacy-CA Indirection",
        [
            [{"id": "own", "tag": "Single Ownership", "title": "Owner Authorization Secret", "body": "Provisioned once via TPM_TakeOwnership", "theme": "amber"}],
            [{"id": "srk", "tag": "Single Root", "title": "Storage Root Key (SRK, RSA-2048)", "body": "Clearing TPM destroys SRK and invalidates every child key", "theme": "slate"}],
            [
                {"id": "sk", "tag": "Child Key", "title": "Storage Key", "body": "Wraps downstream keys", "theme": "white"},
                {"id": "bk", "tag": "Child Key", "title": "Binding / Sealing Key", "body": "PCR-bound data blobs", "theme": "white"},
                {"id": "sgk", "tag": "Child Key", "title": "Signing Key", "body": "Application signatures", "theme": "white"},
            ],
            [
                {"id": "ek", "tag": "Hardware Identity", "title": "Endorsement Key (EK)", "body": "1 RSA key per chip; decryption-only (cannot sign quotes directly)", "theme": "amber"},
                {"id": "pca", "tag": "External Broker", "title": "Privacy CA", "body": "Verifies EK cert and encrypts AIK credential back to EK", "theme": "slate"},
                {"id": "aik", "tag": "Quote Signer", "title": "Attestation Identity Key (AIK)", "body": "Signs PCR quotes without exposing raw EK modulus", "theme": "purple"},
            ],
        ],
        [
            ("own", "srk", "controls", "amber", False),
            ("srk", "sk", None, "slate", False),
            ("srk", "bk", None, "slate", False),
            ("srk", "sgk", None, "slate", False),
        ],
        footer="TPM 1.2 coupled platform and OS administration under one SRK and fixed algorithms to SHA-1 + RSA-2048."
    )

    # 6. Ch 2: 01-tpm-2x-hierarchies.svg
    build_fan_bands(
        P("01-tpm-2x-hierarchies.svg"),
        "TPM 2.0 Four-Domain Hierarchy & Deterministic Primary Seeds",
        [
            [
                {"id": "ps", "tag": "Platform (OEM/UEFI)", "title": "Platform Seed (PPS)", "body": "Controlled by early firmware; survives OS TPM Clear", "theme": "slate"},
                {"id": "es", "tag": "Endorsement (Identity)", "title": "Endorsement Seed (EPS)", "body": "Fused at manufacture; never changes across device life", "theme": "purple"},
                {"id": "ss", "tag": "Storage (OS Owner)", "title": "Storage Seed (SPS)", "body": "Rotated on TPM2_Clear to wipe OS/user keys cleanly", "theme": "teal"},
                {"id": "ns", "tag": "Null (Ephemeral)", "title": "Null Seed", "body": "Re-randomized on every reboot; zero persistence", "theme": "stone", "dashed": True},
            ],
            [
                {"id": "pk", "tag": "Firmware Root", "title": "Platform Primary Keys", "body": "Firmware NVRAM locks & anti-rollback state", "theme": "white"},
                {"id": "ek", "tag": "TPM2_CreatePrimary", "title": "EK & Restricted AK", "body": "EK decrypts MakeCredential challenge to certify co-resident AK", "theme": "white"},
                {"id": "srk", "tag": "TPM2_CreatePrimary", "title": "SRK -> BitLocker & NGC", "body": "Wraps sealed BitLocker VMK and Windows Hello keys", "theme": "white"},
                {"id": "nk", "tag": "Session Only", "title": "Transient Keys", "body": "Destroyed automatically on power cycle", "theme": "white", "dashed": True},
            ],
        ],
        [
            ("ps", "pk", "KDFa", "slate", False),
            ("es", "ek", "KDFa", "purple", False),
            ("ss", "srk", "KDFa", "teal", False),
            ("ns", "nk", "ephemeral", "slate", True),
        ],
        footer="Isolating SPS from EPS lets enterprises reset Storage ownership (TPM2_Clear) without destroying hardware Endorsement identity."
    )

    # 7. Ch 2: 01-tpm-attack-timeline.svg
    build_timeline_spine(
        P("01-tpm-attack-timeline.svg"),
        "Three Physical & Microarchitectural Attack Classes Against TPM 2.0",
        [
            {"year": "2017", "tag": "ROM Crypto Defect · CVE-2017-15361", "title": "ROCA (Infineon RSALib Prime Structure)", "body": "Low-entropy primorial RSA primes allowed practical private-key factorization from public moduli; required firmware capsule update + TPM Clear.", "theme": "amber"},
            {"year": "2019-2024", "tag": "Discrete dTPM · Passive Hardware Interposer", "title": "LPC / SPI Bus Sniffing (Andzakovic, SCRT, WithSecure)", "body": "A $40 logic analyzer on exposed motherboard SPI/LPC pins captures cleartext VMK bytes returned by TPM2_Unseal when BitLocker runs TPM-only without a pre-boot PIN.", "theme": "red"},
            {"year": "2019", "tag": "Firmware fTPM · CVE-2019-11090 / CVE-2019-16863", "title": "TPM-Fail (ECDSA Nonce Timing Side-Channel)", "body": "Data-dependent execution timing in Intel PTT and STMicroelectronics ECDSA routines leaked private signing keys across shared CPU resources.", "theme": "amber"},
            {"year": "2023", "tag": "Firmware fTPM · Physical Fault Injection", "title": "faulTPM (AMD PSP Voltage Glitching)", "body": "Sub-microsecond SVI2 voltage glitches against Zen 2/3 SoC rails corrupted PSP cryptographic checks and extracted sealed fTPM secrets.", "theme": "red"},
        ],
        footer="Eliminating exposed motherboard traces motivated moving the TPM onto the CPU die (Microsoft Pluton, Chapter 3)."
    )

    # 8. Ch 3: tpm-vs-pluton-topology.svg
    build_fan_bands(
        P("tpm-vs-pluton-topology.svg"),
        "Physical Bus & Packaging Evolution: dTPM vs. fTPM vs. Microsoft Pluton",
        [
            [
                {"id": "dtpm", "tag": "1 · Discrete dTPM", "title": "External Microcontroller on Motherboard", "body": "CPU <-> Chipset <-> Exposed SPI / LPC traces -> Discrete TPM IC.\nVulnerability: Passive $40 logic analyzer sniffs unencrypted TPM2_Unseal responses on board pins.", "theme": "red"},
                {"id": "ftpm", "tag": "2 · Firmware fTPM (PTT / PSP)", "title": "Chipset / SoC Management Enclave", "body": "No external SPI/LPC wires to TPM, but firmware updates depend on fragmented OEM UEFI capsule delivery.", "theme": "amber"},
                {"id": "pluton", "tag": "3 · On-Die Microsoft Pluton", "title": "Dedicated Security Core Inside CPU Die", "body": "Communicates over internal SoC interconnect via CRB; SHACK keeps raw keys out of firmware SRAM; serviced directly via Windows Update.", "theme": "green"},
            ]
        ],
        [],
        footer="Pluton closes passive motherboard bus sniffing by collapsing the CPU-to-TPM wire inside the silicon package."
    )

    # 9. Ch 3: 02-pluton-boot-update.svg
    build_vertical_flow(
        P("02-pluton-boot-update.svg"),
        "Pluton Silicon Boot & Windows Update Servicing Pipeline",
        [
            {"tag": "1 · Hardware Reset", "title": "Immutable On-Die Boot ROM (FIPS 140-3 L2)", "body": "Executes first out of silicon ROM; holds fused Microsoft root public key hash", "theme": "slate"},
            {"tag": "2 · First Mutable Stage", "title": "Verify & Load First Mutable Code (FMC)", "body": "Checks cryptographic signature and anti-rollback Security Version Number (SVN)", "theme": "teal", "edge_label": "ROM verifies signature + SVN"},
            {"tag": "3 · Runtime Bring-Up", "title": "Rust-Based Pluton Runtime & SHACK Key Engine", "body": "Exposes standard TCG TPM 2.0 Command Response Buffer (CRB) to UEFI and Windows", "theme": "teal", "edge_label": "loads isolated runtime"},
            {"tag": "4 · Fleet Servicing", "title": "Signed Firmware Delivered via Windows Update", "body": "Stages signed update image directly from Microsoft without waiting on OEM BIOS capsules", "theme": "amber", "edge_label": "stages signed capsule"},
            {"tag": "5 · Atomic Commit", "title": "Reboot Verification & Anti-Rollback Ratchet", "body": "Boot ROM validates new image signature and commits updated SVN floor", "theme": "green", "edge_label": "verified on reboot"},
        ],
        footer="Unifying silicon RoT design with Windows Update eliminates multi-quarter OEM firmware patch lag."
    )

    # 10. Ch 3: 02-pluton-cve-propagation.svg
    build_fan_bands(
        P("02-pluton-cve-propagation.svg"),
        "Shared Reference Specification Blast Radius: CVE-2025-2884",
        [
            [{"id": "ref", "tag": "Upstream Specification Source", "title": "TCG TPM 2.0 Reference Implementation (Rev 01.83)", "body": "Out-of-bounds read/write flaw in CryptHmacSign symmetric key handling", "theme": "red"}],
            [
                {"id": "plu", "tag": "On-Die Silicon", "title": "Microsoft Pluton", "body": "Patched fleet-wide via Windows Update", "theme": "green"},
                {"id": "ptt", "tag": "Chipset fTPM", "title": "Intel PTT", "body": "OEM UEFI capsule (INTEL-SA-01209)", "theme": "amber"},
                {"id": "dtpm", "tag": "Discrete IC", "title": "Hardware dTPMs", "body": "Per-vendor advisories & OEM flash tools", "theme": "amber"},
                {"id": "vtp", "tag": "Virtual / Cloud", "title": "libtpms / swtpm", "body": "Hypervisor package rebuilds", "theme": "slate"},
            ],
        ],
        [
            ("ref", "plu", "shared spec lineage", "red", False),
            ("ref", "ptt", "shared spec lineage", "red", False),
            ("ref", "dtpm", "shared spec lineage", "red", False),
            ("ref", "vtp", "shared spec lineage", "red", False),
        ],
        footer="Centralizing firmware on TCG reference code unifies behavior, making rapid fleet patch delivery (Windows Update) decisive."
    )

    # 11. Ch 4: 03-measured-boot-srtm-chain.svg
    build_split_domains(
        P("03-measured-boot-srtm-chain.svg"),
        "Windows Static Root of Trust for Measurement (SRTM) -> PCR Bank Map",
        left={
            "label": "Sequential Boot Execution",
            "theme": "slate",
            "cards": [
                {"tag": "Stage 1", "title": "CRTM (Boot Guard / PSP / UEFI SEC)", "body": "Measures initial firmware volumes before PEI/DXE", "theme": "white", "in_arrow": True},
                {"tag": "Stage 2", "title": "UEFI PEI & DXE Drivers", "body": "Measures platform config, PCIe Option ROMs, boot order", "theme": "white", "in_edge": "handoff"},
                {"tag": "Stage 3", "title": "UEFI BDS & Secure Boot Variables", "body": "Measures PK/KEK/DB/DBX + authority cert + bootmgfw.efi", "theme": "white", "in_edge": "handoff"},
                {"tag": "Stage 4", "title": "Windows Boot (bootmgfw -> winload -> ELAM)", "body": "Measures BCD policy, kernel, boot drivers, ELAM, WDAC", "theme": "white", "in_edge": "handoff"},
                {"tag": "Stage 5", "title": "EV_SEPARATOR & OS Handoff", "body": "Caps boot PCRs and freezes WBCL boot prefix", "theme": "green", "in_edge": "cap PCRs"},
            ],
        },
        right={
            "label": "TPM 2.0 SHA-256 PCR Bank",
            "theme": "amber",
            "cards": [
                {"tag": "Firmware Code", "title": "PCR[0]", "body": "CRTM + UEFI firmware executable volumes", "theme": "white"},
                {"tag": "Platform & Option ROMs", "title": "PCR[1..3, 5..6]", "body": "SMBIOS/ACPI config, Option ROM code & GPT partition table", "theme": "white"},
                {"tag": "Secure Boot & Boot Manager", "title": "PCR[7] & PCR[4]", "body": "PCR[7]: PK/KEK/DB/DBX + matching signer\nPCR[4]: bootmgfw.efi PE image digest", "theme": "green"},
                {"tag": "Windows OS Loader State", "title": "PCR[12..14]", "body": "BCD flags (debug/testsigning), boot drivers, MOK/ELAM", "theme": "white"},
                {"tag": "BitLocker Access Control", "title": "PCR[11]", "body": "Capped by bootmgr before OS handoff so VTL0 cannot replay unseal", "theme": "teal"},
            ],
        },
        bridges=[
            (0, 0, "lr", "TPM2_PCR_Extend", "slate"),
            (1, 1, "lr", "TPM2_PCR_Extend", "slate"),
            (2, 2, "lr", "TPM2_PCR_Extend", "green"),
            (3, 3, "lr", "TPM2_PCR_Extend", "slate"),
            (4, 4, "lr", "caps PCR[11]", "teal"),
        ],
        footer="PCR_new = SHA256(PCR_old || digest): reordering, altering, or omitting any stage permanently diverges the final PCR digest."
    )

    # 12. Ch 4: 03-measured-boot-seal-unseal.svg
    build_fan_bands(
        P("03-measured-boot-seal-unseal.svg"),
        "BitLocker TPM2_Seal & PolicyPCR Unseal Gate (Default UEFI Profile: PCR 7 + 11)",
        [
            [
                {"id": "seal", "tag": "Provisioning Time", "title": "TPM2_Create / Seal(VMK, PolicyPCR)", "body": "Encrypts BitLocker Volume Master Key under Storage Root Key bound to expected PCR[7, 11] digest", "theme": "slate"},
                {"id": "boot", "tag": "Every Subsequent Boot", "title": "bootmgfw.efi Starts Policy Session", "body": "Executes TPM2_PolicyPCR against live hardware PCR[7, 11] values and invokes TPM2_Unseal", "theme": "teal"},
            ],
            [{"id": "gate", "tag": "Inside TPM 2.0 Boundary", "title": "Live sessionDigest == Sealed authPolicy?", "body": "Hardware compares current PCR state against sealed policy digest before decrypting VMK", "theme": "amber"}],
            [
                {"id": "ok", "tag": "Digest Matches", "title": "VMK Released -> Unlocks FVEK", "body": "bootmgfw caps PCR[11] so post-boot OS cannot re-unseal raw VMK", "theme": "green"},
                {"id": "fail", "tag": "Digest Mismatch (TPM_RC_POLICY_FAIL)", "title": "TPM Refuses Unseal -> 48-Digit Recovery", "body": "Triggered by DBX update, Secure Boot toggle, or untrusted bootloader", "theme": "red"},
            ],
        ],
        [
            ("seal", "gate", "stores authPolicy", "slate", False),
            ("boot", "gate", "submits live PCRs", "teal", False),
            ("gate", "ok", "match", "green", False),
            ("gate", "fail", "mismatch", "red", False),
        ],
        footer="TPM-only profile (PCR 7 + 11) unlocks unattended; adding a Pre-Boot PIN (TPM+PIN) adds dictionary-protected user intent."
    )

    # 13. Ch 4: 03-measured-boot-srtm-vs-drtm.svg
    build_split_domains(
        P("03-measured-boot-srtm-vs-drtm.svg"),
        "Static Measurement (SRTM) vs. System Guard Secure Launch (DRTM)",
        left={
            "label": "SRTM Plane · PCR[0..15]",
            "theme": "amber",
            "cards": [
                {"tag": "Reset Vector", "title": "CPU Reset -> OEM SEC / PEI / DXE", "body": "Hundreds of vendor UEFI drivers & SMM modules execute in TCB", "theme": "white", "in_arrow": True},
                {"tag": "Bootloader", "title": "BDS -> bootmgfw.efi -> winload.efi", "body": "Cumulative hashes in PCR[0..7] vary across every BIOS version", "theme": "white", "in_edge": "measures all OEM code"},
                {"tag": "Fragility", "title": "Large TCB & Brittle Allowlists", "body": "Any OEM firmware vuln compromises early boot before OS starts", "theme": "red", "dashed": True, "in_arrow": True},
            ],
        },
        right={
            "label": "DRTM Plane · PCR[17..22] (Locality 4)",
            "theme": "green",
            "cards": [
                {"tag": "CPU Hardware Instruction", "title": "GETSEC[SENTER] (Intel) / SKINIT (AMD)", "body": "Blocks DMA/SMI, resets PCR[17..22] via Locality 4 hardware wire", "theme": "white", "in_arrow": True},
                {"tag": "Small Signed Anchor", "title": "CPU Measured ACM / SLB ->PCR[17]", "body": "Vendor-signed silicon init module establishes clean execution state", "theme": "white", "in_edge": "hardware measurement"},
                {"tag": "VBS Launch", "title": "tcblaunch.exe -> hvix64.exe -> PCR[18]", "body": "Boots Hyper-V & VTL1 Secure Kernel directly from clean DRTM root", "theme": "green", "in_edge": "launches VBS"},
            ],
        },
        bridges=[(1, 0, "lr", "late launch", "teal")],
        boundary_label="DRTM Re-Roots Trust",
        footer="DRTM removes early OEM UEFI drivers from the VBS trust chain by re-establishing a clean hardware-measured root mid-boot."
    )

    # 14. Ch 4: 03-measured-boot-bitpixie-leak.svg
    build_vertical_flow(
        P("03-measured-boot-bitpixie-leak.svg"),
        "Bitpixie (CVE-2023-21563): Extracting VMK Without Breaking TPM PCRs",
        [
            {"tag": "Step 1 · Attacker BCD Edit", "title": "Modify Unencrypted BCD / PXE Boot Configuration", "body": "Physical/LAN attacker sets soft-reboot PXE fallback targeting older Microsoft-signed bootmgfw.efi", "theme": "amber"},
            {"tag": "Step 2 · Valid TPM Unseal", "title": "PCR[7] & PCR[11] Match Default UEFI Profile", "body": "Downgraded bootmgfw.efi is signed by same Production PCA 2011; TPM legitimately unseals VMK into RAM", "theme": "slate", "edge_label": "PCR[7, 11] valid"},
            {"tag": "Step 3 · Lifecycle Bug", "title": "PXE Soft Reboot Leaves Unsealed VMK in Physical DRAM", "body": "Pre-patch bootmgr jumps to alternate boot app without scrubbing VMK bytes or resetting platform RAM", "theme": "red", "edge_label": "CVE-2023-21563 (no RAM wipe)"},
            {"tag": "Step 4 · Extraction", "title": "Signed Linux Shim / WinPE Scans RAM for -FVE-FS-", "body": "Recovers live BitLocker VMK and decrypts NTFS volume offline", "theme": "red", "edge_label": "dumps warm DRAM"},
        ],
        footer="Closed by KB5025885 bootloader revocations, KB5034957 WinRE updates, or requiring a BitLocker pre-boot PIN."
    )

    # 15. Ch 5: 04-attestation-windows-flow.svg
    build_sequence(
        P("04-attestation-windows-flow.svg"),
        "Production Windows Measured Boot Attestation Pipeline",
        [
            {"title": "TPM 2.0 / Pluton", "sub": "Restricted AIK + PCRs", "theme": "slate"},
            {"title": "Windows Client", "sub": "HealthAttestation CSP", "theme": "teal"},
            {"title": "Attestation Verifier", "sub": "HAS / Azure Attestation", "theme": "purple"},
            {"title": "MDM & Policy PDP", "sub": "Intune + Entra CA", "theme": "amber"},
        ],
        [
            (2, 1, "1 · Fresh cryptographic nonce challenge", "purple", False),
            (1, 0, "2 · TPM2_Quote(AIK, PCR[0..7,11..14], nonce)", "teal", False),
            (0, 1, "3 · Signed TPMS_ATTEST (0xFF544347) + signature", "slate", False),
            (1, 2, "4 · Quote + AIK cert + raw WBCL binary log", "teal", False),
            (2, 2, "5 · Verify AIK chain, nonce, & replay WBCL == pcrDigest", "purple", False),
            (2, 3, "6 · Signed JWT posture claims (SecureBoot, HVCI, ELAM)", "green", False),
            (3, 1, "7 · isCompliant = true -> Conditional Access grants token", "amber", False),
        ],
        footer="The WBCL log is unauthenticated on disk, but any forged WBCL entry fails hash-replay verification against the AIK-signed PCR quote."
    )

    # 16. Ch 5: 04-attestation-privacy-ca-vs-daa.svg
    build_split_domains(
        P("04-attestation-privacy-ca-vs-daa.svg"),
        "Remote Hardware Anonymity: Brokered Privacy CA vs. Zero-Knowledge ECDAA",
        left={
            "label": "Shipping Enterprise Model: Privacy CA",
            "theme": "teal",
            "cards": [
                {"tag": "Step 1 · Enrollment", "title": "Send EKCert + Restricted AKPub to CA", "body": "MAA or AD CS validates TPM vendor EK certificate chain", "theme": "white", "in_arrow": True},
                {"tag": "Step 2 · Challenge", "title": "TPM2_MakeCredential -> ActivateCredential", "body": "Secret encrypted to EKPub and bound to Name(AKPub); only co-resident TPM unwraps", "theme": "white", "in_edge": "co-residency proof"},
                {"tag": "Step 3 · Operational Trade-Off", "title": "Simple ECDSA/RSA Quotes; Trusted Broker", "body": "Verifier sees AKCert (not EK), while the CA/MAA broker enforces privacy by policy", "theme": "green", "in_edge": "issues AKCert / JWT"},
            ],
        },
        right={
            "label": "TCG Academic Alternative: ECDAA",
            "theme": "purple",
            "cards": [
                {"tag": "Step 1 · One-Time Blind Join", "title": "Issuer Certifies Hidden Secret f Blindly", "body": "Bilinear pairing credential (A, B, C, D) issued without learning f", "theme": "white", "in_arrow": True},
                {"tag": "Step 2 · Split Sign", "title": "TPM2_Commit + Zero-Knowledge Proof", "body": "Host randomizes credential and proves validity without revealing identity", "theme": "white", "in_edge": "blind randomization"},
                {"tag": "Step 3 · Why Production Skipped It", "title": "Complex Pairing Curves (BN_P256) & Rogue-Key Lists", "body": "Barreto-Naehrig curve weakness + revocation complexity kept Windows on AKs", "theme": "amber", "dashed": True, "in_edge": "unlinkable signature"},
            ],
        },
        footer="Enterprise Windows favors deterministic EK->AK activation (MAA / HealthAttestation) because manageability and fleet inventory outweigh anonymous group signatures."
    )

    # 17. Ch 6: 07-hypervisor-hyperv-stack.svg
    build_fan_bands(
        P("07-hypervisor-hyperv-stack.svg"),
        "Hyper-V Type-1 Micro-Kernel Partitioning Architecture",
        [
            [
                {"id": "root", "tag": "Root Partition (Host OS)", "title": "Full Windows Kernel + VSPs + vmwp.exe", "body": "Owns physical drivers, vmswitch.sys, ACPI/PCI, and per-VM worker processes; isolated from hypervisor Ring -1", "theme": "teal", "w_weight": 1.25},
                {"id": "child", "tag": "Child Partition (Guest VM)", "title": "Guest OS + Enlightenment VSCs", "body": "Synthetic NIC/Storage VSCs communicate over shared-memory VMBus + SynIC interrupts without hardware emulation", "theme": "slate", "w_weight": 1.0},
            ],
            [{"id": "hv", "tag": "Ring -1 (VMX Root / SVM Host)", "title": "Microsoft Hypervisor (hvix64.exe / hvax64.exe)", "body": "Minimal ~1.5 MB TCB: owns only vCPU scheduling, SLAT (EPT/NPT) page tables, IOMMU DMA remapping, and hypercalls", "theme": "amber", "w_weight": 1.0}],
            [{"id": "hw", "tag": "Silicon", "title": "x86-64 / ARM64 CPU + VT-x/AMD-V + SLAT + IOMMU (VT-d / AMD-Vi)", "body": "Hardware enforces memory and DMA isolation between partitions", "theme": "stone", "w_weight": 1.0}],
        ],
        [
            ("root", "hv", "hypercalls (VMCALL)", "teal", False),
            ("child", "hv", "VMBus / SynIC", "slate", False),
            ("hv", "hw", "owns VMX / SLAT", "amber", False),
        ],
        footer="Moving device emulation out of Ring -1 into Root Partition VSPs kept hvix64.exe small enough to anchor Virtualization-Based Security."
    )

    # 18. Ch 6: 05-secure-kernel-vtl-architecture.svg
    build_split_domains(
        P("05-secure-kernel-vtl-architecture.svg"),
        "Virtualization-Based Security (VBS): VTL0 Normal World vs. VTL1 Secure World",
        left={
            "label": "VTL0 · Normal World (Untrusted by VTL1)",
            "theme": "amber",
            "cards": [
                {"tag": "VTL0 Ring 3", "title": "Win32 Apps, Services, & lsass.exe", "body": "Standard user processes, browsers, and protocol brokers", "theme": "white"},
                {"tag": "VTL0 Ring 0", "title": "NT Kernel (ntoskrnl.exe) & 3rd-Party Drivers", "body": "Assumed compromisable via BYOVD or kernel 0-day; cannot map VTL1 RAM", "theme": "red", "dashed": True, "in_arrow": True},
            ],
        },
        right={
            "label": "VTL1 · Secure World (Isolated TCB)",
            "theme": "green",
            "cards": [
                {"tag": "VTL1 Ring 3 · IUM", "title": "Isolated User Mode Trustlets", "body": "LsaIso.exe (Credential Guard), BioIso.exe (ESS), KeyIso, VBS Enclaves", "theme": "white"},
                {"tag": "VTL1 Ring 0", "title": "Secure Kernel (securekernel.exe + skci.dll)", "body": "Enforces HVCI W^X over VTL0 and mediates every VTL0<->VTL1 transition", "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[(1, 1, "both", "Secure Call (VMCALL)", "teal")],
        boundary_label="SLAT Memory Wall",
        foundation={
            "tag": "Ring -1 Authority",
            "title": "Hyper-V Hypervisor + Per-VTL SLAT (EPT / NPT) + MBEC",
            "body": "Maintains separate nested page tables per VTL: VTL1 physical frames are unmapped in VTL0's SLAT",
            "theme": "slate",
            "left_label": "restricts VTL0 RWX",
            "right_label": "protects VTL1 RAM",
        },
        footer="Even full Ring 0 arbitrary read/write in VTL0 triggers an immediate hardware EPT/NPT fault if directed at VTL1 physical pages."
    )

    # 19. Ch 6: 07-hypervisor-slat-double-walk.svg
    build_split_domains(
        P("07-hypervisor-slat-double-walk.svg"),
        "Per-VTL SLAT Double Page Walk for a Protected Guest Physical Page (G)",
        left={
            "label": "Compromised VTL0 Kernel Attempt",
            "theme": "red",
            "cards": [
                {"tag": "Walk 1 · VTL0 CR3", "title": "Forged VTL0 PTE Maps GVA -> GPA (G)", "body": "Malicious VTL0 Ring 0 driver crafts guest page table pointing at LsaIso's GPA G", "theme": "white", "in_arrow": True},
                {"tag": "Walk 2 · VTL0 SLAT", "title": "Hypervisor VTL0 EPT/NPT Entry = NO ACCESS", "body": "Hardware nested page walk finds Read=0, Write=0, Exec=0 for GPA G in VTL0's SLAT", "theme": "white", "in_edge": "CPU consults VTL0 EPT"},
                {"tag": "Outcome", "title": "EPT / NPT Violation (#VE / VMEXIT)", "body": "CPU aborts memory read in silicon before cache line is ever returned", "theme": "red", "in_arrow": True},
            ],
        },
        right={
            "label": "Authorized VTL1 Secure Kernel Access",
            "theme": "green",
            "cards": [
                {"tag": "Walk 1 · VTL1 CR3", "title": "Secure Kernel Maps VTL1 GVA -> GPA (G)", "body": "securekernel.exe or LsaIso.exe accesses its isolated secret buffer", "theme": "white", "in_arrow": True},
                {"tag": "Walk 2 · VTL1 SLAT", "title": "Hypervisor VTL1 EPT/NPT Maps GPA (G) -> HPA", "body": "More permissive VTL1 SLAT tree grants R/W access to physical DRAM frame", "theme": "white", "in_edge": "CPU consults VTL1 EPT"},
                {"tag": "Outcome", "title": "Memory Access Retires Cleanly", "body": "Same physical RAM, governed by two distinct hardware SLAT trees", "theme": "green", "in_arrow": True},
            ],
        },
        footer="VTL0 owns its own guest page tables (CR3), but Hyper-V owns SLAT: forging a VTL0 PTE cannot grant access to unmapped physical RAM."
    )

    # 20. Ch 6: 17-vbs-trustlets-five-gates.svg
    build_vertical_flow(
        P("17-vbs-trustlets-five-gates.svg"),
        "Five Load-Time Gates Admitting an Isolated User Mode (IUM) Trustlet",
        [
            {"tag": "Gate 1 · Process Creation", "title": "PROC_THREAD_ATTRIBUTE_SECURE_PROCESS", "body": "VTL0 caller passes secure-process attribute to NtCreateUserProcess; Secure Kernel intercepts creation", "theme": "slate"},
            {"tag": "Gate 2 · Cryptographic Verification", "title": "skci.dll Verifies Image Page Hashes Inside VTL1", "body": "Validates PE image integrity in VTL1 memory so VTL0 cannot swap pages post-check (no TOCTOU)", "theme": "teal", "edge_label": "verified in VTL1"},
            {"tag": "Gate 3 · Signer & Dual EKUs", "title": "Signing Level 12 (WinTcb) + WSCV & IUM EKUs", "body": "Requires Microsoft root + Windows System Component (1.3.6.1.4.1.311.10.3.6) + IUM EKU (.10.3.37)", "theme": "teal"},
            {"tag": "Gate 4 · Policy Metadata (.tpolicy)", "title": "Parse Embedded TrustletIdentity, SVN, & Capabilities", "body": "Extracts unique 64-bit Trustlet Type ID and Security Version Number for anti-rollback sealing", "theme": "amber"},
            {"tag": "Gate 5 · Minimal IUM Runtime", "title": "Isolated Address Space + Per-Trustlet Storage Key", "body": "No Win32k/GUI, no arbitrary DLLs; Secure Kernel derives symmetric sealing key bound to Trustlet ID + SVN", "theme": "green"},
        ],
        footer="Even Microsoft-signed system binaries cannot enter VTL1 unless compiled with .tpolicy metadata and dual IUM EKUs."
    )

    # 21. Ch 6: 17-vbs-trustlets-agent-trustlet-split.svg
    build_split_domains(
        P("17-vbs-trustlets-agent-trustlet-split.svg"),
        "Canonical Agent / Trustlet Split Across the VTL Boundary",
        left={
            "label": "VTL0 Host Agent (lsass / WbioSrvc / ncrypt)",
            "theme": "slate",
            "cards": [
                {"tag": "Complex Surface", "title": "Network, ASN.1, RPC, & Device I/O", "body": "Handles sockets, Kerberos/NTLM wire framing, Thread pool, and Win32 service plumbing", "theme": "white"},
                {"tag": "Opaque Handle Only", "title": "Encrypted Ciphertext Blob", "body": "Holds wrapped key blob unusable without VTL1 trustlet invocation", "theme": "amber", "in_arrow": True},
            ],
        },
        right={
            "label": "VTL1 IUM Trustlet (LsaIso / BioIso / ProvIso)",
            "theme": "green",
            "cards": [
                {"tag": "Minimal Code", "title": "Narrow Cryptographic / Matcher Logic", "body": "Tiny attack surface executing deterministic crypto or biometric template comparison", "theme": "white"},
                {"tag": "Isolated Secret", "title": "Plaintext Keys & Templates in VTL1 RAM", "body": "Never exported across ALPC; returns only derived signature or match verdict", "theme": "green", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "ALPC / Secure Call request", "teal"),
            (1, 1, "rl", "signed output / verdict only", "green"),
        ],
        boundary_label="Secure Kernel Marshaling",
        footer="Keeping parsers in VTL0 shrinks VTL1 to a few thousand lines of auditable code, trading raw secret theft for an authorized-use oracle."
    )

    # 22. Ch 7: 20-authenticode-signature-nest.svg
    build_fan_bands(
        P("20-authenticode-signature-nest.svg"),
        "PE Authenticode Structural Hash & PKCS #7 SignedData Nesting",
        [
            [
                {"id": "pe", "tag": "Portable Executable (PE/COFF)", "title": "Hashed Image Sections (.text, .rdata, headers)", "body": "Authenticode SHA-256 omits exactly 3 regions: Optional Header Checksum, DataDirectory[SECURITY] entry, and trailing Certificate Table bytes", "theme": "slate"},
            ],
            [
                {"id": "wc", "tag": "File Offset (Not Mapped RVA)", "title": "WIN_CERTIFICATE -> PKCS #7 SignedData", "body": "ASN.1 DER container holding X.509 cert chain, SignerInfo, and authenticated attributes", "theme": "teal"},
            ],
            [
                {"id": "spc", "tag": "eContent (1.3.6.1.4.1.311.2.1.4)", "title": "SpcIndirectDataContent", "body": "Carries canonical PE image digest + optional per-page hashes for HVCI", "theme": "green"},
                {"id": "chain", "tag": "certificates", "title": "X.509 Signer -> Root + EKUs", "body": "Chains to Microsoft / WHQL / Code Signing Root with EKU constraints", "theme": "purple"},
                {"id": "ts", "tag": "unauthenticatedAttributes", "title": "RFC 3161 Timestamp Token", "body": "Proves signature existed before cert expiry (lifetime signing)", "theme": "amber"},
            ],
        ],
        [
            ("pe", "wc", "DataDirectory[4]", "slate", False),
            ("wc", "spc", "signs digest", "green", False),
            ("wc", "chain", "bundles certs", "purple", False),
            ("wc", "ts", "countersigns", "amber", False),
        ],
        footer="CVE-2013-3900 exploited unhashed padding appended after WIN_CERTIFICATE; EnableCertPaddingCheck enforces strict zero-padding."
    )

    # 23. Ch 7: 06-code-integrity-hvci-vtl-split.svg
    build_split_domains(
        P("06-code-integrity-hvci-vtl-split.svg"),
        "Code Integrity Split Under HVCI: ci.dll (VTL0) vs. skci.dll (VTL1)",
        left={
            "label": "VTL0 · Normal Kernel",
            "theme": "amber",
            "cards": [
                {"tag": "Image Loader", "title": "ntoskrnl.exe + ci.dll", "body": "Requests section creation when loading drivers or executables; cannot mark kernel pages executable on its own", "theme": "white", "in_arrow": True},
                {"tag": "KDP Protected Data", "title": "g_CiOptions Policy Variable", "body": "Locked read-only in VTL0 SLAT via Kernel Data Protection so BYOVD cannot zero DSE", "theme": "slate", "in_arrow": True},
            ],
        },
        right={
            "label": "VTL1 · Secure Kernel",
            "theme": "green",
            "cards": [
                {"tag": "Authoritative Verifier", "title": "securekernel.exe + skci.dll", "body": "Validates PE page hashes, KMCS root, WDAC SiPolicy.p7b, and Driver Blocklist inside VTL1", "theme": "green", "in_arrow": True},
                {"tag": "SLAT W^X Enforcement", "title": "Immutable Executable Pages", "body": "Instructs hypervisor to grant SLAT Execute only after stripping SLAT Write", "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[(0, 0, "lr", "VMCALL: verify section", "teal")],
        boundary_label="VTL0 / VTL1 Boundary",
        foundation={
            "tag": "Hardware Enforcement",
            "title": "Hyper-V SLAT (EPT / NPT + MBEC)",
            "body": "Enforces W^X across all kernel physical frames and blocks VTL0 writes to g_CiOptions",
            "theme": "slate",
            "left_label": "traps g_CiOptions writes",
            "right_label": "programs EPT X-bit",
        },
        footer="Pre-HVCI, DSE lived entirely in VTL0 RAM (defeated by zeroing g_CiOptions); HVCI moves the verdict and page permissions across SLAT."
    )

    # 24. Ch 7: 06-code-integrity-five-gates.svg
    build_vertical_flow(
        P("06-code-integrity-five-gates.svg"),
        "Layered Windows Driver & Executable Admission Funnel",
        [
            {"tag": "Candidate Binary", "title": "Driver (.sys) or Executable (.exe / .dll) Load Request", "body": "NtLoadDriver or NtCreateSection(SEC_IMAGE) enters kernel loader", "theme": "slate"},
            {"tag": "Gate 1 · Identity", "title": "KMCS / Authenticode Chain & Page-Hash Check", "body": "Verifies cryptographic integrity and Microsoft / WHQL / Attestation root", "theme": "slate"},
            {"tag": "Gate 2 · Known-Bad Denylist", "title": "Microsoft Vulnerable Driver Blocklist (DriverSiPolicy.p7b)", "body": "Default-on since Win 11 22H2; blocks known BYOVD hashes and certs", "theme": "amber"},
            {"tag": "Gate 3 · Memory Safety", "title": "HVCI / SKCI (VTL1 W^X & No Unsigned RWX)", "body": "Blocks drivers that allocate RWX pool memory or self-modify code", "theme": "teal"},
            {"tag": "Gate 4 · Enterprise Allowlist", "title": "App Control for Business (WDAC) / Smart App Control", "body": "Restricts execution to explicitly approved enterprise signers, paths, or ISG", "theme": "green"},
            {"tag": "Residual Surface", "title": "Signed Zero-Day BYOVD & Allowed LOLBins", "body": "Validly signed drivers not yet blocklisted or signed tools (msbuild.exe) interpreting untrusted input", "theme": "red", "dashed": True, "edge_label": "survives static checks", "edge_color": "#8d2d3b"},
        ],
        side_notes={
            1: {"tag": "Rejected", "title": "Unsigned / Tampered", "body": "Blocked by CI", "theme": "red", "edge_label": "fail"},
            2: {"tag": "Rejected", "title": "Known LOLDriver", "body": "Blocked by hash/cert", "theme": "red", "edge_label": "match"},
            4: {"tag": "Rejected", "title": "Unapproved Publisher", "body": "Blocked by WDAC", "theme": "red", "edge_label": "not allowed"},
        },
        footer="Static code signing proves publisher provenance at load time; by Rice's theorem it cannot decide runtime safety."
    )

    # 25. Ch 7: 21-app-control-publisher-gate.svg
    build_split_domains(
        P("21-app-control-publisher-gate.svg"),
        "The Publisher-Allowlist Blind Spot: Load-Time Identity vs. Runtime Behavior",
        left={
            "label": "1 · Policy-Evaluation Time (NtCreateSection)",
            "theme": "green",
            "cards": [
                {"tag": "Signed Binary", "title": "msbuild.exe / powershell.exe / cdb.exe", "body": "Valid Microsoft Authenticode signature chaining to Microsoft Root; matches enterprise publisher allow rule", "theme": "white"},
                {"tag": "CI Verdict", "title": "ALLOW: Mapped as Trusted Image", "body": "Every fact ci.dll / skci.dll inspects is fixed before main() runs", "theme": "green", "in_edge": "passes WDAC"},
            ],
        },
        right={
            "label": "2 · Post-Entry Runtime Execution",
            "theme": "red",
            "cards": [
                {"tag": "Data Input", "title": "Reads Untrusted Project / Script / Command File", "body": "msbuild.exe parses attacker XML InlineTask and compiles arbitrary C# in-memory", "theme": "white"},
                {"tag": "Security Gap", "title": "Attacker Logic Runs Inside Trusted Process", "body": "Requires Microsoft Recommended Block Rules + AMSI / Constrained Language Mode", "theme": "red", "in_edge": "executes payload"},
            ],
        },
        bridges=[(1, 0, "lr", "entry point runs", "amber")],
        boundary_label="Static vs. Dynamic Horizon",
        footer="Closing LOLBins requires pairing App Control publisher policy with Microsoft's LOLBin blocklist rules and script Enlightened Enforcement."
    )

    # 26. Ch 7: 21-app-control-threat-quadrant.svg
    c = SvgCanvas(840, 470)
    y = c.add_header("Application Control Design Space: Admin Resistance vs. Per-User Granularity") + 16
    ax_x, ax_y = 110.0, y + 10.0
    pw, ph = 670.0, 330.0
    c.add_rect(ax_x, ax_y, pw, ph, fill="#faf8f5", stroke="#bfb8ad", rx=6, layer="bg")
    c.add_line(ax_x + pw / 2, ax_y, ax_x + pw / 2, ax_y + ph, color="#cbd5e1", width=1.3, dash="5,4", layer="bg")
    c.add_line(ax_x, ax_y + ph / 2, ax_x + pw, ax_y + ph / 2, color="#cbd5e1", width=1.3, dash="5,4", layer="bg")

    cw, ch = pw / 2 - 44.0, ph / 2 - 36.0
    c.add_card(ax_x + 22, ax_y + 18, cw, h=ch, tag="Serviced Security Boundary",
               title="App Control for Business (WDAC)", body="Machine-wide, kernel + user mode, signed SiPolicy.p7b + HVCI resists local Admin",
               theme="green", align="center")
    c.add_card(ax_x + pw / 2 + 22, ax_y + 18, cw, h=ch, tag="No Single Control",
               title="Run WDAC + AppLocker Together", body="Use WDAC as machine-wide admin-resistant floor and AppLocker for per-user / group scoping",
               theme="purple", dashed=True, align="center")
    c.add_card(ax_x + 22, ax_y + ph / 2 + 18, cw, h=ch, tag="Consumer / Unmanaged",
               title="Smart App Control (SAC)", body="ISG cloud reputation + signature gate on clean Win 11 installs; one-way off switch",
               theme="teal", align="center")
    c.add_card(ax_x + pw / 2 + 22, ax_y + ph / 2 + 18, cw, h=ch, tag="Defense-in-Depth Only",
               title="AppLocker (appid.sys + appidsvc)", body="Per-SID/group rules without PKI, but local Admin stops service or edits registry rules",
               theme="amber", align="center")

    c.add_text(ax_x + pw / 4, ax_y + ph + 22, "Machine-Wide Policy", size=10.5, fill="#365378", bold=True, anchor="middle")
    c.add_text(ax_x + 3 * pw / 4, ax_y + ph + 22, "Per-User / Group Scoping", size=10.5, fill="#365378", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + ph / 4, "Admin-", size=10.2, fill="#2b6a4c", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + ph / 4 + 14, "Resistant", size=10.2, fill="#2b6a4c", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + 3 * ph / 4, "Admin", size=10.2, fill="#875a14", bold=True, anchor="middle")
    c.add_text(54.0, ax_y + 3 * ph / 4 + 14, "Bypassable", size=10.2, fill="#875a14", bold=True, anchor="middle")
    c.height = ax_y + ph + 46.0
    c.save(P("21-app-control-threat-quadrant.svg"))

    # 27. Ch 8: 18-ppl-signer-lattice.svg
    rungs = [
        ("None (Unprotected)", "Standard Admin / SYSTEM"),
        ("PPL · Authenticode", "Signer = 1"),
        ("PPL · Antimalware", "Signer = 3 (Defender / EDR)"),
        ("PPL · Lsa", "Signer = 4 (lsass.exe)"),
        ("PPL · Windows", "Signer = 5 (services)"),
        ("PPL · WinTcb", "Signer = 6 (csrss / smss)"),
    ]
    cols = [("None", "rung 0"), ("Authenticode", "rung 1"), ("Antimalware", "rung 3"),
            ("Lsa", "rung 4"), ("Windows", "rung 5"), ("WinTcb", "rung 6")]
    ppl_cells = []
    for r in range(6):
        row = []
        for col_i in range(6):
            if r >= col_i:
                row.append(("FULL", "green" if r > col_i else "teal"))
            else:
                row.append(("STRIPPED", "red"))
        ppl_cells.append(row)
    build_matrix(
        P("18-ppl-signer-lattice.svg"),
        "Protected Process Light (_PS_PROTECTION) Signer Dominance Matrix",
        "Caller row opens Target column with full mask (PROCESS_VM_READ / WRITE) iff Caller Rung >= Target Rung",
        rungs, cols, ppl_cells,
        "FULL = full access mask survives RtlTestProtectedAccess to DACL check. STRIPPED = VM read/write/inject bits removed before SeAccessCheck."
    )

    # 28. Ch 8: 18-ppl-access-check.svg
    build_vertical_flow(
        P("18-ppl-access-check.svg"),
        "Inside NtOpenProcess: Why SeDebugPrivilege Cannot Open a PPL Target",
        [
            {"tag": "Caller (Unprotected SYSTEM)", "title": "OpenProcess(PROCESS_VM_READ, lsass_pid)", "body": "Admin tool enables SeDebugPrivilege and requests VM read access to PPL-protected lsass.exe", "theme": "slate"},
            {"tag": "Step 1 · Kernel Object Open", "title": "NtOpenProcess -> PspProcessOpen", "body": "Compares caller _EPROCESS.Protection (0x00) against target lsass.exe Protection (0x41 PPL-Lsa)", "theme": "teal"},
            {"tag": "Step 2 · Protection Filter", "title": "RtlTestProtectedAccess Strips Forbidden Mask Bits", "body": "Removes PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_DUP_HANDLE, and PROCESS_CREATE_THREAD; only QUERY_LIMITED_INFORMATION survives", "theme": "amber", "edge_label": "rung 0 < rung 4"},
            {"tag": "Step 3 · Standard Reference Monitor", "title": "SeAccessCheck Evaluates DACL & SeDebugPrivilege", "body": "SeDebugPrivilege runs AFTER mask stripping and cannot restore access bits already forbidden by PPL", "theme": "slate"},
            {"tag": "Result", "title": "STATUS_ACCESS_DENIED (0xC0000022)", "body": "User-mode handle open fails; attacker is forced to seek a Ring 0 BYOVD driver", "theme": "red"},
        ],
        footer="PPL enforces signer dominance in PspProcessOpen prior to SeAccessCheck, neutralizing user-mode SeDebugPrivilege."
    )

    # 29. Ch 9: 19-mitigations-cfg-pipeline.svg
    build_vertical_flow(
        P("19-mitigations-cfg-pipeline.svg"),
        "Control Flow Guard (CFG / XFG) Compile-to-Runtime Pipeline",
        [
            {"tag": "1 · MSVC Compiler (/guard:cf)", "title": "Emit Guard Check Before Every Indirect Call", "body": "Replaces raw call rax with call [__guard_dispatch_icall_fptr] passing target in RAX (and 55-bit type hash in R10 under XFG)", "theme": "slate"},
            {"tag": "2 · Linker (/GUARD:CF + /DYNAMICBASE)", "title": "Build Sorted Guard CF Function Table (GFIDS)", "body": "Records RVA of every valid address-taken function in IMAGE_LOAD_CONFIG_DIRECTORY (no-op if /DYNAMICBASE omitted)", "theme": "slate"},
            {"tag": "3 · Kernel / NTDLL Image Loader", "title": "Populate Sparse Per-Process CFG Bitmap", "body": "Maps 1 bit per 8-byte aligned slot across user virtual address space as DLLs load", "theme": "teal"},
            {"tag": "4 · Runtime Indirect Call", "title": "LdrpValidateUserCallTarget Checks Target Bit", "body": "Indexes CFG bitmap (and XFG prototype hash preceding target function)", "theme": "amber"},
            {"tag": "Bit Clear / Hash Mismatch", "title": "__fastfail(FAST_FAIL_GUARD_ICALL_CHECK_FAILURE)", "body": "Int 0x29 traps directly into kernel (bypassing SEH handlers) with 0xC0000409 termination", "theme": "red", "edge_label": "invalid target", "edge_color": "#8d2d3b"},
        ],
        side_notes={
            3: {"tag": "Valid Target", "title": "Call Proceeds", "body": "Jumps to verified function entry", "theme": "green", "dashed": False, "edge_label": "bit = 1", "edge_color": "#2b6a4c"},
        },
        footer="Forward-edge CFG/XFG constrains indirect calls/jumps; backward-edge Intel CET hardware Shadow Stacks protect RET addresses."
    )

    # 30. Ch 9: 19-mitigations-acg-split.svg
    build_split_domains(
        P("19-mitigations-acg-split.svg"),
        "Arbitrary Code Guard (ACG): Out-of-Process Browser JIT Architecture",
        left={
            "label": "Content Renderer (ACG + CIG Enforced)",
            "theme": "green",
            "cards": [
                {"tag": "Untrusted Input", "title": "Parses DOM, WebAssembly, & JavaScript", "body": "Exposed directly to attacker web payloads; memory corruption assumed possible", "theme": "white"},
                {"tag": "DynamicCodePolicy = Prohibit", "title": "VirtualAlloc(RWX) & VirtualProtect(->RX) Denied", "body": "Kernel blocks creating or modifying executable pages inside renderer", "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "Isolated Out-of-Process JIT Service",
            "theme": "teal",
            "cards": [
                {"tag": "Constrained RPC", "title": "Receives Validated IR / Bytecode", "body": "Never parses raw HTML/DOM; compiles native machine code into shared section", "theme": "white"},
                {"tag": "Read-Execute Mapping", "title": "Maps Immutable RX View Back to Renderer", "body": "Renderer executes JIT pages read-only without ever holding write permission", "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "IPC: bytecode IR", "slate"),
            (1, 1, "rl", "RX section handle", "teal"),
        ],
        boundary_label="Process + ACG Boundary",
        footer="ACG enforces strict W^X across time in user mode: an exploit with arbitrary write in the renderer still cannot mint executable shellcode."
    )

    # 31. Ch 9: 19-mitigations-policy-matrix.svg
    pol_rows = [
        ("DEP + ASLR + HighEntropy", "Baseline foundation"),
        ("CFG / XFG", "Forward-edge CFI"),
        ("CET Shadow Stack", "Backward-edge hardware SSP"),
        ("ACG (DynamicCode)", "Blocks RWX / W->X"),
        ("CIG (Signature)", "Microsoft-signed DLLs only"),
        ("Win32kSystemCallDisable", "Blocks win32k.sys syscalls"),
        ("ChildProcessPolicy", "Blocks spawning cmd/pwsh"),
    ]
    pol_cols = [("Edge Content", "Renderer"), ("Defender", "MsMpEng"), ("lsass.exe", "PPL + VBS"), ("Outlook", "COM/MAPI"), ("Legacy App", "Unmodified")]
    pol_cells = [
        [("ON", "green"), ("ON", "green"), ("ON", "green"), ("ON", "green"), ("ON", "green")],
        [("ON", "green"), ("ON", "green"), ("ON", "green"), ("ON", "green"), ("OPT", "amber")],
        [("ON", "green"), ("ON", "green"), ("ON", "green"), ("OPT", "amber"), ("OPT", "amber")],
        [("ON", "green"), ("OFF (JIT)", "amber"), ("OFF", "stone"), ("OFF (Add-in)", "amber"), ("OFF", "stone")],
        [("ON", "green"), ("ON", "green"), ("ON", "green"), ("PARTIAL", "amber"), ("OFF", "stone")],
        [("ON", "green"), ("OFF", "stone"), ("OFF", "stone"), ("OFF (GUI)", "stone"), ("OFF", "stone")],
        [("ON", "green"), ("OFF", "stone"), ("ON", "green"), ("OFF", "stone"), ("OFF", "stone")],
    ]
    build_matrix(
        P("19-mitigations-policy-matrix.svg"),
        "Process Mitigation Profile Across Representative Windows Processes",
        "Every disabled cell reflects a concrete architectural trade-off (JIT engines, GUI syscalls, or third-party COM plugins)",
        pol_rows, pol_cols, pol_cells,
        "ON = enforced in production. PARTIAL / OPT = conditional or opt-in compatibility mode. OFF = incompatible with process workload."
    )

    # 32. Ch 9: 19-mitigations-bypass-ladder.svg
    build_timeline_spine(
        P("19-mitigations-bypass-ladder.svg"),
        "Seven Generations of Exploit Mitigation vs. Attacker Adaptation",
        [
            {"year": "Gen 1", "tag": "Stack / Heap Shellcode", "title": "Closed by DEP / NX (Hardware Non-Executable Data)", "body": "Residual adaptation: reuse existing executable code chunks via Return-Oriented Programming (ROP).", "theme": "slate"},
            {"year": "Gen 2", "tag": "Fixed-Address Gadgets", "title": "Closed by Mandatory ASLR + High-Entropy 64-Bit Layout", "body": "Residual adaptation: chain an information-disclosure read primitive first to leak a module base pointer.", "theme": "slate"},
            {"year": "Gen 3", "tag": "Corrupted Return Addresses", "title": "Closed by Intel CET / AMD Shadow Stacks (Hardware SSP)", "body": "Residual adaptation: pivot to forward-edge indirect vtable/function-pointer calls (JOP / COP).", "theme": "teal"},
            {"year": "Gen 4", "tag": "Coarse Indirect Calls", "title": "Closed by CFG Bitmap + XFG Type-Signature Hashes", "body": "Residual adaptation: invoke legitimate prototype-matching functions (VirtualProtect / WinExec) or data-only attacks.", "theme": "teal"},
            {"year": "Gen 5", "tag": "In-Process JIT Spray & RWX", "title": "Closed by Arbitrary Code Guard (ACG) + Code Integrity Guard (CIG)", "body": "Residual adaptation: data-only corruption (modifying privilege/origin booleans in heap) or cross-process sandbox IPC bugs.", "theme": "green"},
            {"year": "Gen 6", "tag": "Kernel Mode CFI", "title": "Hardened by HVCI + kCFG + Kernel CET (kCET)", "body": "Live frontier: signed vulnerable drivers (BYOVD) exposing arbitrary physical/kernel R/W primitives.", "theme": "amber"},
        ],
        footer="Mitigations raise exploit cost from one bug to a multi-primitive chain (info-leak + CFI-compliant + sandbox escape)."
    )
    print("Part 1: Generated and collision-verified 32 diagrams!")
