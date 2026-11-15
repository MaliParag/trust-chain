#!/usr/bin/env python3
"""
Complete 44-diagram SVG suite for The Apple Trust Chain (Volume II),
built on shared tools/diagram_lib.py with 7-way collision verification.
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


def gen_opening():
    # 1. trust-chain-map.svg (Prologue)
    c = SvgCanvas(900, 580)
    y = c.add_header(
        "The 20-Chapter Apple Trust Chain",
        "Unified silicon-to-cloud spine across iOS, iPadOS, macOS, watchOS, and visionOS; forks are explicit policy gates",
    ) + 14
    main_x, main_w = 54.0, 556.0
    side_x, side_w = 652.0, 214.0

    tiers = [
        (
            "Finale · Chapter 20",
            "When Vertical Integration Snaps",
            "Mercenary zero-click parser chains (FORCEDENTRY, Triangulation, DarkSword) & UK IPA s.253 sovereign cloud compulsion",
            "red",
            "parser & legal horizon",
        ),
        (
            "Part IV · Chapters 15 to 19",
            "Zero-Knowledge Cloud & Agentic AI",
            "15. CloudKit & ADP · 16. iMessage PQ3 & KT · 17. Find My P-224 · 18. App Intents, MCP & Micro-VMs · 19. Private Cloud Compute",
            "amber",
            "extends SEP attestation off-device",
        ),
        (
            "Part III · Chapters 10 to 14",
            "Data Custody, Identity, & Fleet Trust",
            "10. APFS Data Protection · 11. Keychain & Stolen Device · 12. SEP/App/ACME Attest · 13. Accounts, Passkeys & R1 Gaze · 14. DDM & Platform SSO",
            "green",
            "binds keys to sealed OS & user state",
        ),
        (
            "Part II · Chapters 5 to 8",
            "XNU, Code Signing, & Containment",
            "5. APFS SSV, Cryptexes & dyld · 6. AMFI, TXM, Launch Constraints & Notarization · 7. Mach/XPC, Seatbelt & BlastDoor · 8. macOS TCC & DriverKit",
            "teal",
            "inherits verified kernel & GL2 monitors",
        ),
        (
            "Part I · Chapters 1 to 4",
            "Silicon & Personalized Boot",
            "1. Boot ROM, iBoot & Image4/TSS · 2. Mac 1TR & LocalPolicy · 3. Secure Enclave (SEP) & Biometrics · 4. PAC, SPTM, Exclaves & A19/M5 EMTE",
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
        col = "#8d2d3b" if idx == 0 else "#365378"
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
    c.add_rect(
        side_x,
        rail_top,
        side_w,
        rail_bot - rail_top,
        fill="#f4f1ea",
        stroke="#524c44",
        stroke_width=1.3,
        rx=8,
        dash="5,3",
        layer="bg",
    )
    c.add_card(
        side_x + 12.0,
        rail_top + 24.0,
        side_w - 24.0,
        tag="Interlude · Chapter 9",
        title="Observing the Stack",
        body="macOS EndpointSecurity & XProtect vs. locked iOS sysdiagnose and Shutdown.log forensics",
        theme="white",
        align="center",
        title_size=11.5,
        body_size=10.0,
    )
    c.add_text(
        side_x + side_w / 2,
        rail_bot - 42.0,
        "Telemetry fork:",
        size=9.8,
        fill="#524c44",
        bold=True,
        anchor="middle",
    )
    c.add_text(
        side_x + side_w / 2,
        rail_bot - 26.0,
        "live ESF on Mac; post-hoc on iOS",
        size=9.6,
        fill="#524c44",
        italic=True,
        anchor="middle",
    )
    for idx in (1, 2, 3, 4):
        mid = ys[idx][0] + ys[idx][1] / 2
        c.add_line(main_x + main_w, mid, side_x, mid, color="#787167", width=1.2, dash="3,3", arrow_end=True)

    c.height = cur_y + 20.0
    c.save(P("trust-chain-map.svg"))

    # 2. 00b-apple-soc-privilege-planes.svg (Foundations)
    build_fan_bands(
        P("00b-apple-soc-privilege-planes.svg"),
        "Apple Silicon SoC Privilege Planes & Co-Processor Isolation",
        [
            [
                {"id": "el0", "tag": "ARM64 EL0", "title": "User Processes & Sandboxed Apps", "body": "Safari WebContent, BlastDoor, UIKit/AppKit apps, DriverKit daemons", "theme": "white"},
                {"id": "gl0", "tag": "Guarded GL0", "title": "TXM Thread Execution", "body": "Trusted Execution Monitor evaluates trust caches and DER entitlements", "theme": "purple"},
            ],
            [
                {"id": "el1", "tag": "ARM64 EL1", "title": "XNU Kernel (Mach + BSD + IOKit)", "body": "Scheduling, IPC, VFS, networking; stripped of raw page-table write authority", "theme": "teal"},
                {"id": "gl2", "tag": "Guarded GL2 / EL2", "title": "SPTM & Virtualization Hypervisor", "body": "Owns physical page-type table and Stage-2/SPRR mappings above XNU", "theme": "slate"},
            ],
            [
                {"id": "fabric", "tag": "Hardware Interconnect & IOMMU", "title": "Coherent SoC Fabric Governed by AppleDART & SART", "body": "Per-engine DMA translation blocks PCIe, USB, Wi-Fi, and GPU engines from reading kernel or SPTM frames", "theme": "amber"},
            ],
            [
                {"id": "sep", "tag": "Isolated Enclave", "title": "Secure Enclave (SEP)", "body": "sepOS microkernel, fused UID/GID AES engine, SKS keybags, anti-replay", "theme": "green"},
                {"id": "excl", "tag": "Tightly Coupled", "title": "Secure Exclaves", "body": "Camera/mic indicator ledger & sensor pipelines isolated from XNU", "theme": "green"},
                {"id": "r1", "tag": "Spatial Co-Processor", "title": "Vision Pro R1", "body": "12 ms photon-to-photon pipeline; isolates raw eye-tracking cameras", "theme": "teal"},
            ],
        ],
        [
            ("el0", "el1", "SVC", "teal", False),
            ("gl0", "gl2", "guarded call", "purple", False),
            ("el1", "fabric", "DMA map req", "slate", False),
            ("gl2", "fabric", "DART frame lock", "slate", False),
            ("fabric", "sep", "mailbox IPC", "green", False),
            ("fabric", "excl", "xnuproxy", "green", False),
            ("fabric", "r1", "compositor feed", "teal", False),
        ],
        footer="Even full EL1 XNU compromise cannot rewrite SPTM page tables in GL2 or extract UID-fused keys from SEP.",
    )

    # 3. 00b-xnu-mach-bsd-macf-stack.svg (Foundations)
    build_split_domains(
        P("00b-xnu-mach-bsd-macf-stack.svg"),
        "XNU Hybrid Architecture: Mach Capabilities vs. BSD POSIX & MACF",
        {
            "label": "Mach Microkernel Core (osfmk/)",
            "theme": "slate",
            "cards": [
                {"tag": "Execution Unit", "title": "task_t & thread_t", "body": "Virtual address space (vm_map_t), IPC port namespace, and ledger quotas", "theme": "white"},
                {"tag": "Capability Rights", "title": "mach_port_t & XPC Channels", "body": "Unforgeable kernel-managed send, send-once, and receive rights", "theme": "white", "in_edge": "owns IPC space"},
                {"tag": "Peer Identity", "title": "audit_token_t", "body": "Kernel-stamped {uid, gid, pid, pidversion, asid} immune to PID reuse", "theme": "teal", "in_edge": "stamps trailer"},
            ],
        },
        {
            "label": "BSD Personality & VFS Layer (bsd/)",
            "theme": "stone",
            "cards": [
                {"tag": "POSIX Process", "title": "proc_t & kauth_cred_t", "body": "PID table, UID/GID credentials, signal masks, sockets, and file descriptors", "theme": "white"},
                {"tag": "Storage & Loader", "title": "VFS, APFS, & Mach-O execve", "body": "Mounts SSV/Data volumes, parses Mach-O load commands, maps dyld", "theme": "white", "in_edge": "resolves vnodes"},
                {"tag": "Policy Callouts", "title": "MACF (mac_policy_ops)", "body": "Mandatory hooks on vnode, proc, cred, port, and mmap operations", "theme": "amber", "in_edge": "invokes hooks"},
            ],
        },
        bridges=[
            (0, 0, "both", "1:1 task <-> proc", "slate"),
            (1, 1, "both", "port <-> fd / vnode", "teal"),
            (2, 2, "lr", "mpo_port / cred check", "amber"),
        ],
        boundary_label="Shared EL1 Address Space",
        foundation={
            "tag": "Loaded MACF Policy Modules",
            "title": "AppleMobileFileIntegrity (AMFI) · Sandbox.kext (Seatbelt) · Quarantine · EndpointSecurity",
            "body": "Every POSIX syscall and gated Mach trap must pass all registered MACF policy modules before XNU commits the operation",
            "theme": "green",
            "left_label": "verifies CS flags",
            "right_label": "enforces SBPL & ESF",
        },
        footer="Mach provides capability-based IPC while BSD provides POSIX semantics; MACF unifies mandatory policy across both.",
    )


def gen_part1():
    # 4. 01-secure-boot-image4-chain.svg
    build_horizontal_pipeline(
        P("01-secure-boot-image4-chain.svg"),
        "Apple Silicon Secure Boot Pipeline & Image4 Manifest Verification",
        [
            {"tag": "Stage 0 · Mask ROM", "title": "Boot ROM", "body": "Immutable silicon code & Apple Root CA pubkey hash", "theme": "slate"},
            {"tag": "Stage 1 · NOR/ANS", "title": "LLB", "body": "Low-Level Bootloader verified via Image4 IM4M", "theme": "slate"},
            {"tag": "Stage 2 · Loader", "title": "iBoot", "body": "Configures AppleDART, loads SEP fw & BootKC/XNU", "theme": "teal"},
            {"tag": "Stage 3 · Monitors", "title": "SPTM & TXM", "body": "Initializes GL2 page tables & static trust caches", "theme": "purple"},
            {"tag": "Stage 4 · Kernel", "title": "XNU & SSV", "body": "Verifies APFS root seal hash from Image4 ticket", "theme": "green"},
        ],
        under_anchor={
            "target_idx": 1,
            "tag": "Per-Device Image4 Container",
            "title": "IMG4 = IM4P (Payload) + IM4M (TSS Signed Manifest) + IM4R (BNCH Nonce)",
            "body": "Binds payload SHA-384 digest to chip ECID, board/chip ID, security domain, and boot nonce",
            "theme": "amber",
            "edge_label": "evaluates DER tags",
        },
        footer="Every stage refuses to execute the next unless its IM4M signature chains to the Boot ROM root and matches this chip's ECID.",
    )

    # 5. 01-tss-apnonce-personalization.svg
    build_sequence(
        P("01-tss-apnonce-personalization.svg"),
        "TSS Per-Device Firmware Personalization & Anti-Replay Protocol",
        [
            {"title": "Restore Host / OTA", "sub": "Finder, Configurator, or softwareupdated", "theme": "stone"},
            {"title": "Target SoC (iBoot/DFU)", "sub": "Unique 64-bit ECID", "theme": "slate"},
            {"title": "Secure Enclave (SEP)", "sub": "Hardware TRNG & Nonce", "theme": "green"},
            {"title": "Apple TSS Server", "sub": "Live Signing Authority", "theme": "teal"},
        ],
        [
            (0, 1, "Query device identity & boot nonce", "slate", False),
            (1, 2, "Roll fresh random generator -> BNCH", "green", False),
            (2, 1, "Return ApNonce = SHA-384(generator) & SepNonce", "green", False),
            (1, 0, "Report ECID, ChipID, ApNonce, SepNonce", "slate", False),
            (0, 3, "POST BuildManifest digests + ECID + ApNonce", "teal", False),
            (3, 3, "Verify build is currently signed; sign IM4M", "teal", False),
            (3, 0, "Return per-ECID Apticket (IM4M)", "teal", True),
            (0, 1, "Write IM4P + personalized IM4M to boot storage", "green", False),
        ],
        boundary_after=2,
        boundary_label="Device / Cloud Signing Boundary",
        bottom_note={
            "tag": "Downgrade Prevention Invariant",
            "title": "Captured SHSH / IM4M Tickets Cannot Replay Once ApNonce Rotates or TSS Closes the Signing Window",
            "body": "Unlike x86 UEFI dbx denylists that must enumerate every vulnerable binary, TSS ceases issuing tickets for superseded builds globally.",
            "theme": "amber",
        },
    )

    # 6. 02-mac-1tr-security-modes.svg
    build_fan_bands(
        P("02-mac-1tr-security-modes.svg"),
        "The Apple Silicon Mac Fork: Startup Security Policy Tiers",
        [
            [
                {"id": "rom", "tag": "Unchanged Hardware Root", "title": "Immutable Boot ROM + One True Recovery (1TR)", "body": "Long-press physical power button measurement guarantees genuine paired recoveryOS before security policy changes", "theme": "slate"},
            ],
            [
                {"id": "full", "tag": "Default Tier", "title": "Full Security", "body": "Requires live TSS-personalized BootKC & SSV seal; matches iOS anti-downgrade guarantees", "theme": "green"},
                {"id": "red", "tag": "Enterprise / Kext Tier", "title": "Reduced Security", "body": "Permits older Apple-signed macOS builds and owner-approved third-party kexts linked into AuxKC", "theme": "amber"},
                {"id": "perm", "tag": "Developer / Custom OS Tier", "title": "Permissive Security", "body": "Disables Apple kernel signature mandate; boots custom XNU builds or Asahi Linux m1n1 payloads", "theme": "red"},
            ],
            [
                {"id": "lp", "tag": "Per-OS Volume State", "title": "SEP-Signed LocalPolicy (IM4M Anchored in OIHR / BAA)", "body": "Records policy flags (sip, ssv, auxkc-hash, custom-kc-hash) scoped solely to one APFS volume group; sibling OS installs stay Full Security", "theme": "teal"},
            ],
        ],
        [
            ("rom", "full", "default", "green", False),
            ("rom", "red", "1TR auth", "amber", False),
            ("rom", "perm", "1TR auth", "red", False),
            ("full", "lp", "commits state", "green", False),
            ("red", "lp", "commits AuxKC hash", "amber", False),
            ("perm", "lp", "commits custom hash", "red", False),
        ],
        footer="Mac openness never weakens Boot ROM; every relaxation is an explicit LocalPolicy state signed by this Mac's own SEP.",
    )

    # 7. 02-localpolicy-sep-signing.svg
    build_vertical_flow(
        P("02-localpolicy-sep-signing.svg"),
        "Owner-Authorized LocalPolicy Ratchet Inside One True Recovery (1TR)",
        [
            {"tag": "Step 1 · Physical Intent", "title": "Sustained Power-Button Hold at Cold Boot", "body": "PMU hardware signal routed to iBoot/SEP proves physical button hold; remote root malware cannot spoof 1TR entry", "theme": "slate"},
            {"tag": "Step 2 · Paired OS", "title": "Boot Paired One True Recovery (1TR)", "body": "Loads genuine Apple-signed recoveryOS matching the active System Firmware version", "theme": "slate", "edge_label": "PMU flag = true"},
            {"tag": "Step 3 · Owner Auth", "title": "Verify Volume Owner Credential in SEP", "body": "Startup Security Utility or bputil authenticates Local Admin password / SecureToken against SEP keybag", "theme": "teal", "edge_label": "user credential"},
            {"tag": "Step 4 · Hardware Sign", "title": "SEP Signs New LocalPolicy Image4 Manifest", "body": "OIHR private key inside SEP signs policy digest, previous LocalPolicy hash, and monotonic anti-replay counter", "theme": "green", "edge_label": "authorized"},
            {"tag": "Step 5 · Next Boot", "title": "iBoot Evaluates LocalPolicy Against SEP Counter", "body": "Verifies OIHR signature and monotonic counter before admitting AuxKC or custom Mach-O kernel", "theme": "green", "edge_label": "increment counter"},
        ],
        side_notes={
            0: {"tag": "Blocked", "title": "Normal macOS Reboot", "body": "PMU button-hold bit is clear; SEP refuses to sign security-lowering LocalPolicy transitions from booted macOS", "theme": "red", "edge_label": "no hold"},
            4: {"tag": "Blocked", "title": "Stale Policy Replay", "body": "Restoring an older LocalPolicy file fails SEP monotonic anti-replay check", "theme": "red", "edge_label": "counter mismatch"},
        },
        footer="Chaining LocalPolicy hashes through a SEP monotonic counter prevents offline rollback to a weakened policy.",
    )

    # 8. 03-sep-hardware-architecture.svg
    build_split_domains(
        P("03-sep-hardware-architecture.svg"),
        "Secure Enclave Processor (SEP) Hardware Isolation Boundary",
        {
            "label": "Application Processor (AP) Domain",
            "theme": "stone",
            "cards": [
                {"tag": "User Space", "title": "secd, biometrickitd, & Apps", "body": "Hold opaque wrapped key blobs; never observe raw SEP private keys", "theme": "white"},
                {"tag": "EL1 Kernel Driver", "title": "AppleSEPManager & AppleKeyStore", "body": "Serializes keybag and SKS requests into 64-bit mailbox messages", "theme": "white", "in_edge": "IOKit userclient"},
                {"tag": "Shared System DRAM", "title": "Encrypted SEP Carveout", "body": "Protected by dedicated SEP Memory AES Engine + QARMA/authentication tags", "theme": "amber", "in_edge": "isolated phys range"},
            ],
        },
        {
            "label": "Secure Enclave (SEP) Silicon Island",
            "theme": "green",
            "cards": [
                {"tag": "Persistence & Auth", "title": "SKS Keybags & Anti-Replay Counter", "body": "Unwraps Data Protection & Keychain blobs under hardware passcode backoff", "theme": "white"},
                {"tag": "ROM + Microkernel", "title": "SEPROM & sepOS (L4-Derived)", "body": "Independent boot ROM and PAC-hardened user tasks (sks, sepos, bio)", "theme": "white", "in_edge": "IPC services"},
                {"tag": "Key & Memory Core", "title": "Hardware UID/GID & Memory AES Engine", "body": "Silicon-fused 256-bit UID key + inline DRAM encryption/authentication", "theme": "teal", "in_edge": "key-select bus"},
            ],
        },
        bridges=[
            (0, 0, "lr", "opaque key blobs", "slate"),
            (1, 1, "both", "Hardware Mailbox FIFO", "teal"),
            (2, 2, "rl", "AES+MAC inline engine", "amber"),
        ],
        boundary_label="Hardware Bus & Fuse Wall",
        footer="Even if an exploit compromises sepOS software, the raw UID fuse bits remain unreadable inside the hardware AES key-select engine.",
    )

    # 9. 03-biometric-neural-pipelines.svg
    build_fan_bands(
        P("03-biometric-neural-pipelines.svg"),
        "Hardware-Isolated Biometric Pipelines Across Apple Form Factors",
        [
            [
                {"id": "tid", "tag": "Touch ID (Mac / iPad / SE)", "title": "Capacitive Ridge Sensor", "body": "Mutually authenticated AES-wrapped SPI channel directly from Touch ID sensor IC (or Magic Keyboard enclave) to SEP", "theme": "slate"},
                {"id": "fid", "tag": "Face ID (iPhone / iPad Pro)", "title": "TrueDepth IR + Flood Illuminator", "body": "Dedicated MIPI/ISP path routes IR depth frames through Secure Neural Engine DMA-locked to SEP", "theme": "teal"},
                {"id": "oid", "tag": "Optic ID (Apple Vision Pro)", "title": "IR LED + Eye Cameras via R1", "body": "Spatiotemporal iris capture routed through R1 hardware isolation to SEP Neural Engine descriptor", "theme": "purple"},
            ],
            [
                {"id": "match", "tag": "SEP Biometric Matcher (sepOS)", "title": "Mathematical Descriptor Comparison & Liveness Gate", "body": "Compares incoming feature vector against SEP-encrypted enrollment template (never raw images); enforces 5-fail / 48-hour / BFU fallbacks", "theme": "green"},
            ],
            [
                {"id": "aks", "tag": "Cryptographic Consequence (Not a Boolean)", "title": "SKS Releases Biometric-Bound Keybag / Keychain / Apple Pay Token", "body": "Match directly unwraps key material inside SEP; AP cannot forge a match bit to decrypt user secrets", "theme": "amber"},
            ],
        ],
        [
            ("tid", "match", "encrypted SPI", "slate", False),
            ("fid", "match", "secure ANE bus", "teal", False),
            ("oid", "match", "R1 -> SEP channel", "purple", False),
            ("match", "aks", "releases key slot", "green", False),
        ],
        footer="Biometric authentication succeeds only by releasing cryptographic keys inside SEP, never by returning a spoofable boolean to XNU.",
    )

    # 10. 04-sptm-txm-guarded-domains.svg
    build_vertical_flow(
        P("04-sptm-txm-guarded-domains.svg"),
        "Hardware Page-Table Custody: From XNU Self-Protection to SPTM & TXM",
        [
            {"tag": "Silicon Reset Lock", "title": "KTRR & APRR / SPRR Permission Indirection", "body": "Locks static kernel text in physical memory controller and remaps page permissions via pinned register indices", "theme": "slate"},
            {"tag": "Guarded Root (GL2)", "title": "Secure Page Table Monitor (SPTM)", "body": "Minimal immutable monitor owning physical frame types (XNU_DEFAULT, TXM_TRUSTED, IOMMU_PAGE); arbitrates every mapping change", "theme": "purple", "edge_label": "initializes frame table"},
            {"tag": "Guarded Verifier (GL0)", "title": "Trusted Execution Monitor (TXM)", "body": "Evaluates Mach-O CodeDirectories, trust caches, and DER entitlements outside XNU write reach", "theme": "teal", "edge_label": "delegates CS policy"},
            {"tag": "Deprivileged OS (EL1)", "title": "XNU Kernel & IOKit Drivers", "body": "Requests page mappings via SPTM calls; kernel R/W bugs can no longer forge executable code pages or trust-cache entries", "theme": "slate", "edge_label": "enforces W^X"},
            {"tag": "Isolated Indicators", "title": "Secure Exclaves (Camera / Mic Ledger)", "body": "Hardware-enforced indicator pixels must be lit in display pipeline before sensor DMA buffers unlock", "theme": "green", "edge_label": "xnuproxy RPC"},
        ],
        footer="Replacing in-kernel PPL (A12-A14) with out-of-kernel SPTM + TXM (A15+/M2+) shrinks the page-table TCB to a tiny static binary.",
    )

    # 11. 04-mie-emte-tag-check.svg
    build_vertical_flow(
        P("04-mie-emte-tag-check.svg"),
        "A19 / M5 Memory Integrity Enforcement (MIE): Synchronous EMTE Pipeline",
        [
            {"tag": "Step 1 · Allocation", "title": "kalloc_type / libmalloc Assigns 4-Bit Secret Tag", "body": "Hardware CSPRNG mints random allocation tag T_alloc written to physical Tag RAM and embedded in pointer bits [59:56]", "theme": "slate"},
            {"tag": "Step 2 · Confidentiality", "title": "EMTE Tag-Oracle Suppression", "body": "Blocks speculative timing, cache-line probing, and gadget-based tag readout across EL0/EL1 boundaries", "theme": "purple", "edge_label": "hides tag state"},
            {"tag": "Step 3 · Dereference", "title": "CPU Load / Store Checks Pointer Tag == Granule Tag", "body": "Every 16-byte memory access compares pointer logical tag T_ptr against physical granule tag T_mem in zero-latency hardware", "theme": "teal", "edge_label": "memory access"},
            {"tag": "Step 4 · Valid Access", "title": "Instruction Retires Cleanly", "body": "Spatial bounds and temporal lifecycle match; execution continues at native Apple Silicon throughput", "theme": "green", "edge_label": "T_ptr == T_mem"},
        ],
        side_notes={
            2: {"tag": "Tag Mismatch", "title": "Immediate Synchronous Trap", "body": "Buffer overflow or use-after-free (retagged on free) faults on the exact offending instruction before corrupting state", "theme": "red", "edge_label": "T_ptr != T_mem"},
        },
        footer="Unlike asynchronous MTE reporting modes that allow post-corruption window races, MIE enforces synchronous traps across XNU and 70+ daemons.",
    )


def gen_part2():
    # 12. 05-apfs-ssv-cryptex-tree.svg
    build_fan_bands(
        P("05-apfs-ssv-cryptex-tree.svg"),
        "APFS Signed System Volume (SSV) Merkle Seal & Cryptex Grafting",
        [
            [
                {"id": "im4m", "tag": "Image4 Root Anchor", "title": "TSS-Personalized OS Manifest (IM4M)", "body": "Signed by Apple Root CA (Full Security) or SEP OIHR (LocalPolicy); embeds expected 384-bit APFS Seal Hash", "theme": "slate"},
            ],
            [
                {"id": "snap", "tag": "Immutable Boot Snapshot", "title": "APFS Sealed System Snapshot Root", "body": "Mounted strictly read-only at /; live System volume vnodes are never writable even by UID 0", "theme": "teal"},
                {"id": "cryp", "tag": "Out-of-Band Graft", "title": "Personalized Cryptex1 (OS / Safari / ANE)", "body": "Independent DMG + APFS volume verified via its own TSS Image4 ticket and grafted onto System namespace", "theme": "purple"},
            ],
            [
                {"id": "meta", "tag": "Metadata Tree", "title": "Catalog B-Tree & Extended Attributes", "body": "SHA-256/384 hashes over paths, modes, xattrs, and extent maps", "theme": "white"},
                {"id": "ext", "tag": "Data Extents", "title": "4 KB Physical File Blocks", "body": "Verified on every page-in from NVMe flash before reaching buffer cache", "theme": "white"},
                {"id": "data", "tag": "Mutable Sibling", "title": "APFS Data Volume (/System/Volumes/Data)", "body": "Firmlinked for /Users, /Library, /private/var; unsealed & Data-Protected", "theme": "amber"},
            ],
        ],
        [
            ("im4m", "snap", "pins root digest", "teal", False),
            ("im4m", "cryp", "Cryptex1 ticket", "purple", False),
            ("snap", "meta", "Merkle branch", "teal", False),
            ("snap", "ext", "extent hashes", "teal", False),
            ("cryp", "data", "firmlink overlay", "amber", True),
        ],
        footer="Any single-bit flash modification under / fails SSV page-in verification and triggers an immediate kernel panic or recovery force-restore.",
    )

    # 13. 05-dyld-shared-cache-trust.svg
    build_horizontal_pipeline(
        P("05-dyld-shared-cache-trust.svg"),
        "dyld4 Shared Cache Mapping, PrebuiltLoader, & State Trust Boundary",
        [
            {"tag": "SSV / Cryptex", "title": "dyld_shared_cache", "body": "2,500+ pre-linked OS dylibs & PAC-signed GOT/auth stubs", "theme": "slate"},
            {"tag": "XNU Shared Region", "title": "ASLR Slide Once", "body": "Kernel slides cache once per boot; shares clean pages across all processes", "theme": "teal"},
            {"tag": "Process Startup", "title": "dyld4 Runtime", "body": "Validates PrebuiltLoader closure or builds JustInTimeLoader", "theme": "purple"},
            {"tag": "Hardened State", "title": "TPRO / APRR Read-Only", "body": "Locks loader metadata & authenticated pointers after fixups finish", "theme": "green"},
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Exploited Boundary · CVE-2026-20700",
            "title": "Improper dyld State Management During Writable Window",
            "body": "Corrupting dyld internal loader state from an initial renderer/process write primitive pivots into arbitrary code execution",
            "theme": "red",
            "edge_label": "state corruption",
        },
        footer="Because dyld executes inside every process before main() with pointer-signing authority, its writable fixup window is a prime exploit target.",
    )

    # 14. 06-txm-trustcache-pipeline.svg
    build_vertical_flow(
        P("06-txm-trustcache-pipeline.svg"),
        "Mach-O Code Signing Verification: Trust Caches, TXM, and Page-In Hashes",
        [
            {"tag": "Load / Fault", "title": "Mach-O LC_CODE_SIGNATURE & CS_CodeDirectory", "body": "Embeds per-4KB-page SHA-256 hashes, DER entitlements slot (-7), and CMS signature blob", "theme": "slate"},
            {"tag": "Gate 1 · Platform", "title": "CDHash in Static Trust Cache (BootKC / SSV)?", "body": "TXM checks immutable sorted CDHash array baked into signed OS image", "theme": "teal", "edge_label": "register blob"},
            {"tag": "Gate 2 · Grafts", "title": "CDHash in Dynamic Trust Cache (Cryptex / Developer DDI)?", "body": "Checks Image4-authenticated runtime trust cache payloads", "theme": "teal", "edge_label": "miss -> check dynamic"},
            {"tag": "Gate 3 · Third-Party", "title": "CoreTrust + AMFI / TXM CMS & Provisioning Evaluation", "body": "Verifies Apple CA chain, App Store / Notarization / Provisioning Profile, and allowed DER entitlements", "theme": "purple", "edge_label": "miss -> parse CMS"},
            {"tag": "Runtime VM Enforcement", "title": "Page-Fault Hash Check + CS_HARD / CS_KILL", "body": "vm_fault verifies every executable page against CodeDirectory; invalid pages send immediate SIGKILL", "theme": "green", "edge_label": "admitted"},
        ],
        side_notes={
            3: {"tag": "Rejected", "title": "SIGKILL (CS_INVALID)", "body": "EXEC_EXIT_REASON_CODESIGNING aborts launch on bad CMS or entitlement", "theme": "red", "edge_label": "invalid"},
        },
        footer="Trust caches keep third-party X.509/CMS parsers off the critical path for first-party OS binaries.",
    )

    # 15. 06-launch-constraints-vs-gatekeeper.svg
    build_fan_bands(
        P("06-launch-constraints-vs-gatekeeper.svg"),
        "Software Admission Models Across First-Party Daemons, iOS/EU DMA, and macOS",
        [
            [
                {"id": "lc", "tag": "System Daemons (iOS & macOS)", "title": "Launch & Environment Constraints", "body": "DER boolean rules (self, parent, responsible) encoded in trust cache block copying a signed Apple daemon to /tmp and spawning it outside launchd", "theme": "slate"},
                {"id": "dma", "tag": "iOS App Store & EU DMA", "title": "Mandatory App Review or EU Notarization", "body": "Every iOS binary requires an Apple-countersigned signature; EU Marketplace apps undergo automated malware scan + CoreTrust marketplace binding", "theme": "teal"},
                {"id": "gk", "tag": "macOS General Computing", "title": "Gatekeeper, Quarantine, & Notary Ticket", "body": "syspolicyd checks com.apple.quarantine xattr, Developer ID cert, stapled/online CloudKit notary ticket, and XProtect denylist on first launch", "theme": "amber"},
            ],
            [
                {"id": "txm", "tag": "Unified Kernel Enforcement Floor", "title": "TXM / AMFI + Hardened Runtime (CS_RUNTIME)", "body": "Enforces W^X, library validation (same TeamID or platform dylibs), DYLD_* env stripping, and DER entitlement gates after launch", "theme": "green"},
            ],
        ],
        [
            ("lc", "txm", "kernel spawn gate", "slate", False),
            ("dma", "txm", "CoreTrust profile", "teal", False),
            ("gk", "txm", "syspolicyd verdict", "amber", False),
        ],
        footer="Launch Constraints closed the classic macOS living-off-the-land trick of re-executing entitled system binaries from an untrusted parent.",
    )

    # 16. 07-xpc-audit-token-vs-pid.svg
    build_split_domains(
        P("07-xpc-audit-token-vs-pid.svg"),
        "XPC Client Authentication: Vulnerable pid_t Lookup vs. Kernel audit_token_t",
        {
            "label": "Broken: PID Lookup (TOCTOU)",
            "theme": "red",
            "cards": [
                {"tag": "1 · Malicious Client", "title": "Unprivileged Process (PID 4812)", "body": "Sends XPC privilege request then immediately calls execve() into an Apple-signed binary", "theme": "white"},
                {"tag": "2 · Race Window", "title": "PID 4812 Reused by Trusted Binary", "body": "POSIX PID remains 4812 across execve() or rapid fork-wrap exhaustion", "theme": "amber", "in_edge": "execve swaps image"},
                {"tag": "3 · Confused Daemon", "title": "processIdentifier -> SecCodeCopyGuest", "body": "Privileged XPC helper inspects current PID 4812, sees Apple signature, and grants root action", "theme": "red", "in_edge": "checks wrong image"},
            ],
        },
        {
            "label": "Hardened: Kernel audit_token_t",
            "theme": "green",
            "cards": [
                {"tag": "1 · Message Send", "title": "mach_msg Kernel Trap", "body": "XNU stamps immutable mach_msg_audit_trailer_t onto message in kernel memory", "theme": "white"},
                {"tag": "2 · Generation Counter", "title": "pidversion Increments on execve()", "body": "Every execve() or process respawn monotonically bumps kernel pidversion", "theme": "teal", "in_edge": "immutable trailer"},
                {"tag": "3 · Peer Requirement", "title": "Peer Code-Signing Requirement", "body": "Evaluates signing identity & entitlements against exact {pid, pidversion} audit_token_t", "theme": "green", "in_edge": "rejects stale token"},
            ],
        },
        bridges=[],
        boundary_label="IPC Identity Invariant",
        footer="Never authenticate XPC peers by processIdentifier (pid_t); always bind SecTask / peer signing requirements to audit_token_t.",
    )

    # 17. 07-blastdoor-webkit-containment.svg
    build_fan_bands(
        P("07-blastdoor-webkit-containment.svg"),
        "Deprivileged Parser Containment: BlastDoor & Multi-Process BrowserEngineKit",
        [
            [
                {"id": "net", "tag": "Untrusted Wire Input", "title": "Zero-Click APNs / IDS Push & Arbitrary Web Content", "body": "Attacker-controlled JBIG2, WebP, Font, BlastDoor plist, HTML/Wasm, and WebGL shader streams", "theme": "red"},
            ],
            [
                {"id": "bd", "tag": "Messages Airlock (Swift)", "title": "BlastDoor Service", "body": "Tight Seatbelt profile: no network, no IPC brokering, no writable fs; outputs flat bitmap/plain structs to imagent", "theme": "teal"},
                {"id": "wc", "tag": "Renderer Sandbox", "title": "WebContent Process + APRR JIT", "body": "Per-site isolated process; JIT RX/RW thread-local APRR toggle; zero direct filesystem or camera access", "theme": "purple"},
                {"id": "gpu", "tag": "Graphics Broker", "title": "GPU & Networking Extensions", "body": "Mediates Metal/ANGLE shaders and TLS sockets over narrow IPC; target of 2nd-stage sandbox escapes", "theme": "amber"},
            ],
            [
                {"id": "xnu", "tag": "Kernel & System Services Attack Surface", "title": "Seatbelt MACF Filter Blocks Unneeded Mach Traps & IOKit UserClients", "body": "Forces attacker chains (FORCEDENTRY, BLASTPASS, DarkSword) to burn multiple zero-days just to exit user-mode containment", "theme": "slate"},
            ],
        ],
        [
            ("net", "bd", "iMessage / FaceTime", "teal", False),
            ("net", "wc", "HTTPS / JS", "purple", False),
            ("wc", "gpu", "IPC", "amber", False),
            ("bd", "xnu", "minimal syscalls", "slate", False),
            ("wc", "xnu", "filtered traps", "slate", False),
            ("gpu", "xnu", "IOKit / Metal", "slate", False),
        ],
        footer="Containment assumes C/C++ media and JS parsers will fail, stripping ambient authority from the compromised process.",
    )

    # 18. 08-tcc-attribution-chain.svg
    build_vertical_flow(
        P("08-tcc-attribution-chain.svg"),
        "macOS TCC Attribution: Client Process vs. Responsible Process (responsible_pid)",
        [
            {"tag": "Child Helper", "title": "Spawned CLI Tool, Shell, or MCP Agent (/bin/sh, python3, node)", "body": "Unbundled binary attempts open('~/Desktop/secrets.txt') or ScreenCapture / AppleEvents call", "theme": "slate"},
            {"tag": "MACF / Daemon Intercept", "title": "Sandbox / FileProvider / WindowServer Queries tccd", "body": "Passes caller audit_token_t alongside kernel-tracked responsible_pid (the GUI app that launched the process tree)", "theme": "teal", "edge_label": "TCC access check"},
            {"tag": "Database Lookup", "title": "User or System TCC.db Evaluation", "body": "Checks SystemPolicyAllFiles, Camera, Microphone, or AppleEvents against responsible csreq", "theme": "purple", "edge_label": "resolve responsible app"},
            {"tag": "Grant / Prompt", "title": "Access Permitted Under Parent App's Consent", "body": "Terminal, IDE, or Electron host's prior TCC grant silently authorizes every child command it spawns", "theme": "amber", "edge_label": "parent authorized"},
        ],
        side_notes={
            2: {"tag": "Confused Deputy", "title": "HM Surf & CVE-2025-43530", "body": "Abusing Safari config paths (CVE-2024-44133) or VoiceOver scrod AppleEvents (CVE-2025-43530) inherits TCC without user prompts", "theme": "red", "edge_label": "spoofed trust"},
        },
        footer="Because unbundled UNIX tools lack their own Info.plist identity, responsible_pid inheritance turns consented IDEs and terminals into high-value deputies.",
    )

    # 19. 08-kext-to-driverkit-migration.svg
    build_split_domains(
        P("08-kext-to-driverkit-migration.svg"),
        "Deprivileging Third-Party Extensions on macOS: Kexts vs. System Extensions",
        {
            "label": "Legacy: EL1 Kernel Kexts",
            "theme": "red",
            "cards": [
                {"tag": "Shared Kernel Space", "title": "Third-Party IOKit / Kauth Kext", "body": "Executes at ARM64 EL1 inside XNU address space with unrestricted kernel memory access", "theme": "white"},
                {"tag": "Boot Requirement", "title": "Requires 1TR Reduced Security", "body": "Forces owner to weaken BootKC policy and build a local AuxKC via kmutil", "theme": "amber", "in_edge": "weakens boot tier"},
                {"tag": "Blast Radius", "title": "Kernel Panic or Ring-0 Rootkit", "body": "One USB/AV driver bug crashes macOS or grants arbitrary kernel read/write", "theme": "red", "in_edge": "single fault = panic"},
            ],
        },
        {
            "label": "Modern: EL0 System Extensions",
            "theme": "green",
            "cards": [
                {"tag": "User-Space Process", "title": "DriverKit, NetworkExtension, & ESF", "body": "Runs as sandboxed EL0 daemon communicating over Mach RPC and AppleDART IOMMU", "theme": "white"},
                {"tag": "Boot Preservation", "title": "Preserves Full Security & SSV", "body": "Approved via System Settings + MDM without booting 1TR or modifying AuxKC", "theme": "teal", "in_edge": "keeps Full Security"},
                {"tag": "Blast Radius", "title": "Isolated Daemon Restart", "body": "Driver crash restarts the user-space dext cleanly without disturbing XNU", "theme": "green", "in_edge": "fault contained"},
            ],
        },
        bridges=[],
        boundary_label="EL1 / EL0 Privilege Relocation",
        footer="Moving drivers, firewalls, and EDR sensors out of EL1 aligns macOS kernel integrity with iOS without sacrificing extensibility.",
    )


def gen_interlude_and_part3():
    # 20. 09-esf-auth-notify-pipeline.svg
    build_vertical_flow(
        P("09-esf-auth-notify-pipeline.svg"),
        "macOS EndpointSecurity (ESF): Synchronous AUTH Gates vs. Asynchronous NOTIFY",
        [
            {"tag": "Kernel Syscall", "title": "Process Invokes execve(), open(), mmap(), mount(), or signal()", "body": "XNU enters MACF policy hook registered by EndpointSecurity.kext", "theme": "slate"},
            {"tag": "Mute Filter", "title": "Check Process / Path Mute Set (es_mute_path)", "body": "Skips muted system paths to prevent recursive deadlocks and event storms", "theme": "amber", "edge_label": "MACF hook"},
            {"tag": "AUTH Event", "title": "Thread Blocks Waiting for User-Space EDR Verdict", "body": "Dispatches ES_EVENT_TYPE_AUTH_* with strict kernel deadline timestamp; EDR returns ALLOW or DENY", "theme": "teal", "edge_label": "not muted"},
            {"tag": "NOTIFY Event", "title": "Non-Blocking Audit Record Enqueued to Ring Buffer", "body": "Delivers ES_EVENT_TYPE_NOTIFY_* alongside Unified Logging (.tracev3) and XProtect Behavioral telemetry", "theme": "green", "edge_label": "ES_AUTH_RESULT_ALLOW"},
        ],
        side_notes={
            1: {"tag": "Blind Spot", "title": "Default Muted Paths", "body": "Abusing over-broad muted paths or starving ESF deadlines evades EDR visibility", "theme": "red", "edge_label": "muted"},
            2: {"tag": "Blocked", "title": "EPERM Returned to Caller", "body": "ES_AUTH_RESULT_DENY aborts syscall before kernel commits state", "theme": "red", "edge_label": "DENY"},
        },
        footer="If an ESF client misses its AUTH deadline, the kernel forcefully kills the unresponsive security extension to prevent system hang.",
    )

    # 21. 09-macos-edr-vs-ios-forensics.svg
    build_split_domains(
        P("09-macos-edr-vs-ios-forensics.svg"),
        "Observability Fork: Live macOS EDR Hooks vs. Locked iOS Post-Hoc Forensics",
        {
            "label": "macOS: Live Enterprise Telemetry",
            "theme": "teal",
            "cards": [
                {"tag": "First-Party Defense", "title": "XProtect + Remediator + Bastion", "body": "Launch-time YARA rules, scheduled remediation scans, and behavioral blocks", "theme": "white"},
                {"tag": "Third-Party EDR", "title": "EndpointSecurity Client Extension", "body": "Entitled SystemExtension receives live process, file, mmap, TCC, and XPC events", "theme": "white", "in_edge": "live hooks"},
                {"tag": "Audit Trail", "title": "Unified Logging (.tracev3)", "body": "Persistent structured logs inspectable via log show / log stream", "theme": "white", "in_edge": "correlates events"},
            ],
        },
        {
            "label": "iOS / visionOS: Post-Hoc Triage",
            "theme": "stone",
            "cards": [
                {"tag": "Privacy Invariant", "title": "No Cross-App Process or File Inspection", "body": "Mobile " "EDR" " apps run inside standard App Sandbox; limited to VPN/DNS tunnels & MDM posture", "theme": "white"},
                {"tag": "Diagnostic Capture", "title": "sysdiagnose & Encrypted Backups", "body": "Exports bounded diagnostic archives containing CrashReporter and system logs", "theme": "white", "in_edge": "post-hoc export"},
                {"tag": "Spyware Indicators", "title": "Shutdown.log, DataUsage.sqlite, & Cache.db", "body": "Reveals anomalous /private/var/db/ executions and mercenary network domains via MVT", "theme": "amber", "in_edge": "forensic triage"},
            ],
        },
        bridges=[],
        boundary_label="Architectural Telemetry Trade-Off",
        footer="iOS prevents a rogue 'security app' from becoming spyware itself, at the cost of restricting defenders to post-hoc forensic artifacts.",
    )

    # 22. 10-apfs-data-protection-hierarchy.svg
    build_fan_bands(
        P("10-apfs-data-protection-hierarchy.svg"),
        "APFS Per-File Data Protection Key Hierarchy & XTS-AES Extent Encryption",
        [
            [
                {"id": "root", "tag": "SEP Keybag Root Inputs", "title": "256-Bit Silicon UID + Stretched User Passcode + Effaceable Storage Locker", "body": "Hardware UID tangles brute-force attempts to this chip; passcode unlocks user keybag; effaceable locker enables instant wipe", "theme": "slate"},
            ],
            [
                {"id": "ca", "tag": "Class A (Complete)", "title": "UID + Passcode", "body": "Evicted from RAM 10s after screen lock", "theme": "green"},
                {"id": "cb", "tag": "Class B (UnlessOpen)", "title": "ECDH Public Write", "body": "Creates encrypted files while locked; read needs unlock", "theme": "teal"},
                {"id": "cc", "tag": "Class C (FirstAuth)", "title": "Unavailable in BFU", "body": "Resident in AFU for background notifications & mail", "theme": "amber"},
                {"id": "cd", "tag": "Class D (None)", "title": "UID + Media Key", "body": "Accessible in BFU for boot & Wi-Fi; chip-bound", "theme": "stone"},
            ],
            [
                {"id": "pfk", "tag": "Storage Engine Enforcement", "title": "Per-File Random 256-Bit Key -> Per-Extent XTS-AES Hardware Engine", "body": "Each file inode stores its wrapped per-file key in APFS xattr; ANS/NVMe inline crypto engine derives tweak from block address", "theme": "slate"},
            ],
        ],
        [
            ("root", "ca", "UID + pass", "green", False),
            ("root", "cb", "ECDH pub", "teal", False),
            ("root", "cc", "1st unlock", "amber", False),
            ("root", "cd", "UID + eff", "slate", False),
            ("ca", "pfk", "unwraps PFK", "green", False),
            ("cb", "pfk", "unwraps PFK", "teal", False),
            ("cc", "pfk", "unwraps PFK", "amber", False),
            ("cd", "pfk", "unwraps PFK", "slate", False),
        ],
        footer="Deleting a file destroys its per-file key in APFS metadata; erasing the device destroys the effaceable locker in milliseconds.",
    )

    # 23. 10-bfu-afu-state-machine.svg
    build_vertical_flow(
        P("10-bfu-afu-state-machine.svg"),
        "Device Lock State Machine: BFU, AFU, USB Restricted Mode, & 72-Hour Auto-Reboot",
        [
            {"tag": "Cold Boot / Panic", "title": "Before First Unlock (BFU)", "body": "Only Class D keys available; Class A/B/C keys encrypted under UID + passcode inside SEP; biometrics disabled", "theme": "green"},
            {"tag": "Passcode Entered", "title": "Unlocked Interactive Session", "body": "SEP unwraps Class A, B, and C keys; Face ID / Touch ID enabled; USB data accessories require explicit user trust", "theme": "teal", "edge_label": "valid passcode"},
            {"tag": "Screen Locked", "title": "After First Unlock (AFU)", "body": "Class A keys wiped from RAM after 10s, but Class C keys & decrypted daemon memory remain resident for notifications", "theme": "amber", "edge_label": "lock button / timeout"},
            {"tag": "Physical Port Gate", "title": "USB Restricted Mode Engaged", "body": "Disables Lightning / USB-C data lines when locked (mitigated further after CVE-2025-24200 state fix)", "theme": "slate", "edge_label": "locked port policy"},
            {"tag": "iOS 18.1+ Timer", "title": "72-Hour Inactivity Automatic Reboot -> BFU", "body": "SEP timer triggers clean kernel reboot if device stays locked in AFU for 72 hours, purging Class C keys from RAM", "theme": "green", "edge_label": "72h elapsed"},
        ],
        side_notes={
            2: {"tag": "Forensic Risk", "title": "AFU Kernel / USB Exploits", "body": "Physical extraction boxes target AFU devices before Class C keys and keychain caches are evicted", "theme": "red", "edge_label": "seized in AFU"},
        },
        footer="The 72-hour AFU-to-BFU timer bounds how long a seized iPhone remains vulnerable to AFU-only physical exploits inside an evidence locker.",
    )

    # 24. 11-dp-keychain-vs-file-keychain.svg
    build_split_domains(
        P("11-dp-keychain-vs-file-keychain.svg"),
        "macOS Dual Keychain Reality: SEP Data Protection vs. Legacy File-Based Keychain",
        {
            "label": "Modern: SEP Keychain (secd)",
            "theme": "green",
            "cards": [
                {"tag": "Platform Scope", "title": "All iOS Apps + Sandboxed/Modern macOS", "body": "Requires App ID prefix & provisioned keychain-access-groups entitlement", "theme": "white"},
                {"tag": "Cryptographic Root", "title": "SEP UID + kSecAttrAccessible Classes", "body": "Rows stored in keychain-2.db wrapped by SEP hardware keys; supports SecureEnclave tokens", "theme": "teal", "in_edge": "SEP-sealed"},
                {"tag": "Caller Gate", "title": "Kernel Entitlement Enforcement", "body": "Unrelated local processes cannot read items even if running as the same UNIX UID", "theme": "green", "in_edge": "isolates apps"},
            ],
        },
        {
            "label": "Legacy: File Keychain (macOS)",
            "theme": "red",
            "cards": [
                {"tag": "Platform Scope", "title": "CLI Tools & Unprovisioned Apps", "body": "~/Library/Keychains/ login.keychain-db unlocked automatically at user login", "theme": "white"},
                {"tag": "Cryptographic Root", "title": "3DES / AES Master Key Derived From Login Password", "body": "File can be copied off-box once attacker obtains user login password", "theme": "amber", "in_edge": "software-wrapped"},
                {"tag": "Commodity Abuse", "title": "Atomic Stealer (AMOS) & Poseidon", "body": "Spoofs osascript password dialog, copies login.keychain-db, and decrypts browser/app secrets offline", "theme": "red", "in_edge": "offline crack/decrypt"},
            ],
        },
        bridges=[],
        boundary_label="kSecUseDataProtectionKeychain Flag",
        footer="Always set kSecUseDataProtectionKeychain = true on macOS so secrets bind to SEP hardware and DER entitlements rather than login.keychain-db.",
    )

    # 25. 11-stolen-device-protection-gate.svg
    build_vertical_flow(
        P("11-stolen-device-protection-gate.svg"),
        "Stolen Device Protection: Defeating Shoulder-Surfed Passcode Takeover",
        [
            {"tag": "High-Risk Action", "title": "Change Apple Account Password, Disable Find My, or View Saved Passkeys", "body": "Attacker possesses unlocked iPhone AND observed the victim's 6-digit passcode prior to physical theft", "theme": "amber"},
            {"tag": "Gate 1 · Biometric Only", "title": "Require Live Face ID or Touch ID Match (No Passcode Fallback)", "body": "SEP rejects passcode substitution completely for protected credential and recovery operations", "theme": "teal", "edge_label": "SDP enabled"},
            {"tag": "Gate 2 · Location Context", "title": "Device Inside CoreRoutine Familiar Location?", "body": "Checks encrypted on-device significant-location history (home / workplace) for critical account mutations", "theme": "purple", "edge_label": "biometric passed"},
            {"tag": "Gate 3 · Temporal Delay", "title": "Enforce 1-Hour Security Delay + Second Biometric Match", "body": "When away from familiar locations, starts non-bypassable 60-minute timer before second Face ID/Touch ID check", "theme": "green", "edge_label": "unfamiliar location"},
        ],
        side_notes={
            1: {"tag": "Thwarted", "title": "Passcode Thief Blocked", "body": "Knowing the passcode no longer grants iCloud password reset, Recovery Key enrollment, or Activation Lock removal", "theme": "red", "edge_label": "no biometric"},
        },
        footer="Previously, the user passcode functioned as an omnipotent single point of failure overriding biometrics and Apple Account custody.",
    )

    # 26. 12-sep-attestation-cert-chain.svg
    build_vertical_flow(
        P("12-sep-attestation-cert-chain.svg"),
        "SEP Hardware Key Attestation & X.509 Posture Certificate Hierarchy",
        [
            {"tag": "Root of Trust", "title": "Apple Attestation Root CA", "body": "Offline Apple root public key pinned by enterprise MDM, ACME servers, and relying parties", "theme": "slate"},
            {"tag": "Provisioned Intermediate", "title": "Basic / Enterprise Attestation Authority (BAA)", "body": "Device-class or factory-provisioned SEP intermediate certificate", "theme": "slate", "edge_label": "signs intermediate"},
            {"tag": "Hardware Leaf", "title": "Non-Exportable SEP P-256 Attested Key", "body": "Generated inside SEP for App Attest, ACME MDA, or Enterprise keypair; private key never leaves enclave", "theme": "teal", "edge_label": "certifies leaf + nonce"},
            {"tag": "Custom X.509 OIDs", "title": "Cryptographic Claims Embedded in Leaf Certificate", "body": "Encodes OS version, SIP/SSV status, Secure Boot tier, LLB/SEP firmware hashes, and server freshness nonce", "theme": "green", "edge_label": "embeds OIDs"},
        ],
        footer="Verifying the X.509 chain proves both that the private key lives inside genuine Apple SEP silicon and what OS posture booted it.",
    )

    # 27. 12-app-attest-vs-mda-acme.svg
    build_split_domains(
        P("12-app-attest-vs-mda-acme.svg"),
        "Two Remote Attestation Primitives: App Attest vs. Managed Device Attestation",
        {
            "label": "Consumer: DCAppAttestService",
            "theme": "teal",
            "cards": [
                {"tag": "Identity Scope", "title": "Anonymous Per-App, Per-Install Key", "body": "Prevents cross-app device tracking; clears across app reinstall or reset", "theme": "white"},
                {"tag": "Wire Format", "title": "WebAuthn-Style CBOR AttestationObject", "body": "Contains x5c cert chain, SHA-256(AppID), credential pubkey, and signCount=0", "theme": "white", "in_edge": "attestKey"},
                {"tag": "Ongoing Requests", "title": "Lightweight CBOR Assertions", "body": "Signs clientDataHash with monotonic SEP counter to block replay and app cloning", "theme": "green", "in_edge": "generateAssertion"},
            ],
        },
        {
            "label": "Enterprise: Managed Attest (MDA)",
            "theme": "slate",
            "cards": [
                {"tag": "Identity Scope", "title": "Managed Enterprise Identity (Serial / UDID)", "body": "Permitted only for MDM/DDM enrolled devices under explicit organizational policy", "theme": "white"},
                {"tag": "Wire Format", "title": "RFC 8555 ACME + device-attest-01", "body": "ACME client requests SEP attestation over server challenge nonce inside CSR flow", "theme": "white", "in_edge": "ACME challenge"},
                {"tag": "Ongoing Requests", "title": "mTLS / 802.1X Client X.509 Certificate", "body": "Hardware-bound client cert authenticates VPN, Wi-Fi, and Zero Trust gateways", "theme": "green", "in_edge": "issues X.509"},
            ],
        },
        bridges=[],
        boundary_label="Privacy vs. Fleet Attribution",
        footer="App Attest proves genuine silicon without revealing serial numbers; MDA reveals device identity only to authorized MDM/ACME issuers.",
    )

    # 28. 13-gsa-passkey-continuity-flow.svg
    build_sequence(
        P("13-gsa-passkey-continuity-flow.svg"),
        "Apple Account GSA Auth, Synced Passkeys, & Watch Auto Unlock ToF Gate",
        [
            {"title": "Mac (Locked)", "sub": "Continuity / AuthKit", "theme": "slate"},
            {"title": "Apple Watch", "sub": "Paired Unlocked SEP", "theme": "teal"},
            {"title": "iCloud Keychain", "sub": "E2EE Circle Sync", "theme": "green"},
            {"title": "Relying Party / GSA", "sub": "SRP-6a or WebAuthn", "theme": "purple"},
        ],
        [
            (0, 3, "GSA SRP-6a zero-knowledge password proof + 2FA", "purple", False),
            (0, 2, "Join E2EE Keychain circle via SEP peer signature", "green", False),
            (2, 0, "Sync WebAuthn P-256 Passkeys wrapped to circle", "green", True),
            (0, 1, "BLE proximity wake + mutual Continuity session", "teal", False),
            (0, 1, "802.11 Fine Timing Measurement (ToF) ranging pulse", "teal", False),
            (1, 0, "Verify RTT <= ~3m physical bound; release unlock token", "green", True),
            (0, 3, "Sign WebAuthn challenge with synced Passkey after Touch ID", "purple", False),
        ],
        bottom_note={
            "tag": "Speed-of-Light Relay Bound",
            "title": "Wi-Fi / UWB Time-of-Flight Ranging Defeats Bluetooth Relay Attacks Against Watch Auto Unlock",
            "body": "Even if an attacker relays BLE packets from a victim's desk to a distant coffee shop, electromagnetic propagation delay exceeds the nanosecond RTT budget.",
            "theme": "amber",
        },
    )

    # 29. 13-visionos-r1-gaze-isolation.svg
    build_horizontal_pipeline(
        P("13-visionos-r1-gaze-isolation.svg"),
        "visionOS Spatial Gaze Privacy: Hardware-Isolated Eye Tracking to Pinch Commit",
        [
            {"tag": "Internal IR Cameras", "title": "Eye-Tracking Stream", "body": "High-rate pupil & corneal glint frames revealing cognitive focus", "theme": "red"},
            {"tag": "Real-Time Silicon", "title": "R1 Co-Processor", "body": "Processes sensor fusion at 12 ms latency over private bus", "theme": "purple"},
            {"tag": "System Process", "title": "RealityKit Compositor", "body": "Renders hover highlight effects inside system process without app callbacks", "theme": "teal"},
            {"tag": "User Intent Gate", "title": "Finger Pinch Detected", "body": "Hand-tracking cameras confirm explicit thumb-index tap gesture", "theme": "amber"},
            {"tag": "App Sandbox", "title": "Vision Pro App", "body": "Receives single synthetic UIEvent tap on target element only", "theme": "green"},
        ],
        footer="Untrusted visionOS apps never learn what buttons, ads, or text a user looked at without pinching, eliminating involuntary biometric telemetry.",
    )

    # 30. 14-ade-ddm-autonomous-loop.svg
    build_split_domains(
        P("14-ade-ddm-autonomous-loop.svg"),
        "Enterprise Fleet Management: Legacy Imperative MDM vs. Declarative DDM",
        {
            "label": "Legacy MDM: Imperative Polling",
            "theme": "stone",
            "cards": [
                {"tag": "Trigger", "title": "APNs Wakeup -> Device Polls MDM", "body": "Server queues sequential InstallProfile / DeviceInformation XML plist commands", "theme": "white"},
                {"tag": "Latency", "title": "Round-Trip Drift Under Offline/Change", "body": "Posture drift goes undetected until server schedules next inventory poll", "theme": "amber", "in_edge": "round-trip lag"},
                {"tag": "Scalability", "title": "Thundering-Herd OS Update Storms", "body": "Server must compute state diffs per device across 100k+ endpoints", "theme": "white", "in_edge": "server bottleneck"},
            ],
        },
        {
            "label": "Declarative Device Management (DDM)",
            "theme": "green",
            "cards": [
                {"tag": "Enrollment Anchor", "title": "ABM + ADE Non-Removable Supervision", "body": "Activation server enforces MDM enrollment before Setup Assistant completes", "theme": "white"},
                {"tag": "Local Engine", "title": "Activations, Configurations, & Predicates", "body": "Device evaluates local predicates autonomously and applies OS/passcode/cert policies offline", "theme": "teal", "in_edge": "autonomous eval"},
                {"tag": "Proactive Telemetry", "title": "Event-Driven StatusChannel Reports", "body": "Client pushes JSON StatusItems immediately when OS build or attestation changes", "theme": "green", "in_edge": "instant push"},
            ],
        },
        bridges=[],
        boundary_label="Imperative vs. Autonomous Control",
        footer="Anchored by ABM/ADE supervision, DDM turns the Apple endpoint into an autonomous policy engine with proactive status streaming.",
    )

    # 31. 14-platform-sso-sep-binding.svg
    build_sequence(
        P("14-platform-sso-sep-binding.svg"),
        "macOS Platform Single Sign-On: Binding Cloud Identity to SEP Hardware",
        [
            {"title": "macOS LoginWindow", "sub": "AuthPlugin & Local Account", "theme": "slate"},
            {"title": "Platform SSO Extension", "sub": "Entra ID / Okta Broker", "theme": "teal"},
            {"title": "Secure Enclave (SEP)", "sub": "Device & User P-256 Keys", "theme": "green"},
            {"title": "Enterprise IdP", "sub": "OIDC / WS-Trust / Kerberos", "theme": "purple"},
        ],
        [
            (1, 2, "Generate non-exportable Device Signing & Encryption Keys", "green", False),
            (1, 3, "Register device public keys + ACME MDA attestation cert", "purple", False),
            (0, 1, "User authenticates at LoginWindow / Lock Screen", "slate", False),
            (1, 2, "Sign OIDC / PRT assertion JWT with SEP Device Key", "green", False),
            (1, 3, "Exchange hardware-signed assertion for PRT / SSO tokens", "purple", False),
            (3, 1, "Return encrypted PRT session key wrapped to SEP Encryption Key", "purple", True),
            (1, 0, "Unlock FileVault/Keychain & mint optional Kerberos TGT", "teal", True),
        ],
        bottom_note={
            "tag": "Pass-the-PRT Mitigation on macOS",
            "title": "Cloud Session Proof-of-Possession Keys Remain Non-Exportable Inside the Mac's Secure Enclave",
            "body": "Exfiltrating broker cache files from ~/Library cannot replay Enterprise PRT assertions from an attacker's machine without SEP signing access.",
            "theme": "green",
        },
    )


def gen_part4_and_finale():
    # 32. 15-standard-icloud-vs-adp.svg
    build_split_domains(
        P("15-standard-icloud-vs-adp.svg"),
        "CloudKit Key Custody: Standard Data Protection vs. Advanced Data Protection",
        {
            "label": "Standard iCloud (Default)",
            "theme": "amber",
            "cards": [
                {"tag": "Always E2EE (~14 Services)", "title": "Keychain, Health, Passwords, Messages*", "body": "Protected by synced iCloud Keychain circle; Apple never holds service keys (*when Backup off)", "theme": "green"},
                {"tag": "Server-Escrowed Keys", "title": "iCloud Backup, Photos, Drive, Notes", "body": "Chunk encryption keys uploaded to Apple CloudKit key servers for web recovery", "theme": "amber", "in_edge": "Backup wraps Messages key"},
                {"tag": "Compulsion Surface", "title": "Apple Can Comply With Valid Legal Process", "body": "Account compromise at cloud tier or lawful warrant exposes Backup, Photos, and Drive", "theme": "red", "in_edge": "Apple in TCB"},
            ],
        },
        {
            "label": "Advanced Data Protection (ADP)",
            "theme": "green",
            "cards": [
                {"tag": "Expanded E2EE (23+ Categories)", "title": "Backup, Photos, Drive, Notes, Reminders, Safari", "body": "Client rotates service keys and purges historical escrowed keys from Apple servers", "theme": "green"},
                {"tag": "Trusted Devices Only", "title": "SEP-Anchored Keychain Circle Custody", "body": "Service keys live solely inside user's enrolled trusted devices + optional 28-char Recovery Key / Contact", "theme": "teal", "in_edge": "zero cloud key copy"},
                {"tag": "Zero-Knowledge Cloud", "title": "Apple Excluded From Data TCB", "body": "Server breach or subpoena yields only ciphertext (except legacy Mail, Contacts, Calendar)", "theme": "green", "in_edge": "Apple outside TCB"},
            ],
        },
        bridges=[],
        boundary_label="Who Holds the Root Wrapping Keys?",
        footer="Enabling ADP closes the iCloud Backup side door that previously placed iMessage backup keys inside Apple's server custody.",
    )

    # 33. 15-icloud-keychain-hsm-escrow.svg
    build_sequence(
        P("15-icloud-keychain-hsm-escrow.svg"),
        "iCloud Keychain Verifiable Cloud HSM Escrow & Passcode Destruction Counter",
        [
            {"title": "User Device (SEP)", "sub": "Recovery Backup Writer", "theme": "slate"},
            {"title": "Apple Cloud Relay", "sub": "Untrusted Transport", "theme": "stone"},
            {"title": "Cloud Security Module", "sub": "Custom HSM Fleet (aks)", "theme": "green"},
        ],
        [
            (2, 0, "Publish HSM fleet public key + Apple-signed firmware measurement", "green", False),
            (0, 0, "Verify M-of-N Apple team signatures on HSM firmware audit image", "slate", False),
            (0, 1, "Encrypt Keychain escrow blob under user passcode + HSM cluster key", "slate", False),
            (1, 2, "Store sealed escrow record (Apple servers cannot read plaintext)", "stone", False),
            (0, 2, "New device recovery: send SRP passcode proof over secure channel", "teal", False),
            (2, 2, "Enforce <= 10 failed attempts; permanently destroy record on 10th fail", "green", False),
            (2, 0, "Release unwrapped Keychain recovery secret on valid proof", "green", True),
        ],
        footer="Even when Standard users skip a manual 28-character Recovery Key, Apple's Cloud HSM fleet prevents offline brute-forcing of 6-digit passcodes.",
    )

    # 34. 16-pq3-hybrid-ratchet.svg
    build_vertical_flow(
        P("16-pq3-hybrid-ratchet.svg"),
        "iMessage PQ3 Level-3 Protocol: Classical + Post-Quantum Continuous Ratchet",
        [
            {"tag": "Prekey Bundle (IDS)", "title": "P-256 Identity/Prekeys + ML-KEM-768 Post-Quantum Public Key", "body": "Recipient uploads classical ECDH prekeys alongside lattice KEM encapsulation keys signed by SEP/Identity key", "theme": "slate"},
            {"tag": "Initial Handshake", "title": "Hybrid X3DH + ML-KEM-768 Key Establishment", "body": "Combines classical ECDH shared secrets and ML-KEM secret via HKDF-SHA256 to defeat harvest-now, decrypt-later", "theme": "teal", "edge_label": "0-RTT hybrid init"},
            {"tag": "Symmetric & DH Ratchet", "title": "Per-Message Forward Secrecy Chain", "body": "Advances sending/receiving chain keys on every message and classical P-256 Diffie-Hellman ratchet on turn flips", "theme": "green", "edge_label": "message traffic"},
            {"tag": "Level-3 Post-Quantum Heal", "title": "Periodic ML-KEM-1024 Re-Encapsulation Every N Messages / Bytes", "body": "Injects fresh post-quantum KEM entropy mid-session (amortized across chunks) for post-compromise security against quantum adversaries", "theme": "purple", "edge_label": "periodic PQ ratchet"},
        ],
        footer="Level-3 PQ3 goes beyond PQXDH initial key exchange by periodically healing compromised session state against future quantum attackers.",
    )

    # 35. 16-contact-key-verification-kt.svg
    build_sequence(
        P("16-contact-key-verification-kt.svg"),
        "iMessage Contact Key Verification (KT): Auditing the IDS Key Directory",
        [
            {"title": "Sender Device", "sub": "Queries Recipient Keys", "theme": "slate"},
            {"title": "Apple IDS Directory", "sub": "Key Lookup Service", "theme": "amber"},
            {"title": "KT Transparency Log", "sub": "Append-Only Merkle Map", "theme": "teal"},
            {"title": "Recipient Device", "sub": "Self-Audit Monitor", "theme": "green"},
        ],
        [
            (3, 1, "Register SEP-backed iMessage / FaceTime public keys", "green", False),
            (1, 2, "Commit VRF(account) -> key-set leaf into signed Merkle tree head", "teal", False),
            (0, 1, "Lookup keys for recipient@icloud.com", "slate", False),
            (1, 0, "Return public keys + cryptographic Merkle inclusion proof", "amber", True),
            (0, 2, "Verify inclusion proof & gossip-check signed tree head consistency", "teal", False),
            (3, 2, "Background self-audit verifies all logged keys match local trusted circle", "green", False),
            (0, 3, "Optional out-of-band 8-digit Verification Code pins exact key hash", "green", True),
        ],
        bottom_note={
            "tag": "Equivocation Detection Invariant",
            "title": "Apple Cannot Silently Serve a Ghost Key to One Sender Without Leaving an Immutable Proof in the KT Merkle Log",
            "body": "If IDS injects an unauthorized key, the recipient's background KT self-audit detects the rogue Merkle leaf and surfaces a UI warning.",
            "theme": "red",
        },
    )

    # 36. 17-find-my-p224-beacon-flow.svg
    build_horizontal_pipeline(
        P("17-find-my-p224-beacon-flow.svg"),
        "Offline Find My Network: Zero-Knowledge Rotating P-224 Location Relay",
        [
            {"tag": "Lost Offline Device", "title": "15-Min P-224 Key Roll", "body": "Derives unlinkable public key P_i + BLE MAC from master key d_0 & symmetric KDF", "theme": "slate"},
            {"tag": "BLE Broadcast", "title": "Nearby Stranger iPhone", "body": "Receives P_i over Bluetooth; learns neither owner identity nor prior P_{i-1}", "theme": "teal"},
            {"tag": "Finder ECIES", "title": "Encrypt GPS to P_i", "body": "Encrypts finder GPS coords with ephemeral ECDH(e, P_i) + AES-GCM", "theme": "purple"},
            {"tag": "Apple Relay", "title": "Blind Hash Index", "body": "Stores ciphertext indexed by SHA-256(P_i) without device or GPS knowledge", "theme": "amber"},
            {"tag": "Owner Device", "title": "Re-Derive d_i & Decrypt", "body": "Computes recent SHA-256(P_i) window, fetches blobs, and decrypts GPS locally", "theme": "green"},
        ],
        footer="Neither the stranger's relay iPhone nor Apple's servers learn the lost device's identity or plaintext coordinates.",
    )

    # 37. 17-dult-anti-tracking-tradeoff.svg
    build_dual_rail_timeline(
        P("17-dult-anti-tracking-tradeoff.svg"),
        "Offline Beacon Tension: Anti-Theft Unlinkability vs. Unwanted-Stalking Detection",
        "Privacy / Anti-Theft Design",
        "Anti-Stalking Countermeasures (DULT)",
        [
            {
                "year": "2019",
                "left": {"tag": "Find My Launch", "title": "15-Minute BLE Key & MAC Rotation", "body": "Prevents retail stores and passive RF sniffers from tracking a passerby's MacBook or iPhone", "theme": "teal"},
                "right": {"tag": "Inherent Tension", "title": "Rapid Rotation Hides Rogue Trackers Too", "body": "If keys rotated every 15 minutes unconditionally, a victim phone could not tell one hidden tracker followed it all day", "theme": "red"},
            },
            {
                "year": "2021",
                "left": {"tag": "AirTag Launch", "title": "Separated-From-Owner State Split", "body": "Near owner: fast rotation; separated from owner: slower 24h window key so nearby victims correlate travel", "theme": "amber"},
                "right": {"tag": "Acoustic + iOS Alert", "title": "Chime + 'AirTag Found Moving With You'", "body": "On-device trajectory clustering triggers alert and UWB Precision Finding to locate hidden tag", "theme": "green"},
            },
            {
                "year": "2024-2026",
                "left": {"tag": "Cross-Ecosystem Gap", "title": "Android Users Needed Manual Scan App", "body": "Platform-specific beacon formats left non-Apple victims without background stalking alerts", "theme": "amber"},
                "right": {"tag": "IETF DULT Standard", "title": "Joint iOS + Android Unwanted Tracker Spec", "body": "Standardized separated-mode BLE flags enable native cross-OS stalking alerts across AirTag and third-party tags", "theme": "green"},
            },
        ],
        footer="Unlinkability and unwanted-tracker detection are mathematically opposed; separated-owner state switching balances both threat models.",
    )

    # 38. 18-foundation-models-defense-pipeline.svg
    build_horizontal_pipeline(
        P("18-foundation-models-defense-pipeline.svg"),
        "WWDC26 Foundation Models Framework: Three-Layer Agentic Prompt-Injection Defense",
        [
            {"tag": "Untrusted Data", "title": "Email / Web / Doc Tool Output", "body": "Contains adversarial indirect prompt injection attempting tool exfiltration", "theme": "red"},
            {"tag": "Layer 1 · Redact", "title": ".historyTransform PII Scrub", "body": "Strips secrets & PII before transcript renders into model context window", "theme": "amber"},
            {"tag": "Layer 2 · Spotlight", "title": "Untrusted Delimiter Tagging", "body": "Wraps external data inside explicit spotlighting provenance markers for LLM", "theme": "teal"},
            {"tag": "Model Output", "title": "Typed App Intent / Tool Call", "body": "SystemLanguageModel emits structured @Generable / Tool invocation", "theme": "purple"},
            {"tag": "Layer 3 · Gate", "title": ".onToolCall Pre-Execution Hook", "body": "Deterministic Swift guard validates args, requests user UI confirm, or throws", "theme": "green"},
        ],
        footer="Probabilistic LLMs never become security enforcement boundaries; deterministic .onToolCall code gates every side-effecting action.",
    )

    # 39. 18-mcp-tcc-microvm-isolation.svg
    build_split_domains(
        P("18-mcp-tcc-microvm-isolation.svg"),
        "macOS Coding Agents (MCP / ACP): Host TCC Confused Deputy vs. Micro-VM Isolation",
        {
            "label": "Host-Process Execution Hazard",
            "theme": "red",
            "cards": [
                {"tag": "Consented Host", "title": "IDE / Terminal (Xcode, VS Code, iTerm)", "body": "Granted Full Disk Access, SSH keys, Keychain, and AppleEvents for daily work", "theme": "white"},
                {"tag": "Untrusted Input", "title": "Malicious Repo, MCP Server, or Skill", "body": "Prompt injection or postinstall script executes inside spawned agent subprocess", "theme": "amber", "in_edge": "spawns MCP tool"},
                {"tag": "Inherited Authority", "title": "responsible_pid Grants Silent Access", "body": "tccd attributes agent child I/O to consented IDE; exfiltrates ~/.aws, cookies, & code", "theme": "red", "in_edge": "inherits host TCC"},
            ],
        },
        {
            "label": "Micro-VM Agent Isolation",
            "theme": "green",
            "cards": [
                {"tag": "Hypervisor Boundary", "title": "Virtualization.framework Per-Agent VM", "body": "Apple Containerization boots dedicated minimal kernel + vminitd in sub-second GL2 VM", "theme": "white"},
                {"tag": "Explicit Mounts", "title": "VirtioFS Scoped to Single Workspace Dir", "body": "Host ~/.ssh, login.keychain-db, and TCC-protected folders do not exist inside guest", "theme": "teal", "in_edge": "narrow VirtioFS"},
                {"tag": "Egress & Device Gate", "title": "vmnet Filter + macOS 26 Accessory Access", "body": "Dedicated container IP subject to egress allowlists; raw USB/host devices denied", "theme": "green", "in_edge": "network & I/O fence"},
            ],
        },
        bridges=[],
        boundary_label="Process Tree vs. Stage-2 Hypervisor",
        footer="Running autonomous MCP/ACP agents inside per-task Virtualization.framework micro-VMs severs macOS responsible_pid TCC inheritance.",
    )

    # 40. 19-pcc-ohttp-attestation-flow.svg
    build_sequence(
        P("19-pcc-ohttp-attestation-flow.svg"),
        "Private Cloud Compute (PCC): Verifiable Stateless Cloud Inference Flow",
        [
            {"title": "User Device", "sub": "Foundation Models / Siri", "theme": "slate"},
            {"title": "Public Transparency Log", "sub": "Append-Only Image4 Ledger", "theme": "purple"},
            {"title": "Third-Party OHTTP Relay", "sub": "Fastly / Cloudflare Blind Hop", "theme": "amber"},
            {"title": "PCC Apple Silicon Node", "sub": "Stateless SEP + No NVMe", "theme": "green"},
        ],
        [
            (3, 1, "Publish signed PCC OS Image4 measurements before fleet rollout", "purple", False),
            (1, 0, "Cache verified PCC Transparency Log roots & allowed build digests", "purple", True),
            (0, 0, "Fetch attested PCC node ephemeral HPKE keys; verify SEP chain & Log inclusion", "slate", False),
            (0, 2, "Send OHTTP request: Relay sees client IP, Prompt encrypted to PCC SEP key", "amber", False),
            (2, 3, "Forward blinded ciphertext: PCC sees prompt after decrypt, never client IP", "green", False),
            (3, 3, "Run inference in encrypted RAM; zero persistent disk, zero operator shell", "green", False),
            (3, 0, "Return HPKE-encrypted response via OHTTP; wipe ephemeral context", "green", True),
        ],
        bottom_note={
            "tag": "Cryptographic Non-Targetability",
            "title": "Client Devices Refuse to Encrypt Prompts to Any PCC Server Build Absent From the Public Transparency Log",
            "body": "Apple cannot deploy a secret logging build to one targeted user without publishing the backdoored binary to external security researchers first.",
            "theme": "teal",
        },
    )

    # 41. 19-pcc-vs-cvm-comparison.svg
    build_matrix(
        P("19-pcc-vs-cvm-comparison.svg"),
        "Confidential Cloud AI Architecture Comparison",
        "How Apple Private Cloud Compute differs structurally from tenant-managed x86/ARM Confidential VMs",
        [
            ("Root Silicon & TEE", "Hardware enclave boundary"),
            ("Persistent Storage", "Disk / crash-dump retention"),
            ("Operator Shell / Debug", "Live admin inspection"),
            ("Binary Transparency", "Publicly inspectable OS image"),
            ("Network IP Unlinkability", "Decoupling IP from payload"),
        ],
        [
            ("Apple PCC", "Stateless Consumer AI"),
            ("Azure CVM / SEV-SNP", "Enterprise Tenant IaaS"),
            ("Traditional Cloud GPU", "Standard TLS Inference"),
        ],
        [
            [("Custom Apple Silicon + SEP", "green"), ("AMD SEV-SNP / Intel TDX", "teal"), ("Host Hypervisor Trusted", "red")],
            [("Zero Persistent Storage", "green"), ("Encrypted Virtual Disk", "amber"), ("Standard Cloud Volumes", "red")],
            [("Removed in Production OS", "green"), ("Tenant SSH / Guest Agent", "amber"), ("Full Operator Access", "red")],
            [("Mandatory Public Log", "green"), ("Tenant-Verified Guest", "teal"), ("Opaque Provider Image", "red")],
            [("Mandatory 3P OHTTP Relay", "green"), ("Direct Tenant VNet / TLS", "amber"), ("Provider Terminates TLS", "red")],
        ],
        "Legend: Green = Enforced by verifiable vendor-excluding invariant; Teal = Tenant-controlled cryptographic guarantee; Amber = Policy/tenant-dependent; Red = Provider inside TCB.",
        footer="PCC solves a harder problem than tenant IaaS: proving to millions of consumers that the cloud operator running the service cannot inspect their prompts.",
    )

    # 42. 20-mercenary-zero-click-chains.svg
    build_fan_bands(
        P("20-mercenary-zero-click-chains.svg"),
        "Evolution of In-the-Wild iOS Full-Chain Exploits vs. Apple Silicon Defenses",
        [
            [
                {"id": "fe", "tag": "2021 · FORCEDENTRY (NSO)", "title": "Fake GIF -> CoreGraphics JBIG2 Logic Circuit", "body": "Built 70,000+ AND/OR/XOR gates inside JBIG2 segment decoder (CVE-2021-30860) to synthesize an arbitrary memory R/W computer without JIT", "theme": "red"},
                {"id": "tri", "tag": "2023 · Operation Triangulation", "title": "iMessage Font -> Undocumented Silicon MMIO", "body": "TrueType ADJUST overflow -> JS/WebKit -> wrote undocumented hardware DMA/hash MMIO registers (CVE-2023-38606) to bypass PPL page protections", "theme": "red"},
                {"id": "ds", "tag": "2025-2026 · DarkSword Kit", "title": "WebKit JIT -> ANGLE GPU -> XNU CoW -> dyld", "body": "Chained 6 bugs across JSC (CVE-2025-43529), ANGLE (CVE-2025-14174), XNU CoW (CVE-2025-43510), and dyld state (CVE-2026-20700)", "theme": "red"},
            ],
            [
                {"id": "ans1", "tag": "Architectural Response", "title": "BlastDoor + Lockdown Mode", "body": "Strips JBIG2, complex fonts, and zero-click attachment pre-rendering under Lockdown Mode", "theme": "green"},
                {"id": "ans2", "tag": "Architectural Response", "title": "SPTM (GL2) + MMIO Range Locks", "body": "Fences undocumented SoC debug/MMIO registers in Boot ROM/iBoot and moves page tables into SPTM", "theme": "green"},
                {"id": "ans3", "tag": "Architectural Response", "title": "A19 / M5 Synchronous EMTE (MIE)", "body": "Hardware memory tagging traps spatial/temporal corruption on first dereference across XNU, WebKit, & daemons", "theme": "green"},
            ],
        ],
        [
            ("fe", "ans1", "forced surface cut", "green", False),
            ("tri", "ans2", "forced MMIO lock", "green", False),
            ("ds", "ans3", "forced hardware MTE", "green", False),
        ],
        footer="Each generation of silicon hardening forced mercenary vendors to chain 4 to 6 distinct vulnerabilities across renderers, brokers, linkers, and hardware.",
    )

    # 43. 20-uk-ipa-s253-adp-boundary.svg
    build_vertical_flow(
        P("20-uk-ipa-s253-adp-boundary.svg"),
        "Sovereign Compulsion vs. Mathematical E2EE: The 2025-2026 UK IPA Section 253 Dispute",
        [
            {"tag": "Jan 2025 · Secret Mandate", "title": "UK Home Office Issues IPA 2016 Section 253 Technical Capability Notice", "body": "Demands capability to access encrypted iCloud backups/files under statutory non-disclosure rules tightened by the 2024 Amendment Act", "theme": "red"},
            {"tag": "Architectural Choice", "title": "Refusal to Build a Global Client-Side Key-Escrow Backdoor", "body": "Modifying SEP/Keychain client code to dual-encrypt ADP keys to an escrow root would introduce a systemic global TCB vulnerability", "theme": "amber", "edge_label": "no selective E2EE backdoor"},
            {"tag": "Feb 21, 2025 · Feature Withdrawal", "title": "Apple Disables New ADP Enrollment in the United Kingdom", "body": "UK accounts fall back to Standard iCloud (server-held Backup/Drive/Photos keys) while global ADP cryptography remains uncompromised", "theme": "teal", "edge_label": "regional withdrawal"},
            {"tag": "Apr 2025 - Aug 2026 · Legal Challenge", "title": "Investigatory Powers Tribunal Public Rulings & Narrowed UK-Only Notice", "body": "IPT rejects total secrecy (Apr 2025); UK drops non-UK citizen scope (Aug 2025); Apple files fresh IPT challenge to revised UK-user TCN (Aug 2026)", "theme": "slate", "edge_label": "tribunal litigation"},
        ],
        footer="When sovereign law forbids zero-knowledge cloud storage in one jurisdiction, removing the feature locally is the only way to avoid poisoning global client code.",
    )

    # 44. 20-apple-trust-chain-horizon.svg
    build_split_domains(
        P("20-apple-trust-chain-horizon.svg"),
        "The Permanent Horizon of the Apple Trust Chain",
        {
            "label": "Silicon & Crypto Guarantees",
            "theme": "green",
            "cards": [
                {"tag": "Boot & System Integrity", "title": "Boot ROM -> Image4 -> SSV -> SPTM", "body": "Blocks unauthenticated bootkits, persistent / modifications, and naive kernel RWX page injection", "theme": "white"},
                {"tag": "Physical At-Rest Custody", "title": "SEP UID + Anti-Replay + BFU Timer", "body": "Bounds offline NAND brute-force to hardware-throttled SEP guesses and forces idle AFU devices back to BFU", "theme": "white"},
                {"tag": "Verifiable Cloud & Messaging", "title": "ADP + PQ3 + KT + PCC Transparency", "body": "Removes Apple's cloud servers from plaintext custody and exposes directory or server-build equivocation", "theme": "white"},
            ],
        },
        {
            "label": "Irreducible Attack Surfaces",
            "theme": "red",
            "cards": [
                {"tag": "Immutable Silicon & Shared State", "title": "Mask-ROM Bugs, MMIO, & GPU Residue", "body": "checkm8, usbliter8, CVE-2023-38606 MMIO, and CVE-2026-49269 M1 GPU registers sit below OS patchability or CPU MMUs", "theme": "white"},
                {"tag": "Complex Parsers & Deputies", "title": "Media/JS Engines, TCC, & MCP Agents", "body": "Logic circuits in decoders and responsible_pid inheritance grant ambient authority without breaking crypto", "theme": "white"},
                {"tag": "Sovereign Law & Enrollment Gates", "title": "IPA s.253 & Server-Controlled Toggle UI", "body": "Jurisdictions can compel feature disablement at enrollment even when deployed E2EE math is unbreakable", "theme": "white"},
            ],
        },
        bridges=[
            (0, 0, "lr", "bounded by silicon errata", "red"),
            (1, 1, "lr", "bypassed in live AFU session", "amber"),
            (2, 2, "lr", "constrained at enrollment", "red"),
        ],
        boundary_label="Mechanism Validity vs. System Reality",
        footer="Vertical integration eliminates multi-vendor seams, concentrating all remaining risk into parser complexity, microarchitectural state, and legal jurisdiction.",
    )


def main():
    import runpy
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_opening()
    gen_part1()
    gen_part2()
    gen_interlude_and_part3()
    gen_part4_and_finale()
    here = os.path.dirname(os.path.abspath(__file__))
    for b in ("gen_extra_b1.py", "gen_extra_b2.py", "gen_extra_b3.py", "gen_extra_b4.py"):
        bp = os.path.join(here, b)
        if os.path.exists(bp):
            runpy.run_path(bp, run_name="__main__")
    svgs = sorted(f for f in os.listdir(DIAG_DIR) if f.endswith(".svg"))
    print(f"Successfully generated and 7-way collision-verified {len(svgs)} SVG diagrams in {DIAG_DIR}")


if __name__ == "__main__":
    main()

