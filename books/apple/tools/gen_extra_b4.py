#!/usr/bin/env python3
"""
Batch 4 standalone SVG generator for Chapters 16-20 (Volume II: The Apple Trust Chain).
Generates 5 collision-verified architectural diagrams into books/apple/src/diagrams/:
  - 16-extra-kt-vrf-merkle-tree.svg
  - 17-extra-p224-ratchet-ecies-math.svg
  - 18-extra-tcc-responsible-pid-confused-deputy.svg
  - 19-extra-vre-transparency-log-audit.svg
  - 20-extra-triangulation-four-stage-bypass.svg
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def gen_16_kt_vrf_merkle_tree():
    build_fan_bands(
        P("16-extra-kt-vrf-merkle-tree.svg"),
        "Contact Key Verification (KT) VRF-Indexed Prefix Merkle Map and Audit Planes",
        [
            [
                {
                    "id": "reg",
                    "tag": "Account & SEP Registration Plane (Octagon + iCloud Keychain)",
                    "title": "Account ECDSA Key Signs Per-Device SEP P-256 Auth + ML-KEM-1024 / P-256 Prekeys",
                    "body": "IDS logs registration and returns Signed Mutation Timestamp (SMT) promising map merge within 48h MMD",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "vrf",
                    "tag": "RFC 9381 ECVRF Privacy Index",
                    "title": "idx = SHA-256(VRF_sk(URI))",
                    "body": "Pseudorandom 256-bit leaf index + pi_VRF proof blocks phone/email directory scraping",
                    "theme": "purple",
                },
                {
                    "id": "map",
                    "tag": "CONIKS / SEEMless Sparse Prefix Tree",
                    "title": "Verifiable Log-Backed Map",
                    "body": "Stores salted commitment to Account Key, device vector, and KT opt-in flag at prefix idx",
                    "theme": "teal",
                },
                {
                    "id": "sth",
                    "tag": "Monotonic Append-Only Log (>2B/wk)",
                    "title": "Signed Tree Heads (STH)",
                    "body": "Commits each map revision into an immutable Merkle consistency chain across epochs",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "sender",
                    "tag": "Peer Lookup & Piggyback Gossip",
                    "title": "Sender Inclusion + STH Gossip",
                    "body": "identityservicesd checks pi_VRF + pi_Merkle and gossips STH hashes inside iMessage traffic",
                    "theme": "green",
                },
                {
                    "id": "owner",
                    "tag": "Owner Self-Audit (transparencyd)",
                    "title": "KT Leaf vs. E2EE CloudKit Circle",
                    "body": "Every trusted device audits own URI against Octagon/CloudKit state and flags ghost keys",
                    "theme": "green",
                },
                {
                    "id": "sas",
                    "tag": "High-Assurance Out-of-Band Pin",
                    "title": "Vaudenay SAS / Static APVR Code",
                    "body": "8-digit live code or Contact card APVR URI pins Account Key hash across future upgrades",
                    "theme": "green",
                },
            ],
        ],
        [
            ("reg", "vrf", "maps URI", "purple", False),
            ("reg", "map", "merges SMT <= 48h", "teal", False),
            ("reg", "sth", "signs epoch", "amber", False),
            ("vrf", "sender", "verifies pi_VRF", "green", False),
            ("map", "owner", "audits device set", "green", False),
            ("sth", "sas", "pins root + key", "green", False),
        ],
        footer="Combining VRF index hiding, SMT merge bounds, encrypted in-band STH gossip, and Octagon self-auditing defeats silent IDS key injection.",
    )


def gen_17_p224_ratchet_ecies_math():
    build_fan_bands(
        P("17-extra-p224-ratchet-ecies-math.svg"),
        "Offline Find My Affine P-224 Key Diversification and ECIES Report Construction",
        [
            [
                {
                    "id": "own_seed",
                    "tag": "Owner SEP & Octagon Keychain Circle",
                    "title": "Master P-224 Pair (d_0, P_0 = d_0*G) + 256-Bit Seed SK_0",
                    "body": "Private scalar d_0 stays E2EE inside owner Keychain circle; never transmitted to Apple servers",
                    "theme": "slate",
                },
                {
                    "id": "acc_state",
                    "tag": "Offline Accessory / BLE Reserve Firmware",
                    "title": "Provisioned With Public Point (P_0, SK_0) Only",
                    "body": "AirTag MCU omits d_0 so physical chip decapping cannot recover pre-compromise private scalars",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "ratchet",
                    "tag": "Autonomous Symmetric Ratchet & Affine Scalar Blinding (secp224r1, 112-Bit Security)",
                    "title": "SK_i = KDF(SK_{i-1}, 'update'); (u_i, v_i) = KDF(SK_i, 'diversify') -> P_i = u_i*P_0 + v_i*G",
                    "body": "Fits exact 28-byte compressed x(P_i) into 31-byte BLE legacy PDU (6B Random Static MAC + 22B Manufacturer Payload)",
                    "theme": "amber",
                }
            ],
            [
                {
                    "id": "finder",
                    "tag": "Stranger Finder iPhone (searchpartyd)",
                    "title": "ECIES: (K_enc, IV) = X9.63-KDF(e*P_i, Q_e || P_i)",
                    "body": "Encrypts Finder GPS via AES-128-GCM and uploads <SHA-256(P_i), Q_e, C_loc, tag> anonymously",
                    "theme": "purple",
                },
                {
                    "id": "recover",
                    "tag": "Owner Recovery (Find My.app)",
                    "title": "d_i = (u_i*d_0 + v_i) mod q -> ECDH(d_i, Q_e) = e*P_i",
                    "body": "Batch-queries Apple blind KV table by SHA-256(P_i) window and unwraps AES-GCM coordinates locally",
                    "theme": "green",
                },
            ],
        ],
        [
            ("own_seed", "ratchet", "syncs P_0, SK_0", "slate", False),
            ("acc_state", "ratchet", "steps every 15m / 24h", "teal", False),
            ("ratchet", "finder", "BLE advertises P_i", "purple", False),
            ("ratchet", "recover", "recomputes SHA-256(P_i)", "green", False),
        ],
        footer="Affine blinding lets accessories roll unlinkable public keys P_i without holding d_0 while preserving algebraic owner decryption.",
    )


def gen_18_tcc_responsible_pid_confused_deputy():
    build_vertical_flow(
        P("18-extra-tcc-responsible-pid-confused-deputy.svg"),
        "macOS TCC responsible_pid Attribution Chain and Coding-Agent Confused Deputy",
        [
            {
                "tag": "Stage 1 · Consented Parent App Bundle",
                "title": "Developer Terminal or AI IDE Holds Broad User TCC.db Grants",
                "body": "Terminal.app, iTerm2, Xcode, or IDE approved for Full Disk Access, ~/Documents, SSH agent, and AppleEvents",
                "theme": "slate",
            },
            {
                "tag": "Stage 2 · Subprocess Tree Inheritance (posix_spawn / fork)",
                "title": "Host Spawns CLI Coding Agent, xcrun mcpbridge, or stdio MCP Server",
                "body": "Unbundled child binaries inherit parent Mach responsibility ledger token unless explicitly disclaimed",
                "theme": "amber",
                "edge_label": "spawns agent / MCP",
                "edge_color": "#b07926",
            },
            {
                "tag": "Stage 3 · Untrusted Workspace & Context Ingestion",
                "title": "Agent Parses Cloned Repo, AGENTS.md, or Poisoned MCP Tool Output",
                "body": "Indirect prompt injection, MCP tool rug pull, or malicious build hook steers child process commands",
                "theme": "red",
                "edge_label": "ingests untrusted input",
                "edge_color": "#8d2d3b",
            },
            {
                "tag": "Stage 4 · Kernel MACF & tccd Attribution Lookup",
                "title": "responsibility_get_pid_for_audit_token() Resolves Child Back to IDE",
                "body": "tccd checks parent bundle's TCC.db record (auth_value = 2) rather than prompting for the unbundled CLI child",
                "theme": "purple",
                "edge_label": "queries audit_token_t",
            },
            {
                "tag": "Stage 5 · Silent Ambient Authority Exercise",
                "title": "Zero-Prompt Access to ~/.ssh, ~/.aws, login.keychain-db, and TCC Folders",
                "body": "Exfiltrates cloud credentials, browser cookies, or pivots via AppleEvents automation (CVE-2025-43530)",
                "theme": "red",
                "edge_label": "grants silent access",
                "edge_color": "#8d2d3b",
            },
        ],
        side_notes={
            1: {
                "tag": "Architectural Fix",
                "title": "Per-Container Micro-VM",
                "body": "apple/container boots Virtualization.framework Linux VM + vminitd, severing host PID & TCC tree",
                "theme": "green",
                "dashed": False,
                "edge_label": "severs host tree",
                "edge_color": "#2b6a4c",
            },
            3: {
                "tag": "Confused Deputy",
                "title": "Zero User TCC Prompts",
                "body": "Consent granted for human typing silently authorizes autonomous prompt-injected subprocesses",
                "theme": "red",
                "edge_label": "bypasses UI prompt",
                "edge_color": "#8d2d3b",
            },
        },
        footer="Because macOS attributes unbundled CLI tools to their responsible GUI parent, host-run coding agents inherit ambient user authority.",
    )


def gen_19_vre_transparency_log_audit():
    build_fan_bands(
        P("19-extra-vre-transparency-log-audit.svg"),
        "Private Cloud Compute Release Transparency, Thimble Gate, and VRE Audit Loop",
        [
            [
                {
                    "id": "rel",
                    "tag": "Measured Server Release Bundle",
                    "title": "Apple Silicon Image4 + Cryptexes OR Google Cloud A4 aCOS + Megacontainer",
                    "body": "Canonicalizes OS, darwin-init, model/adapter cryptex manifests, or Titan/TDX/B200 digests into release record",
                    "theme": "slate",
                },
                {
                    "id": "pub",
                    "tag": "Public Binary & Source Artifacts",
                    "title": "Plaintext iBoot, sepOS, pccOS Images & apple/security-pcc Source",
                    "body": "Publishes inspectable binaries, splunkloggingd allowlists, Thimble, and CloudAttestation code for researchers",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "log",
                    "tag": "Apple Transparency Service (Append-Only Merkle Tree + RFC 9298 MASQUE Proxy)",
                    "title": "Signed Release Ledger With 14-Day Expiry & Daily Promoted Consistency Milestones",
                    "body": "Hardcoded third-party MASQUE proxies blind client IP during log fetches to defeat targeted split-view equivocation",
                    "theme": "purple",
                }
            ],
            [
                {
                    "id": "thimble",
                    "tag": "Client Enforcement (privatecloudcomputed)",
                    "title": "Thimble + CloudAttestation Gate",
                    "body": "Verifies SEP DCIK or Titan+TDX+B200 quotes AND Merkle inclusion before wrapping HPKE prompt keys",
                    "theme": "green",
                },
                {
                    "id": "vre",
                    "tag": "External Audit (pccvre & GCP Tooling)",
                    "title": "PCC Virtual Research Environment",
                    "body": "Simulates AP + SEP on macOS, boots logged releases, injects debug shells, and audits SPL output",
                    "theme": "amber",
                },
            ],
        ],
        [
            ("rel", "log", "appends digest", "purple", False),
            ("pub", "log", "matches hashes", "teal", False),
            ("log", "thimble", "proves inclusion", "green", False),
            ("log", "vre", "audits published build", "amber", False),
        ],
        footer="User devices refuse unlogged server binaries while researchers boot the exact logged images inside macOS pccvre.",
    )


def gen_20_triangulation_four_stage_bypass():
    build_vertical_flow(
        P("20-extra-triangulation-four-stage-bypass.svg"),
        "Operation Triangulation (2023): Four-Zero-Day Chain Past BlastDoor and Silicon PPL",
        [
            {
                "tag": "Zero-Day 1 · CVE-2023-41990 (FontParser)",
                "title": "Invisible Zero-Click iMessage Attachment Triggers Legacy TrueType ADJUST Overflow",
                "body": "Undocumented 1990s Apple-only TrueType font instruction corrupts heap to bootstrap ROP and NSExpression stages",
                "theme": "red",
            },
            {
                "tag": "Stage 2 · JavaScriptCore DollarVM + PAC Bypass",
                "title": "11,000-Line Obfuscated JS Stage Unlocks JSC Debugging Gadgets & Forges Pointers",
                "body": "Patches JavaScriptCore internal flags via NSPredicate reflection to gain arbitrary native API calls without JIT",
                "theme": "amber",
                "edge_label": "NSExpression -> JSC",
                "edge_color": "#b07926",
            },
            {
                "tag": "Zero-Day 2 · CVE-2023-32434 (XNU Mach VM)",
                "title": "mach_make_memory_entry + vm_map Integer Overflow Maps Physical RAM Into User Space",
                "body": "Grants user-mode exploit direct R/W over entire physical DRAM, yet CPU APRR/PPL still blocks page-table writes",
                "theme": "purple",
                "edge_label": "maps physical RAM",
            },
            {
                "tag": "Zero-Day 3 · CVE-2023-38606 (Silicon MMIO DMA)",
                "title": "Writes Target Physical Address, Data, & Hash to Unadvertised gfx-asc Registers",
                "body": "Powers GPU block, halts core via 0x206040000 UTT, and triggers 0x206140008..0x206150048 hardware DMA around PPL",
                "theme": "red",
                "edge_label": "hardware MMIO write",
                "edge_color": "#8d2d3b",
            },
            {
                "tag": "Zero-Day 4 · CVE-2023-32435 (WebKit + Implant)",
                "title": "Scrubs IMAgent Forensics, Validates Victim in Hidden WebKit View, & Deploys Implant",
                "body": "Re-exploits CVE-2023-32434 + CVE-2023-38606 from Mach-O payload; operates strictly in AFU RAM until reboot",
                "theme": "slate",
                "edge_label": "deploys TriangleDB",
            },
        ],
        side_notes={
            0: {
                "tag": "Parser Elimination",
                "title": "TrueType Rewritten in Swift",
                "body": "Apple removed ADJUST in iOS 16.6 and replaced legacy C TrueType parser with memory-safe Swift",
                "theme": "green",
                "dashed": False,
                "edge_label": "deletes C bug class",
                "edge_color": "#2b6a4c",
            },
            3: {
                "tag": "Silicon Response",
                "title": "MMIO Fence + SPTM (GL2)",
                "body": "Firmware locked unadvertised MMIO ranges; A17 Pro+ SPTM isolates page tables & IOMMU tables",
                "theme": "green",
                "dashed": False,
                "edge_label": "locks SoC fabric",
                "edge_color": "#2b6a4c",
            },
        },
        footer="When CPU APRR/PPL blocked direct page-table writes, Triangulation routed around the CPU core through undocumented SoC MMIO registers.",
    )


if __name__ == "__main__":
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_16_kt_vrf_merkle_tree()
    gen_17_p224_ratchet_ecies_math()
    gen_18_tcc_responsible_pid_confused_deputy()
    gen_19_vre_transparency_log_audit()
    gen_20_triangulation_four_stage_bypass()
    print("Successfully generated 5 collision-verified Batch 4 extra SVG diagrams in", DIAG_DIR)
