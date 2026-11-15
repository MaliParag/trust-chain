#!/usr/bin/env python3
"""
Batch 2 supplementary SVG diagram generator (Chapters 6-10) for The Apple Trust Chain (Volume II).
Generates 5 collision-verified SVGs (06-extra-*.svg through 10-extra-*.svg) using shared tools/diagram_lib.py.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_sequence,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def gen_06_extra():
    build_fan_bands(
        P("06-extra-macho-superblob-slots.svg"),
        "Mach-O LC_CODE_SIGNATURE SuperBlob & CS_CodeDirectory Hash Slots",
        [
            [
                {
                    "id": "sb",
                    "tag": "Mach-O __LINKEDIT · CSMAGIC_EMBEDDED_SIGNATURE (0xfade0cc0)",
                    "title": "CS_SuperBlob Typed Index Table (CS_BlobIndex[])",
                    "body": "Indexes CodeDirectory (0x0), Requirements (0x2), XML/DER Entitlements (0x5 / 0x7), Launch Constraints (0x8..0xb), CMS Signature (0x10000), & Notary Ticket (0x10002)",
                    "theme": "slate",
                },
            ],
            [
                {
                    "id": "neg1",
                    "tag": "Special Slots -1..-5",
                    "title": "Bundle & Legacy Metadata",
                    "body": "h[-1] Info.plist · h[-2] Internal Requirements · h[-3] CodeResources · h[-5] XML Entitlements (0xfade7171)",
                    "theme": "white",
                },
                {
                    "id": "neg7",
                    "tag": "Special Slots -7..-11",
                    "title": "DER Entitlements & LWCR",
                    "body": "h[-7] ASN.1 DER Entitlements (0xfade7172) · h[-8..-11] Self, Parent, Responsible, & Library Constraints (0xfade8181)",
                    "theme": "purple",
                },
                {
                    "id": "pos",
                    "tag": "Positive Slots 0..P-1",
                    "title": "4 KB Executable Code Pages",
                    "body": "h[0..P-1] per-page SHA-256 digests covering __TEXT up to codeLimit64; verified lazily on page-in",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "cdh",
                    "tag": "Canonical Identity · CDHash = Trunc_160(SHA-256(CS_CodeDirectory))",
                    "title": "TXM (GL0) Trust Cache / CoreTrust Anchor + XNU vm_fault Page-In Gate",
                    "body": "Binds metadata slots and 4 KB code pages into a single 20-byte CDHash; page mismatch clears CS_VALID and triggers SIGKILL under CS_KILL",
                    "theme": "green",
                },
            ],
        ],
        [
            ("sb", "neg1", "binds bundle", "slate", False),
            ("sb", "neg7", "canonical DER", "purple", False),
            ("sb", "pos", "4 KB chunks", "teal", False),
            ("neg1", "cdh", "hashed in CD", "slate", False),
            ("neg7", "cdh", "TXM parsed", "purple", False),
            ("pos", "cdh", "ubc_cs_page_validate", "green", False),
        ],
        footer="Every negative metadata digest and positive 4 KB page digest sits inside CS_CodeDirectory, so mutating entitlements or resources changes CDHash.",
    )


def gen_07_extra():
    build_fan_bands(
        P("07-extra-iokit-jsc-sandbox-surface.svg"),
        "WebContent Renderer Hardening vs. Residual IOKit Kernel Surface",
        [
            [
                {
                    "id": "jsc1",
                    "tag": "JSC Type Isolation",
                    "title": "StructureID Contiguous Heap",
                    "body": "2 GB (iOS) / 4 GB (macOS) Structure reservation; tryDecode() bounds-checks 32-bit offsets and nukedStructureIDBit",
                    "theme": "purple",
                },
                {
                    "id": "jsc2",
                    "tag": "bmalloc Pointer Caging",
                    "title": "16 GB / 64 GB Primitive Gigacage",
                    "body": "Masks TypedArray & ArrayBuffer backing pointers into isolated virtual cage away from JSObject vtables",
                    "theme": "teal",
                },
                {
                    "id": "jsc3",
                    "tag": "Thread-Local W^X",
                    "title": "APRR Fast JIT Toggle",
                    "body": "pthread_jit_write_protect_np flips core-local permission register so JIT pages never map global RWX",
                    "theme": "slate",
                },
            ],
            [
                {
                    "id": "sbx",
                    "tag": "Seatbelt MACF Containment · Sandbox.kext Bytecode VM",
                    "title": "Default-Deny Filter Over VFS, bootstrap_look_up, Syscall Bitmasks, & iokit-open-user-client",
                    "body": "Blocks direct file/socket access and strips 95%+ of IOKit classes; mediates graphics via narrow GPU Extension & residual user-clients",
                    "theme": "amber",
                },
            ],
            [
                {
                    "id": "iok",
                    "tag": "Residual EL1 Kernel Attack Surface",
                    "title": "IOUserClient::externalMethod Selector Dispatch",
                    "body": "IOConnectCallMethod passes scalarInput[16] & structureInput; CVE-2021-30807 hit IOMobileFramebuffer selector #83 OOB index",
                    "theme": "red",
                },
                {
                    "id": "harden",
                    "tag": "Modern Kernel Countermeasure",
                    "title": "IOExternalMethodDispatch2022 & DriverKit",
                    "body": "Enforces per-selector checkEntitlement, scalar/struct bounds, single-thread locking, and SPTM/MIE heap isolation",
                    "theme": "green",
                },
            ],
        ],
        [
            ("jsc1", "sbx", "post-RCE", "purple", False),
            ("jsc2", "sbx", "post-RCE", "teal", False),
            ("jsc3", "sbx", "ROP/JOP only", "slate", False),
            ("sbx", "iok", "allowed selector", "red", False),
            ("sbx", "harden", "filtered trap", "green", False),
        ],
        footer="Even after defeating StructureID, Gigacage, and APRR inside WebContent, an attacker can reach EL1 only through Seatbelt-permitted Mach and IOKit selectors.",
    )


def gen_08_extra():
    build_split_domains(
        P("08-extra-tcc-database-eval-flow.svg"),
        "macOS Dual TCC.db Scopes, Attribution Evaluation, & BTM Persistence",
        {
            "label": "System Scope (root tccd.system)",
            "theme": "slate",
            "cards": [
                {
                    "tag": "SIP & UF_DATAVAULT Sealed",
                    "title": "/Library/.../com.apple.TCC/TCC.db",
                    "body": "Stores machine-wide grants: SystemPolicyAllFiles (FDA), ScreenCapture, Accessibility, ListenEvent, EndpointSecurityClient",
                    "theme": "white",
                },
                {
                    "tag": "Enterprise Override",
                    "title": "MDM PPPC Configuration Profile",
                    "body": "Supervised com.apple.TCC.configuration-profile-policy pre-authorizes FDA/ESF by TeamID + csreq (never silent Camera/Mic)",
                    "theme": "teal",
                    "in_edge": "merges policy",
                },
                {
                    "tag": "Persistence Monitor",
                    "title": "Background Task Management (BTM)",
                    "body": "backgroundtaskmanagementd audits LaunchAgents/Daemons, alerts user, & emits NOTIFY_BTM_LAUNCH_ITEM_ADD",
                    "theme": "purple",
                    "in_edge": "guards launchd",
                },
            ],
        },
        {
            "label": "Per-User Scope (UID 501 tccd)",
            "theme": "amber",
            "cards": [
                {
                    "tag": "User Data Vault",
                    "title": "~/Library/.../com.apple.TCC/TCC.db",
                    "body": "Stores per-user grants: Desktop, Documents, Downloads, Camera, Microphone, Contacts, & per-target AppleEvents",
                    "theme": "white",
                },
                {
                    "tag": "Kernel Attribution",
                    "title": "audit_token_t + responsible_pid",
                    "body": "XNU resolves unbundled CLI/script callers to parent GUI app and verifies live DER signature against stored csreq blob",
                    "theme": "amber",
                    "in_edge": "evaluates csreq",
                },
                {
                    "tag": "Confused-Deputy Surface",
                    "title": "Ambient Entitlements & Injection",
                    "body": "CVE-2020-9934 ($HOME), CVE-2021-30713 (XCSSET), CVE-2023-26818 (Telegram DYLD), HM Surf, & CVE-2025-43530 (scrod)",
                    "theme": "red",
                    "in_edge": "bypass vector",
                },
            ],
        },
        bridges=[
            (1, 1, "both", "XPC upcall", "slate"),
        ],
        boundary_label="System vs. User Consent Plane",
        footer="Both TCC.db stores sit behind UF_DATAVAULT, forcing attackers to subvert responsible_pid attribution or Apple-entitled daemons rather than editing SQLite directly.",
    )


def gen_09_extra():
    build_fan_bands(
        P("09-extra-ios-forensic-artifact-survival.svg"),
        "Locked-iOS Spyware Triage: Volatile Implant Wipe vs. Surviving Forensic Artifacts",
        [
            [
                {
                    "id": "imp",
                    "tag": "AFU Exploitation · Pegasus, Predator, & Operation Triangulation",
                    "title": "Volatile In-Memory / Staging Implant (/private/var/db/... or /private/var/tmp/)",
                    "body": "APFS Signed System Volume blocks rootfs persistence; reboot or 72-hour AFU inactivity timer wipes implant binary and RAM state",
                    "theme": "red",
                },
            ],
            [
                {
                    "id": "sd",
                    "tag": "Reboot Barrier Ledger",
                    "title": "Shutdown.log",
                    "body": "Logs PIDs & anomalous /private/var/db/ paths delaying SIGTERM during clean shutdown",
                    "theme": "amber",
                },
                {
                    "id": "du",
                    "tag": "symptomsd Accounting",
                    "title": "DataUsage & netusage.sqlite",
                    "body": "Retains orphaned ZPROCESS names, timestamps, & WAN byte counts after binary unlink",
                    "theme": "teal",
                },
                {
                    "id": "bm",
                    "tag": "Append-Only Streams",
                    "title": "Biome SEGB Segments",
                    "body": "Segmented binary records preserve tombstoned app/focus/device events with timestamps",
                    "theme": "purple",
                },
                {
                    "id": "cr",
                    "tag": "Fault Telemetry",
                    "title": "ips Crash & Cache.db",
                    "body": "Captures BlastDoor / imagent / WebKit EXC_BAD_ACCESS traces & attachment fetch artifacts",
                    "theme": "slate",
                },
            ],
            [
                {
                    "id": "mvt",
                    "tag": "Offline Acquisition & Correlation · Zero Third-Party Kernel Hooks Required",
                    "title": "sysdiagnose Archive + Encrypted Backup Parsed by Mobile Verification Toolkit (MVT)",
                    "body": "Correlates cross-database timeline anomalies and STIX2 indicators to prove compromise months after reboot",
                    "theme": "green",
                },
            ],
        ],
        [
            ("imp", "sd", "SIGTERM lag", "amber", False),
            ("imp", "du", "WAN sockets", "teal", False),
            ("imp", "bm", "state events", "purple", False),
            ("imp", "cr", "parser faults", "slate", False),
            ("sd", "mvt", "sysdiagnose", "green", False),
            ("du", "mvt", "encrypted backup", "green", False),
            ("bm", "mvt", "SEGB parse", "green", False),
            ("cr", "mvt", "IOC timeline", "green", False),
        ],
        footer="Even when mercenary spyware deletes its staged files and vanishes on reboot, independent system ledgers preserve durable execution and network traces.",
    )


def gen_10_extra():
    build_sequence(
        P("10-extra-class-b-asymmetric-wrap.svg"),
        "Class B (NSFileProtectionCompleteUnlessOpen) Asymmetric Write-While-Locked Flow",
        [
            {"title": "Background Daemon", "sub": "Mail / Health (Locked AFU)", "theme": "slate"},
            {"title": "apfs.kext & AKS", "sub": "cprotect / j_crypto_val_t", "theme": "teal"},
            {"title": "Secure Enclave (SEP)", "sub": "SKS SystemKeybag", "theme": "purple"},
            {"title": "ANS NVMe Engine", "sub": "Inline AES-256-XTS", "theme": "green"},
        ],
        [
            (2, 2, "Screen locks: SEP wipes Class B private key d_B; keeps public Q_B = d_B * G", "red", False),
            (0, 1, "open_dprotected_np(CLASS_B) while device is locked", "slate", False),
            (1, 2, "Request ephemeral ECDH wrap under public Q_B", "teal", False),
            (2, 1, "Mint K_file + ephemeral (e_f, Q_f); wrap K_file via HKDF(e_f * Q_B); zero e_f", "purple", False),
            (1, 3, "Store (Q_f, wrapped K_file) in j_crypto_val_t; stream XTS-AES blocks", "green", False),
            (0, 1, "close(fd) -> apfs.kext zeroes unwrapped K_file in RAM", "amber", True),
            (2, 1, "Later user unlock: SEP unwraps d_B, computes d_B * Q_f, recovers K_file", "green", False),
        ],
        boundary_after=1,
        boundary_label="AP / SEP Hardware Key Boundary",
        footer="Asymmetric ECDH allows locked background daemons to write new encrypted Class B files without holding keys to read closed Class B files.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_06_extra()
    gen_07_extra()
    gen_08_extra()
    gen_09_extra()
    gen_10_extra()
    print("SUCCESS: Generated and 7-way collision-verified 5 Batch-2 supplementary SVGs.")


if __name__ == "__main__":
    main()
