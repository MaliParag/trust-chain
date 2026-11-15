#!/usr/bin/env python3
"""Batch 2 extra diagram generator for Chapters 6-10 of The Android Trust Chain."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", "tools"))
sys.path.insert(0, TOOLS_ROOT)

from diagram_lib import (  # noqa: E402
    build_fan_bands,
    build_split_domains,
    build_sequence,
    build_horizontal_pipeline,
)


def generate_extra_b2(diag_dir: str) -> None:
    os.makedirs(diag_dir, exist_ok=True)

    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 1. Ch 6: 06-extra-cil-treblesplit-mls.svg
    build_fan_bands(
        P("06-extra-cil-treblesplit-mls.svg"),
        "Treble Split CIL Policy Compilation & MCS Category Pair App Isolation",
        bands=[
            [
                {
                    "id": "plat_cil",
                    "tag": "/system/etc/selinux · Platform",
                    "title": "plat_sepolicy.cil + mapping/YYYYMM.cil",
                    "body": "Holds private framework domains, current public types, and backward-compatible versioned attribute maps",
                    "theme": "slate",
                },
                {
                    "id": "vend_cil",
                    "tag": "/vendor/etc/selinux · Vendor",
                    "title": "vendor_sepolicy.cil + plat_pub_versioned.cil",
                    "body": "Binds SoC HAL rules to frozen versioned attributes (hal_camera_202504) without touching private types",
                    "theme": "teal",
                },
            ],
            [
                {
                    "id": "secilc",
                    "tag": "First-Stage init · system/core/init/selinux.cpp",
                    "title": "secilc Merge, neverallow Check, & /sys/fs/selinux/load",
                    "body": "Links platform + mapping + vendor CIL trees into one binary policy and locks enforce = 1 before daemon spawn",
                    "theme": "green",
                }
            ],
            [
                {
                    "id": "app_a",
                    "tag": "User 0 · App A (u0_a214)",
                    "title": "u:r:untrusted_app:s0:c214,c256,c512,c768",
                    "body": "seapp_contexts encodes appId (c214,c256) + userId 0 (c512,c768); matches own app_data_file only",
                    "theme": "purple",
                },
                {
                    "id": "app_b",
                    "tag": "User 10 · Work App (u10_a214)",
                    "title": "u:r:untrusted_app:s0:c214,c256,c522,c768",
                    "body": "Same untrusted_app type and appId, but distinct user category c522; mlsconstrain blocks cross-profile read",
                    "theme": "amber",
                },
            ],
        ],
        edges=[
            ("plat_cil", "secilc", "supplies mapping + core", "slate", False),
            ("vend_cil", "secilc", "links versioned HALs", "teal", False),
            ("secilc", "app_a", "enforces mlsconstrain", "purple", False),
            ("secilc", "app_b", "isolates profile categories", "amber", False),
        ],
        footer="Split CIL lets /system update via OTA without breaking /vendor HALs, while MCS category pairs isolate apps sharing untrusted_app.",
    )

    # 2. Ch 7: 07-extra-mediaserver-to-hal-isolation.svg
    build_split_domains(
        P("07-extra-mediaserver-to-hal-isolation.svg"),
        "De-Privileging Media & Hardware Stacks: Pre-Treble mediaserver vs. Treble HALs",
        left={
            "label": "Android 4-6 · Monolithic mediaserver",
            "theme": "red",
            "cards": [
                {
                    "tag": "Single Address Space · UID 1013",
                    "title": "Parsers + Codecs + Camera + Audio Combined",
                    "body": "libstagefright MP4/MKV extractors ran in-process alongside camera, mic, Bluetooth, and dlopen() vendor .so blobs",
                    "theme": "white",
                },
                {
                    "tag": "Stagefright Failure · CVE-2015-1538",
                    "title": "One Integer Overflow Compromises All Hardware",
                    "body": "Remote MMS or browser video heap corruption immediately yielded camera/audio snooping and wide /dev ioctl reach",
                    "theme": "red",
                    "in_arrow": True,
                },
            ],
        },
        right={
            "label": "Android 8-16 · Split Media + Treble AIDL HALs",
            "theme": "green",
            "cards": [
                {
                    "tag": "Mainline APEX · media.extractor & media.swcodec",
                    "title": "Zero-Device, No-Network seccomp Parser Jail",
                    "body": "Container parsers hold zero file descriptors or /dev nodes; read bytes strictly over Binder DataSource",
                    "theme": "white",
                },
                {
                    "tag": "Isolated /vendor Daemons · Stable AIDL",
                    "title": "hal_camera, hal_codec2, & hal_audio_default",
                    "body": "Each vendor HAL runs in its own UID, SELinux domain, and seccomp filter with zero network socket capability",
                    "theme": "green",
                    "in_arrow": True,
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "splits parsers + seccomp", "green"),
            (1, 1, "lr", "isolates vendor .so -> AIDL", "teal"),
        ],
        boundary_label="Architectural Blast-Radius Containment",
        footer="Breaking mediaserver into restricted Mainline sandboxes and Binderized Treble HALs forces attackers to chain multiple cross-process bugs.",
    )

    # 3. Ch 8: 08-extra-tiktag-speculative-oracle.svg
    build_sequence(
        P("08-extra-tiktag-speculative-oracle.svg"),
        "TIKTAG-v1 / TIKTAG-v2 Speculative MTE Tag Oracle vs. Layered Defenses",
        actors=[
            {"title": "Attacker Script", "sub": "Guessed Tag Tg in [59:56]", "theme": "red"},
            {"title": "Branch & ROB", "sub": "Mispredicted Window", "theme": "amber"},
            {"title": "MTE & Cache/LSQ", "sub": "Granule Tag Tm Check", "theme": "purple"},
            {"title": "Android Mitigations", "sub": "Browser & OS Gates", "theme": "green"},
        ],
        messages=[
            (0, 1, "Train branch predictor, then feed slow false branch + guess_ptr(Tg)", "red", False),
            (1, 2, "Speculatively execute CHECK loads (v1) or store-to-load pair (v2)", "amber", False),
            (2, 2, "Mismatch (Tg != Tm): squash architectural SEGV_MTESERR on mispredicted path", "purple", False),
            (2, 0, "Microarchitectural delta: v1 shrinks prefetch/speculation; v2 blocks STLF", "red", True),
            (0, 0, "Time L1 cache hit on probe_ptr over Tg in 1..15 -> leak Tm in < 4s without crash!", "red", True),
            (3, 0, "Advanced Protection: disable V8 JIT + WebGPU & isolate sites / timers", "green", False),
        ],
        boundary_after=2,
        boundary_label="No Architectural SIGSEGV Raised",
        footer="Speculative tag oracles convert 15/16 crash containment into a silent side channel unless JIT gadget compilation or speculation shrinkage is blocked.",
    )

    # 4. Ch 9: 09-extra-parcel-mismatch-confused-deputy.svg
    build_horizontal_pipeline(
        P("09-extra-parcel-mismatch-confused-deputy.svg"),
        "Parcel Read/Write Deserialization Mismatch (LaunchAnywhere / CVE-2023-20963)",
        stages=[
            {
                "tag": "Stage 1 · Attacker App",
                "title": "Crafts Asymmetric Bundle",
                "body": "Packs malformed WorkSource + hidden Intent key-value bytes inside Bundle",
                "theme": "red",
            },
            {
                "tag": "Stage 2 · First Unparcel",
                "title": "system_server Reads N Bytes",
                "body": "Buggy createFromParcel() advances cursor out of sync; dangerous Intent stays hidden",
                "theme": "amber",
            },
            {
                "tag": "Stage 3 · Re-Serialize",
                "title": "writeToParcel() Writes M != N",
                "body": "system_server re-writes WorkSource cleanly, shifting cursor onto attacker bytes!",
                "theme": "purple",
            },
            {
                "tag": "Stage 4 · Second Unparcel",
                "title": "KEY_INTENT Emerges as UID 1000",
                "body": "AccountManager / ActivityManager launches arbitrary internal Activity as system!",
                "theme": "red",
            },
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Android 13-16 Structural Fix",
            "title": "Per-Item LazyValue Length Prefixing & Typed getParcelable(Class)",
            "body": "Enforces exact byte-count framing around every Bundle entry and CreatorToken checks on nested Intents",
            "theme": "green",
            "edge_label": "detects M != N",
        },
        footer="When readFromParcel and writeToParcel disagree on byte length, a privileged broker unwittingly mints attacker-controlled Parcelable fields.",
    )

    # 5. Ch 10: 10-extra-v3-key-rotation-lineage.svg
    build_horizontal_pipeline(
        P("10-extra-v3-key-rotation-lineage.svg"),
        "APK Signature Scheme v3 / v3.1 SigningCertificateLineage & Capability Flags",
        stages=[
            {
                "tag": "Node 1 · Original Key K1",
                "title": "2016 Legacy RSA-2048 Cert",
                "body": "Signs delegation Sign_K1(K2 || flags); strips PAST_CERT_PERMISSION on retired K1",
                "theme": "slate",
            },
            {
                "tag": "Node 2 · Rotated Key K2",
                "title": "2021 ECDSA P-256 Cert",
                "body": "Signs Sign_K2(K3 || flags); retains PAST_CERT_INSTALLED_DATA for seamless v1 upgrades",
                "theme": "teal",
            },
            {
                "tag": "Leaf · Active Key K3",
                "title": "2026 HSM P-384 Signer",
                "body": "Signs APK v3.1 block (0x1b93ad61) + full lineage attribute (0x3ba06f8c)",
                "theme": "green",
            },
            {
                "tag": "Gate · PackageManager",
                "title": "Lineage & SDK Verification",
                "body": "Verifies unbroken chain from pinned K1/K2 to K3 + 1 MiB Merkle digest",
                "theme": "purple",
            },
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Backward Compatibility · Block 0xf05368c0 vs. 0x1b93ad61",
            "title": "v3.1 Targets API 33+ While v3 Block Preserves Legacy Signer for Older SDKs",
            "body": "Includes rotation-min-sdk-version stripping protection inside signed data so attackers cannot downgrade lineage",
            "theme": "amber",
            "edge_label": "SDK targeting",
        },
        footer="Self-certified proof-of-rotation frees Android apps from permanent TOFU key lock-in without introducing a central CA single point of failure.",
    )


if __name__ == "__main__":
    out_dir = os.path.abspath(os.path.join(HERE, "..", "src", "diagrams"))
    generate_extra_b2(out_dir)
    print("Generated and collision-verified 5 extra Batch 2 SVG diagrams in", out_dir)
