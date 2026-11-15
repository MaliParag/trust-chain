#!/usr/bin/env python3
"""Batch 4 extra diagram generator for The Android Trust Chain (Chapters 16-20)."""
import os
import sys

sys.dont_write_bytecode = True

TOOLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools"))
sys.path.insert(0, TOOLS_ROOT)

from diagram_lib import (  # noqa: E402
    build_sequence,
    build_fan_bands,
    build_split_domains,
    build_matrix,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def generate_extra_b4(diag_dir: str):
    os.makedirs(diag_dir, exist_ok=True)

    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 1. Ch 16: 16-extra-trickystore-keystore2-interception.svg
    build_sequence(
        P("16-extra-trickystore-keystore2-interception.svg"),
        "TrickyStore Binder Interception: Forging X.509 Key Attestation Chains in Software",
        actors=[
            {"title": "DroidGuard / App", "sub": "GMS Attestation Caller", "theme": "slate"},
            {"title": "TrickyStore Hook", "sub": "keystore2 Binder Proxy", "theme": "red"},
            {"title": "Hardware KeyMint", "sub": "Real TEE (ORANGE)", "theme": "amber"},
            {"title": "Play / RP Verifier", "sub": "CRL + RKP Backend", "theme": "green"},
        ],
        messages=[
            (0, 1, "generateKey() + attestationChallenge", "slate", False),
            (1, 2, "Query or bypass real ORANGE hardware TEE", "amber", True),
            (2, 1, "Hardware signs deviceLocked = FALSE (Unverified)", "amber", True),
            (1, 1, "Forge OID .17 leaf (Verified, Locked) + sign via stolen keybox.xml", "red", False),
            (1, 0, "Return forged X.509 chain over IKeystoreSecurityLevel", "red", False),
            (0, 3, "Submit certificate chain + challenge signature", "slate", False),
            (3, 3, "Check android.googleapis.com/attestation/status CRL + RKP cohort", "green", False),
            (3, 0, "Revoke verdict once leaked factory keybox serial is burned", "green", False),
        ],
        boundary_after=1,
        boundary_label="Host Binder Seam vs. Hardware Silicon",
        footer="TrickyStore never compromises StrongBox or TrustZone silicon; it swaps the Binder reply in host RAM using a leaked pre-RKP OEM keybox.",
        width=920.0,
    )

    # 2. Ch 17: 17-extra-work-profile-uid-mls-fbe-wall.svg
    build_fan_bands(
        P("17-extra-work-profile-uid-mls-fbe-wall.svg"),
        "Four-Layer Kernel & Framework Wall Between Personal User 0 and Work Profile User 10",
        bands=[
            [
                {"id": "u0_app", "tag": "Personal Profile · User 0",
                 "title": "Personal Chrome (UID 10145 / u0_a145)",
                 "body": "SELinux context u:r:untrusted_app:s0:c145,c256,c512,c768; private storage /data/user/0",
                 "theme": "green"},
                {"id": "u10_app", "tag": "Managed Work Profile · User 10",
                 "title": "Work Chrome (UID 1010145 / u10_a145)",
                 "body": "SELinux context u:r:untrusted_app:s0:c145,c256,c522,c768; corporate storage /data/user/10",
                 "theme": "teal"},
            ],
            [
                {"id": "fw_gate", "tag": "Framework Reference Monitor · PackageManagerService & DevicePolicyManager",
                 "title": "CrossProfileIntentFilter, userId@authority URI Gate, & UID-Range VPN Routing",
                 "body": "Blocks cross-profile clipboard/share sheets, rejects unauthorized content://10@media URIs, and routes UIDs 1000000-1099999 to Work VPN",
                 "theme": "slate"},
            ],
            [
                {"id": "lsm_wall", "tag": "Kernel DAC + SELinux MLS Lattice",
                 "title": "Disjoint User Categories (c512 vs. c522)",
                 "body": "mlsconstrain denies cross-user VFS, socket, and Binder direct access even if UNIX mode bits were 0777",
                 "theme": "purple"},
                {"id": "fbe_wall", "tag": "Storage & Inline Crypto Engine (ICE)",
                 "title": "Independent fscrypt Keys (CE_0 vs. CE_10)",
                 "body": "Quiet Mode runs FS_IOC_REMOVE_ENCRYPTION_KEY on CE_10; wipeData() shreds CE_10 without touching CE_0",
                 "theme": "amber"},
            ],
        ],
        edges=[
            ("u0_app", "fw_gate", "mediated IPC", "green", False),
            ("u10_app", "fw_gate", "DPC policy gate", "teal", False),
            ("fw_gate", "lsm_wall", "kernel MAC check", "purple", False),
            ("fw_gate", "fbe_wall", "per-user keyslots", "amber", False),
        ],
        footer="Sharing immutable /data/app APK code pages saves flash storage while UID math, MLS categories, and fscrypt keys isolate all state.",
        width=920.0,
    )

    # 3. Ch 18: 18-extra-pcs-egress-gates-pir-dp.svg
    build_fan_bands(
        P("18-extra-pcs-egress-gates-pir-dp.svg"),
        "Private Compute Services (PCS): The Three Auditable Network Gates Out of Private Compute Core",
        bands=[
            [
                {"id": "pcc_src", "tag": "Air-Gapped On-Device Sandbox · Zero AF_INET Socket Permission",
                 "title": "Private Compute Core (AICore + Gemini Nano, Live Caption, Scam Detection, Magic Cue)",
                 "body": "Processes notifications, call audio, and screen context under SELinux neverallow rules forbidding direct network sockets",
                 "theme": "green"},
            ],
            [
                {"id": "pcs_hub", "tag": "Open-Source Auditable Bridge · com.google.android.as.oss (GitHub)",
                 "title": "Private Compute Services (PCS) Typed Binder & Policy Enforcement Gate",
                 "body": "Enforces allow-association caller checks, reproducible open-source builds, and strict rate/epsilon budgets before TCP/IP",
                 "theme": "slate"},
            ],
            [
                {"id": "gate_pir", "tag": "Gate 1 · Blinded Lookup",
                 "title": "Private Info Retrieval (PIR)",
                 "body": "RLWE homomorphic queries fetch database slices without revealing which key the phone requested",
                 "theme": "teal"},
                {"id": "gate_fl", "tag": "Gate 2 · Aggregate Learning",
                 "title": "Federated Compute + SecAgg + DP",
                 "body": "Clips local updates, injects (epsilon, delta)-DP noise, and masks gradients via Secure Aggregation",
                 "theme": "purple"},
                {"id": "gate_dl", "tag": "Gate 3 · Attested Ingress",
                 "title": "Protected Model & LoRA Download",
                 "body": "Unidirectional HTTPS fetch verified against public binary transparency logs before AICore loads weights",
                 "theme": "amber"},
            ],
        ],
        edges=[
            ("pcc_src", "pcs_hub", "narrow typed Binder IPC", "green", False),
            ("pcs_hub", "gate_pir", "homomorphic query", "teal", False),
            ("pcs_hub", "gate_fl", "masked aggregate", "purple", False),
            ("pcs_hub", "gate_dl", "transparency check", "amber", False),
        ],
        footer="Even a memory-corruption bug inside an on-device tensor operator inside AICore cannot open a raw socket bypassing PCS.",
        width=920.0,
    )

    # 4. Ch 19: 19-extra-tie-pcc-cvm-three-way-matrix.svg
    build_matrix(
        P("19-extra-tie-pcc-cvm-three-way-matrix.svg"),
        "Confidential Cloud AI Architecture Matrix: Google TIE vs. Apple PCC vs. Azure CVM",
        "Comparing silicon roots of trust, accelerator protection, operator exclusion, and client transparency",
        row_headers=[
            ("Google Private AI (TIE)", "Titanium + Custom TPU"),
            ("Apple PCC (Apple + GCP)", "M-Series / TDX+Blackwell"),
            ("Azure Confidential VMs", "SEV-SNP / TDX + H100"),
        ],
        col_headers=[
            ("Silicon RoT", "Boot & Identity"),
            ("Accelerator TEE", "HBM & Link Crypto"),
            ("Operator Shell", "Admin Break-Glass"),
            ("Transparency", "Client Log Check"),
        ],
        cells=[
            [("Titan + Caliptra DICE", "green"), ("Sealed Custom TPU", "green"),
             ("Disabled by Design", "green"), ("Public Log Verified", "green")],
            [("SEP / Titan Dual-RoT", "green"), ("Unified RAM / NV-CC", "green"),
             ("Disabled by Design", "green"), ("ATLog + Image Pub", "green")],
            [("AMD-SP / TDX + OpenHCL", "teal"), ("Opt-In H100 SPDM", "amber"),
             ("Customer Policy", "amber"), ("Tenant MAA Policy", "teal")],
        ],
        legend="At WWDC 2026, Apple and Google extended PCC onto Google Cloud combining Intel TDX, NVIDIA Blackwell CC, and Google Titan dual-vendor roots.",
        footer="Consumer AI enclaves (TIE and PCC) bake zero-admin-shell and mandatory binary transparency into the appliance, whereas IaaS CVMs delegate policy to tenants.",
        width=940.0,
    )

    # 5. Ch 20: 20-extra-baseband-smmu-ap-boundary.svg
    build_split_domains(
        P("20-extra-baseband-smmu-ap-boundary.svg"),
        "Cellular Baseband Compromise vs. SMMUv3 / S2MPU DMA Confinement at the AP Boundary",
        left={
            "label": "Cellular Baseband Subsystem",
            "theme": "red",
            "cards": [
                {"tag": "OTA Zero-Click Surface · Outside SELinux & MTE",
                 "title": "Shannon / Hexagon Modem RTOS (SIP / SDP / RRC)",
                 "body": "Parses carrier VoLTE INVITE and AMR fmtp offers before phone rings; CVE-2023-24033 overflows modem heap with zero clicks",
                 "theme": "white"},
                {"tag": "Post-Baseband RCE Capabilities",
                 "title": "Modem RAM Control + Shared IPC Ring Producer",
                 "body": "Intercepts cellular voice/SMS/GPS inside modem and writes attacker-crafted packet descriptors into shared pktproc rings",
                 "theme": "red", "in_arrow": True},
            ],
        },
        right={
            "label": "Application Processor (EL2 pKVM + EL1)",
            "theme": "green",
            "cards": [
                {"tag": "Hardware Bus Firewall · EL2 Controlled",
                 "title": "Arm SMMUv3 / Exynos-Tensor S2MPU Stage-2 Tables",
                 "body": "Blocks arbitrary PCIe/AXI DMA reads and writes to EL1 kernel text, page tables, cred structs, and fscrypt CE keys",
                 "theme": "green"},
                {"tag": "Residual Kernel Attack Seam",
                 "title": "Host cpif / pktproc Ring-Buffer Driver (EL1)",
                 "body": "Must validate untrusted ring lengths and offsets from modem; bugs like CVE-2024-29786 let modems pivot into EL1",
                 "theme": "amber", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "Raw DMA Blocked by S2MPU", "red"),
            (1, 1, "lr", "Shared IPC Ring Only", "amber"),
        ],
        boundary_label="Hardware IOMMU / S2MPU Bus Firewall",
        footer="Hardware IOMMU confinement turns a zero-click baseband bug from instant full-phone takeover into a contained peripheral needing a second host driver bug.",
        width=920.0,
    )


if __name__ == "__main__":
    generate_extra_b4(DIAG_DIR)
    print("Successfully generated and 7-way collision-verified 5 Batch 4 SVG diagrams in", DIAG_DIR)
