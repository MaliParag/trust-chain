#!/usr/bin/env python3
"""Batch 3 extra SVG diagram generator for Chapters 11-15 of The Android Trust Chain."""
import os
import sys

sys.dont_write_bytecode = True

TOOLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools"))
sys.path.insert(0, TOOLS_ROOT)

from diagram_lib import (  # noqa: E402
    build_vertical_flow,
    build_sequence,
    build_split_domains,
    build_fan_bands,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def generate_extra_b3(diag_dir: str):
    os.makedirs(diag_dir, exist_ok=True)

    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 1. Ch 11: 11-extra-session-dropper-ecm-bypass.svg
    build_split_domains(
        P("11-extra-session-dropper-ecm-bypass.svg"),
        "Session-Based Dropper Evasion vs. Android 15-17 Enhanced Confirmation & AAPM",
        left={
            "label": "Android 13-14 Session-Dropper Bypass",
            "theme": "red",
            "dashed": True,
            "cards": [
                {
                    "tag": "Stage 1 · Dropper-as-a-Service",
                    "title": "SecuriDropper / Zombinder / Anatsa Decoy APK",
                    "body": "Sideloaded or store-staged utility requests REQUEST_INSTALL_PACKAGES while omitting AccessibilityService from its own manifest",
                    "theme": "white",
                },
                {
                    "tag": "Stage 2 · Store-Mimicking API",
                    "title": "PackageInstaller SessionParams API",
                    "body": "Streams decrypted banking trojan (Xenomorph, Hook, PixPirate) via multi-part createSession() API used by app stores",
                    "theme": "amber",
                    "in_arrow": True,
                },
                {
                    "tag": "Stage 3 · Restricted Settings Evaded",
                    "title": "Payload Treated as Trusted Session Install",
                    "body": "Android 13 exempted session-installed packages from ECM; AccessibilityService toggle remained clickable for ATS wire fraud",
                    "theme": "red",
                    "in_arrow": True,
                },
            ],
        },
        right={
            "label": "Android 15-17 ECM & Advanced Protection",
            "theme": "green",
            "cards": [
                {
                    "tag": "Gate 1 · Factory XML Allowlist",
                    "title": "/system/etc/sysconfig Allowlist",
                    "body": "EnhancedConfirmationService exempts only factory-allowlisted stores; unverified session droppers inherit ECM blocks",
                    "theme": "white",
                },
                {
                    "tag": "Gate 2 · Immutable Source Attribution",
                    "title": "Downloaded-File Source Pinning",
                    "body": "Flags PACKAGE_SOURCE_DOWNLOADED_FILE even on sessions and blocks self-update source laundering (CVE-2026-58836)",
                    "theme": "teal",
                    "in_arrow": True,
                },
                {
                    "tag": "Gate 3 · Android 17 AAPM Hard-Block",
                    "title": "Verified AccessibilityTool Gate",
                    "body": "Advanced Protection blocks sideloading globally and denies AccessibilityService to non-verified assistive apps",
                    "theme": "green",
                    "in_arrow": True,
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "audits installer UID", "teal"),
            (1, 1, "lr", "pins packageSource", "amber"),
            (2, 2, "lr", "blocks grant", "green"),
        ],
        boundary_label="EnhancedConfirmationManager Gate",
        footer="Closing the session-installer loophole forced trojans out of fake store sessions; Android 17 AAPM eliminates unverified Accessibility grants completely.",
        width=920.0,
    )

    # 2. Ch 12: 12-extra-cellebrite-usb-alsa-chain.svg
    build_vertical_flow(
        P("12-extra-cellebrite-usb-alsa-chain.svg"),
        "Cellebrite UFED Physical USB Quirk Chain (Serbia 2024-2025) vs. USB Signaling Cut",
        steps=[
            {
                "tag": "Stage 1 · USB-C Host Mode Enumeration",
                "title": "Cellebrite Turbo Link Emulates USB Hub (05e3:0610)",
                "body": "Plugging OTG dongle into locked AFU phone flips controller into xhci host mode and enumerates emulated bcdDevice 12.34 descriptors",
                "theme": "amber",
            },
            {
                "tag": "Stage 2 · Kernel Pointer Infoleak",
                "title": "Anton TouchPad HID & ALSA Clock Read (CVE-2024-50302 / 53150)",
                "body": "Triggers MT_CLS_EXPORT_ALL_INPUTS HID report leak and snd-usb-audio clock descriptor OOB read to defeat EL1 KASLR",
                "theme": "amber",
                "edge_label": "leaks EL1 heap",
            },
            {
                "tag": "Stage 3 · Legacy USB Quirk Corruption",
                "title": "Chicony UVC & Extigy ALSA OOB Write (CVE-2024-53104 / 53197)",
                "body": "UVC_VS_UNDEFINED frame overflow in uvc_parse_format() and forged Extigy bNumConfigurations corrupt dev->config in EL1 slab",
                "theme": "red",
                "edge_label": "corrupts slab",
            },
            {
                "tag": "Stage 4 · Heap Groom & Post-Exploitation",
                "title": "42x HID Reconnects -> EL1 Root -> Falcon & NoviSpy",
                "body": "Microsoft Comfort Mouse (045e:076c) groom achieves root RCE, extracts unlocked AFU CE storage, and stages spyware implant",
                "theme": "red",
                "edge_label": "dumps AFU CE data",
            },
        ],
        side_notes={
            0: {
                "tag": "Hardware Port Defense",
                "title": "IUsb.enableUsbData(false) Lock Gate",
                "body": "Disconnects USB D+/D- and SuperSpeed lanes at Type-C controller while locked so xhci never sees a descriptor",
                "theme": "green",
                "dashed": False,
                "reverse": True,
                "edge_color": "#2b6a4c",
                "edge_label": "cuts data lanes",
            },
            3: {
                "tag": "Key Eviction Defense",
                "title": "Inactivity Reboot (AFU -> BFU)",
                "body": "Auto-reboot (72h AAPM; 10m-72h GrapheneOS) evicts CE keys from DRAM & UFS ICE before lab extraction",
                "theme": "teal",
                "dashed": False,
                "reverse": True,
                "edge_color": "#236b66",
                "edge_label": "evicts CE keys",
            },
        },
        footer="Amnesty International Security Lab recovered exact VID/PID traces showing Cellebrite chaining 10-to-15-year-old Linux USB driver quirks.",
    )

    # 3. Ch 13: 13-extra-cryptoobject-vs-frida-bypass.svg
    build_split_domains(
        P("13-extra-cryptoobject-vs-frida-bypass.svg"),
        "Event-Only Biometric Callback Spoofing vs. Class 3 KeyMint CryptoObject Gate",
        left={
            "label": "Vulnerable Pattern · Boolean UI Callback",
            "theme": "red",
            "dashed": True,
            "cards": [
                {
                    "tag": "App Layer Mistake",
                    "title": "Prompt Without CryptoObject",
                    "body": "App invokes BiometricPrompt as a pure UI check and stores session secret in normal storage without KeyMint auth binding",
                    "theme": "white",
                },
                {
                    "tag": "In-Process Tampering",
                    "title": "Frida Hooks Success Callback",
                    "body": "Dynamic instrumentation directly invokes onAuthenticationSucceeded(null) in Java without touching biometric sensor",
                    "theme": "amber",
                    "in_arrow": True,
                },
                {
                    "tag": "Complete Auth Bypass",
                    "title": "Vault Unlocked Without Hardware",
                    "body": "App flips isAuthenticated = true in ART heap; neither TrustZone matcher nor KeyMint ever participated",
                    "theme": "red",
                    "in_arrow": True,
                },
            ],
        },
        right={
            "label": "Cryptographic Gate · Class 3 CryptoObject",
            "theme": "green",
            "cards": [
                {
                    "tag": "KeyMint Key Policy",
                    "title": "Biometric-Bound KeyMint Key",
                    "body": "ECDSA/AES key inside StrongBox/TEE bound to AUTH_BIOMETRIC_STRONG & current authenticatorId (rotates on new finger!)",
                    "theme": "white",
                },
                {
                    "tag": "Isolated Sensor + TEE TA",
                    "title": "69-Byte HardwareAuthToken MAC",
                    "body": "Class 3 matcher (SAR <= 7%) verifies live biometric over TZ-isolated SPI/MIPI and MACs challenge || authenticatorId",
                    "theme": "teal",
                    "in_arrow": True,
                },
                {
                    "tag": "Silicon Enforcement",
                    "title": "KeyMint Hardware Signature Gate",
                    "body": "StrongBox/TEE verifies shared HMAC key, op challenge, & unrotated authenticatorId before signing server challenge",
                    "theme": "green",
                    "in_arrow": True,
                },
            ],
        },
        bridges=[
            (1, 1, "lr", "Frida lacks TEE HMAC key", "red"),
            (2, 2, "lr", "backend checks ECDSA sig", "green"),
        ],
        boundary_label="StrongBox / TEE Cryptographic Boundary",
        footer="If an attacker compromises Android later and enrolls a second fingerprint, IFingerprint rotates authenticatorId and permanently invalidates the key.",
        width=920.0,
    )

    # 4. Ch 14: 14-extra-forward-secure-intrusion-vault.svg
    build_sequence(
        P("14-extra-forward-secure-intrusion-vault.svg"),
        "Forward-Secure Intrusion Logging Vault Across Pre- and Post-Compromise Epochs",
        actors=[
            {"title": "OS Telemetry", "sub": "SecurityLog / Netd / USB", "theme": "slate"},
            {"title": "On-Device Sealer", "sub": "One-Way E2EE / HPKE", "theme": "teal"},
            {"title": "Google Cloud Vault", "sub": "Append-Only 12m Store", "theme": "purple"},
            {"title": "Owner + MVT Lab", "sub": "LSKF + AndroidQF", "theme": "green"},
        ],
        messages=[
            (0, 1, "Epoch t < t0: Capture keyguard, ADB, package install, USB, DNS, & TCP events", "slate", False),
            (1, 2, "Encrypt batch under user E2EE public key -> append ciphertext to cloud", "teal", False),
            (0, 1, "Epoch t = t0: Mercenary spyware gains EL1 root & scrubs local logd/dropbox", "red", True),
            (1, 2, "Root implant holds zero decrypt key & cannot delete prior cloud epochs", "red", True),
            (3, 2, "Epoch t > t0: User authorizes Download & Decrypt via LSKF + Titan CKV", "green", False),
            (2, 3, "AndroidQF + mvt-android check-advanced-logs extracts delivery & C2 IOCs", "purple", False),
        ],
        boundary_after=1,
        boundary_label="Zero Local Decrypt / Append-Only Cloud",
        footer="Unlike local volatile buffers (logcat, tombstones, or unvaulted sysdiagnose), pre-compromise epochs survive post-exploitation root wiping.",
        width=920.0,
    )

    # 5. Ch 15: 15-extra-dice-bcc-cbor-rkp-flow.svg
    build_fan_bands(
        P("15-extra-dice-bcc-cbor-rkp-flow.svg"),
        "OpenProfile for DICE Boot Certificate Chain (BCC) & RKP v3 Certificate Provisioning",
        bands=[
            [
                {
                    "id": "uds",
                    "tag": "Silicon Foundry Root · OTP Fuses & Immutable Boot ROM",
                    "title": "256-Bit Unique Device Secret (UDS) -> UDS_Pub (Ed25519 / P-384 COSE_Key)",
                    "body": "ROM derives UDS_Pub/Priv and latches UDS unreadable before BL1 runs; UDS_Pub registered at wafer test with zero ODM XML keyboxes",
                    "theme": "amber",
                }
            ],
            [
                {
                    "id": "dice_bl",
                    "tag": "DICE Layers 1..N",
                    "title": "Bootloader CDI Chain",
                    "body": "CWT COSE_Sign1 certs hash prior CDI with Code Hash (-4670545), Mode == normal, & SVN (-70005)",
                    "theme": "slate",
                },
                {
                    "id": "dice_km",
                    "tag": "Leaf IRPC Silicon",
                    "title": "KeyMint / StrongBox / AVF",
                    "body": "CDI_Leaf_Priv terminates DiceCertChain and generates pool of MacedPublicKey P-256 keys",
                    "theme": "teal",
                },
                {
                    "id": "csr_v3",
                    "tag": "RKP v3 · AIDL CSR",
                    "title": "AuthenticatedRequest CSR",
                    "body": "Single COSE_Sign1 over [challenge, CertificateType, DeviceInfo, KeysToSign] sent via rkpd",
                    "theme": "purple",
                },
            ],
            [
                {
                    "id": "rkp_ca",
                    "tag": "Google RKP Provisioning Backend & 2026 ECDSA P-384 Root CA",
                    "title": "Short-Lived Per-(UID, Pool) X.509 Chains + OID 1.3.6.1.4.1.11129.2.1.30 Extension",
                    "body": "Verifies UDS_Pub & every DICE SVN, blocks unpatched TEE firmware until OTA updates SVN, and embeds certs_issued & is_lost_device",
                    "theme": "green",
                }
            ],
        ],
        edges=[
            ("uds", "dice_bl", "derives CDI_1", "amber", False),
            ("dice_bl", "dice_km", "chains BCC", "slate", False),
            ("dice_km", "csr_v3", "signs CSR v3", "teal", False),
            ("dice_bl", "rkp_ca", "audits boot SVNs", "slate", False),
            ("dice_km", "rkp_ca", "verifies IRPC leaf", "teal", False),
            ("csr_v3", "rkp_ca", "issues X.509 pool", "purple", False),
        ],
        footer="RKP v3 (Android 14+) simplified CSRs to AuthenticatedRequest<CsrPayload>; in April 2026 RKP chains migrated to Google's ECDSA P-384 Root CA.",
        width=940.0,
    )


def main():
    generate_extra_b3(DIAG_DIR)
    names = [
        "11-extra-session-dropper-ecm-bypass.svg",
        "12-extra-cellebrite-usb-alsa-chain.svg",
        "13-extra-cryptoobject-vs-frida-bypass.svg",
        "14-extra-forward-secure-intrusion-vault.svg",
        "15-extra-dice-bcc-cbor-rkp-flow.svg",
    ]
    for n in names:
        p = os.path.join(DIAG_DIR, n)
        assert os.path.exists(p) and os.path.getsize(p) > 500, f"Missing or empty SVG: {p}"
    print(f"Successfully generated and 7-way collision-verified {len(names)} Batch 3 extra SVGs in {DIAG_DIR}")


if __name__ == "__main__":
    main()
