#!/usr/bin/env python3
"""
Batch 3 extra SVG diagrams (Chapters 11-15) for The Apple Trust Chain (Volume II),
built on shared tools/diagram_lib.py with 7-way collision verification.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_dual_rail_timeline,
    build_fan_bands,
    build_sequence,
    build_split_domains,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def gen_ch11_extra():
    # 11-extra-shoulder-surf-killchain-vs-sdp.svg
    build_dual_rail_timeline(
        P("11-extra-shoulder-surf-killchain-vs-sdp.svg"),
        "The 180-Second Passcode-Theft Kill Chain (WSJ 2023) vs. Stolen Device Protection",
        "Pre-iOS 17.3 Shoulder-Surf Takeover",
        "iOS 17.3+ Stolen Device Protection (SDP)",
        [
            {
                "year": "T+0s",
                "left": {
                    "tag": "Passcode Recon",
                    "title": "Shoulder-Surf 6-Digit PIN & Snatch iPhone",
                    "body": "Thief forces Face ID failure in crowded venue, films PIN entry, and steals unlocked or locked handset",
                    "theme": "red",
                },
                "right": {
                    "tag": "Context Evaluation",
                    "title": "CoreRoutine Flags Unfamiliar Location",
                    "body": "Bar, street, or transit node fails encrypted on-device Significant Locations check (or Always mode active)",
                    "theme": "teal",
                },
            },
            {
                "year": "T+30s",
                "left": {
                    "tag": "Account Reset",
                    "title": "Change Apple Account Password via Device PIN",
                    "body": "AuthKit accepts local SEP passcode token to reset Apple ID password and kick out victim's other devices",
                    "theme": "red",
                },
                "right": {
                    "tag": "Delay Gate",
                    "title": "Biometric #1 + Mandatory 60-Minute Timer",
                    "body": "Password reset requires live Face ID / Touch ID with zero PIN fallback, then blocks for 1 full hour",
                    "theme": "green",
                },
            },
            {
                "year": "T+90s",
                "left": {
                    "tag": "Permanent Lockout",
                    "title": "Generate 28-Char Recovery Key & Disable Find My",
                    "body": "Enrolling a new Recovery Key blocks Apple Support recovery; thief clears Activation Lock for resale",
                    "theme": "amber",
                },
                "right": {
                    "tag": "Custody Lock",
                    "title": "Recovery Key, Biometry, & Find My Frozen",
                    "body": "Find My cannot be disabled while SDP is on; Recovery Key mutation requires second live Face ID after 1h",
                    "theme": "green",
                },
            },
            {
                "year": "T+180s",
                "left": {
                    "tag": "Vault Drain",
                    "title": "Passcode Fallback Unlocks Keychain & Banking",
                    "body": "Thief opens Passwords vault via PIN fallback to drain bank apps, crypto seeds, and tax records",
                    "theme": "red",
                },
                "right": {
                    "tag": "Biometric Only",
                    "title": "Zero Passcode Fallback on Saved Credentials",
                    "body": "Passwords.app, Passkeys, Safari AutoFill cards, and eSIM transfer strictly require live Face ID / Touch ID",
                    "theme": "green",
                },
            },
        ],
        footer="Severing passcode fallback turns a 3-minute irrevocable account lockout into a blocked hardware brick while the owner enables Lost Mode.",
    )


def gen_ch12_extra():
    # 12-extra-acme-device-attest-01-handshake.svg
    build_sequence(
        P("12-extra-acme-device-attest-01-handshake.svg"),
        "Enterprise Managed Device Attestation: RFC 8555 ACME device-attest-01 Handshake",
        [
            {"title": "Endpoint & SEP", "sub": "mdmclient + SKS / SIK", "theme": "slate"},
            {"title": "Apple Attest CA", "sub": "SIK / scrt Validator", "theme": "teal"},
            {"title": "Enterprise ACME CA", "sub": "device-attest-01 Verifier", "theme": "purple"},
            {"title": "Zero Trust Gateway", "sub": "802.1X / mTLS / VPN", "theme": "green"},
        ],
        [
            (0, 0, "Generate non-exportable P-256/P-384 HardwareBound key in SEP", "slate", False),
            (0, 2, "POST newOrder (permanent-identifier = ClientIdentifier)", "purple", False),
            (2, 0, "Return device-attest-01 challenge (128-bit+ random token)", "purple", True),
            (0, 1, "Send SEP hardware attestation + SIK/ucrt + SHA-256(token)", "teal", False),
            (1, 0, "Verify scrt & boot hashes; mint x5c leaf with 1.2.840.113635.100.8.* OIDs", "teal", True),
            (0, 2, "Fulfill challenge with WebAuthn attObj + finalize CSR", "purple", False),
            (2, 2, "Verify Apple Enterprise Root, OID 8.11.1 nonce, SIP (8.13.1), & Serial (8.9.1)", "purple", False),
            (2, 0, "Issue operational X.509 client certificate bound to SEP key", "green", True),
            (0, 3, "Complete TLS 1.3 CertificateVerify signed inside SEP", "green", False),
        ],
        bottom_note={
            "tag": "Enrollment-Scoped Privacy Switch",
            "title": "Automated Device Enrollment Includes Serial/UDID (OIDs 8.9.1 / 8.9.2); BYOD User Enrollment Omits Both",
            "body": "Enterprise CAs gain cryptographic posture proof (OS version, sepOS, LLB, SIP, Secure Boot) without tracking personal BYOD hardware serials.",
            "theme": "amber",
        },
        footer="Replacing static SCEP shared secrets with ACME device-attest-01 binds issued X.509 identities to non-exportable SEP silicon.",
    )


def gen_ch13_extra():
    # 13-extra-watch-tof-relay-defense.svg
    build_split_domains(
        P("13-extra-watch-tof-relay-defense.svg"),
        "Auto Unlock Physical Distance Bounding: Speed-of-Light ToF vs. Relay Attack",
        {
            "label": "Legitimate Desk Unlock (< 3 m)",
            "theme": "green",
            "cards": [
                {"tag": "Wrist State", "title": "Passcode-Unlocked Watch on Skin", "body": "Optical/capacitive wrist-detect sensor holds pairwise SEP Continuity keys active", "theme": "white"},
                {"tag": "802.11mc FTM / UWB", "title": "Hardware Timestamp Exchange (t1..t4)", "body": "Mac logs TX t1 & RX t4; Watch SEP/PHY signs turnaround delta (t3 - t2) in hardware", "theme": "teal", "in_edge": "BLE wake -> Wi-Fi FTM"},
                {"tag": "Physical Verdict", "title": "Air RTT <= ~20 ns (d <= 3 m): UNLOCK", "body": "c * ((t4 - t1) - (t3 - t2)) / 2 confirms Watch is physically beside the Mac", "theme": "green", "in_edge": "passes ToF gate"},
            ],
        },
        {
            "label": "Two-Attacker Cafe Relay (> 15 m)",
            "theme": "red",
            "cards": [
                {"tag": "Proxy Bridge", "title": "Attacker A Near Mac; Attacker B in Cafe", "body": "Colluding SDR / BLE-Wi-Fi transceivers forward encrypted frames across coax or WLAN", "theme": "white"},
                {"tag": "Unforgeable Physics", "title": "Cannot Compress Propagation Time", "body": "Cryptographic timestamps prevent forging t2/t3; RF cable/air + SDR adds >= 100 ns", "theme": "amber", "in_edge": "relays ciphertext"},
                {"tag": "Physical Verdict", "title": "Measured d > 3 m Budget: ABORT", "body": "sharingd rejects unlock despite valid BLE auth and intact AES-GCM tags", "theme": "red", "in_edge": "fails ToF bound"},
            ],
        },
        bridges=[
            (1, 1, "lr", "speed-of-light c = 0.30 m/ns", "slate"),
        ],
        boundary_label="Nanosecond Time-of-Flight Gate",
        footer="Cryptographic authentication proves WHICH Watch answered; nanosecond Time-of-Flight ranging proves WHERE that Watch physically sits.",
    )


def gen_ch14_extra():
    # 14-extra-byod-dual-apfs-volume-split.svg
    build_split_domains(
        P("14-extra-byod-dual-apfs-volume-split.svg"),
        "Account-Driven User Enrollment: Cryptographic BYOD Dual-APFS Volume Split",
        {
            "label": "Personal Sovereign Domain",
            "theme": "green",
            "cards": [
                {"tag": "Identity Anchor", "title": "Personal Apple Account & Passcode", "body": "User retains full ownership, iCloud Photos, Passkeys, App Store, and Find My custody", "theme": "white"},
                {"tag": "Storage & Vault", "title": "User APFS Data Volume & secd Scope", "body": "Personal files and Keychain rows wrapped under personal SEP keybag; invisible to MDM", "theme": "green", "in_edge": "personal keybag"},
                {"tag": "Privacy Guarantees", "title": "Zero Device Wipe, App Inventory, or Serial", "body": "MDM cannot issue EraseDevice, read personal app lists, or see OID 8.9.1 SerialNumber", "theme": "teal", "in_edge": "telemetry blocked"},
            ],
        },
        {
            "label": "Enterprise Managed Workspace",
            "theme": "slate",
            "cards": [
                {"tag": "Identity Anchor", "title": "Federated Managed Apple Account", "body": "Discovered via /.well-known/com.apple.remotemanagement + OIDC/PSSO token", "theme": "white"},
                {"tag": "Storage & Vault", "title": "Dedicated Enterprise APFS Volume", "body": "Managed apps, DDM assets, Per-App VPN, and enterprise Keychain use separate SEP keys", "theme": "white", "in_edge": "enterprise keybag"},
                {"tag": "Clean Offboarding", "title": "Instant Cryptographic Volume Shred", "body": "Unenroll destroys Enterprise APFS volume & SEP keys in milliseconds; personal volume untouched", "theme": "amber", "in_edge": "crypto-erase"},
            ],
        },
        bridges=[],
        boundary_label="Hard Cryptographic Volume & Keybag Wall",
        foundation={
            "tag": "Shared Physical Silicon Root",
            "title": "Single Apple Silicon SoC: Boot ROM, SSV System Volume, & Secure Enclave (SEP)",
            "body": "Enforces Full Security and MDA OS posture proofs for enterprise Zero Trust without requiring device Supervision",
            "theme": "slate",
            "left_label": "seals personal volume",
            "right_label": "isolates managed volume",
        },
        footer="User Enrollment replaces intrusive MDM supervision on personal phones and Macs with mathematical key separation inside APFS and SEP.",
    )


def gen_ch15_extra():
    # 15-extra-octagon-clique-pcs-hierarchy.svg
    build_fan_bands(
        P("15-extra-octagon-clique-pcs-hierarchy.svg"),
        "Octagon Peer Clique, CKKS Views, and CloudKit Protected Cloud Storage (PCS) Tree",
        [
            [
                {"id": "peers", "tag": "Octagon Trust Clique (OTClique)", "title": "Trusted Device SEP Peer Keys", "body": "Peer P-384/P-256 signing & encryption keys counter-signed into circle manifest", "theme": "teal", "w_weight": 1.3},
                {"id": "rec", "tag": "Out-of-Band Recovery Anchors", "title": "28-Char Recovery Key / Custodian (CRK)", "body": "128-bit+ HKDF Backup Key or peer-wrapped Recovery Contact voucher", "theme": "purple", "w_weight": 1.0},
            ],
            [
                {"id": "ckks", "tag": "CKKS Synced Key Hierarchy", "title": "Top-Level Keys (TLK) -> Class A / Class C Keys -> PCS Master Identities (pcsi / pcsk)", "body": "TLKShares wrapped per Octagon peer; Synced Keychain items encrypted with 512-bit AES-SIV under view keys", "theme": "green"},
            ],
            [
                {"id": "bkp", "tag": "PCS Service Key", "title": "iCloud Backup", "body": "E2EE under ADP (wraps Messages backup)", "theme": "green"},
                {"id": "pho", "tag": "PCS Service Key", "title": "Photos & Notes", "body": "Client-rotated 256-bit service root keys", "theme": "green"},
                {"id": "drv", "tag": "PCS Service Key", "title": "iCloud Drive", "body": "Pages, PDFs, & Desktop/Documents sync", "theme": "green"},
                {"id": "pim", "tag": "Outside PCS E2EE", "title": "Mail, Contacts, Cal", "body": "Server-held keys for SMTP/CalDAV/CardDAV", "theme": "red", "dashed": True},
            ],
            [
                {"id": "leaf", "tag": "CloudKit Object Storage (cloudd)", "title": "Container -> Zone Key (K_zone) -> Record Key (K_record) -> Per-Chunk AES-256-GCM", "body": "Every field and S3/Apple asset chunk encrypted on client before upload; under ADP Apple holds zero K_service copies", "theme": "slate"},
            ],
        ],
        [
            ("peers", "ckks", "wraps TLKShare", "teal", False),
            ("rec", "ckks", "escrows TLKs", "purple", True),
            ("ckks", "bkp", "ADP custody", "green", False),
            ("ckks", "pho", "ADP custody", "green", False),
            ("ckks", "drv", "ADP custody", "green", False),
            ("bkp", "leaf", "wraps zone", "green", False),
            ("pho", "leaf", "wraps zone", "green", False),
            ("drv", "leaf", "wraps zone", "green", False),
            ("pim", "leaf", "server TLS/at-rest", "red", True),
        ],
        footer="Under Advanced Data Protection, evicting Apple from CloudKit requires moving only the PCS Service Keys into the Octagon CKKS clique.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_ch11_extra()
    gen_ch12_extra()
    gen_ch13_extra()
    gen_ch14_extra()
    gen_ch15_extra()
    print("SUCCESS: Generated and collision-verified 5 extra Batch 3 SVGs.")


if __name__ == "__main__":
    main()
