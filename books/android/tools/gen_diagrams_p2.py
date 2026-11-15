#!/usr/bin/env python3
"""Part 2 diagram definitions for The Android Trust Chain: Chapters 11-20 (20 diagrams)."""
import os
from diagram_lib import (
    build_vertical_flow, build_sequence, build_split_domains,
    build_horizontal_pipeline, build_fan_bands, build_matrix, build_dual_rail_timeline,
)


def generate_part2(diag_dir: str):
    def P(name: str) -> str:
        return os.path.join(diag_dir, name)

    # 24. Ch 11: 11-accessibility-trojan-killchain.svg
    build_vertical_flow(
        P("11-accessibility-trojan-killchain.svg"),
        "UI-Layer Trojan Kill Chain: Bypassing Sandbox & Crypto via AccessibilityService",
        steps=[
            {"tag": "Stage 1 · Delivery", "title": "Sideloaded Dropper / Session-Installer APK",
             "body": "Masquerades as courier, PDF reader, or browser update distributed via phishing SMS or chat link",
             "theme": "amber"},
            {"tag": "Stage 2 · Social Engineering", "title": "Lures User to Grant AccessibilityService",
             "body": "Requests BIND_ACCESSIBILITY_SERVICE + NotificationListenerService above intact kernel sandbox",
             "theme": "amber", "edge_label": "if not blocked"},
            {"tag": "Stage 3 · Screen & OTP Harvest", "title": "Reads AccessibilityNodeInfo Tree & 2FA Codes",
             "body": "Scrapes banking balances, keystrokes, wallet seed phrases, and incoming SMS/push OTP notifications",
             "theme": "red", "edge_label": "TYPE_VIEW_TEXT_CHANGED"},
            {"tag": "Stage 4 · Automated Fraud (ATS)", "title": "dispatchGesture() & performAction(ACTION_CLICK)",
             "body": "Initiates wire transfer inside victim's authenticated banking session behind dimmed overlay screen",
             "theme": "red", "edge_label": "injects UI clicks"},
        ],
        side_notes={
            1: {"tag": "Android 13-17 Gate", "title": "Restricted Settings (ECM) & Adv. Protection",
                "body": "Greys out Accessibility/Notification toggles for sideloaded APKs; Advanced Protection blocks outright",
                "theme": "green", "edge_label": "platform block"},
            2: {"tag": "Android 15-17 Gate", "title": "Sensitive Notification OTP Redaction",
                "body": "Withholds 2FA/OTP text from untrusted NotificationListeners, screen shares, and recently unlocked sessions",
                "theme": "teal", "edge_label": "redacts OTP"},
        },
        footer="Banking trojans (FluBot, Cerberus, SharkBot) require zero kernel exploits once granted ambient UI-layer observation and injection."
    )

    # 25. Ch 11: 11-advanced-protection-lockdown.svg
    build_fan_bands(
        P("11-advanced-protection-lockdown.svg"),
        "Android 16/17 Advanced Protection Mode: Unified High-Risk Surface Lockdown",
        bands=[
            [{"id": "toggle", "tag": "Single System Policy · Settings -> Security -> Advanced Protection",
              "title": "AdvancedProtectionManager Hardware-Backed Enforcement State",
              "body": "Eliminates piecemeal per-app security hygiene by locking exploit, phishing, and physical surfaces simultaneously",
              "theme": "green"}],
            [
                {"id": "app_gate", "tag": "Install & UI Surface", "title": "Blocks Sideloading & Unverified Accessibility",
                 "body": "Disables unknown-source APK installs, forces Play Protect live scanning, & locks Restricted Settings",
                 "theme": "teal"},
                {"id": "mem_web", "tag": "Memory & Browser Surface", "title": "Enforces Arm MTE + Chrome JIT/WebGPU Lock",
                 "body": "Enables hardware MTE across eligible apps, enforces HTTPS-First, & disables V8 JIT / WebGPU on untrusted sites",
                 "theme": "purple"},
                {"id": "radio_usb", "tag": "Physical & Radio Surface", "title": "2G Baseband Disable, USB Lock, & Intrusion Logs",
                 "body": "Blocks 2G stingray downgrade, locks USB-C to charge-only while locked, & enables E2EE Intrusion Logging",
                 "theme": "slate"},
            ],
            [{"id": "app_api", "tag": "Third-Party App Signal · AdvancedProtectionManager.isAdvancedProtectionEnabled()",
              "title": "Opt-In High-Assurance Posture for Signal, WhatsApp, Banking, & Enterprise Apps",
              "body": "Allows messaging and financial apps to automatically enable strict call-relay, link-preview disable, and passkey gates",
              "theme": "white"}],
        ],
        edges=[
            ("toggle", "app_gate", "locks app/UI vectors", "teal", False),
            ("toggle", "mem_web", "hardens memory & web", "purple", False),
            ("toggle", "radio_usb", "hardens radio & USB", "slate", False),
            ("app_gate", "app_api", "broadcasts state", "green", False),
            ("mem_web", "app_api", "broadcasts state", "green", False),
            ("radio_usb", "app_api", "broadcasts state", "green", False),
        ],
        footer="Advanced Protection counters both commercial zero-click spyware (JIT/MTE/baseband) and social-engineered trojans (APK/Accessibility)."
    )

    # 26. Ch 12: 12-fbe-bfu-afu-key-hierarchy.svg
    build_split_domains(
        P("12-fbe-bfu-afu-key-hierarchy.svg"),
        "File-Based Encryption (fscrypt v2) & Direct Boot: BFU vs. AFU Key Custody",
        left={
            "label": "Before First Unlock (BFU)",
            "theme": "green",
            "cards": [
                {"tag": "Device Encrypted (DE) Only", "title": "DE_0 Key Unwrapped from KeyMint + Boot State",
                 "body": "Allows alarm clock, emergency dialer, Wi-Fi bootstrap, and accessibility screen readers to run after reboot",
                 "theme": "white"},
                {"tag": "Credential Encrypted (CE) Evicted", "title": "CE_0 Master Key Absent from DRAM & ICE",
                 "body": "Sealed under SyntheticPassword -> Weaver StrongBox slot + KeyMint; zero plaintext photos/messages in RAM",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "After First Unlock (AFU)",
            "theme": "amber",
            "cards": [
                {"tag": "Background Continuity", "title": "CE_0 Key Programmed in UFS Inline Crypto (ICE)",
                 "body": "Hardware keyslots encrypt/decrypt AES-256-XTS file blocks inline so E2EE messengers receive push messages",
                 "theme": "white"},
                {"tag": "Physical Extraction Target", "title": "Kernel Compromise Can Read Active CE Mounts",
                 "body": "Motivates lock-screen USB data block, auto-reboot back to BFU after inactivity, & Theft Detection Lock",
                 "theme": "red", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "First LSKF Unlock -> AFU", "teal"),
            (1, 1, "rl", "Reboot / Timeout Evicts CE", "green"),
        ],
        boundary_label="LSKF Unwrap / Reboot Eviction",
        footer="In BFU state, even a full Linux kernel zero-day cannot decrypt Credential Encrypted user files without passing StrongBox Weaver."
    )

    # 27. Ch 12: 12-usb-zero-day-vs-locks.svg
    build_sequence(
        P("12-usb-zero-day-vs-locks.svg"),
        "Physical USB Extraction Chains (Cellebrite 2025) vs. USB Port & Theft Locks",
        actors=[
            {"title": "Forensic Rig", "sub": "Emulated USB Gadget", "theme": "red"},
            {"title": "USB-C Controller", "sub": "Type-C / Gadget Policy", "theme": "teal"},
            {"title": "Linux USB Drivers", "sub": "UVC / ALSA / HID", "theme": "amber"},
            {"title": "Theft & Identity Locks", "sub": "Android 15-17 Guards", "theme": "green"},
        ],
        messages=[
            (0, 1, "Plug physical cable into locked AFU handset", "red", False),
            (1, 0, "Hardened path: USB data pins disabled while locked (charge-only)", "green", False),
            (0, 2, "Unprotected path: crafted UVC (CVE-2024-53104) & ALSA Audio (CVE-2024-53197)", "red", True),
            (2, 2, "Kernel heap OOB write -> Ring 0 RCE -> dump unlocked AFU CE files", "red", True),
            (3, 3, "Snatch-and-run defense: IMU + Wi-Fi/BLE triggers Theft Detection Lock", "green", False),
            (3, 1, "Identity Check: outside trusted locations, PIN alone cannot disable security", "green", False),
        ],
        boundary_after=1,
        boundary_label="Hardware USB Data Signaling Gate",
        footer="Disabling USB host/peripheral data enumeration while locked severs the entire kernel USB driver surface documented by Amnesty Lab."
    )

    # 28. Ch 13: 13-biometric-class-tiers.svg
    build_matrix(
        P("13-biometric-class-tiers.svg"),
        "Android Biometric Strength Classes (CDD Section 7.3.10) & KeyMint Privileges",
        "Why architectural pipeline isolation, not sensor marketing, determines cryptographic eligibility",
        row_headers=[
            ("Class 3 · Strong", "Ultrasonic FP / 3D Face"),
            ("Class 2 · Weak", "2D IR / Assisted Face"),
            ("Class 1 · Convenience", "RGB Camera Face"),
        ],
        col_headers=[
            ("Spoof / Impostor", "SAR & FAR Bounds"),
            ("Sensor -> TEE", "Pipeline Isolation"),
            ("BiometricPrompt", "UI API Access"),
            ("CryptoObject", "KeyMint Key Gate"),
        ],
        cells=[
            [("SAR <= 7%", "green"), ("Secure Hardware", "green"),
             ("Allowed (All)", "green"), ("Yes (AuthToken)", "green")],
            [("7% < SAR <= 20%", "amber"), ("Isolated Matcher", "teal"),
             ("Non-Crypto Only", "amber"), ("Denied", "red")],
            [("SAR > 20%", "red"), ("Normal World OK", "red"),
             ("Lockscreen Only", "red"), ("Denied", "red")],
        ],
        legend="Class 3 forces mandatory LSKF fallback at least every 72 hours or after 4 hours of inactivity; Class 1/2 have tighter timers.",
        footer="Always bind BiometricPrompt to a Keystore CryptoObject so malware cannot hook onAuthenticationSucceeded() in Java.",
        width=940.0,
    )

    # 29. Ch 13: 13-passkey-sync-cable-flow.svg
    build_sequence(
        P("13-passkey-sync-cable-flow.svg"),
        "Credential Manager Passkeys: E2EE Vault Sync & CTAP2.2 caBLE Proximity Flow",
        actors=[
            {"title": "Desktop Browser", "sub": "Relying Party Origin", "theme": "slate"},
            {"title": "Android Handset", "sub": "Credential Manager + BLE", "theme": "green"},
            {"title": "GPM Security Domain", "sub": "E2EE Passkey Vault", "theme": "teal"},
            {"title": "Titan Cloud HSM", "sub": "LSKF Recovery Escrow", "theme": "purple"},
        ],
        messages=[
            (0, 1, "Scan QR -> BLE proximity advert + noise-encrypted caBLE tunnel", "slate", False),
            (1, 1, "Verify Class 3 Biometric / LSKF via BiometricPrompt", "green", False),
            (1, 2, "Unwrap RP-scoped ECDSA P-256 passkey private key locally", "teal", False),
            (1, 0, "Sign challenge || SHA-256(rpId) -> phishing-resistant assertion", "green", False),
            (2, 3, "New-device recovery: LSKF-wrapped sync key verified inside Titan HSM", "purple", True),
        ],
        boundary_after=1,
        boundary_label="Plaintext Passkey Never Leaves Client/HSM",
        footer="Origin binding (rpIdHash) stops real-time adversary-in-the-middle phishing; BLE proximity proves physical co-location."
    )

    # 30. Ch 14: 14-telemetry-tiers-architecture.svg
    build_fan_bands(
        P("14-telemetry-tiers-architecture.svg"),
        "Mobile Telemetry Without Kernel Hooks: Consumer, Enterprise, & High-Risk Forensics",
        bands=[
            [{"id": "no_edr", "tag": "Foundational Design Choice · GKI KMI Stability & Sandbox Integrity",
              "title": "Zero Third-Party Kernel Extensions or Cross-UID Memory Inspection APIs",
              "body": "Prevents EDR kernel panics and stops rogue security apps from becoming omniscient spyware across personal sandboxes",
              "theme": "slate"}],
            [
                {"id": "gpp", "tag": "Consumer Real-Time Defense",
                 "title": "Google Play Protect + Dynamic Signal Monitoring",
                 "body": "On-device ML + Android 17 behavioral telemetry detects runtime dropper staging, icon hiding, & permission abuse",
                 "theme": "green"},
                {"id": "seclog", "tag": "Managed Enterprise Fleet",
                 "title": "DevicePolicyManager SecurityLog & NetworkLog",
                 "body": "Streams audited process-start, ADB, Keystore, Wi-Fi, and DNS/TCP metadata exclusively on Fully Managed / COPE devices",
                 "theme": "teal"},
                {"id": "ilog", "tag": "Targeted Spyware Forensics",
                 "title": "Android 16/17 E2EE Cloud Intrusion Logging",
                 "body": "Seals tamper-evident USB, network, install, & boot events to cloud storage under user's personal E2EE key",
                 "theme": "purple"},
            ],
        ],
        edges=[
            ("no_edr", "gpp", "built-in platform ML", "green", False),
            ("no_edr", "seclog", "MDM-scoped audit stream", "teal", False),
            ("no_edr", "ilog", "zero-knowledge forensic vault", "purple", False),
        ],
        footer="Intrusion Logging solves the spyware anti-forensics dilemma: root implants after compromise cannot erase prior cloud-sealed logs."
    )

    # 31. Ch 14: 14-e2ee-intrusion-logging-flow.svg
    build_horizontal_pipeline(
        P("14-e2ee-intrusion-logging-flow.svg"),
        "End-to-End Encrypted Intrusion Logging: Forward-Sealed Post-Compromise Forensics",
        stages=[
            {"tag": "1 · Capture", "title": "System Forensic Events",
             "body": "USB connections, app installs, network endpoints, lock & boot events", "theme": "slate"},
            {"tag": "2 · Seal Locally", "title": "Hybrid E2EE Seal",
             "body": "Encrypted on device under user's LSKF-backed public key; zero local decrypt", "theme": "teal"},
            {"tag": "3 · Append Cloud", "title": "Write-Only Cloud Vault",
             "body": "Google servers store opaque ciphertext blobs with append-only timestamps", "theme": "purple"},
            {"tag": "4 · Audit", "title": "Forensic Decrypt",
             "body": "Owner + investigator unwrap timeline offline using user LSKF + passkey", "theme": "green"},
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Anti-Tamper Guarantee",
            "title": "Compromised Device Cannot Delete or Read Prior Batches",
            "body": "Even a full Ring 0 spyware implant lacks cloud deletion rights and cannot rewrite already-uploaded history",
            "theme": "red",
            "edge_label": "blocks log wipe",
        },
        footer="Neither Google nor a post-exploitation implant can read historical Intrusion Logs without the user's LSKF recovery credential."
    )

    # 32. Ch 15: 15-key-attestation-asn1-tree.svg
    build_vertical_flow(
        P("15-key-attestation-asn1-tree.svg"),
        "X.509 Key Attestation Extension (OID 1.3.6.1.4.1.11129.2.1.17) Verification Schema",
        steps=[
            {"tag": "Certificate Chain Root", "title": "Google Hardware Attestation Root / RKP Root CA",
             "body": "Verify leaf->intermediate->root signatures and check serials against android.googleapis.com/attestation/status",
             "theme": "slate"},
            {"tag": "Freshness & Level", "title": "KeyDescription: attestationSecurityLevel & Challenge",
             "body": "Confirm securityLevel == TrustedEnvironment (1) or StrongBox (2) and exact server-generated random nonce",
             "theme": "teal", "edge_label": "parse OID .17"},
            {"tag": "Hardware Policy", "title": "teeEnforced AuthorizationList (Ignoring softwareEnforced)",
             "body": "Inspect origin == GENERATED, osPatchlevel, vendorPatchlevel, bootPatchlevel, & attestationApplicationId",
             "theme": "green", "edge_label": "read teeEnforced"},
            {"tag": "Silicon Boot Anchor", "title": "RootOfTrust SEQUENCE (4 Mandatory Fields)",
             "body": "verifiedBootKey (OEM SHA-256 or custom key), deviceLocked == TRUE, verifiedBootState == Verified/SelfSigned, verifiedBootHash",
             "theme": "purple", "edge_label": "verify boot state"},
        ],
        side_notes={
            2: {"tag": "Classic Verifier Bug", "title": "Trusting softwareEnforced",
                "body": "Compromised userspace can forge any claim in softwareEnforced; rely strictly on teeEnforced",
                "theme": "red", "edge_label": "never trust"},
        },
        footer="Checking verifiedBootKey explicitly lets high-security relying parties accept both stock OEM GREEN and pinned GrapheneOS YELLOW."
    )

    # 33. Ch 15: 15-rkp-provisioning-sequence.svg
    build_sequence(
        P("15-rkp-provisioning-sequence.svg"),
        "Remote Key Provisioning (RKP): Eliminating Factory Keyboxes via DICE BCC",
        actors=[
            {"title": "Silicon / KeyMint", "sub": "IRemotelyProvisionedComponent", "theme": "green"},
            {"title": "rkpd Daemon", "sub": "Mainline Userspace", "theme": "slate"},
            {"title": "Google RKP Backend", "sub": "Provisioning Authority", "theme": "purple"},
            {"title": "App / Verifier", "sub": "Short-Lived Leaf Cert", "theme": "teal"},
        ],
        messages=[
            (1, 2, "Fetch Geek (Google Endpoint Encryption Key) + server EEK challenge", "slate", False),
            (1, 0, "generateKeyPair() + generateCertificateRequestV2(challenge)", "slate", False),
            (0, 0, "Sign MacedPublicKey pool using silicon UDS -> DICE Boot Certificate Chain (BCC)", "green", False),
            (0, 1, "Return COSE_Sign1 CSR + encrypted UDS-derived BCC", "green", False),
            (1, 2, "Submit CSR over HTTPS (zero factory batch keybox used)", "purple", False),
            (2, 1, "Verify DICE silicon root & patch levels -> issue short-lived attestation certs", "purple", False),
            (1, 3, "Assign per-app attestation key to sign X.509 OID .17 leaf certificate", "teal", False),
        ],
        boundary_after=0,
        boundary_label="Per-Die UDS Never Leaves Silicon",
        footer="Factory batch keyboxes leaked repeatedly at ODM lines; RKP rotates short-lived pools and revokes compromised cohorts dynamically."
    )

    # 34. Ch 16: 16-play-integrity-vs-root-hiding.svg
    build_dual_rail_timeline(
        P("16-play-integrity-vs-root-hiding.svg"),
        "Adversarial Escalation: Root Hiding & Keybox Spoofing vs. Hardware Attestation",
        left_label="Root Hiding & Spoofing Tradecraft",
        right_label="Platform & Attestation Countermeasures",
        rows=[
            {"year": "2016-19",
             "left": {"tag": "Userspace Hiding", "title": "MagiskHide Mount Namespaces",
                      "body": "Unmounts su/overlayfs inside target app mount namespace and spoofs ro.boot.verifiedbootstate props",
                      "theme": "red"},
             "right": {"tag": "Hardware Signal", "title": "KeyMaster Boot-State Binding",
                       "body": "Bootloader passes locked/ORANGE state directly to TEE before Linux kernel starts; userspace cannot reset",
                       "theme": "green"}},
            {"year": "2021-23",
             "left": {"tag": "In-Process Injection", "title": "Zygisk, Shamiko, & PlayIntegrityFix",
                      "body": "Hooks GMS DroidGuard process to downgrade attestation fallback to basic fingerprint checks",
                      "theme": "red"},
             "right": {"tag": "API Retirement", "title": "SafetyNet Sunset -> Play Integrity API",
                       "body": "Mandates hardware-backed Key Attestation for MEETS_DEVICE_INTEGRITY on Android 13+ devices",
                       "theme": "green"}},
            {"year": "2023-24",
             "left": {"tag": "Kernel-Mode Root", "title": "KernelSU & APatch",
                      "body": "Grants UID 0 via kernel kprobes/patches without touching /system files, evading mount scanners",
                      "theme": "red"},
             "right": {"tag": "AVB Boot Hash", "title": "Verified boot.img Digest in RootOfTrust",
                       "body": "Patching GKI kernel requires unlocked ORANGE bootloader, immediately changing TEE verifiedBootState",
                       "theme": "green"}},
            {"year": "2024-26",
             "left": {"tag": "Binder Cert Swap", "title": "TrickyStore + Leaked OEM Keyboxes",
                      "body": "Intercepts keystore2 Binder replies in system_server and re-signs leaf certs using stolen factory XML keyboxes",
                      "theme": "red"},
             "right": {"tag": "Dynamic Revocation", "title": "Mandatory RKP + Keybox Revocation Waves",
                       "body": "Revokes leaked factory keyboxes on status list and enforces recent RKP-minted StrongBox/TEE chains",
                       "theme": "green"}},
        ],
        footer="Software heuristics always lose to Ring 0; only unrevoked RKP/StrongBox keys anchored in UDS resist host kernel spoofing."
    )

    # 35. Ch 16: 16-relying-party-verification-choice.svg
    build_split_domains(
        P("16-relying-party-verification-choice.svg"),
        "Relying-Party Architecture: Opaque Play Integrity Verdicts vs. Direct Key Attestation",
        left={
            "label": "Play Integrity (Brokered)",
            "theme": "amber",
            "cards": [
                {"tag": "Bundled Risk Signals", "title": "Device + Play Licensing + Play Protect",
                 "body": "Returns signed JSON verdict (BASIC, DEVICE, STRONG) plus app install source and active malware flags",
                 "theme": "white"},
                {"tag": "Ecosystem Coupling", "title": "Requires Certified GMS & OEM Lock Key",
                 "body": "Automatically fails privacy-hardened custom OSes (GrapheneOS YELLOW) even when hardware AVB & StrongBox are locked",
                 "theme": "amber", "in_arrow": True},
            ],
        },
        right={
            "label": "Direct Key Attestation",
            "theme": "green",
            "cards": [
                {"tag": "First-Party Cryptographic Proof", "title": "Server Parses X.509 OID .17 Directly",
                 "body": "Binds session/token directly to non-exportable StrongBox/TEE private key with zero opaque broker middleman",
                 "theme": "white"},
                {"tag": "Sovereign Root Policy", "title": "Accepts OEM GREEN + Pinned Custom YELLOW",
                 "body": "Verifies deviceLocked == TRUE, patch levels, RKP status, and allowlisted verifiedBootKey digests (including GrapheneOS)",
                 "theme": "green", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "both parse X.509 OID .17", "slate"),
            (1, 1, "lr", "decouples distribution\nfrom silicon trust", "green"),
        ],
        boundary_label="Policy Coupling vs. Direct Proof",
        footer="Government, enterprise, and security-conscious apps should verify hardware Key Attestation chains directly on their own backends."
    )

    # 36. Ch 17: 17-work-profile-isolation.svg
    build_split_domains(
        P("17-work-profile-isolation.svg"),
        "Android Enterprise Work Profile: Dual-UID & Separate FBE Cryptographic Isolation",
        left={
            "label": "Personal Profile (User 0)",
            "theme": "green",
            "cards": [
                {"tag": "Personal UIDs (u0_a*)", "title": "Personal Apps, Photos, & Private Browser",
                 "body": "UID = 0 * 100000 + appId; invisible to enterprise MDM inventory, network logs, and work certificates",
                 "theme": "white"},
                {"tag": "Personal FBE Key (CE_0)", "title": "/data/user/0 Encrypted Under Personal LSKF",
                 "body": "Survives intact when employee leaves company or IT triggers remote enterprise wipe",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "Managed Work Profile (User 10)",
            "theme": "teal",
            "cards": [
                {"tag": "Work UIDs (u10_a*)", "title": "Badged Work Apps + Device Policy Controller",
                 "body": "UID = 10 * 100000 + appId; enforces work VPN, DLP clipboard block, managed CA certs, & Play allowlist",
                 "theme": "white"},
                {"tag": "Separate Work FBE Key (CE_10)", "title": "/data/user/10 + Separate Work Challenge",
                 "body": "Paused ('Work Off') evicts CE_10 key; wipeData() destroys CE_10 in KeyMint for instant cryptographic erasure",
                 "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "both", "CrossProfileIntentFilter", "slate"),
            (1, 1, "lr", "Separate fscrypt Keys", "teal"),
        ],
        boundary_label="Kernel UserHandle + FBE Boundary",
        footer="Kernel UID math separates User 0 (10210) from User 10 (1010210) using the exact same SELinux and DAC primitives as separate apps."
    )

    # 37. Ch 17: 17-enterprise-deployment-modes.svg
    build_matrix(
        P("17-enterprise-deployment-modes.svg"),
        "Android Enterprise Management Modes: Privacy vs. Administrative Control",
        "Hardware-anchored Zero-Touch provisioning and DevicePolicyManager boundaries across fleet models",
        row_headers=[
            ("BYOD Work Profile", "Employee Handset"),
            ("COPE (Work Profile)", "Corp-Owned Personal"),
            ("Fully Managed", "Corp-Only Handset"),
            ("Dedicated (COSU)", "Single-App Kiosk"),
        ],
        col_headers=[
            ("Zero-Touch", "Factory Lock"),
            ("Personal Data", "User 0 Privacy"),
            ("SecurityLog", "Fleet Telemetry"),
            ("Wipe Scope", "DPC Authority"),
        ],
        cells=[
            [("No (Opt-In)", "slate"), ("Full Isolation", "green"),
             ("Blocked", "green"), ("Work Only", "green")],
            [("Yes (HW Bound)", "teal"), ("Isolated User 0", "green"),
             ("Device Policy", "amber"), ("Work or Factory", "amber")],
            [("Yes (HW Bound)", "teal"), ("None (Work Only)", "slate"),
             ("Full SecurityLog", "teal"), ("Factory Reset", "teal")],
            [("Yes (HW Bound)", "teal"), ("Locked Task", "purple"),
             ("Full Telemetry", "teal"), ("Factory Reset", "teal")],
        ],
        legend="Zero-Touch Enrollment binds device hardware IDs in Google's provisioning service so factory reset re-enrolls MDM before setup.",
        footer="Hardware Key Attestation ID properties (IMEI/serial) are accessible only to authorized DPCs on corporate-provisioned devices.",
        width=940.0,
    )

    # 38. Ch 18: 18-pcc-aicore-sandbox.svg
    build_split_domains(
        P("18-pcc-aicore-sandbox.svg"),
        "Private Compute Core (PCC) & AICore: Zero-Ambient-Egress On-Device Intelligence",
        left={
            "label": "Private Compute Core (PCC)",
            "theme": "green",
            "cards": [
                {"tag": "Isolated Foundation Model", "title": "AICore + Gemini Nano (TPU / NPU)",
                 "body": "Processes sensitive notifications, call summaries, & Smart Reply inside SELinux sandbox with zero INET sockets",
                 "theme": "white"},
                {"tag": "Ephemeral State", "title": "Per-Caller Isolated Context & LoRA Adapters",
                 "body": "Prevents cross-app prompt leakage; model weights updated without exfiltrating user inference inputs",
                 "theme": "green", "in_arrow": True},
            ],
        },
        right={
            "label": "Open-Source Bridge (PCS)",
            "theme": "teal",
            "cards": [
                {"tag": "Inspectable APK · GitHub AOSP", "title": "Private Compute Services (PCS)",
                 "body": "Tiny open-source package holding the sole network path; reproducible/auditable by external researchers",
                 "theme": "white"},
                {"tag": "Privacy-Preserving Protocols", "title": "Federated Compute, SecAgg, & PIR",
                 "body": "Enforces differential privacy, cryptographic secure aggregation, and Private Information Retrieval",
                 "theme": "teal", "in_arrow": True},
            ],
        },
        bridges=[
            (0, 0, "lr", "Typed Binder IPC Only", "green"),
            (1, 1, "lr", "DP / SecAgg Gradients Only", "teal"),
        ],
        boundary_label="SELinux Neverallow Network Air-Gap",
        footer="PCC components lack INTERNET permission at the kernel SELinux level; every byte crossing into PCS must traverse narrow privacy APIs."
    )

    # 39. Ch 18: 18-appfunctions-vs-virtual-window.svg
    build_sequence(
        P("18-appfunctions-vs-virtual-window.svg"),
        "Android 16/17 Agentic Execution: Typed AppFunctions vs. Secure Virtual Window",
        actors=[
            {"title": "User & System UI", "sub": "Explicit Intent & Confirm", "theme": "slate"},
            {"title": "Gemini Agent", "sub": "System Orchestrator", "theme": "purple"},
            {"title": "AppFunctions API", "sub": "Typed Schema (Preferred)", "theme": "green"},
            {"title": "Secure Virtual Window", "sub": "Isolated Off-Screen UI", "theme": "teal"},
        ],
        messages=[
            (0, 1, "User prompt: 'Order my usual dinner / find booking'", "slate", False),
            (1, 2, "Path A: AppFunctionManager.executeAppFunction(typedRequest)", "green", False),
            (2, 1, "Target app validates caller permission & schema -> structured result", "green", False),
            (1, 3, "Path B (legacy UI): launch opt-in app inside isolated VirtualDisplay", "teal", True),
            (3, 1, "Scoped view automation (cannot scrape unrelated background apps)", "teal", True),
            (1, 0, "Mandatory human takeover / confirmation before payment or send", "purple", False),
        ],
        boundary_after=1,
        boundary_label="Least-Privilege Tool & Display Mediation",
        bottom_note={
            "tag": "Prompt-Injection Defense Contrast",
            "title": "Why Sideloaded AccessibilityService Agents Break the Trust Chain",
            "body": "Third-party Accessibility agents hold omniscient read/click power across banking & 2FA apps; AppFunctions + Virtual Window isolate scope",
            "theme": "red",
        },
        footer="Indirect prompt injection inside untrusted emails or web pages requires strict separation between untrusted data and payment/send commits."
    )

    # 40. Ch 19: 19-titan-backup-key-vault.svg
    build_sequence(
        P("19-titan-backup-key-vault.svg"),
        "End-to-End Encrypted Cloud Backups & Google Titan Cloud Key Vault HSM",
        actors=[
            {"title": "Android Client", "sub": "BackupManager + Keystore", "theme": "green"},
            {"title": "Google Backup Host", "sub": "Untrusted Cloud Storage", "theme": "slate"},
            {"title": "Titan Cloud Key Vault", "sub": "Custom HSM Cohort", "theme": "purple"},
            {"title": "Replacement Phone", "sub": "LSKF Recovery Client", "theme": "teal"},
        ],
        messages=[
            (0, 0, "Generate random 256-bit Application Backup Key; encrypt app data locally", "green", False),
            (0, 2, "Wrap Backup Key to verified Titan HSM cohort public key + LSKF claim", "purple", False),
            (0, 1, "Upload AES-GCM backup ciphertext (host holds zero decryption key)", "slate", False),
            (3, 2, "Recovery: submit noise-encrypted LSKF proof to Titan HSM", "teal", False),
            (2, 2, "Verify signed HSM firmware & enforce strict <= 10 lifetime attempt counter", "purple", False),
            (2, 3, "Release wrapped Backup Key -> decrypt backup locally on new phone", "green", False),
        ],
        boundary_after=1,
        boundary_label="Hardware-Enforced Attempt Limit in Titan Silicon",
        footer="Even a compromised cloud storage host or Insider cannot brute-force a 6-digit PIN: Titan HSM permanently bricks the vault after 10 misses."
    )

    # 41. Ch 19: 19-private-ai-compute-tie.svg
    build_fan_bands(
        P("19-private-ai-compute-tie.svg"),
        "Private AI Compute: Hardware-Attested Titanium Intelligence Enclaves (TIE) on TPUs",
        bands=[
            [{"id": "client", "tag": "On-Device Verifier · Android Private Compute Client",
              "title": "Verifies Remote DICE Attestation & Transparency Log Before Opening HPKE Tunnel",
              "body": "Refuses to transmit prompt unless remote enclave proves genuine signed TIE firmware & zero debug/operator backdoors",
              "theme": "green"}],
            [{"id": "tunnel", "tag": "Blind Front-End Routing · Untrusted Cloud Control Plane",
              "title": "Oblivious / Blinded Relay Terminating Ciphertext Exclusively Inside Sealed Enclave",
              "body": "Load balancers and host administrators route opaque encrypted packets without TLS termination keys",
              "theme": "slate"}],
            [
                {"id": "cpu_enc", "tag": "Confidential Host Node",
                 "title": "AMD SEV-SNP / Titanium Sealed Orchestrator",
                 "body": "Hardware-encrypted DRAM + DICE identity anchored in Google Titan root of trust",
                 "theme": "teal"},
                {"id": "tpu_enc", "tag": "Accelerator Boundary",
                 "title": "Custom Google TPU inside Titanium Intelligence Enclave",
                 "body": "Authenticated PCIe/ICI link + ephemeral HBM state wiped cleanly upon inference completion",
                 "theme": "purple"},
            ],
        ],
        edges=[
            ("client", "tunnel", "end-to-end HPKE ciphertext", "green", False),
            ("tunnel", "cpu_enc", "sealed enclave ingress", "teal", False),
            ("tunnel", "tpu_enc", "attested Gemini inference", "purple", False),
        ],
        footer="Private AI Compute extends PCC's zero-operator-access guarantee from on-device Gemini Nano to frontier cloud TPU models."
    )

    # 42. Ch 20: 20-predator-baseband-gpu-chain.svg
    build_vertical_flow(
        P("20-predator-baseband-gpu-chain.svg"),
        "Anatomy of Multi-Vendor Spyware Chains: Basebands, Browsers, & GPU Kernel Drivers",
        steps=[
            {"tag": "Entry Vector A or B", "title": "0-Click VoLTE SDP (CVE-2023-24033) OR 1-Click Chrome Renderer",
             "body": "Exynos/Shannon cellular baseband RCE over carrier IMS, or Cytrox Predator V8 JIT bug inside u0_i* sandbox",
             "theme": "amber"},
            {"tag": "Sandbox Escape Seam", "title": "Vendor GPU Driver Bug (Mali CVE-2023-4211 / Adreno CVE-2024-23380)",
             "body": "untrusted_app / renderer reaches /dev/mali0 or /dev/kgsl-3d0 ioctl -> GPU page-table UAF yields physical R/W",
             "theme": "red", "edge_label": "reachable GPU ioctl"},
            {"tag": "Kernel Privilege", "title": "Data-Only Patch of task_struct cred & selinux_state",
             "body": "Side-steps KCFI/SCS by overwriting data structures in kernel RAM without hijacking code pointers",
             "theme": "red", "edge_label": "bypasses KCFI via data"},
            {"tag": "In-Memory Implant", "title": "Exfiltrate AFU Messengers & Mic Without Modifying /system",
             "body": "Avoids tripping AVB dm-verity by living in RAM or re-triggering via non-persistent app/browser cache",
             "theme": "red", "edge_label": "evades AVB at rest"},
        ],
        side_notes={
            0: {"tag": "Countermeasure", "title": "Adv. Protection & Baseband Sandboxing",
                "body": "Disables V8 JIT/WebGPU, turns off 2G, & isolates modem DMA via SMMUv3",
                "theme": "green", "edge_label": "blocks entry"},
            1: {"tag": "Countermeasure", "title": "Arm MTE + Rust Drivers + SELinux xperm",
                "body": "Shrinks reachable ioctls and catches spatial/temporal corruption before R/W",
                "theme": "teal", "edge_label": "hardens seam"},
        },
        footer="Every major commercial spyware chain avoids Android's Rust/AVB core and pivots through third-party C/C++ silicon vendor code."
    )

    # 43. Ch 20: 20-multivendor-patch-gap.svg
    build_horizontal_pipeline(
        P("20-multivendor-patch-gap.svg"),
        "The Structural Multi-Vendor Patch Gap: How Upstream Fixes Become In-the-Wild N-Days",
        stages=[
            {"tag": "Hop 1 · Day 0", "title": "Upstream Git Fix",
             "body": "Patch lands in public Linux, Chromium, Arm Mali, or Qualcomm repo", "theme": "slate"},
            {"tag": "Hop 2 · +30-60d", "title": "Silicon BSP Drop",
             "body": "SoC vendor bundles source drop for downstream OEM licensees; attackers diff git", "theme": "amber"},
            {"tag": "Hop 3 · +60-120d", "title": "Android Bulletin",
             "body": "Google publishes coordinated CVE advisory & GKI kernel patches", "theme": "teal"},
            {"tag": "Hop 4 · +90-210d+", "title": "OEM & Carrier OTA",
             "body": "Per-model regression test & staged carrier rollout finally reaches handset", "theme": "red"},
        ],
        under_anchor={
            "target_idx": 2,
            "tag": "Architectural Compression",
            "title": "Project Mainline APEX + GKI 2.0 Bypass OEM Lag for Core OS",
            "body": "Ships media, ART, Bluetooth, UWB, & core kernel fixes fast, leaving vendor_dlkm (.ko) & modem firmware as the final mile",
            "theme": "green",
            "edge_label": "bypasses lag",
        },
        footer="Project Zero documented multiple Mali & Qualcomm bugs exploited in the wild months after upstream fixes were already public."
    )
