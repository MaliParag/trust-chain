#!/usr/bin/env python3
"""
Generates series-matched 1400x1850 SVG + PNG Front and Back Covers for
Volume II (Apple), Volume III (Linux), and Volume IV (Android) of
The Platform Trust Chain Series.
"""
import math
import os
import subprocess
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W, H = 1400, 1850

SERIF = 'Georgia, Baskerville, "Times New Roman", serif'
SANS = '-apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif'
MONO = 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace'

SPECS = {
    "apple": {
        "vol_rubric": "VOLUME II  ·  SYSTEMS SECURITY  ·  UNIFIED SILICON TO PRIVATE CLOUD",
        "word1": "APPLE",
        "word2": "TRUST CHAIN",
        "sub1": "From Boot ROM and Secure Enclave Across iOS, macOS, iPadOS,",
        "sub2": "watchOS, and visionOS to Private Cloud Compute",
        "accent": "#7cc4f8",
        "snap": "#df5a67",
        "rail_label": "UNIFIED DARWIN · PLATFORM FORKS",
        "nodes": [
            (775,  "snap",   "FINALE · CHAPTER 20",          "ZERO-CLICK CHAINS & SOVEREIGN COMPULSION",
             "FORCEDENTRY  ·  Operation Triangulation  ·  UK IPA Section 253 ADP Compulsion"),
            (955,  "ring",   "PART IV · CHAPTERS 15 TO 19",  "ZERO-KNOWLEDGE CLOUD & AGENTIC AI",
             "iCloud HSM Escrow & ADP  ·  PQ3 & KT  ·  App Intents & MCP  ·  Private Cloud Compute"),
            (1135, "ring",   "PART III · CHAPTERS 10 TO 14", "DATA CUSTODY, ATTESTATION, & CONTINUITY",
             "APFS BFU/AFU  ·  Stolen Device Protection  ·  App Attest & MDA  ·  Passkeys & DDM"),
            (1315, "ring",   "PART II & INTERLUDE · CH. 5 TO 9", "XNU, CODE SIGNING, & OBSERVABILITY",
             "APFS SSV  ·  AMFI & TXM vs. Notarization  ·  Seatbelt & BlastDoor  ·  TCC & ESF"),
            (1495, "anchor", "PART I · CHAPTERS 1 TO 4",     "APPLE SILICON & PERSONALIZED BOOT",
             "Boot ROM  ·  Image4 & TSS  ·  macOS 1TR LocalPolicy  ·  SEP  ·  PAC, SPTM, & EMTE"),
        ],
        "lead1": "One silicon architecture across five operating systems.",
        "lead2": "Every guarantee is personalized in hardware or intentionally relaxed by owner policy.",
        "p1": (
            "Since the transition to Apple Silicon, iOS, iPadOS, macOS, watchOS, and visionOS share "
            "one vertical chain of cryptographic invariants: immutable Boot ROM and per-device Image4 "
            "tickets verify boot stages, the Secure Enclave Processor (SEP) isolates biometric and "
            "key material behind UID fuses, SPTM and Memory Integrity Enforcement (EMTE) harden XNU, "
            "and Private Cloud Compute extends hardware attestation to cloud AI."
        ),
        "p2": (
            "Rather than treating Apple's platforms as disconnected products, this volume traces "
            "their shared Darwin spine once and highlights the exact forks where threat models "
            "diverge: closed iPhone TXM enforcement versus macOS 1TR LocalPolicy, Notarization, and "
            "MCP agent boundaries, visionOS R1 gaze isolation, and mercenary zero-click chains."
        ),
        "parts": [
            ("PART I · SILICON", "Chapters 1 to 4", "Boot ROM, Image4/TSS, AppleDART, macOS 1TR LocalPolicy, SEP/sepOS, PAC, SPTM, Exclaves, and EMTE"),
            ("PART II & INTERLUDE", "Chapters 5 to 9", "APFS SSV, AMFI, TXM vs. Gatekeeper/Notarization, XPC/Seatbelt/BlastDoor, TCC, ESF, and forensics"),
            ("PART III · DATA & TRUST", "Chapters 10 to 14", "APFS Data Protection, Keychains, Stolen Device Protection, App Attest/MDA, Passkeys, and DDM/PSSO"),
            ("PART IV · CLOUD & AI", "Chapters 15 to 19", "iCloud HSM escrow & ADP, iMessage PQ3 + KT, Find My, App Intents/MCP agents, and Private Cloud Compute"),
            ("FINALE · THE SEAMS", "Chapter 20", "FORCEDENTRY, Operation Triangulation MMIO, WebKit-to-dyld chains, and UK IPA Section 253 compulsion"),
        ],
    },
    "linux": {
        "vol_rubric": "VOLUME III  ·  SYSTEMS SECURITY  ·  COMPOSABLE OPEN-SOURCE ROOTS TO CLOUD",
        "word1": "LINUX",
        "word2": "TRUST CHAIN",
        "sub1": "From UEFI, Unified Kernel Images, and dm-verity Through",
        "sub2": "LSMs, eBPF, and Containers to Confidential Cloud",
        "accent": "#e5954b",
        "snap": "#df5a67",
        "rail_label": "eBPF & LSM MEDIATION",
        "nodes": [
            (775,  "snap",   "FINALE · CHAPTER 20",          "UPSTREAM SUPPLY-CHAIN SUBVERSION",
             "XZ Utils liblzma Backdoor  ·  Sigstore & Rekor  ·  SLSA & Reproducible Builds"),
            (955,  "ring",   "PART IV · CHAPTERS 14 TO 19",  "CONTAINERS, AI SANDBOXES, & CONFIDENTIAL VMs",
             "Namespaces & seccomp  ·  gVisor & Firecracker  ·  SPIFFE/SPIRE  ·  SVSM & CoCo"),
            (1135, "ring",   "PART III · CHAPTERS 9 TO 13",  "USERSPACE PRIVILEGE, SECRETS, & IDENTITY",
             "Capabilities & userns  ·  systemd run0  ·  systemd-creds  ·  PAM, FIDO2, & OpenSSH"),
            (1315, "ring",   "PART II & INTERLUDE · CH. 5 TO 8", "KERNEL HARDENING, LSMs, & eBPF",
             "Kernel Lockdown & Rust  ·  SELinux, AppArmor, & Landlock  ·  LSM-BPF vs. Verifier"),
            (1495, "anchor", "PART I · CHAPTERS 1 TO 4",     "UEFI, SHIM, UKI, & VERIFIED ROOTFS",
             "shim & SBAT  ·  Unified Kernel Images (UKI)  ·  systemd-pcrlock  ·  dm-verity, IPE, & Keylime"),
        ],
        "lead1": "On Linux, trust is assembled from composable mechanisms rather than dictated by one vendor.",
        "lead2": "Every unsealed seam between bootloader, initramfs, kernel, and tarball breaks the chain.",
        "p1": (
            "Unlike vertically integrated proprietary platforms, Linux spans workstations, immutable "
            "appliances, hyperscale Kubernetes nodes, AI execution sandboxes, and confidential cloud "
            "guests. Closing the gap between a signed kernel and an unverified initramfs required "
            "shim/SBAT, signed Unified Kernel Images (UKIs), systemd-pcrlock TPM2 policies, dm-verity, "
            "Integrity Policy Enforcement (IPE), and stacked Linux Security Modules."
        ),
        "p2": (
            "This volume traces how modern Linux composes those primitives from reset vector to "
            "confidential cloud, analyzing where user namespaces and shared kernels fail against "
            "untrusted code, how eBPF acts as both enforcement substrate and attack surface, how "
            "Firecracker and Landlock isolate AI agents, and how XZ Utils subverted upstream trust."
        ),
        "parts": [
            ("PART I · VERIFIED BOOT", "Chapters 1 to 4", "UEFI shim, MOK, SBAT, Unified Kernel Images, systemd-pcrlock TPM2 PCRs, LUKS2, dm-verity, IPE, and Keylime"),
            ("PART II & INTERLUDE", "Chapters 5 to 8", "Kernel Lockdown, KCFI/CET/Rust, SELinux, AppArmor, unprivileged Landlock, and the eBPF dual edge"),
            ("PART III · USERSPACE AUTH", "Chapters 9 to 13", "Capabilities & userns, systemd run0, D-Bus sandboxing, systemd-creds, PAM/SSSD, and OpenSSH/FIDO2"),
            ("PART IV · CLOUD & AI", "Chapters 14 to 19", "OCI containers, gVisor & Firecracker AI sandboxes, SPIFFE/SPIRE, COCONUT-SVSM, and Confidential Containers"),
            ("FINALE · SUPPLY CHAIN", "Chapter 20", "XZ Utils (CVE-2024-3094) IFUNC backdoor, dlopen() isolation, Reproducible Builds, SLSA, and Sigstore"),
        ],
    },
    "android": {
        "vol_rubric": "VOLUME IV  ·  SYSTEMS SECURITY  ·  VERIFIED BOOT, pKVM, & MOBILE ISOLATION",
        "word1": "ANDROID",
        "word2": "TRUST CHAIN",
        "sub1": "From Verified Boot 2.0, StrongBox, and pKVM Through",
        "sub2": "SELinux and Keystore to Play Integrity and Private Compute",
        "accent": "#57c98c",
        "snap": "#df5a67",
        "rail_label": "SELINUX & BINDER MEDIATION",
        "nodes": [
            (775,  "snap",   "FINALE · CHAPTER 20",          "GPUs, BASEBANDS, & MULTI-VENDOR SEAMS",
             "Mali & Adreno GPU Drivers  ·  Exynos/Shannon Baseband RCE  ·  The OEM Patch Gap"),
            (955,  "ring",   "PART IV · CHAPTERS 15 TO 19",  "ATTESTATION, ENTERPRISE, & AGENTIC AI",
             "Key Attestation & RKP  ·  Play Integrity  ·  AICore & AppFunctions  ·  Private AI Compute"),
            (1135, "ring",   "PART III & INTERLUDE · CH. 9 TO 14", "APP SANDBOX, STORAGE, & FORENSICS",
             "Per-App UID & Binder  ·  Advanced Protection  ·  FBE & Identity Check  ·  Intrusion Logging"),
            (1315, "ring",   "PART II · CHAPTERS 5 TO 8",    "pKVM, SELINUX, GKI, & ARM MTE",
             "Protected KVM (AVF)  ·  Enforcing SELinux neverallow  ·  Treble/GKI & Rust  ·  Arm MTE"),
            (1495, "anchor", "PART I · CHAPTERS 1 TO 4",     "BOOT ROM, AVB 2.0, & STRONGBOX",
             "SoC Boot ROM  ·  AVB 2.0 VBMeta & Rollback Indexes  ·  dm-verity  ·  Titan M2 & KeyMint"),
        ],
        "lead1": "Every installed application is treated as a mutually distrusting principal from day one.",
        "lead2": "Hardware-backed Verified Boot, SELinux, and pKVM turn Linux into a zero-root mobile OS.",
        "p1": (
            "Android re-engineered the Linux kernel around a radically different premise than desktop "
            "Unix: there is no ambient multi-app user session, persistent OS partitions are sealed "
            "under dm-verity and Android Verified Boot 2.0 (VBMeta), every app runs as an isolated UID "
            "confined by mandatory SELinux neverallow rules and Binder IPC, and keys reside in StrongBox."
        ),
        "p2": (
            "With Protected KVM (pKVM) moving isolation beneath both Linux and TrustZone, Arm MTE "
            "hardening native heaps, Intrusion Logging preserving tamper-evident forensics, and Private "
            "AI Compute extending attestation to cloud TPUs, this volume traces mobile trust end to end "
            "and examines where GPUs, basebands, USB drivers, and OEM patch lag fracture the chain."
        ),
        "parts": [
            ("PART I · VERIFIED BOOT", "Chapters 1 to 4", "SoC ROM, Green/Yellow/Orange lock states, AVB 2.0 VBMeta, dm-verity/APEX, StrongBox, and KeyMint/Weaver"),
            ("PART II · pKVM & KERNEL", "Chapters 5 to 8", "Protected KVM (AVF/Microdroid), enforcing SELinux neverallow, Project Treble/GKI, Rust, and Arm MTE"),
            ("PART III & INTERLUDE", "Chapters 9 to 14", "Per-app UIDs & Binder, Advanced Protection, FBE & Identity Check, Passkeys, and E2EE Intrusion Logging"),
            ("PART IV · CLOUD & AI", "Chapters 15 to 19", "RKP Key Attestation, Play Integrity vs. keyboxes, Work Profiles, AICore/AppFunctions, and Private AI Compute"),
            ("FINALE · THE SEAMS", "Chapter 20", "Mali/Adreno GPU chains, Exynos/Shannon baseband RCE, TrustZone trustlets, and the multi-tier OEM patch gap"),
        ],
    },
}


def text_el(x, y, s, font=SERIF, size=24, fill="#f6f3ec", weight="400",
            style="normal", anchor="start", spacing=0.0):
    sp = f' letter-spacing="{spacing}px"' if spacing else ""
    st = f' font-style="{style}"' if style != "normal" else ""
    return (f'<text x="{x}" y="{y}" font-family=\'{font}\' font-size="{size}" '
            f'font-weight="{weight}"{st}{sp} fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>')


def wrap_para(text, max_chars):
    words = text.split()
    lines, cur = [], words[0]
    for w in words[1:]:
        if len(cur) + 1 + len(w) <= max_chars:
            cur += " " + w
        else:
            lines.append(cur)
            cur = w
    lines.append(cur)
    return lines


def common_frame(els, acc):
    els.append(f"""
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#070b12"/>
      <stop offset="52%" stop-color="#0d1523"/>
      <stop offset="100%" stop-color="#070a11"/>
    </linearGradient>
    <radialGradient id="accGlow" cx="55%" cy="58%" r="48%">
      <stop offset="0%" stop-color="{acc}" stop-opacity="0.09"/>
      <stop offset="65%" stop-color="#2b4c7e" stop-opacity="0.05"/>
      <stop offset="100%" stop-color="#070b12" stop-opacity="0.0"/>
    </radialGradient>
    <linearGradient id="accRule" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="{acc}" stop-opacity="0.95"/>
      <stop offset="65%" stop-color="{acc}" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="{acc}" stop-opacity="0.0"/>
    </linearGradient>
    <pattern id="archGrid" width="60" height="60" patternUnits="userSpaceOnUse">
      <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#8fa8c8" stroke-width="0.6" stroke-opacity="0.045"/>
    </pattern>
  </defs>
  <rect x="0" y="0" width="1400" height="1850" fill="url(#bgGrad)"/>
  <rect x="0" y="0" width="1400" height="1850" fill="url(#accGlow)"/>
  <rect x="64" y="64" width="1272" height="1722" fill="url(#archGrid)"/>
  <rect x="56" y="56" width="1288" height="1738" fill="none" stroke="#223046" stroke-width="1.5"/>
  <rect x="68" y="68" width="1264" height="1714" fill="none" stroke="{acc}" stroke-width="0.8" stroke-opacity="0.30"/>
  <path d="M 56 96 L 56 56 L 96 56 M 1304 56 L 1344 56 L 1344 96 M 56 1754 L 56 1794 L 96 1794 M 1304 1794 L 1344 1794 L 1344 1754"
        fill="none" stroke="{acc}" stroke-width="2.0" stroke-opacity="0.75"/>
""")


def build_front(sp):
    acc = sp["accent"]
    snap = sp["snap"]
    els = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">']
    common_frame(els, acc)
    lx = 136
    els.append(text_el(lx, 162, sp["vol_rubric"], font=SANS, size=14.5, fill=acc, weight="600", spacing=1.4))
    els.append(f'<line x1="{lx}" y1="184" x2="1264" y2="184" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx + 4, 256, "T H E", font=SERIF, size=27, fill=acc, weight="700"))
    els.append(text_el(lx, 366, sp["word1"], font=SERIF, size=112, fill="#f7f4ed", weight="700", spacing=1.2))
    els.append(text_el(lx, 484, sp["word2"], font=SERIF, size=106, fill=acc, weight="700", spacing=1.0))
    els.append(f'<rect x="{lx}" y="528" width="540" height="2.2" fill="url(#accRule)"/>')
    els.append(text_el(lx, 584, sp["sub1"], font=SERIF, size=29, fill="#cbd5e1", style="italic"))
    els.append(text_el(lx, 626, sp["sub2"], font=SERIF, size=29, fill="#cbd5e1", style="italic"))

    cx = 478
    rail_x = 196
    rt, rb = 955, 1495
    els.append(f'<path d="M {cx - 74} {rt} L {rail_x} {rt} L {rail_x} {rb} L {cx - 74} {rb}" '
               f'fill="none" stroke="#537299" stroke-width="1.6" stroke-dasharray="6,5"/>')
    for ny in (1135, 1315):
        els.append(f'<line x1="{rail_x}" y1="{ny}" x2="{cx - 74}" y2="{ny}" stroke="#537299" stroke-width="1.3" stroke-dasharray="4,5"/>')
    mid_rail = (rt + rb) / 2
    els.append(f'<rect x="{rail_x - 22}" y="{mid_rail - 185}" width="44" height="370" rx="6" fill="#0c1422" stroke="#456184" stroke-width="1.2"/>')
    els.append(f'<text x="{rail_x + 5}" y="{mid_rail}" font-family=\'{SANS}\' font-size="13" font-weight="700" letter-spacing="1.1px" '
               f'fill="#8cb0db" text-anchor="middle" transform="rotate(-90 {rail_x + 5} {mid_rail})">{escape(sp["rail_label"])}</text>')

    nodes = sp["nodes"]
    for idx in range(len(nodes) - 1):
        y_top, y_bot = nodes[idx][0], nodes[idx + 1][0]
        col = snap if idx == 0 else acc
        y_start, y_end = y_bot - 56, y_top + 58
        els.append(f'<line x1="{cx}" y1="{y_start}" x2="{cx}" y2="{y_end + 8}" stroke="{col}" stroke-width="2.4" stroke-opacity="0.88"/>')
        els.append(f'<polygon points="{cx},{y_end - 2} {cx - 7},{y_end + 12} {cx + 7},{y_end + 12}" fill="{col}"/>')

    tx = 564
    for cy, kind, ptag, ptitle, pdetail in nodes:
        col = snap if kind == "snap" else acc
        if kind == "anchor":
            pts = [f"{cx + 52 * math.cos(math.radians(30 + k * 60)):.1f},{cy + 52 * math.sin(math.radians(30 + k * 60)):.1f}" for k in range(6)]
            els.append(f'<polygon points="{" ".join(pts)}" fill="#101a2b" stroke="{col}" stroke-width="3.0"/>')
            els.append(f'<rect x="{cx - 20}" y="{cy - 20}" width="40" height="40" rx="4" fill="#162338" stroke="{col}" stroke-width="1.8"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{col}"/>')
        elif kind == "ring":
            els.append(f'<circle cx="{cx}" cy="{cy}" r="50" fill="#0e1726" stroke="{col}" stroke-width="2.8"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="36" fill="none" stroke="{col}" stroke-width="1.0" stroke-opacity="0.45"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{col}"/>')
        else:
            els.append(f'<path d="M {cx - 32:.1f} {cy - 38:.1f} A 50 50 0 1 0 {cx + 34:.1f} {cy + 36:.1f}" fill="none" stroke="{acc}" stroke-width="2.8" stroke-opacity="0.65"/>')
            els.append(f'<path d="M {cx - 18:.1f} {cy - 47:.1f} A 50 50 0 0 1 {cx + 46:.1f} {cy + 18:.1f}" transform="translate(7,-6)" fill="none" stroke="{snap}" stroke-width="3.2"/>')
            els.append(f'<line x1="{cx - 38}" y1="{cy + 28}" x2="{cx + 42}" y2="{cy - 34}" stroke="{snap}" stroke-width="2.2" stroke-dasharray="7,5"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{snap}"/>')

        els.append(text_el(tx, cy - 22, ptag, font=SANS, size=13.5, fill=col, weight="700", spacing=1.2))
        els.append(text_el(tx, cy + 6, ptitle, font=SERIF, size=23.5, fill="#f7f4ed", weight="700", spacing=0.4))
        els.append(text_el(tx, cy + 32, pdetail, font=MONO, size=13.0, fill="#9fb0c7"))

    els.append(f'<line x1="{lx}" y1="1648" x2="1264" y2="1648" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx, 1716, "Parag Mali", font=SERIF, size=42, fill="#f7f4ed", weight="400", spacing=0.4))
    els.append("</svg>\n")
    return "\n".join(els)


def build_back(sp):
    acc = sp["accent"]
    els = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">']
    common_frame(els, acc)
    lx, rx = 136, 1264
    cw = rx - lx

    els.append(text_el(lx, 162, f'THE {sp["word1"]} {sp["word2"]}  ·  ARCHITECTURAL OVERVIEW', font=SANS, size=15, fill=acc, weight="600", spacing=1.5))
    els.append(f'<line x1="{lx}" y1="184" x2="{rx}" y2="184" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx, 248, sp["lead1"], font=SERIF, size=32, fill="#f7f4ed", weight="700"))
    els.append(text_el(lx, 294, sp["lead2"], font=SERIF, size=28, fill=acc, style="italic"))

    cy = 364
    for para in (sp["p1"], sp["p2"]):
        for line in wrap_para(para, 92):
            els.append(text_el(lx, cy, line, font=SERIF, size=22.0, fill="#d0d9e6"))
            cy += 34
        cy += 18

    els.append(text_el(lx, cy + 16, "ARCHITECTURE OF THIS VOLUME", font=SANS, size=14.5, fill=acc, weight="700", spacing=1.4))
    cy += 36

    row_h = 104
    for idx, (p_name, p_ch, p_desc) in enumerate(sp["parts"]):
        bar = sp["snap"] if idx == len(sp["parts"]) - 1 else acc
        els.append(f'<rect x="{lx}" y="{cy}" width="{cw}" height="{row_h - 12}" rx="6" fill="#0d1728" stroke="#22324a" stroke-width="1.2"/>')
        els.append(f'<rect x="{lx}" y="{cy}" width="5" height="{row_h - 12}" rx="2" fill="{bar}"/>')
        els.append(text_el(lx + 24, cy + 35, p_name, font=SANS, size=14.5, fill=bar, weight="700", spacing=1.0))
        els.append(text_el(lx + 24, cy + 62, p_ch, font=MONO, size=13.5, fill="#8ea2bd"))
        dlines = wrap_para(p_desc, 74)
        if len(dlines) == 1:
            els.append(text_el(lx + 298, cy + 51, dlines[0], font=SERIF, size=18.0, fill="#eef2f7"))
        else:
            els.append(text_el(lx + 298, cy + 39, dlines[0], font=SERIF, size=17.4, fill="#eef2f7"))
            els.append(text_el(lx + 298, cy + 64, dlines[1], font=SERIF, size=17.4, fill="#eef2f7"))
        cy += row_h

    els.append(f'<line x1="{lx}" y1="1648" x2="{rx}" y2="1648" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx, 1696, "Parag Mali", font=SERIF, size=30, fill="#f7f4ed", weight="700"))
    els.append(text_el(lx, 1728, "The Platform Trust Chain Series", font=MONO, size=15.5, fill="#8cb0db"))

    bx, by, bw, bh = rx - 418, 1668, 418, 72
    els.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="5" fill="#0d1728" stroke="{acc}" stroke-width="1.1" stroke-opacity="0.55"/>')
    els.append(text_el(bx + bw / 2, by + 30, "OPEN TECHNICAL SERIES  ·  2026", font=SANS, size=13.5, fill=acc, weight="700", anchor="middle", spacing=1.1))
    els.append(text_el(bx + bw / 2, by + 53, "CC BY-NC-SA 4.0  ·  SYSTEMS SECURITY", font=SANS, size=11.8, fill="#9fb0c7", weight="500", anchor="middle", spacing=0.8))
    els.append("</svg>\n")
    return "\n".join(els)


def main():
    for slug, sp in SPECS.items():
        sdir = os.path.join(ROOT, "books", slug, "src")
        os.makedirs(sdir, exist_ok=True)
        f_svg, f_png = os.path.join(sdir, "cover.svg"), os.path.join(sdir, "cover.png")
        b_svg, b_png = os.path.join(sdir, "back-cover.svg"), os.path.join(sdir, "back-cover.png")
        open(f_svg, "w", encoding="utf-8").write(build_front(sp))
        open(b_svg, "w", encoding="utf-8").write(build_back(sp))
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), f_svg, "-o", f_png], check=True)
        subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), b_svg, "-o", b_png], check=True)
        print(f"Generated covers for books/{slug}/src/ ({W}x{H})")


if __name__ == "__main__":
    main()
