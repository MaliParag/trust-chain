#!/usr/bin/env python3
"""
Generates high-craft Front Cover (src/cover.svg + src/cover.png) and
Back Cover (src/back-cover.svg + src/back-cover.png) at exact 1400x1850
(7.00 in x 9.25 in technical hardcover trim).
"""
import math
import os
import subprocess
from xml.sax.saxutils import escape

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")

SERIF = 'Georgia, Baskerville, "Times New Roman", serif'
SANS = '-apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif'
MONO = 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace'

W, H = 1400, 1850


def check_text(t: str):
    if "\u2014" in t or " -- " in t:
        raise ValueError(f"Forbidden em-dash in cover text: {t!r}")


def text_el(x, y, s, font=SERIF, size=24, fill="#f6f3ec", weight="400",
            style="normal", anchor="start", spacing=0.0, opacity=1.0):
    check_text(s)
    sp = f' letter-spacing="{spacing}px"' if spacing else ""
    st = f' font-style="{style}"' if style != "normal" else ""
    op = f' opacity="{opacity}"' if opacity < 1.0 else ""
    return (f'<text x="{x}" y="{y}" font-family=\'{font}\' font-size="{size}" '
            f'font-weight="{weight}"{st}{sp}{op} fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>')


def common_defs_and_frame(els):
    els.append("""
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#070b12"/>
      <stop offset="52%" stop-color="#0d1523"/>
      <stop offset="100%" stop-color="#070a11"/>
    </linearGradient>
    <radialGradient id="goldGlow" cx="55%" cy="58%" r="48%">
      <stop offset="0%" stop-color="#d4a843" stop-opacity="0.09"/>
      <stop offset="65%" stop-color="#2b4c7e" stop-opacity="0.05"/>
      <stop offset="100%" stop-color="#070b12" stop-opacity="0.0"/>
    </radialGradient>
    <radialGradient id="snapGlow" cx="38%" cy="44%" r="22%">
      <stop offset="0%" stop-color="#d45763" stop-opacity="0.14"/>
      <stop offset="100%" stop-color="#070b12" stop-opacity="0.0"/>
    </radialGradient>
    <linearGradient id="goldRule" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#d4a843" stop-opacity="0.95"/>
      <stop offset="65%" stop-color="#d4a843" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="#d4a843" stop-opacity="0.0"/>
    </linearGradient>
    <pattern id="archGrid" width="60" height="60" patternUnits="userSpaceOnUse">
      <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#8fa8c8" stroke-width="0.6" stroke-opacity="0.045"/>
    </pattern>
  </defs>
  <rect x="0" y="0" width="1400" height="1850" fill="url(#bgGrad)"/>
  <rect x="0" y="0" width="1400" height="1850" fill="url(#goldGlow)"/>
  <rect x="64" y="64" width="1272" height="1722" fill="url(#archGrid)"/>
  <!-- Outer slate frame & inner gold corner registration marks -->
  <rect x="56" y="56" width="1288" height="1738" fill="none" stroke="#223046" stroke-width="1.5"/>
  <rect x="68" y="68" width="1264" height="1714" fill="none" stroke="#d4a843" stroke-width="0.8" stroke-opacity="0.28"/>
  <!-- Corner L-ticks -->
  <path d="M 56 96 L 56 56 L 96 56 M 1304 56 L 1344 56 L 1344 96 M 56 1754 L 56 1794 L 96 1794 M 1304 1794 L 1344 1794 L 1344 1754"
        fill="none" stroke="#d4a843" stroke-width="2.0" stroke-opacity="0.72"/>
""")


def build_front_cover():
    els = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">']
    common_defs_and_frame(els)
    els.append('<rect x="0" y="0" width="1400" height="1850" fill="url(#snapGlow)"/>')

    lx = 136
    # Top rubric
    els.append(text_el(lx, 162, "SYSTEMS SECURITY  ·  ARCHITECTURE & ADVERSARIAL ANALYSIS",
                       font=SANS, size=15, fill="#d4a843", weight="600", spacing=1.5))
    els.append(f'<line x1="{lx}" y1="184" x2="1264" y2="184" stroke="#233248" stroke-width="1.2"/>')

    # Main Title Block
    els.append(text_el(lx + 4, 256, "T H E", font=SERIF, size=27, fill="#d4a843", weight="700"))
    els.append(text_el(lx, 366, "WINDOWS", font=SERIF, size=112, fill="#f7f4ed", weight="700", spacing=1.2))
    els.append(text_el(lx, 484, "TRUST CHAIN", font=SERIF, size=106, fill="#d4a843", weight="700", spacing=1.0))

    # Subtitle
    els.append(f'<rect x="{lx}" y="528" width="540" height="2.2" fill="url(#goldRule)"/>')
    els.append(text_el(lx, 584, "How Modern Windows Builds Trust from Silicon to Cloud,",
                       font=SERIF, size=30, fill="#cbd5e1", style="italic"))
    els.append(text_el(lx, 626, "and Where Attackers Break It",
                       font=SERIF, size=30, fill="#cbd5e1", style="italic"))

    # Centerpiece Architectural Spine (y = 755 .. 1545)
    # 5 nodes ordered top (Finale: snapped crimson link) to bottom (Part I: fused silicon anchor)
    cx = 478
    nodes = [
        # (cy, kind, part_tag, title, detail, accent)
        (775,  "snap",   "FINALE · CHAPTER 20",          "WHEN THE CHAIN SNAPS",
         "Storm-0558  ·  Stolen Signing Root vs. Omitted RFC 8725 Issuer Check", "#df5a67"),
        (955,  "ring",   "PART IV · CHAPTERS 17 TO 19",  "CLOUD & CONFIDENTIAL COMPUTE",
         "Zero Trust PDP/PEP  ·  Continuous Access Evaluation  ·  SEV-SNP & TDX", "#d4a843"),
        (1135, "ring",   "PART III · CHAPTERS 10 TO 15", "CREDENTIALS & ACCESS",
         "Tokens & MIC  ·  Credential Guard  ·  NTLM Sunset  ·  Kerberos  ·  Passkeys", "#d4a843"),
        (1315, "ring",   "PART II · CHAPTERS 6 TO 9",    "KERNEL & CODE INTEGRITY",
         "Hyper-V SLAT  ·  VTL1 Secure Kernel  ·  HVCI  ·  WDAC  ·  PPL  ·  CET", "#d4a843"),
        (1495, "anchor", "PART I · CHAPTERS 1 TO 5",     "SILICON & FIRMWARE ROOTS",
         "Boot Guard & HVB  ·  UEFI Secure Boot  ·  TPM 2.0  ·  Pluton  ·  PCR[0..14]", "#d4a843"),
    ]

    # Left side bracket: Interlude Ch 16 (ETW Observability Rail spanning Parts I-IV)
    rail_x = 196
    rt, rb = 955, 1495
    els.append(f'<path d="M {cx - 74} {rt} L {rail_x} {rt} L {rail_x} {rb} L {cx - 74} {rb}" '
               f'fill="none" stroke="#537299" stroke-width="1.6" stroke-dasharray="6,5"/>')
    for ny in (1135, 1315):
        els.append(f'<line x1="{rail_x}" y1="{ny}" x2="{cx - 74}" y2="{ny}" '
                   f'stroke="#537299" stroke-width="1.3" stroke-dasharray="4,5"/>')
    for ny in (955, 1135, 1315, 1495):
        els.append(f'<circle cx="{rail_x}" cy="{ny}" r="4.5" fill="#0d1523" stroke="#6d8fb8" stroke-width="1.8"/>')

    # Vertical rotated label on the ETW sightline pill
    mid_rail = (rt + rb) / 2
    els.append(f'<rect x="{rail_x - 22}" y="{mid_rail - 165}" width="44" height="330" rx="6" '
               f'fill="#0c1422" stroke="#456184" stroke-width="1.2"/>')
    els.append(f'<text x="{rail_x + 5}" y="{mid_rail}" font-family=\'{SANS}\' font-size="13.5" '
               f'font-weight="700" letter-spacing="1.2px" fill="#8cb0db" text-anchor="middle" '
               f'transform="rotate(-90 {rail_x + 5} {mid_rail})">CH. 16 · ETW TELEMETRY</text>')

    # Upward inheritance connectors between consecutive nodes
    for idx in range(len(nodes) - 1):
        y_top = nodes[idx][0]
        y_bot = nodes[idx + 1][0]
        col = "#df5a67" if idx == 0 else "#d4a843"
        y_start = y_bot - 56
        y_end = y_top + 58
        els.append(f'<line x1="{cx}" y1="{y_start}" x2="{cx}" y2="{y_end + 8}" '
                   f'stroke="{col}" stroke-width="2.4" stroke-opacity="0.88"/>')
        # Crisp upward arrowhead
        els.append(f'<polygon points="{cx},{y_end - 2} {cx - 7},{y_end + 12} {cx + 7},{y_end + 12}" fill="{col}"/>')

    # Render the 5 emblem medallions + right-aligned architectural descriptions
    tx = 564
    for cy, kind, ptag, ptitle, pdetail, acc in nodes:
        if kind == "anchor":
            # Octagonal/hexagonal silicon die frame + inner gold core
            pts = []
            for k in range(6):
                ang = math.radians(30 + k * 60)
                pts.append(f"{cx + 52 * math.cos(ang):.1f},{cy + 52 * math.sin(ang):.1f}")
            els.append(f'<polygon points="{" ".join(pts)}" fill="#101a2b" stroke="{acc}" stroke-width="3.0"/>')
            els.append(f'<rect x="{cx - 20}" y="{cy - 20}" width="40" height="40" rx="4" '
                       f'fill="#162338" stroke="{acc}" stroke-width="1.8"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{acc}"/>')
        elif kind == "ring":
            els.append(f'<circle cx="{cx}" cy="{cy}" r="50" fill="#0e1726" stroke="{acc}" stroke-width="2.8"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="36" fill="none" stroke="{acc}" stroke-width="1.0" stroke-opacity="0.45"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{acc}"/>')
        elif kind == "snap":
            # Fractured ring: two separated arcs + crimson fault slash showing where trust snaps!
            # Left-lower arc (125 deg to 305 deg) and right-upper offset arc (-35 deg to 95 deg shifted +5,-5)
            els.append(f'<path d="M {cx - 32:.1f} {cy - 38:.1f} A 50 50 0 1 0 {cx + 34:.1f} {cy + 36:.1f}" '
                       f'fill="none" stroke="#d4a843" stroke-width="2.8" stroke-opacity="0.65"/>')
            els.append(f'<path d="M {cx - 18:.1f} {cy - 47:.1f} A 50 50 0 0 1 {cx + 46:.1f} {cy + 18:.1f}" '
                       f'transform="translate(7,-6)" fill="none" stroke="{acc}" stroke-width="3.2"/>')
            els.append(f'<line x1="{cx - 38}" y1="{cy + 28}" x2="{cx + 42}" y2="{cy - 34}" '
                       f'stroke="{acc}" stroke-width="2.2" stroke-dasharray="7,5"/>')
            els.append(f'<circle cx="{cx}" cy="{cy}" r="6.5" fill="{acc}"/>')

        # Right-side text block aligned cleanly to medallion center
        els.append(text_el(tx, cy - 22, ptag, font=SANS, size=13.5, fill=acc, weight="700", spacing=1.2))
        els.append(text_el(tx, cy + 6, ptitle, font=SERIF, size=24.5, fill="#f7f4ed", weight="700", spacing=0.5))
        els.append(text_el(tx, cy + 32, pdetail, font=MONO, size=13.4, fill="#9fb0c7"))

    # Bottom Divider & Author Bar
    els.append(f'<line x1="{lx}" y1="1648" x2="1264" y2="1648" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx, 1716, "Parag Mali", font=SERIF, size=42, fill="#f7f4ed", weight="400", spacing=0.4))

    els.append("</svg>\n")
    return "\n".join(els)


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


def build_back_cover():
    els = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">']
    common_defs_and_frame(els)

    lx = 136
    rx = 1264
    cw = rx - lx

    # Top rubric
    els.append(text_el(lx, 162, "THE WINDOWS TRUST CHAIN  ·  ARCHITECTURAL OVERVIEW",
                       font=SANS, size=15, fill="#d4a843", weight="600", spacing=1.5))
    els.append(f'<line x1="{lx}" y1="184" x2="{rx}" y2="184" stroke="#233248" stroke-width="1.2"/>')

    # Pull-quote lead
    els.append(text_el(lx, 248, "In modern Windows, no layer can assert its own trustworthiness.",
                       font=SERIF, size=34, fill="#f7f4ed", weight="700"))
    els.append(text_el(lx, 294, "Every security invariant is inherited from silicon or lost at the seam.",
                       font=SERIF, size=31, fill="#d4a843", style="italic"))

    # Two-paragraph synopsis
    p1 = (
        "Modern Windows is defended not by isolated features, but by a directed chain of "
        "cryptographic and hardware invariants: fused silicon roots verify UEFI firmware before "
        "the OS loader runs, TPM 2.0 and Microsoft Pluton bind Measured Boot state into PCR banks, "
        "Hyper-V SLAT partitions physical memory into VTL0 and VTL1, kernel code integrity and "
        "access tokens constrain execution, Kerberos tickets and WebAuthn passkeys authenticate "
        "identity, ETW records kernel telemetry, and cloud policy engines continuously evaluate risk."
    )
    p2 = (
        "Across twenty chapters grounded in 876 primary-source specifications, RFCs, research "
        "papers, and incident reports, this book pairs the exact mechanism of each link with the "
        "adversarial techniques (BlackLotus, Bitpixie, BYOVD, Potato escalation, Pass-the-Challenge, "
        "Golden Ticket, Pass-the-PRT, and Storm-0558) that break the chain whenever a higher tier "
        "mistakes cryptographic validity for authorization."
    )

    cy = 364
    for para in (p1, p2):
        for line in wrap_para(para, 92):
            els.append(text_el(lx, cy, line, font=SERIF, size=22.5, fill="#d0d9e6"))
            cy += 34
        cy += 18

    # Architecture of the Book Engraved Grid (6 rows)
    els.append(text_el(lx, cy + 16, "ARCHITECTURE OF THE TWENTY-CHAPTER EDITION",
                       font=SANS, size=14.5, fill="#d4a843", weight="700", spacing=1.4))
    cy += 36

    parts = [
        ("PART I · SILICON", "Chapters 1 to 5",
         "UEFI Secure Boot, TPM 1.2 to 2.0, Microsoft Pluton, Measured Boot PCRs, and Remote Attestation", "#d4a843"),
        ("PART II · KERNEL & CODE", "Chapters 6 to 9",
         "Hyper-V VBS & VTL1 Trustlets, Authenticode, HVCI, App Control (WDAC), PPL, ACG, CFG/XFG, and CET", "#d4a843"),
        ("PART III · CREDENTIALS", "Chapters 10 to 15",
         "Tokens & MIC, Credential Guard, NTLM Deprecation, Kerberos & [MS-PAC], Pass-the-PRT, and Passkeys", "#d4a843"),
        ("INTERLUDE · TELEMETRY", "Chapter 16",
         "ETW Lock-Free Per-CPU Ring Buffers, Manifest Fan-Out, 0xC3 Patching vs. Kernel EtwTi, and PPL Gates", "#7ea6d8"),
        ("PART IV · CLOUD", "Chapters 17 to 19",
         "NIST SP 800-207 Conditional Access, Continuous Access Evaluation (CAE), and Azure Confidential VMs", "#d4a843"),
        ("FINALE · THE SNAP", "Chapter 20",
         "Storm-0558, Stolen 2016 MSA Signing Key, Omitted RFC 8725 Issuer Validation, and SFI Remediation", "#df5a67"),
    ]

    row_h = 96
    for p_name, p_ch, p_desc, acc in parts:
        els.append(f'<rect x="{lx}" y="{cy}" width="{cw}" height="{row_h - 10}" rx="6" '
                   f'fill="#0d1728" stroke="#22324a" stroke-width="1.2"/>')
        els.append(f'<rect x="{lx}" y="{cy}" width="5" height="{row_h - 10}" rx="2" fill="{acc}"/>')
        els.append(text_el(lx + 24, cy + 33, p_name, font=SANS, size=14.5, fill=acc, weight="700", spacing=1.0))
        els.append(text_el(lx + 24, cy + 60, p_ch, font=MONO, size=13.5, fill="#8ea2bd"))
        desc_lines = wrap_para(p_desc, 74)
        if len(desc_lines) == 1:
            els.append(text_el(lx + 298, cy + 49, desc_lines[0], font=SERIF, size=18.2, fill="#eef2f7"))
        else:
            els.append(text_el(lx + 298, cy + 37, desc_lines[0], font=SERIF, size=17.6, fill="#eef2f7"))
            els.append(text_el(lx + 298, cy + 61, desc_lines[1], font=SERIF, size=17.6, fill="#eef2f7"))
        cy += row_h

    # Three Quantitative Pillars Bar
    cy += 18
    col_w = (cw - 36) / 3
    pillars = [
        ("876 PRIMARY SOURCES", "Normative TCG, UEFI, Intel, AMD, IETF, NIST, and [MS-*] protocol specs"),
        ("UNIFORM RIGOR", "Formal invariants, 6-column attack catalogs, and theoretical limits"),
        ("LIVE VERIFICATION", "Non-destructive PowerShell, bcdedit, wevtutil, and registry audits"),
    ]
    for idx, (pt, pb) in enumerate(pillars):
        px = lx + idx * (col_w + 18)
        els.append(f'<rect x="{px:.1f}" y="{cy}" width="{col_w:.1f}" height="106" rx="6" '
                   f'fill="#0a1220" stroke="#2a3c57" stroke-width="1.1"/>')
        els.append(text_el(px + 20, cy + 34, pt, font=SANS, size=14, fill="#d4a843", weight="700", spacing=1.0))
        lines = wrap_para(pb, 38)
        for li, ln in enumerate(lines[:2]):
            els.append(text_el(px + 20, cy + 62 + li * 22, ln, font=SERIF, size=16.5, fill="#b8c5d6"))

    # Bottom Colophon & License Bar
    els.append(f'<line x1="{lx}" y1="1648" x2="{rx}" y2="1648" stroke="#233248" stroke-width="1.2"/>')
    els.append(text_el(lx, 1696, "Parag Mali", font=SERIF, size=30, fill="#f7f4ed", weight="700"))
    els.append(text_el(lx, 1728, "https://maliparag.github.io/windows-trust-chain",
                       font=MONO, size=15.5, fill="#8cb0db"))

    # Right badge box
    bx, by, bw, bh = rx - 418, 1668, 418, 72
    els.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="5" '
               f'fill="#0d1728" stroke="#d4a843" stroke-width="1.1" stroke-opacity="0.55"/>')
    els.append(text_el(bx + bw / 2, by + 30, "OPEN TECHNICAL EDITION  ·  2026",
                       font=SANS, size=13.5, fill="#d4a843", weight="700", anchor="middle", spacing=1.1))
    els.append(text_el(bx + bw / 2, by + 53, "CC BY-NC-SA 4.0  ·  SECURITY & OPERATING SYSTEMS",
                       font=SANS, size=11.8, fill="#9fb0c7", weight="500", anchor="middle", spacing=0.8))

    els.append("</svg>\n")
    return "\n".join(els)


def main():
    front_svg = os.path.join(SRC, "cover.svg")
    front_png = os.path.join(SRC, "cover.png")
    back_svg = os.path.join(SRC, "back-cover.svg")
    back_png = os.path.join(SRC, "back-cover.png")

    with open(front_svg, "w", encoding="utf-8") as f:
        f.write(build_front_cover())
    with open(back_svg, "w", encoding="utf-8") as f:
        f.write(build_back_cover())

    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), front_svg, "-o", front_png], check=True)
    subprocess.run(["rsvg-convert", "-w", str(W), "-h", str(H), back_svg, "-o", back_png], check=True)
    print(f"Generated {front_svg}, {front_png}, {back_svg}, {back_png} ({W}x{H})")


if __name__ == "__main__":
    main()
