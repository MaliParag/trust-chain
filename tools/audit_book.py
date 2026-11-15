#!/usr/bin/env python3
"""
Automated book-craft & editorial verifier (paired with editorial.md).
Part 1 enforces universal book-craft invariants; HOUSE_CONFIG isolates
book-specific section headings, components, and house rules so this script
can be reused across different books by updating HOUSE_CONFIG alone.
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- Book-Specific House Sheet Configuration ---
HOUSE_CONFIG = {
    "required_h2": [
        "Overview",
        "Core Engineering Problem & Threat Model",
        "Architectural Deep Dive",
        "Attack Catalog & Gap Analysis",
        "Theoretical Limits & Structural Invariants",
        "Inspecting and Verifying on a Running System",
        "Summary & Handoff",
    ],
    "overview_heading": "Overview",
    "overview_keys": [
        "**Role in the Chain:**",
        "**Core Security Invariant:**",
        "**Trusted Computing Base (TCB):**",
        "**Primary Failure Modes:**",
        "**Handoff:**",
    ],
    "required_table_header": "| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |",
    "diagnostics_h2": "Inspecting and Verifying on a Running System",
    "max_cmd_lines": 4,
    "forbid_em_dash": True,
    "forbid_emojis": True,
    "forbid_body_lists": True,
    "require_figure_prefix": "Figure: ",
    "special_unnumbered_chapters": {"00-prologue.md", "00b-foundations.md"},
    "allow_lead_bold_pages": {"00-title.md", "80-glossary.md", "90-colophon.md"},
    "list_exempt_pages": {"70-references.md", "95-index.md", "README.md", "CONTRIBUTING.md", "SUMMARY.md", "editorial.md"},
}

UNIVERSAL_BANNED_META = [
    r"most engineers skip",
    r"mechanism-densest",
    r"we have walked the chain",
    r"this is the part you do today",
    r"open an elevated powershell",
    r"execute .* in an elevated powershell",
    r"aha #",
    r":::\s*trust-ledger",
    r"<!--\s*evidence",
    r"\]\.:\s*",
    r"\bChapter 0\d\b",
    r"\bLaw\s+\d+\b",
    r"\bmanuscript\b",
]


def load_valid_refs(refs_path: str) -> set:
    if not os.path.exists(refs_path):
        return set()
    text = open(refs_path, encoding="utf-8").read()
    nums = [int(m) for m in re.findall(r"^(\d+)\.\s+", text, flags=re.M)]
    assert nums == list(range(1, len(nums) + 1)), "References in 70-references.md are not sequential 1..N!"
    return set(nums)


def audit_file(path: str, valid_refs: set, is_core_chapter: bool) -> list:
    errors = []
    base = os.path.basename(path)
    text = open(path, encoding="utf-8").read()

    # 1. Control bytes, em-dashes, emojis
    bad_ctrl = {ord(c) for c in text if ord(c) < 9 or (13 < ord(c) < 32)}
    if bad_ctrl:
        errors.append(f"Control bytes present: {bad_ctrl}")
    if HOUSE_CONFIG["forbid_em_dash"] and "\u2014" in text:
        lns = [i + 1 for i, l in enumerate(text.splitlines()) if "\u2014" in l]
        errors.append(f"Forbidden em-dash on lines {lns}")
    if HOUSE_CONFIG["forbid_emojis"]:
        emj = re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", text)
        if emj:
            errors.append(f"Forbidden emojis present: {set(emj)}")

    no_fences = re.sub(r"```[\s\S]*?```", lambda m: "\n" * m.group(0).count("\n"), text)
    prose_only = re.sub(r"`[^`\n]+`", "CODE", no_fences)

    # 2. Raw ASCII arrows & banned meta-commentary / leaks
    for idx, line in enumerate(prose_only.splitlines(), 1):
        if "->" in line and not line.lstrip().startswith("|"):
            errors.append(f"Raw ASCII '->' in prose on L{idx}")
    for pat in UNIVERSAL_BANNED_META:
        for m in re.finditer(pat, prose_only, flags=re.I):
            ln = prose_only[:m.start()].count("\n") + 1
            errors.append(f"Banned meta/leak pattern '{pat}' on L{ln}")

    # 3. Typographic restraint (no inline prose or table-cell bolding)
    if base not in HOUSE_CONFIG["list_exempt_pages"]:
        in_bq = False
        for idx, raw_line in enumerate(no_fences.splitlines(), 1):
            s = raw_line.lstrip()
            line_nc = re.sub(r"`[^`\n]+`", "CODE", s)
            b_matches = list(re.finditer(r"\*\*[^*\n]+\*\*", line_nc))
            if not b_matches:
                if not s.startswith(">"):
                    in_bq = False
                continue
            if s.startswith("|"):
                errors.append(f"Table-cell bolding on L{idx}: {b_matches[0].group(0)}")
                continue
            if s.startswith(">"):
                if not in_bq:
                    in_bq = True
                    if len(b_matches) > 1 or not re.match(r"^>\s*\*\*[^*\n]+\*\*", line_nc):
                        errors.append(f"Inline bolding in callout on L{idx}")
                else:
                    errors.append(f"Inline bolding in callout body on L{idx}")
                continue
            in_bq = False
            if re.match(r"^(?:[-*]|\d+\.)\s+\*\*[^*\n]+\*\*", line_nc) and len(b_matches) == 1:
                continue
            if base in HOUSE_CONFIG["allow_lead_bold_pages"] and re.match(r"^\*\*[^*\n]+\*\*", line_nc) and len(b_matches) == 1:
                continue
            errors.append(f"Inline prose bolding on L{idx}: {b_matches[0].group(0)}")

    # 4. Prose-first book cadence (no body bullet/numbered lists when forbid_body_lists=True)
    if HOUSE_CONFIG["forbid_body_lists"] and base not in HOUSE_CONFIG["list_exempt_pages"]:
        ov_hdr = HOUSE_CONFIG["overview_heading"]
        body_wo_ov = re.sub(rf"^## {re.escape(ov_hdr)}\s*\n[\s\S]*?(?=^## )", "", no_fences, flags=re.M) if is_core_chapter else no_fences
        bad_lists = [idx + 1 for idx, l in enumerate(body_wo_ov.splitlines()) if re.match(r"^\s*(?:[-*]|\d+\.)\s+", l)]
        if bad_lists:
            errors.append(f"Body list items found ({len(bad_lists)} items, first at L{bad_lists[0]})")

    # 5. Core chapter structural progression
    if is_core_chapter:
        h1s = re.findall(r"^#\s+(.+)$", no_fences, flags=re.M)
        if len(h1s) != 1:
            errors.append(f"Expected 1 H1, found {len(h1s)}")
        if HOUSE_CONFIG["required_h2"]:
            h2s = re.findall(r"^##\s+(.+)$", no_fences, flags=re.M)
            if h2s != HOUSE_CONFIG["required_h2"]:
                errors.append(f"H2 mismatch: got {h2s}")
        ov_m = re.search(rf"^## {re.escape(HOUSE_CONFIG['overview_heading'])}\s*\n([\s\S]*?)(?=^## )", text, flags=re.M)
        if ov_m:
            for k in HOUSE_CONFIG["overview_keys"]:
                if k not in ov_m.group(1):
                    errors.append(f"Missing Overview coordinate: {k}")
        if HOUSE_CONFIG["required_table_header"] and HOUSE_CONFIG["required_table_header"] not in text:
            errors.append("Missing required summary table header")
        diag_h2 = HOUSE_CONFIG["diagnostics_h2"]
        if diag_h2 and f"## {diag_h2}" in text:
            after = text.split(f"## {diag_h2}", 1)[1]
            for m in re.finditer(r"```(?:powershell|cmd|batch|bash|sh)\n([\s\S]*?)```", after, flags=re.I):
                cmds = [l for l in m.group(1).strip().splitlines() if l.strip() and not l.strip().startswith("#")]
                if len(cmds) > HOUSE_CONFIG["max_cmd_lines"]:
                    errors.append(f"Diagnostic block exceeds {HOUSE_CONFIG['max_cmd_lines']} lines ({len(cmds)})")

    # 6. Diagrams & zero leaked diagrams/ paths
    diag_dir = os.path.join(ROOT, "src", "diagrams")
    pref = HOUSE_CONFIG["require_figure_prefix"]
    for idx, raw_l in enumerate(no_fences.splitlines(), 1):
        if raw_l.lstrip().startswith("!["):
            if pref and not raw_l.lstrip().startswith(f"![{pref}"):
                errors.append(f"Figure caption missing '{pref}' prefix on L{idx}")
        elif "diagrams/" in raw_l:
            errors.append(f"Leaked 'diagrams/' path in prose on L{idx}")
    for svg in re.findall(r"\]\(diagrams/([^)]+)\)", text):
        if not os.path.exists(os.path.join(diag_dir, svg)):
            errors.append(f"Missing diagram file src/diagrams/{svg}")

    # 7. Citations resolve in 70-references.md
    if valid_refs:
        cite_scan = re.sub(r"!\[.+?\]\([^)]*\)|\[[^\]]+\]\([^)]*\)", "", prose_only)
        for m in re.finditer(r"(?<![A-Za-z0-9_}`])\[(\d+(?:\s*,\s*\d+)*)\](?!\()", cite_scan):
            for ns in m.group(1).split(","):
                if int(ns.strip()) not in valid_refs:
                    errors.append(f"Unresolved citation [{ns.strip()}]")

    return errors


def verify_chapter_number_links():
    summary_path = os.path.join(ROOT, "src", "SUMMARY.md")
    if not os.path.exists(summary_path):
        return []
    numbered = re.findall(r"^- \[.+?\]\(chapters/([^)]+\.md)\)", open(summary_path, encoding="utf-8").read(), flags=re.M)
    slug_to_num = {s: i + 1 for i, s in enumerate(numbered)}
    errs = []
    for p in sorted(glob.glob(os.path.join(ROOT, "src", "**", "*.md"), recursive=True)):
        t = open(p, encoding="utf-8").read()
        for m in re.finditer(r"\[([^\]]*?(?:Chapter|Ch\.)\s*(\d+)[^\]]*)\]\((?:(?:\.\./)?chapters/)?([0-9a-zA-Z_-]+\.md)\)", t):
            num, slug = int(m.group(2)), m.group(3)
            if slug in slug_to_num and slug_to_num[slug] != num:
                errs.append(f"{os.path.relpath(p, ROOT)}: '{m.group(0)}' points to Ch. {slug_to_num[slug]}")
        for m in re.finditer(r"\[([^\]]+)\]\((?:(?:\.\./)?chapters/)?([0-9a-zA-Z_-]+\.md)\)\s*\(Chapter\s+(\d+)\)", t):
            slug, num = m.group(2), int(m.group(3))
            if slug in slug_to_num and slug_to_num[slug] != num:
                errs.append(f"{os.path.relpath(p, ROOT)}: '{m.group(0)}' points to Ch. {slug_to_num[slug]}")
    return errs


def main():
    refs_path = os.path.join(ROOT, "src", "back-matter", "70-references.md")
    valid_refs = load_valid_refs(refs_path)
    targets = sys.argv[1:] or [
        p for p in sorted(glob.glob(os.path.join(ROOT, "src", "**", "*.md"), recursive=True))
        if os.path.basename(p) not in ("SUMMARY.md", "70-references.md", "95-index.md")
    ]
    failed = 0
    for p in targets:
        base = os.path.basename(p)
        is_core = ("/chapters/" in p.replace("\\", "/") or p.startswith("src/chapters/")) and base not in HOUSE_CONFIG["special_unnumbered_chapters"]
        errs = audit_file(p, valid_refs, is_core)
        if errs:
            failed += 1
            print(f"FAIL {os.path.relpath(p, ROOT)}:")
            for e in errs:
                print(f"  - {e}")
    link_errs = verify_chapter_number_links()
    for le in link_errs:
        failed += 1
        print(f"FAIL link parity: {le}")
    if failed:
        sys.exit(1)
    print(f"PASS: Verified {len(targets)} prose files, {len(valid_refs)} sequential references, and 100% chapter-link parity.")


if __name__ == "__main__":
    main()
