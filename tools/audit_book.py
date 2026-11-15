#!/usr/bin/env python3
"""
Multi-volume book-craft & editorial verifier (paired with editorial.md).
Loads each volume's house configuration from books/<slug>/house.json and
verifies universal + volume-specific editorial, typographic, diagram,
citation, and chapter-link invariants across all volumes in tools/books.json.

Usage:
  python3 tools/audit_book.py                  # audits all volumes
  python3 tools/audit_book.py --book windows   # audits one volume
"""
import argparse
import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
    assert nums == list(range(1, len(nums) + 1)), f"Non-sequential references in {refs_path}"
    return set(nums)


def audit_file(path: str, src_dir: str, cfg: dict, valid_refs: set, is_core_chapter: bool) -> list:
    errors = []
    base = os.path.basename(path)
    text = open(path, encoding="utf-8").read()

    bad_ctrl = {ord(c) for c in text if ord(c) < 9 or (13 < ord(c) < 32)}
    if bad_ctrl:
        errors.append(f"Control bytes present: {bad_ctrl}")
    if cfg.get("forbid_em_dash", True) and "\u2014" in text:
        lns = [i + 1 for i, l in enumerate(text.splitlines()) if "\u2014" in l]
        errors.append(f"Forbidden em-dash on lines {lns}")
    if cfg.get("forbid_emojis", True):
        emj = re.findall(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", text)
        if emj:
            errors.append(f"Forbidden emojis present: {set(emj)}")

    no_fences = re.sub(r"```[\s\S]*?```", lambda m: "\n" * m.group(0).count("\n"), text)
    prose_only = re.sub(r"`[^`\n]+`", "CODE", no_fences)

    for idx, line in enumerate(prose_only.splitlines(), 1):
        if "->" in line and not line.lstrip().startswith("|"):
            errors.append(f"Raw ASCII '->' in prose on L{idx}")
    for pat in UNIVERSAL_BANNED_META:
        for m in re.finditer(pat, prose_only, flags=re.I):
            ln = prose_only[:m.start()].count("\n") + 1
            errors.append(f"Banned meta/leak pattern '{pat}' on L{ln}")

    list_exempt = set(cfg.get("list_exempt_pages", []))
    allow_lead_bold = set(cfg.get("allow_lead_bold_pages", []))

    if base not in list_exempt:
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
            if base in allow_lead_bold and re.match(r"^\*\*[^*\n]+\*\*", line_nc) and len(b_matches) == 1:
                continue
            errors.append(f"Inline prose bolding on L{idx}: {b_matches[0].group(0)}")

    if cfg.get("forbid_body_lists", True) and base not in list_exempt:
        ov_hdr = cfg.get("overview_heading", "Overview")
        body_wo_ov = re.sub(rf"^## {re.escape(ov_hdr)}\s*\n[\s\S]*?(?=^## )", "", no_fences, flags=re.M) if is_core_chapter else no_fences
        bad_lists = [idx + 1 for idx, l in enumerate(body_wo_ov.splitlines()) if re.match(r"^\s*(?:[-*]|\d+\.)\s+", l)]
        if bad_lists:
            errors.append(f"Body list items found ({len(bad_lists)} items, first at L{bad_lists[0]})")

    if is_core_chapter:
        h1s = re.findall(r"^#\s+(.+)$", no_fences, flags=re.M)
        if len(h1s) != 1:
            errors.append(f"Expected 1 H1, found {len(h1s)}")
        req_h2 = cfg.get("required_h2")
        if req_h2:
            h2s = re.findall(r"^##\s+(.+)$", no_fences, flags=re.M)
            if h2s != req_h2:
                errors.append(f"H2 mismatch: got {h2s}")
        ov_hdr = cfg.get("overview_heading")
        if ov_hdr and cfg.get("overview_keys"):
            ov_m = re.search(rf"^## {re.escape(ov_hdr)}\s*\n([\s\S]*?)(?=^## )", text, flags=re.M)
            if ov_m:
                for k in cfg["overview_keys"]:
                    if k not in ov_m.group(1):
                        errors.append(f"Missing Overview coordinate: {k}")
        req_tbl = cfg.get("required_table_header")
        if req_tbl and req_tbl not in text:
            errors.append("Missing required summary table header")
        diag_h2 = cfg.get("diagnostics_h2")
        max_cmd = cfg.get("max_cmd_lines", 4)
        if diag_h2 and f"## {diag_h2}" in text:
            after = text.split(f"## {diag_h2}", 1)[1]
            for m in re.finditer(r"```(?:powershell|cmd|batch|bash|sh)\n([\s\S]*?)```", after, flags=re.I):
                cmds = [l for l in m.group(1).strip().splitlines() if l.strip() and not l.strip().startswith("#")]
                if len(cmds) > max_cmd:
                    errors.append(f"Diagnostic block exceeds {max_cmd} lines ({len(cmds)})")

    diag_dir = os.path.join(src_dir, "diagrams")
    pref = cfg.get("require_figure_prefix", "Figure: ")
    for idx, raw_l in enumerate(no_fences.splitlines(), 1):
        if raw_l.lstrip().startswith("!["):
            if pref and not raw_l.lstrip().startswith(f"![{pref}"):
                errors.append(f"Figure caption missing '{pref}' prefix on L{idx}")
        elif "diagrams/" in raw_l:
            errors.append(f"Leaked 'diagrams/' path in prose on L{idx}")
    for svg in re.findall(r"\]\(diagrams/([^)]+)\)", text):
        if not os.path.exists(os.path.join(diag_dir, svg)):
            errors.append(f"Missing diagram file {os.path.join(diag_dir, svg)}")

    cite_scan = re.sub(r"!\[.+?\]\([^)]*\)|\[[^\]]+\]\([^)]*\)", "", prose_only)
    for m in re.finditer(r"(?<![A-Za-z0-9_}`])\[(\d+(?:\s*,\s*\d+)*)\](?!\()", cite_scan):
        for ns in m.group(1).split(","):
            if int(ns.strip()) not in valid_refs:
                errors.append(f"Unresolved citation [{ns.strip()}]")

    return errors


def verify_chapter_number_links(src_dir: str) -> list:
    summary_path = os.path.join(src_dir, "SUMMARY.md")
    if not os.path.exists(summary_path):
        return []
    numbered = re.findall(r"^- \[.+?\]\(chapters/([^)]+\.md)\)", open(summary_path, encoding="utf-8").read(), flags=re.M)
    slug_to_num = {s: i + 1 for i, s in enumerate(numbered)}
    errs = []
    for p in sorted(glob.glob(os.path.join(src_dir, "**", "*.md"), recursive=True)):
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


def audit_volume(vol: dict) -> bool:
    book_dir = os.path.join(ROOT, vol["dir"])
    house_path = os.path.join(book_dir, "house.json")
    if not os.path.exists(house_path):
        return True
    house = json.load(open(house_path, encoding="utf-8"))
    cfg = house.get("audit", {})
    src_dir = os.path.join(book_dir, "src")
    refs_path = os.path.join(src_dir, "back-matter", "70-references.md")
    valid_refs = load_valid_refs(refs_path)
    specials = set(cfg.get("special_unnumbered_chapters", []))

    md_files = [
        p for p in sorted(glob.glob(os.path.join(src_dir, "**", "*.md"), recursive=True))
        if os.path.basename(p) not in ("SUMMARY.md", "70-references.md", "95-index.md")
    ]
    failed = 0
    for p in md_files:
        base = os.path.basename(p)
        is_core = ("/chapters/" in p.replace("\\", "/")) and base not in specials
        errs = audit_file(p, src_dir, cfg, valid_refs, is_core)
        if errs:
            failed += 1
            print(f"FAIL [{vol['slug']}] {os.path.relpath(p, ROOT)}:")
            for e in errs:
                print(f"  - {e}")
    for le in verify_chapter_number_links(src_dir):
        failed += 1
        print(f"FAIL [{vol['slug']}] link parity: {le}")
    if not failed:
        print(f"PASS [{vol['slug']}]: {len(md_files)} prose files, {len(valid_refs)} sequential refs, 100% link parity.")
    return failed == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--book", help="Specific volume slug (windows, apple, linux, android)")
    args = ap.parse_args()

    reg = json.load(open(os.path.join(ROOT, "tools", "books.json"), encoding="utf-8"))
    vols = [v for v in reg["volumes"] if not args.book or v["slug"] == args.book]
    if not vols:
        raise SystemExit(f"Unknown book slug: {args.book}")

    ok = True
    for v in vols:
        if not audit_volume(v):
            ok = False
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
