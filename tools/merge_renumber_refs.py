#!/usr/bin/env python3
"""
Merges batch reference sidecars (books/<slug>/tools/refs_b*.md) into
books/<slug>/src/back-matter/70-references.md, deduplicates identical
entries, prunes uncited orphans, and sequentially renumbers [1..N] across
all Markdown prose files in books/<slug>/src/ without touching code fences,
inline code spans, or Markdown links/images.
"""
import argparse
import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CITE_RE = re.compile(r"(?<![A-Za-z0-9_}`])\[(\d+(?:\s*,\s*\d+)*)\](?!\()")


def parse_ref_lines(path: str) -> dict:
    out = {}
    if not os.path.exists(path):
        return out
    for raw in open(path, encoding="utf-8").read().splitlines():
        m = re.match(r"^\s*(\d+)\.\s+(.+?)\s*$", raw)
        if m:
            out[int(m.group(1))] = m.group(2).strip()
    return out


def transform_prose_Outside_code_and_links(text: str, fn):
    """Apply `fn(segment)` only to prose outside fenced code, inline `code`, and `[...](...)` links/images."""
    # Split fenced code blocks first
    parts = re.split(r"(```[\s\S]*?```)", text)
    out_parts = []
    for idx, part in enumerate(parts):
        if idx % 2 == 1:
            out_parts.append(part)
            continue
        # Within non-fenced text, split inline code spans and markdown links/images
        tokens = re.split(r"(`[^`\n]+`|!\[[^\]]*\]\([^)]*\)|\[[^\]]+\]\([^)]*\))", part)
        new_tokens = []
        for tidx, tok in enumerate(tokens):
            if tidx % 2 == 1:
                new_tokens.append(tok)
            else:
                new_tokens.append(fn(tok))
        out_parts.append("".join(new_tokens))
    return "".join(out_parts)


def ordered_prose_files(book_dir: str) -> list:
    house = json.load(open(os.path.join(book_dir, "house.json"), encoding="utf-8"))
    src_dir = os.path.join(book_dir, "src")
    seen = []
    for rel, _ in house.get("front", []):
        seen.append(os.path.join(src_dir, rel))
    for rel, _ in house.get("specials", []):
        seen.append(os.path.join(src_dir, rel))
    for part in house.get("parts", []):
        for slug in part.get("items", []):
            seen.append(os.path.join(src_dir, "chapters", f"{slug}.md"))
    for rel in house.get("back", []):
        if os.path.basename(rel) not in ("70-references.md", "95-index.md"):
            seen.append(os.path.join(src_dir, rel))
    for p in sorted(glob.glob(os.path.join(src_dir, "**", "*.md"), recursive=True)):
        if os.path.basename(p) not in ("SUMMARY.md", "70-references.md", "95-index.md") and p not in seen:
            seen.append(p)
    return [p for p in seen if os.path.exists(p)]


def dedup_key(entry_body: str) -> str:
    # Normalize whitespace and strip escaped leading \[Name\] wrapper for comparison
    norm = re.sub(r"\s+", " ", entry_body.strip()).lower()
    url_m = re.search(r"<(https?://[^>]+)>", norm)
    title_m = re.search(r"\*([^*]+)\*", norm)
    if url_m and title_m:
        u = url_m.group(1).rstrip("/")
        t = re.sub(r"[^a-z0-9]+", "", title_m.group(1))[:48]
        return f"{u}::{t}"
    return norm


def process_volume(slug: str):
    book_dir = os.path.join(ROOT, "books", slug)
    src_dir = os.path.join(book_dir, "src")
    tools_dir = os.path.join(book_dir, "tools")
    refs_path = os.path.join(src_dir, "back-matter", "70-references.md")

    pool = parse_ref_lines(refs_path)
    sidecars = sorted(glob.glob(os.path.join(tools_dir, "refs_b*.md")))
    for sc in sidecars:
        sc_refs = parse_ref_lines(sc)
        for k, v in sc_refs.items():
            pool[k] = v

    files = ordered_prose_files(book_dir)

    # First pass: collect all cited old IDs in reading order
    cited_order = []
    cited_set = set()
    missing = set()

    for fp in files:
        txt = open(fp, encoding="utf-8").read()

        def scan_seg(seg):
            for m in CITE_RE.finditer(seg):
                for ns in m.group(1).split(","):
                    oid = int(ns.strip())
                    if oid not in pool:
                        missing.add((os.path.basename(fp), oid))
                    elif oid not in cited_set:
                        cited_set.add(oid)
                        cited_order.append(oid)
            return seg

        transform_prose_Outside_code_and_links(txt, scan_seg)

    if missing:
        raise RuntimeError(f"[{slug}] Missing reference definitions in pool: {sorted(missing)[:15]}")

    # Build deduplicated sequential 1..M table in first-citation reading order
    key_to_new_id = {}
    old_to_new = {}
    final_entries = []

    for oid in cited_order:
        body = pool[oid]
        dk = dedup_key(body)
        if dk in key_to_new_id:
            old_to_new[oid] = key_to_new_id[dk]
        else:
            nid = len(final_entries) + 1
            key_to_new_id[dk] = nid
            old_to_new[oid] = nid
            final_entries.append(body)

    # Second pass: rewrite citations in all prose files
    for fp in files:
        txt = open(fp, encoding="utf-8").read()

        def replace_seg(seg):
            def repl(m):
                mapped = []
                for ns in m.group(1).split(","):
                    nid = old_to_new[int(ns.strip())]
                    if nid not in mapped:
                        mapped.append(nid)
                mapped.sort()
                return "[" + ", ".join(str(x) for x in mapped) + "]"

            return CITE_RE.sub(repl, seg)

        new_txt = transform_prose_Outside_code_and_links(txt, replace_seg)
        if new_txt != txt:
            with open(fp, "w", encoding="utf-8") as f:
                f.write(new_txt)

    # Write clean sequential 70-references.md
    out_lines = ["# References", ""]
    for idx, body in enumerate(final_entries, 1):
        out_lines.append(f"{idx}. {body}")
    out_lines.append("")
    with open(refs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    # Remove consumed sidecars
    for sc in sidecars:
        os.remove(sc)

    print(f"[{slug}] Merged & renumbered {len(final_entries)} unique sequential primary references (from {len(pool)} raw entries).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--book", required=True)
    args = ap.parse_args()
    process_volume(args.book)


if __name__ == "__main__":
    main()
