#!/usr/bin/env python3
"""Bake read-along into every built chapter page that has timing data.
Runs after `mdbook build`, over book/. Matches pages to timing keys by slug
(name minus number prefix). Intended for the CI deploy step (and local testing).
"""
import os, re, sys, glob, json, subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BOOK = os.path.join(REPO, "book")
TIMING = os.environ.get("TIMING_DIR", os.path.join(REPO, "books", "windows", "reader-timing"))
INJECT = os.path.join(REPO, "tools", "inject_readalong.py")


def slug(name):
    return re.sub(r"^\d+[a-z]?-", "", name)


keys = {}
for f in glob.glob(os.path.join(TIMING, "*.json")):
    k = os.path.basename(f)[:-5]
    keys[slug(k)] = k

from difflib import SequenceMatcher
from inject_readalong import ProseWrapper, norm

done = 0
skipped = 0
for sub in ("front-matter", "chapters", "back-matter"):
    for page in sorted(glob.glob(os.path.join(BOOK, sub, "*.html"))):
        base = os.path.basename(page)[:-5]
        s = slug(base)
        if s in keys:
            timing_path = os.path.join(TIMING, keys[s] + ".json")
            timing = json.load(open(timing_path, encoding="utf-8"))
            raw_html = open(page, encoding="utf-8").read()
            m = re.search(r"<main\b[^>]*>([\s\S]*?)</main>", raw_html)
            if m:
                pw = ProseWrapper()
                pw.feed(m.group(1))
                prose_words = [norm(sp["tok"]) for sp in pw._spans if norm(sp["tok"])]
                narr_words = [norm(w) for w in timing.get("w", []) if norm(w)]
                ratio = SequenceMatcher(a=prose_words, b=narr_words, autojunk=False).ratio() if prose_words and narr_words else 0.0
                if ratio < 0.80:
                    skipped += 1
                    continue
            subprocess.run([sys.executable, INJECT, page, keys[s]], check=True)
            done += 1

print(f"read-along baked into {done} pages (skipped {skipped} pages awaiting fresh audio timing)")
