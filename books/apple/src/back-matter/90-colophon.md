# Colophon

*The Apple Trust Chain* (Volume II of *The Platform Trust Chain Series*) is set in the *Alabaster, Brushed Titanium, and Glacier Blueprint* interior palette (`#f8f9fb` light paper and `#0b1017` dark slate with `#1e5fa8` / `#7cc4f8` blueprint accents), pairing `Charter`, `Iowan Old Style`, and `Source Serif 4` body typography with `Inter` and system sans-serif display headings alongside `SF Mono` / `Menlo` code blocks.

**Production Pipeline.** The text is authored in CommonMark Markdown with `KaTeX` mathematical typesetting (`$...$` and `$$...$$`) and compiled into both a searchable responsive web edition and a `7.00 x 9.25 in` print-ready PDF edition (`the-apple-trust-chain.pdf`) via the shared multi-volume publishing toolchain (`mdBook`, `tools/mdbook-trustchain.mjs`, `tools/gen-summary.mjs`, `tools/build-pdf.mjs`, and `tools/audit_book.py`) governed by the craft principles in `editorial.md`.

**Vector Architecture Diagrams.** All forty-four architectural figures in this volume are generated programmatically in Python via `books/apple/tools/gen_diagrams.py` atop `tools/diagram_lib.py`, enforcing strict orthogonal connector geometry, row-synchronized split domains, masked edge labels, and automated seven-way geometric collision verification on every build.

**License.** Copyright © 2026 Parag Mali. Licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/), with all commercial rights reserved by the author. See [Copyright](../front-matter/01-copyright.md).
