# Colophon

*The Windows Trust Chain* is authored in plain CommonMark Markdown and built from
a single open-source repository without proprietary publishing tools.

**Web Edition.** Built with mdBook alongside a custom Node.js build-time
preprocessor (`tools/mdbook-trustchain.mjs`) that renders display and inline
mathematical notation via KaTeX, structures callouts and figures with visible
captions, and links inline citations directly to 912 verified primary-source
entries in the [References](70-references.md). Post-build metadata, canonical
URLs, structured `schema.org/Book` JSON-LD, and sitemaps are generated via
`tools/gen-seo.mjs`.

**Diagrams, Covers, and PDF Edition.** All 76 architectural diagrams (`tools/gen_diagrams.py`)
and the front and back covers (`tools/gen_covers.py`) are generated from declarative
vector specifications with automated collision and orthogonal-alignment verification.
The print-ready `7 in x 9.25 in` PDF edition (`tools/build-pdf.mjs`) compiles the
complete book with full-bleed vector covers, KaTeX mathematical notation,
native PDF bookmarks, and hyperlinked primary-source citations.

**Editorial Verification.** Every chapter in the twenty-three-chapter book is
validated mechanically against structural progression rules, citation resolution
against `src/back-matter/70-references.md`, diagram integrity, diagnostic code
conciseness, and house typographic standards.

**License.** Copyright © 2026 Parag Mali. Licensed under Creative Commons
Attribution-NonCommercial-ShareAlike 4.0 International
([CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)), with all
commercial rights reserved by the author. See the
[Copyright](../front-matter/01-copyright.md) page for full terms.
