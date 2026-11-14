# Colophon

*The Windows Trust Chain* is authored in plain CommonMark Markdown and built from
a single open-source repository without proprietary publishing tools.

**Web Edition.** Built with mdBook alongside a custom Node.js build-time
preprocessor (`tools/mdbook-trustchain.mjs`) that renders display and inline
mathematical notation via KaTeX, structures callouts and figures with visible
captions, and links inline citations directly to 876 verified primary-source
entries in the [References](70-references.md). Post-build metadata, canonical
URLs, structured `schema.org/Book` JSON-LD, and sitemaps are generated via
`tools/gen-seo.mjs`.

**Diagrams and Typography.** Architectural diagrams are authored as clean,
resolution-independent SVG figures designed to remain legible across light
and dark reading themes. Print and PDF layouts pair Typst and Pandoc
using Source Serif 4 for body prose, Source Sans 3 for headings and
diagrams, and JetBrains Mono for code and terminal inspection blocks.

**Editorial Verification.** Every chapter in the twenty-chapter manuscript is
validated mechanically against structural progression rules, citation resolution
against `src/back-matter/70-references.md`, diagram integrity, diagnostic code
conciseness, and house typographic standards.

**License.** Copyright © 2026 Parag Mali. Licensed under Creative Commons
Attribution-NonCommercial-ShareAlike 4.0 International
([CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)), with all
commercial rights reserved by the author. See the
[Copyright](../front-matter/01-copyright.md) page for full terms.
