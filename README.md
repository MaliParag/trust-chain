# The Windows Trust Chain

How modern Windows builds a verifiable chain of trust from silicon to cloud, and where attackers break it.

> **Preview edition.** Content is actively maintained. Technical corrections and
> reproductions are welcome via
> [issues](https://github.com/MaliParag/windows-trust-chain/issues) and
> [pull requests](CONTRIBUTING.md).

This repository holds the source manuscript for an open, primary-source-grounded
systems security book written for security architects, principal detection
engineers, incident responders, and platform engineers. It traces how trust is
*inherited* link by link, from UEFI firmware and the TPM up through the Hyper-V
Secure Kernel, code integrity, access tokens, Active Directory cryptography,
passkeys, `ETW` telemetry, and cloud attestation, and analyzes the exact seams
where real-world adversaries break each link.

> **Read it online:** <https://maliparag.github.io/windows-trust-chain/>

## What Is Inside

- **20 numbered core chapters** (plus a Prologue and a Foundations
  primer) organized into four architectural parts, an observability interlude,
  and a finale:
  - **Part I · Silicon (Chapters 1 to 5):** Secure Boot, The TPM, Pluton,
    Measured Boot, and Attestation.
  - **Part II · Kernel & Code (Chapters 6 to 9):** The Secure Kernel and VBS,
    Code Integrity and Application Control, Protected Process Light, and Process
    Mitigation Policies.
  - **Part III · Credentials & Access (Chapters 10 to 15):** Windows Access
    Control, Integrity Levels, and Impersonation; Credential Guard and LSASS
    Isolation; The Death of NTLM; Kerberos and Ticket Forgery; Pass-the-Hash to
    Pass-the-PRT; and Windows Hello and Passkeys.
  - **Interlude · Watching the Chain (Chapter 16):** ETW: The EDR Substrate.
  - **Part IV · Cloud (Chapters 17 to 19):** Zero Trust, Continuous Access
    Evaluation, and Confidential VMs.
  - **Finale · When the Chain Snaps (Chapter 20):** When the Chain Snaps:
    Storm-0558.
- **Uniform eight-part chapter progression:** Overview (`Role`,
  `Invariant`, `TCB`, `Failure Modes`, `Handoff`), Core Engineering Problem &
  Threat Model, Architectural Deep Dive, six-column Attack Catalog & Gap
  Analysis, Theoretical Limits & Structural Invariants, live non-destructive
  PowerShell/CLI verification (`Inspecting and Verifying on a Running System`),
  and Summary & Handoff.
- **876 primary-source references** linking every claim to normative vendor
  specifications, RFCs, peer-reviewed security papers, and public incident
  reports.

The web edition is built with [mdBook](https://rust-lang.github.io/mdBook/) and
KaTeX, providing fast full-text search, responsive SVG figures with captions,
and light/dark reading themes.

## Read or Build Locally

You need [mdBook](https://rust-lang.github.io/mdBook/) (`0.4.43+` or `0.5.x`)
and Node.js (`18+`, used by the build-time preprocessor and SEO generator).

```bash
npm install
mdbook serve --open   # live-reload preview at http://localhost:3000
mdbook build          # static site into ./book
```

Production deployments additionally run the post-build SEO pass (canonical URLs,
Open Graph and Twitter cards, `schema.org/Book` JSON-LD, `sitemap.xml`, and
`robots.txt`):

```bash
SITE_URL=https://maliparag.github.io/windows-trust-chain node tools/gen-seo.mjs
node tools/build-pdf.mjs   # writes ./book/the-windows-trust-chain.pdf
```

If you modify chapter titles or reading order, regenerate `src/SUMMARY.md`:

```bash
node tools/gen-summary.mjs
```

## Repository Layout

```text
.
├── src/
│   ├── SUMMARY.md          Table of contents (generated in canonical reading order)
│   ├── front-matter/       Title, copyright, preface, reading guide
│   ├── chapters/           Prologue, Foundations, and 20 numbered core chapters
│   ├── back-matter/        References, glossary, about, colophon, index
│   └── diagrams/           SVG architectural figures referenced by chapters
├── theme/                  Custom CSS and preview banner script
├── tools/
│   ├── gen-summary.mjs       Regenerates src/SUMMARY.md in canonical reading order
│   ├── gen_diagrams.py       Regenerates and collision-checks all 68 SVG diagrams
│   ├── mdbook-trustchain.mjs mdBook preprocessor (KaTeX math, callouts, figures)
│   └── gen-seo.mjs           Post-build SEO metadata, JSON-LD, sitemap, and robots
├── book.toml               mdBook configuration
└── .github/workflows/      Automated build and GitHub Pages deployment
```

## Contributing

Corrections, clarifications, and reproductions are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md). Keep the house style: zero em-dashes, zero
emojis, primary-source `[N]` citations, and verbatim preservation of quoted
standards and advisories.

## License

Everything in this repository (prose, diagrams, and build tooling) is licensed
under
[Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/)
(`CC BY-NC-SA 4.0`). See [LICENSE](LICENSE). Commercial rights are reserved by
the author.

Verbatim quotations from vendors, researchers, and standards bodies, and any
trademarks, remain the property of their respective owners.

## Author

Written by Parag Mali.
