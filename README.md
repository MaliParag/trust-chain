# The Platform Trust Chain Series

How modern operating systems build verifiable chains of trust from silicon reset vectors to cloud control planes, and where attackers break them.

> **Read online:**
> - **Series Overview:** <https://maliparag.github.io/windows-trust-chain/series/>
> - **Volume I · The Windows Trust Chain (Complete · 23 Chapters, 379-Page PDF):** <https://maliparag.github.io/windows-trust-chain/>
> - **Volume II · The Apple Trust Chain (Blueprint & Prologue):** <https://maliparag.github.io/windows-trust-chain/apple/>
> - **Volume III · The Linux Trust Chain (Blueprint & Prologue):** <https://maliparag.github.io/windows-trust-chain/linux/>
> - **Volume IV · The Android Trust Chain (Blueprint & Prologue):** <https://maliparag.github.io/windows-trust-chain/android/>

This monorepo houses an open, primary-source-grounded series of systems security monographs written for security architects, principal detection engineers, incident responders, and platform engineers, sharing one publishing, diagramming, PDF, and editorial verification engine.

## Volumes in This Repository

| Volume | Directory | Status | Scope |
|---|---|---|---|
| **Vol. I · Windows** | [`books/windows/`](books/windows/) | Complete (23 chapters, 76 SVG figures, 912 primary sources, 379-page PDF) | `UEFI Secure Boot`, `TPM 2.0`, `Pluton`, `Measured Boot`, `Attestation`, `Hyper-V VBS/VTL1`, `HVCI`/`WDAC`, `PPL`, `CET`/`CFG`, `Tokens`/`MIC`, `BitLocker`/`DPAPI`/`Recall` enclaves, `Credential Guard`, `NTLM` sunset, `Kerberos`/`krbtgt`, `AD CS`/`dMSA`, `PRT`, `Passkeys`, `ETW`, `Zero Trust`, `CAE`, `Agent Workspace` & `Entra Agent ID`, `Confidential VMs`, and `Storm-0558` |
| **Vol. II · Apple** | [`books/apple/`](books/apple/) | Blueprint & Prologue (20 planned chapters) | Unified Apple Silicon (`A`/`M`/`S`/`R1`) across `iOS`, `iPadOS`, `macOS`, `watchOS`, and `visionOS`: `Boot ROM`, `Image4`/`TSS`, `macOS` `1TR` `LocalPolicy`, `SEP`/`sepOS`, `PAC`/`SPTM`/`Exclaves`/`EMTE`, `SSV`, `AMFI` & `TXM` vs. `Notarization`, `Seatbelt`/`BlastDoor`, `TCC` & `EndpointSecurity`, `APFS` Data Protection, `Stolen Device Protection`, `App Attest`/`MDA`, `iCloud ADP`, `PQ3`, `App Intents`/`MCP` Agentic AI, and `Private Cloud Compute` |
| **Vol. III · Linux** | [`books/linux/`](books/linux/) | Blueprint & Prologue (20 planned chapters) | Composable open-source trust: `UEFI`/`shim`/`SBAT`, `Unified Kernel Images` (`UKI`) & `systemd-pcrlock` (`TPM2`), `LUKS2`, `dm-verity`/`fs-verity`, `IMA`/`IPE` & `Keylime`, `Kernel Lockdown`, `SELinux`/`AppArmor`/`Landlock`, `eBPF` dual edge, `user_namespaces` & `systemd` `run0`, `gVisor`/`Firecracker` AI agent sandboxes, `SPIFFE`/`SPIRE`, `COCONUT-SVSM` & `CoCo`, and `XZ Utils` |
| **Vol. IV · Android** | [`books/android/`](books/android/) | Blueprint & Prologue (20 planned chapters) | Zero-ambient-session mobile isolation: SoC `Boot ROM`, `AVB 2.0` `VBMeta` & rollback indexes, `dm-verity`/`APEX`, `TrustZone` `KeyMint` & `StrongBox` (`Titan M2`), `Protected KVM` (`pKVM` / `AVF`), enforcing `SELinux`, `Arm MTE`, per-app `UID` & `Binder` IPC, `Advanced Protection` & `Intrusion Logging`, `FBE` & `Identity Check`, `RKP` `Key Attestation` vs. `Play Integrity`, `AICore`/`AppFunctions` Agentic AI, and `Private AI Compute` (`TIE`) |

## Build, Audit, and Author Locally

Requires [mdBook](https://rust-lang.github.io/mdBook/) (`0.4.43+`), Node.js (`20+`), Python 3, and `rsvg-convert` (only when regenerating cover PNGs).

```bash
npm install
npm run audit                        # run editorial, citation, & link checks across all volumes
npm run summary                      # regenerate SUMMARY.md for all volumes (or -- --book apple)
npm run build                        # build all 4 volumes + series portal into ./book
npm run pdf -- --book windows        # build 7 x 9.25 in PDF edition with full-bleed vector covers
(cd books/apple && mdbook serve --open) # live-reload preview while authoring a specific volume
```

## Repository Layout

```text
.
├── books/
│   ├── windows/            Volume I: The Windows Trust Chain (23 chapters, diagrams, covers, PDF)
│   ├── apple/              Volume II: The Apple Trust Chain (iOS, macOS, iPadOS, watchOS, visionOS)
│   ├── linux/              Volume III: The Linux Trust Chain
│   └── android/            Volume IV: The Android Trust Chain
├── editorial.md            Portable Book-Craft Playbook (Part I universal + Part II house sheet)
├── theme/                  Shared mdBook CSS, KaTeX head partial, and series volume switcher
├── tools/
│   ├── books.json            Declarative registry of all volumes in the series
│   ├── audit_book.py         Multi-volume editorial, prose-cadence, citation, and link verifier
│   ├── diagram_lib.py        Shared 7-way collision- and alignment-verified SVG diagram engine
│   ├── gen-summary.mjs       Generates src/SUMMARY.md per volume from house.json
│   ├── mdbook-trustchain.mjs Preprocessor (KaTeX math, Overview cards, callouts, figures, [N] links)
│   ├── gen-seo.mjs           Builds secondary volumes, series/index.html, SEO metadata, & table layout
│   ├── gen_series_covers.py  Generates 1400x1850 vector/PNG covers for upcoming volumes
│   └── build-pdf.mjs         Compiles 7 x 9.25 in print/PDF editions via headless Chrome
└── book.toml               Root mdBook entry point (preserves existing CI and Windows root URLs)
```

## Editorial Standard & Contributing

Every volume follows the universal book-craft principles in [`editorial.md`](editorial.md), pairing shared typographic, prose-cadence, citation, and diagram-geometry invariants with a per-volume [`house.json`](books/windows/house.json) so each operating system retains its own natural chapter structure. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-nc-sa/4.0/) (`CC BY-NC-SA 4.0`). See [LICENSE](LICENSE). Commercial rights are reserved by the author.

Written by Parag Mali.
