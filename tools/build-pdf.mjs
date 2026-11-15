#!/usr/bin/env node
/**
 * Builds the publication-grade PDF edition of "The Windows Trust Chain"
 * (7.00 in x 9.25 in technical monograph trim) from ./book/print.html,
 * complete with full-bleed vector Front Cover (src/cover.svg), hyperlinked
 * Contents, Part/Chapter rubrics, KaTeX math, 68 vector SVG diagrams,
 * native PDF bookmark outline, and full-bleed vector Back Cover (src/back-cover.svg).
 *
 * Usage: node tools/build-pdf.mjs [output-pdf-path]
 */
import http from 'node:http';
import { spawn, execSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, statSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BOOK_DIR = path.join(ROOT, 'book');
const SRC_DIR = path.join(ROOT, 'src');
const KATEX_DIR = path.join(ROOT, 'node_modules', 'katex', 'dist');
const OUT_PDF = path.resolve(ROOT, process.argv[2] || path.join('book', 'the-windows-trust-chain.pdf'));

function findChrome() {
  if (process.env.CHROME_BIN && existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }
  const macCandidates = [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  ];
  for (const c of macCandidates) {
    if (existsSync(c)) return c;
  }
  for (const bin of ['google-chrome', 'google-chrome-stable', 'chromium-browser', 'chromium']) {
    try {
      const p = execSync(`which ${bin}`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
      if (p) return p;
    } catch {}
  }
  throw new Error('Could not locate Google Chrome or Chromium. Set CHROME_BIN.');
}

const CHAPTER_RUBRICS = new Map([
  ['the-windows-trust-chain', 'Title Page'],
  ['copyright', 'Front Matter'],
  ['preface', 'Front Matter'],
  ['how-to-read-this-book', 'Front Matter'],
  ['prologue', 'Opening  ·  Prologue'],
  ['foundations', 'Opening  ·  Foundations'],
  ['secure-boot', 'Part I · Silicon  ·  Chapter 1'],
  ['the-tpm', 'Part I · Silicon  ·  Chapter 2'],
  ['pluton', 'Part I · Silicon  ·  Chapter 3'],
  ['measured-boot', 'Part I · Silicon  ·  Chapter 4'],
  ['attestation', 'Part I · Silicon  ·  Chapter 5'],
  ['the-secure-kernel-and-vbs', 'Part II · Kernel & Code  ·  Chapter 6'],
  ['code-integrity-and-application-control', 'Part II · Kernel & Code  ·  Chapter 7'],
  ['protected-process-light', 'Part II · Kernel & Code  ·  Chapter 8'],
  ['process-mitigation-policies', 'Part II · Kernel & Code  ·  Chapter 9'],
  ['windows-access-control-integrity-levels-and-impersonation', 'Part III · Credentials & Access  ·  Chapter 10'],
  ['data-protection-and-local-secret-custody', 'Part III · Credentials & Access  ·  Chapter 11'],
  ['credential-guard-and-lsass-isolation', 'Part III · Credentials & Access  ·  Chapter 12'],
  ['the-death-of-ntlm', 'Part III · Credentials & Access  ·  Chapter 13'],
  ['kerberos-and-ticket-forgery', 'Part III · Credentials & Access  ·  Chapter 14'],
  ['enterprise-pki-service-identities-and-hybrid-bridges', 'Part III · Credentials & Access  ·  Chapter 15'],
  ['pass-the-hash-to-pass-the-prt', 'Part III · Credentials & Access  ·  Chapter 16'],
  ['windows-hello-and-passkeys', 'Part III · Credentials & Access  ·  Chapter 17'],
  ['etw-the-edr-substrate', 'Interlude · Watching the Chain  ·  Chapter 18'],
  ['zero-trust', 'Part IV · Cloud  ·  Chapter 19'],
  ['continuous-access-evaluation', 'Part IV · Cloud  ·  Chapter 20'],
  ['workload-and-ai-agent-security', 'Part IV · Cloud  ·  Chapter 21'],
  ['confidential-vms', 'Part IV · Cloud  ·  Chapter 22'],
  ['when-the-chain-snaps-storm-0558', 'Finale · When the Chain Snaps  ·  Chapter 23'],
  ['references', 'Back Matter  ·  Primary Sources'],
  ['glossary', 'Back Matter  ·  Glossary'],
  ['about-this-book', 'Back Matter  ·  About'],
  ['colophon', 'Back Matter  ·  Colophon'],
  ['index', 'Back Matter  ·  Index'],
]);

const TOC_GROUPS = [
  {
    heading: 'Front Matter & Opening',
    items: [
      ['Preface', 'preface'],
      ['How to Read This Book', 'how-to-read-this-book'],
      ['Prologue', 'prologue'],
      ['Foundations', 'foundations'],
    ],
  },
  {
    heading: 'Part I · Silicon',
    items: [
      ['1. Secure Boot', 'secure-boot'],
      ['2. The TPM', 'the-tpm'],
      ['3. Pluton', 'pluton'],
      ['4. Measured Boot', 'measured-boot'],
      ['5. Attestation', 'attestation'],
    ],
  },
  {
    heading: 'Part II · Kernel & Code',
    items: [
      ['6. The Secure Kernel and VBS', 'the-secure-kernel-and-vbs'],
      ['7. Code Integrity and Application Control', 'code-integrity-and-application-control'],
      ['8. Protected Process Light', 'protected-process-light'],
      ['9. Process Mitigation Policies', 'process-mitigation-policies'],
    ],
  },
  {
    heading: 'Part III · Credentials & Access',
    items: [
      ['10. Windows Access Control, Integrity Levels, and Impersonation', 'windows-access-control-integrity-levels-and-impersonation'],
      ['11. Data Protection and Local Secret Custody', 'data-protection-and-local-secret-custody'],
      ['12. Credential Guard and LSASS Isolation', 'credential-guard-and-lsass-isolation'],
      ['13. The Death of NTLM', 'the-death-of-ntlm'],
      ['14. Kerberos and Ticket Forgery', 'kerberos-and-ticket-forgery'],
      ['15. Enterprise PKI, Service Identities, and Hybrid Bridges', 'enterprise-pki-service-identities-and-hybrid-bridges'],
      ['16. Pass-the-Hash to Pass-the-PRT', 'pass-the-hash-to-pass-the-prt'],
      ['17. Windows Hello and Passkeys', 'windows-hello-and-passkeys'],
    ],
  },
  {
    heading: 'Interlude · Watching the Chain',
    items: [
      ['18. ETW: The EDR Substrate', 'etw-the-edr-substrate'],
    ],
  },
  {
    heading: 'Part IV · Cloud & Finale',
    items: [
      ['19. Zero Trust', 'zero-trust'],
      ['20. Continuous Access Evaluation', 'continuous-access-evaluation'],
      ['21. Workload and AI Agent Security', 'workload-and-ai-agent-security'],
      ['22. Confidential VMs', 'confidential-vms'],
      ['23. When the Chain Snaps: Storm-0558', 'when-the-chain-snaps-storm-0558'],
    ],
  },
  {
    heading: 'Back Matter',
    items: [
      ['References (912 Primary Sources)', 'references'],
      ['Glossary', 'glossary'],
      ['About This Book', 'about-this-book'],
      ['Colophon', 'colophon'],
      ['Index', 'index'],
    ],
  },
];

function buildTocHtml() {
  const sections = TOC_GROUPS.map((g) => {
    const lis = g.items
      .map(([label, id]) => `<li><a href="#${id}">${label}</a></li>`)
      .join('\n');
    return `<div class="pdf-toc-group"><h3>${g.heading}</h3><ul>${lis}</ul></div>`;
  }).join('\n');
  return `
<div style="break-before: page; page-break-before: always;"></div>
<section class="pdf-toc">
  <div class="pdf-ch-rubric">Contents</div>
  <h1 id="contents">Table of Contents</h1>
  <div class="pdf-toc-columns">
    ${sections}
  </div>
</section>`;
}

function namespaceSvgIds(svgRaw, prefix) {
  return svgRaw
    .replace(/\swidth="1400"\s+height="1850"/, ' width="100%" height="100%" preserveAspectRatio="none"')
    .replace(/\bid="([A-Za-z0-9_-]+)"/g, `id="${prefix}_$1"`)
    .replace(/url\(#([A-Za-z0-9_-]+)\)/g, `url(#${prefix}_$1)`);
}

function buildPdfHtml() {
  const printPath = path.join(BOOK_DIR, 'print.html');
  if (!existsSync(printPath)) {
    throw new Error('book/print.html not found. Run `mdbook build` first.');
  }
  const rawHtml = readFileSync(printPath, 'utf8');
  const mainMatch = rawHtml.match(/<main>([\s\S]*?)<\/main>/i);
  if (!mainMatch) {
    throw new Error('Could not extract <main> from book/print.html');
  }
  let bodyContent = mainMatch[1];

  // Strip any interactive audio read-along bars and web-only PDF self-download link
  bodyContent = bodyContent.replace(/<div class="ra-bar"[\s\S]*?<\/div>\s*<\/div>/g, '');
  bodyContent = bodyContent.replace(/,\s*or download the <a href="[^"]*the-windows-trust-chain\.pdf">PDF Edition<\/a>/g, '');

  // Prepend Part/Chapter rubrics above every top-level <h1 id="...">
  bodyContent = bodyContent.replace(/<h1 id="([^"]+)">/g, (full, id) => {
    const rubric = CHAPTER_RUBRICS.get(id);
    if (!rubric || id === 'the-windows-trust-chain') return full;
    return `<div class="pdf-ch-rubric">${rubric}</div>\n${full}`;
  });

  // Insert hyperlinked Table of Contents right before Preface
  bodyContent = bodyContent.replace(
    /<div style="break-before: page; page-break-before: always;"><\/div>\s*<div class="pdf-ch-rubric">Front Matter<\/div>\s*<h1 id="preface">/,
    `${buildTocHtml()}\n<div style="break-before: page; page-break-before: always;"></div>\n<div class="pdf-ch-rubric">Front Matter</div>\n<h1 id="preface">`
  );

  const trustchainCss = readFileSync(path.join(ROOT, 'theme', 'trustchain.css'), 'utf8');
  const frontSvg = namespaceSvgIds(readFileSync(path.join(SRC_DIR, 'cover.svg'), 'utf8'), 'fc');
  const backSvg = namespaceSvgIds(readFileSync(path.join(SRC_DIR, 'back-cover.svg'), 'utf8'), 'bc');

  return `<!DOCTYPE html>
<html lang="en" class="light">
<head>
  <meta charset="utf-8">
  <title>The Windows Trust Chain - Parag Mali</title>
  <link rel="stylesheet" href="/_katex/katex.min.css">
  <style>
${trustchainCss}

/* === Publication Monograph Print Stylesheet (7.00 in x 9.25 in) === */
@page {
  size: 7in 9.25in;
  margin: 0.68in 0.62in 0.72in 0.62in;
  @top-left {
    content: "THE WINDOWS TRUST CHAIN";
    font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
    font-size: 7.0pt;
    letter-spacing: 0.08em;
    color: #64748b;
  }
  @top-right {
    content: "PARAG MALI";
    font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
    font-size: 7.0pt;
    letter-spacing: 0.08em;
    color: #64748b;
  }
  @bottom-center {
    content: counter(page);
    font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
    font-size: 7.6pt;
    color: #64748b;
  }
}
@page frontcover {
  size: 7in 9.25in;
  margin: 0;
  @top-left { content: none; }
  @top-right { content: none; }
  @bottom-center { content: none; }
}
@page backcover {
  size: 7in 9.25in;
  margin: 0;
  @top-left { content: none; }
  @top-right { content: none; }
  @bottom-center { content: none; }
}

* { box-sizing: border-box; -webkit-print-color-adjust: exact; print-color-adjust: exact; }

html, body {
  margin: 0;
  padding: 0;
  background: #ffffff;
  color: #191919;
  font-family: Georgia, "Times New Roman", serif;
  font-size: 9.7pt;
  line-height: 1.48;
  orphans: 3;
  widows: 3;
}

/* Full-bleed Front & Back Cover pages */
.pdf-front-cover {
  page: frontcover;
  width: 100%;
  height: 100vh;
  margin: 0;
  padding: 0;
  overflow: hidden;
  break-after: page;
  page-break-after: always;
}
.pdf-back-cover {
  page: backcover;
  width: 100%;
  height: 100vh;
  margin: 0;
  padding: 0;
  overflow: hidden;
  break-before: page;
  page-break-before: always;
}
.pdf-front-cover svg,
.pdf-back-cover svg {
  display: block;
  width: 100%;
  height: 100%;
}

/* Interior Monograph Body */
.pdf-interior {
  width: 100%;
}

.pdf-ch-rubric {
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 8.0pt;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #2b547e;
  margin: 0 0 4pt 0;
  padding-bottom: 3pt;
  border-bottom: 0.75pt solid #cbd5e1;
  break-after: avoid;
}

h1, h2, h3, h4 {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  color: #0f172a;
  line-height: 1.24;
  break-after: avoid;
  page-break-after: avoid;
}
h1 {
  font-size: 20pt;
  font-weight: 800;
  margin: 2pt 0 12pt 0;
  letter-spacing: -0.01em;
}
h2 {
  font-size: 13pt;
  font-weight: 700;
  margin: 16pt 0 6pt 0;
  padding-bottom: 2.5pt;
  border-bottom: 0.5pt solid #e2e8f0;
}
h3 {
  font-size: 10.6pt;
  font-weight: 700;
  margin: 12pt 0 4pt 0;
  color: #1e293b;
}
h4 {
  font-size: 9.8pt;
  font-weight: 700;
  margin: 9pt 0 3pt 0;
}
h1 a.header, h2 a.header, h3 a.header, h4 a.header {
  color: inherit;
  text-decoration: none;
}

p { margin: 0 0 7.5pt 0; text-align: left; }
ul, ol { margin: 0 0 8pt 0; padding-left: 16pt; }
li { margin: 2.2pt 0; }

a {
  color: #1d4f82;
  text-decoration: none;
}
a.cite-ref {
  color: #2b547e;
  font-size: 0.92em;
}

hr {
  border: 0;
  border-top: 0.6pt solid #cbd5e1;
  margin: 12pt 0;
}

/* Inline & Block Code */
code {
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 8.3pt;
  background: #f3f5f8;
  padding: 0.8pt 3pt;
  border-radius: 2.5pt;
  color: #1e293b;
  overflow-wrap: break-word;
}
pre {
  margin: 7pt 0 10pt 0;
  padding: 7pt 9pt;
  background: #f6f8fa;
  border: 0.6pt solid #d8dee4;
  border-radius: 4pt;
  white-space: pre-wrap !important;
  overflow-wrap: anywhere !important;
  word-break: break-word;
  line-height: 1.36;
  break-inside: avoid;
}
pre code {
  background: transparent;
  padding: 0;
  font-size: 7.8pt;
  color: #0f172a;
}
pre .buttons { display: none !important; }

/* Tables: wrap all columns cleanly inside 5.76in text block! */
.pdf-interior table,
.content table {
  display: table !important;
  width: 100% !important;
  max-width: 100% !important;
  table-layout: fixed !important;
  border-collapse: collapse;
  margin: 9pt 0 11pt 0;
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 7.4pt;
  line-height: 1.34;
  overflow: visible !important;
}
thead { display: table-header-group; }
tr { break-inside: avoid; page-break-inside: avoid; }
th {
  background: #edf2f7;
  color: #0f172a;
  font-weight: 700;
  text-align: left;
  padding: 4.5pt 4.5pt;
  border: 0.6pt solid #cbd5e1;
  overflow-wrap: anywhere !important;
  word-break: break-word !important;
}
td {
  padding: 4pt 4.5pt;
  border: 0.6pt solid #d8e0ea;
  vertical-align: top;
  overflow-wrap: anywhere !important;
  word-break: break-word !important;
}
td code, th code {
  font-size: 7.0pt;
  padding: 0.5pt 2pt;
  white-space: normal !important;
  overflow-wrap: anywhere !important;
  word-break: break-word !important;
}

/* Chapter Overview Box (Print PDF) */
.chapter-overview {
  margin: 10pt 0 14pt 0;
  border: 1pt solid #366393;
  border-left: 3.6pt solid #1f466e;
  border-radius: 5pt;
  background: #f3f7fc;
  overflow: hidden;
  break-inside: avoid;
  page-break-inside: avoid;
}
.chapter-overview > h2 {
  margin: 0 !important;
  padding: 5pt 10pt !important;
  font-size: 7.6pt !important;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  background: #e5eff9;
  border-bottom: 0.6pt solid #c6d8ec !important;
  color: #1e446b !important;
}
.overview-row {
  display: grid;
  grid-template-columns: 1.55in 1fr;
  gap: 8pt;
  padding: 4.5pt 10pt;
  border-bottom: 0.5pt solid #d5e2f0;
  align-items: baseline;
  font-size: 8.7pt;
  line-height: 1.38;
}
.overview-row:last-child {
  border-bottom: 0;
}
.overview-key {
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 7.2pt;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #1e446b;
}
.overview-val p {
  margin: 0;
}

/* Trust-Chain Ledger & Callouts */
.trust-ledger {
  margin: 10pt 0 12pt 0;
  padding: 8pt 11pt 7pt;
  border: 0.75pt solid #b8cbe0;
  border-left: 3.2pt solid #2b547e;
  border-radius: 0 4pt 4pt 0;
  background: #f5f8fc;
  font-size: 8.9pt;
  line-height: 1.40;
  break-inside: avoid;
}
.trust-ledger::before {
  color: #2b547e;
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 7.2pt;
  margin-bottom: 4pt;
}
.trust-ledger li > strong:first-child { color: #1e3a5f; }

.callout {
  margin: 9pt 0 10pt 0;
  padding: 6.5pt 10pt;
  border: 0.5pt solid #e2e8f0;
  border-left: 2.8pt solid #2b547e;
  border-radius: 0 3.5pt 3.5pt 0;
  background: #f8fafc;
  font-size: 9.0pt;
  line-height: 1.42;
  break-inside: avoid;
}
.callout-warning {
  border-color: #ebc8c4;
  border-left-color: #a23b2c;
  background: #fcf4f3;
}

blockquote {
  margin: 8pt 0;
  padding: 5pt 10pt;
  border-left: 2.5pt solid #94a3b8;
  background: #f8fafc;
  color: #334155;
  font-size: 9.1pt;
}

/* Vector SVG Figures */
figure {
  margin: 11pt 0 12pt 0;
  text-align: center;
  break-inside: avoid;
  page-break-inside: avoid;
}
figure img,
.pdf-interior img[src$=".svg"] {
  display: block;
  max-width: 100%;
  max-height: 6.3in;
  width: auto;
  height: auto;
  margin: 0 auto;
  padding: 4pt;
  background: #ffffff;
  border: 0.5pt solid #dce3ec;
  border-radius: 4pt;
  box-shadow: none !important;
}
figcaption {
  font-family: -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif;
  font-size: 7.9pt;
  line-height: 1.35;
  color: #475569;
  margin-top: 4.5pt;
  text-align: center;
}

/* Table of Contents layout */
.pdf-toc-columns {
  column-count: 2;
  column-gap: 18pt;
}
.pdf-toc-group {
  break-inside: avoid;
  margin-bottom: 9pt;
}
.pdf-toc-group h3 {
  font-size: 8.6pt;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: #2b547e;
  margin: 0 0 3pt 0;
  border-bottom: 0.5pt solid #e2e8f0;
  padding-bottom: 1.5pt;
}
.pdf-toc-group ul {
  list-style: none;
  padding-left: 0;
  margin: 0;
}
.pdf-toc-group li {
  font-size: 8.4pt;
  line-height: 1.36;
  margin: 2pt 0;
}

/* Compact 876-entry References bibliography */
#references ~ ol {
  font-size: 7.9pt;
  line-height: 1.34;
  padding-left: 22pt;
}
#references ~ ol li {
  margin: 2pt 0;
  overflow-wrap: anywhere;
}

/* KaTeX print sizing */
.katex { font-size: 1.02em; }
.katex-display { margin: 8pt 0; overflow: visible; break-inside: avoid; }
  </style>
</head>
<body>
  <section class="pdf-front-cover" aria-label="Front Cover">
    ${frontSvg}
  </section>
  <main class="pdf-interior content">
    ${bodyContent}
  </main>
  <section class="pdf-back-cover" aria-label="Back Cover">
    ${backSvg}
  </section>
</body>
</html>`;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
};

function startServer(pdfHtml) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
      if (urlPath === '/__pdf.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(pdfHtml);
        return;
      }
      let fsPath;
      if (urlPath.startsWith('/_katex/')) {
        fsPath = path.join(KATEX_DIR, urlPath.slice('/_katex/'.length));
      } else {
        fsPath = path.join(BOOK_DIR, urlPath.replace(/^\/+/, ''));
      }
      if (!existsSync(fsPath) || !statSync(fsPath).isFile()) {
        res.writeHead(404);
        res.end('Not found');
        return;
      }
      const ext = path.extname(fsPath).toLowerCase();
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(readFileSync(fsPath));
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port });
    });
  });
}

class CdpSession {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.seq = 0;
    this.pending = new Map();
    this.events = new Map();
  }
  async connect() {
    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', reject, { once: true });
    });
    this.ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(String(ev.data));
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
      } else if (msg.method && this.events.has(msg.method)) {
        for (const fn of this.events.get(msg.method)) fn(msg.params);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.seq;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  waitForEvent(method, timeoutMs = 60000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Timeout waiting for ${method}`)), timeoutMs);
      const list = this.events.get(method) || [];
      const handler = (params) => {
        clearTimeout(timer);
        this.events.set(method, (this.events.get(method) || []).filter((f) => f !== handler));
        resolve(params);
      };
      list.push(handler);
      this.events.set(method, list);
    });
  }
  close() {
    try { this.ws.close(); } catch {}
  }
}

async function waitForJson(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url);
      if (r.ok) return await r.json();
    } catch {}
    await new Promise((r) => setTimeout(r, 120));
  }
  throw new Error(`Timed out connecting to Chrome DevTools at ${url}`);
}

async function main() {
  const chromeBin = findChrome();
  const pdfHtml = buildPdfHtml();
  const { server, port } = await startServer(pdfHtml);
  const profileDir = mkdtempSync(path.join(os.tmpdir(), 'wtc-pdf-'));

  const chrome = spawn(chromeBin, [
    '--headless=new',
    '--disable-gpu',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--no-first-run',
    `--user-data-dir=${profileDir}`,
    '--remote-debugging-port=0',
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });

  let debugPort = null;
  chrome.stderr.on('data', (chunk) => {
    const s = chunk.toString();
    const m = s.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\//);
    if (m) debugPort = Number(m[1]);
  });

  try {
    const start = Date.now();
    while (!debugPort && Date.now() - start < 15000) {
      await new Promise((r) => setTimeout(r, 80));
    }
    if (!debugPort) throw new Error('Chrome did not report DevTools port');

    const targets = await waitForJson(`http://127.0.0.1:${debugPort}/json/list`);
    const pageTarget = targets.find((t) => t.type === 'page');
    if (!pageTarget) throw new Error('No page target found in Chrome');

    const cdp = new CdpSession(pageTarget.webSocketDebuggerUrl);
    await cdp.connect();
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');

    const loadDone = cdp.waitForEvent('Page.loadEventFired', 60000);
    await cdp.send('Page.navigate', { url: `http://127.0.0.1:${port}/__pdf.html` });
    await loadDone;

    // Wait until all web fonts and all 68 SVG images report complete, and assert ZERO horizontal overflow across all tables/code/figures!
    const imgStats = await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      returnByValue: true,
      expression: `(async () => {
        await document.fonts.ready;
        const imgs = Array.from(document.querySelectorAll('img'));
        await Promise.all(imgs.map((img) => img.complete ? Promise.resolve() : new Promise((res) => {
          img.addEventListener('load', res, { once: true });
          img.addEventListener('error', res, { once: true });
        })));
        const broken = imgs.filter((i) => !i.complete || i.naturalWidth === 0).map((i) => i.getAttribute('src'));
        const mainRect = document.querySelector('.pdf-interior').getBoundingClientRect();
        const overflows = [];
        document.querySelectorAll('.pdf-interior table, .pdf-interior pre, .pdf-interior figure').forEach((el, idx) => {
          const r = el.getBoundingClientRect();
          if (r.width > mainRect.width + 1.5 || el.scrollWidth > mainRect.width + 2.0) {
            overflows.push(\`\${el.tagName}#\${idx} (w=\${Math.round(r.width)}, scroll=\${el.scrollWidth}, max=\${Math.round(mainRect.width)})\`);
          }
        });
        return { totalImgs: imgs.length, totalTables: document.querySelectorAll('.pdf-interior table').length, broken, overflows };
      })()`,
    });

    const { totalImgs, totalTables, broken, overflows } = imgStats.result.value;
    if (broken.length > 0) {
      throw new Error(`Broken images in PDF render: ${broken.join(', ')}`);
    }
    if (overflows.length > 0) {
      throw new Error(`Horizontal overflow in PDF render: ${overflows.join('; ')}`);
    }

    const headerTemplate = `
      <div style="width:100%; font-family:-apple-system,'Helvetica Neue',Arial,sans-serif; font-size:7.2pt; color:#64748b; padding:0 0.62in; display:flex; justify-content:space-between; letter-spacing:0.04em;">
        <span>THE WINDOWS TRUST CHAIN</span>
        <span>PARAG MALI</span>
      </div>`;
    const footerTemplate = `
      <div style="width:100%; font-family:-apple-system,'Helvetica Neue',Arial,sans-serif; font-size:7.5pt; color:#64748b; padding:0 0.62in; text-align:center;">
        <span class="pageNumber"></span>
      </div>`;

    const pdfRes = await cdp.send('Page.printToPDF', {
      printBackground: true,
      preferCSSPageSize: true,
      displayHeaderFooter: false,
      generateDocumentOutline: true,
      generateTaggedPDF: false,
    });

    const buf = Buffer.from(pdfRes.data, 'base64');
    writeFileSync(OUT_PDF, buf);
    console.log(`PDF written: ${OUT_PDF} (${(buf.length / (1024 * 1024)).toFixed(2)} MB, ${totalImgs} vector figures & ${totalTables} tables verified overflow-free)`);
    cdp.close();
  } finally {
    if (chrome.exitCode === null) {
      chrome.kill('SIGTERM');
      await new Promise((res) => chrome.once('exit', res));
    }
    server.close();
    try { rmSync(profileDir, { recursive: true, force: true }); } catch {}
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
