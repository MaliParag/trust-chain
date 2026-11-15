#!/usr/bin/env node
/**
 * Multi-volume build & post-build SEO / table-layout / series-index pass for
 * The Platform Trust Chain Series.
 *
 * Runs after root `mdbook build` (both locally and in GitHub Actions CI):
 *   1. Builds all secondary volumes (`books/apple`, `books/linux`, `books/android`)
 *      into `book/<mount>/` via `mdbook build`.
 *   2. Generates `book/series/index.html` showcasing all four volumes.
 *   3. Formats all HTML tables (`<colgroup>` + `<wbr>`) and injects per-volume
 *      canonical URLs, Open Graph, Twitter cards, and `schema.org/Book` JSON-LD.
 *   4. Writes unified `sitemap.xml` and `robots.txt`.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BOOK_DIR = path.resolve(ROOT, process.argv[2] || 'book');
const BASE = (process.env.SITE_URL || 'https://maliparag.github.io/windows-trust-chain').replace(/\/+$/, '');
const REGISTRY = JSON.parse(readFileSync(path.join(ROOT, 'tools', 'books.json'), 'utf8'));
const LICENSE = 'https://creativecommons.org/licenses/by-nc-sa/4.0/';
const IMAGE_W = 1400;
const IMAGE_H = 1850;

// 1. Build all secondary volumes into book/<mount>/ so a single root build populates every OS volume
for (const vol of REGISTRY.volumes) {
  if (!vol.mount) continue;
  const volBookToml = path.join(ROOT, vol.dir, 'book.toml');
  if (!existsSync(volBookToml)) continue;
  const volDir = path.join(ROOT, vol.dir);
  const destDir = path.join(BOOK_DIR, vol.mount);
  execFileSync('mdbook', ['build', '-d', destDir], { cwd: volDir, stdio: 'inherit' });
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function attr(s) {
  return s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}

// 2. Generate book/series/index.html portal
function buildSeriesPortal() {
  const seriesDir = path.join(BOOK_DIR, 'series');
  mkdirSync(seriesDir, { recursive: true });
  const cards = REGISTRY.volumes.map((v) => {
    const href = v.mount ? `../${v.mount}/index.html` : `../index.html`;
    const coverHref = v.mount ? `../${v.mount}/cover.png` : `../cover.png`;
    return `
      <a class="vol-card" href="${href}" style="--accent:${v.accent}">
        <div class="vol-cover-wrap">
          <img src="${coverHref}" alt="${esc(v.title)} cover" loading="lazy">
        </div>
        <div class="vol-meta">
          <div class="vol-tag">${esc(v.volume)} · ${esc(v.status)}</div>
          <h2>${esc(v.title)}</h2>
          <p>${esc(v.subtitle)}</p>
        </div>
      </a>`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(REGISTRY.seriesTitle)} - ${esc(REGISTRY.author)}</title>
  <meta name="description" content="${esc(REGISTRY.seriesSubtitle)}">
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at 50% 0%, #132036 0%, #090e18 65%);
      color: #edf2f7;
      min-height: 100vh;
    }
    .wrap { max-width: 1160px; margin: 0 auto; padding: 3.2rem 1.5rem 4rem; }
    .eyebrow {
      color: #d4a843; font-size: 0.78rem; font-weight: 700;
      letter-spacing: 0.16em; text-transform: uppercase; margin-bottom: 0.6rem;
    }
    h1 {
      font-family: Georgia, Baskerville, serif;
      font-size: clamp(2rem, 4vw, 3rem);
      margin: 0 0 0.75rem; color: #f8f5ee;
    }
    .lead {
      max-width: 760px; font-size: 1.08rem; line-height: 1.6;
      color: #b9c6d8; margin: 0 0 2.5rem;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(245px, 1fr));
      gap: 1.5rem;
    }
    .vol-card {
      display: flex; flex-direction: column;
      background: #0e1726;
      border: 1px solid #24354f;
      border-top: 3px solid var(--accent, #d4a843);
      border-radius: 10px;
      overflow: hidden;
      text-decoration: none;
      color: inherit;
      transition: transform 0.16s ease, border-color 0.16s ease;
    }
    .vol-card:hover { transform: translateY(-3px); border-color: var(--accent, #d4a843); }
    .vol-cover-wrap { background: #070b12; aspect-ratio: 1400 / 1850; overflow: hidden; }
    .vol-cover-wrap img { width: 100%; height: 100%; object-fit: cover; display: block; }
    .vol-meta { padding: 1.1rem 1.2rem 1.3rem; }
    .vol-tag {
      font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em;
      text-transform: uppercase; color: var(--accent, #d4a843); margin-bottom: 0.4rem;
    }
    .vol-meta h2 {
      font-family: Georgia, serif; font-size: 1.22rem; margin: 0 0 0.45rem; color: #f7f4ed;
    }
    .vol-meta p { margin: 0; font-size: 0.88rem; line-height: 1.5; color: #9fb0c7; }
    footer {
      margin-top: 3rem; padding-top: 1.4rem; border-top: 1px solid #1e2d44;
      font-size: 0.86rem; color: #8496b0; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.8rem;
    }
    footer a { color: #9cc4f0; text-decoration: none; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="eyebrow">Open Systems Security Monographs · ${esc(REGISTRY.author)}</div>
    <h1>${esc(REGISTRY.seriesTitle)}</h1>
    <p class="lead">${esc(REGISTRY.seriesSubtitle)}. Each volume traces one platform's verifiable chain of trust link by link from immutable silicon roots up to cloud policy and confidential AI compute, grounded in primary specifications.</p>
    <div class="grid">${cards}</div>
    <footer>
      <span>Copyright © 2026 ${esc(REGISTRY.author)} · CC BY-NC-SA 4.0</span>
      <span><a href="${esc(REGISTRY.repoUrl)}">GitHub Repository</a></span>
    </footer>
  </div>
</body>
</html>\n`;
  writeFileSync(path.join(seriesDir, 'index.html'), html, 'utf8');
}

buildSeriesPortal();

function formatTables(html) {
  return html.replace(/<table\b[^>]*>[\s\S]*?<\/table>/gi, (tableHtml) => {
    if (/<colgroup\b/i.test(tableHtml)) return tableHtml;
    const rows = [...tableHtml.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)].map((m) => m[1]);
    if (rows.length === 0) return tableHtml;

    const strip = (s) => s.replace(/<[^>]+>/g, '').replace(/&[a-z#0-9]+;/gi, 'x').trim();
    const hdrCells = [...rows[0].matchAll(/<th\b[^>]*>([\s\S]*?)<\/th>/gi)].map((m) => strip(m[1]));
    const nCols = hdrCells.length;
    if (nCols < 2) return tableHtml;

    let pcts;
    if (nCols === 6 && /^year$/i.test(hdrCells[1])) {
      pcts = [16, 8, 14, 14, 26, 22];
    } else {
      const bodyRows = rows.slice(1).map((r) =>
        [...r.matchAll(/<t[dh]\b[^>]*>([\s\S]*?)<\/t[dh]>/gi)].map((m) => strip(m[1]))
      ).filter((r) => r.length === nCols);

      const weights = hdrCells.map((h, j) => {
        const longestWord = Math.max(...h.split(/\s+/).map((w) => w.length), 3);
        const minW = Math.min(18, Math.max(10, longestWord * 1.1 + 3));
        const avgBody = bodyRows.length
          ? bodyRows.reduce((acc, r) => acc + r[j].length, 0) / bodyRows.length
          : h.length;
        return Math.max(minW, Math.pow(Math.max(avgBody, h.length * 0.85), 0.56) * 5.2);
      });
      const sumW = weights.reduce((a, b) => a + b, 0);
      pcts = weights.map((w) => Math.round((w / sumW) * 1000) / 10);
      const drift = Math.round((100 - pcts.reduce((a, b) => a + b, 0)) * 10) / 10;
      pcts[pcts.length - 1] = Math.round((pcts[pcts.length - 1] + drift) * 10) / 10;
    }

    const colgroup = `<colgroup>${pcts.map((p) => `<col style="width:${p}%">`).join('')}</colgroup>`;
    let updated = tableHtml.replace(/^(<table\b[^>]*>)/i, `$1${colgroup}`);
    updated = updated.replace(/(<td\b[^>]*>[\s\S]*?<\/td>)/gi, (td) =>
      td.replace(/<code>([\s\S]*?)<\/code>/gi, (_, inner) =>
        `<code>${inner.replace(/([\\/_])/g, '$1<wbr>')}</code>`
      )
    );
    return updated;
  });
}

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) out.push(...walk(p));
    else if (name.endsWith('.html')) out.push(p);
  }
  return out;
}

// Map relative path under BOOK_DIR to its owning volume metadata
const subMounts = REGISTRY.volumes.filter((v) => v.mount).map((v) => v.mount);
function resolveVolume(rel) {
  for (const v of REGISTRY.volumes) {
    if (v.mount && (rel === `${v.mount}` || rel.startsWith(`${v.mount}/`))) {
      return { vol: v, localRel: rel.slice(v.mount.length + 1) };
    }
  }
  return { vol: REGISTRY.volumes[0], localRel: rel };
}

const SKIP_BASENAMES = new Set(['404.html', 'toc.html']);
const pages = [];
let injectedCount = 0;

for (const file of walk(BOOK_DIR)) {
  const rel = path.relative(BOOK_DIR, file).split(path.sep).join('/');
  const base = path.basename(file);
  if (SKIP_BASENAMES.has(base)) continue;

  if (rel === 'series/index.html') {
    pages.push(`${BASE}/series/`);
    continue;
  }

  let html = readFileSync(file, 'utf8');
  if (!html.includes('</head>')) continue;
  if (html.includes('data-seo="1"')) continue;

  const { vol, localRel } = resolveVolume(rel);
  const housePath = path.join(ROOT, vol.dir, 'house.json');
  const house = existsSync(housePath) ? JSON.parse(readFileSync(housePath, 'utf8')) : {};
  const vTitle = house.title || vol.title;
  const vSub = house.subtitle || vol.subtitle;
  const vDesc = house.description || vSub;
  const vAuthor = house.author || REGISTRY.author;
  const vBase = vol.mount ? `${BASE}/${vol.mount}` : BASE;
  const vDir = vol.mount ? path.join(BOOK_DIR, vol.mount) : BOOK_DIR;
  const vImg = existsSync(path.join(vDir, 'cover.png')) ? `${vBase}/cover.png` : null;

  const isVolRoot = localRel === 'index.html';
  const isPrint = localRel === 'print.html';
  const url = isVolRoot ? `${vBase}/` : `${vBase}/${localRel}`;

  const titleMatch = html.match(/<title>([\s\S]*?)<\/title>/i);
  let pageTitle = titleMatch ? attr(titleMatch[1].trim()) : vTitle;
  const descMatch = html.match(/<meta name="description" content="([^"]*)"/i);
  const pageDesc = descMatch ? attr(descMatch[1]) : vDesc;

  if (isVolRoot) {
    const full = `${vTitle}: ${vSub}`;
    html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${esc(full)}</title>`);
    html = html.replace(/href="\.\.\/(front-matter|chapters|back-matter)\//g, 'href="$1/');
    if (house.pdfFilename) {
      const pdfRe = new RegExp(`href="\\.\\.\\/${house.pdfFilename.replace(/\./g, '\\.')}"`, 'g');
      html = html.replace(pdfRe, `href="${house.pdfFilename}"`);
    }
    pageTitle = full;
  }

  const bookSchema = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'Book',
    name: vTitle,
    alternateName: `${vTitle}: ${vSub}`,
    headline: vSub,
    author: { '@type': 'Person', name: vAuthor },
    publisher: { '@type': 'Person', name: vAuthor },
    inLanguage: 'en',
    bookFormat: 'https://schema.org/EBook',
    genre: 'Computer security',
    url: `${vBase}/`,
    description: vDesc,
    license: LICENSE,
    ...(vImg ? { image: vImg } : {}),
  });

  const tags = [];
  tags.push(`<meta data-seo="1" property="og:type" content="${isVolRoot ? 'book' : 'article'}">`);
  tags.push(`<meta property="og:site_name" content="${esc(vTitle)}">`);
  tags.push(`<meta property="og:title" content="${esc(pageTitle)}">`);
  tags.push(`<meta property="og:description" content="${esc(pageDesc)}">`);
  tags.push(`<meta property="og:url" content="${esc(url)}">`);
  tags.push(`<meta property="og:locale" content="en_US">`);
  if (vImg) {
    tags.push(`<meta property="og:image" content="${esc(vImg)}">`);
    tags.push(`<meta property="og:image:width" content="${IMAGE_W}">`);
    tags.push(`<meta property="og:image:height" content="${IMAGE_H}">`);
    tags.push(`<meta property="og:image:alt" content="${esc(vTitle)} book cover">`);
  }
  tags.push(`<meta name="twitter:card" content="${vImg ? 'summary_large_image' : 'summary'}">`);
  tags.push(`<meta name="twitter:title" content="${esc(pageTitle)}">`);
  tags.push(`<meta name="twitter:description" content="${esc(pageDesc)}">`);
  if (vImg) tags.push(`<meta name="twitter:image" content="${esc(vImg)}">`);
  tags.push(`<meta name="author" content="${esc(vAuthor)}">`);

  if (isPrint) {
    if (!/name="robots"/i.test(html)) tags.push('<meta name="robots" content="noindex, follow">');
  } else {
    tags.push(`<link rel="canonical" href="${esc(url)}">`);
    pages.push(url);
  }

  if (isVolRoot || base.startsWith('0') || /chapters\//.test(localRel)) {
    tags.push(`<script type="application/ld+json">${bookSchema}</script>`);
  }

  html = formatTables(html);
  html = html.replace('</head>', `        ${tags.join('\n        ')}\n    </head>`);
  writeFileSync(file, html, 'utf8');
  injectedCount++;
}

pages.sort((a, b) => (a === `${BASE}/` ? -1 : b === `${BASE}/` ? 1 : a.localeCompare(b)));
const today = new Date().toISOString().slice(0, 10);
const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...pages.map((u) => `  <url><loc>${u}</loc><lastmod>${today}</lastmod></url>`),
  '</urlset>',
  '',
].join('\n');
writeFileSync(path.join(BOOK_DIR, 'sitemap.xml'), sitemap, 'utf8');

const robots = ['User-agent: *', 'Allow: /', '', `Sitemap: ${BASE}/sitemap.xml`, ''].join('\n');
writeFileSync(path.join(BOOK_DIR, 'robots.txt'), robots, 'utf8');

console.log(`SEO & Multi-Volume: processed ${injectedCount} pages across ${REGISTRY.volumes.length} volumes; wrote series/index.html + sitemap.xml (${pages.length} urls)`);
