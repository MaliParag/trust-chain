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
import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeSeriesPortals } from './build-series-portal.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BOOK_DIR = path.resolve(ROOT, process.argv[2] || 'book');
const REGISTRY = JSON.parse(readFileSync(path.join(ROOT, 'tools', 'books.json'), 'utf8'));
const envSite = process.env.SITE_URL && !process.env.SITE_URL.includes('/windows-trust-chain')
  ? process.env.SITE_URL
  : null;
const BASE = (envSite || REGISTRY.siteUrl || 'https://maliparag.github.io/trust-chain').replace(/\/+$/, '');
const LICENSE = 'https://creativecommons.org/licenses/by-nc-sa/4.0/';
const IMAGE_W = 1400;
const IMAGE_H = 1850;

// 1. Build all volumes with explicit mounts (`windows`, `apple`, `linux`, `android`) into `book/<mount>/`
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

  if (rel === 'index.html' || rel === 'series/index.html') {
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

// Write flagship Apple-grade Series Showcase at both book/index.html and book/series/index.html
writeSeriesPortals(BOOK_DIR, { ...REGISTRY, siteUrl: BASE });
pages.push(`${BASE}/`, `${BASE}/series/`);
const uniquePages = Array.from(new Set(pages));
uniquePages.sort((a, b) => (a === `${BASE}/` ? -1 : b === `${BASE}/` ? 1 : a.localeCompare(b)));
const today = new Date().toISOString().slice(0, 10);
const sitemap = [
  '<?xml version="1.0" encoding="UTF-8"?>',
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
  ...uniquePages.map((u) => `  <url><loc>${u}</loc><lastmod>${today}</lastmod></url>`),
  '</urlset>',
  '',
].join('\n');
writeFileSync(path.join(BOOK_DIR, 'sitemap.xml'), sitemap, 'utf8');

const robots = ['User-agent: *', 'Allow: /', '', `Sitemap: ${BASE}/sitemap.xml`, ''].join('\n');
writeFileSync(path.join(BOOK_DIR, 'robots.txt'), robots, 'utf8');

console.log(`SEO & Multi-Volume: processed ${injectedCount} pages across ${REGISTRY.volumes.length} volumes; wrote index.html + series/index.html + sitemap.xml (${uniquePages.length} urls)`);
