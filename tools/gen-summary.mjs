#!/usr/bin/env node
/**
 * Multi-book SUMMARY.md generator for The Platform Trust Chain Series.
 * Reads books/<slug>/house.json and writes books/<slug>/src/SUMMARY.md.
 *
 * Usage:
 *   node tools/gen-summary.mjs                  # updates all volumes in tools/books.json
 *   node tools/gen-summary.mjs --book windows   # updates a single volume
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REGISTRY = JSON.parse(readFileSync(path.join(ROOT, 'tools', 'books.json'), 'utf8'));

const args = process.argv.slice(2);
const bookIdx = args.indexOf('--book');
const targetSlug = bookIdx >= 0 ? args[bookIdx + 1] : null;

const volumes = targetSlug
  ? REGISTRY.volumes.filter((v) => v.slug === targetSlug)
  : REGISTRY.volumes;

if (volumes.length === 0) {
  throw new Error(`Unknown book slug: ${targetSlug}`);
}

function extractH1(srcDir, relPath) {
  const p = path.join(srcDir, relPath);
  if (!existsSync(p)) throw new Error(`Missing source file: ${p}`);
  const line = readFileSync(p, 'utf8').split(/\r?\n/).find((l) => /^#\s+/.test(l)) || '# Untitled';
  return line
    .replace(/^#\s+/, '')
    .replace(/^(Chapter\s+\d+[A-Za-z]*|Prologue|Foundations)\s*[·:\-]\s*/i, '')
    .trim();
}

for (const vol of volumes) {
  const bookDir = path.join(ROOT, vol.dir);
  const housePath = path.join(bookDir, 'house.json');
  if (!existsSync(housePath)) continue;

  const house = JSON.parse(readFileSync(housePath, 'utf8'));
  const srcDir = path.join(bookDir, 'src');
  const out = ['# Summary', ''];

  for (const [rel, label] of house.front || []) out.push(`[${label}](${rel})`);
  for (const [rel, label] of house.specials || []) out.push(`[${label}](${rel})`);
  out.push('');

  for (const part of house.parts || []) {
    if (!part.items || part.items.length === 0) continue;
    out.push(`# ${part.title}`, '');
    for (const slug of part.items) {
      const rel = `chapters/${slug}.md`;
      out.push(`- [${extractH1(srcDir, rel)}](${rel})`);
    }
    out.push('');
  }

  if (house.back && house.back.length > 0) {
    out.push('---', '');
    for (const rel of house.back) out.push(`[${extractH1(srcDir, rel)}](${rel})`);
    out.push('');
  }

  const summaryPath = path.join(srcDir, 'SUMMARY.md');
  writeFileSync(summaryPath, out.join('\n'), 'utf8');
  console.log(`wrote ${path.relative(ROOT, summaryPath)}`);
}
