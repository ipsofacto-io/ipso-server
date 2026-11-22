import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const root = process.cwd();
const tokens = readFileSync(join(root, 'src/brand/styles/tokens.css'), 'utf8');
const kit = readFileSync(join(root, 'src/brand/styles/ipso.css'), 'utf8');
const app = readFileSync(join(root, 'src/styles/app.css'), 'utf8');

// The paints the views use. axe cannot judge them here: the unit run does not apply CSS. A pair is the
// foreground on the background a person actually sees, in both themes. Text needs 4.5:1 and a boundary or
// state that is not text needs 3:1 (WCAG 2.2, 1.4.3 and 1.4.11).

function block(source: string, selector: string): Record<string, string> {
  const start = source.indexOf(selector);
  if (start < 0) throw new Error(`missing ${selector}`);
  const body = source.slice(start, source.indexOf('}', start));
  const found: Record<string, string> = {};
  for (const match of body.matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)) {
    const name = match[1];
    const raw = match[2];
    if (name === undefined || raw === undefined) continue;
    found[name] = raw.trim();
  }
  return found;
}

function resolve(raw: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  const value = (name: string, seen: string[]): string => {
    if (out[name]) return out[name];
    const declared = raw[name];
    if (!declared) throw new Error(`missing ${name}`);
    const ref = declared.match(/^var\((--[a-z0-9-]+)\)$/);
    if (!ref) return declared;
    const next = ref[1];
    if (next === undefined || seen.includes(name)) throw new Error(`cycle at ${name}`);
    return value(next, [...seen, name]);
  };
  for (const name of Object.keys(raw)) out[name] = value(name, []);
  return out;
}

const light = resolve(block(tokens, ':root, [data-theme="light"]'));
const dark = resolve(block(tokens, '[data-theme="dark"]'));

function channel(hex: string, index: number): number {
  const value = Number.parseInt(hex.slice(1 + index * 2, 3 + index * 2), 16) / 255;
  return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}

function luminance(hex: string): number {
  const r = channel(hex, 0);
  const g = channel(hex, 1);
  const b = channel(hex, 2);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(foreground: string, background: string): number {
  const lighter = Math.max(luminance(foreground), luminance(background));
  const darker = Math.min(luminance(foreground), luminance(background));
  return (lighter + 0.05) / (darker + 0.05);
}

function paint(theme: Record<string, string>, foreground: string, background: string): number {
  const fg = theme[foreground];
  const bg = theme[background];
  if (!fg?.startsWith('#') || !bg?.startsWith('#')) throw new Error(`${foreground} on ${background} is not a hex pair`);
  return contrast(fg, bg);
}

const text: [string, string, string][] = [
  ['body', '--ink', '--surface'],
  ['cards and inputs', '--ink', '--surface-raised'],
  ['muted text on the page', '--ink-muted', '--surface'],
  ['labels, hints and placeholders', '--ink-muted', '--surface-raised'],
  ['table headers and code headings', '--ink-muted', '--surface-sunken'],
  ['links on the page', '--link', '--surface'],
  ['links in a card or a table', '--link', '--surface-raised'],
  ['errors and failed results', '--carminio', '--surface-raised'],
  ['rejected status', '--carminio', '--carminio-soft'],
  ['verified status', '--on-menta', '--menta'],
  ['verifying status', '--ink', '--menta-soft'],
  ['primary button and skip link', '--on-action', '--action'],
  ['danger button', '--on-carminio', '--carminio'],
  ['pending pill', '--on-pietra', '--pietra'],
  ['error notice', '--ink', '--carminio-soft'],
  ['current navigation item', '--ink', '--rosa-soft'],
];

const ui: [string, string, string][] = [
  ['focus ring on the page', '--focus', '--surface'],
  ['focus ring on a card', '--focus', '--surface-raised'],
  ['input and button border', '--line-strong', '--surface-raised'],
  ['button border on the page', '--line-strong', '--surface'],
  ['current navigation bar', '--fucsia', '--rosa-soft'],
  ['verifying status border', '--menta-strong', '--menta-soft'],
  ['invalid input border', '--carminio', '--surface-raised'],
];

describe('contrast of the paints the views use', () => {
  for (const theme of [
    ['light', light],
    ['dark', dark],
  ] as const) {
    const [name, colors] = theme;
    it(`keeps text at 4.5:1 in the ${name} theme`, () => {
      const short = text.flatMap(([label, fg, bg]) => (paint(colors, fg, bg) >= 4.5 ? [] : [`${label}: ${paint(colors, fg, bg).toFixed(2)}`]));
      expect(short).toEqual([]);
    });

    it(`keeps boundaries and state at 3:1 in the ${name} theme`, () => {
      const short = ui.flatMap(([label, fg, bg]) => (paint(colors, fg, bg) >= 3 ? [] : [`${label}: ${paint(colors, fg, bg).toFixed(2)}`]));
      expect(short).toEqual([]);
    });
  }

  it('keeps buttons and inputs at least 24px, and underlines a link in the content', () => {
    expect(kit).toMatch(/\.ip-btn \{[^}]*height: 44px/);
    expect(kit).toMatch(/\.ip-btn-sm \{[^}]*height: 36px/);
    expect(kit).toMatch(/\.ip-input \{[^}]*height: 44px/);
    expect(app).toMatch(/a \{[^}]*text-decoration: underline/);
  });
});
