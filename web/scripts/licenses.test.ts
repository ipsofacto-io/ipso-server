import { describe, expect, it } from 'vitest';

import { check, isAllowed } from './licenses.ts';

describe('the licence gate', () => {
  it('allows the licences of the list and an SPDX expression with an allowed way out', () => {
    for (const license of ['MIT', 'ISC', 'Apache-2.0', 'BSD-3-Clause', '0BSD', 'OFL-1.1', '(MIT OR CC0-1.0)', 'MIT OR GPL-3.0-only']) {
      expect(isAllowed(license), license).toBe(true);
    }
  });

  it('refuses a licence off the list, a copyleft one among them, and an AND with one term off it', () => {
    for (const license of ['GPL-3.0-only', 'AGPL-3.0', 'MPL-2.0', 'UNLICENSED', 'SEE LICENSE IN LICENSE', 'MIT AND GPL-3.0-only', '']) {
      expect(isAllowed(license), license).toBe(false);
    }
  });

  it('judges what ships and counts the rest', () => {
    const report = check({
      lockfileVersion: 3,
      packages: {
        '': { license: 'FSL-1.1-ALv2' },
        'node_modules/react': { license: 'MIT' },
        'node_modules/@fontsource/jetbrains-mono': { license: 'OFL-1.1' },
        'node_modules/lightningcss': { license: 'MPL-2.0', dev: true },
      },
    });
    expect(report).toEqual({ shipped: 2, offenders: [] });
  });

  it('names a shipped package with a licence off the list or none at all', () => {
    const report = check({
      lockfileVersion: 3,
      packages: {
        'node_modules/a/node_modules/copyleft': { license: 'GPL-3.0-only' },
        'node_modules/unknown': {},
        'node_modules/fine': { license: 'ISC' },
      },
    });
    expect(report.shipped).toBe(3);
    expect(report.offenders).toEqual(['copyleft: GPL-3.0-only', 'unknown: no licence in the lockfile']);
  });
});
