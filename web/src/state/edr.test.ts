import { describe, expect, it } from 'vitest';

import { ids, scopes } from '../../fixtures/data.ts';
import type { Scope } from '../api/types';
import { aYearAfter, approvalRequest, checkApproval, edrScope, isDate, slugFrom, type ApprovalForm } from './edr';

const form: ApprovalForm = {
  title: 'Services read secrets from the vault',
  slug: 'services-read-secrets-from-the-vault',
  owner: 'team:platform',
  criticality: 'warning',
  validFrom: '2026-11-08',
  reviewBy: '2027-11-08',
  sourceUrl: 'https://github.com/acme/payments/pull/412',
  sourceType: 'pr',
};

const EDR_KEYS = [
  'edr', 'id', 'slug', 'title', 'status', 'owner', 'scope', 'valid_from', 'valid_to', 'review_by',
  'supersedes', 'criticality', 'checks', 'waivers', 'sources', 'tags',
];

describe('slugFrom', () => {
  it('joins lowercase words with hyphens', () => {
    expect(slugFrom('Services read secrets from the vault, not from environment files')).toBe('services-read-secrets-from-the-vault-not-from-environment-files');
    expect(slugFrom('  TLS 1.2+ everywhere!  ')).toBe('tls-1-2-everywhere');
  });

  it('drops accents and what has no ASCII form', () => {
    expect(slugFrom('Caché étagé')).toBe('cache-etage');
    expect(slugFrom('日本語')).toBe('');
  });

  it('stops at 128 characters without ending on a hyphen', () => {
    const slug = slugFrom(`${'a'.repeat(127)} b`);
    expect(slug).toBe('a'.repeat(127));
    expect(slugFrom('word '.repeat(60)).length).toBeLessThanOrEqual(128);
    expect(slugFrom('word '.repeat(60)).endsWith('-')).toBe(false);
  });
});

describe('dates', () => {
  it('accepts a real calendar date and nothing else', () => {
    expect(isDate('2026-11-08')).toBe(true);
    expect(isDate('2028-02-29')).toBe(true);
    for (const bad of ['2026-02-30', '2026-13-01', '2026-1-1', '', '2026-11-08T00:00:00Z']) expect(isDate(bad)).toBe(false);
  });

  it('puts the review a year after the start', () => {
    expect(aYearAfter('2026-11-08')).toBe('2027-11-08');
    expect(aYearAfter('2028-02-29')).toBe('2029-03-01');
    expect(aYearAfter('nope')).toBe('');
  });
});

describe('checkApproval', () => {
  it('has nothing to say about a form the server and the schema accept', () => {
    expect(checkApproval(form, [ids.repo])).toEqual({});
  });

  it('says what is wrong with each field', () => {
    const errors = checkApproval(
      { ...form, title: ' padded', slug: 'Not A Slug', owner: 'platform', validFrom: '2026-02-30', reviewBy: 'soon', sourceUrl: 'http://example.test' },
      [],
    );
    expect(Object.keys(errors).sort()).toEqual(['owner', 'reviewBy', 'scopes', 'slug', 'sourceUrl', 'title', 'validFrom']);
  });

  it('holds the title to 300 characters, counted as characters', () => {
    expect(checkApproval({ ...form, title: '😀'.repeat(300) }, [ids.repo]).title).toBeUndefined();
    expect(checkApproval({ ...form, title: '😀'.repeat(301) }, [ids.repo]).title).toBeDefined();
    expect(checkApproval({ ...form, title: '' }, [ids.repo]).title).toBeDefined();
  });

  it('holds the slug to 128 characters, and the scopes to 100', () => {
    expect(checkApproval({ ...form, slug: 'a'.repeat(128) }, [ids.repo]).slug).toBeUndefined();
    expect(checkApproval({ ...form, slug: 'a'.repeat(129) }, [ids.repo]).slug).toBeDefined();
    expect(checkApproval(form, Array.from({ length: 100 }, (_, i) => String(i))).scopes).toBeUndefined();
    expect(checkApproval(form, Array.from({ length: 101 }, (_, i) => String(i))).scopes).toBeDefined();
  });

  it('refuses a source link that carries a user name or a password', () => {
    expect(checkApproval({ ...form, sourceUrl: 'https://token@wiki.example.test/page' }, [ids.repo]).sourceUrl).toBeDefined();
    expect(checkApproval({ ...form, sourceUrl: 'https://user:secret@wiki.example.test/page' }, [ids.repo]).sourceUrl).toBeDefined();
    expect(checkApproval({ ...form, sourceUrl: 'https://wiki.example.test/page' }, [ids.repo]).sourceUrl).toBeUndefined();
  });

  it('wants the review after the start', () => {
    expect(checkApproval({ ...form, reviewBy: form.validFrom }, [ids.repo]).reviewBy).toBeDefined();
    expect(checkApproval({ ...form, reviewBy: '2026-11-09' }, [ids.repo]).reviewBy).toBeUndefined();
  });

  it('wants an owner written as team:name', () => {
    for (const owner of ['team:platform', 'team:app-sec', 'team:a1']) expect(checkApproval({ ...form, owner }, [ids.repo]).owner).toBeUndefined();
    for (const owner of ['', 'team:', 'team:Platform', 'team:-x', 'team:x-', 'group:platform', 'team:a b']) expect(checkApproval({ ...form, owner }, [ids.repo]).owner).toBeDefined();
  });
});

describe('edrScope', () => {
  it('names the org, the repo and the env on the way up the tree', () => {
    expect(edrScope([ids.prod], scopes)).toEqual([{ org: 'acme', repo: 'acme/payments', env: ['prod'] }]);
    expect(edrScope([ids.paths], scopes)).toEqual([{ org: 'acme', repo: 'acme/payments', paths: ['deploy/**'] }]);
    expect(edrScope([ids.repo], scopes)).toEqual([{ org: 'acme', repo: 'acme/payments' }]);
  });

  it('leaves out a service, which the EDR has no key for, and a node that names nothing', () => {
    expect(edrScope([ids.service], scopes)).toEqual([{ org: 'acme' }]);
    const orphan: Scope = { id: 'x', parent_id: null, kind: 'service', selector: 'lonely' };
    expect(edrScope(['x'], [orphan])).toEqual([]);
  });

  it('writes one item for what is picked twice, and for an id it does not know', () => {
    expect(edrScope([ids.repo, ids.repo, 'unknown'], scopes)).toEqual([{ org: 'acme', repo: 'acme/payments' }]);
  });

  it('stops at a parent that loops back', () => {
    const loop: Scope[] = [
      { id: 'a', parent_id: 'b', kind: 'repo', selector: 'x/a' },
      { id: 'b', parent_id: 'a', kind: 'org', selector: 'x' },
    ];
    expect(edrScope(['a'], loop)).toEqual([{ repo: 'x/a', org: 'x' }]);
  });
});

describe('approvalRequest', () => {
  const request = approvalRequest(form, [ids.repo, ids.prod], scopes, '01JB0000000000000000000000');

  it('approves with the decision and the scopes the person picked', () => {
    expect(request.outcome).toBe('approved');
    expect(request.decision?.scope_refs).toEqual([ids.repo, ids.prod]);
    expect(request.decision?.valid_from).toBe('2026-11-08T00:00:00Z');
  });

  it('writes all sixteen keys of the EDR and no other', () => {
    expect(Object.keys(request.decision?.body ?? {}).sort()).toEqual([...EDR_KEYS].sort());
    expect(request.decision?.body).toMatchObject({
      edr: 1,
      id: '01JB0000000000000000000000',
      status: 'accepted',
      valid_to: null,
      supersedes: [],
      checks: [],
      waivers: [],
      tags: [],
      sources: [{ type: 'pr', url: 'https://github.com/acme/payments/pull/412' }],
      criticality: 'warning',
      review_by: '2027-11-08',
    });
  });

  it('names no tenant, no principal and no approver: the session speaks for them', () => {
    expect(JSON.stringify(request)).not.toMatch(/tenant|principal|approver/i);
  });

  it('makes an id that is a ULID when it is not given one', () => {
    expect(String(approvalRequest(form, [ids.repo], scopes).decision?.body.id)).toMatch(/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/);
  });
});
