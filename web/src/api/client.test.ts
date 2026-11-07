import { afterEach, describe, expect, it, vi } from 'vitest';

import { ApiError, createApi } from './client';

function answer(status: number, body: unknown, headers: Record<string, string> = {}) {
  return vi.fn(async () => new Response(body === undefined ? null : JSON.stringify(body), { status, headers }));
}

afterEach(() => vi.unstubAllGlobals());

describe('createApi', () => {
  it('sends the query without the keys that are empty', async () => {
    const fetch = answer(200, { ok: true });
    vi.stubGlobal('fetch', fetch);
    await createApi().getJSON('/v1/decisions', { limit: 50, before: undefined, valid: '', known: '2026-11-07T00:00:00Z' });
    expect(fetch).toHaveBeenCalledOnce();
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/v1/decisions?limit=50&known=2026-11-07T00%3A00%3A00Z');
    expect(init).toMatchObject({ method: 'GET', cache: 'no-store', credentials: 'same-origin', redirect: 'error' });
  });

  it('puts no tenant anywhere: the session speaks for it', async () => {
    const fetch = answer(200, {});
    vi.stubGlobal('fetch', fetch);
    await createApi().getJSON('/v1/scopes', { limit: 100 });
    expect(String((fetch.mock.calls[0] as unknown[])[0])).not.toMatch(/tenant/);
  });

  it('prefixes the base and sends the headers it was given', async () => {
    const fetch = answer(200, {});
    vi.stubGlobal('fetch', fetch);
    await createApi({ base: 'http://mock.test', headers: { Cookie: 'a=b' } }).getJSON('/v1/waivers');
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://mock.test/v1/waivers');
    expect(init.headers).toMatchObject({ Accept: 'application/json', Cookie: 'a=b' });
  });

  it('turns an error answer into an ApiError with the closed code', async () => {
    vi.stubGlobal('fetch', answer(400, { error: 'invalid query' }));
    await expect(createApi().getJSON('/v1/decisions')).rejects.toMatchObject({ name: 'ApiError', status: 400, code: 'invalid query' });
  });

  it('keeps the issuer and the subject of an unknown login, and reads Retry-After', async () => {
    vi.stubGlobal('fetch', answer(403, { error: 'unknown_login', issuer: 'https://idp.test', subject: 'person-9' }));
    await expect(createApi().getJSON('/v1/scopes')).rejects.toMatchObject({ status: 403, code: 'unknown_login', issuer: 'https://idp.test', subject: 'person-9' });
    vi.stubGlobal('fetch', answer(429, { error: 'rate limited' }, { 'Retry-After': '7' }));
    await expect(createApi().getJSON('/v1/scopes')).rejects.toMatchObject({ status: 429, retryAfter: 7 });
  });

  it('gives a body that is not JSON the code "internal"', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>bad gateway</html>', { status: 502 })));
    await expect(createApi().getJSON('/v1/scopes')).rejects.toMatchObject({ status: 502, code: 'internal' });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>', { status: 200 })));
    await expect(createApi().getJSON('/v1/scopes')).rejects.toMatchObject({ status: 200, code: 'internal' });
  });

  it('says status 0 when the request got no answer, and rethrows an abort as it is', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
    const error = await createApi().getJSON('/v1/scopes').catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 0, code: 'network' });

    const controller = new AbortController();
    controller.abort();
    vi.stubGlobal('fetch', vi.fn(async () => { throw new DOMException('aborted', 'AbortError'); }));
    await expect(createApi().getJSON('/v1/scopes', {}, controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('posts with no body and no query', async () => {
    const fetch = answer(204, undefined);
    vi.stubGlobal('fetch', fetch);
    await createApi().post('/auth/logout');
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('/auth/logout');
    expect(init).toMatchObject({ method: 'POST' });
    expect(init.body).toBeUndefined();
  });
});
