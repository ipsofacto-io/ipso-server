// What the premises page says before it sends (ADR-0119). The server stays the authority on a host: it lowercases it and
// answers 400 for anything that is not a DNS name, so the checks here are the ones it makes, said in words.
import type { ClearanceRequest, PremiseHostRequest } from '../api/types';

export const HOST_MAX = 253;
// The premise_host_allow_host constraint of migration 00006, as internal/registry/write.go reads it.
const HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
// An IPv4 address, or a run of digits and dots: a probe never dials one (ADR-0098).
const NUMERIC = /^[0-9.]+$/;

export type HostCheck = { ok: true; host: string } | { ok: false; error: string };

export function checkHost(value: string): HostCheck {
  const host = value.trim().toLowerCase();
  if (host === '') return { ok: false, error: 'Give the host name a premise probe may dial.' };
  if (host.length > HOST_MAX) return { ok: false, error: `A host name has at most ${HOST_MAX} characters.` };
  if (NUMERIC.test(host)) return { ok: false, error: 'That is an address. Give a host name: a probe never dials an address.' };
  if (!HOST.test(host)) {
    return {
      ok: false,
      error: 'A host is a DNS name in lowercase ASCII, such as status.example.com, with no scheme, port or path. Write it in punycode when it is not ASCII.',
    };
  }
  return { ok: true, host };
}

/** An allow or a withdraw: the same request with a different flag. It names a host and never a tenant or a person. */
export function hostRequest(host: string, allowed: boolean): PremiseHostRequest {
  return { host, allowed };
}

/** A clearance has no field: the path names the decision and the premise, and the person is the session's. */
export function clearance(): ClearanceRequest {
  return {};
}

/** A stored value as the text a person reads. `"false"` and `false` differ, and the value is never markup. */
export function premiseValue(value: unknown): string {
  return JSON.stringify(value) ?? 'null';
}
