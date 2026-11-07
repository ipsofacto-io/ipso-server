// The body of a decision and the payload of a proposal are stored as the author wrote them, and a model or an
// import wrote some of them. Nothing here trusts a shape: each reader returns what fits or a neutral value.

export type Json = Record<string, unknown>;

export function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null;
}

export function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item !== '') : [];
}

export function asRecords(value: unknown): Json[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

/** Pretty JSON for a code block, cut at `limit` characters so a huge payload cannot freeze the page. */
export function preview(value: unknown, limit = 20_000): string {
  const text = JSON.stringify(value, null, 2) ?? '';
  return text.length > limit ? `${text.slice(0, limit)}\n... ${text.length - limit} more characters` : text;
}
