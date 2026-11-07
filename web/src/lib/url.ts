/**
 * A link from a record is data, not code. Only an https URL becomes a link, because a stored value such as
 * "javascript:..." would run when someone clicked it. Anything else is shown as text.
 */
export function safeHttpsUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.username === '' && parsed.password === '' ? parsed.href : null;
  } catch {
    return null;
  }
}
