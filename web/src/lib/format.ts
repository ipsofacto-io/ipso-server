/** An RFC 3339 time as UTC to the minute: "2026-11-07 14:30 UTC". Anything else is returned as it came. */
export function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return `${parsed.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

/** An EDR date ("2026-12-01") as it is, and any other time as UTC to the minute. */
export function formatDate(value: string): string {
  return /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : formatTime(value);
}

export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

/**
 * The current time in the form a datetime-local field takes, in UTC. A field holds whole minutes, so the time
 * is rounded up: rounded down, a question for "now" would miss what was recorded in the last minute.
 */
export function nowForField(now: Date = new Date()): string {
  const minute = 60_000;
  return new Date(Math.ceil(now.getTime() / minute) * minute).toISOString().slice(0, 16);
}

/** The current time as RFC 3339, with no rounding. */
export function nowAsTime(now: Date = new Date()): string {
  return now.toISOString();
}

/** A datetime-local value, which is read as UTC, as an RFC 3339 time. Anything else is returned as it came. */
export function fieldToTime(value: string): string {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value) ? `${value}:00Z` : value;
}

/** An RFC 3339 time as a datetime-local value in UTC, or '' when it is not one. */
export function timeToField(value: string | null): string {
  if (value === null) return '';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? '' : parsed.toISOString().slice(0, 16);
}
