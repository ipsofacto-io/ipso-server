export type Query = Readonly<Record<string, string | number | undefined>>;

/**
 * An answer that is not a 2xx. `status` 0 means the request got no answer at all. `code` is the closed error
 * code of the API ("rate limited", "not found") or of /auth ("unknown_login"), and is never shown to a person
 * as it came: the views say it in words.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter: number | null;
  readonly issuer: string | null;
  readonly subject: string | null;

  constructor(init: { status: number; code: string; retryAfter?: number | null; issuer?: string | null; subject?: string | null }) {
    super(`${init.status} ${init.code}`);
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.retryAfter = init.retryAfter ?? null;
    this.issuer = init.issuer ?? null;
    this.subject = init.subject ?? null;
  }
}

export interface Api {
  getJSON<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T>;
  /** An unsafe call with no body, such as POST /auth/logout. */
  post(path: string, signal?: AbortSignal): Promise<void>;
}

export interface ApiOptions {
  /** Prefixed to every path. The browser uses '' (the page's own origin); the contract test names a mock server. */
  base?: string;
  /** Sent with every request. The browser sends its cookie by itself; the contract test names one. */
  headers?: Readonly<Record<string, string>>;
}

export function createApi({ base = '', headers = {} }: ApiOptions = {}): Api {
  async function send(method: 'GET' | 'POST', path: string, query: Query, signal?: AbortSignal): Promise<Response> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== '') params.set(key, String(value));
    }
    const text = params.toString();
    let response: Response;
    try {
      response = await fetch(`${base}${path}${text === '' ? '' : `?${text}`}`, {
        method,
        headers: { Accept: 'application/json', ...headers },
        cache: 'no-store',
        credentials: 'same-origin',
        redirect: 'error',
        ...(signal ? { signal } : {}),
      });
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new ApiError({ status: 0, code: 'network' });
    }
    if (!response.ok) throw await refusal(response);
    return response;
  }

  return {
    async getJSON<T>(path: string, query: Query = {}, signal?: AbortSignal): Promise<T> {
      const response = await send('GET', path, query, signal);
      try {
        return (await response.json()) as T;
      } catch {
        throw new ApiError({ status: response.status, code: 'internal' });
      }
    },
    async post(path: string, signal?: AbortSignal): Promise<void> {
      await send('POST', path, {}, signal);
    },
  };
}

async function refusal(response: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    // An answer with no JSON body (a proxy's page) is an error with no code.
  }
  const fields = typeof body === 'object' && body !== null ? (body as Record<string, unknown>) : {};
  const retry = Number(response.headers.get('Retry-After'));
  return new ApiError({
    status: response.status,
    code: typeof fields.error === 'string' ? fields.error : 'internal',
    retryAfter: Number.isFinite(retry) && retry > 0 ? retry : null,
    issuer: typeof fields.issuer === 'string' ? fields.issuer : null,
    subject: typeof fields.subject === 'string' ? fields.subject : null,
  });
}

export function toApiError(error: unknown): ApiError {
  return error instanceof ApiError ? error : new ApiError({ status: 0, code: 'network' });
}

export const api: Api = createApi();
