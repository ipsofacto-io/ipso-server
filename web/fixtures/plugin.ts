import type { Plugin } from 'vite';

import { respond } from './server.ts';

/**
 * `npm run fixtures` serves the app over the stand-in API of fixtures/server.ts, so a view can be built and looked at
 * with no database and no identity provider. Opening /auth/login/dex signs in, and POST /auth/logout signs out.
 */
export function fixturesPlugin(): Plugin {
  const middleware = (request: { url?: string; method?: string; headers: { cookie?: string } }, response: {
    statusCode: number;
    setHeader(name: string, value: string): void;
    end(body?: string): void;
  }, next: () => void) => {
    const url = request.url ?? '';
    if (!url.startsWith('/v1/') && !url.startsWith('/auth/')) return next();
    const reply = respond({ method: request.method ?? 'GET', url, cookie: request.headers.cookie ?? '' });
    response.statusCode = reply.status;
    for (const [name, value] of Object.entries(reply.headers)) response.setHeader(name, value);
    if (reply.body === undefined) return response.end();
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify(reply.body));
  };
  return {
    name: 'ipso-fixtures',
    configureServer(server) {
      server.middlewares.use(middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use(middleware);
    },
  };
}
