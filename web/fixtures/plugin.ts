import type { IncomingMessage, ServerResponse } from 'node:http';

import type { Plugin } from 'vite';

import { newFixtureState, respond } from './server.ts';

// A body over this is read no further: the stand-in answers 413 for it, as the server does.
const READ_LIMIT = (1 << 20) + 1;

async function bodyOf(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const piece = Buffer.from(chunk as Uint8Array);
    chunks.push(piece);
    size += piece.length;
    if (size >= READ_LIMIT) break;
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * `npm run fixtures` serves the app over the stand-in API of fixtures/server.ts, so a view can be built and looked at
 * with no database and no identity provider. Opening /auth/login/dex signs in, and POST /auth/logout signs out. A
 * write changes the state the plugin keeps until the server stops, so an answered draft leaves its queue.
 */
export function fixturesPlugin(): Plugin {
  const state = newFixtureState();
  const middleware = (request: IncomingMessage, response: ServerResponse, next: () => void) => {
    const url = request.url ?? '';
    if (!url.startsWith('/v1/') && !url.startsWith('/auth/')) return next();
    const method = request.method ?? 'GET';
    void (async () => {
      try {
        const body = method === 'POST' ? await bodyOf(request) : undefined;
        const reply = respond({ method, url, cookie: request.headers.cookie ?? '', contentType: request.headers['content-type'], body }, new Date(), state);
        response.statusCode = reply.status;
        for (const [name, value] of Object.entries(reply.headers)) response.setHeader(name, value);
        if (reply.raw !== undefined) return response.end(reply.raw);
        if (reply.body === undefined) return response.end();
        response.setHeader('Content-Type', 'application/json');
        response.end(JSON.stringify(reply.body));
      } catch {
        // A body that could not be read (the client left) is answered as the server would, and never stops the dev server.
        response.statusCode = 400;
        response.end();
      }
    })();
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
