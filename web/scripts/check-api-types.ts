import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// src/api/schema.d.ts is generated from api/openapi.yaml and committed. A change to the document that is not
// followed by `npm run api:types` leaves the app reading the old shapes, so CI fails here.
const root = new URL('..', import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), 'ipso-api-types-'));
try {
  const generated = join(dir, 'schema.d.ts');
  execFileSync(join(root, 'node_modules/.bin/openapi-typescript'), [join(root, '../api/openapi.yaml'), '-o', generated], { stdio: 'ignore' });
  if (readFileSync(generated, 'utf8') !== readFileSync(join(root, 'src/api/schema.d.ts'), 'utf8')) {
    console.error('::error::src/api/schema.d.ts differs from api/openapi.yaml. Run `npm run api:types` in web/ and commit the result.');
    process.exit(1);
  }
  console.log('src/api/schema.d.ts matches api/openapi.yaml.');
} finally {
  rmSync(dir, { recursive: true, force: true });
}
