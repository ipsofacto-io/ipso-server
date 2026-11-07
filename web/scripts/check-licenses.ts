import { readFileSync } from 'node:fs';

import { check, type Lock } from './licenses.ts';

const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8')) as Lock;
const report = check(lock);

// The check reads one shape of lockfile and fails only when it finds an offender. It would pass for any other
// shape, so first require what it is meant to see: lockfile version 3 and the packages the app ships.
if (lock.lockfileVersion !== 3 || report.shipped === 0) {
  console.error('::error::package-lock.json is not a lockfile of version 3 with packages that ship, so the format may have changed');
  process.exit(1);
}
if (report.offenders.length > 0) {
  console.error(`::error::Packages that ship in the web app with a licence outside the list:\n${report.offenders.map((line) => `  ${line}`).join('\n')}`);
  process.exit(1);
}
console.log(`${report.shipped} packages ship in the web app, and every licence is on the list.`);
