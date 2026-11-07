// The licence gate of the web app. What ships to a browser is every package of package-lock.json that is not a
// dev dependency, so each of those has to carry a licence on the list. A dev dependency (the build, the tests)
// never reaches a person, so it is counted and not judged. go-licenses covers the Go side and knows no npm.

export const ALLOWED: ReadonlySet<string> = new Set(['MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'OFL-1.1']);

export interface LockPackage {
  license?: unknown;
  dev?: boolean;
}

export interface Lock {
  lockfileVersion?: number;
  packages?: Record<string, LockPackage>;
}

/** An SPDX expression is allowed when every AND term has an allowed OR alternative. A name outside SPDX is not. */
export function isAllowed(license: string): boolean {
  const expression = license.replace(/^\(|\)$/g, '');
  return expression.split(/\s+AND\s+/).every((term) => term.split(/\s+OR\s+/).some((alternative) => ALLOWED.has(alternative.trim())));
}

export interface Report {
  shipped: number;
  offenders: string[];
}

export function check(lock: Lock): Report {
  const packages = Object.entries(lock.packages ?? {}).filter(([name]) => name !== '');
  const shipped = packages.filter(([, pkg]) => pkg.dev !== true);
  const offenders = shipped.flatMap(([name, pkg]) => {
    const license = typeof pkg.license === 'string' ? pkg.license : null;
    return license !== null && isAllowed(license) ? [] : [`${name.replace(/^.*node_modules\//, '')}: ${license ?? 'no licence in the lockfile'}`];
  });
  return { shipped: shipped.length, offenders };
}
