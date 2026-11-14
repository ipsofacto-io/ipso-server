// Records for `npm run fixtures` and for the tests: a small tenant with a decision in every state of the
// lifecycle, a supersession, waivers at different deadlines, drafts in all three queues, and CI verdicts.
// Times that matter to a view (when a waiver ends) are relative to `now`, so the views read the same on any day.
import type {
  AgentProposal,
  CheckProposal,
  Decision,
  PremiseHost,
  PremiseReason,
  Proposal,
  Scope,
  StoredVerdict,
  Waiver,
} from '../src/api/types.ts';

const uuid = (n: number): string => `0194f2a0-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ulid = (n: number): string => `01JB${String(n).padStart(2, '0')}5QEHVBS2Q67NPD1BPZ2E`.slice(0, 26);
const day = 24 * 60 * 60 * 1000;
const iso = (date: Date): string => date.toISOString().replace('.000Z', 'Z');

export const ids = {
  org: uuid(1),
  service: uuid(2),
  repo: uuid(3),
  paths: uuid(4),
  prod: uuid(5),
  useTls: uuid(101),
  pinImages: uuid(102),
  adminPort: uuid(103),
  legacyFtp: uuid(104),
  sftpOnly: uuid(105),
  postgresOnly: uuid(106),
  noEval: uuid(107),
  oldQueue: uuid(108),
};

function body(n: number, fields: Record<string, unknown>): Record<string, unknown> {
  return { edr: 1, id: ulid(n), owner: 'team:platform', criticality: 'blocking', sources: [], tags: [], supersedes: [], checks: [], ...fields };
}

export const decisions: Decision[] = [
  {
    id: ids.oldQueue,
    version: 1,
    body: body(8, { slug: 'retire-the-old-queue', title: 'Retire the old message queue', status: 'deprecated', owner: 'team:platform', criticality: 'advisory', review_by: '2027-03-01', valid_from: '2025-09-01', valid_to: null, scope: [{ org: 'acme' }] }),
  },
  {
    id: ids.noEval,
    version: 1,
    body: body(7, {
      slug: 'no-dynamic-code-execution',
      title: 'No dynamic code execution in services',
      status: 'proposed',
      owner: 'team:appsec',
      criticality: 'warning',
      review_by: '2027-05-01',
      valid_from: '2026-11-01',
      valid_to: null,
      scope: [{ org: 'acme', paths: ['services/**'] }],
      sources: [{ type: 'pr', url: 'https://github.com/acme/platform/pull/212' }],
    }),
  },
  {
    id: ids.postgresOnly,
    version: 2,
    body: body(6, { slug: 'postgres-only', title: 'PostgreSQL is the only primary store', status: 'rejected', owner: 'team:data', criticality: 'blocking', review_by: '2026-12-15', valid_from: '2026-06-01', valid_to: '2026-09-30', scope: [{ repo: 'acme/payments' }] }),
  },
  {
    id: ids.sftpOnly,
    version: 1,
    body: body(5, {
      slug: 'sftp-only-file-transfer',
      title: 'File transfer uses SFTP only',
      status: 'verified',
      owner: 'team:security',
      criticality: 'blocking',
      review_by: '2027-06-01',
      valid_from: '2026-06-01',
      valid_to: null,
      supersedes: ['replace-legacy-ftp'],
      scope: [{ org: 'acme' }],
      checks: [{ engine: 'semgrep', ref: 'rules/no-ftp.yaml', mode: 'block' }],
    }),
  },
  {
    id: ids.legacyFtp,
    version: 3,
    body: body(4, { slug: 'replace-legacy-ftp', title: 'Replace the legacy FTP gateway', status: 'superseded', owner: 'team:security', criticality: 'blocking', review_by: '2026-09-01', valid_from: '2025-01-01', valid_to: '2026-06-01', scope: [{ org: 'acme' }] }),
  },
  {
    id: ids.adminPort,
    version: 1,
    body: body(3, {
      slug: 'admin-port-from-bastion',
      title: 'Admin ports are open only from the bastion',
      status: 'needs-review',
      owner: 'team:security',
      criticality: 'blocking',
      review_by: '2026-10-01',
      valid_from: '2026-06-01',
      valid_to: null,
      scope: [{ org: 'acme', env: ['prod'] }],
      checks: [{ engine: 'checkov', ref: 'CKV_AWS_24', mode: 'block' }],
      premises: [{ id: 'bastion-exists', statement: 'The bastion host accepts connections from the office network.', every: 30, probe: { type: 'http' } }],
    }),
  },
  {
    id: ids.pinImages,
    version: 1,
    body: body(2, {
      slug: 'pin-base-images',
      title: 'Base images are pinned by digest',
      status: 'accepted',
      owner: 'team:platform',
      criticality: 'warning',
      review_by: '2027-01-15',
      valid_from: '2026-09-01',
      valid_to: null,
      scope: [{ repo: 'acme/payments', paths: ['Dockerfile', 'deploy/**'] }],
      checks: [{ engine: 'opa', target: 'dockerfile', mode: 'warn' }],
      tags: ['supply-chain'],
    }),
  },
  {
    id: ids.useTls,
    version: 2,
    body: body(1, {
      slug: 'use-tls',
      title: 'Public ingress terminates TLS 1.2 or later',
      status: 'verified',
      owner: 'team:security',
      criticality: 'blocking',
      review_by: '2027-02-01',
      valid_from: '2026-01-01',
      valid_to: null,
      scope: [{ org: 'acme', env: ['prod', 'staging'] }],
      checks: [
        { engine: 'checkov', ref: 'CKV_AWS_103', mode: 'block' },
        { engine: 'kyverno', ref: 'require-tls-ingress', mode: 'block' },
      ],
      sources: [
        { type: 'pr', url: 'https://github.com/acme/platform/pull/70' },
        { type: 'note', url: 'javascript:alert(1)' },
      ],
      tags: ['network', 'tls'],
      premises: [{ id: 'tls-min-version', statement: 'The status page reports TLS 1.2 as the lowest version served.', every: 7, probe: { type: 'http' } }],
    }),
  },
];

export const scopes: Scope[] = [
  { id: ids.prod, parent_id: ids.repo, kind: 'env', selector: 'prod' },
  { id: ids.paths, parent_id: ids.repo, kind: 'path', selector: 'deploy/**' },
  { id: ids.repo, parent_id: ids.service, kind: 'repo', selector: 'acme/payments' },
  { id: ids.service, parent_id: ids.org, kind: 'service', selector: 'payments' },
  { id: ids.org, parent_id: null, kind: 'org', selector: 'acme' },
];

export function waivers(now: Date): Waiver[] {
  return [
    { id: uuid(203), decision_id: ids.useTls, scope_id: ids.prod, ticket_ref: 'SEC-482', valid_from: iso(new Date(now.getTime() - 30 * day)), expires_at: iso(new Date(now.getTime() + 40 * day)) },
    { id: uuid(202), decision_id: ids.adminPort, scope_id: ids.repo, ticket_ref: 'OPS-1190', valid_from: iso(new Date(now.getTime() - 9 * day)), expires_at: iso(new Date(now.getTime() + 3 * day)) },
    { id: uuid(201), decision_id: ids.pinImages, scope_id: ids.paths, ticket_ref: 'PLAT-77', valid_from: iso(new Date(now.getTime() - 2 * day)), expires_at: iso(new Date(now.getTime() + 0.5 * day)) },
  ];
}

export function proposals(now: Date): Proposal[] {
  return [
    {
      id: uuid(302),
      kind: 'decision',
      origin: 'llm',
      status: 'pending',
      trust_level: 'untrusted',
      payload: { title: 'Services read secrets from the vault, not from environment files', statement: 'Secrets are read from the vault at start.' },
      confidence: 0.82,
      model_id: 'mistral-large-latest',
      prompt_version: 'pr-decision-v3',
      repo: 'acme/payments',
      pr_number: 412,
      source_url: 'https://github.com/acme/payments/pull/412',
      captured_at: iso(new Date(now.getTime() - 3 * 60 * 60 * 1000)),
    },
    {
      id: uuid(301),
      kind: 'decision',
      origin: 'llm',
      status: 'pending',
      trust_level: 'untrusted',
      payload: { slug: 'retry-with-backoff', statement: '<script>alert("not run")</script> Retries use exponential backoff.' },
      confidence: 0.54,
      model_id: 'mistral-large-latest',
      prompt_version: 'pr-decision-v3',
      repo: 'acme/ledger',
      pr_number: 98,
      source_url: 'javascript:alert(1)',
      captured_at: iso(new Date(now.getTime() - 26 * 60 * 60 * 1000)),
    },
  ];
}

export function agentProposals(now: Date): AgentProposal[] {
  return [
    {
      id: uuid(401),
      principal_id: uuid(900),
      status: 'pending',
      payload: { title: 'Public endpoints need rate limits', criticality: 'warning' },
      captured_at: iso(new Date(now.getTime() - 5 * 60 * 60 * 1000)),
    },
  ];
}

export function checkProposals(now: Date): CheckProposal[] {
  return [
    {
      id: uuid(501),
      status: 'pending',
      decision_id: ids.useTls,
      decision_version: 2,
      engine: 'opa',
      target: 'agent-edit',
      spec: { deny: 'http:// listener in a Terraform file' },
      rego: 'package ipso.agent_edit\n\ndeny contains msg if {\n  input.path == "main.tf"\n  contains(input.after, "http://")\n  msg := "ingress must terminate TLS"\n}\n',
      fixtures: [{ name: 'allows https' }, { name: 'denies http' }],
      repaired: true,
      model_id: 'mistral-large-latest',
      prompt_version: 'check-draft-v2',
      captured_at: iso(new Date(now.getTime() - 50 * 60 * 1000)),
    },
  ];
}

/** The open review reasons (ADR-0117). The observed value of the first is markup, to show that the app renders it as text. */
export function premiseReasons(now: Date): PremiseReason[] {
  return [
    {
      id: uuid(802),
      decision_id: ids.useTls,
      premise_id: 'tls-min-version',
      opened_at: iso(new Date(now.getTime() - 3 * 60 * 60 * 1000)),
      url: 'http://status.example.com/tls.json',
      pointer: '/tls/minimum',
      expected: '1.2',
      observed: '<img src=x onerror="alert(1)">',
    },
    {
      id: uuid(801),
      decision_id: ids.adminPort,
      premise_id: 'bastion-exists',
      opened_at: iso(new Date(now.getTime() - 30 * 60 * 60 * 1000)),
      url: 'https://status.example.com/bastion.json',
      pointer: '/reachable',
      expected: true,
      observed: false,
    },
  ];
}

/** The rows of the allowlist, oldest first. The latest row of a host decides, so status.example.com is allowed again. */
export const premiseHostRows: PremiseHost[] = [
  { id: uuid(811), host: 'status.example.com', allowed: false },
  { id: uuid(812), host: 'status.example.com', allowed: true },
  { id: uuid(813), host: 'legacy.example.com', allowed: false },
];

export function verdicts(now: Date): StoredVerdict[] {
  const base = {
    upload_id: uuid(700),
    repo: 'acme/payments',
    sha: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
    ref: 'refs/heads/main',
    event: 'push',
    workflow_ref: 'acme/payments/.github/workflows/ipso.yml@refs/heads/main',
    check: 'checkov' as const,
    env: 'prod',
    ipso_version: '0.5.0',
    build_sha256: 'a'.repeat(64),
    sarif_sha256: null,
    evidence: {},
    // No digest came with the run, so there is no reading against a recorded baseline.
    baseline: null as StoredVerdict['baseline'],
    // A pass has nothing to waive, so it has no reading against the recorded waivers (ADR-0123).
    waiver: null as StoredVerdict['waiver'],
  };
  const day = 24 * 60 * 60 * 1000;
  const notWaived: StoredVerdict['waiver'] = { result: 'fail', expires_at: null };
  return [
    { ...base, id: uuid(603), decision_id: ulid(1), slug: 'use-tls', check_index: 0, mode: 'block', result: 'pass', violations: 0, run_id: 9912345, run_attempt: 1, run_url: 'https://github.com/acme/payments/actions/runs/9912345', evaluated_at: iso(new Date(now.getTime() - 2 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 2 * 60 * 60 * 1000 + 4000)) },
    { ...base, id: uuid(602), decision_id: ulid(1), slug: 'use-tls', check_index: 1, mode: 'block', result: 'fail', violations: 2, waiver: notWaived, run_id: 9911876, run_attempt: 2, run_url: 'https://github.com/acme/payments/actions/runs/9911876', evaluated_at: iso(new Date(now.getTime() - 27 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 27 * 60 * 60 * 1000 + 4000)) },
    { ...base, id: uuid(601), decision_id: ulid(1), slug: 'use-tls', check_index: 0, mode: 'warn', result: 'waived', violations: 1, waiver: { result: 'waived', expires_at: iso(new Date(now.getTime() + 20 * day)) }, run_id: 9910001, run_attempt: 1, run_url: 'https://github.com/acme/payments/actions/runs/9910001', evaluated_at: iso(new Date(now.getTime() - 80 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 80 * 60 * 60 * 1000 + 4000)) },
    // The run reported a failure and every digest it sent is in the recorded baseline (ADR-0122).
    { ...base, id: uuid(600), decision_id: ulid(1), slug: 'use-tls', check_index: 2, mode: 'block', result: 'fail', violations: 3, baseline: { result: 'waived(baseline)', fingerprints: 3, waived: 3 }, waiver: notWaived, run_id: 9909002, run_attempt: 1, run_url: 'https://github.com/acme/payments/actions/runs/9909002', evaluated_at: iso(new Date(now.getTime() - 100 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 100 * 60 * 60 * 1000 + 4000)) },
    // The run waived its violations with its local baseline, which nobody recorded on the server.
    { ...base, id: uuid(599), decision_id: ulid(1), slug: 'use-tls', check_index: 3, mode: 'block', result: 'waived', violations: 2, baseline: { result: 'fail', fingerprints: 2, waived: 0 }, waiver: notWaived, run_id: 9909001, run_attempt: 1, run_url: 'https://github.com/acme/payments/actions/runs/9909001', evaluated_at: iso(new Date(now.getTime() - 120 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 120 * 60 * 60 * 1000 + 4000)) },
    // The run reported a failure and a waiver recorded on the server covers the repository and the environment (ADR-0123).
    { ...base, id: uuid(598), decision_id: ulid(1), slug: 'use-tls', check_index: 4, mode: 'block', result: 'fail', violations: 1, waiver: { result: 'waived', expires_at: iso(new Date(now.getTime() + 30 * day)) }, run_id: 9909000, run_attempt: 1, run_url: 'https://github.com/acme/payments/actions/runs/9909000', evaluated_at: iso(new Date(now.getTime() - 140 * 60 * 60 * 1000)), recorded_at: iso(new Date(now.getTime() - 140 * 60 * 60 * 1000 + 4000)) },
  ];
}
