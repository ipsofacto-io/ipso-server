import { useState, type FormEvent } from 'react';
import { Link } from 'react-router';

import { calls } from '../api/calls';
import { useResource, useWrite } from '../api/hooks';
import type { CandidateCheck, CandidatePremise, CreateHumanProposalRequest, VerifiabilityDiagnosis } from '../api/types';
import { Button, TextField } from '../brand';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { ModelLabel } from '../components/ModelLabel';
import { Notice } from '../components/Notice';
import { Page } from '../components/Page';
import { ScopePicker } from '../components/ScopePicker';
import { SelectField } from '../components/SelectField';
import type { Json } from '../lib/json';
import { decisionPath } from '../state/decision';
import { aYearAfter, CRITICALITIES, today, type Criticality } from '../state/edr';
import { scopesForLabels } from './Scopes';

interface LLMFixtureRow {
  name: string;
  expect: 'allow' | 'deny';
  input: string;
  expectedQuote: string;
}

interface DraftCheckRow {
  engine: 'opa' | 'semgrep' | 'checkov' | 'kyverno' | 'llm' | 'llm-advisory';
  target: string;
  ref: string;
  mode: 'block' | 'warn' | 'advise';
  maxAgeDays: string;
  rubric: string;
  fixtures: LLMFixtureRow[];
}

interface DraftPremiseRow {
  id: string;
  statement: string;
  every: string;
}

const DEFAULT_FIXTURES: LLMFixtureRow[] = [
  {
    name: 'compliant-example',
    expect: 'allow',
    input: '{"egress":[{"cidr":"10.0.0.0/8","port":443}]}',
    expectedQuote: '',
  },
  {
    name: 'violating-example',
    expect: 'deny',
    input: '{"egress":[{"cidr":"0.0.0.0/0","port":0}]}',
    expectedQuote: '0.0.0.0/0',
  },
];

function parseCandidateLLMSpec(raw: string | undefined): { rubric: string; fixtures: LLMFixtureRow[] } {
  if (!raw) return { rubric: '', fixtures: DEFAULT_FIXTURES.map((f) => ({ ...f })) };
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const rubric = typeof parsed.rubric === 'string' ? parsed.rubric : '';
    const fixturesRaw = Array.isArray(parsed.fixtures) ? parsed.fixtures : [];
    const fixtures: LLMFixtureRow[] = fixturesRaw
      .filter((item): item is Record<string, unknown> => typeof item === 'object' && item !== null)
      .map((item, idx) => ({
        name: typeof item.name === 'string' && item.name ? item.name : `case-${idx + 1}`,
        expect: item.expect === 'deny' ? 'deny' : 'allow',
        input: typeof item.input === 'string' ? item.input : '',
        expectedQuote: typeof item.expected_quote === 'string' ? item.expected_quote : '',
      }));
    return {
      rubric,
      fixtures: fixtures.length > 0 ? fixtures : DEFAULT_FIXTURES.map((f) => ({ ...f })),
    };
  } catch {
    return { rubric: '', fixtures: DEFAULT_FIXTURES.map((f) => ({ ...f })) };
  }
}

export function NewDecisionView() {
  const scopes = useResource((signal) => scopesForLabels(signal), []);
  const analyze = useWrite((req: { title: string; statement: string; context?: string }) => calls.analyzeVerifiability(req));
  const submitProposal = useWrite((req: CreateHumanProposalRequest) => calls.createHumanProposal(req));

  const start = today();
  const [title, setTitle] = useState('');
  const [statement, setStatement] = useState('');
  const [context, setContext] = useState('');
  const [owner, setOwner] = useState('team:platform');
  const [criticality, setCriticality] = useState<Criticality>('warning');
  const [reviewBy, setReviewBy] = useState(aYearAfter(start));
  const [pickedScopes, setPickedScopes] = useState<string[]>([]);
  const [approveNow, setApproveNow] = useState(false);

  const [diagnosis, setDiagnosis] = useState<VerifiabilityDiagnosis | null>(null);
  const [checks, setChecks] = useState<DraftCheckRow[]>([]);
  const [premises, setPremises] = useState<DraftPremiseRow[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [created, setCreated] = useState<{ proposalId: string; status: string; decisionId?: string } | null>(null);

  async function onAnalyze() {
    setFormError(null);
    if (!title.trim() || !statement.trim()) {
      setFormError('Enter both a title and a decision statement before checking verifiability.');
      return;
    }
    const res = await analyze.run({
      title: title.trim(),
      statement: statement.trim(),
      ...(context.trim() ? { context: context.trim() } : {}),
    });
    if (res.status === 'done') {
      setDiagnosis(res.result);
    }
  }

  function adoptCandidateCheck(candidate: CandidateCheck) {
    const engine = (candidate.engine as DraftCheckRow['engine']) || 'opa';
    const spec = parseCandidateLLMSpec(candidate.llm_spec);
    setChecks((prev) => [
      ...prev,
      {
        engine,
        target: candidate.target ?? (engine === 'llm' ? 'json-snapshot' : 'plan'),
        ref: candidate.ref ?? '',
        mode: (candidate.mode as DraftCheckRow['mode']) ?? 'warn',
        maxAgeDays: candidate.max_age_days ? String(candidate.max_age_days) : '7',
        rubric: spec.rubric || statement.trim(),
        fixtures: spec.fixtures,
      },
    ]);
  }

  function adoptCandidatePremise(candidate: CandidatePremise) {
    if (premises.some((p) => p.id === candidate.id)) return;
    setPremises((prev) => [
      ...prev,
      {
        id: candidate.id,
        statement: candidate.statement,
        every: String(candidate.every || 30),
      },
    ]);
  }

  function addBlankLLMCheck() {
    setChecks((prev) => [
      ...prev,
      {
        engine: 'llm',
        target: 'json-snapshot',
        ref: '',
        mode: 'warn',
        maxAgeDays: '7',
        rubric: statement.trim(),
        fixtures: DEFAULT_FIXTURES.map((f) => ({ ...f })),
      },
    ]);
  }

  function validateChecks(): string | null {
    for (const [idx, ch] of checks.entries()) {
      if (ch.maxAgeDays.trim() !== '') {
        const days = Number(ch.maxAgeDays);
        if (!Number.isInteger(days) || days < 1 || days > 365) {
          return `Check ${idx + 1}: max age days must be an integer between 1 and 365.`;
        }
      }
      if (ch.engine === 'llm') {
        if (!ch.rubric.trim()) {
          return `Check ${idx + 1}: an engine llm check requires a non-empty rubric.`;
        }
        if (ch.mode === 'block') {
          const hasAllow = ch.fixtures.some((f) => f.expect === 'allow' && f.input.trim() !== '');
          const hasDeny = ch.fixtures.some((f) => f.expect === 'deny' && f.input.trim() !== '');
          if (!hasAllow || !hasDeny) {
            return `Check ${idx + 1}: mode block on engine llm requires at least one allow fixture and one deny fixture.`;
          }
        }
      }
    }
    return null;
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    if (!title.trim() || !statement.trim()) {
      setFormError('Title and statement are required.');
      return;
    }
    if (pickedScopes.length === 0) {
      setFormError('Pick at least one scope.');
      return;
    }
    const checkErr = validateChecks();
    if (checkErr) {
      setFormError(checkErr);
      return;
    }

    const checksPayload: Json[] = checks.map((ch) => {
      const days = ch.maxAgeDays.trim() ? Number(ch.maxAgeDays) : undefined;
      const item: Json = {
        engine: ch.engine,
        target: ch.target,
        mode: ch.mode,
      };
      if (ch.ref.trim()) item.ref = ch.ref.trim();
      if (days !== undefined) item.max_age_days = days;
      if (ch.engine === 'llm') {
        item.llm_spec = {
          version: 1,
          target: ch.target,
          rubric: ch.rubric.trim(),
          fixtures: ch.fixtures.map((f) => ({
            name: f.name.trim() || 'fixture',
            expect: f.expect,
            input: f.input,
            ...(f.expectedQuote.trim() ? { expected_quote: f.expectedQuote.trim() } : {}),
          })),
        };
      }
      return item;
    });

    const premisesPayload: Json[] = premises.map((p) => ({
      id: p.id.trim(),
      statement: p.statement.trim(),
      every: Number(p.every) || 30,
    }));

    const out = await submitProposal.run({
      title: title.trim(),
      statement: statement.trim(),
      ...(context.trim() ? { context: context.trim() } : {}),
      owner: owner.trim() || 'team:platform',
      criticality,
      ...(reviewBy.trim() ? { review_by: reviewBy.trim() } : {}),
      scope_refs: pickedScopes,
      ...(checksPayload.length > 0 ? { checks: checksPayload } : {}),
      ...(premisesPayload.length > 0 ? { premises: premisesPayload } : {}),
      approve_now: approveNow,
    });
    if (out.status === 'done') {
      setCreated({
        proposalId: out.result.proposal_id,
        status: out.result.status,
        decisionId: out.result.decision_id,
      });
    }
  }

  const busy = analyze.status === 'sending' || submitProposal.status === 'sending';

  return (
    <Page
      title="New decision"
      intro="Write a decision, check whether its wording can be verified automatically, attach optional premises or checks, and submit it as a tracked proposal."
      actions={<Link to="/decisions">All decisions</Link>}
    >
      {created ? (
        <Notice tone="info" title={created.status === 'approved' ? 'Decision approved and recorded.' : 'Proposal submitted for review.'}>
          {created.decisionId ? (
            <p>
              Recorded in the registry. <Link to={decisionPath(created.decisionId)}>Open the decision</Link>.
            </p>
          ) : (
            <p className="mono">{`Proposal ${created.proposalId} is pending approval.`}</p>
          )}
        </Notice>
      ) : null}

      <form className="stack" onSubmit={onSubmit} noValidate aria-label="Define a decision">
        <fieldset className="fieldset" disabled={busy}>
          <legend className="ip-label">Statement and ownership</legend>
          <div className="form-row">
            <TextField label="Title" value={title} onChange={(e) => setTitle(e.target.value)} hint="Short imperative summary of what was decided." />
            <TextField label="Owner" mono value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="team:security" hint="The team accountable for this decision." />
          </div>
          <TextField
            label="Decision statement"
            value={statement}
            onChange={(e) => setStatement(e.target.value)}
            hint="State concrete invariants rather than vague preferences so automated checks can verify compliance."
          />
          <TextField
            label="Context"
            value={context}
            onChange={(e) => setContext(e.target.value)}
            hint="Optional background, constraints, and alternatives considered."
          />
          <div className="form-row">
            <SelectField label="Criticality" value={criticality} onChange={(e) => setCriticality(e.target.value as Criticality)}>
              {CRITICALITIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </SelectField>
            <TextField label="Review by" type="date" value={reviewBy} onChange={(e) => setReviewBy(e.target.value)} hint="Date when the decision must be reviewed." />
          </div>
          <div className="actions">
            <Button type="button" variant="secondary" size="sm" onClick={() => void onAnalyze()} disabled={busy}>
              {analyze.status === 'sending' ? 'Checking verifiability' : 'Check verifiability'}
            </Button>
            <Button type="button" variant="quiet" size="sm" onClick={addBlankLLMCheck} disabled={busy}>
              Add engine llm check
            </Button>
          </div>
        </fieldset>

        {analyze.status === 'failed' ? <ErrorNotice error={analyze.error} /> : null}

        {diagnosis ? (
          <section className="card" aria-label="Verifiability analysis">
            <header className="card-head">
              <h3 className="card-title">{`Verifiability: ${diagnosis.classification}`}</h3>
            </header>
            <p>{diagnosis.summary}</p>
            {diagnosis.ai_generated && diagnosis.model_id ? (
              <dl className="meta">
                <ModelLabel modelID={diagnosis.model_id} promptVersion={diagnosis.prompt_version} />
              </dl>
            ) : null}
            {diagnosis.suggestions.length > 0 ? (
              <div>
                <h4 className="ip-label">Suggestions</h4>
                <ul className="plain">
                  {diagnosis.suggestions.map((s) => (
                    <li key={s}>{s}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {diagnosis.candidate_checks.length > 0 ? (
              <div>
                <h4 className="ip-label">Suggested checks</h4>
                <ul className="plain">
                  {diagnosis.candidate_checks.map((candidate, idx) => (
                    <li key={`${candidate.engine}-${idx}`}>
                      <span className="mono">{`${candidate.engine} (${candidate.target ?? 'default'})`}</span>
                      {candidate.rationale ? ` - ${candidate.rationale} ` : ' '}
                      <Button type="button" variant="secondary" size="sm" onClick={() => adoptCandidateCheck(candidate)}>
                        {`Use ${candidate.engine} check`}
                      </Button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
            {diagnosis.candidate_premises.length > 0 ? (
              <div>
                <h4 className="ip-label">Suggested premises</h4>
                <ul className="plain">
                  {diagnosis.candidate_premises.map((premise) => (
                    <li key={premise.id}>
                      <span>{`${premise.statement} (${premise.id}) `}</span>
                      <Button type="button" variant="secondary" size="sm" onClick={() => adoptCandidatePremise(premise)}>
                        {`Use premise ${premise.id}`}
                      </Button>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>
        ) : null}

        {checks.length > 0 ? (
          <section className="card" aria-label="Configured checks">
            <h3 className="card-title">Checks</h3>
            {checks.map((ch, idx) => (
              <div key={idx} className="stack">
                <div className="form-row">
                  <SelectField
                    label={`Check ${idx + 1} engine`}
                    value={ch.engine}
                    onChange={(e) => {
                      const next = e.target.value as DraftCheckRow['engine'];
                      setChecks((prev) => prev.map((row, i) => (i === idx ? { ...row, engine: next } : row)));
                    }}
                  >
                    {(['opa', 'semgrep', 'checkov', 'kyverno', 'llm', 'llm-advisory'] as const).map((eng) => (
                      <option key={eng} value={eng}>
                        {eng}
                      </option>
                    ))}
                  </SelectField>
                  <SelectField
                    label={`Check ${idx + 1} mode`}
                    value={ch.mode}
                    onChange={(e) => {
                      const next = e.target.value as DraftCheckRow['mode'];
                      setChecks((prev) => prev.map((row, i) => (i === idx ? { ...row, mode: next } : row)));
                    }}
                  >
                    <option value="block">block</option>
                    <option value="warn">warn</option>
                    <option value="advise">advise</option>
                  </SelectField>
                  <TextField
                    label={`Check ${idx + 1} target`}
                    mono
                    value={ch.target}
                    onChange={(e) => setChecks((prev) => prev.map((row, i) => (i === idx ? { ...row, target: e.target.value } : row)))}
                  />
                  <TextField
                    label={`Check ${idx + 1} max age days`}
                    mono
                    value={ch.maxAgeDays}
                    onChange={(e) => setChecks((prev) => prev.map((row, i) => (i === idx ? { ...row, maxAgeDays: e.target.value } : row)))}
                  />
                </div>
                {ch.engine === 'llm' ? (
                  <div className="stack">
                    <TextField
                      label={`Check ${idx + 1} rubric`}
                      value={ch.rubric}
                      onChange={(e) => setChecks((prev) => prev.map((row, i) => (i === idx ? { ...row, rubric: e.target.value } : row)))}
                      hint="Authoritative rubric evaluated with verbatim quote verification. Blocking mode requires allow and deny fixtures."
                    />
                    {ch.fixtures.map((fx, fxIdx) => (
                      <div key={fxIdx} className="form-row">
                        <TextField
                          label={`Check ${idx + 1} fixture ${fxIdx + 1} name`}
                          mono
                          value={fx.name}
                          onChange={(e) =>
                            setChecks((prev) =>
                              prev.map((row, i) =>
                                i === idx
                                  ? {
                                      ...row,
                                      fixtures: row.fixtures.map((f, j) => (j === fxIdx ? { ...f, name: e.target.value } : f)),
                                    }
                                  : row,
                              ),
                            )
                          }
                        />
                        <SelectField
                          label={`Check ${idx + 1} fixture ${fxIdx + 1} expect`}
                          value={fx.expect}
                          onChange={(e) => {
                            const exp = e.target.value as 'allow' | 'deny';
                            setChecks((prev) =>
                              prev.map((row, i) =>
                                i === idx
                                  ? {
                                      ...row,
                                      fixtures: row.fixtures.map((f, j) => (j === fxIdx ? { ...f, expect: exp } : f)),
                                    }
                                  : row,
                              ),
                            );
                          }}
                        >
                          <option value="allow">allow</option>
                          <option value="deny">deny</option>
                        </SelectField>
                        <TextField
                          label={`Check ${idx + 1} fixture ${fxIdx + 1} input`}
                          mono
                          value={fx.input}
                          onChange={(e) =>
                            setChecks((prev) =>
                              prev.map((row, i) =>
                                i === idx
                                  ? {
                                      ...row,
                                      fixtures: row.fixtures.map((f, j) => (j === fxIdx ? { ...f, input: e.target.value } : f)),
                                    }
                                  : row,
                              ),
                            )
                          }
                        />
                      </div>
                    ))}
                  </div>
                ) : null}
                <div>
                  <Button
                    type="button"
                    variant="quiet"
                    size="sm"
                    onClick={() => setChecks((prev) => prev.filter((_, i) => i !== idx))}
                  >
                    {`Remove check ${idx + 1}`}
                  </Button>
                </div>
              </div>
            ))}
          </section>
        ) : null}

        {scopes.status === 'loading' ? <Loading what="scopes" /> : null}
        {scopes.status === 'error' ? <ErrorNotice error={scopes.error} onRetry={scopes.reload} /> : null}
        {scopes.status === 'ready' ? (
          <ScopePicker
            legend="Scopes"
            hint="Select every organization, service, repository, or environment where this decision applies."
            scopes={scopes.data}
            selected={pickedScopes}
            onChange={setPickedScopes}
          />
        ) : null}

        <label className="checkbox-row">
          <input type="checkbox" checked={approveNow} onChange={(e) => setApproveNow(e.target.checked)} disabled={busy} />
          <span>Approve and record immediately (requires decision approval permission on all selected scopes)</span>
        </label>

        {formError ? (
          <p role="alert" className="error-text">
            {formError}
          </p>
        ) : null}
        {submitProposal.status === 'failed' ? <ErrorNotice error={submitProposal.error} /> : null}

        <div className="actions">
          <Button type="submit" variant="primary" disabled={busy || scopes.status !== 'ready'}>
            {submitProposal.status === 'sending' ? 'Saving' : approveNow ? 'Approve and record decision' : 'Submit proposal'}
          </Button>
        </div>
      </form>
    </Page>
  );
}
