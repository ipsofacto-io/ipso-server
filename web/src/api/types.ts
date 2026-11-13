import type { components } from './schema';
import type { Json } from '../lib/json';

type Schemas = components['schemas'];

// The OpenAPI document types a record as an open object, which TypeScript reads as an object with no
// property. The app reads a record through lib/json, so those fields are `Json` here.
export type Decision = Omit<Schemas['Decision'], 'body'> & { body: Json };
export type DecisionPage = Omit<Schemas['DecisionPage'], 'decisions'> & { decisions: Decision[] };
export type Scope = Schemas['Scope'];
export type ScopePage = Schemas['ScopePage'];
export type Waiver = Schemas['Waiver'];
export type WaiverPage = Schemas['WaiverPage'];
export type Proposal = Omit<Schemas['Proposal'], 'payload'> & { payload: Json };
export type AgentProposal = Omit<Schemas['AgentProposal'], 'payload'> & { payload: Json };
export type CheckProposal = Omit<Schemas['CheckProposal'], 'spec'> & { spec: Json };
export type StoredVerdict = Omit<Schemas['StoredVerdict'], 'evidence'> & { evidence: Json };
export type AuditDecisions = Omit<Schemas['AuditDecisions'], 'decisions'> & { decisions: Decision[] };
export type AuditBeliefs = {
  added: Decision[];
  removed: Decision[];
  changed: { id: string; then: Decision; now: Decision }[];
};
export type AuditChain = Schemas['AuditChain'];
export type AuditWaivers = Schemas['AuditWaivers'];

// The writes (ADR-0109). The decision an approval writes is an open object that the server checks, so it is `Json`.
export type DecisionDraft = Omit<Schemas['DecisionDraft'], 'body'> & { body: Json };
export type ApprovalRequest = Omit<Schemas['ApprovalRequest'], 'decision'> & { decision?: DecisionDraft };
export type Approval = Schemas['Approval'];
export type WaiverRequest = Schemas['WaiverRequest'];
export type SupersessionRequest = Schemas['SupersessionRequest'];
export type Supersession = Schemas['Supersession'];
export type GrandfatherRequest = Schemas['GrandfatherRequest'];
export type GrandfatherPeriod = Schemas['GrandfatherPeriod'];
// The answer to a drafted check names an outcome and writes no decision (ADR-0116, ADR-0118).
export type CheckApprovalRequest = Schemas['CheckApprovalRequest'];
export type CheckApproval = Schemas['CheckApproval'];

// The premise review reasons and the allowlist (ADR-0109, ADR-0117, ADR-0119). The expected and the observed value are
// any JSON value, and the observed one came from a public URL: the app only shows them as text.
export type PremiseReason = Omit<Schemas['PremiseReason'], 'expected' | 'observed'> & { expected: unknown; observed: unknown };
export type PremiseHost = Schemas['PremiseHost'];
export type PremiseHostRequest = Schemas['PremiseHostRequest'];
export type Clearance = Schemas['Clearance'];
export type ClearanceRequest = Schemas['ClearanceRequest'];

// The export of the tenant (ADR-0111, ADR-0115).
export type Export = Schemas['Export'];
export type ExportRequest = Schemas['ExportRequest'];

/** A sign-in provider the page may link to (GET /auth/providers). */
export interface ProviderInfo {
  id: string;
  kind: string;
}
