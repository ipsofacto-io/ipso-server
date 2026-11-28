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
// What a model found about a pending proposal and the decisions in force: a hint that changes nothing (ADR-0172).
export type ProposalRelations = Schemas['ProposalRelations'];
export type ProposalRelation = Schemas['ProposalRelation'];
export type CheckProposal = Omit<Schemas['CheckProposal'], 'spec'> & { spec: Json };
export type StoredVerdict = Omit<Schemas['StoredVerdict'], 'evidence'> & { evidence: Json };
export type AdvisoryPlace = Schemas['AdvisoryPlace'];
export type AdvisoryVerdict = Schemas['AdvisoryVerdict'];
export type AuditDecisions = Omit<Schemas['AuditDecisions'], 'decisions'> & { decisions: Decision[] };
// Q3 answers the decisions at a merge and the verdicts stored for its commit, which are null when no run was stored (ADR-0124).
export type AuditMerge = Omit<Schemas['AuditMerge'], 'decisions' | 'verdicts'> & { decisions: Decision[]; verdicts: StoredVerdict[] | null };
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
// The fingerprints of one repository for a decision that has grandfather terms (ADR-0052, ADR-0121).
export type BaselineRequest = Schemas['BaselineRequest'];
export type Baseline = Schemas['Baseline'];
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

// The invitations of the tenant (ADR-0127). An open invitation never holds its token: only the answer to create does.
export type Invitation = Schemas['Invitation'];
export type InvitationPage = Schemas['InvitationPage'];
export type InvitationRequest = Schemas['InvitationRequest'];
export type InvitationCreated = Schemas['InvitationCreated'];
export type InvitationRole = InvitationRequest['role'];

// The role bindings of the tenant (ADR-0128). scope_id is null when the binding covers the whole tenant.
export type RoleBinding = Schemas['RoleBinding'];
export type RoleBindingPage = Schemas['RoleBindingPage'];
export type RoleBindingRequest = Schemas['RoleBindingRequest'];

/** A sign-in provider the page may link to (GET /auth/providers). */
export interface ProviderInfo {
  id: string;
  kind: string;
}

/** Where POST /auth/invitation/{provider} says to send the browser: the first step of the provider's sign-in (ADR-0127). */
export interface InvitationStart {
  location: string;
}

/** One organization a verified person may pick at sign-in in multi-tenant mode (ADR-0171). */
export interface TenantChoice {
  id: string;
  name: string;
}

/** The pending sign-in choice returned by GET /auth/tenants (ADR-0171). */
export interface PendingTenants {
  tenants: TenantChoice[];
  flow: 'browser' | 'cli';
}

/** Where POST /auth/tenants says to send the browser after verifying the chosen tenant (ADR-0171). */
export interface TenantChoiceStart {
  location: string;
}

// Verifiability analysis, human proposals, and Decision Health (ADR-0161, ADR-0163).
export type VerifiabilityRequest = Schemas['VerifiabilityRequest'];
export type CandidatePremise = Schemas['CandidatePremise'];
export type CandidateCheck = Schemas['CandidateCheck'];
export type VerifiabilityDiagnosis = Schemas['VerifiabilityDiagnosis'];
export type HumanProposal = Omit<Schemas['HumanProposal'], 'payload'> & { payload: Json };
export type CreateHumanProposalRequest = Omit<Schemas['CreateHumanProposalRequest'], 'premises' | 'checks'> & {
  premises?: Json[];
  checks?: Json[];
};
export type CreateHumanProposalAnswer = Schemas['CreateHumanProposalAnswer'];
export type PremiseAlert = Schemas['PremiseAlert'];
export type HealthVerdictRef = Schemas['HealthVerdictRef'];
export type DecisionValidity = Schemas['DecisionValidity'];
export type ScopeCompliance = Schemas['ScopeCompliance'];
export type DecisionCompliance = Schemas['DecisionCompliance'];
export type DecisionHealth = Schemas['DecisionHealth'];
export type DecisionHealthPage = Schemas['DecisionHealthPage'];

