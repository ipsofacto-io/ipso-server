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

/** A sign-in provider the page may link to (GET /auth/providers). */
export interface ProviderInfo {
  id: string;
  kind: string;
}
