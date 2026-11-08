import { api as defaultApi, type Api } from './client';
import type {
  AgentProposal,
  Approval,
  ApprovalRequest,
  AuditBeliefs,
  AuditChain,
  AuditDecisions,
  AuditWaivers,
  CheckProposal,
  DecisionPage,
  GrandfatherPeriod,
  GrandfatherRequest,
  Proposal,
  ProviderInfo,
  ScopePage,
  StoredVerdict,
  Supersession,
  SupersessionRequest,
  Waiver,
  WaiverPage,
  WaiverRequest,
} from './types';

/** The paging of every list: pass the last id of a page as `before` to read the next one (ADR-0090). */
export type Paging = {
  limit?: number;
  before?: string;
};
/** The two times of a bitemporal read. Absent means now. */
export type Times = {
  valid?: string;
  known?: string;
};
export type Subject = {
  repo: string;
  path?: string;
  env?: string;
};

/** Every route the web app calls, and no other. The contract test (ADR-0091) calls them through the same code. */
export function makeCalls(api: Api) {
  return {
    listDecisions: (q: Times & Paging = {}, signal?: AbortSignal) => api.getJSON<DecisionPage>('/v1/decisions', q, signal),
    getDecision: (ref: string, q: Times = {}, signal?: AbortSignal) =>
      api.getJSON<DecisionPage>(`/v1/decisions/${encodeURIComponent(ref)}`, q, signal),
    listScopes: (q: { known?: string } & Paging = {}, signal?: AbortSignal) => api.getJSON<ScopePage>('/v1/scopes', q, signal),
    listWaivers: (q: Times & Paging = {}, signal?: AbortSignal) => api.getJSON<WaiverPage>('/v1/waivers', q, signal),
    listProposals: (q: Paging = {}, signal?: AbortSignal) => api.getJSON<{ proposals: Proposal[] }>('/v1/proposals', q, signal),
    listAgentProposals: (q: Paging = {}, signal?: AbortSignal) =>
      api.getJSON<{ agent_proposals: AgentProposal[] }>('/v1/agent-proposals', q, signal),
    listCheckProposals: (q: Paging = {}, signal?: AbortSignal) =>
      api.getJSON<{ check_proposals: CheckProposal[] }>('/v1/check-proposals', q, signal),
    listVerdicts: (q: { repo?: string; decision?: string } & Paging = {}, signal?: AbortSignal) =>
      api.getJSON<{ verdicts: StoredVerdict[] }>('/v1/verdicts', q, signal),
    auditDecisions: (q: Subject & { valid: string; known: string }, signal?: AbortSignal) =>
      api.getJSON<AuditDecisions>('/v1/audit/decisions', q, signal),
    auditBeliefs: (q: Subject & { valid: string; then: string; now: string }, signal?: AbortSignal) =>
      api.getJSON<AuditBeliefs>('/v1/audit/beliefs', q, signal),
    auditMerges: (q: Subject & { at: string; known?: string }, signal?: AbortSignal) =>
      api.getJSON<AuditDecisions>('/v1/audit/merges', q, signal),
    auditSupersessions: (decisionID: string, q: { known: string }, signal?: AbortSignal) =>
      api.getJSON<AuditChain>(`/v1/audit/supersessions/${encodeURIComponent(decisionID)}`, q, signal),
    auditWaivers: (q: { known: string; now: string }, signal?: AbortSignal) => api.getJSON<AuditWaivers>('/v1/audit/waivers', q, signal),
    approveProposal: (id: string, request: ApprovalRequest, signal?: AbortSignal) =>
      api.postJSON<Approval>(`/v1/proposals/${encodeURIComponent(id)}/approval`, request, signal),
    approveAgentProposal: (id: string, request: ApprovalRequest, signal?: AbortSignal) =>
      api.postJSON<Approval>(`/v1/agent-proposals/${encodeURIComponent(id)}/approval`, request, signal),
    recordWaiver: (request: WaiverRequest, signal?: AbortSignal) => api.postJSON<Waiver>('/v1/waivers', request, signal),
    recordSupersession: (request: SupersessionRequest, signal?: AbortSignal) =>
      api.postJSON<Supersession>('/v1/supersessions', request, signal),
    recordGrandfatherPeriod: (decisionID: string, request: GrandfatherRequest, signal?: AbortSignal) =>
      api.postJSON<GrandfatherPeriod>(`/v1/decisions/${encodeURIComponent(decisionID)}/grandfather-period`, request, signal),
    providers: (signal?: AbortSignal) => api.getJSON<{ providers: ProviderInfo[] }>('/auth/providers', {}, signal),
    logout: (signal?: AbortSignal) => api.post('/auth/logout', signal),
  };
}

export const calls = makeCalls(defaultApi);
