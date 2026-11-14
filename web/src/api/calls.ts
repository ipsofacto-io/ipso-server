import { api as defaultApi, type Api } from './client';
import type {
  AgentProposal,
  Approval,
  ApprovalRequest,
  AuditBeliefs,
  AuditChain,
  AuditDecisions,
  AuditWaivers,
  Baseline,
  BaselineRequest,
  CheckApproval,
  CheckApprovalRequest,
  CheckProposal,
  Clearance,
  ClearanceRequest,
  DecisionPage,
  Export,
  ExportRequest,
  GrandfatherPeriod,
  GrandfatherRequest,
  PremiseHost,
  PremiseHostRequest,
  PremiseReason,
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
    listVerdicts: (q: { repo?: string; decision?: string; known?: string } & Paging = {}, signal?: AbortSignal) =>
      api.getJSON<{ known: string; verdicts: StoredVerdict[] }>('/v1/verdicts', q, signal),
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
    /** The answer to a drafted check. The path names the decision the check was drafted for (ADR-0116, ADR-0118). */
    approveCheckProposal: (decisionID: string, id: string, request: CheckApprovalRequest, signal?: AbortSignal) =>
      api.postJSON<CheckApproval>(`/v1/decisions/${encodeURIComponent(decisionID)}/check-proposals/${encodeURIComponent(id)}/approval`, request, signal),
    recordWaiver: (request: WaiverRequest, signal?: AbortSignal) => api.postJSON<Waiver>('/v1/waivers', request, signal),
    recordSupersession: (request: SupersessionRequest, signal?: AbortSignal) =>
      api.postJSON<Supersession>('/v1/supersessions', request, signal),
    recordGrandfatherPeriod: (decisionID: string, request: GrandfatherRequest, signal?: AbortSignal) =>
      api.postJSON<GrandfatherPeriod>(`/v1/decisions/${encodeURIComponent(decisionID)}/grandfather-period`, request, signal),
    /** The fingerprints of one repository, recorded once for a decision that has grandfather terms (ADR-0121). */
    recordBaseline: (decisionID: string, request: BaselineRequest, signal?: AbortSignal) =>
      api.postJSON<Baseline>(`/v1/decisions/${encodeURIComponent(decisionID)}/baselines`, request, signal),
    /** The review reasons no clearance names, each with the fail that opened it (ADR-0117). */
    listPremiseReasons: (q: Paging = {}, signal?: AbortSignal) =>
      api.getJSON<{ premise_reasons: PremiseReason[] }>('/v1/premise-reasons', q, signal),
    /** The latest row of each host of the allowlist, a withdrawn host included (ADR-0117). */
    listPremiseHosts: (q: Paging = {}, signal?: AbortSignal) => api.getJSON<{ premise_hosts: PremiseHost[] }>('/v1/premise-hosts', q, signal),
    /** Closes the open review reason of a premise. The path names the decision the reason is on (ADR-0109, ADR-0119). */
    clearPremiseReason: (decisionID: string, premiseID: string, request: ClearanceRequest, signal?: AbortSignal) =>
      api.postJSON<Clearance>(`/v1/decisions/${encodeURIComponent(decisionID)}/premises/${encodeURIComponent(premiseID)}/clearance`, request, signal),
    /** Appends a row to the allowlist: allowed true allows a host, false withdraws it. Only an admin may (ADR-0109). */
    allowPremiseHost: (request: PremiseHostRequest, signal?: AbortSignal) => api.postJSON<PremiseHost>('/v1/premise-hosts', request, signal),
    /** The export the tenant holds, 404 when there is none. Only an admin who is a person may ask (ADR-0115). */
    currentExport: (signal?: AbortSignal) => api.getJSON<Export>('/v1/exports/current', {}, signal),
    startExport: (request: ExportRequest, signal?: AbortSignal) => api.postJSON<Export>('/v1/exports', request, signal),
    providers: (signal?: AbortSignal) => api.getJSON<{ providers: ProviderInfo[] }>('/auth/providers', {}, signal),
    logout: (signal?: AbortSignal) => api.post('/auth/logout', signal),
  };
}

export const calls = makeCalls(defaultApi);

/**
 * Where the archive of a ready export comes from. The page links to it and the browser saves the body to a file,
 * so the app never holds the archive (ADR-0115). It is a link and not a call, and the pact plays it by name.
 */
export function exportArchivePath(id: string): string {
  return `/v1/exports/${encodeURIComponent(id)}/archive`;
}
