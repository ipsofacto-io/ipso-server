import type { StatusTone } from '../brand';

// ADR-0107 and section 2.2: the state a decision is in, as the brand shows it. Every state has a word and an
// icon. Menta means Verified and nothing else, so it appears for no other state.

export type BrandState =
  | { kind: 'status'; tone: StatusTone; pending: boolean }
  | { kind: 'label'; label: 'Superseded' | 'Deprecated' }
  | { kind: 'none' };

export function brandState(status: unknown): BrandState {
  switch (status) {
    case 'verified':
      return { kind: 'status', tone: 'verified', pending: false };
    case 'accepted':
      return { kind: 'status', tone: 'verifying', pending: false };
    case 'proposed':
      return { kind: 'status', tone: 'verifying', pending: true };
    case 'needs-review':
    case 'needs_review':
      return { kind: 'status', tone: 'needs-review', pending: false };
    case 'rejected':
      return { kind: 'status', tone: 'rejected', pending: false };
    case 'superseded':
      return { kind: 'label', label: 'Superseded' };
    case 'deprecated':
      return { kind: 'label', label: 'Deprecated' };
    default:
      return { kind: 'none' };
  }
}
