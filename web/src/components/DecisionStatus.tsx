import { Status } from '../brand';
import { brandState } from '../state/brandState';

/** The state of a decision in the brand's words: a word and an icon, never a colour alone (section 2.2). */
export function DecisionStatus({ status }: { status: unknown }) {
  const state = brandState(status);
  switch (state.kind) {
    case 'status':
      return (
        <span className="state">
          <Status tone={state.tone} />
          {state.pending ? <span className="state-pending">Pending approval</span> : null}
        </span>
      );
    case 'label':
      return <span className="state-label">{state.label}</span>;
    case 'none':
      return <span className="state-label state-none">No status</span>;
  }
}
