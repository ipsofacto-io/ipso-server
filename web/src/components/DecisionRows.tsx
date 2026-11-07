import { Link } from 'react-router';

import type { Decision } from '../api/types';
import { formatDate } from '../lib/format';
import { decisionPath, summarize } from '../state/decision';
import { DecisionStatus } from './DecisionStatus';

/** The decisions of a list as a table: the same columns in the registry and in the audit answers. */
export function DecisionRows({ decisions, caption }: { decisions: Decision[]; caption: string }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">State</th>
            <th scope="col">Decision</th>
            <th scope="col">Owner</th>
            <th scope="col">Criticality</th>
            <th scope="col">Review by</th>
            <th scope="col">Version</th>
          </tr>
        </thead>
        <tbody>
          {decisions.map((decision) => {
            const d = summarize(decision);
            return (
              <tr key={`${d.id}@${d.version}`}>
                <td>
                  <DecisionStatus status={d.status} />
                </td>
                <td>
                  <Link to={decisionPath(d.id)}>{d.title}</Link>
                  {d.slug && d.slug !== d.title ? <div className="muted mono">{d.slug}</div> : null}
                </td>
                <td className="mono">{d.owner ?? 'none'}</td>
                <td>{d.criticality ?? 'none'}</td>
                <td className="mono">{d.reviewBy ? formatDate(d.reviewBy) : 'none'}</td>
                <td className="mono">{d.version}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
