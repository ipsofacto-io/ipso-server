import { useEffect, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router';

import { Button, TextField } from '../brand';
import { fieldToTime, formatTime, timeToField } from '../lib/format';

/** The two times of a bitemporal read, kept in the address so a view can be shared. Absent means now. */
export function useTimes(): { valid: string | undefined; known: string | undefined } {
  const [params] = useSearchParams();
  return { valid: params.get('valid') ?? undefined, known: params.get('known') ?? undefined };
}

export function TimeControls({ valid, known }: { valid?: string; known?: string }) {
  const [, setParams] = useSearchParams();
  const [validField, setValidField] = useState(timeToField(valid ?? null));
  const [knownField, setKnownField] = useState(timeToField(known ?? null));

  // The address is the truth: back, forward and a shared link change it without a click on Apply.
  useEffect(() => {
    setValidField(timeToField(valid ?? null));
    setKnownField(timeToField(known ?? null));
  }, [valid, known]);

  function apply(event: FormEvent) {
    event.preventDefault();
    setParams((current) => {
      const next = new URLSearchParams(current);
      for (const [name, value] of [['valid', validField], ['known', knownField]] as const) {
        if (value === '') next.delete(name);
        else next.set(name, fieldToTime(value));
      }
      return next;
    });
  }

  function reset() {
    setValidField('');
    setKnownField('');
    setParams((current) => {
      const next = new URLSearchParams(current);
      next.delete('valid');
      next.delete('known');
      return next;
    });
  }

  const shown = `${valid ? formatTime(valid) : 'now'}, as known ${known ? formatTime(known) : 'now'}`;
  return (
    <details className="times" open={Boolean(valid || known)}>
      <summary>
        <span className="ip-label">As of</span> <span className="mono">{shown}</span>
      </summary>
      <form className="form-row" onSubmit={apply}>
        <TextField
          label="In force at (UTC)"
          type="datetime-local"
          mono
          value={validField}
          onChange={(event) => setValidField(event.target.value)}
          hint="The time the decision applies to."
        />
        <TextField
          label="Known at (UTC)"
          type="datetime-local"
          mono
          value={knownField}
          onChange={(event) => setKnownField(event.target.value)}
          hint="The time the registry knew it."
        />
        <div className="form-actions">
          <Button type="submit" variant="secondary" size="sm">
            Apply
          </Button>
          <Button variant="quiet" size="sm" onClick={reset}>
            Now
          </Button>
        </div>
      </form>
    </details>
  );
}
