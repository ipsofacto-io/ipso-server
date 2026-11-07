import * as React from 'react';
import { cx } from './cx';

export interface TextFieldProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  /** Error message: replaces the hint and turns the border carminio. */
  error?: string;
  /** Text in JetBrains Mono, for IDs, fingerprints and keys. */
  mono?: boolean;
}

/** Labelled text input with hint and error. */
export function TextField({ label, hint, error, mono, className, id, ...rest }: TextFieldProps) {
  const autoId = React.useId();
  const fieldId = id ?? `ip-field-${autoId}`;
  const describedBy = error ? `${fieldId}-err` : hint ? `${fieldId}-hint` : undefined;
  return (
    <div className={cx('ip-field', error && 'ip-field-invalid', className)}>
      <label className="ip-field-label" htmlFor={fieldId}>
        {label}
      </label>
      <input
        {...rest}
        id={fieldId}
        className={cx('ip-input', mono && 'ip-input-mono')}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
      />
      {error ? (
        <div id={`${fieldId}-err`} className="ip-field-error">
          {error}
        </div>
      ) : hint ? (
        <div id={`${fieldId}-hint`} className="ip-field-hint">
          {hint}
        </div>
      ) : null}
    </div>
  );
}
