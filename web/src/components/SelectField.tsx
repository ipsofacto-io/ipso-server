import { useId, type ReactNode, type SelectHTMLAttributes } from 'react';

export interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string;
  hint?: string;
  /** Replaces the hint and turns the border carminio, as the kit's text field does. */
  error?: string;
  children: ReactNode;
}

/** A labelled native select. It takes the kit's field markup, which has no select of its own. */
export function SelectField({ label, hint, error, className, id, children, ...rest }: SelectFieldProps) {
  const auto = useId();
  const fieldId = id ?? `ip-select-${auto}`;
  const describedBy = error ? `${fieldId}-err` : hint ? `${fieldId}-hint` : undefined;
  return (
    <div className={`ip-field${error ? ' ip-field-invalid' : ''}${className ? ` ${className}` : ''}`}>
      <label className="ip-field-label" htmlFor={fieldId}>
        {label}
      </label>
      <select {...rest} id={fieldId} className="ip-input ip-select" aria-invalid={error ? true : undefined} aria-describedby={describedBy}>
        {children}
      </select>
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
