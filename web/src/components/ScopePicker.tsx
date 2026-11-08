import { useId } from 'react';

import type { Scope } from '../api/types';
import { buildTree } from '../views/Scopes';

type Tree = ReturnType<typeof buildTree>;

/**
 * The scope tree, to pick from. With `one` a person picks a single scope (a waiver covers one), and with no
 * `one` any number (a decision names up to 100). A group with a legend, so a screen reader says what is asked.
 */
export function ScopePicker({
  legend,
  hint,
  scopes,
  selected,
  onChange,
  one = false,
  error,
}: {
  legend: string;
  hint?: string;
  scopes: readonly Scope[];
  selected: readonly string[];
  onChange(next: string[]): void;
  one?: boolean;
  error?: string;
}) {
  const name = useId();
  const tree = buildTree([...scopes]);
  const describedBy = error ? `${name}-err` : hint ? `${name}-hint` : undefined;

  const toggle = (id: string, checked: boolean) => {
    if (one) onChange(checked ? [id] : []);
    else onChange(checked ? [...selected.filter((s) => s !== id), id] : selected.filter((s) => s !== id));
  };

  return (
    <fieldset className="fieldset" aria-describedby={describedBy} aria-invalid={error ? true : undefined}>
      <legend className="ip-label">{legend}</legend>
      {scopes.length === 0 ? <p className="muted">The tenant has no scope yet. A scope is created through the API first.</p> : null}
      <Branch nodes={tree} depth={0} name={name} one={one} selected={selected} toggle={toggle} />
      {error ? (
        <div id={`${name}-err`} className="ip-field-error">
          {error}
        </div>
      ) : hint ? (
        <div id={`${name}-hint`} className="ip-field-hint">
          {hint}
        </div>
      ) : null}
    </fieldset>
  );
}

function Branch({
  nodes,
  depth,
  name,
  one,
  selected,
  toggle,
}: {
  nodes: Tree;
  depth: number;
  name: string;
  one: boolean;
  selected: readonly string[];
  toggle(id: string, checked: boolean): void;
}) {
  if (nodes.length === 0 || depth > 12) return null;
  return (
    <ul className={depth === 0 ? 'tree' : 'tree tree-nested'}>
      {nodes.map((node) => (
        <li key={node.scope.id}>
          <label className="choice">
            <input
              type={one ? 'radio' : 'checkbox'}
              name={one ? name : undefined}
              checked={selected.includes(node.scope.id)}
              onChange={(event) => toggle(node.scope.id, event.target.checked)}
            />
            <span>
              <span className="ip-label">{node.scope.kind}</span> <span className="mono">{node.scope.selector}</span>
            </span>
          </label>
          <Branch nodes={node.children} depth={depth + 1} name={name} one={one} selected={selected} toggle={toggle} />
        </li>
      ))}
    </ul>
  );
}
