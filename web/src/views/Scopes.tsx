import { calls } from '../api/calls';
import { useResource } from '../api/hooks';
import type { Scope } from '../api/types';
import { EmptyState } from '../components/EmptyState';
import { ErrorNotice } from '../components/ErrorNotice';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';

const PAGE = 100;
// A tenant has a few hundred scopes at most. The cap keeps a bad answer from looping the page forever.
const MAX_PAGES = 50;

/** Reads the whole scope tree, a page at a time (ADR-0090). */
export async function loadAllScopes(signal: AbortSignal, known?: string): Promise<Scope[]> {
  const all: Scope[] = [];
  let before: string | undefined;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const { scopes } = await calls.listScopes({ known, limit: PAGE, before }, signal);
    all.push(...scopes);
    const last = scopes.at(-1);
    if (scopes.length < PAGE || !last) break;
    before = last.id;
  }
  return all;
}

const REMEMBER_FOR = 30_000;
let remembered: { at: number; scopes: Scope[] } | null = null;

export function forgetScopes(): void {
  remembered = null;
}

/**
 * The scopes, for a view that only labels an id with one (the waivers). The tree view always reads fresh and
 * leaves what it read here, so the two do not walk the same pages one after the other.
 */
export async function scopesForLabels(signal: AbortSignal): Promise<Scope[]> {
  if (remembered && Date.now() - remembered.at < REMEMBER_FOR) return remembered.scopes;
  const scopes = await loadAllScopes(signal);
  remembered = { at: Date.now(), scopes };
  return scopes;
}

interface Node {
  scope: Scope;
  children: Node[];
}

/** A scope whose parent is not in the answer is a root, so a tree never loses a branch. */
export function buildTree(scopes: Scope[]): Node[] {
  const nodes = new Map<string, Node>(scopes.map((scope) => [scope.id, { scope, children: [] }]));
  const roots: Node[] = [];
  for (const node of nodes.values()) {
    const parent = node.scope.parent_id ? nodes.get(node.scope.parent_id) : undefined;
    if (parent && parent !== node) parent.children.push(node);
    else roots.push(node);
  }
  // Nodes that no root reaches sit in a parent cycle. They are shown as roots, so no row is hidden.
  const reached = new Set<string>();
  const walk = (list: Node[]) => {
    for (const node of list) {
      if (reached.has(node.scope.id)) continue;
      reached.add(node.scope.id);
      walk(node.children);
    }
  };
  walk(roots);
  for (const node of nodes.values()) {
    if (!reached.has(node.scope.id)) {
      // Cut the cycle where it is entered, so the branch is drawn once.
      const parent = node.scope.parent_id ? nodes.get(node.scope.parent_id) : undefined;
      if (parent) parent.children = parent.children.filter((child) => child !== node);
      roots.push(node);
      walk([node]);
    }
  }
  const order = (list: Node[], seen = new Set<Node>()) => {
    list.sort((a, b) => a.scope.selector.localeCompare(b.scope.selector));
    for (const node of list) {
      if (seen.has(node)) continue;
      seen.add(node);
      order(node.children, seen);
    }
  };
  order(roots);
  return roots;
}

function Branch({ nodes, depth }: { nodes: Node[]; depth: number }) {
  if (nodes.length === 0 || depth > 12) return null;
  return (
    <ul className={depth === 0 ? 'tree' : 'tree tree-nested'}>
      {nodes.map((node) => (
        <li key={node.scope.id}>
          <span className="ip-label">{node.scope.kind}</span> <span className="mono">{node.scope.selector}</span>
          <Branch nodes={node.children} depth={depth + 1} />
        </li>
      ))}
    </ul>
  );
}

export function ScopesView() {
  const scopes = useResource(async (signal) => {
    const all = await loadAllScopes(signal);
    remembered = { at: Date.now(), scopes: all };
    return all;
  }, []);
  return (
    <Page title="Scopes" intro="Where a decision applies: the organization, its services and repositories, paths and environments.">
      {scopes.status === 'loading' ? <Loading what="scopes" /> : null}
      {scopes.status === 'error' ? <ErrorNotice error={scopes.error} onRetry={scopes.reload} /> : null}
      {scopes.status === 'ready' && scopes.data.length === 0 ? <EmptyState title="No scopes yet.">Import your decisions to create them.</EmptyState> : null}
      {scopes.status === 'ready' && scopes.data.length > 0 ? <Branch nodes={buildTree(scopes.data)} depth={0} /> : null}
    </Page>
  );
}
