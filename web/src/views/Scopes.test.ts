import { describe, expect, it } from 'vitest';

import type { Scope } from '../api/types';
import { buildTree } from './Scopes';

const scope = (id: string, parent_id: string | null, selector: string): Scope => ({ id, parent_id, kind: 'path', selector });

const names = (nodes: ReturnType<typeof buildTree>): string[] => nodes.flatMap((node) => [node.scope.selector, ...names(node.children)]);

describe('buildTree', () => {
  it('nests a scope under its parent and orders siblings by selector', () => {
    const tree = buildTree([scope('c', 'a', 'z'), scope('a', null, 'acme'), scope('b', 'a', 'b')]);
    expect(tree).toHaveLength(1);
    expect(names(tree)).toEqual(['acme', 'b', 'z']);
  });

  it('makes a scope a root when its parent is not in the answer', () => {
    expect(names(buildTree([scope('x', 'gone', 'orphan'), scope('a', null, 'acme')]))).toEqual(['acme', 'orphan']);
  });

  it('keeps a scope that is its own parent', () => {
    expect(names(buildTree([scope('a', 'a', 'loop')]))).toEqual(['loop']);
  });

  it('shows every scope of a parent cycle once, so no row is hidden', () => {
    const tree = buildTree([scope('a', 'b', 'first'), scope('b', 'a', 'second'), scope('r', null, 'root')]);
    expect(names(tree).sort()).toEqual(['first', 'root', 'second']);
  });
});
