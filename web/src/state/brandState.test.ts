import { describe, expect, it } from 'vitest';

import { brandState } from './brandState';

describe('brandState (section 2.2)', () => {
  it.each([
    ['verified', 'verified', false],
    ['accepted', 'verifying', false],
    ['proposed', 'verifying', true],
    ['needs-review', 'needs-review', false],
    ['needs_review', 'needs-review', false],
    ['rejected', 'rejected', false],
  ])('%s is shown as %s', (status, tone, pending) => {
    expect(brandState(status)).toEqual({ kind: 'status', tone, pending });
  });

  it('shows a superseded or deprecated decision as a label, never a status', () => {
    expect(brandState('superseded')).toEqual({ kind: 'label', label: 'Superseded' });
    expect(brandState('deprecated')).toEqual({ kind: 'label', label: 'Deprecated' });
  });

  it('shows nothing for a state it does not know, so menta is never guessed', () => {
    for (const status of [undefined, null, 'VERIFIED', 'done', 7, {}]) expect(brandState(status)).toEqual({ kind: 'none' });
  });

  it('uses the verified tone for verified and nothing else', () => {
    const tones = ['verified', 'accepted', 'proposed', 'needs-review', 'rejected', 'superseded', 'deprecated'].filter((status) => {
      const state = brandState(status);
      return state.kind === 'status' && state.tone === 'verified';
    });
    expect(tones).toEqual(['verified']);
  });
});
