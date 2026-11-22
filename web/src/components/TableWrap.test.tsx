import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { TableWrap } from './TableWrap';

const scrollWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'scrollWidth');
const clientWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth');

afterEach(() => {
  vi.unstubAllGlobals();
  if (scrollWidth) Object.defineProperty(HTMLElement.prototype, 'scrollWidth', scrollWidth);
  if (clientWidth) Object.defineProperty(HTMLElement.prototype, 'clientWidth', clientWidth);
});

function widths(scroll: number, client: number) {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      private readonly measure: () => void;
      constructor(measure: () => void) {
        this.measure = measure;
      }
      observe() {
        this.measure();
      }
      disconnect() {}
    },
  );
  Object.defineProperty(HTMLElement.prototype, 'scrollWidth', { configurable: true, get: () => scroll });
  Object.defineProperty(HTMLElement.prototype, 'clientWidth', { configurable: true, get: () => client });
}

describe('a table wider than the page', () => {
  it('can be scrolled from the keyboard only when the table does not fit', () => {
    widths(800, 320);
    const wide = render(
      <TableWrap>
        <table>
          <caption>Wide</caption>
        </table>
      </TableWrap>,
    );
    expect(screen.getByRole('table', { name: 'Wide' }).parentElement).toHaveAttribute('tabindex', '0');
    wide.unmount();

    widths(320, 800);
    render(
      <TableWrap>
        <table>
          <caption>Fits</caption>
        </table>
      </TableWrap>,
    );
    expect(screen.getByRole('table', { name: 'Fits' }).parentElement).not.toHaveAttribute('tabindex');
  });
});
