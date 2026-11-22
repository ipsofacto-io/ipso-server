import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';

/**
 * A table that can be wider than the page. When it is, the wrapper is a named region and the arrow keys
 * scroll it (WCAG 2.1.1). When it fits, it is not a tab stop. The effect runs again when the table changes,
 * so a table that arrives after the first paint is measured too.
 */
export function TableWrap({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrolls, setScrolls] = useState(false);
  const [label, setLabel] = useState('Table');

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const measure = () => {
      setScrolls(el.scrollWidth > el.clientWidth + 1);
      const caption = el.querySelector('caption')?.textContent?.trim();
      if (caption) setLabel(caption);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    for (const table of el.querySelectorAll('table')) observer.observe(table);
    window.addEventListener('resize', measure);
    measure();
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, [children]);

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const el = ref.current;
    if (!el || !scrolls) return;
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    el.scrollLeft += event.key === 'ArrowRight' ? 48 : -48;
    event.preventDefault();
  }

  return (
    <div
      ref={ref}
      className="table-wrap"
      tabIndex={scrolls ? 0 : undefined}
      role={scrolls ? 'region' : undefined}
      aria-label={scrolls ? label : undefined}
      onKeyDown={onKeyDown}
    >
      {children}
    </div>
  );
}
