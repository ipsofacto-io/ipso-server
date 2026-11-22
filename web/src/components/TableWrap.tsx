import { useEffect, useRef, useState, type ReactNode } from 'react';

/**
 * A table that can be wider than the page. When it is, the wrapper takes keyboard focus so the row can be
 * scrolled without a pointer (WCAG 2.1.1). When it fits, it is not a tab stop.
 */
export function TableWrap({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrolls, setScrolls] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const measure = () => setScrolls(el.scrollWidth > el.clientWidth + 1);
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    const table = el.querySelector('table');
    if (table) observer.observe(table);
    window.addEventListener('resize', measure);
    measure();
    return () => {
      observer.disconnect();
      window.removeEventListener('resize', measure);
    };
  }, []);

  return (
    <div ref={ref} className="table-wrap" tabIndex={scrolls ? 0 : undefined}>
      {children}
    </div>
  );
}
