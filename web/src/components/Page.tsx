import { useEffect, type ReactNode } from 'react';

/** Sets the title of the tab: the view first, then the name. */
export function useTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} · ipso`;
  }, [title]);
}

export function Page({ title, intro, actions, children }: { title: string; intro?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  useTitle(title);
  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h1 className="page-title">{title}</h1>
          {intro ? <p className="page-intro">{intro}</p> : null}
        </div>
        {actions ? <div className="page-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}
