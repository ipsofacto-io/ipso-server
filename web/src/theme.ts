/**
 * The brand has a light and a dark theme, switched by data-theme (the kit's tokens). The app follows the system:
 * it sets the attribute once and again whenever the system changes. It returns the call that stops following.
 */
export function followSystemTheme(root: HTMLElement, query: MediaQueryList): () => void {
  const apply = () => {
    root.dataset.theme = query.matches ? 'dark' : 'light';
  };
  apply();
  query.addEventListener('change', apply);
  return () => query.removeEventListener('change', apply);
}
