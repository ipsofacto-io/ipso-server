import type { ReactNode } from 'react';
import { Link } from 'react-router';

/** A link inside the app that looks like the kit's button, so a click moves in the router and reloads nothing. */
export function LinkButton({
  to,
  variant = 'secondary',
  size = 'md',
  children,
}: {
  to: string;
  variant?: 'primary' | 'secondary' | 'quiet';
  size?: 'md' | 'sm';
  children: ReactNode;
}) {
  return (
    <Link to={to} className={`ip-btn ip-btn-${variant}${size === 'sm' ? ' ip-btn-sm' : ''}`}>
      {children}
    </Link>
  );
}
