import { useEffect, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate } from 'react-router';

import { calls } from '../api/calls';
import { toApiError } from '../api/client';
import { Button, Wordmark } from '../brand';
import { notRefused } from '../state/export';
import { useApp } from './AppContext';

const NAV = [
  { to: '/decisions', label: 'Decisions' },
  { to: '/scopes', label: 'Scopes' },
  { to: '/inbox', label: 'Inbox' },
  { to: '/advisory', label: 'Advisory' },
  { to: '/waivers', label: 'Waivers' },
  { to: '/premises', label: 'Premises' },
  { to: '/audit', label: 'Audit' },
] as const;

/**
 * Decides whether the menu has an entry that only some roles take. No route says what role a person holds
 * (ADR-0110), so the entry follows the answer of the read its screen makes (ADR-0115, ADR-0127). The layout makes
 * the read once when a session starts, unless the page is open: the page makes the same read and reports what it
 * found.
 */
function useMenuEntry(
  signedIn: boolean | null,
  onItsPage: boolean,
  read: (signal: AbortSignal) => Promise<unknown>,
  shown: boolean | null,
  setShown: (value: boolean | null) => void,
): boolean {
  const onPage = useRef(onItsPage);
  onPage.current = onItsPage;
  const readRef = useRef(read);
  readRef.current = read;
  useEffect(() => {
    if (signedIn !== true) {
      setShown(null);
      return;
    }
    if (onPage.current) return;
    const controller = new AbortController();
    readRef.current(controller.signal).then(
      () => {
        if (!controller.signal.aborted) setShown(true);
      },
      (cause: unknown) => {
        if (!controller.signal.aborted) setShown(notRefused(toApiError(cause).status));
      },
    );
    return () => controller.abort();
  }, [signedIn, setShown]);
  return shown === true;
}

function SignOut() {
  const { setSignedIn } = useApp();
  const navigate = useNavigate();
  const [failed, setFailed] = useState(false);

  async function signOut() {
    setFailed(false);
    try {
      await calls.logout();
      setSignedIn(false);
      navigate('/signin');
    } catch {
      setFailed(true);
    }
  }

  return (
    <div className="signout">
      <Button variant="quiet" size="sm" onClick={() => void signOut()}>
        Sign out
      </Button>
      {failed ? (
        <span className="muted" role="alert">
          Sign-out failed. Try again.
        </span>
      ) : null}
    </div>
  );
}

export function Layout() {
  const { signedIn, busy, canExport, setCanExport, canInvite, setCanInvite } = useApp();
  const location = useLocation();
  const showExport = useMenuEntry(signedIn, location.pathname === '/export', (signal) => calls.currentExport(signal), canExport, setCanExport);
  const showInvitations = useMenuEntry(
    signedIn,
    location.pathname === '/invitations',
    (signal) => calls.listInvitations({ limit: 1 }, signal),
    canInvite,
    setCanInvite,
  );
  const nav = [...NAV, ...(showInvitations ? [{ to: '/invitations', label: 'Invitations' }] : []), ...(showExport ? [{ to: '/export', label: 'Export' }] : [])];
  const main = useRef<HTMLElement>(null);
  const first = useRef(true);

  // A route change moves focus to the page, so a keyboard or screen reader user starts at its top.
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    main.current?.focus({ preventScroll: false });
  }, [location.pathname]);

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar-inner">
          <Link to="/" className="brand" aria-label="ipso, home">
            <Wordmark height={30} blink={busy} label="ipso" />
          </Link>
          <nav aria-label="Main" className="nav">
            {nav.map((item) => (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => (isActive ? 'nav-link nav-link-active' : 'nav-link')}>
                {item.label}
              </NavLink>
            ))}
          </nav>
          {signedIn ? <SignOut /> : null}
        </div>
      </header>
      <main id="main" ref={main} tabIndex={-1} className="main">
        {/* A call the server refused with 401 means there is no session: the sign-in is the page. An invitation or pending tenant choice takes no session. */}
        {signedIn === false && location.pathname !== '/signin' && location.pathname !== '/signin/tenant' && location.pathname !== '/invitation' ? <Navigate to="/signin" replace /> : <Outlet />}
      </main>
      <footer className="foot">
        <div className="foot-inner">
          <Link to="/pages">All pages</Link>
        </div>
      </footer>
    </>
  );
}
