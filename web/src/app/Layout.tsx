import { useEffect, useRef, useState } from 'react';
import { Link, Navigate, NavLink, Outlet, useLocation, useNavigate } from 'react-router';

import { calls } from '../api/calls';
import { Button, Wordmark } from '../brand';
import { useApp } from './AppContext';

const NAV = [
  { to: '/decisions', label: 'Decisions' },
  { to: '/scopes', label: 'Scopes' },
  { to: '/inbox', label: 'Inbox' },
  { to: '/waivers', label: 'Waivers' },
  { to: '/audit', label: 'Audit' },
] as const;

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
  const { signedIn, busy } = useApp();
  const location = useLocation();
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
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => (isActive ? 'nav-link nav-link-active' : 'nav-link')}>
                {item.label}
              </NavLink>
            ))}
          </nav>
          {signedIn ? <SignOut /> : null}
        </div>
      </header>
      <main id="main" ref={main} tabIndex={-1} className="main">
        {/* A call the server refused with 401 means there is no session: the sign-in is the page. */}
        {signedIn === false && location.pathname !== '/signin' ? <Navigate to="/signin" replace /> : <Outlet />}
      </main>
    </>
  );
}
