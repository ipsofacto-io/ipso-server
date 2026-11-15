import { useEffect, useState } from 'react';

import { calls } from '../api/calls';
import { toApiError } from '../api/client';
import { useResource } from '../api/hooks';
import { Button, Mascot } from '../brand';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { goTo } from '../lib/navigate';
import { providerLabel } from './SignIn';

/** An invitation token is 32 random bytes as unpadded base64url (ADR-0127). */
const TOKEN = /^[A-Za-z0-9_-]{43}$/;

/**
 * The token of the link, or null. It is in the fragment, so no server or proxy that carried the link saw it.
 */
export function tokenOf(hash: string): string | null {
  const text = hash.startsWith('#') ? hash.slice(1) : hash;
  return TOKEN.test(text) ? text : null;
}

/** Where a provider's sign-in starts: an address of the provider, or of this server for a stand-in. */
function safeLocation(location: string): string | null {
  try {
    const url = new URL(location, window.location.origin);
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}

/** What a person is told when the server refuses the start. The code is never shown as it came. */
function refusal(status: number, code: string, retryAfter: number | null): string {
  if (status === 403 && code === 'unknown_invitation') {
    return 'This invitation was already used, was withdrawn, or has expired. Ask the person who invited you for a new one.';
  }
  if (status === 429) {
    return retryAfter === null ? 'Too many tries. Wait a moment and try again.' : `Too many tries. Try again in ${retryAfter} seconds.`;
  }
  if (status === 0) return 'The invitation could not be checked. Check your connection and try again.';
  return 'The invitation could not be started. Try again, and ask for a new invitation if it keeps failing.';
}

/**
 * The page an invitation link opens (ADR-0127). It reads the token from the fragment and removes it from the address
 * at once, so the token is not in the history or in a copied address. The person picks the provider they sign in
 * with, the token goes to the server in a POST, and the browser is sent to the provider. The invitation is used at
 * the end of the sign-in, so a person who abandons it can try the link again until it expires.
 */
export function InvitationPanel() {
  // The token is read once, before anything clears it. A person who reloads has no fragment left and is asked
  // for the link again, which is the price of keeping it out of the history.
  const [token] = useState(() => tokenOf(window.location.hash));
  const providers = useResource((signal) => calls.providers(signal), [], { session: false });
  const [starting, setStarting] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  useEffect(() => {
    if (window.location.hash !== '') {
      window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}`);
    }
  }, []);

  // A browser that restores this page from its back/forward cache after the person came back from the provider keeps
  // the state of the page, so the buttons must not stay in the middle of a sign-in that is over.
  useEffect(() => {
    const restored = (event: PageTransitionEvent) => {
      if (event.persisted) setStarting(null);
    };
    window.addEventListener('pageshow', restored);
    return () => window.removeEventListener('pageshow', restored);
  }, []);

  async function start(provider: string) {
    if (token === null || starting !== null) return;
    setStarting(provider);
    setProblem(null);
    try {
      const answer = await calls.startInvitation(provider, token);
      const location = safeLocation(answer.location);
      if (location === null) {
        setProblem(refusal(500, 'internal', null));
        setStarting(null);
        return;
      }
      goTo(location);
    } catch (cause) {
      const error = toApiError(cause);
      setProblem(refusal(error.status, error.code, error.retryAfter));
      setStarting(null);
    }
  }

  return (
    <div className="signin">
      <Mascot state="idle" size={64} label="" />
      <h2 className="signin-title">You are invited to ipso</h2>
      {token === null ? (
        <p className="signin-text" role="alert">
          This invitation link is not complete. Open the whole link again, or ask the person who invited you for a new one.
        </p>
      ) : (
        <>
          <p className="signin-text">Sign in with the account you want to use for ipso. Your first sign-in joins you to the organization that invited you.</p>
          {providers.status === 'loading' ? <Loading what="sign-in options" /> : null}
          {providers.status === 'error' ? (
            <p className="signin-text" role="alert">
              {providers.error.status === 404 ? 'Sign-in is not configured on this server.' : 'The sign-in options did not load. Reload the page to try again.'}
            </p>
          ) : null}
          {providers.status === 'ready' && providers.data.providers.length === 0 ? (
            <p className="signin-text" role="alert">
              Sign-in is not configured on this server.
            </p>
          ) : null}
          {providers.status === 'ready' ? (
            <div className="signin-actions">
              {providers.data.providers.map((provider, index) => (
                <Button
                  key={provider.id}
                  variant={index === 0 ? 'primary' : 'secondary'}
                  disabled={starting !== null}
                  onClick={() => void start(provider.id)}
                >
                  {starting === provider.id ? 'Opening the sign-in...' : `Sign in with ${providerLabel(provider.id, provider.kind)}`}
                </Button>
              ))}
            </div>
          ) : null}
          {problem === null ? null : (
            <p className="signin-text" role="alert">
              {problem}
            </p>
          )}
        </>
      )}
    </div>
  );
}

export function InvitationView() {
  return (
    <Page title="Invitation">
      <InvitationPanel />
    </Page>
  );
}
