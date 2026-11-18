import { useEffect, useState } from 'react';

import { calls } from '../api/calls';
import { useResource } from '../api/hooks';
import { Button, Mascot } from '../brand';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';

export function providerLabel(id: string, kind: string): string {
  return kind === 'github' ? 'GitHub' : id;
}

/** A value from the fragment long enough to be a real issuer or subject, and short enough to show. */
const MAX_SHOWN = 2048;
const CONTROL = /[\u0000-\u001F\u007F]/;

const GENERIC = 'The sign-in did not finish. Start again.';

/** Words for each code the callback can answer. The code itself is never shown (ADR-0130). */
const WORDS: Record<string, string> = {
  unknown_login: 'This account is not a member of this organization. Give an administrator the issuer and the subject below so they can invite you or bind the login.',
  unknown_invitation: 'This invitation was already used, was withdrawn, or has expired. Ask the person who invited you for a new one.',
  invalid_login: GENERIC,
  login_refused: 'The sign-in was cancelled or refused. Start again if you still want to sign in.',
  forbidden: 'This login belongs to an agent. Sign in with a person account.',
  rate_limited: 'Too many tries. Wait a moment and try again.',
  internal: 'The sign-in could not be completed. Try again in a moment.',
  not_found: 'This sign-in provider is not configured.',
};

export interface SignInRefusal {
  words: string;
  issuer: string | null;
  subject: string | null;
}

function shown(value: string | null): string | null {
  if (value === null || value.length === 0 || value.length > MAX_SHOWN || CONTROL.test(value)) return null;
  return value;
}

/**
 * The refusal a callback put in the fragment, or null when the address has none. Only unknown_login keeps the
 * issuer and the subject, and only as text. Any other fragment gets the words of a sign-in that did not finish.
 */
export function refusalOf(hash: string): SignInRefusal | null {
  const text = hash.startsWith('#') ? hash.slice(1) : hash;
  if (text === '') return null;
  const params = new URLSearchParams(text);
  const code = params.get('code');
  const words = code !== null && WORDS[code] !== undefined ? WORDS[code] : GENERIC;
  if (code !== 'unknown_login') return { words, issuer: null, subject: null };
  return { words, issuer: shown(params.get('issuer')), subject: shown(params.get('subject')) };
}

/** The sign-in. It lists the providers the server is set up with and links to the first step of each. */
export function SignInPanel({ refusal = null }: { refusal?: SignInRefusal | null }) {
  const providers = useResource((signal) => calls.providers(signal), [], { session: false });
  return (
    <div className="signin">
      <Mascot state="idle" size={64} label="" />
      <h2 className="signin-title">Sign in to ipso</h2>
      <p className="signin-text">Use the account your organization set up for ipso.</p>
      {refusal ? (
        <p className="signin-text" role="alert">
          {refusal.words}
          {refusal.issuer !== null ? (
            <>
              {' '}
              Issuer: <span className="mono">{refusal.issuer}</span>.
            </>
          ) : null}
          {refusal.subject !== null ? (
            <>
              {' '}
              Subject: <span className="mono">{refusal.subject}</span>.
            </>
          ) : null}
        </p>
      ) : null}
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
            <Button key={provider.id} href={`/auth/login/${encodeURIComponent(provider.id)}`} variant={index === 0 ? 'primary' : 'secondary'}>
              Sign in with {providerLabel(provider.id, provider.kind)}
            </Button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function SignInView() {
  // Read once, then drop the fragment, so a refresh or a copied address does not keep the subject.
  const [refusal] = useState(() => refusalOf(window.location.hash));
  useEffect(() => {
    if (window.location.hash !== '') {
      window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}`);
    }
  }, []);
  return (
    <Page title="Sign in">
      <SignInPanel refusal={refusal} />
    </Page>
  );
}
