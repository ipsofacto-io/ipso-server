import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router';

import { calls } from '../api/calls';
import { toApiError } from '../api/client';
import { useResource } from '../api/hooks';
import type { TenantChoice } from '../api/types';
import { Button, Mascot } from '../brand';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';
import { goTo } from '../lib/navigate';

/** Validates the redirect target returned by POST /auth/tenants for the active flow (ADR-0171). */
export function safeChoiceLocation(location: string, flow: 'browser' | 'cli'): string | null {
  if (flow === 'browser') {
    return location === '/' ? '/' : null;
  }
  try {
    const url = new URL(location);
    if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.pathname !== '/callback') return null;
    if (url.username !== '' || url.password !== '' || url.hash !== '') return null;
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    return url.href;
  } catch {
    return null;
  }
}

function loadErrorWords(status: number, retryAfter: number | null): string {
  if (status === 401) return 'This sign-in choice has expired or is no longer available. Start sign-in again.';
  if (status === 403) return 'This account no longer has an active organization to sign in to. Contact an administrator.';
  if (status === 404) return 'Organization selection is not enabled on this server.';
  if (status === 429) {
    return retryAfter === null ? 'Too many tries. Wait a moment and try again.' : `Too many tries. Try again in ${retryAfter} seconds.`;
  }
  if (status === 0) return 'Your organizations could not be loaded. Check your connection and try again.';
  return 'Your organizations could not be loaded. Start sign-in again.';
}

function submitErrorWords(status: number, retryAfter: number | null): string {
  if (status === 401) return 'This sign-in choice has expired or was already used. Start sign-in again.';
  if (status === 403) return 'You cannot sign in to that organization. Start sign-in again.';
  if (status === 429) {
    return retryAfter === null ? 'Too many tries. Wait a moment and try again.' : `Too many tries. Try again in ${retryAfter} seconds.`;
  }
  if (status === 0) return 'The sign-in could not be completed. Check your connection and try again.';
  return 'The sign-in could not be completed. Start sign-in again.';
}

function tenantLabel(tenant: TenantChoice, nameCounts: Map<string, number>): string {
  return (nameCounts.get(tenant.name) ?? 0) > 1 ? `${tenant.name} (${tenant.id})` : tenant.name;
}

/**
 * The tenant picker shown after an identity provider callback in multi-tenant mode when a verified
 * person holds open human logins in two or more organizations (ADR-0171). Shared by browser and CLI
 * loopback PKCE sign-in.
 */
export function ChooseTenantPanel() {
  const navigate = useNavigate();
  const pending = useResource((signal) => calls.pendingTenants(signal), [], { session: false });
  const [choosing, setChoosing] = useState<string | null>(null);
  const [canceling, setCanceling] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [consumed, setConsumed] = useState(false);

  useEffect(() => {
    const restored = (event: PageTransitionEvent) => {
      if (event.persisted) {
        setChoosing(null);
        setCanceling(false);
      }
    };
    window.addEventListener('pageshow', restored);
    return () => window.removeEventListener('pageshow', restored);
  }, []);

  async function choose(tenantId: string, flow: 'browser' | 'cli') {
    if (choosing !== null || canceling || consumed) return;
    setChoosing(tenantId);
    setProblem(null);
    try {
      const answer = await calls.chooseTenant(tenantId);
      const location = safeChoiceLocation(answer.location, flow);
      if (location === null) {
        setConsumed(true);
        setProblem(submitErrorWords(500, null));
        setChoosing(null);
        return;
      }
      goTo(location);
    } catch (cause) {
      const error = toApiError(cause);
      if (error.status === 401 || error.status === 403) {
        setConsumed(true);
      }
      setProblem(submitErrorWords(error.status, error.retryAfter));
      setChoosing(null);
    }
  }

  async function cancel() {
    if (choosing !== null || canceling) return;
    setCanceling(true);
    setProblem(null);
    try {
      await calls.cancelTenantChoice();
    } catch {
      // Even if the choice already expired, send the person back to sign-in cleanly.
    }
    navigate('/signin', { replace: true });
  }

  const isCLI = pending.status === 'ready' && pending.data.flow === 'cli';
  const nameCounts = new Map<string, number>();
  if (pending.status === 'ready') {
    for (const tenant of pending.data.tenants) {
      nameCounts.set(tenant.name, (nameCounts.get(tenant.name) ?? 0) + 1);
    }
  }

  return (
    <div className="signin">
      <Mascot state="idle" size={64} label="" />
      <h2 className="signin-title">{isCLI ? 'Choose an organization for the CLI' : 'Choose an organization'}</h2>
      {pending.status === 'loading' ? <Loading what="your organizations" /> : null}
      {pending.status === 'error' ? (
        <>
          <p className="signin-text" role="alert">
            {loadErrorWords(pending.error.status, pending.error.retryAfter)}
          </p>
          <div className="signin-actions">
            <Button variant="primary" onClick={() => navigate('/signin', { replace: true })}>
              Back to sign in
            </Button>
          </div>
        </>
      ) : null}
      {pending.status === 'ready' ? (
        <>
          <p className="signin-text">
            {isCLI
              ? 'Your account belongs to more than one organization. Pick the one you want to sign in to with the ipso CLI.'
              : 'Your account belongs to more than one organization. Pick the one you want to sign in to.'}
          </p>
          {problem !== null ? (
            <p className="signin-text" role="alert">
              {problem}
            </p>
          ) : null}
          {consumed ? (
            <div className="signin-actions">
              <Button variant="primary" onClick={() => navigate('/signin', { replace: true })}>
                Start sign-in again
              </Button>
            </div>
          ) : (
            <div className="signin-actions">
              {pending.data.tenants.map((tenant, index) => (
                <Button
                  key={tenant.id}
                  variant={index === 0 ? 'primary' : 'secondary'}
                  disabled={choosing !== null || canceling}
                  onClick={() => void choose(tenant.id, pending.data.flow)}
                >
                  {choosing === tenant.id ? 'Signing in...' : tenantLabel(tenant, nameCounts)}
                </Button>
              ))}
              <Button variant="quiet" disabled={choosing !== null || canceling} onClick={() => void cancel()}>
                {canceling ? 'Canceling...' : 'Cancel'}
              </Button>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}

export function ChooseTenantView() {
  return (
    <Page title="Choose an organization">
      <ChooseTenantPanel />
    </Page>
  );
}
