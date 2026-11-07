import { calls } from '../api/calls';
import { useResource } from '../api/hooks';
import { Button, Mascot } from '../brand';
import { Loading } from '../components/Loading';
import { Page } from '../components/Page';

function providerLabel(id: string, kind: string): string {
  return kind === 'github' ? 'GitHub' : id;
}

/** The sign-in. It lists the providers the server is set up with and links to the first step of each. */
export function SignInPanel() {
  const providers = useResource((signal) => calls.providers(signal), [], { session: false });
  return (
    <div className="signin">
      <Mascot state="idle" size={64} label="" />
      <h2 className="signin-title">Sign in to ipso</h2>
      <p className="signin-text">Use the account your organization set up for ipso.</p>
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
  return (
    <Page title="Sign in">
      <SignInPanel />
    </Page>
  );
}
