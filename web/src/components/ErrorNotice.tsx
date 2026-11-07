import type { ApiError } from '../api/client';
import { Button } from '../brand';
import { SignInPanel } from '../views/SignIn';
import { Notice } from './Notice';

/** Says what an API refusal means in words. A 401 is the sign-in itself, and a 429 never signs anyone out. */
export function ErrorNotice({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  if (error.status === 401) return <SignInPanel />;

  let title: string;
  let text: string;
  switch (true) {
    case error.status === 403:
      title = 'Your sign-in is not bound to a person of this tenant.';
      text = 'Ask a tenant admin to bind it.';
      break;
    case error.status === 429:
      title = 'Too many requests.';
      text = error.retryAfter ? `Try again in ${error.retryAfter} seconds.` : 'Try again in a moment.';
      break;
    case error.status === 404:
      title = 'Nothing is here.';
      text = 'The page or the record does not exist.';
      break;
    case error.status === 400:
      title = 'The question is not valid.';
      text = 'Check the fields and ask again.';
      break;
    case error.code === 'response too large':
      title = 'The answer is too large to show.';
      text = 'Narrow the question with a path or an environment.';
      break;
    case error.status === 503 || error.code === 'timeout':
      title = 'The request took too long.';
      text = 'Try again.';
      break;
    case error.status === 0:
      title = 'The server did not answer.';
      text = 'Check the connection and try again.';
      break;
    default:
      title = 'Something went wrong.';
      text = 'Try again. If it keeps happening, tell the person who runs ipso.';
  }
  return (
    <Notice tone="error" title={title}>
      <p>{text}</p>
      {onRetry ? (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </Notice>
  );
}
