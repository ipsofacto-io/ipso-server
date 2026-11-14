import type { ApiError } from '../api/client';
import { Button } from '../brand';
import { SignInPanel } from '../views/SignIn';
import { Notice } from './Notice';

/**
 * Says what an API refusal means in words. A 401 is the sign-in itself, and a 429 never signs anyone out. A form
 * says what a 409 means for its own write with `conflict`, a 400 in its own words with `invalid`, and a 413 with
 * `tooLarge`, because the server answers each with a code and no message (ADR-0109). A question whose answer can be too
 * large says in `tooWide` what, if anything, narrows it: the default advice names a path and an environment, which
 * narrow decisions and not the verdicts of a commit (ADR-0124).
 */
export function ErrorNotice({
  error,
  onRetry,
  conflict,
  invalid,
  tooLarge,
  tooWide,
}: {
  error: ApiError;
  onRetry?: () => void;
  conflict?: string;
  invalid?: string;
  tooLarge?: string;
  tooWide?: string;
}) {
  if (error.status === 401) return <SignInPanel />;

  let title: string;
  let text: string;
  switch (true) {
    case error.status === 403:
      title = 'You do not have a role that allows this.';
      text = 'Ask a tenant admin for one.';
      break;
    case error.status === 429:
      title = 'Too many requests.';
      text = error.retryAfter ? `Try again in ${error.retryAfter} seconds.` : 'Try again in a moment.';
      break;
    case error.status === 404:
      title = 'Nothing is here.';
      text = 'The page or the record does not exist.';
      break;
    case error.status === 409:
      title = 'This conflicts with what is recorded.';
      text = conflict ?? 'Someone may have changed it first. Read the page again and check.';
      break;
    case error.status === 413:
      title = 'That is too large.';
      text = tooLarge ?? 'Shorten it and send it again.';
      break;
    case error.status === 415:
      title = 'The server did not accept the format.';
      text = 'Reload the page and try again. If it keeps happening, tell the person who runs ipso.';
      break;
    case error.status === 400:
      title = invalid ? 'The server refused a value.' : 'The question is not valid.';
      text = invalid ?? 'Check the fields and ask again.';
      break;
    case error.code === 'response too large':
      title = 'The answer is too large to show.';
      text = tooWide ?? 'Narrow the question with a path or an environment.';
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
