import { safeHttpsUrl } from '../lib/url';

/** A link out of a record: an https URL becomes a link, anything else is text. */
export function ExternalLink({ href, children }: { href: unknown; children: string }) {
  const url = safeHttpsUrl(href);
  if (url === null) return <span className="mono">{children}</span>;
  return (
    <a href={url} rel="noopener noreferrer" target="_blank">
      {children}
    </a>
  );
}
