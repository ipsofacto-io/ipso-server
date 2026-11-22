import { Link } from 'react-router';

import { Page } from '../components/Page';

/** Every page a person can open, apart from a step that belongs to one of these. */
export const PAGES = [
  { to: '/decisions', label: 'Decisions' },
  { to: '/scopes', label: 'Scopes' },
  { to: '/inbox', label: 'Inbox' },
  { to: '/waivers', label: 'Waivers' },
  { to: '/premises', label: 'Premises' },
  { to: '/audit', label: 'Audit' },
  { to: '/invitations', label: 'Invitations' },
  { to: '/export', label: 'Export' },
  { to: '/signin', label: 'Sign in' },
] as const;

/** A second way to reach each page. The menu is the first (WCAG 2.4.5). */
export function PagesView() {
  return (
    <Page title="All pages" intro="Every page of the app. A record, a waiver and a sign-in are opened from the page they belong to.">
      <ul className="plain">
        {PAGES.map((page) => (
          <li key={page.to}>
            <Link to={page.to}>{page.label}</Link>
          </li>
        ))}
      </ul>
    </Page>
  );
}
