import { BrowserRouter, Navigate, Route, Routes } from 'react-router';

import { AppProvider } from './app/AppContext';
import { Layout } from './app/Layout';
import { EmptyState } from './components/EmptyState';
import { Page } from './components/Page';
import {
  AuditBeliefsView,
  AuditDecisionsView,
  AuditIndexView,
  AuditMergesView,
  AuditSupersessionsView,
  AuditWaiversView,
} from './views/Audit';
import { DecisionDetailView } from './views/DecisionDetail';
import { DecisionsView } from './views/Decisions';
import { ExportView } from './views/Export';
import { InboxView } from './views/Inbox';
import { InvitationView } from './views/Invitation';
import { InvitationsView } from './views/Invitations';
import { NewDecisionView } from './views/NewDecision';
import { PagesView } from './views/Pages';
import { PremisesView } from './views/Premises';
import { RecordBaselineView } from './views/RecordBaseline';
import { RecordSupersessionView } from './views/RecordSupersession';
import { RecordWaiverView } from './views/RecordWaiver';
import { ScopesView } from './views/Scopes';
import { SignInView } from './views/SignIn';
import { WaiversView } from './views/Waivers';

function NotFoundView() {
  return (
    <Page title="Not found">
      <EmptyState title="This page does not exist.">Use the menu to find what you were looking for.</EmptyState>
    </Page>
  );
}

/** The routes, apart from the router, so a test can mount them in a memory router. */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/decisions" replace />} />
        <Route path="decisions" element={<DecisionsView />} />
        <Route path="decisions/new" element={<NewDecisionView />} />
        <Route path="decisions/:ref" element={<DecisionDetailView />} />
        <Route path="scopes" element={<ScopesView />} />
        <Route path="inbox" element={<InboxView />} />
        <Route path="waivers" element={<WaiversView />} />
        <Route path="waivers/new" element={<RecordWaiverView />} />
        <Route path="premises" element={<PremisesView />} />
        <Route path="pages" element={<PagesView />} />
        <Route path="supersessions/new" element={<RecordSupersessionView />} />
        <Route path="baselines/new" element={<RecordBaselineView />} />
        <Route path="export" element={<ExportView />} />
        <Route path="invitations" element={<InvitationsView />} />
        <Route path="audit" element={<AuditIndexView />} />
        <Route path="audit/decisions" element={<AuditDecisionsView />} />
        <Route path="audit/beliefs" element={<AuditBeliefsView />} />
        <Route path="audit/merges" element={<AuditMergesView />} />
        <Route path="audit/supersessions" element={<AuditSupersessionsView />} />
        <Route path="audit/waivers" element={<AuditWaiversView />} />
        <Route path="signin" element={<SignInView />} />
        <Route path="invitation" element={<InvitationView />} />
        <Route path="*" element={<NotFoundView />} />
      </Route>
    </Routes>
  );
}

export function App() {
  return (
    <AppProvider>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </AppProvider>
  );
}
