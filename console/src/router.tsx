import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  Link,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";
import { SearchX } from "lucide-react";

import { type AppTab, APP_TABS } from "./app-tabs";
import { Shell } from "./shell";
import { EmptyState, Page } from "./ui";

// W707 (follow-up 32): each page module loads with its first route, so the
// first load holds only the shell and the page it opens.
const loadAccountsPages = () => import("./accounts-pages");
const LoginPage = lazyRouteComponent(loadAccountsPages, "LoginPage");
const UsersPage = lazyRouteComponent(loadAccountsPages, "UsersPage");

const loadDatabasesAndSiteOps = () => import("./databases-and-site-ops");
const DatabasesPage = lazyRouteComponent(loadDatabasesAndSiteOps, "DatabasesPage");

const loadHostingWizards = () => import("./hosting-wizards");
const AddDomainPage = lazyRouteComponent(loadHostingWizards, "AddDomainPage");
const CreateWebsitePage = lazyRouteComponent(loadHostingWizards, "CreateWebsitePage");

const loadKbPages = () => import("./kb-pages");
const KnowledgeBaseArticlePage = lazyRouteComponent(loadKbPages, "KnowledgeBaseArticlePage");
const KnowledgeBaseHomePage = lazyRouteComponent(loadKbPages, "KnowledgeBaseHomePage");

const loadMailPages = () => import("./mail-pages");
const EmailManagementPage = lazyRouteComponent(loadMailPages, "EmailManagementPage");

const loadOpsViews = () => import("./ops-views");
const HostAlertsPage = lazyRouteComponent(loadOpsViews, "HostAlertsPage");
const HostFirewallPage = lazyRouteComponent(loadOpsViews, "HostFirewallPage");
const SiteMaintenancePage = lazyRouteComponent(loadOpsViews, "SiteMaintenancePage");

const loadHostPages = () => import("./host-pages");
const HostMetrics = lazyRouteComponent(loadHostPages, "HostMetrics");
const HostServices = lazyRouteComponent(loadHostPages, "HostServices");
const Overview = lazyRouteComponent(loadHostPages, "Overview");

const loadSitePages = () => import("./site-pages");
const SiteConfiguration = lazyRouteComponent(loadSitePages, "SiteConfiguration");
const SiteOperations = lazyRouteComponent(loadSitePages, "SiteOperations");
const SiteOverview = lazyRouteComponent(loadSitePages, "SiteOverview");
const SiteRecovery = lazyRouteComponent(loadSitePages, "SiteRecovery");
const SitesPage = lazyRouteComponent(loadSitePages, "SitesPage");

const loadOperationPages = () => import("./operation-pages");
const OperationDetail = lazyRouteComponent(loadOperationPages, "OperationDetail");
const OperationsPage = lazyRouteComponent(loadOperationPages, "OperationsPage");
const PlanDetail = lazyRouteComponent(loadOperationPages, "PlanDetail");

const loadRecoveryPages = () => import("./recovery-pages");
const ArtifactPage = lazyRouteComponent(loadRecoveryPages, "ArtifactPage");
const ReceiptPage = lazyRouteComponent(loadRecoveryPages, "ReceiptPage");
const RecoveryPage = lazyRouteComponent(loadRecoveryPages, "RecoveryPage");

const loadSettingsPages = () => import("./settings-pages");
const SettingsPage = lazyRouteComponent(loadSettingsPages, "SettingsPage");
const StatesPage = lazyRouteComponent(loadSettingsPages, "StatesPage");

const loadPlanWorkflow = () => import("./plan-workflow");
const PlanNew = lazyRouteComponent(loadPlanWorkflow, "PlanNew");
const PlanReview = lazyRouteComponent(loadPlanWorkflow, "PlanReview");

const loadPlatformPages = () => import("./platform-pages");
const AppDetailPage = lazyRouteComponent(loadPlatformPages, "AppDetailPage");
const AppsPage = lazyRouteComponent(loadPlatformPages, "AppsPage");
const DomainsPage = lazyRouteComponent(loadPlatformPages, "DomainsPage");
const HostDiagnosesPage = lazyRouteComponent(loadPlatformPages, "HostDiagnosesPage");
const HostUpdatesPage = lazyRouteComponent(loadPlatformPages, "HostUpdatesPage");
const MigrationPage = lazyRouteComponent(loadPlatformPages, "MigrationPage");

const loadPlatformSubviews = () => import("./platform-subviews");
const DomainDetailPage = lazyRouteComponent(loadPlatformSubviews, "DomainDetailPage");
const DomainDnsPage = lazyRouteComponent(loadPlatformSubviews, "DomainDnsPage");
const EmDashMigrationDetailPage = lazyRouteComponent(
  loadPlatformSubviews,
  "EmDashMigrationDetailPage",
);
const RecoverySchedulesPage = lazyRouteComponent(loadPlatformSubviews, "RecoverySchedulesPage");
const RecoveryStorePage = lazyRouteComponent(loadPlatformSubviews, "RecoveryStorePage");

const loadServerOpsPages = () => import("./server-ops-pages");
const HostCronPage = lazyRouteComponent(loadServerOpsPages, "HostCronPage");
const HostLogsPage = lazyRouteComponent(loadServerOpsPages, "HostLogsPage");

const rootRoute = createRootRoute({
  component: () => (
    <Shell>
      <Outlet />
    </Shell>
  ),
  notFoundComponent: NotFoundPage,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: Overview,
});

const metricsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/metrics",
  component: HostMetrics,
});

const servicesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/services",
  component: HostServices,
});

const diagnosesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/diagnoses",
  component: HostDiagnosesPage,
});

const updatesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/updates",
  component: HostUpdatesPage,
});

const alertsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/alerts",
  component: HostAlertsPage,
});

const firewallRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/firewall",
  component: HostFirewallPage,
});

const cronRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/cron",
  component: HostCronPage,
});

const logsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/host/logs",
  component: HostLogsPage,
});

const mailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/mail",
  component: () => <EmailManagementPage initialTab="mailboxes" />,
});

const mailRelayRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/mail/relay",
  component: () => <EmailManagementPage initialTab="relay" />,
});

const appsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/apps",
  component: AppsPage,
});

const databasesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/databases",
  component: DatabasesPage,
});

const appDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/apps/$appId",
  validateSearch: (search: Record<string, unknown>): { tab?: AppTab } => {
    const tab = APP_TABS.find((key) => key === search.tab);
    return tab ? { tab } : {};
  },
  component: function AppDetailRoute() {
    const { appId } = appDetailRoute.useParams();
    const { tab = "overview" } = appDetailRoute.useSearch();
    return <AppDetailPage appId={appId} tab={tab} />;
  },
});

const domainsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/domains",
  component: DomainsPage,
});

const domainNewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/domains/new",
  component: AddDomainPage,
});

const domainDetailRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/domains/$hostname",
  component: function DomainDetailRoute() {
    const { hostname } = domainDetailRoute.useParams();
    return <DomainDetailPage hostname={hostname} />;
  },
});

const domainDnsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/domains/$hostname/dns",
  component: function DomainDnsRoute() {
    const { hostname } = domainDnsRoute.useParams();
    return <DomainDnsPage hostname={hostname} />;
  },
});

const migrationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/migration",
  component: MigrationPage,
});

const emdashMigrationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/migration/emdash/$migrationId",
  component: function EmDashMigrationRoute() {
    const { migrationId } = emdashMigrationRoute.useParams();
    return <EmDashMigrationDetailPage migrationId={migrationId} />;
  },
});

const sitesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites",
  component: SitesPage,
});

const siteNewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/new",
  component: CreateWebsitePage,
});

const siteRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId",
  component: function SiteRoute() {
    const { siteId } = siteRoute.useParams();
    return <SiteOverview siteId={siteId} />;
  },
});

const siteConfigRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId/configuration",
  component: function SiteConfigRoute() {
    const { siteId } = siteConfigRoute.useParams();
    return <SiteConfiguration siteId={siteId} />;
  },
});

const siteMaintenanceRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId/maintenance",
  component: function SiteMaintenanceRoute() {
    const { siteId } = siteMaintenanceRoute.useParams();
    return <SiteMaintenancePage siteId={siteId} />;
  },
});

const siteOpsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId/operations",
  component: function SiteOpsRoute() {
    const { siteId } = siteOpsRoute.useParams();
    return <SiteOperations siteId={siteId} />;
  },
});

const siteRecoveryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/sites/$siteId/recovery",
  component: function SiteRecoveryRoute() {
    const { siteId } = siteRecoveryRoute.useParams();
    return <SiteRecovery siteId={siteId} />;
  },
});

const operationsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/operations",
  component: OperationsPage,
});

const operationRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/operations/$operationId",
  component: function OperationRoute() {
    const { operationId } = operationRoute.useParams();
    return <OperationDetail operationId={operationId} />;
  },
});

const planNewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/plans/new",
  component: PlanNew,
});

const planReviewRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/plans/new/review",
  component: PlanReview,
});

const planRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/plans/$planId",
  component: function PlanRoute() {
    const { planId } = planRoute.useParams();
    return <PlanDetail planId={planId} />;
  },
});

const recoveryRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recovery",
  component: RecoveryPage,
});

const recoverySchedulesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recovery/schedules",
  component: RecoverySchedulesPage,
});

const recoveryStoreRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recovery/store",
  component: RecoveryStorePage,
});

const artifactRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recovery/artifacts/$artifactId",
  component: function ArtifactRoute() {
    const { artifactId } = artifactRoute.useParams();
    return <ArtifactPage artifactId={artifactId} />;
  },
});

const receiptRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/recovery/evidence/$receiptId",
  component: function ReceiptRoute() {
    const { receiptId } = receiptRoute.useParams();
    return <ReceiptPage receiptId={receiptId} />;
  },
});

const usersRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/users",
  component: UsersPage,
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  component: LoginPage,
});

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

const helpRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/help",
  component: KnowledgeBaseHomePage,
});

const helpArticleRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/help/$slug",
  component: function HelpArticleRoute() {
    const { slug } = helpArticleRoute.useParams();
    return <KnowledgeBaseArticlePage slug={slug} />;
  },
});

const statesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/states",
  component: StatesPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  metricsRoute,
  servicesRoute,
  diagnosesRoute,
  updatesRoute,
  alertsRoute,
  firewallRoute,
  cronRoute,
  logsRoute,
  mailRoute,
  mailRelayRoute,
  sitesRoute,
  siteNewRoute,
  siteRoute,
  siteConfigRoute,
  siteMaintenanceRoute,
  siteOpsRoute,
  siteRecoveryRoute,
  appsRoute,
  databasesRoute,
  appDetailRoute,
  domainsRoute,
  domainNewRoute,
  domainDetailRoute,
  domainDnsRoute,
  migrationRoute,
  emdashMigrationRoute,
  operationsRoute,
  operationRoute,
  planNewRoute,
  planReviewRoute,
  planRoute,
  recoveryRoute,
  recoverySchedulesRoute,
  recoveryStoreRoute,
  artifactRoute,
  receiptRoute,
  usersRoute,
  loginRoute,
  settingsRoute,
  helpRoute,
  helpArticleRoute,
  statesRoute,
]);

export { routeTree };

function pathDepth(pathname: string): number {
  return pathname.split("/").filter(Boolean).length;
}

function reducedMotion(): boolean {
  return (
    document.documentElement.dataset.motion === "reduce" ||
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
  );
}

/**
 * W695 (v0.2 pass 18): the route transition type. Going deeper slides forward,
 * going up slides back, and a same-depth move only fades; a search-only change
 * (such as the app tabs) and reduced motion get no transition.
 */
export function routeTransitionTypes(change: {
  fromLocation?: { pathname: string };
  toLocation: { pathname: string };
  pathChanged: boolean;
}): string[] | false {
  if (!change.pathChanged || reducedMotion()) return false;
  const from = change.fromLocation ? pathDepth(change.fromLocation.pathname) : 0;
  const to = pathDepth(change.toLocation.pathname);
  if (to > from) return ["nav-forward"];
  if (to < from) return ["nav-back"];
  return ["nav-lateral"];
}

/** W718: an address no route matches, inside the shell, with a way back. */
function NotFoundPage() {
  return (
    <Page live>
      <div className="page-head">
        <div>
          <h1>Page not found</h1>
        </div>
      </div>
      <EmptyState
        icon={SearchX}
        title="No Console page has this address"
        description="The link may be mistyped, or the page may have moved. The sidebar and the search palette list every page."
        action={
          <Link to="/" className="btn sm">
            Go to Host overview
          </Link>
        }
      />
    </Page>
  );
}

const router = createRouter({
  routeTree,
  // W707: a page's module starts loading when a link to it is hovered or focused.
  defaultPreload: "intent",
  defaultViewTransition: { types: routeTransitionTypes },
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function AppRouter() {
  return <RouterProvider router={router} />;
}
