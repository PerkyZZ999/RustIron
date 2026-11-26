import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
} from "@tanstack/react-router";

import { LoginPage, UsersPage } from "./accounts-pages";
import { DatabasesPage } from "./databases-and-site-ops";
import { AddDomainPage, CreateWebsitePage } from "./hosting-wizards";
import { KnowledgeBaseArticlePage, KnowledgeBaseHomePage } from "./kb-pages";
import { EmailManagementPage } from "./mail-pages";
import { HostAlertsPage, HostFirewallPage, SiteMaintenancePage } from "./ops-views";
import {
  ArtifactPage,
  HostMetrics,
  HostServices,
  OperationDetail,
  OperationsPage,
  Overview,
  PlanDetail,
  ReceiptPage,
  RecoveryPage,
  SettingsPage,
  SiteConfiguration,
  SiteOperations,
  SiteOverview,
  SiteRecovery,
  SitesPage,
  StatesPage,
} from "./pages";
import { PlanNew, PlanReview } from "./plan-workflow";
import {
  AppDetailPage,
  AppsPage,
  DomainsPage,
  HostDiagnosesPage,
  HostUpdatesPage,
  MigrationPage,
} from "./platform-pages";
import {
  DomainDetailPage,
  DomainDnsPage,
  EmDashMigrationDetailPage,
  RecoverySchedulesPage,
  RecoveryStorePage,
} from "./platform-subviews";
import { HostCronPage, HostLogsPage } from "./server-ops-pages";
import { Shell } from "./shell";

const rootRoute = createRootRoute({
  component: () => (
    <Shell>
      <Outlet />
    </Shell>
  ),
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
  component: function AppDetailRoute() {
    const { appId } = appDetailRoute.useParams();
    return <AppDetailPage appId={appId} />;
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

const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

export function AppRouter() {
  return <RouterProvider router={router} />;
}
