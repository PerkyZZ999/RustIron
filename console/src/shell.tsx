import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  ArrowLeftRight,
  ArrowRight,
  Bell,
  BookOpen,
  Box,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock,
  ClockAlert,
  Database,
  FileText,
  Gauge,
  Globe,
  History,
  House,
  Link2,
  ListChecks,
  Mail,
  Menu,
  Moon,
  RefreshCw,
  Search,
  Server,
  ServerOff,
  Settings,
  Shield,
  Sun,
  UserRound,
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import { RefreshCwIcon, type RefreshCwIconHandle } from "lucide-animated";
import {
  createContext,
  type ReactNode,
  type RefObject,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";

import { BrandLockup, BrandMark } from "@/components/console/brand-logo";
import { CommandDialog, CommandDialogPopup } from "@/components/ui/command-dialog";
import { Popover, PopoverPopup, PopoverTrigger } from "@/components/ui/popover";
import { ToastProvider, toastManager } from "@/components/ui/toast";
import { initConsoleLog, logInteraction, logPageView } from "@/lib/log";
import { cn } from "@/lib/utils";
import { StandaloneAuthGate } from "./accounts-pages";
import { AuthProvider, useAuth } from "./auth-context";
import { DataProvider, useData } from "./data";
import { searchTargets } from "./fixture";
import { articleBySlug, kbSearchTargets } from "./kb-data";
import { consoleSearchPages, liveAttention, liveSearchTargets } from "./live";
import { PlanDraftProvider } from "./plan-workflow";
import { PreferencesProvider } from "./prefs";
import { Glyph } from "./ui";

type Mode = "light" | "dark";

type NavItem = {
  to: string;
  label: string;
  icon: LucideIcon;
  match: "exact" | "prefix";
};

const navGroups: { heading?: string; items: NavItem[] }[] = [
  {
    items: [{ to: "/", label: "Overview", icon: House, match: "exact" }],
  },
  {
    heading: "Hosting",
    items: [
      { to: "/sites", label: "Sites", icon: Globe, match: "prefix" },
      { to: "/apps", label: "Apps", icon: Box, match: "prefix" },
      { to: "/databases", label: "Databases", icon: Database, match: "prefix" },
      { to: "/migration", label: "Migration", icon: ArrowLeftRight, match: "prefix" },
    ],
  },
  {
    heading: "Domains & mail",
    items: [
      { to: "/domains", label: "Domains", icon: Link2, match: "prefix" },
      { to: "/mail", label: "Email", icon: Mail, match: "prefix" },
    ],
  },
  {
    heading: "Safety",
    items: [
      { to: "/recovery", label: "Recovery", icon: History, match: "prefix" },
      { to: "/operations", label: "Operations", icon: Activity, match: "prefix" },
    ],
  },
  {
    heading: "Host",
    items: [
      { to: "/host/metrics", label: "Metrics", icon: Gauge, match: "prefix" },
      { to: "/host/services", label: "Services", icon: Server, match: "prefix" },
      { to: "/host/firewall", label: "Firewall", icon: Shield, match: "prefix" },
      { to: "/host/cron", label: "Cron jobs", icon: Clock, match: "prefix" },
      { to: "/host/logs", label: "Logs", icon: FileText, match: "prefix" },
      { to: "/host/diagnoses", label: "Diagnoses", icon: ListChecks, match: "prefix" },
      { to: "/host/alerts", label: "Alerts", icon: Bell, match: "prefix" },
      { to: "/host/updates", label: "Updates", icon: RefreshCw, match: "prefix" },
    ],
  },
];

const utilities = [
  { to: "/users", label: "Users", icon: Users },
  { to: "/settings", label: "Settings", icon: Settings },
  { to: "/help", label: "Docs & KB", icon: BookOpen },
];

const segmentLabels: Record<string, string> = {
  host: "Host",
  new: "New",
  dns: "DNS",
  emdash: "EmDash",
  cron: "Cron jobs",
  states: "Shared states",
  mail: "Email",
  relay: "Relay",
  users: "Users & access",
  help: "Docs & KB",
};

const RESOURCE_ID_RE = /^(?:[a-z]+_[A-Z0-9]+|(?:site|op|app|plan|snap|rcpt)_.*)$/;

function formatSegment(segment: string): string {
  if (RESOURCE_ID_RE.test(segment)) return segment;
  const kb = articleBySlug(segment);
  if (kb) return kb.title;
  return segmentLabels[segment] ?? segment.charAt(0).toUpperCase() + segment.slice(1);
}

function breadcrumbFor(pathname: string): { label: string; href?: string }[] {
  if (pathname === "/") return [{ label: "Host overview" }];
  const segments = pathname.split("/").filter(Boolean);
  let href = "";
  return segments.map((segment, index) => {
    href += `/${segment}`;
    const isLast = index === segments.length - 1;
    return { label: formatSegment(segment), href: isLast ? undefined : href };
  });
}

function current(path: string, to: string, match: "exact" | "prefix") {
  if (to === "/") return path === "/";
  if (match === "exact") return path === to;
  if (to === "/operations") return path.startsWith("/operations") || path.startsWith("/plans");
  return path === to || path.startsWith(`${to}/`);
}

function NavLink({
  to,
  label,
  icon: Icon,
  selected,
  onNavigate,
}: {
  to: string;
  label: string;
  icon: LucideIcon;
  selected: boolean;
  onNavigate: () => void;
}) {
  return (
    <li>
      <Link
        to={to}
        onClick={onNavigate}
        aria-current={selected ? "page" : undefined}
        className={cn(
          "group relative flex h-9 items-center gap-3 rounded-control px-3 text-sm transition-colors duration-150 ease-out hover:no-underline",
          selected
            ? "bg-selection font-medium text-foreground"
            : "font-normal text-muted-foreground hover:bg-hover hover:text-foreground",
        )}
      >
        {selected ? (
          <span
            aria-hidden="true"
            className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-primary"
          />
        ) : null}
        <Icon
          aria-hidden="true"
          className={cn(
            "size-4.5 shrink-0 transition-colors duration-150",
            selected ? "text-foreground" : "text-muted-foreground group-hover:text-foreground",
          )}
          strokeWidth={selected ? 2 : 1.75}
        />
        <span className="truncate">{label}</span>
      </Link>
    </li>
  );
}

const darkQuery = "(prefers-color-scheme: dark)";

export type ThemePreference = "system" | Mode;

function ageText(observedAt: number) {
  const seconds = Math.max(0, Math.round((Date.now() - observedAt) / 1000));
  if (seconds < 60) return `${seconds} s ago`;
  const minutes = Math.round(seconds / 60);
  return minutes < 60 ? `${minutes} min ago` : `${Math.round(minutes / 60)} h ago`;
}

function SourceBadge() {
  const { source } = useData();
  if (source.kind === "loading") {
    return (
      <span className="fixture" role="status">
        Loading observation…
      </span>
    );
  }
  if (source.kind === "unavailable") {
    return (
      <span className="fixture" role="status">
        {source.notEnrolled ? "Live · executor not enrolled" : "Live data unavailable"}
      </span>
    );
  }
  if (source.kind === "live") {
    return (
      <span className="fixture" role="status">
        Live · {source.host.host_id} · {source.stale ? "stale" : ageText(source.observedAt)}
      </span>
    );
  }
  return <span className="fixture">Fixture data · not live</span>;
}

function initialPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem("ri-theme");
    if (stored === "dark" || stored === "light") return stored;
  } catch {
    // Storage can be unavailable; the system preference is the fallback.
  }
  return "system";
}

function systemMode(): Mode {
  try {
    return window.matchMedia(darkQuery).matches ? "dark" : "light";
  } catch {
    return "dark";
  }
}

const ThemeContext = createContext<{
  preference: ThemePreference;
  mode: Mode;
  setPreference: (next: ThemePreference) => void;
}>({ preference: "system", mode: "dark", setPreference: () => {} });

/** Theme preference shared by the top bar toggle and the settings page. */
export function useThemePreference() {
  return useContext(ThemeContext);
}

function userInitials(name: string): string {
  const letters = name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
  return letters || "OP";
}

function SourceStatusIcon() {
  const { source } = useData();
  if (source.kind === "unavailable" && source.notEnrolled) {
    return <ServerOff aria-hidden="true" className="size-3 shrink-0 text-warning" />;
  }
  if (source.kind === "live" && source.stale) {
    return <ClockAlert aria-hidden="true" className="size-3 shrink-0 text-warning" />;
  }
  return <CircleCheck aria-hidden="true" className="size-3 shrink-0 text-success" />;
}

function operatorCardInfo(
  source: ReturnType<typeof useData>["source"],
  backend: ReturnType<typeof useData>["backend"],
  user: { name: string; role: string } | null,
) {
  return {
    host: source.kind === "live" ? source.host.host_id : "lab-01",
    href: user ? "/users" : "/login",
    name: user ? user.name : "Operator",
    roleLabel: user ? user.role : "Local session",
    initials: user ? userInitials(user.name) : null,
    modeLabel: backend?.write_workflows_enabled
      ? "Rustiron Console · signed apply"
      : "Rustiron Console · read-only",
  };
}

function SidebarOperatorCard({ onNavigate }: { onNavigate: () => void }) {
  const { source, backend } = useData();
  const { status } = useAuth();
  const info = operatorCardInfo(source, backend, status?.session?.user ?? null);

  return (
    <div className="sidebar-foot mt-3 rounded-control border border-border bg-subtle p-3 text-xs">
      <Link
        to={info.href}
        onClick={onNavigate}
        className="flex items-center gap-2.5 rounded-md transition-colors hover:no-underline"
      >
        <span className="sr-only">Console account</span>
        <span
          aria-hidden="true"
          className="grid size-7 shrink-0 place-items-center rounded-full border border-border bg-raised text-xs font-semibold text-foreground"
        >
          {info.initials ?? <UserRound className="size-3.5" strokeWidth={1.75} />}
        </span>
        <span className="min-w-0 flex-1 leading-tight">
          <span className="block truncate font-medium text-foreground">{info.name}</span>
          <span className="block truncate text-muted-foreground">
            {info.roleLabel} · <span translate="no">{info.host}</span>
          </span>
        </span>
      </Link>
      <div className="mt-2.5 border-t border-border pt-2 text-[11px] leading-4 text-muted-foreground">
        <div className="truncate">{info.modeLabel}</div>
        <div className="mt-0.5 flex items-center gap-1.5">
          <SourceStatusIcon />
          <SourceBadge />
        </div>
      </div>
    </div>
  );
}

function observationMeta(source: ReturnType<typeof useData>["source"]): {
  hostId: string;
  statusLine: string;
  tone: string;
} {
  if (source.kind === "live") {
    return {
      hostId: source.host.host_id,
      statusLine: source.stale ? "Observation stale" : `Observed ${ageText(source.observedAt)}`,
      tone: source.stale ? "text-warning" : "text-success",
    };
  }
  if (source.kind === "unavailable") {
    return {
      hostId: "lab-01",
      statusLine: source.notEnrolled ? "Not enrolled" : "Unavailable",
      tone: "text-destructive",
    };
  }
  return { hostId: "lab-01", statusLine: "Fixture · 38 s ago", tone: "text-success" };
}

function ObservationBadge() {
  const { source } = useData();
  const { hostId, statusLine, tone } = observationMeta(source);

  const isLiveFresh = source.kind === "live" && !source.stale;

  return (
    <div
      className="hidden items-center gap-2 rounded-control border border-border bg-subtle px-2.5 py-1.5 lg:flex"
      aria-label={`Host ${hostId}, ${statusLine}`}
    >
      {isLiveFresh ? (
        <span aria-hidden="true" className="dot ok live-dot-pulse" />
      ) : (
        <CircleCheck aria-hidden="true" className={cn("size-3.5 shrink-0", tone)} strokeWidth={2} />
      )}
      <div className="flex flex-col leading-tight">
        <span className="font-mono text-xs font-medium text-foreground" translate="no">
          {hostId}
        </span>
        <span className="text-[11px] text-muted-foreground">{statusLine}</span>
      </div>
    </div>
  );
}

function isUnitTestDom(): boolean {
  return typeof navigator !== "undefined" && /HappyDOM/i.test(navigator.userAgent);
}

function AuthenticatedShell({
  path,
  mode,
  setPreference,
  children,
}: {
  path: string;
  mode: Mode;
  setPreference: (next: ThemePreference) => void;
  children: ReactNode;
}) {
  const { status, resolved } = useAuth();
  const [navOpen, setNavOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");
  const searchId = useId();
  const menuRef = useRef<HTMLButtonElement>(null);

  const locked = Boolean(status?.auth_required && !status.session);
  const waitingForAuth = !resolved && !isUnitTestDom();

  useEffect(() => {
    if (locked || waitingForAuth) return;
    function onKey(event: KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setQuery("");
        setSearchOpen(true);
      }
      if (event.key === "Escape") setNavOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [locked, waitingForAuth]);

  function closeNav() {
    setNavOpen(false);
    menuRef.current?.focus();
  }

  // W648: Do not flash the Console sidebar/topbar while initial auth status resolves in a browser.
  if (waitingForAuth) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-foreground">
        <main id="main" className="flex flex-col items-center gap-3 text-center">
          <BrandMark className="size-10" />
          <h1 className="sr-only">Loading RustIron Console</h1>
          <span className="text-sm text-muted-foreground" role="status">
            Checking session…
          </span>
        </main>
      </div>
    );
  }

  // W648: Full-screen standalone auth gate — zero sidebar, topbar, search, or host data when signed out.
  if (locked) {
    return (
      <StandaloneAuthGate themeControl={<ThemeToggle mode={mode} onChoose={setPreference} />} />
    );
  }

  const sessionKey = status?.session?.sessionId ?? "open";

  return (
    <DataProvider key={sessionKey}>
      <PlanDraftProvider>
        <div className={navOpen ? "app nav-open" : "app"}>
          <a className="skip-link" href="#main">
            Skip to content
          </a>
          <ConsoleSidebar
            path={path}
            navOpen={navOpen}
            onNavigate={() => setNavOpen(false)}
            onClose={closeNav}
          />
          <button type="button" className="scrim" aria-label="Close menu" onClick={closeNav} />
          <div className="main-col">
            <ConsoleTopbar
              path={path}
              navOpen={navOpen}
              mode={mode}
              menuRef={menuRef}
              onOpenNav={() => setNavOpen(true)}
              onOpenSearch={() => setSearchOpen(true)}
              onChooseTheme={setPreference}
            />
            <main id="main">{children}</main>
          </div>
          <SearchPalette
            open={searchOpen}
            onOpenChange={setSearchOpen}
            query={query}
            setQuery={setQuery}
            searchId={searchId}
          />
        </div>
      </PlanDraftProvider>
    </DataProvider>
  );
}

function SearchPalette({
  open,
  onOpenChange,
  query,
  setQuery,
  searchId,
}: {
  open: boolean;
  onOpenChange: (next: boolean) => void;
  query: string;
  setQuery: (value: string) => void;
  searchId: string;
}) {
  const data = useData();
  const navigate = useNavigate();
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const titleId = useId();
  const baseTargets =
    data.source.kind === "fixture"
      ? searchTargets
      : data.observation
        ? liveSearchTargets(data.observation)
        : consoleSearchPages;
  const targets = [...baseTargets, ...kbSearchTargets()];
  const needle = query.trim().toLowerCase();
  const matches = targets.filter((item) => item.label.toLowerCase().includes(needle));

  function openTarget(href: string) {
    onOpenChange(false);
    setQuery("");
    logInteraction("command_navigate", { href });
    void navigate({ to: href });
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) setQuery("");
      }}
    >
      <CommandDialogPopup aria-labelledby={titleId}>
        <div className="flex items-center gap-2.5 border-b border-border px-4 py-3">
          <h2 id={titleId} className="sr-only">
            Search Console
          </h2>
          <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
          <input
            id={searchId}
            aria-label="Search sites, operations, artifacts"
            placeholder="Jump to sites, apps, domains, operations…"
            value={query}
            autoComplete="off"
            spellCheck={false}
            className="w-full min-w-0 bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && matches[0]) {
                event.preventDefault();
                openTarget(matches[0].href);
              }
            }}
          />
          <button
            type="button"
            aria-label="Close search"
            onClick={() => onOpenChange(false)}
            className="grid size-7 shrink-0 cursor-pointer place-items-center rounded-control text-muted-foreground transition-colors hover:bg-hover hover:text-foreground"
          >
            <X aria-hidden="true" className="size-4" />
          </button>
        </div>
        <ul className="max-h-80 overflow-y-auto scrollbar-thin p-2">
          {matches.length === 0 ? (
            <li className="px-3 py-8 text-center text-sm text-muted-foreground">
              No matches. Filters do not run host commands.
            </li>
          ) : (
            matches.map((item) => (
              <li key={item.href}>
                <button
                  type="button"
                  onClick={() => openTarget(item.href)}
                  className="flex w-full cursor-pointer items-center justify-between gap-3 rounded-control px-3 py-2 text-left text-sm text-foreground transition-colors hover:bg-selection"
                >
                  <span className="truncate">{item.label}</span>
                  {item.href === pathname ? (
                    <span className="rounded-full border border-border bg-subtle px-2 py-0.5 text-xs text-muted-foreground">
                      Current
                    </span>
                  ) : (
                    <ArrowRight
                      aria-hidden="true"
                      className="size-3.5 shrink-0 text-muted-foreground"
                    />
                  )}
                </button>
              </li>
            ))
          )}
        </ul>
        <div className="flex items-center justify-between border-t border-border bg-subtle px-4 py-2 text-xs text-muted-foreground">
          <span>↵ Open first match · Esc Close</span>
          <span>Read-only jump list</span>
        </div>
      </CommandDialogPopup>
    </CommandDialog>
  );
}

const fixtureAttention = {
  count: 1,
  items: [
    {
      href: "/operations/op_7Q2KX9",
      label: "Config activation op_7Q2KX9 · shop.lab.test",
    },
  ],
};

function NotificationsButton() {
  const data = useData();
  const [open, setOpen] = useState(false);
  const attention =
    data.source.kind === "fixture"
      ? fixtureAttention
      : data.observation
        ? liveAttention(data.observation)
        : { count: 0, items: [] };
  const { count, items } = attention;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        aria-label={count > 0 ? `Notifications, ${count} need attention` : "Notifications"}
        className="relative grid size-9 cursor-pointer place-items-center rounded-control border border-border bg-raised text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:bg-hover hover:text-foreground active:scale-[0.98]"
      >
        <Bell aria-hidden="true" className="size-4" strokeWidth={1.75} />
        {count > 0 ? (
          <span
            aria-hidden="true"
            className="absolute -right-1.5 -top-1.5 grid h-4.5 min-w-4.5 place-items-center rounded-full border border-destructive bg-error-surface px-1 text-[11px] font-semibold leading-none text-destructive tabular"
          >
            {count}
          </span>
        ) : null}
      </PopoverTrigger>
      <PopoverPopup align="end" className="w-84 overflow-hidden p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-sm font-semibold text-foreground">
            {count > 0 ? "Needs attention" : "Notifications"}
          </h2>
          {count > 0 ? (
            <span className="rounded-full border border-border bg-subtle px-2 py-0.5 text-xs font-medium text-muted-foreground tabular">
              {count} open
            </span>
          ) : null}
        </div>
        <ul className="max-h-72 divide-y divide-border overflow-y-auto scrollbar-thin">
          {items.length === 0 ? (
            <li className="px-4 py-8 text-center text-sm text-muted-foreground">
              No current incidents in this observation.
            </li>
          ) : (
            items.map((item) => (
              <li key={`${item.href}-${item.label}`}>
                <Link
                  to={item.href}
                  onClick={() => {
                    setOpen(false);
                    logInteraction("notification_open", { href: item.href });
                  }}
                  className="group flex w-full items-start gap-2.5 px-4 py-3 text-left text-sm text-foreground transition-colors hover:bg-hover hover:no-underline"
                >
                  <CircleAlert
                    aria-hidden="true"
                    className="mt-0.5 size-4 shrink-0 text-destructive"
                  />
                  <span className="min-w-0 flex-1 leading-5">{item.label}</span>
                  <ArrowRight
                    aria-hidden="true"
                    className="mt-1 size-3.5 shrink-0 text-muted-foreground transition-transform duration-150 group-hover:translate-x-0.5 group-hover:text-foreground"
                  />
                </Link>
              </li>
            ))
          )}
        </ul>
        <div className="border-t border-border bg-subtle px-4 py-2.5">
          <Link
            to="/host/diagnoses"
            onClick={() => setOpen(false)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-focus hover:underline"
          >
            View all host diagnoses
            <ArrowRight aria-hidden="true" className="size-3" />
          </Link>
        </div>
      </PopoverPopup>
    </Popover>
  );
}

function TopbarRefreshButton() {
  const { refresh, refreshing } = useData();
  const iconRef = useRef<RefreshCwIconHandle>(null);

  return (
    <button
      className={cn(
        "grid size-9 cursor-pointer place-items-center rounded-control border border-border bg-raised text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:bg-hover hover:text-foreground active:scale-[0.98]",
        refreshing && "text-foreground",
      )}
      type="button"
      aria-label="Refresh host data"
      title="Refresh host data"
      onClick={() => {
        iconRef.current?.startAnimation();
        logInteraction("host_refresh");
        void refresh().then(() => {
          toastManager.add({
            id: "host-refresh",
            type: "success",
            title: "Host data refreshed",
          });
        });
      }}
    >
      <RefreshCwIcon ref={iconRef} size={16} aria-hidden="true" />
    </button>
  );
}

function ThemeToggle({ mode, onChoose }: { mode: Mode; onChoose: (next: Mode) => void }) {
  return (
    <div
      className="inline-flex h-9 items-center rounded-control border border-border bg-subtle p-0.5"
      role="group"
      aria-label="Theme"
    >
      <button
        type="button"
        aria-pressed={mode === "light"}
        aria-label="Light theme"
        onClick={() => onChoose("light")}
        className={cn(
          "grid size-7.5 cursor-pointer place-items-center rounded-[6px] transition-colors",
          mode === "light"
            ? "bg-raised text-foreground shadow-xs"
            : "text-muted-foreground hover:text-foreground",
        )}
      >
        <Sun aria-hidden="true" className="size-4" strokeWidth={1.75} />
      </button>
      <button
        type="button"
        aria-pressed={mode === "dark"}
        aria-label="Dark theme"
        onClick={() => onChoose("dark")}
        className={cn(
          "grid size-7.5 cursor-pointer place-items-center rounded-[6px] transition-colors",
          mode === "dark"
            ? "bg-raised text-foreground shadow-xs"
            : "text-muted-foreground hover:text-foreground",
        )}
      >
        <Moon aria-hidden="true" className="size-4" strokeWidth={1.75} />
      </button>
    </div>
  );
}

function ConsoleSidebar({
  path,
  navOpen,
  onNavigate,
  onClose,
}: {
  path: string;
  navOpen: boolean;
  onNavigate: () => void;
  onClose: () => void;
}) {
  return (
    <nav
      className="sidebar glass-shell border-r border-border scrollbar-thin"
      id="sidebar"
      aria-label="Primary"
    >
      <div className="flex items-center justify-between gap-2 pb-2">
        <Link
          className="flex min-w-0 items-center gap-2 rounded-control px-2 py-1.5 transition-colors hover:bg-hover hover:no-underline"
          to="/"
          onClick={onNavigate}
          aria-label="RustIron Operations Console"
        >
          <BrandLockup className="h-7 w-auto shrink-0" />
          <span className="sr-only">RustIron Operations Console</span>
        </Link>
        {navOpen ? (
          <button
            type="button"
            aria-label="Close navigation menu"
            onClick={onClose}
            className="grid size-8 shrink-0 cursor-pointer place-items-center rounded-control text-muted-foreground transition-colors hover:bg-hover hover:text-foreground md:hidden"
          >
            <X aria-hidden="true" className="size-4" />
          </button>
        ) : null}
      </div>
      <div className="mt-1 flex flex-col gap-1">
        {navGroups.map((group) => (
          <div key={group.heading ?? "top"} className={group.heading ? "pt-3" : undefined}>
            {group.heading ? (
              <div className="px-3 pb-1.5 text-xs font-medium text-muted-foreground">
                {group.heading}
              </div>
            ) : null}
            <ul className="flex flex-col gap-0.5">
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  {...item}
                  selected={current(path, item.to, item.match)}
                  onNavigate={onNavigate}
                />
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="mt-auto pt-5">
        <div className="border-t border-border pt-3">
          <ul className="flex flex-col gap-0.5">
            {utilities.map((item) => (
              <NavLink
                key={item.to}
                {...item}
                selected={current(path, item.to, "prefix")}
                onNavigate={onNavigate}
              />
            ))}
          </ul>
        </div>
        <SidebarOperatorCard onNavigate={onNavigate} />
      </div>
    </nav>
  );
}

function ConsoleTopbar({
  path,
  navOpen,
  mode,
  menuRef,
  onOpenNav,
  onOpenSearch,
  onChooseTheme,
}: {
  path: string;
  navOpen: boolean;
  mode: Mode;
  menuRef: RefObject<HTMLButtonElement | null>;
  onOpenNav: () => void;
  onOpenSearch: () => void;
  onChooseTheme: (next: Mode) => void;
}) {
  const crumbs = breadcrumbFor(path);
  return (
    <header className="topbar glass-shell">
      <div className="flex min-w-0 items-center gap-3">
        <button
          ref={menuRef}
          className="icon-btn menu-btn"
          type="button"
          aria-label="Menu"
          aria-controls="sidebar"
          aria-expanded={navOpen}
          onClick={onOpenNav}
        >
          <Glyph icon={Menu} />
        </button>
        <nav
          aria-label="Breadcrumb"
          className="hidden min-w-0 items-center gap-1.5 text-sm md:flex"
        >
          {crumbs.map((crumb, index) => (
            <span key={`${crumb.label}-${index}`} className="flex min-w-0 items-center gap-1.5">
              {index > 0 ? (
                <ChevronRight
                  aria-hidden="true"
                  className="size-3.5 shrink-0 text-muted-foreground"
                  strokeWidth={2}
                />
              ) : null}
              {crumb.href ? (
                <Link
                  to={crumb.href}
                  className="truncate text-muted-foreground transition-colors hover:text-foreground hover:no-underline"
                >
                  {crumb.label}
                </Link>
              ) : (
                <span aria-current="page" className="truncate font-medium text-foreground">
                  {crumb.label}
                </span>
              )}
            </span>
          ))}
        </nav>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <button
          className="hidden h-9 w-52 cursor-pointer items-center gap-2 rounded-control border border-border bg-subtle px-3 text-sm text-muted-foreground transition-colors duration-150 hover:border-border-strong hover:bg-hover hover:text-foreground sm:flex lg:w-64"
          type="button"
          onClick={onOpenSearch}
        >
          <Search aria-hidden="true" className="size-4 shrink-0" strokeWidth={1.75} />
          <span className="flex-1 truncate text-left">Search Console…</span>
          <kbd className="rounded border border-border bg-surface px-1.5 py-0.5 font-mono text-[11px] leading-none text-muted-foreground">
            Ctrl K
          </kbd>
        </button>
        <button
          type="button"
          aria-label="Open search"
          onClick={onOpenSearch}
          className="grid size-9 cursor-pointer place-items-center rounded-control border border-border bg-raised text-muted-foreground transition-colors hover:border-border-strong hover:bg-hover hover:text-foreground sm:hidden"
        >
          <Search aria-hidden="true" className="size-4" strokeWidth={2} />
        </button>
        <ThemeToggle mode={mode} onChoose={onChooseTheme} />
        <TopbarRefreshButton />
        <NotificationsButton />
        <span aria-hidden="true" className="mx-1 hidden h-6 w-px bg-border lg:block" />
        <ObservationBadge />
      </div>
    </header>
  );
}

function useThemeState() {
  const [preference, setPreferenceState] = useState(initialPreference);
  const [system, setSystem] = useState(systemMode);
  const mode: Mode = preference === "system" ? system : preference;

  useEffect(() => {
    document.documentElement.dataset.theme = mode;
    document.documentElement.style.colorScheme = mode;
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.setAttribute("content", mode);
  }, [mode]);

  useEffect(() => {
    let media: MediaQueryList;
    try {
      media = window.matchMedia(darkQuery);
    } catch {
      return undefined;
    }
    const onChange = () => setSystem(media.matches ? "dark" : "light");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  function setPreference(next: ThemePreference) {
    setPreferenceState(next);
    try {
      if (next === "system") localStorage.removeItem("ri-theme");
      else localStorage.setItem("ri-theme", next);
    } catch {
      // The choice still applies for this visit without storage.
    }
  }

  return { preference, mode, setPreference };
}

export function Shell({ children }: { children: ReactNode }) {
  const path = useRouterState({ select: (state) => state.location.pathname });
  const { preference, mode, setPreference } = useThemeState();

  useEffect(() => {
    initConsoleLog();
  }, []);

  useEffect(() => {
    const pathCrumbs = breadcrumbFor(path);
    logPageView(path, pathCrumbs[pathCrumbs.length - 1]?.label ?? "Host overview");
  }, [path]);

  return (
    <ThemeContext.Provider value={{ preference, mode, setPreference }}>
      <PreferencesProvider>
        <ToastProvider>
          <AuthProvider>
            <AuthenticatedShell path={path} mode={mode} setPreference={setPreference}>
              {children}
            </AuthenticatedShell>
          </AuthProvider>
        </ToastProvider>
      </PreferencesProvider>
    </ThemeContext.Provider>
  );
}
