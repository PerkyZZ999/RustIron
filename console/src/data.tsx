// One data source for every screen: the live read-only observation when the
// server has one, otherwise the mockup fixture. Screens never mix the two
// silently; the shell labels which one is showing and how old it is.
import { consoleRequest } from "./console-request";
import {
  createContext,
  type ReactNode,
  useCallback,
  use,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { BackendStatus } from "./backend-server";
import {
  type HostService,
  hostServices,
  type OperationRow,
  operationRows,
  type RecoveryRow,
  recoveryRows,
  type Site,
  sites,
  type SiteSnapshot,
} from "./fixture";
import {
  isExecutorRefusal,
  isObservation,
  liveOperations,
  liveRecovery,
  liveServices,
  liveSiteSnapshots,
  liveSites,
  type Machine,
  type Observation,
} from "./live";

/** Older than this, a live observation is shown as stale. */
const STALE_MS = 60_000;
const POLL_MS = 15_000;

type Source =
  | { kind: "fixture" }
  | { kind: "loading" }
  | { kind: "live"; observedAt: number; stale: boolean; host: Observation["host"] }
  | { kind: "unavailable"; reason: string; notEnrolled?: true };

type Data = {
  source: Source;
  sites: Site[];
  operations: OperationRow[];
  recovery: RecoveryRow[];
  siteSnapshots: Record<string, SiteSnapshot[]>;
  services: HostService[];
  /** Live host status; null on fixture data or when the host read failed. */
  machine: Machine | null;
  /** The live journal snapshot; null on fixture data. */
  observation: Observation | null;
  /** W612 (CP04/D-090): live loopback backend adapter status; null when offline/unprobed. */
  backend: BackendStatus | null;
  /** True while an on-demand refresh is in flight. */
  refreshing: boolean;
  /** Re-reads /api/observation (or /api/coordinator/live). */
  /** Resolves true when a live or fixture observation arrived, false when it did not. */
  refresh: () => Promise<boolean>;
};

const noopRefresh = async () => false;

const fixture: Data = {
  source: { kind: "fixture" },
  sites,
  operations: operationRows,
  recovery: recoveryRows,
  siteSnapshots: {},
  services: hostServices,
  machine: null,
  observation: null,
  backend: null,
  refreshing: false,
  refresh: noopRefresh,
};

const loadingData: Data = {
  source: { kind: "loading" },
  sites: [],
  operations: [],
  recovery: [],
  siteSnapshots: {},
  services: [],
  machine: null,
  observation: null,
  backend: null,
  refreshing: false,
  refresh: noopRefresh,
};

const DataContext = createContext<Data>(fixture);

/**
 * W732 (QA-01): true unless the Console runs on its sample data. Loading and
 * unavailable sources are the real host with nothing known yet, so they never
 * fall back to sample content.
 */
export function isRealHost(source: Source): boolean {
  return source.kind !== "fixture";
}

/** The host's name for headings: the observed ID, the sample host, or "this host". */
export function hostLabel(source: Source): string {
  if (source.kind === "live") return source.host.host_id;
  return source.kind === "fixture" ? "lab-01" : "this host";
}

export function useData() {
  return use(DataContext);
}

type Reply =
  | { kind: "fixture" }
  | { kind: "live"; observation: Observation; observedAt: number }
  | { kind: "unavailable"; reason: string; notEnrolled?: true };

/** W347: the executor answered EXECUTOR_NOT_ENROLLED; there is no journal to show. */
const notEnrolled: Reply = {
  kind: "unavailable",
  reason: "The executor is installed but not enrolled (EXECUTOR_NOT_ENROLLED)",
  notEnrolled: true,
};

/** W745 (QA-14): what failed and what to check, per server code (Runbook 38). */
const UNAVAILABLE_REASONS: Record<string, string> = {
  LIVE_SOURCE_NOT_CONFIGURED:
    "No observation file is configured; set RUSTIRON_OBSERVATION and enable rustiron-console-observe.timer (Runbook 38)",
  UNAUTHORIZED_PEER:
    "The coordinator refused the Console's user; run the Console as rustiron-coordinator (Runbook 38)",
  COORDINATOR_NOT_CONFIGURED: "No coordinator socket is configured (RUSTIRON_COORDINATOR_SOCKET)",
  DEPENDENCY_UNAVAILABLE:
    "The coordinator's inventory or executor is not answering; check rustiron-coordinator and rustiron-executor",
};

export function unavailableReason(status: number | null, code: string | null): string {
  if (status === null) return "The Console server did not answer";
  const reason = code === null ? undefined : UNAVAILABLE_REASONS[code];
  if (reason) return reason;
  return code ? `The server answered ${status} (${code})` : `The server answered ${status}`;
}

async function loadFromEndpoint(endpoint: string): Promise<Reply> {
  const reply = await consoleRequest<{
    source?: string;
    observed_at?: number;
    observation?: unknown;
  } | null>(endpoint);
  if (!reply.ok) {
    return { kind: "unavailable", reason: unavailableReason(reply.status, reply.code) };
  }
  const body = reply.data ?? {};
  if (body.source === "fixture") return { kind: "fixture" };
  if (isExecutorRefusal(body.observation)) return notEnrolled;
  if (typeof body.observed_at !== "number" || !isObservation(body.observation)) {
    return {
      kind: "unavailable",
      reason: "The server sent an observation this Console does not recognise",
    };
  }
  return { kind: "live", observation: body.observation, observedAt: body.observed_at };
}

async function load(backend: BackendStatus | null): Promise<Reply> {
  const obsReply = await loadFromEndpoint("/api/observation");
  if (obsReply.kind === "live") return obsReply;
  if (backend?.coordinator_configured) {
    return loadFromEndpoint("/api/coordinator/live");
  }
  return obsReply;
}

async function loadBackendStatus(): Promise<BackendStatus | null> {
  const reply = await consoleRequest<Partial<BackendStatus> | null>("/api/backend/status");
  if (!reply.ok || reply.data?.schema !== "rustiron-console-backend/1") return null;
  return reply.data as BackendStatus;
}

function toData(
  observation: Observation,
  observedAt: number,
  now: number,
  backend: BackendStatus | null,
): Data {
  return {
    source: {
      kind: "live",
      observedAt,
      stale: now - observedAt > STALE_MS,
      host: observation.host,
    },
    sites: liveSites(observation),
    operations: liveOperations(observation),
    recovery: liveRecovery(observation),
    siteSnapshots: liveSiteSnapshots(observation),
    services: observation.machine ? liveServices(observation.machine) : [],
    machine: observation.machine ?? null,
    observation,
    backend,
    refreshing: false,
    refresh: noopRefresh,
  };
}

export function DataProvider({ children }: { children: ReactNode }) {
  // W736 (QA-05): nothing is known before the first reply; the sample data
  // appears only when the server says the Console runs on it.
  const [data, setData] = useState<Data>(loadingData);
  const [refreshing, setRefreshing] = useState(false);
  const apply = useRef(noopRefresh);
  useEffect(() => {
    let active = true;
    let last: { observation: Observation; observedAt: number } | null = null;
    async function refresh(manual = false): Promise<boolean> {
      if (manual && active) setRefreshing(true);
      const backend = await loadBackendStatus();
      const reply = await load(backend);
      if (!active) return false;
      setRefreshing(false);
      if (reply.kind === "fixture") setData({ ...fixture, backend });
      else if (reply.kind === "live") {
        last = reply;
        setData(toData(reply.observation, reply.observedAt, Date.now(), backend));
      } else if (last && !reply.notEnrolled) {
        // Keep the last observation visible, marked stale, rather than blanking.
        setData(toData(last.observation, last.observedAt, Number.POSITIVE_INFINITY, backend));
      } else {
        // Not enrolled is a definite executor answer: an older journal view is not kept.
        last = null;
        setData({
          source: { ...reply },
          sites: [],
          operations: [],
          recovery: [],
          siteSnapshots: {},
          services: [],
          machine: null,
          observation: null,
          backend,
          refreshing: false,
          refresh: noopRefresh,
        });
      }
      return reply.kind !== "unavailable";
    }
    apply.current = () => refresh(true);
    void refresh(false);
    const timer = setInterval(() => void refresh(false), POLL_MS);
    return () => {
      active = false;
      apply.current = noopRefresh;
      clearInterval(timer);
    };
  }, []);
  const refresh = useCallback(() => apply.current(), []);
  const value = useMemo(() => ({ ...data, refreshing, refresh }), [data, refreshing, refresh]);
  return <DataContext.Provider value={value}>{children}</DataContext.Provider>;
}
