// One data source for every screen: the live read-only observation when the
// server has one, otherwise the mockup fixture. Screens never mix the two
// silently; the shell labels which one is showing and how old it is.
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
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
  refresh: () => Promise<void>;
};

const noopRefresh = async () => {};

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

const DataContext = createContext<Data>(fixture);

export function useData() {
  return useContext(DataContext);
}

type Reply =
  | { kind: "fixture" }
  | { kind: "live"; observation: Observation; observedAt: number }
  | { kind: "unavailable"; reason: string; notEnrolled?: true };

/** W347: the executor answered EXECUTOR_NOT_ENROLLED; there is no journal to show. */
const notEnrolled: Reply = {
  kind: "unavailable",
  reason: "the executor is installed but not enrolled (EXECUTOR_NOT_ENROLLED)",
  notEnrolled: true,
};

async function loadFromEndpoint(endpoint: string): Promise<Reply> {
  try {
    const response = await fetch(endpoint, { cache: "no-store" });
    if (!response.ok) return { kind: "unavailable", reason: `server answered ${response.status}` };
    const body = (await response.json()) as {
      source?: string;
      observed_at?: number;
      observation?: unknown;
    };
    if (body.source === "fixture") return { kind: "fixture" };
    if (isExecutorRefusal(body.observation)) return notEnrolled;
    if (typeof body.observed_at !== "number" || !isObservation(body.observation)) {
      return { kind: "unavailable", reason: "unrecognised observation" };
    }
    return { kind: "live", observation: body.observation, observedAt: body.observed_at };
  } catch {
    return { kind: "unavailable", reason: "console server unreachable" };
  }
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
  try {
    const response = await fetch("/api/backend/status", { cache: "no-store" });
    if (!response.ok) return null;
    const body = (await response.json()) as Partial<BackendStatus> | null;
    if (body?.schema !== "rustiron-console-backend/1") return null;
    return body as BackendStatus;
  } catch {
    return null;
  }
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
  const [data, setData] = useState<Data>({ ...fixture, source: { kind: "loading" } });
  const [refreshing, setRefreshing] = useState(false);
  const apply = useRef(noopRefresh);
  useEffect(() => {
    let active = true;
    let last: { observation: Observation; observedAt: number } | null = null;
    async function refresh(manual = false) {
      if (manual && active) setRefreshing(true);
      const backend = await loadBackendStatus();
      const reply = await load(backend);
      if (!active) return;
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
  return (
    <DataContext.Provider value={{ ...data, refreshing, refresh }}>{children}</DataContext.Provider>
  );
}
