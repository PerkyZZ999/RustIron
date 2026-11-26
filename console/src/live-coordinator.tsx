// W626: Real on-demand coordinator IPC inspection & redacted evidence export
// panels (progressive disclosure) for SiteDetail and OperationDetail views.
import { ChevronDown, Download, RefreshCw, Terminal } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

import { useData } from "./data";
import { Glyph } from "./ui";

type FetchState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; code: string }
  | { kind: "ok"; payload: unknown; fetchedAt: string };

async function fetchCoordinatorJson(path: string): Promise<FetchState> {
  try {
    const res = await fetch(path, { cache: "no-store" });
    const body = (await res.json()) as { error?: string; data?: { value?: unknown } };
    if (!res.ok) return { kind: "error", code: body.error ?? `HTTP_${res.status}` };
    return {
      kind: "ok",
      payload: body.data?.value ?? body,
      fetchedAt: new Date().toISOString().slice(11, 19) + " UTC",
    };
  } catch {
    return { kind: "error", code: "COORDINATOR_UNREACHABLE" };
  }
}

function triggerJsonDownload(filename: string, payload: unknown) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function triggerCsvDownload(filename: string, rows: string[][]) {
  const csv = rows
    .map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function LiveSiteCoordinatorPanel({ siteId }: { siteId: string }) {
  const { backend } = useData();
  const reachable = backend?.coordinator_reachable === true;
  const [state, setState] = useState<FetchState>({ kind: "idle" });

  const load = useCallback(async () => {
    setState({ kind: "loading" });
    setState(await fetchCoordinatorJson(`/api/coordinator/sites/${encodeURIComponent(siteId)}`));
  }, [siteId]);

  useEffect(() => {
    if (!reachable) return undefined;
    let active = true;
    void fetchCoordinatorJson(`/api/coordinator/sites/${encodeURIComponent(siteId)}`).then(
      (res) => {
        if (active) setState(res);
      },
    );
    return () => {
      active = false;
    };
  }, [reachable, siteId]);

  if (!reachable) return null;

  return (
    <details className="disclose">
      <summary>
        <Glyph icon={Terminal} />
        <span>Live coordinator record (/api/coordinator/sites/{siteId})</span>
        <Glyph icon={ChevronDown} className="chev" />
      </summary>
      <div className="d-body">
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 10 }}>
          <span className="cap">
            {state.kind === "ok"
              ? `Fetched at ${state.fetchedAt}`
              : state.kind === "loading"
                ? "Querying local Unix socket…"
                : state.kind === "error"
                  ? `Coordinator returned ${state.code}`
                  : "Connected to local coordinator"}
          </span>
          <button type="button" className="btn quiet sm" onClick={() => void load()}>
            <Glyph icon={RefreshCw} />
            Refresh
          </button>
        </div>
        {state.kind === "ok" ? (
          <pre className="code signed-bytes">{JSON.stringify(state.payload, null, 2)}</pre>
        ) : null}
      </div>
    </details>
  );
}

export function LiveOperationEvidenceBar({
  operationId,
  fallbackPayload,
}: {
  operationId: string;
  fallbackPayload: unknown;
}) {
  const { backend } = useData();
  const reachable = backend?.coordinator_reachable === true;
  const [liveStatus, setLiveStatus] = useState<FetchState>({ kind: "idle" });
  const [liveEvidence, setLiveEvidence] = useState<FetchState>({ kind: "idle" });

  const load = useCallback(async () => {
    setLiveStatus({ kind: "loading" });
    setLiveEvidence({ kind: "loading" });
    const [statusRes, evRes] = await Promise.all([
      fetchCoordinatorJson(`/api/coordinator/operations/${encodeURIComponent(operationId)}`),
      fetchCoordinatorJson(`/api/coordinator/evidence/${encodeURIComponent(operationId)}`),
    ]);
    setLiveStatus(statusRes);
    setLiveEvidence(evRes);
  }, [operationId]);

  useEffect(() => {
    if (!reachable) return undefined;
    let active = true;
    void Promise.all([
      fetchCoordinatorJson(`/api/coordinator/operations/${encodeURIComponent(operationId)}`),
      fetchCoordinatorJson(`/api/coordinator/evidence/${encodeURIComponent(operationId)}`),
    ]).then(([statusRes, evRes]) => {
      if (!active) return;
      setLiveStatus(statusRes);
      setLiveEvidence(evRes);
    });
    return () => {
      active = false;
    };
  }, [reachable, operationId]);

  const exportPayload = liveEvidence.kind === "ok" ? liveEvidence.payload : fallbackPayload;

  return (
    <section className="panel" aria-label="Operation evidence export and live status">
      <div className="panel-head">
        <h2>Evidence export</h2>
        <div className="row" style={{ gap: 8 }}>
          {reachable ? (
            <button type="button" className="btn quiet sm" onClick={() => void load()}>
              <Glyph icon={RefreshCw} />
              Query coordinator
            </button>
          ) : null}
          <button
            type="button"
            className="btn sm"
            onClick={() =>
              triggerJsonDownload(`rustiron-evidence-${operationId}.json`, exportPayload)
            }
          >
            <Glyph icon={Download} />
            Download redacted JSON
          </button>
        </div>
      </div>
      <p className="cap">
        {liveEvidence.kind === "ok"
          ? `Live coordinator evidence fetched at ${liveEvidence.fetchedAt}. Redacted: no secrets or private keys.`
          : "Exports the redacted operation record from this observation without credentials or signing keys."}
      </p>
      {liveStatus.kind === "ok" ? (
        <details className="disclose" style={{ marginTop: 12 }}>
          <summary>
            <Glyph icon={Terminal} />
            <span>Live coordinator operation_status ({liveStatus.fetchedAt})</span>
            <Glyph icon={ChevronDown} className="chev" />
          </summary>
          <div className="d-body">
            <pre className="code signed-bytes">{JSON.stringify(liveStatus.payload, null, 2)}</pre>
          </div>
        </details>
      ) : null}
    </section>
  );
}
