// W626: Real, functional plan builder, review, blast-radius calculator, and
// offline SSHSIG handoff workflow (replaces static mockup screens on /plans/new
// and /plans/new/review while preserving D-004/D-005/D-098 separate custody).
import { Button } from "@/components/ui/button";
import { Link, useNavigate } from "@tanstack/react-router";
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  FileCode,
  Globe,
  RefreshCw,
  ShieldCheck,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { createContext, type ReactNode, useContext, useEffect, useMemo, useState } from "react";

import {
  buildAppDeployCmd,
  buildConfigActivateCmd,
  buildProductBackupCaptureCmd,
  buildProductRestoreProbeCmd,
  buildSiteCredentialRotateCmd,
  buildSiteProvisionCmd,
  INSPECT_AND_SIGN_STEPS,
} from "./cli-commands";
import { useData } from "./data";
import { Crumbs, Glyph, Page, TableScroll } from "./ui";
import { SeparateCustodyApplyPanel } from "./write-panel";

type PlanAction = "config" | "backup" | "probe" | "provision" | "credential" | "app";

const planActionList: [PlanAction, string, string][] = [
  ["config", "Config activation", "Apply approved settings to a site’s owned include."],
  ["backup", "Backup capture", "Create an encrypted snapshot with retention lock."],
  ["probe", "Recovery probe", "Test restore in an isolated sandbox and emit a receipt."],
  ["provision", "Site provision", "Create an isolated site account, database, and skeleton."],
  [
    "credential",
    "Credential rotation",
    "Rotate a website's MariaDB password locally with zero downtime.",
  ],
  ["app", "Modern app deploy", "Deploy a prebuilt Node.js 22, Bun 1.4, or EmDash 1.6.0 release."],
];

type PlanDraft = {
  action: PlanAction;
  siteId: string;
  hostname: string;
  phpWorkers: string;
  cacheRecipe: string;
  backupMode: "marker" | "frozen";
  snapshotId: string;
  newSiteId: string;
  newHostname: string;
  quotaMib: string;
  appReleaseId: string;
  appRuntime: "node_22_v1" | "bun_1_v1";
  appMigrating: boolean;
  reason: string;
};

const STORAGE_KEY = "ri-plan-draft-v1";

const defaultDraft: PlanDraft = {
  action: "config",
  siteId: "",
  hostname: "",
  phpWorkers: "4",
  cacheRecipe: "litespeed_cache_793_cache_on_v1",
  backupMode: "marker",
  snapshotId: "",
  newSiteId: "site_new",
  newHostname: "new.example.test",
  quotaMib: "2048",
  appReleaseId: "rel-20261124-01",
  appRuntime: "node_22_v1",
  appMigrating: false,
  reason: "",
};

function loadDraft(): PlanDraft {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultDraft;
    const parsed = JSON.parse(raw) as Partial<PlanDraft>;
    return { ...defaultDraft, ...parsed };
  } catch {
    return defaultDraft;
  }
}

type DraftContextValue = {
  draft: PlanDraft;
  patchDraft: (patch: Partial<PlanDraft>) => void;
  resetDraft: () => void;
};

const DraftContext = createContext<DraftContextValue>({
  draft: defaultDraft,
  patchDraft: () => {},
  resetDraft: () => {},
});

export function PlanDraftProvider({ children }: { children: ReactNode }) {
  const [draft, setDraft] = useState<PlanDraft>(loadDraft);

  const patchDraft = (patch: Partial<PlanDraft>) => {
    setDraft((prev) => {
      const next = { ...prev, ...patch };
      try {
        sessionStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Keep in-memory state if sessionStorage is unavailable.
      }
      return next;
    });
  };

  const resetDraft = () => {
    setDraft(defaultDraft);
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore storage errors.
    }
  };

  return (
    <DraftContext.Provider value={{ draft, patchDraft, resetDraft }}>
      {children}
    </DraftContext.Provider>
  );
}

type ComputedPlanMeta = {
  verb: string;
  title: string;
  targetLabel: string;
  olsReload: boolean;
  downtime: string;
  dataLoss: string;
  rollback: string;
  cliCommand: string;
  changes: [string, string][];
  draftJson: Record<string, unknown>;
};

type PlanMetaInput = {
  draft: PlanDraft;
  safeSite: string;
  safeHost: string;
  hostId: string;
  siteCount: number;
  reason: string | undefined;
};

function configMeta({
  draft,
  safeSite,
  safeHost,
  hostId,
  siteCount,
  reason,
}: PlanMetaInput): ComputedPlanMeta {
  return {
    verb: "config_activate",
    title: "Config activation",
    targetLabel: safeHost,
    olsReload: true,
    downtime: "Graceful OLS reload across all served sites",
    dataLoss: "None (configuration generation only)",
    rollback: "Automatic restore to predecessor OLS generation if probe fails",
    cliCommand: buildConfigActivateCmd({
      siteId: safeSite,
      hostId,
      note: `Requested PHP workers ${draft.phpWorkers}, cache ${draft.cacheRecipe}`,
    }),
    changes: [
      ["Target site", `${safeHost} (${safeSite})`],
      ["PHP worker limit", draft.phpWorkers],
      ["Page cache recipe", draft.cacheRecipe],
      ["Affected sites", `1 changed · ${siteCount} reloaded & probed`],
    ],
    draftJson: {
      schema_version: 2,
      verb: "config_activate",
      host_id: hostId,
      site_id: safeSite,
      hostname: safeHost,
      php_workers: Number(draft.phpWorkers) || 4,
      page_cache_recipe: draft.cacheRecipe,
      reason,
    },
  };
}

function backupMeta({
  draft,
  safeSite,
  safeHost,
  hostId,
  reason,
}: PlanMetaInput): ComputedPlanMeta {
  const frozen = draft.backupMode === "frozen";
  return {
    verb: "backup_capture",
    title: "Backup capture",
    targetLabel: safeHost,
    olsReload: false,
    downtime: frozen ? "Up to 10 s serving freeze (503)" : "None (online marker check)",
    dataLoss: "None (read-only snapshot upload with COMPLIANCE lock)",
    rollback: "Failed capture leaves unclaimed snapshot; settle with capture-reconcile",
    cliCommand: buildProductBackupCaptureCmd({
      siteId: safeSite,
      consistency: draft.backupMode,
      hostId,
    }),
    changes: [
      ["Target site", `${safeHost} (${safeSite})`],
      ["Consistency mode", frozen ? "Frozen (10 s cap)" : "Online marker check"],
      ["Store retention", "COMPLIANCE Object Lock verified post-upload"],
    ],
    draftJson: {
      schema_version: 1,
      verb: "backup_capture",
      host_id: hostId,
      site_id: safeSite,
      consistency: draft.backupMode,
      reason,
    },
  };
}

function probeMeta({ draft, safeSite, safeHost, hostId, reason }: PlanMetaInput): ComputedPlanMeta {
  return {
    verb: "restore_probe",
    title: "Recovery probe",
    targetLabel: safeHost,
    olsReload: false,
    downtime: "None (isolated sandbox only)",
    dataLoss: "None (never touches live site root or DB)",
    rollback: "Sandbox cleaned automatically; uncertain cleanup uses probe-cleanup",
    cliCommand: buildProductRestoreProbeCmd({
      siteId: safeSite,
      snapshotId: draft.snapshotId,
      hostId,
    }),
    changes: [
      ["Target site", `${safeHost} (${safeSite})`],
      ["Snapshot ID", draft.snapshotId || "Latest recorded capture"],
      ["Evidence emitted", "7 independent recovery fields + signed receipt"],
    ],
    draftJson: {
      schema_version: 1,
      verb: "restore_probe",
      host_id: hostId,
      site_id: safeSite,
      snapshot_id: draft.snapshotId || null,
      reason,
    },
  };
}

function provisionMeta({ draft, hostId, reason }: PlanMetaInput): ComputedPlanMeta {
  const newSite = draft.newSiteId || "sitenew";
  const newHost = draft.newHostname || "new.example.test";
  const quota = draft.quotaMib || "2048";
  return {
    verb: "site_provision",
    title: "Site provision",
    targetLabel: newHost,
    olsReload: false,
    downtime: "None (site stays unserved until separate config_activate)",
    dataLoss: "None (creates fresh isolated account and DB)",
    rollback: "Failed provision quarantines site without serving; retire via site_retire",
    cliCommand: buildSiteProvisionCmd({
      siteId: newSite,
      hostname: newHost,
      quotaMib: quota,
      hostId,
    }),
    changes: [
      ["New site ID", newSite],
      ["Hostname", newHost],
      ["Install recipe", "WordPress standard install"],
      ["Disk quota", `${quota} MiB`],
    ],
    draftJson: {
      schema_version: 1,
      verb: "site_provision",
      host_id: hostId,
      site_id: newSite,
      hostname: newHost,
      recipe: "wordpress713_install_v1",
      quota_mib: Number(quota) || 2048,
      reason,
    },
  };
}

function credentialMeta({ safeSite, safeHost, hostId, reason }: PlanMetaInput): ComputedPlanMeta {
  return {
    verb: "site_credential_rotate",
    title: "Database credential rotation",
    targetLabel: safeHost,
    olsReload: false,
    downtime: "Brief per-site PHP pool restart only",
    dataLoss: "None (DB password generated locally via getrandom; secret_in_plan: false)",
    rollback: "1 bounded automatic rollback if db.cnf swap or health probe fails",
    cliCommand: buildSiteCredentialRotateCmd({ siteId: safeSite, hostname: safeHost, hostId }),
    changes: [
      ["Target site", `${safeHost} (${safeSite})`],
      ["Secret custody", "Generated on host; never in plan, grant, logs, or browser"],
      ["Verification", "New login ok + old password rejected + HTTP 200"],
    ],
    draftJson: {
      schema_version: 1,
      verb: "site_credential_rotate",
      host_id: hostId,
      site_id: safeSite,
      hostname: safeHost,
      secret_in_plan: false,
      reason,
    },
  };
}

function appMeta({ draft, safeSite, safeHost, hostId, reason }: PlanMetaInput): ComputedPlanMeta {
  const rel = draft.appReleaseId || "rel-01";
  return {
    verb: "app_deploy",
    title: "Modern app deploy",
    targetLabel: safeHost,
    olsReload: false,
    downtime: "Atomic current symlink switch + systemd unit restart",
    dataLoss: draft.appMigrating
      ? "Requires a verified backup capture within 24 h for SQLite rollback"
      : "None (previous release retained read-only under releases/)",
    rollback: "Automatic restore of previous release (and SQLite snapshot) if health probe fails",
    cliCommand: buildAppDeployCmd({
      siteId: safeSite,
      releaseId: rel,
      runtime: draft.appRuntime,
      migrating: draft.appMigrating,
      hostId,
    }),
    changes: [
      ["Target app", `${safeHost} (${safeSite})`],
      ["Release ID", rel],
      ["Runtime profile", draft.appRuntime],
      [
        "Migration guard",
        draft.appMigrating ? "Requires <= 24 h verified backup capture" : "No schema migration",
      ],
    ],
    draftJson: {
      schema_version: 1,
      verb: "app_deploy",
      host_id: hostId,
      site_id: safeSite,
      release_id: rel,
      runtime: draft.appRuntime,
      migrating: draft.appMigrating,
      reason,
    },
  };
}

const metaBuilders: Record<PlanAction, (input: PlanMetaInput) => ComputedPlanMeta> = {
  config: configMeta,
  backup: backupMeta,
  probe: probeMeta,
  provision: provisionMeta,
  credential: credentialMeta,
  app: appMeta,
};

function buildPlanMeta(
  draft: PlanDraft,
  siteId: string,
  hostname: string,
  hostId: string,
  siteCount: number,
): ComputedPlanMeta {
  return metaBuilders[draft.action]({
    draft,
    safeSite: siteId || "site_id",
    safeHost: hostname || "example.test",
    hostId,
    siteCount,
    reason: draft.reason.trim() || undefined,
  });
}

function PlanSteps({ current }: { current: 1 | 2 | 3 }) {
  const items = [
    [1, "Action and inputs"],
    [2, "Review impact and sign"],
    [3, "Track operation"],
  ] as const;
  return (
    <ol className="steps" aria-label="Plan progress">
      {items.map(([number, label]) => {
        const cls = number < current ? "done" : number === current ? "cur" : undefined;
        return (
          <li key={number} className={cls} aria-current={cls === "cur" ? "step" : undefined}>
            <span className="n">{number < current ? <Glyph icon={Check} /> : number}</span>
            {label}
          </li>
        );
      })}
    </ol>
  );
}

function CopyCommandButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return undefined;
    const t = setTimeout(() => setCopied(false), 2000);
    return () => clearTimeout(t);
  }, [copied]);
  return (
    <button
      type="button"
      className="btn quiet sm"
      aria-label={label}
      onClick={() => void navigator.clipboard?.writeText(text).then(() => setCopied(true))}
    >
      <Glyph icon={copied ? Check : Copy} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function SiteSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (siteId: string, hostname: string) => void;
}) {
  const { sites } = useData();
  return (
    <div className="form-row">
      <label htmlFor="p-site">Target site</label>
      {sites.length > 0 ? (
        <select
          id="p-site"
          className="input"
          value={value}
          onChange={(e) => {
            const match = sites.find((s) => s.id === e.target.value);
            onChange(e.target.value, match?.domain ?? e.target.value);
          }}
        >
          {sites.map((site) => (
            <option key={site.id} value={site.id}>
              {site.domain} ({site.id})
            </option>
          ))}
        </select>
      ) : (
        <input
          id="p-site"
          className="input mono"
          value={value}
          placeholder="site_id"
          onChange={(e) => onChange(e.target.value, e.target.value)}
        />
      )}
    </div>
  );
}

function validateDraft(draft: PlanDraft): { workersErr: string | null; quotaErr: string | null } {
  let workersErr: string | null = null;
  if (draft.action === "config") {
    const n = Number(draft.phpWorkers);
    if (!Number.isInteger(n) || n < 1 || n > 16) {
      workersErr = "Must be an integer between 1 and 16.";
    }
  }
  let quotaErr: string | null = null;
  if (draft.action === "provision") {
    const q = Number(draft.quotaMib);
    if (!Number.isInteger(q) || q < 256 || q > 65536) {
      quotaErr = "Must be an integer between 256 and 65536 MiB.";
    }
  }
  return { workersErr, quotaErr };
}

function FieldError({ id, msg }: { id: string; msg: string | null }) {
  if (!msg) return null;
  return (
    <span id={id} className="err-msg" role="alert">
      <Glyph icon={AlertCircle} />
      {msg}
    </span>
  );
}

function ConfigActionFields({
  draft,
  patch,
  workersErr,
}: {
  draft: PlanDraft;
  patch: (p: Partial<PlanDraft>) => void;
  workersErr: string | null;
}) {
  return (
    <>
      <div className="form-row">
        <label htmlFor="p-workers">PHP worker limit (1–16)</label>
        <input
          id="p-workers"
          className="input tnum"
          type="number"
          min={1}
          max={16}
          aria-invalid={workersErr ? "true" : "false"}
          aria-describedby={workersErr ? "p-workers-err" : undefined}
          value={draft.phpWorkers}
          onChange={(e) => patch({ phpWorkers: e.target.value })}
        />
        <FieldError id="p-workers-err" msg={workersErr} />
      </div>
      <div className="form-row">
        <label htmlFor="p-cache">Page cache recipe</label>
        <select
          id="p-cache"
          className="input"
          value={draft.cacheRecipe}
          onChange={(e) => patch({ cacheRecipe: e.target.value })}
        >
          <option value="litespeed_cache_793_cache_on_v1">
            litespeed_cache_793_cache_on_v1 (cache on)
          </option>
          <option value="none">None (opt out)</option>
        </select>
      </div>
    </>
  );
}

function ProvisionActionFields({
  draft,
  patch,
  quotaErr,
}: {
  draft: PlanDraft;
  patch: (p: Partial<PlanDraft>) => void;
  quotaErr: string | null;
}) {
  return (
    <>
      <div className="form-row">
        <label htmlFor="p-new-id">New site ID</label>
        <input
          id="p-new-id"
          className="input mono"
          value={draft.newSiteId}
          onChange={(e) => patch({ newSiteId: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="p-new-host">Hostname</label>
        <input
          id="p-new-host"
          className="input mono"
          value={draft.newHostname}
          onChange={(e) => patch({ newHostname: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="p-quota">Disk quota (MiB)</label>
        <input
          id="p-quota"
          className="input tnum"
          type="number"
          min={256}
          max={65536}
          aria-invalid={quotaErr ? "true" : "false"}
          aria-describedby={quotaErr ? "p-quota-err" : undefined}
          value={draft.quotaMib}
          onChange={(e) => patch({ quotaMib: e.target.value })}
        />
        <FieldError id="p-quota-err" msg={quotaErr} />
      </div>
    </>
  );
}

function AppActionFields({
  draft,
  patch,
}: {
  draft: PlanDraft;
  patch: (p: Partial<PlanDraft>) => void;
}) {
  return (
    <>
      <div className="form-row">
        <label htmlFor="p-rel">Release ID</label>
        <input
          id="p-rel"
          className="input mono"
          value={draft.appReleaseId}
          onChange={(e) => patch({ appReleaseId: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="p-rt">Runtime profile</label>
        <select
          id="p-rt"
          className="input"
          value={draft.appRuntime}
          onChange={(e) => patch({ appRuntime: e.target.value as "node_22_v1" | "bun_1_v1" })}
        >
          <option value="node_22_v1">node_22_v1 (Node.js 22 LTS / EmDash 1.6.0)</option>
          <option value="bun_1_v1">bun_1_v1 (Bun 1.4)</option>
        </select>
      </div>
      <div className="form-row">
        <label htmlFor="p-mig">Database / SQLite migration</label>
        <select
          id="p-mig"
          className="input"
          value={draft.appMigrating ? "yes" : "no"}
          onChange={(e) => patch({ appMigrating: e.target.value === "yes" })}
        >
          <option value="no">No migration script</option>
          <option value="yes">Includes migration (requires &lt;= 24 h verified backup)</option>
        </select>
      </div>
    </>
  );
}

function ActionInputs({
  draft,
  siteId,
  patch,
  workersErr,
  quotaErr,
}: {
  draft: PlanDraft;
  siteId: string;
  patch: (p: Partial<PlanDraft>) => void;
  workersErr: string | null;
  quotaErr: string | null;
}) {
  return (
    <section className="panel" aria-labelledby="in-t">
      <div className="panel-head">
        <h2 id="in-t">Bounded inputs</h2>
        <span className="meta">Closed grammar · no raw directives or shell</span>
      </div>
      <div className="form-grid">
        {draft.action !== "provision" ? (
          <SiteSelect
            value={siteId}
            onChange={(id, host) => patch({ siteId: id, hostname: host })}
          />
        ) : null}

        {draft.action === "config" ? (
          <ConfigActionFields draft={draft} patch={patch} workersErr={workersErr} />
        ) : null}

        {draft.action === "backup" ? (
          <div className="form-row">
            <label htmlFor="p-consistency">Capture consistency</label>
            <select
              id="p-consistency"
              className="input"
              value={draft.backupMode}
              onChange={(e) => patch({ backupMode: e.target.value as "marker" | "frozen" })}
            >
              <option value="marker">Online marker check (zero downtime)</option>
              <option value="frozen">Opt-in serving freeze (max 10 s 503)</option>
            </select>
          </div>
        ) : null}

        {draft.action === "probe" ? (
          <div className="form-row">
            <label htmlFor="p-snap">Snapshot ID (optional — defaults to latest)</label>
            <input
              id="p-snap"
              className="input mono"
              value={draft.snapshotId}
              placeholder="snap_..."
              onChange={(e) => patch({ snapshotId: e.target.value })}
            />
          </div>
        ) : null}

        {draft.action === "provision" ? (
          <ProvisionActionFields draft={draft} patch={patch} quotaErr={quotaErr} />
        ) : null}

        {draft.action === "app" ? <AppActionFields draft={draft} patch={patch} /> : null}

        <div className="form-row" style={{ gridColumn: "1 / -1" }}>
          <label htmlFor="p-reason">Operator note (optional, stored in audit intent)</label>
          <input
            id="p-reason"
            className="input"
            value={draft.reason}
            placeholder="Why this change is needed"
            onChange={(e) => patch({ reason: e.target.value })}
          />
        </div>
      </div>
    </section>
  );
}

export function PlanNew() {
  const data = useData();
  const { draft, patchDraft } = useContext(DraftContext);
  const firstSite = data.sites[0];
  const resolvedSiteId = draft.siteId || firstSite?.id || "";
  const resolvedHostname =
    data.sites.find((s) => s.id === resolvedSiteId)?.domain ||
    draft.hostname ||
    firstSite?.domain ||
    "";
  const hostId = data.source.kind === "live" ? data.source.host.host_id : "lab-01";
  const meta = useMemo(
    () => buildPlanMeta(draft, resolvedSiteId, resolvedHostname, hostId, data.sites.length),
    [draft, resolvedSiteId, resolvedHostname, hostId, data.sites.length],
  );
  const { workersErr, quotaErr } = validateDraft(draft);
  const hasValidationError = Boolean(workersErr || quotaErr);

  return (
    <Page live>
      <Crumbs items={[{ href: "/operations", label: "Operations" }, { label: "New plan" }]} />
      <div className="page-head">
        <div>
          <h1>New plan</h1>
          <p className="sub">
            Choose an approved operation and its bounded inputs. Nothing changes until you review
            the blast radius and sign the grant offline with your operator key.
          </p>
        </div>
      </div>
      <PlanSteps current={1} />
      <div className="grid g-main-side">
        <div className="stack">
          <fieldset className="panel">
            <div className="panel-head">
              <legend>
                <h2>Action</h2>
              </legend>
              <span className="meta">Approved catalogue · {planActionList.length} actions</span>
            </div>
            <div className="grid g2 tight">
              {planActionList.map(([id, title, detail]) => (
                <label
                  key={id}
                  className={draft.action === id ? "radio-card selected" : "radio-card"}
                >
                  <input
                    type="radio"
                    name="plan-action"
                    className="sr-only"
                    value={id}
                    checked={draft.action === id}
                    onChange={() => patchDraft({ action: id })}
                  />
                  <span className="rc-dot" aria-hidden="true" />
                  <strong>{title}</strong>
                  <span className="cap">{detail}</span>
                </label>
              ))}
            </div>
          </fieldset>
          <ActionInputs
            draft={draft}
            siteId={resolvedSiteId}
            patch={patchDraft}
            workersErr={workersErr}
            quotaErr={quotaErr}
          />
          <div className="row end">
            <Link className="btn" to="/operations">
              Cancel
            </Link>
            {hasValidationError ? (
              <Button variant="default" disabled>
                Continue to review
              </Button>
            ) : (
              <Link
                className="btn primary"
                to="/plans/new/review"
                onClick={() => patchDraft({ siteId: resolvedSiteId, hostname: resolvedHostname })}
              >
                Continue to review
                <Glyph icon={ArrowRight} />
              </Link>
            )}
          </div>
        </div>
        <aside className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Impact &amp; blast radius</h2>
              <span className={meta.olsReload ? "pill warn" : "pill ok"}>
                {meta.olsReload ? "All-site OLS reload" : "Single-site scope"}
              </span>
            </div>
            <ul className="list">
              <li>
                <Glyph icon={Globe} className="list-muted" />
                <span className="grow">
                  <span className="t">{meta.targetLabel}</span>
                  <span className="s">Verb: {meta.verb}</span>
                </span>
              </li>
              <li>
                <Glyph
                  icon={meta.olsReload ? RefreshCw : ShieldCheck}
                  className={meta.olsReload ? "list-warn" : "list-ok"}
                />
                <span className="grow">
                  <span className="t">
                    {meta.olsReload
                      ? `All ${data.sites.length} registered sites`
                      : "Neighbors untouched"}
                  </span>
                  <span className="s">{meta.downtime}</span>
                </span>
              </li>
            </ul>
            <p className="cap" style={{ marginTop: 12 }}>
              Rollback boundary: {meta.rollback}
            </p>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>CLI plan command</h2>
              <CopyCommandButton text={meta.cliCommand} label="Copy plan create command" />
            </div>
            <pre className="code signed-bytes">{meta.cliCommand}</pre>
          </section>
        </aside>
      </div>
    </Page>
  );
}

export function PlanReview() {
  const data = useData();
  const navigate = useNavigate();
  const { draft, resetDraft } = useContext(DraftContext);
  const firstSite = data.sites[0];
  const resolvedSiteId = draft.siteId || firstSite?.id || "";
  const resolvedHostname =
    data.sites.find((s) => s.id === resolvedSiteId)?.domain ||
    draft.hostname ||
    firstSite?.domain ||
    "";
  const hostId = data.source.kind === "live" ? data.source.host.host_id : "lab-01";
  const meta = useMemo(
    () => buildPlanMeta(draft, resolvedSiteId, resolvedHostname, hostId, data.sites.length),
    [draft, resolvedSiteId, resolvedHostname, hostId, data.sites.length],
  );
  const signCmd = `${meta.cliCommand}\n${INSPECT_AND_SIGN_STEPS}`;

  return (
    <Page live>
      <Crumbs
        items={[
          { href: "/operations", label: "Operations" },
          { href: "/plans/new", label: "New plan" },
          { label: "Review & sign" },
        ]}
      />
      <div className="page-head">
        <div>
          <h1>Review plan before approval</h1>
          <p className="sub">
            {meta.title} for <span className="mono">{meta.targetLabel}</span> on{" "}
            <span className="mono">{hostId}</span> · separate-custody offline SSHSIG approval
          </p>
        </div>
      </div>
      <PlanSteps current={2} />
      {meta.olsReload ? (
        <div className="attention" role="alert">
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>Global effect: every served site reloads.</strong> This updates one site’s
            configuration, and the graceful OpenLiteSpeed reload and probe cover all{" "}
            {data.sites.length} registered site(s).
          </div>
        </div>
      ) : null}
      <div className="grid g-main-side">
        <div className="stack">
          <section className="panel">
            <div className="panel-head">
              <h2>Planned parameters</h2>
              <span className="mono cap">{meta.verb}</span>
            </div>
            <TableScroll label="Planned parameters">
              <table className="data">
                <thead>
                  <tr>
                    <th scope="col">Field</th>
                    <th scope="col">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {meta.changes.map(([field, val]) => (
                    <tr key={field}>
                      <td>{field}</td>
                      <td className="mono">{val}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </section>
          <section className="panel">
            <div className="panel-head">
              <h2>Consequences &amp; rollback</h2>
            </div>
            <dl className="kv">
              <dt>Downtime exposure</dt>
              <dd>{meta.downtime}</dd>
              <dt>Data-loss exposure</dt>
              <dd>{meta.dataLoss}</dd>
              <dt>Failure / rollback</dt>
              <dd>{meta.rollback}</dd>
              <dt>Uncertain outcome</dt>
              <dd>No automatic silent retry; blocked resources require explicit reconciliation.</dd>
            </dl>
          </section>
          <details className="disclose">
            <summary>
              <Glyph icon={FileCode} />
              <span>Draft parameters JSON (pre-canonicalization)</span>
              <Glyph icon={ChevronDown} className="chev" />
            </summary>
            <div className="d-body">
              <pre className="code signed-bytes">{JSON.stringify(meta.draftJson, null, 2)}</pre>
            </div>
          </details>
          <SeparateCustodyApplyPanel />
        </div>
        <aside className="stack">
          <section className="panel">
            <div className="panel-head">
              <div className="row" style={{ gap: 8 }}>
                <Glyph icon={Terminal} />
                <h2>Sign offline with your key</h2>
              </div>
              <CopyCommandButton text={signCmd} label="Copy offline signing commands" />
            </div>
            <p className="muted" style={{ marginBottom: 8 }}>
              Run on your workstation that holds the operator SSH key, then load or paste the
              generated files in the panel on the left:
            </p>
            <pre className="code signed-bytes">{signCmd}</pre>
            <p className="cap" style={{ marginTop: 8 }}>
              The browser and Console server never store or create signing keys.
            </p>
          </section>
          <div className="row" style={{ gap: 8 }}>
            <Link className="btn" to="/plans/new">
              <Glyph icon={ArrowLeft} />
              Edit inputs
            </Link>
            <Button
              variant="destructive"
              onClick={() => {
                resetDraft();
                void navigate({ to: "/plans/new" });
              }}
            >
              Discard draft
            </Button>
          </div>
        </aside>
      </div>
    </Page>
  );
}
