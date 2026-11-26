// W632 (P29 Slice 12): Interactive Backup Now, Backup Schedule Creator,
// Guided Site Restore Wizard, CyberPanel Import Wizard, and WordPress -> EmDash CMS Wizard.
import { Link } from "@tanstack/react-router";
import {
  ArrowLeftRight,
  CalendarClock,
  Check,
  ChevronDown,
  Copy,
  HardDriveUpload,
  RotateCcw,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useState } from "react";

import {
  buildAppProvisionCmd,
  buildManualVerbPlanNote,
  buildMigrateDryRunCmd,
  buildProductBackupCaptureCmd,
  buildProductRestoreProbeCmd,
  buildProductStandingCaptureCmd,
  buildWordPressToEmdashPlanCmd,
  INSPECT_AND_SIGN_STEPS,
  REVIEW_AND_SIGN_STEPS,
  shellQuote,
} from "./cli-commands";
import { toastManager } from "./components/ui/toast";
import { useData } from "./data";
import { Glyph } from "./ui";
import { SeparateCustodyApplyPanel } from "./write-panel";

function CopyCommand({ text, label }: { text: string; label: string }) {
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
      onClick={() =>
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          toastManager.add({ id: `copy-${label}`, type: "success", title: "Command copied" });
        })
      }
    >
      <Glyph icon={copied ? Check : Copy} className={copied ? "check-pop" : undefined} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

type BackupActionTab = "capture" | "probe" | "restore";

function buildBackupCmd(
  tab: BackupActionTab,
  site: string,
  consistency: "marker" | "frozen",
  snapshotId: string,
): string {
  const base =
    tab === "capture"
      ? buildProductBackupCaptureCmd({ siteId: site, consistency })
      : tab === "probe"
        ? buildProductRestoreProbeCmd({ siteId: site, snapshotId })
        : buildManualVerbPlanNote({
            verb: "site_restore",
            runbook: "Runbook 26",
            summary: `Target site ${shellQuote(site)} · Snapshot ${shellQuote(snapshotId.trim() || "<snapshot_id>")}`,
          });
  return `${base}\n${INSPECT_AND_SIGN_STEPS}`;
}

function BackupSitePicker({
  sites,
  value,
  onChange,
}: {
  sites: { id: string; domain: string }[];
  value: string;
  onChange: (id: string) => void;
}) {
  if (sites.length === 0) {
    return (
      <input
        id="bk-site"
        className="input mono"
        value={value}
        placeholder="site_id"
        onChange={(e) => onChange(e.target.value)}
      />
    );
  }
  return (
    <select id="bk-site" className="input" value={value} onChange={(e) => onChange(e.target.value)}>
      {sites.map((s) => (
        <option key={s.id} value={s.id}>
          {s.domain} ({s.id})
        </option>
      ))}
    </select>
  );
}

export function BackupRestoreActionsPanel() {
  const { sites } = useData();
  const [tab, setTab] = useState<BackupActionTab>("capture");
  const [siteId, setSiteId] = useState(sites[0]?.id ?? "");
  const [consistency, setConsistency] = useState<"marker" | "frozen">("marker");
  const [snapshotId, setSnapshotId] = useState("");
  const resolvedSite = siteId || sites[0]?.id || "site_id";
  const cmd = buildBackupCmd(tab, resolvedSite, consistency, snapshotId);

  return (
    <section className="panel stack" aria-labelledby="bk-act-t">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={tab === "restore" ? RotateCcw : HardDriveUpload} />
          <h2 id="bk-act-t">Backup &amp; restore actions</h2>
        </div>
        <CopyCommand text={cmd} label="Copy backup or restore command" />
      </div>

      <div
        className="row"
        style={{ gap: 6, flexWrap: "wrap" }}
        role="tablist"
        aria-label="Backup actions"
      >
        {(
          [
            ["capture", "Backup now"],
            ["probe", "Test restore probe"],
            ["restore", "Guided site restore"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            className={tab === id ? "btn primary sm" : "btn quiet sm"}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === "restore" ? (
        <div className="attention warn" role="alert">
          <Glyph icon={TriangleAlert} />
          <div className="att-body">
            <strong>Guided live restore:</strong> Rustiron verifies the snapshot manifest and takes
            a fresh safety capture before switching content. If verification fails, follow the
            explicit reconcile or revert steps in the{" "}
            <Link className="link" to="/help/$slug" params={{ slug: "backups-and-restores" }}>
              Backups &amp; restores guide
            </Link>
            .
          </div>
        </div>
      ) : null}

      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="bk-site">Target website</label>
          <BackupSitePicker sites={sites} value={resolvedSite} onChange={setSiteId} />
        </div>

        {tab === "capture" ? (
          <div className="form-row">
            <label htmlFor="bk-cons">Consistency mode</label>
            <select
              id="bk-cons"
              className="input"
              value={consistency}
              onChange={(e) => setConsistency(e.target.value as "marker" | "frozen")}
            >
              <option value="marker">Online marker check (zero downtime)</option>
              <option value="frozen">Brief write freeze (max 10 s 503)</option>
            </select>
          </div>
        ) : (
          <div className="form-row">
            <label htmlFor="bk-snap">Snapshot ID</label>
            <input
              id="bk-snap"
              className="input mono"
              placeholder="snap_..."
              value={snapshotId}
              onChange={(e) => setSnapshotId(e.target.value)}
            />
          </div>
        )}
      </div>

      <pre className="code signed-bytes">{cmd}</pre>

      <details className="disclose">
        <summary>
          <Glyph icon={ShieldCheck} />
          <span>Submit signed backup or restore plan</span>
          <Glyph icon={ChevronDown} className="chev" />
        </summary>
        <div className="d-body">
          <SeparateCustodyApplyPanel />
        </div>
      </details>
    </section>
  );
}

export function BackupScheduleWizard() {
  const { sites } = useData();
  const [selected, setSelected] = useState<string[]>(() => sites.slice(0, 4).map((s) => s.id));
  const [windowLabel, setWindowLabel] = useState("daily-03:00-utc");
  const [retentionDays, setRetentionDays] = useState("30");
  // D-035 caps standing-capture grant duration at 35 days.
  const [validDays, setValidDays] = useState("30");

  const parsedDays = Math.max(1, Math.min(35, Number.parseInt(validDays, 10) || 30));
  const hasSelection = selected.length > 0;
  const periodSeconds = windowLabel === "every-12h-utc" ? 43_200 : 86_400;
  const maxRuns =
    windowLabel === "weekly-sun-02:00-utc"
      ? Math.max(1, Math.min(35, Math.ceil(parsedDays / 7)))
      : parsedDays;
  const cmd = hasSelection
    ? `# Standing capture schedule (${windowLabel}, retention ${retentionDays}d, D-035 <= ${parsedDays}d — Runbook 13)\n${buildProductStandingCaptureCmd({ siteIds: selected, periodSeconds, windowSeconds: 3600, maxRuns })}\n${REVIEW_AND_SIGN_STEPS}`
    : "# Select at least 1 website (up to 16) to generate a standing-capture command.";

  function toggleSite(id: string) {
    setSelected((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id].slice(0, 16),
    );
  }

  return (
    <section className="panel stack" aria-labelledby="sched-wiz-t">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={CalendarClock} />
          <h2 id="sched-wiz-t">Create backup schedule</h2>
        </div>
        {hasSelection ? <CopyCommand text={cmd} label="Copy backup schedule command" /> : null}
      </div>

      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="sc-win">Capture window</label>
          <select
            id="sc-win"
            className="input"
            value={windowLabel}
            onChange={(e) => setWindowLabel(e.target.value)}
          >
            <option value="daily-03:00-utc">Daily at 03:00 UTC</option>
            <option value="every-12h-utc">Every 12 hours (03:00 &amp; 15:00 UTC)</option>
            <option value="weekly-sun-02:00-utc">Weekly Sunday at 02:00 UTC</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="sc-ret">Object Lock retention (days)</label>
          <select
            id="sc-ret"
            className="input tnum"
            value={retentionDays}
            onChange={(e) => setRetentionDays(e.target.value)}
          >
            <option value="7">7 days</option>
            <option value="14">14 days</option>
            <option value="30">30 days (recommended)</option>
            <option value="90">90 days</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="sc-exp">Schedule grant duration (days, max 35)</label>
          <input
            id="sc-exp"
            className="input tnum"
            type="number"
            min={1}
            max={35}
            value={validDays}
            onChange={(e) => setValidDays(e.target.value)}
          />
        </div>
      </div>

      {sites.length > 0 ? (
        <fieldset className="plain">
          <legend>Websites included (max 16)</legend>
          <div className="row" style={{ gap: 12, flexWrap: "wrap", marginTop: 6 }}>
            {sites.map((s) => (
              <label key={s.id} className="row" style={{ gap: 6 }}>
                <input
                  type="checkbox"
                  checked={selected.includes(s.id)}
                  onChange={() => toggleSite(s.id)}
                />
                <span className="mono">{s.domain}</span>
              </label>
            ))}
          </div>
        </fieldset>
      ) : null}

      <pre className="code signed-bytes">{cmd}</pre>

      <details className="disclose">
        <summary>
          <Glyph icon={ShieldCheck} />
          <span>Submit signed backup schedule</span>
          <Glyph icon={ChevronDown} className="chev" />
        </summary>
        <div className="d-body">
          <SeparateCustodyApplyPanel />
        </div>
      </details>
    </section>
  );
}

type MigrationMode = "cyberpanel" | "emdash";

type MigrationForm = {
  mode: MigrationMode;
  sourceHost: string;
  targetSiteId: string;
  targetHost: string;
  archivePath: string;
  wxrPath: string;
  mediaDir: string;
  emdashPort: string;
};

function buildMigrationCmd(f: MigrationForm): string {
  const siteId = f.targetSiteId || (f.mode === "cyberpanel" ? "site01" : "emdashsite");
  const host = f.targetHost || f.sourceHost;
  const port = Number.parseInt(f.emdashPort, 10) || 3401;
  if (f.mode === "cyberpanel") {
    return `# 1. Offline dry-run & compatibility check (Runbook 37)\n${buildMigrateDryRunCmd()}\n# 2. Signed site_import for ${shellQuote(siteId)} (${shellQuote(host)}) from ${shellQuote(f.archivePath)} follows Runbook 37`;
  }
  return `# 1. Plan WordPress WXR + uploads migration to EmDash 1.6.0 (Runbook 33)\n${buildWordPressToEmdashPlanCmd(
    {
      wxrPath: f.wxrPath,
      mediaDir: f.mediaDir,
      sourceOrigin: `https://${f.sourceHost || host}`,
      targetOrigin: `https://${host}`,
    },
  )}\n# 2. Provision EmDash CMS app site (Node.js 22)\n${buildAppProvisionCmd({
    siteId,
    hostname: host,
    runtime: "node_22_v1",
    port,
    healthPath: "/_emdash/api/health",
    entrypoint: "dist/server/entry.mjs",
  })}\n${INSPECT_AND_SIGN_STEPS}`;
}

function MigrationModeFields({
  form,
  patch,
}: {
  form: MigrationForm;
  patch: (p: Partial<MigrationForm>) => void;
}) {
  if (form.mode === "cyberpanel") {
    return (
      <div className="form-row">
        <label htmlFor="mig-arc">CyberPanel export archive</label>
        <input
          id="mig-arc"
          className="input mono"
          value={form.archivePath}
          onChange={(e) => patch({ archivePath: e.target.value })}
        />
      </div>
    );
  }
  return (
    <>
      <div className="form-row">
        <label htmlFor="mig-wxr">WordPress WXR XML export</label>
        <input
          id="mig-wxr"
          className="input mono"
          value={form.wxrPath}
          onChange={(e) => patch({ wxrPath: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="mig-media">Uploads folder</label>
        <input
          id="mig-media"
          className="input mono"
          value={form.mediaDir}
          onChange={(e) => patch({ mediaDir: e.target.value })}
        />
      </div>
      <div className="form-row">
        <label htmlFor="mig-port">EmDash local port</label>
        <input
          id="mig-port"
          className="input tnum"
          type="number"
          min={1024}
          max={65535}
          value={form.emdashPort}
          onChange={(e) => patch({ emdashPort: e.target.value })}
        />
      </div>
    </>
  );
}

export function MigrationWizardsPanel() {
  const [form, setForm] = useState<MigrationForm>({
    mode: "cyberpanel",
    sourceHost: "oldsite.example.com",
    targetSiteId: "oldsite_wp",
    targetHost: "oldsite.example.com",
    archivePath: "./cyberpanel-export.tar.gz",
    wxrPath: "./wordpress-export.xml",
    mediaDir: "./wp-content/uploads",
    emdashPort: "3401",
  });
  const patch = (p: Partial<MigrationForm>) => setForm((prev) => ({ ...prev, ...p }));
  const cmd = buildMigrationCmd(form);

  return (
    <section className="panel stack" aria-labelledby="mig-wiz-t">
      <div className="panel-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={ArrowLeftRight} />
          <h2 id="mig-wiz-t">Start a migration</h2>
        </div>
        <CopyCommand text={cmd} label="Copy migration commands" />
      </div>

      <div
        className="row"
        style={{ gap: 6, flexWrap: "wrap" }}
        role="tablist"
        aria-label="Migration type"
      >
        <button
          type="button"
          role="tab"
          aria-selected={form.mode === "cyberpanel"}
          className={form.mode === "cyberpanel" ? "btn primary sm" : "btn quiet sm"}
          onClick={() => patch({ mode: "cyberpanel" })}
        >
          Import from CyberPanel
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={form.mode === "emdash"}
          className={form.mode === "emdash" ? "btn primary sm" : "btn quiet sm"}
          onClick={() => patch({ mode: "emdash" })}
        >
          WordPress → EmDash CMS
        </button>
      </div>

      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="mig-src">Source domain</label>
          <input
            id="mig-src"
            className="input mono"
            value={form.sourceHost}
            onChange={(e) => patch({ sourceHost: e.target.value })}
          />
        </div>
        <div className="form-row">
          <label htmlFor="mig-id">Target site ID</label>
          <input
            id="mig-id"
            className="input mono"
            value={form.targetSiteId}
            onChange={(e) => patch({ targetSiteId: e.target.value })}
          />
        </div>
        <div className="form-row">
          <label htmlFor="mig-dst">Target domain</label>
          <input
            id="mig-dst"
            className="input mono"
            value={form.targetHost}
            onChange={(e) => patch({ targetHost: e.target.value })}
          />
        </div>
        <MigrationModeFields form={form} patch={patch} />
      </div>

      <pre className="code signed-bytes">{cmd}</pre>

      <details className="disclose">
        <summary>
          <Glyph icon={ShieldCheck} />
          <span>Submit signed migration plan</span>
          <Glyph icon={ChevronDown} className="chev" />
        </summary>
        <div className="d-body">
          <SeparateCustodyApplyPanel />
        </div>
      </details>
    </section>
  );
}
