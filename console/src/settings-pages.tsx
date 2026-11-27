// W714 (pass 33, fix 7): Settings and shared-state pages, and the package and signer rows. Split from `pages.tsx`.
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toastManager } from "@/components/ui/toast";
import { Link } from "@tanstack/react-router";
import {
  ListChecks,
  type LucideIcon,
  Filter,
  CircleAlert,
  CircleCheck,
  CircleDashed,
  CircleMinus,
  CircleX,
  LoaderCircle,
  ClockAlert,
  Cpu,
  HardDrive,
  KeyRound,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";
import { Fragment, useState } from "react";
import { type ThemePreference, useThemePreference } from "./shell";
import { isRealHost, useData } from "./data";
import {
  type ConsolePreferences,
  type MetricsRange,
  type RowsPerPage,
  type TimeDisplay,
  type TransparencyPref,
  usePreferences,
} from "./prefs";
import {
  enrolledRetentionText,
  type Observation,
  packagePins,
  type PackagePin,
  signerFacts,
  type SignerFacts,
} from "./live";
import { Glyph, Page, TableScroll } from "./ui";
import { EvidenceKey } from "./page-parts";

const themeChoices: { value: ThemePreference; label: string }[] = [
  { value: "system", label: "Match system" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const signers = [
  ["Operator key", "SHA256:Qm4…f2c · ed25519", "Active", "ok"],
  ["Break-glass key", "SHA256:Wd1…07a · offline", "Active", "ok"],
  ["Old operator key", "SHA256:Bz8…c13", "Revoked 3 Oct", "muted"],
] as const;

function observedFact(value: string | null | undefined): [string, string] {
  return value ? [value, "Observed"] : ["Not in this observation", "Not checked"];
}

function settingsProfileRows(
  live: boolean,
  osName: string | null | undefined,
  osVersion: string | null | undefined,
  kernel: string | null | undefined,
  selinux: string | null | undefined,
  listener: string | null | undefined,
  backup: string | null | undefined,
): [string, string, string][] {
  if (!live) {
    return [
      ["AlmaLinux", "10.0", "Matches"],
      ["OpenLiteSpeed", "1.9.3", "Matches"],
      ["LSPHP", "8.4.13", "Matches"],
      ["MariaDB", "11.4.8", "Matches"],
      ["SELinux", "Not readable by observer", "Not checked"],
    ];
  }
  const os = osName && osVersion ? `${osName} ${osVersion}` : null;
  return [
    ["OS", ...observedFact(os)],
    ["Kernel", ...observedFact(kernel)],
    ["SELinux", ...observedFact(selinux)],
    ["OLS listener", ...observedFact(listener)],
    ["Backup destination", ...observedFact(backup)],
  ];
}

/** One row per observed package, or one row saying the pins are missing. */
export function packageRows(pins: PackagePin[] | null): [string, string, string][] {
  if (!pins) return [["Package pins", "Not in this observation", "Not checked"]];
  return pins.map((pin) => [
    pin.name,
    pin.version
      ? `${pin.version} · ${pin.signing_key ? `signed, key ${pin.signing_key}` : "unsigned"}`
      : "Not installed",
    pin.version ? "Observed" : "Not checked",
  ]);
}

function profileCaption(live: boolean, pins: PackagePin[] | null): string {
  if (!live) return "almalinux10-ols-lsphp84 · revision 3 · digest ";
  return pins
    ? "Facts from this observation only. Package pins come from the host RPM database."
    : "Facts from this observation only. Package pins are not in this observation.";
}

function SettingsProfile({ live }: { live: boolean }) {
  const data = useData();
  const machine = data.machine;
  const host = data.source.kind === "live" ? data.source.host : null;
  const rows = settingsProfileRows(
    live,
    machine?.os.name,
    machine?.os.version,
    machine?.os.kernel,
    machine?.selinux,
    host?.ols_listener,
    host?.backup_destination,
  );
  const pins = live ? packagePins(host) : null;
  if (live) rows.push(...packageRows(pins));
  return (
    <section className="panel flush" aria-labelledby="prof-t">
      <div className="panel-head">
        <div>
          <h2 id="prof-t">Supported host profile</h2>
          <p className="cap">
            {profileCaption(live, pins)}
            {live ? null : <code>sha256:a2f0…31bd</code>}
          </p>
        </div>
        <span className="pill">Read-only</span>
      </div>
      <TableScroll label="Supported host profile">
        <table className="data">
          <thead>
            <tr>
              <th scope="col">Component</th>
              <th scope="col">{live ? "Observed" : "Pinned / observed"}</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([component, value, state]) => (
              <tr key={component}>
                <td>{component}</td>
                <td className={state === "Not checked" ? "muted" : undefined}>{value}</td>
                <td>
                  <span
                    className={`state ${state === "Observed" || state === "Matches" ? "ok" : "unknown"}`}
                  >
                    <Glyph
                      icon={
                        state === "Observed" || state === "Matches" ? CircleCheck : CircleDashed
                      }
                    />
                    {state}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableScroll>
    </section>
  );
}

type ObservedHost = {
  host_id: string;
  host_epoch: string;
  issuer: string;
  signer_policy_epoch: string;
  backup_retention_days?: number | null;
};

export function signerRows(facts: SignerFacts | null): [string, string][] {
  if (!facts) return [["Signer key", "Not in this observation"]];
  return [
    ["Key", `${facts.algorithm} ${facts.fingerprint}`],
    ["Namespace", facts.namespace],
    [
      "Revocations",
      facts.revocations_bytes === 0
        ? "Empty list"
        : `${facts.revocations_bytes} bytes · sha256 ${facts.revocations_sha256.slice(0, 12)}`,
    ],
  ];
}

function SettingsSigners({ host }: { host: ObservedHost }) {
  const rows = signerRows(signerFacts(host as Observation["host"]));
  return (
    <dl className="kv">
      <dt>Issuer</dt>
      <dd translate="no">{host.issuer}</dd>
      <dt>Signer epoch</dt>
      <dd translate="no">{host.signer_policy_epoch}</dd>
      <dt>Host epoch</dt>
      <dd translate="no">{host.host_epoch}</dd>
      {rows.map(([label, value]) => (
        <Fragment key={label}>
          <dt>{label}</dt>
          <dd translate="no" className={label === "Key" ? "mono" : undefined}>
            {value}
          </dd>
        </Fragment>
      ))}
    </dl>
  );
}

function SettingsFixtureSigners() {
  return (
    <ul className="list">
      {signers.map(([name, fingerprint, state, kind]) => (
        <li key={name}>
          <Glyph icon={KeyRound} className="list-muted" />
          <span className="grow">
            <span className="t">{name}</span>
            <span className="s mono">{fingerprint}</span>
          </span>
          <span className={`state ${kind}`}>{state}</span>
        </li>
      ))}
    </ul>
  );
}

function SettingsAbout({ live, host }: { live: boolean; host: ObservedHost | null }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>About</h2>
      </div>
      <dl className="kv">
        <dt>Console</dt>
        <dd>{live ? "0.2.0 · read-only" : "0.2.0 · fixture preview, read-only"}</dd>
        {host ? (
          <>
            <dt>Host</dt>
            <dd translate="no">{host.host_id}</dd>
            <dt>Host epoch</dt>
            <dd translate="no">{host.host_epoch}</dd>
          </>
        ) : live ? (
          <>
            <dt>Host</dt>
            <dd>Not in this observation</dd>
          </>
        ) : (
          <>
            <dt>Coordinator</dt>
            <dd>0.4.0</dd>
            <dt>Executor</dt>
            <dd>0.4.0 · host epoch 3</dd>
          </>
        )}
        <dt>Observation retention</dt>
        <dd>{live ? enrolledRetentionText(host?.backup_retention_days) : "30 days"}</dd>
      </dl>
    </section>
  );
}

function SettingsAuthority({ live }: { live: boolean }) {
  const data = useData();
  const host = data.source.kind === "live" ? data.source.host : null;
  return (
    <>
      <section className="panel">
        <div className="panel-head">
          <h2>Approval authority</h2>
          <span className="pill">Read-only</span>
        </div>
        {host ? (
          <SettingsSigners host={host} />
        ) : live ? (
          <p className="muted">No observation is available to show enrolled signers.</p>
        ) : (
          <SettingsFixtureSigners />
        )}
        <p className="cap" style={{ marginTop: 12 }}>
          Signers are enrolled and revoked with the root CLI on the host. The console never stores
          private keys.
        </p>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>Agents</h2>
        </div>
        <p className="muted">
          {live
            ? "Agent identities are not in this observation. Agents cannot approve."
            : "1 agent identity (maint-bot) may request plans. Agents cannot approve; every plan still needs a human signature."}
        </p>
      </section>
      <SettingsAbout live={live} host={host} />
    </>
  );
}

function SettingsPreferencesForm() {
  const { prefs, savePrefs } = usePreferences();
  const [draft, setDraft] = useState<ConsolePreferences>(prefs);
  const [saved, setSaved] = useState(false);

  function updateDraft(patch: Partial<ConsolePreferences>) {
    setDraft((prev) => ({ ...prev, ...patch }));
    setSaved(false);
  }

  return (
    <>
      <div className="form-grid">
        <div className="form-row">
          <label htmlFor="s-tz">Time display</label>
          <select
            id="s-tz"
            className="input"
            name="time-display"
            autoComplete="off"
            value={draft.timeDisplay}
            onChange={(e) => updateDraft({ timeDisplay: e.target.value as TimeDisplay })}
          >
            <option value="utc">UTC (host time)</option>
            <option value="local">Browser local time</option>
          </select>
          <span className="hint">Exports always use UTC</span>
        </div>
        <div className="form-row">
          <label htmlFor="s-range">Default metrics range</label>
          <select
            id="s-range"
            className="input"
            name="metrics-range"
            autoComplete="off"
            value={draft.metricsRange}
            onChange={(e) => updateDraft({ metricsRange: e.target.value as MetricsRange })}
          >
            <option value="1h">1 hour</option>
            <option value="6h">6 hours</option>
            <option value="24h">24 hours</option>
            <option value="7d">7 days</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="s-tr">Transparency</label>
          <select
            id="s-tr"
            className="input"
            name="transparency"
            autoComplete="off"
            value={draft.transparency}
            onChange={(e) => updateDraft({ transparency: e.target.value as TransparencyPref })}
          >
            <option value="system">Match system</option>
            <option value="reduce">Reduce (opaque chrome)</option>
          </select>
        </div>
        <div className="form-row">
          <label htmlFor="s-rows">Table rows per page</label>
          <select
            id="s-rows"
            className="input"
            name="rows-per-page"
            autoComplete="off"
            value={String(draft.rowsPerPage)}
            onChange={(e) => updateDraft({ rowsPerPage: Number(e.target.value) as RowsPerPage })}
          >
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
        <div className="form-row">
          <div className="flex items-center justify-between gap-3 pt-1">
            <div>
              <label htmlFor="s-motion">Reduced motion</label>
              <span className="hint block">
                Disable entrance animations and chart draw transitions
              </span>
            </div>
            <Switch
              id="s-motion"
              checked={draft.motion === "reduce"}
              onCheckedChange={(checked) => updateDraft({ motion: checked ? "reduce" : "system" })}
            />
          </div>
        </div>
      </div>
      <div className="row end">
        {saved ? (
          <span className="saved" role="status">
            Preferences saved in this browser.
          </span>
        ) : null}
        <Button
          variant="default"
          onClick={() => {
            savePrefs(draft);
            setSaved(true);
            toastManager.add({
              id: "prefs-saved",
              type: "success",
              title: "Preferences saved",
              description: "Stored locally in this browser.",
            });
          }}
        >
          Save preferences
        </Button>
      </div>
    </>
  );
}

function AutomationBoundariesCard() {
  return (
    <section className="panel" aria-labelledby="automation-t">
      <div className="panel-head">
        <h2 id="automation-t">Automation &amp; remote access</h2>
        <span className="pill">Explicit approval</span>
      </div>
      <dl className="kv">
        <dt>Local MCP server</dt>
        <dd>
          <span className="mono">rustiron-mcp</span> runs read-only by default; opt-in write mode
          refuses self-approval, blanket tokens, and destructive actions
        </dd>
        <dt>Remote SSH gateway</dt>
        <dd>
          Forced-command allowlist with no interactive shell, sudo, or signing-agent forwarding
        </dd>
        <dt>Background scheduling</dt>
        <dd>Traffic-aware job deferral with automatic backup deadline protection</dd>
        <dt>Multi-host inventory</dt>
        <dd>Read-only fleet aggregation with isolated per-server approval keys and locks</dd>
      </dl>
    </section>
  );
}

export function SettingsPage() {
  const { preference, mode, setPreference } = useThemePreference();
  const data = useData();
  const live = isRealHost(data.source);
  return (
    <Page live={live}>
      <div className="page-head">
        <div>
          <h1>Settings</h1>
          <p className="sub">
            Console preferences, and read-only views of the host profile and approval authority.
            Host security policy is not changed from here.
          </p>
        </div>
      </div>
      <div className="grid g-main-side">
        <div className="stack">
          <section className="panel" aria-labelledby="pref-t">
            <div className="panel-head">
              <h2 id="pref-t">Preferences</h2>
              <span className="meta">Stored in this browser only</span>
            </div>
            <div className="stack" style={{ gap: 20 }}>
              <fieldset className="plain">
                <legend>Theme</legend>
                <div className="grid g3 tight">
                  {themeChoices.map((choice) => (
                    <label
                      key={choice.value}
                      className={preference === choice.value ? "radio-card selected" : "radio-card"}
                    >
                      <input
                        type="radio"
                        name="theme"
                        className="sr-only"
                        value={choice.value}
                        checked={preference === choice.value}
                        onChange={() => setPreference(choice.value)}
                      />
                      <span className="rc-dot" aria-hidden="true" />
                      <strong>{choice.label}</strong>
                      {choice.value === "system" ? (
                        <span className="cap">Currently {mode}</span>
                      ) : null}
                    </label>
                  ))}
                </div>
                <p className="cap" style={{ marginTop: 8 }}>
                  Applies immediately, like the toggle in the top bar.
                </p>
              </fieldset>
              <SettingsPreferencesForm />
            </div>
          </section>
          <SettingsProfile live={live} />
        </div>
        <aside className="stack">
          <SettingsAuthority live={live} />
          <section className="panel" aria-labelledby="backend-t">
            <div className="panel-head">
              <h2 id="backend-t">Backend connection</h2>
              <span className="pill ok">Hardened</span>
            </div>
            <dl className="kv">
              <dt>Console mode</dt>
              <dd>
                {data.backend?.write_workflows_enabled
                  ? "Separate-custody write opt-in"
                  : "Read-only loopback"}
              </dd>
              <dt>Observation feed</dt>
              <dd>
                {data.backend?.observation_configured
                  ? "Configured (/api/observation)"
                  : "Preview data"}
              </dd>
              <dt>Coordinator IPC</dt>
              <dd>
                {data.backend?.coordinator_configured
                  ? data.backend.coordinator_reachable
                    ? "Connected (Unix socket)"
                    : "Configured, unreachable"
                  : "Not configured (observation-only)"}
              </dd>
              <dt>Write workflows</dt>
              <dd>
                {data.backend?.write_workflows_enabled
                  ? "Enabled via external SSHSIG only"
                  : "Disabled (read-only default)"}
              </dd>
              {data.observation?.authority_budget?.consumed ? (
                <>
                  <dt>Authority budget</dt>
                  <dd className="tnum">
                    {data.observation.authority_budget.consumed.total_admissions ?? 0} admissions ·{" "}
                    {data.observation.authority_budget.consumed.total_ols_reloads ?? 0} OLS reloads
                  </dd>
                </>
              ) : null}
            </dl>
          </section>
          <AutomationBoundariesCard />
        </aside>
      </div>
    </Page>
  );
}

const stateLabels: [string, LucideIcon, string][] = [
  ["ok", CircleCheck, "Pass / Running / Verified"],
  ["err", CircleX, "Fail"],
  ["err", CircleAlert, "Needs attention"],
  ["warn", TriangleAlert, "Drift / Warning"],
  ["info", LoaderCircle, "Running"],
  ["unknown", CircleDashed, "Unknown / Not checked"],
  ["notrun", CircleMinus, "Not run"],
  ["stale", ClockAlert, "Stale"],
];

export function StatesPage() {
  const { source } = useData();
  const live = isRealHost(source);
  return (
    <Page live={live}>
      <div className="page-head">
        <div>
          <h1>Shared states</h1>
          <p className="sub">
            Reference sheet for feedback states reused across views: loading, empty, no match,
            unavailable, stale, permission and error. The controls here are samples.
          </p>
        </div>
      </div>
      <div className="grid g3">
        <section className="panel" aria-busy="true">
          <div className="panel-head">
            <h2>Loading</h2>
            <span className="meta">Localized skeleton</span>
          </div>
          <div className="stack" style={{ gap: 10 }}>
            <span className="skeleton" style={{ width: "40%", height: 28 }} />
            <span className="skeleton" style={{ width: "70%" }} />
            <span className="skeleton" style={{ width: "90%" }} />
            <span className="skeleton" style={{ width: "55%" }} />
          </div>
          <p className="cap" style={{ marginTop: 12 }}>
            Only the loading panel shows a skeleton; the rest of the page stays usable.
          </p>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Empty</h2>
          </div>
          <div className="empty-sample">
            <Glyph icon={ListChecks} />
            <p className="t">No operations yet</p>
            <p className="muted">
              Operations appear here once an approved plan is admitted by the executor.
            </p>
            <p style={{ marginTop: 8 }}>
              <Link to="/help/$slug" params={{ slug: "signing-and-plans" }}>
                How operations work
              </Link>
            </p>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>No match</h2>
          </div>
          <div className="empty-sample">
            <Glyph icon={Filter} />
            <p className="t">No sites match &ldquo;Blocked&rdquo; + &ldquo;Observed only&rdquo;</p>
            <p className="muted">8 sites are hidden by filters.</p>
            <div style={{ marginTop: 8 }}>
              <Button variant="outline" size="sm">
                Clear filters
              </Button>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Unavailable</h2>
          </div>
          <div className="metric" style={{ padding: 0 }}>
            <div className="m-head">
              <span className="m-icon c-disk">
                <Glyph icon={HardDrive} />
              </span>
              Disk <span className="cap">/srv/backup-stage</span>
            </div>
            <div className="m-val muted">—</div>
            <div className="m-detail">Not mounted. No value is shown rather than 0%.</div>
            <div className="m-foot">
              <span>Checked 38 s ago</span>
              <Link to="/help/$slug" params={{ slug: "security-and-diagnoses" }}>
                Why?
              </Link>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Stale</h2>
            <span className="state stale">
              <Glyph icon={ClockAlert} />
              Stale · 12 min
            </span>
          </div>
          <div className="metric" style={{ padding: 0 }}>
            <div className="m-head">
              <span className="m-icon c-cpu">
                <Glyph icon={Cpu} />
              </span>
              CPU
            </div>
            <div className="m-val">
              24<small>%</small>
            </div>
            <div className="m-detail">Last value kept, marked stale while reconnecting</div>
            <div className="m-foot">
              <span>Observed 16:30 UTC</span>
              <Button variant="ghost" size="sm">
                <Glyph icon={RefreshCw} />
                Retry now
              </Button>
            </div>
          </div>
        </section>
        <section className="panel">
          <div className="panel-head">
            <h2>Error</h2>
          </div>
          <div className="attention err" style={{ margin: 0 }}>
            <Glyph icon={CircleX} />
            <div className="att-body">
              <strong>Could not load the selected operation.</strong> The coordinator did not
              respond within 10 s. The operation itself is unaffected.
              <div className="att-meta">COORDINATOR_TIMEOUT · 16:44:02 UTC</div>
            </div>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <Button variant="outline" size="sm">
              Try again
            </Button>
            <Link
              className="btn quiet sm"
              to="/help/$slug"
              params={{ slug: "troubleshooting-and-recovery" }}
            >
              Troubleshooting guide
            </Link>
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-head">
          <h2>State labels</h2>
          <span className="meta">Text and shape, never colour alone</span>
        </div>
        <div className="row" style={{ gap: 20 }}>
          {stateLabels.map(([kind, icon, label]) => (
            <span key={label} className={`state ${kind}`}>
              <Glyph icon={icon} />
              {label}
            </span>
          ))}
        </div>
        <div style={{ marginTop: 16 }}>
          <EvidenceKey />
        </div>
      </section>
      <section className="panel">
        <div className="panel-head">
          <h2>Buttons</h2>
        </div>
        <div className="row">
          <Button variant="default">Primary action</Button>
          <Button variant="outline">Secondary</Button>
          <Button variant="ghost">Quiet</Button>
          <Button variant="destructive">Discard plan</Button>
          <Button variant="outline" disabled>
            Disabled
          </Button>
        </div>
        <p className="cap" style={{ marginTop: 12 }}>
          Press Tab to see the focus ring on any of these buttons.
        </p>
      </section>
    </Page>
  );
}
