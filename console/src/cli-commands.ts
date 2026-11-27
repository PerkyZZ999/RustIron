// Single source of truth for copy-pastable CLI commands displayed by Console wizards.
// Every `rustiron plan create ...`, `rustiron-plan ...`, and `wordpress-to-emdash.py ...`
// command here matches the real argument parsers in `crates/cli/src/{main,plan_create,plan_main}.rs`
// and `packaging/wordpress-to-emdash.py`, verified by `cli-commands.test.ts`.

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function envelopeFlags(hostId = "<host_id>"): string {
  const host = hostId.startsWith("<") ? hostId : shellQuote(hostId);
  return `--plan-id <plan_id> --host-id ${host} --host-epoch <epoch> --profile-digest <sha256> --requester <requester>`;
}

export const INSPECT_AND_SIGN_STEPS =
  "rustiron-plan inspect ./plan.json\nssh-keygen -Y sign -n rustiron-plan-v1 -f ~/.ssh/rustiron_operator ./grant.json";

export const REVIEW_AND_SIGN_STEPS =
  "rustiron plan review-file ./plan.json\nssh-keygen -Y sign -n rustiron-plan-v1 -f ~/.ssh/rustiron_operator ./grant.json";

export function buildSiteProvisionCmd(opts: {
  siteId: string;
  hostname: string;
  quotaMib?: string;
  hostId?: string;
}): string {
  const mib = Number.parseInt(opts.quotaMib ?? "", 10);
  const quotaFlags =
    Number.isInteger(mib) && mib > 0
      ? ` --quota-block-hard-kib ${mib * 1024} --quota-inode-hard 200000`
      : "";
  return `rustiron plan create site-provision ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --hostname ${shellQuote(opts.hostname)} --recipe wordpress713_v1 --recipe-digest <sha256> --observed-at <unix> --valid-from <unix> --expires-at <unix>${quotaFlags} > ./plan.json`;
}

export type AppRuntimeProfile = "node_22_v1" | "bun_1_v1" | "static_v1";
export type AppIngressEngine = "ols" | "caddy";
export type AppTopologyKind =
  | "static_spa"
  | "backend_api"
  | "fullstack_split"
  | "fullstack_dual_ssr";
export type AppDatabaseEngine = "none" | "sqlite" | "mariadb" | "postgresql_18";
export type CredentialRotateTarget =
  | "mariadb_user_password"
  | "app_mariadb_password"
  | "app_postgresql_18_password";

export type AppProvisionCmdOpts = {
  siteId: string;
  hostname: string;
  runtime: AppRuntimeProfile;
  port: string | number;
  healthPath?: string;
  entrypoint?: string;
  workerEntrypoint?: string;
  hostId?: string;
  ingress?: AppIngressEngine;
  topology?: AppTopologyKind;
  database?: AppDatabaseEngine;
  blueGreen?: boolean;
  standbyPort?: string | number;
  spaFallback?: boolean;
  frontendDir?: string;
  frontendRuntime?: "node_22_v1" | "bun_1_v1";
  frontendEntrypoint?: string;
  frontendPort?: string | number;
  frontendStandbyPort?: string | number;
  routePrefixes?: string[];
  websocketPrefixes?: string[];
  ssePrefixes?: string[];
  stripApiPrefixes?: string[];
  envKeys?: string[];
};

function appendRepeated(flags: string[], flag: string, values?: string[]): void {
  if (!values) return;
  for (const raw of values) {
    const val = raw.trim();
    if (val) flags.push(`${flag} ${shellQuote(val)}`);
  }
}

function appendPositivePort(flags: string[], flag: string, raw?: string | number): void {
  const n = Number.parseInt(String(raw ?? ""), 10);
  if (Number.isInteger(n) && n > 0) flags.push(`${flag} ${n}`);
}

function appendQuotedOpt(flags: string[], flag: string, raw?: string): void {
  const val = raw?.trim();
  if (val) flags.push(`${flag} ${shellQuote(val)}`);
}

function appendV2FrontendFlags(flags: string[], opts: AppProvisionCmdOpts): void {
  appendQuotedOpt(flags, "--frontend-dir", opts.frontendDir);
  if (opts.frontendRuntime) flags.push(`--frontend-runtime ${opts.frontendRuntime}`);
  appendQuotedOpt(flags, "--frontend-entrypoint", opts.frontendEntrypoint);
  appendPositivePort(flags, "--frontend-port", opts.frontendPort);
  appendPositivePort(flags, "--frontend-standby-port", opts.frontendStandbyPort);
}

function appendV2RouteFlags(flags: string[], opts: AppProvisionCmdOpts): void {
  appendRepeated(flags, "--route-prefix", opts.routePrefixes);
  appendRepeated(flags, "--websocket-prefix", opts.websocketPrefixes);
  appendRepeated(flags, "--sse-prefix", opts.ssePrefixes);
  appendRepeated(flags, "--strip-api-prefix", opts.stripApiPrefixes);
  appendQuotedOpt(flags, "--worker-entrypoint", opts.workerEntrypoint);
  appendRepeated(flags, "--env-key", opts.envKeys);
}

function appendV2AppProvisionFlags(flags: string[], opts: AppProvisionCmdOpts): void {
  if (opts.ingress) flags.push(`--ingress ${opts.ingress}`);
  if (opts.topology) flags.push(`--topology ${opts.topology}`);
  if (opts.database) flags.push(`--database ${opts.database}`);
  if (opts.blueGreen) flags.push("--blue-green");
  appendPositivePort(flags, "--standby-port", opts.standbyPort);
  if (opts.spaFallback) flags.push("--spa-fallback");
  appendV2FrontendFlags(flags, opts);
  appendV2RouteFlags(flags, opts);
}

export function buildAppProvisionCmd(opts: AppProvisionCmdOpts): string {
  const isStatic = opts.topology === "static_spa" || opts.runtime === "static_v1";
  const parsedPort = Number.parseInt(String(opts.port), 10);
  const port = isStatic ? 0 : parsedPort || 3210;
  const entry = isStatic ? "" : (opts.entrypoint ?? "dist/server/entry.mjs");
  const health = opts.healthPath?.trim() || (isStatic ? "/" : "/healthz");
  const flags = [
    `--site-id ${shellQuote(opts.siteId)}`,
    `--hostname ${shellQuote(opts.hostname)}`,
    `--runtime ${opts.runtime}`,
    `--port ${port}`,
    ...(entry ? [`--entrypoint ${shellQuote(entry)}`] : []),
    `--health-path ${shellQuote(health)}`,
  ];
  appendV2AppProvisionFlags(flags, opts);
  return `rustiron plan create app-provision ${envelopeFlags(opts.hostId)} ${flags.join(" ")} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildAppDeployCmd(opts: {
  siteId: string;
  releaseId: string;
  runtime: AppRuntimeProfile;
  migrating?: boolean;
  blueGreenCutover?: boolean;
  healthPath?: string;
  hostId?: string;
}): string {
  const extra: string[] = [];
  if (opts.healthPath?.trim()) extra.push(`--health-path ${shellQuote(opts.healthPath.trim())}`);
  if (opts.blueGreenCutover && opts.runtime !== "static_v1") extra.push("--blue-green-cutover");
  if (opts.migrating) {
    extra.push("--migration-entrypoint scripts/migrate.mjs --capture-operation-id <capture_op_id>");
  }
  const suffix = extra.length > 0 ? ` ${extra.join(" ")}` : "";
  return `rustiron plan create app-deploy ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --release-id ${shellQuote(opts.releaseId)} --runtime ${opts.runtime} --artifact-sha256 <sha256> --manifest-sha256 <sha256> --file-count <count> --total-bytes <bytes>${suffix} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

function appendPackDistFlags(
  parts: string[],
  topology: AppTopologyKind,
  frontendDist?: string,
  backendDist?: string,
): void {
  if (topology !== "backend_api") {
    parts.push(`--frontend-dist ${shellQuote(frontendDist ?? "./frontend/dist")}`);
  }
  if (topology !== "static_spa") {
    parts.push(`--backend-dist ${shellQuote(backendDist ?? "./backend/dist")}`);
  }
}

export function buildAppPackCmd(opts: {
  siteId: string;
  releaseId: string;
  topology: AppTopologyKind;
  runtime: AppRuntimeProfile;
  database?: AppDatabaseEngine;
  frontendDir?: string;
  entrypoint?: string;
  frontendRuntime?: "node_22_v1" | "bun_1_v1";
  frontendEntrypoint?: string;
  blueGreen?: boolean;
  frontendDist?: string;
  backendDist?: string;
  outDir?: string;
}): string {
  const parts = [
    "python3 packaging/rustiron-app-pack.py pack",
    `--site-id ${shellQuote(opts.siteId)}`,
    `--release-id ${shellQuote(opts.releaseId)}`,
    `--out ${shellQuote(opts.outDir ?? "./release-out")}`,
    `--topology ${opts.topology}`,
    `--runtime ${opts.runtime}`,
  ];
  if (opts.database) parts.push(`--database ${opts.database}`);
  appendPackDistFlags(parts, opts.topology, opts.frontendDist, opts.backendDist);
  if (
    opts.frontendDir?.trim() &&
    (opts.topology === "static_spa" || opts.topology === "fullstack_split")
  ) {
    parts.push(`--frontend-dir ${shellQuote(opts.frontendDir.trim())}`);
  }
  if (opts.entrypoint?.trim() && opts.topology !== "static_spa") {
    parts.push(`--entrypoint ${shellQuote(opts.entrypoint.trim())}`);
  }
  if (opts.topology === "fullstack_dual_ssr") {
    if (opts.frontendRuntime) parts.push(`--frontend-runtime ${opts.frontendRuntime}`);
    appendQuotedOpt(parts, "--frontend-entrypoint", opts.frontendEntrypoint);
  }
  if (opts.blueGreen && opts.topology !== "static_spa") parts.push("--blue-green-cutover");
  return parts.join(" ");
}

export function buildConfigActivateCmd(opts: {
  siteId: string;
  hostId?: string;
  note?: string;
}): string {
  const prefix = opts.note ? `# ${opts.note}\n` : "";
  return `${prefix}rustiron plan create config-activate ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --expected-generation <gen> --expected-digest <sha256> --observed-at <unix> --valid-from <unix> --expires-at <unix> --compensation-until <unix> > ./plan.json`;
}

export function buildSiteEjectCmd(opts: { siteId: string; hostId?: string }): string {
  return `rustiron plan create site-eject ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --expected-generation <gen> --expected-digest <sha256> --observed-at <unix> --valid-from <unix> --expires-at <unix> --compensation-until <unix> > ./plan.json`;
}

export function buildProductBackupCaptureCmd(opts: {
  siteId: string;
  consistency: "marker" | "frozen";
  hostId?: string;
}): string {
  const recipe = opts.consistency === "frozen" ? "site_files_db_frozen_v1" : "site_files_db_v1";
  return `rustiron plan create product-backup-capture ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --destination-id <dest_id> --destination-policy-digest <sha256> --recipe-id ${recipe} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildProductRestoreProbeCmd(opts: {
  siteId: string;
  snapshotId?: string;
  hostId?: string;
}): string {
  const snap = opts.snapshotId?.trim() ? shellQuote(opts.snapshotId.trim()) : "<snapshot_id>";
  return `rustiron plan create product-restore-probe ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --destination-id <dest_id> --destination-policy-digest <sha256> --snapshot-id ${snap} --profile-id local_no_egress_v1 --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildProductStandingCaptureCmd(opts: {
  siteIds: string[];
  periodSeconds: number;
  windowSeconds: number;
  maxRuns: number;
  hostId?: string;
}): string {
  const siteFlags = opts.siteIds.map((id) => `--site-id ${shellQuote(id)}`).join(" ");
  const maxRuns = Math.max(1, Math.min(35, opts.maxRuns));
  return `rustiron plan create product-standing-capture ${envelopeFlags(opts.hostId)} ${siteFlags} --destination-id <dest_id> --destination-policy-digest <sha256> --recipe-id site_files_db_v1 --first-window-start <unix> --period-seconds ${opts.periodSeconds} --window-seconds ${opts.windowSeconds} --max-runs ${maxRuns} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildDnsZoneImportCmd(opts: {
  zone: string;
  zoneFile: string;
  hostId?: string;
}): string {
  return `rustiron plan create dns-zone-import ${envelopeFlags(opts.hostId)} --zone ${shellQuote(opts.zone)} --zone-file ${shellQuote(opts.zoneFile)} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildDnsChangeCmd(opts: {
  zone: string;
  operationsFile: string;
  hostId?: string;
}): string {
  return `rustiron plan create dns-change ${envelopeFlags(opts.hostId)} --zone ${shellQuote(opts.zone)} --operations-file ${shellQuote(opts.operationsFile)} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildSiteCredentialRotateCmd(opts: {
  siteId: string;
  hostname: string;
  target?: CredentialRotateTarget;
  hostId?: string;
}): string {
  const targetFlag =
    opts.target && opts.target !== "mariadb_user_password" ? ` --target ${opts.target}` : "";
  return `rustiron plan create site-credential-rotate ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --hostname ${shellQuote(opts.hostname)}${targetFlag} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildMigrateDryRunCmd(): string {
  return "rustiron-plan migrate ./observation.json ./declaration.json ./target.json --target-observation ./target-obs.json --declaration-sig ./declaration.json.sig --allowed-signers ~/.ssh/allowed_signers --principal <operator>";
}

export function buildWordPressToEmdashPlanCmd(opts: {
  wxrPath: string;
  mediaDir: string;
  sourceOrigin: string;
  targetOrigin: string;
}): string {
  return `python3 packaging/wordpress-to-emdash.py plan --wxr ${shellQuote(opts.wxrPath)} --media-dir ${shellQuote(opts.mediaDir)} --source-origin ${shellQuote(opts.sourceOrigin)} --target-origin ${shellQuote(opts.targetOrigin)} --out ./emdash-migration`;
}

/** Honest guidance for canonical executor verbs that do not have a `rustiron plan create` shorthand yet. */
export function buildManualVerbPlanNote(opts: {
  verb: string;
  runbook: string;
  summary: string;
}): string {
  return `# Canonical verb: ${opts.verb} (${opts.runbook})\n# ${opts.summary}\n# Author ./plan.json per ${opts.runbook}, then verify and sign offline:`;
}

export type CanonicalZoneInput = {
  zone: string;
  primaryNs: string;
  secondaryNs: string;
  ipv4: string;
  ipv6: string;
  includeWww: boolean;
  mailHost: string;
};

/** Renders canonical FQDN-per-line DNS zone bytes accepted by `rustiron plan create dns-zone-import` (D-091). */
export function renderCanonicalZone(f: CanonicalZoneInput): string {
  const z = (f.zone.trim().toLowerCase() || "example.com").replace(/\.$/, "");
  const ns1 = (f.primaryNs.trim().toLowerCase() || `ns1.${z}`).replace(/\.$/, "");
  const ns2 = (f.secondaryNs.trim().toLowerCase() || `ns2.${z}`).replace(/\.$/, "");
  const lines = [
    `${z}. 3600 IN SOA ${ns1}. hostmaster.${z}. 2026112601 7200 1800 1209600 300`,
    `${z}. 3600 IN NS ${ns1}.`,
    `${z}. 3600 IN NS ${ns2}.`,
  ];
  if (f.ipv4.trim()) {
    lines.push(`${z}. 3600 IN A ${f.ipv4.trim()}`);
    if (f.includeWww) lines.push(`www.${z}. 3600 IN A ${f.ipv4.trim()}`);
  }
  if (f.ipv6.trim()) {
    lines.push(`${z}. 3600 IN AAAA ${f.ipv6.trim()}`);
    if (f.includeWww) lines.push(`www.${z}. 3600 IN AAAA ${f.ipv6.trim()}`);
  }
  if (f.mailHost.trim()) {
    const mx = f.mailHost.trim().replace(/\.$/, "");
    lines.push(`${z}. 3600 IN MX 10 ${mx}.`, `${z}. 3600 IN TXT "v=spf1 mx -all"`);
  }
  return `${Array.from(new Set(lines)).sort().join("\n")}\n`;
}

export type StagedDnsRecordInput = {
  action: "upsert" | "delete";
  name: string;
  type: string;
  ttl: number;
  value: string;
  priority?: number;
};

/** Renders canonical `SetOperation[]` JSON accepted by `rustiron plan create dns-change` (D-091). */
export function renderDnsOperationsJson(hostname: string, ops: StagedDnsRecordInput[]): string {
  return JSON.stringify(
    ops.map((op) => {
      const owner = op.name === "@" ? `${hostname}.` : `${op.name}.${hostname}.`;
      if (op.action === "delete") {
        return { owner, type: op.type, expected: "absent", action: "remove" };
      }
      return {
        owner,
        type: op.type,
        expected: "absent",
        action: "replace",
        ttl: op.ttl,
        records: [op.priority !== undefined ? `${op.priority} ${op.value}` : op.value],
      };
    }),
    null,
    2,
  );
}
