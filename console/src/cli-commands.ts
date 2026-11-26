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

export function buildAppProvisionCmd(opts: {
  siteId: string;
  hostname: string;
  runtime: "node_22_v1" | "bun_1_v1";
  port: string | number;
  healthPath?: string;
  entrypoint?: string;
  hostId?: string;
}): string {
  const port = Number.parseInt(String(opts.port), 10) || 3210;
  const entry = opts.entrypoint ?? "dist/server/entry.mjs";
  const health = opts.healthPath?.trim() || "/healthz";
  return `rustiron plan create app-provision ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --hostname ${shellQuote(opts.hostname)} --runtime ${opts.runtime} --port ${port} --entrypoint ${shellQuote(entry)} --health-path ${shellQuote(health)} --valid-from <unix> --expires-at <unix> > ./plan.json`;
}

export function buildAppDeployCmd(opts: {
  siteId: string;
  releaseId: string;
  runtime: "node_22_v1" | "bun_1_v1";
  migrating?: boolean;
  hostId?: string;
}): string {
  const migFlags = opts.migrating
    ? " --migration-entrypoint scripts/migrate.mjs --capture-operation-id <capture_op_id>"
    : "";
  return `rustiron plan create app-deploy ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --release-id ${shellQuote(opts.releaseId)} --runtime ${opts.runtime} --artifact-sha256 <sha256> --manifest-sha256 <sha256> --file-count <count> --total-bytes <bytes>${migFlags} --valid-from <unix> --expires-at <unix> > ./plan.json`;
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
  hostId?: string;
}): string {
  return `rustiron plan create site-credential-rotate ${envelopeFlags(opts.hostId)} --site-id ${shellQuote(opts.siteId)} --hostname ${shellQuote(opts.hostname)} --valid-from <unix> --expires-at <unix> > ./plan.json`;
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
