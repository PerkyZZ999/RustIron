// W649: Integrated RustIron Documentation & Knowledge Base data model.
// All commands match real repository CLIs (rustiron, rustiron-plan, rustiron-control,
// packaging/rustiron-install-wizard.py, packaging/rustiron-updater.py,
// packaging/firewall-zone.py, packaging/wordpress-to-emdash.py, scripts/release/bundle_release.py).

import { type KbSlug, kbArticleTitles } from "./kb-index";
import { parseGlossary, parseKbMarkdown } from "./kb-markdown";
import glossaryText from "../kb/glossary.md" with { type: "text" };
import md_console_tour from "../kb/console-tour.md" with { type: "text" };
import md_console_changes from "../kb/console-changes.md" with { type: "text" };
import md_console_sites from "../kb/console-sites.md" with { type: "text" };
import md_console_domains_email from "../kb/console-domains-email.md" with { type: "text" };
import md_console_backups from "../kb/console-backups.md" with { type: "text" };
import md_console_server from "../kb/console-server.md" with { type: "text" };
import md_console_users from "../kb/console-users.md" with { type: "text" };
import md_ai_agents from "../kb/ai-agents.md" with { type: "text" };
import md_ai_agents_connect from "../kb/ai-agents-connect.md" with { type: "text" };
import md_ai_agents_skill from "../kb/ai-agents-skill.md" with { type: "text" };
import md_how_rustiron_works from "../kb/how-rustiron-works.md" with { type: "text" };
import md_install_and_setup from "../kb/install-and-setup.md" with { type: "text" };
import md_signing_and_plans from "../kb/signing-and-plans.md" with { type: "text" };
import md_wordpress_sites from "../kb/wordpress-sites.md" with { type: "text" };
import md_modern_apps_and_emdash from "../kb/modern-apps-and-emdash.md" with { type: "text" };
import md_fullstack_caddy from "../kb/fullstack-caddy.md" with { type: "text" };
import md_postgresql_18 from "../kb/postgresql-18.md" with { type: "text" };
import md_domains_ssl_and_dns from "../kb/domains-ssl-and-dns.md" with { type: "text" };
import md_databases_and_credentials from "../kb/databases-and-credentials.md" with { type: "text" };
import md_email_and_relay from "../kb/email-and-relay.md" with { type: "text" };
import md_backups_and_recovery from "../kb/backups-and-recovery.md" with { type: "text" };
import md_migrations from "../kb/migrations.md" with { type: "text" };
import md_security_and_diagnoses from "../kb/security-and-diagnoses.md" with { type: "text" };
import md_firewall_and_network from "../kb/firewall-and-network.md" with { type: "text" };
import md_updates_and_releases from "../kb/updates-and-releases.md" with { type: "text" };
import md_troubleshooting_and_recovery from "../kb/troubleshooting-and-recovery.md" with { type: "text" };

export type KbCategoryId =
  | "getting-started"
  | "console"
  | "agents"
  | "hosting"
  | "domains-mail"
  | "recovery-migration"
  | "security-ops"
  | "updates-releases";

export type KbCategory = {
  id: KbCategoryId;
  label: string;
  description: string;
};

export type KbCommand = {
  label: string;
  where:
    | "Server (root)"
    | "Workstation (operator)"
    | "Server (unprivileged)"
    | "Build / maintainer";
  code: string;
};

export type KbCallout = {
  tone: "info" | "warn";
  title: string;
  body: string;
};

export type KbSection = {
  id: string;
  heading: string;
  paragraphs: string[];
  bullets?: string[];
  callout?: KbCallout;
  commands?: KbCommand[];
};

export type KbArticle = {
  slug: KbSlug;
  category: KbCategoryId;
  title: string;
  summary: string;
  readMinutes: number;
  runbooks: string[];
  keywords: string[];
  consoleLinks: { to: string; label: string }[];
  sections: KbSection[];
};

export type OperatorRunbookRef = {
  id: string;
  title: string;
  group: string;
  file: string;
  summary: string;
  guideSlug: string;
};

// W679: a non-empty tuple, so the first category needs no `!` assertion.
export const kbCategories: [KbCategory, ...KbCategory[]] = [
  {
    id: "getting-started",
    label: "Get started",
    description: "What RustIron is, how to install it, and how changes are approved.",
  },
  {
    id: "console",
    label: "Using the Console",
    description: "The Console's pages, and how to add sites and approve changes from your browser.",
  },
  {
    id: "agents",
    label: "AI agents",
    description: "Connect an AI agent to RustIron, and what it can and cannot do.",
  },
  {
    id: "hosting",
    label: "Websites & apps",
    description: "WordPress, EmDash, Node.js and Bun apps, and their databases.",
  },
  {
    id: "domains-mail",
    label: "Domains & email",
    description: "Domains, HTTPS certificates, DNS records, and email.",
  },
  {
    id: "recovery-migration",
    label: "Backups & moving sites",
    description: "Encrypted backups, restores, and imports from CyberPanel.",
  },
  {
    id: "security-ops",
    label: "Security & server",
    description: "Health checks, SELinux, the firewall, scheduled jobs, and logs.",
  },
  {
    id: "updates-releases",
    label: "Updates & troubleshooting",
    description: "Updating RustIron and getting out of trouble.",
  },
];

// W769: the article text lives in `console/kb/*.md`, shared with docs.rustiron.app.
const articleSources: [KbSlug, string][] = [
  ["how-rustiron-works", md_how_rustiron_works],
  ["install-and-setup", md_install_and_setup],
  ["signing-and-plans", md_signing_and_plans],
  ["console-tour", md_console_tour],
  ["console-changes", md_console_changes],
  ["console-sites", md_console_sites],
  ["console-domains-email", md_console_domains_email],
  ["console-backups", md_console_backups],
  ["console-server", md_console_server],
  ["console-users", md_console_users],
  ["ai-agents", md_ai_agents],
  ["ai-agents-connect", md_ai_agents_connect],
  ["ai-agents-skill", md_ai_agents_skill],
  ["wordpress-sites", md_wordpress_sites],
  ["modern-apps-and-emdash", md_modern_apps_and_emdash],
  ["fullstack-caddy", md_fullstack_caddy],
  ["databases-and-credentials", md_databases_and_credentials],
  ["postgresql-18", md_postgresql_18],
  ["domains-ssl-and-dns", md_domains_ssl_and_dns],
  ["email-and-relay", md_email_and_relay],
  ["backups-and-recovery", md_backups_and_recovery],
  ["migrations", md_migrations],
  ["security-and-diagnoses", md_security_and_diagnoses],
  ["firewall-and-network", md_firewall_and_network],
  ["updates-and-releases", md_updates_and_releases],
  ["troubleshooting-and-recovery", md_troubleshooting_and_recovery],
];

export const kbArticles: KbArticle[] = articleSources.map(([slug, text]) => {
  const { meta, sections } = parseKbMarkdown(text, slug);
  return {
    slug,
    category: meta.category as KbCategoryId,
    title: kbArticleTitles[slug],
    summary: meta.description as string,
    readMinutes: meta.readMinutes as number,
    runbooks: meta.runbooks as string[],
    keywords: meta.keywords as string[],
    consoleLinks: meta.consoleLinks as { to: string; label: string }[],
    sections: sections as KbSection[],
  };
});

export const operatorRunbooks: OperatorRunbookRef[] = [
  {
    id: "01",
    title: "Recovery objectives",
    group: "Decisions & custody",
    file: "docs/operator/01-RECOVERY-OBJECTIVES.md",
    summary: "Settled RPO, RTO, retention, and capture targets.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "02",
    title: "Off-site copy",
    group: "Decisions & custody",
    file: "docs/operator/02-OFFSITE-COPY.md",
    summary: "Independent backup destination guide (deferred after v1.0).",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "03",
    title: "Key custody",
    group: "Decisions & custody",
    file: "docs/operator/03-KEY-CUSTODY.md",
    summary: "Production and recovery key custody rules.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "04",
    title: "Independent review",
    group: "Decisions & custody",
    file: "docs/operator/04-INDEPENDENT-REVIEW.md",
    summary: "Critical human security review procedure.",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "05",
    title: "Operator key",
    group: "Decisions & custody",
    file: "docs/operator/05-OPERATOR-KEY.md",
    summary: "Create and sign plans with an operator SSHSIG key.",
    guideSlug: "signing-and-plans",
  },
  {
    id: "06",
    title: "Lab backup enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/06-LAB-BACKUP-ENROLLMENT.md",
    summary: "Lab-only backup metadata and credential-file contract.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "07",
    title: "Epoch re-adoption",
    group: "Enrollment & updates",
    file: "docs/operator/07-EPOCH-READOPTION.md",
    summary: "Re-adopt sites after authorized host epoch recovery.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "08",
    title: "Capture freeze limits",
    group: "Backups & recovery",
    file: "docs/operator/08-CAPTURE-FREEZE-LIMITS.md",
    summary: "Freeze window and consistency rules for backups.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "09",
    title: "Product enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/09-PRODUCT-ENROLLMENT.md",
    summary: "Enroll an installed host and operator signing policy.",
    guideSlug: "install-and-setup",
  },
  {
    id: "10",
    title: "Product store enrollment",
    group: "Enrollment & updates",
    file: "docs/operator/10-PRODUCT-STORE-ENROLLMENT.md",
    summary: "Enroll an append-only restic backup destination.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "11",
    title: "After power loss",
    group: "Backups & recovery",
    file: "docs/operator/11-AFTER-POWER-LOSS.md",
    summary: "Recovery and reconcile commands for every verb after a crash.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "12",
    title: "Uninstall",
    group: "Backups & recovery",
    file: "docs/operator/12-UNINSTALL.md",
    summary: "Remove RustIron while preserving live site data and archives.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "13",
    title: "Scheduled capture",
    group: "Backups & recovery",
    file: "docs/operator/13-SCHEDULED-CAPTURE.md",
    summary: "Enable daily backup captures under a signed standing grant.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "14",
    title: "OLS package upgrade",
    group: "Enrollment & updates",
    file: "docs/operator/14-OLS-UPGRADE.md",
    summary: "Upgrade OpenLiteSpeed and verify the shipped parent config.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "15",
    title: "Page cache on",
    group: "Websites & apps",
    file: "docs/operator/15-PAGE-CACHE-ON.md",
    summary: "Enable or disable LiteSpeed Page Cache for a WordPress site.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "16",
    title: "Product update",
    group: "Enrollment & updates",
    file: "docs/operator/16-PRODUCT-UPDATE.md",
    summary: "Update RustIron, migrate journal schema, cut bundles, or roll back.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "17",
    title: "Break-glass",
    group: "Backups & recovery",
    file: "docs/operator/17-BREAK-GLASS.md",
    summary: "Make an emergency manual host change and return to management.",
    guideSlug: "troubleshooting-and-recovery",
  },
  {
    id: "18",
    title: "Owner choices",
    group: "Decisions & custody",
    file: "docs/operator/18-OWNER-CHOICES.md",
    summary: "Recorded owner v1.0 choices for host, store, mail, alerts, and console.",
    guideSlug: "install-and-setup",
  },
  {
    id: "19",
    title: "Risk acceptance",
    group: "Decisions & custody",
    file: "docs/operator/19-RISK-ACCEPTANCE.md",
    summary: "Line-by-line acceptance of known v1.0 limits.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "20",
    title: "Homelab VPS backup",
    group: "Backups & recovery",
    file: "docs/operator/20-HOMELAB-VPS-BACKUP.md",
    summary: "Verify, restore, or undo nightly pull backups to RustFS.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "21",
    title: "Pilot DNS record",
    group: "DNS, firewall & mail",
    file: "docs/operator/21-PILOT-DNS-RECORD.md",
    summary: "Add, check, and remove a pilot DNS A record.",
    guideSlug: "domains-ssl-and-dns",
  },
  {
    id: "22",
    title: "Backup retention",
    group: "Backups & recovery",
    file: "docs/operator/22-BACKUP-RETENTION.md",
    summary: "Prune expired snapshots safely with retention authority.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "23",
    title: "Alert check-in",
    group: "Backups & recovery",
    file: "docs/operator/23-ALERT-CHECKIN.md",
    summary: "Connect a host to Uptime Kuma redacted heartbeat alerts.",
    guideSlug: "security-and-diagnoses",
  },
  {
    id: "24",
    title: "WordPress update",
    group: "Websites & apps",
    file: "docs/operator/24-WORDPRESS-UPDATE.md",
    summary: "Apply signed WordPress core, plugin, or theme updates with rollback.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "25",
    title: "Delete a live site",
    group: "Websites & apps",
    file: "docs/operator/25-DELETE-LIVE-SITE.md",
    summary: "Delete a site behind a fresh verified capture or settle an open deletion.",
    guideSlug: "wordpress-sites",
  },
  {
    id: "26",
    title: "Site restore",
    group: "Backups & recovery",
    file: "docs/operator/26-SITE-RESTORE.md",
    summary: "Restore a live website behind a safety capture or revert.",
    guideSlug: "backups-and-recovery",
  },
  {
    id: "27",
    title: "Database export",
    group: "Backups & recovery",
    file: "docs/operator/27-DATABASE-EXPORT.md",
    summary: "Extract a SQL dump offline from an encrypted backup capture.",
    guideSlug: "databases-and-credentials",
  },
  {
    id: "28",
    title: "Firewall zone",
    group: "DNS, firewall & mail",
    file: "docs/operator/28-FIREWALL-ZONE.md",
    summary: "Apply or check the rustiron firewalld zone without losing SSH.",
    guideSlug: "firewall-and-network",
  },
  {
    id: "29",
    title: "DNS (PowerDNS 5.1)",
    group: "DNS, firewall & mail",
    file: "docs/operator/29-DNS.md",
    summary: "Enroll PowerDNS 5.1, import zones, apply dns_change, and reconcile.",
    guideSlug: "domains-ssl-and-dns",
  },
  {
    id: "30",
    title: "Proxy site",
    group: "Websites & apps",
    file: "docs/operator/30-PROXY-SITE.md",
    summary: "Provision and manage loopback HTTP or WebSocket proxy sites.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "31",
    title: "Advisory watch",
    group: "Enrollment & updates",
    file: "docs/operator/31-ADVISORY-WATCH.md",
    summary: "Check Rust, Bun, AlmaLinux 10, and stack versions against advisories.",
    guideSlug: "updates-and-releases",
  },
  {
    id: "32",
    title: "Modern apps",
    group: "Websites & apps",
    file: "docs/operator/32-MODERN-APPS.md",
    summary: "Provision, deploy, diagnose, roll back, and delete Node.js 22 / Bun 1.4 apps.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "33",
    title: "EmDash CMS",
    group: "Websites & apps",
    file: "docs/operator/33-EMDASH.md",
    summary: "Run EmDash 1.6.0, rehearse WordPress WXR migration, back up, and upgrade.",
    guideSlug: "modern-apps-and-emdash",
  },
  {
    id: "34",
    title: "Developer platform",
    group: "Websites & apps",
    file: "docs/operator/34-DEVELOPER-PLATFORM.md",
    summary: "Unified Day-0 to Day-2 workflow across sites, apps, DNS, backups, and Console.",
    guideSlug: "how-rustiron-works",
  },
  {
    id: "35",
    title: "Site credential rotation",
    group: "Websites & apps",
    file: "docs/operator/35-SITE-CREDENTIAL-ROTATION.md",
    summary: "Rotate per-site MariaDB passwords locally with atomic db.cnf swap.",
    guideSlug: "databases-and-credentials",
  },
  {
    id: "36",
    title: "Mail relay & cutover",
    group: "DNS, firewall & mail",
    file: "docs/operator/36-MAIL-RELAY-AND-CUTOVER.md",
    summary: "Enable per-site Postfix Unix-socket relay and plan mail cutover.",
    guideSlug: "email-and-relay",
  },
  {
    id: "37",
    title: "Replacement migration",
    group: "Migration & cutover",
    file: "docs/operator/37-M6-REPLACEMENT-MIGRATION.md",
    summary: "Fresh-host wave plan, cutover budgets, rollback triggers, and verification.",
    guideSlug: "migrations",
  },
  {
    id: "38",
    title: "Console deployment & hardening",
    group: "Websites & apps",
    file: "docs/operator/38-CONSOLE-PRODUCTION-DEPLOYMENT.md",
    summary: "Deploy and harden the Console with Better Auth, HTTPS origin, and P16 access.",
    guideSlug: "install-and-setup",
  },
];

export const glossaryTerms: [string, string][] = parseGlossary(glossaryText);

export function articleBySlug(slug: string): KbArticle | undefined {
  return kbArticles.find((article) => article.slug === slug);
}

export function articleCategory(id: KbCategoryId): KbCategory {
  return kbCategories.find((c) => c.id === id) ?? kbCategories[0];
}

export function articleMatchesQuery(article: KbArticle, needle: string): boolean {
  if (!needle) return true;
  if (
    article.title.toLowerCase().includes(needle) ||
    article.summary.toLowerCase().includes(needle) ||
    article.keywords.some((k) => k.toLowerCase().includes(needle)) ||
    article.runbooks.some((r) => r.toLowerCase().includes(needle))
  ) {
    return true;
  }
  return article.sections.some(
    (s) =>
      s.heading.toLowerCase().includes(needle) ||
      s.paragraphs.some((p) => p.toLowerCase().includes(needle)) ||
      (s.bullets?.some((b) => b.toLowerCase().includes(needle)) ?? false) ||
      (s.commands?.some(
        (c) => c.label.toLowerCase().includes(needle) || c.code.toLowerCase().includes(needle),
      ) ??
        false),
  );
}
