// W715 (pass 33, fix 8): the Docs & KB article titles by slug, the only source
// of each title. The shell's breadcrumbs and search palette read this index, so
// the first load does not carry the article text in `kb-data.ts`.
export const kbArticleTitles = {
  "how-rustiron-works": "How RustIron Works: Architecture & Security Model",
  "install-and-setup": "Installing RustIron on AlmaLinux 10",
  "signing-and-plans": "How Signed Plans & Grants Work",
  "wordpress-sites": "Host & Manage WordPress Websites",
  "modern-apps-and-emdash": "Deploy EmDash CMS, Node.js 22 & Bun 1.4 Apps",
  "fullstack-caddy": "Full-Stack Bun & Node.js Apps with Confined Caddy HTTP/3",
  "postgresql-18": "PostgreSQL 18.7 Setup, Hardening & Multi-DB Selection",
  "domains-ssl-and-dns": "Domains, Let's Encrypt HTTPS & PowerDNS Zones",
  "databases-and-credentials": "Databases, Password Rotation & Offline SQL Exports",
  "email-and-relay": "Outbound Mail Relay & Mailbox Catalog",
  "backups-and-recovery": "Encrypted Backups, Retention Locks & Site Restore",
  migrations: "Migrating from CyberPanel & WordPress to EmDash CMS",
  "security-and-diagnoses": "Host Diagnoses, SELinux & Root-Only Checks",
  "firewall-and-network": "Firewalld Zone, Cron Timers & Traffic Budget",
  "updates-and-releases": "Updating RustIron & Cutting Signed Releases",
  "troubleshooting-and-recovery": "Troubleshooting, Power Loss & Break-Glass Recovery",
} as const;

export type KbSlug = keyof typeof kbArticleTitles;

/** The title of the article at `slug`, if there is one. */
export function kbArticleTitle(slug: string): string | undefined {
  return Object.hasOwn(kbArticleTitles, slug) ? kbArticleTitles[slug as KbSlug] : undefined;
}

/** One search-palette target for each article. */
export function kbSearchTargets(): { href: string; label: string }[] {
  return Object.entries(kbArticleTitles).map(([slug, title]) => ({
    href: `/help/${slug}`,
    label: `Docs: ${title}`,
  }));
}
