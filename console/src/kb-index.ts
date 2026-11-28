// W715 (pass 33, fix 8): the Docs & KB article titles by slug, the only source
// of each title. The shell's breadcrumbs and search palette read this index, so
// the first load does not carry the article text in `kb-data.ts`.
export const kbArticleTitles = {
  "how-rustiron-works": "How RustIron works",
  "install-and-setup": "Install RustIron",
  "signing-and-plans": "Approve changes with signed plans",
  "console-tour": "Console tour",
  "console-changes": "Make changes from the Console",
  "console-sites": "Websites & apps in the Console",
  "console-domains-email": "Domains & email in the Console",
  "console-backups": "Backups in the Console",
  "console-server": "Server pages",
  "console-users": "Users, roles & sign-in",
  "ai-agents": "AI agents and RustIron",
  "ai-agents-connect": "Connect an AI agent",
  "ai-agents-skill": "The RustIron agent skill",
  "wordpress-sites": "WordPress sites",
  "modern-apps-and-emdash": "Node.js, Bun & EmDash apps",
  "fullstack-caddy": "Full-stack apps with Caddy",
  "databases-and-credentials": "Databases & passwords",
  "postgresql-18": "PostgreSQL",
  "domains-ssl-and-dns": "Domains, HTTPS & DNS",
  "email-and-relay": "Email",
  "backups-and-recovery": "Backups & restores",
  migrations: "Move sites to RustIron",
  "security-and-diagnoses": "Health checks & SELinux",
  "firewall-and-network": "Firewall & scheduled jobs",
  "updates-and-releases": "Update RustIron",
  "troubleshooting-and-recovery": "Troubleshooting",
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
