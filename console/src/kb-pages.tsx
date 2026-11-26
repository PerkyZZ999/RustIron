// W649: Integrated RustIron Documentation & Knowledge Base views (/help and /help/$slug).
import { Link } from "@tanstack/react-router";
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  CircleAlert,
  CircleCheck,
  Clock,
  Copy,
  FileText,
  Info,
  Search,
  Terminal,
  TriangleAlert,
} from "lucide-react";
import { useEffect, useState } from "react";

import { toastManager } from "@/components/ui/toast";
import { useData } from "./data";
import {
  articleBySlug,
  articleCategory,
  articleMatchesQuery,
  glossaryTerms,
  type KbArticle,
  type KbCategoryId,
  type KbCommand,
  type KbSection,
  kbArticles,
  kbCategories,
  operatorRunbooks,
} from "./kb-data";
import { liveHelpItems } from "./live";
import { Crumbs, Glyph, Page, TableScroll } from "./ui";

function KbCopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!copied) return undefined;
    const timer = setTimeout(() => setCopied(false), 1800);
    return () => clearTimeout(timer);
  }, [copied]);

  return (
    <button
      type="button"
      className="btn quiet sm"
      aria-label={label}
      onClick={() =>
        void navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          toastManager.add({ id: "clipboard-copy", type: "success", title: "Command copied" });
        })
      }
    >
      <Glyph icon={copied ? Check : Copy} className={copied ? "check-pop list-ok" : undefined} />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function KbCommandBlock({ command }: { command: KbCommand }) {
  return (
    <div className="kb-cmd">
      <div className="kb-cmd-head">
        <div className="row" style={{ gap: 8 }}>
          <Glyph icon={Terminal} />
          <span className="kb-cmd-label">{command.label}</span>
          <span className="pill">{command.where}</span>
        </div>
        <KbCopyButton text={command.code} label={`Copy command: ${command.label}`} />
      </div>
      <pre className="code">{command.code}</pre>
    </div>
  );
}

function KbArticleCard({ article }: { article: KbArticle }) {
  const cat = articleCategory(article.category);
  return (
    <Link to="/help/$slug" params={{ slug: article.slug }} className="kb-card">
      <div className="kb-card-meta">
        <span className="pill info">{cat.label}</span>
        <span className="cap row" style={{ gap: 4 }}>
          <Glyph icon={Clock} />
          {article.readMinutes} min
        </span>
      </div>
      <h3 className="kb-card-title">{article.title}</h3>
      <p className="muted kb-card-summary">{article.summary}</p>
      <div className="kb-card-foot">
        <div className="row" style={{ gap: 6 }}>
          {article.runbooks.slice(0, 3).map((rb) => (
            <span key={rb} className="pill">
              {rb}
            </span>
          ))}
        </div>
        <span className="kb-card-cta">
          Read guide <Glyph icon={ArrowRight} />
        </span>
      </div>
    </Link>
  );
}

function KbRelevantBanner({ live }: { live: boolean }) {
  const data = useData();
  const relevant = data.observation
    ? liveHelpItems(data.observation)
    : live
      ? []
      : [
          {
            title: "Interrupted configuration activation",
            detail:
              "For op_7Q2KX9. How to establish which generation each site serves and plan an explicit recovery.",
            href: "/operations/op_7Q2KX9",
          },
          {
            title: "Repository key recovery",
            detail:
              "For the failed decryption on portfolio.lab.test. Refresh the escrow copy and record a drill.",
            href: "/help/backups-and-recovery",
          },
        ];

  return (
    <section className="panel relevant" aria-label="Relevant right now">
      <div className="panel-head">
        <h2>Relevant right now</h2>
        <span className="meta">Based on current host state</span>
      </div>
      <div className="grid g2">
        {relevant.length === 0 ? (
          <div className="help-card">
            <span className="hc-icon">
              <Glyph icon={CircleCheck} className="list-ok" />
            </span>
            <div>
              <strong>No current incidents in this observation</strong>
              <p className="muted">
                Every guide and runbook below works directly from SSH even when the Console is
                offline.
              </p>
            </div>
          </div>
        ) : (
          relevant.map((item) => (
            <div className="help-card" key={item.title}>
              <span className="hc-icon">
                <Glyph icon={CircleAlert} className="list-err" />
              </span>
              <div>
                <strong>{item.title}</strong>
                <p className="muted">
                  {item.detail}{" "}
                  <Link to={item.href} translate="no">
                    Open record
                  </Link>
                </p>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function KbReferenceTabs({ needle }: { needle: string }) {
  const [tab, setTab] = useState<"runbooks" | "glossary">("runbooks");
  const shownRunbooks = operatorRunbooks.filter(
    (r) =>
      !needle ||
      `${r.id} ${r.title} ${r.group} ${r.summary} ${r.file}`.toLowerCase().includes(needle),
  );
  const shownTerms = glossaryTerms.filter(
    ([term, meaning]) => !needle || `${term} ${meaning}`.toLowerCase().includes(needle),
  );

  return (
    <section className="panel flush" aria-label="Reference index">
      <div className="kb-ref-head">
        <div>
          <h2>Reference &amp; glossary</h2>
          <p className="cap">
            Complete 38-runbook operator kit index (docs/operator/) and core RustIron terminology.
          </p>
        </div>
        <div className="seg" role="tablist" aria-label="Reference sections">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "runbooks"}
            onClick={() => setTab("runbooks")}
          >
            Operator runbooks ({shownRunbooks.length})
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "glossary"}
            onClick={() => setTab("glossary")}
          >
            Glossary ({shownTerms.length})
          </button>
        </div>
      </div>

      {tab === "runbooks" ? (
        <TableScroll label="Operator runbooks">
          <table className="data">
            <thead>
              <tr>
                <th>ID</th>
                <th>Runbook</th>
                <th>Area</th>
                <th>Summary</th>
                <th>Guide</th>
              </tr>
            </thead>
            <tbody>
              {shownRunbooks.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted">
                    No runbook matches this search.
                  </td>
                </tr>
              ) : (
                shownRunbooks.map((rb) => (
                  <tr key={rb.id}>
                    <td className="mono">{rb.id}</td>
                    <td>
                      <strong>{rb.title}</strong>
                      <div className="cap mono">{rb.file}</div>
                    </td>
                    <td>
                      <span className="pill">{rb.group}</span>
                    </td>
                    <td className="muted">{rb.summary}</td>
                    <td>
                      <Link
                        className="btn quiet sm"
                        to="/help/$slug"
                        params={{ slug: rb.guideSlug }}
                      >
                        Open guide
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableScroll>
      ) : (
        <TableScroll label="Glossary of terms">
          <table className="data">
            <thead>
              <tr>
                <th>Term</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {shownTerms.length === 0 ? (
                <tr>
                  <td colSpan={2} className="muted">
                    No term matches this search.
                  </td>
                </tr>
              ) : (
                shownTerms.map(([term, meaning]) => (
                  <tr key={term}>
                    <th scope="row">{term}</th>
                    <td className="muted">{meaning}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </TableScroll>
      )}
    </section>
  );
}

export function KnowledgeBaseHomePage() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<"all" | KbCategoryId>("all");
  const data = useData();
  const live = data.source.kind === "live" || data.source.kind === "unavailable";
  const host =
    data.source.kind === "live" ? data.source.host.host_id : live ? "this host" : "lab-01";
  const needle = query.trim().toLowerCase();

  const matchingArticles = kbArticles.filter(
    (article) =>
      (category === "all" || article.category === category) && articleMatchesQuery(article, needle),
  );

  return (
    <Page live={live}>
      <Crumbs items={[{ href: "/", label: "Overview" }, { label: "Docs & Knowledge Base" }]} />
      <div className="page-head">
        <div>
          <h1>Docs &amp; Knowledge Base</h1>
          <p className="sub">
            Runbooks for the current state of {host}, plus step-by-step guides, CLI recipes, and
            architecture docs for everything in RustIron.
          </p>
        </div>
        <label className="input search-input help-search">
          <Glyph icon={Search} />
          <input
            type="search"
            aria-label="Search docs, commands, runbooks, and terms"
            placeholder="Search guides, CLI commands, runbooks…"
            autoComplete="off"
            spellCheck={false}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
      </div>

      <KbRelevantBanner live={live} />

      <div className="filter-pills" role="group" aria-label="Filter guides by topic">
        <button type="button" aria-pressed={category === "all"} onClick={() => setCategory("all")}>
          All guides ({kbArticles.length})
        </button>
        {kbCategories.map((cat) => (
          <button
            key={cat.id}
            type="button"
            aria-pressed={category === cat.id}
            onClick={() => setCategory(cat.id)}
          >
            {cat.label}
          </button>
        ))}
      </div>

      {matchingArticles.length === 0 ? (
        <section className="panel empty-state">
          <Glyph icon={BookOpen} />
          <div className="t">No guide matches &ldquo;{query.trim()}&rdquo;</div>
          <p className="muted">
            Try searching for a workflow like wordpress, emdash, ssl, backup, firewall, update, or
            selinux, or check the 38-runbook reference table below.
          </p>
          <button
            type="button"
            className="btn quiet sm"
            onClick={() => {
              setQuery("");
              setCategory("all");
            }}
          >
            Reset search &amp; topic filter
          </button>
        </section>
      ) : (
        <section className="kb-grid" aria-label="Knowledge base guides">
          {matchingArticles.map((article) => (
            <KbArticleCard key={article.slug} article={article} />
          ))}
        </section>
      )}

      <KbReferenceTabs needle={needle} />
    </Page>
  );
}

function KbArticleSection({ section }: { section: KbSection }) {
  return (
    <section id={section.id} className="kb-section">
      <h2>{section.heading}</h2>
      {section.paragraphs.map((text) => (
        <p key={text}>{text}</p>
      ))}
      {section.bullets?.length ? (
        <ul className="kb-bullets">
          {section.bullets.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}
      {section.callout ? (
        <div
          className={section.callout.tone === "warn" ? "attention" : "attention info"}
          role="note"
        >
          <Glyph icon={section.callout.tone === "warn" ? TriangleAlert : Info} />
          <div className="att-body">
            <strong>{section.callout.title}.</strong> {section.callout.body}
          </div>
        </div>
      ) : null}
      {section.commands?.map((command) => (
        <KbCommandBlock key={command.label} command={command} />
      ))}
    </section>
  );
}

export function KnowledgeBaseArticlePage({ slug }: { slug: string }) {
  const data = useData();
  const live = data.source.kind === "live" || data.source.kind === "unavailable";
  const article = articleBySlug(slug);

  if (!article) {
    return (
      <Page live={live}>
        <Crumbs
          items={[
            { href: "/", label: "Overview" },
            { href: "/help", label: "Docs & Knowledge Base" },
            { label: "Not found" },
          ]}
        />
        <section className="panel empty-state">
          <Glyph icon={BookOpen} />
          <h1>Guide not found</h1>
          <p className="muted">
            There is no Knowledge Base guide with slug <span className="mono">{slug}</span>.
          </p>
          <Link className="btn primary sm" to="/help">
            <Glyph icon={ArrowLeft} />
            Back to Docs &amp; Knowledge Base
          </Link>
        </section>
      </Page>
    );
  }

  const cat = articleCategory(article.category);
  const idx = kbArticles.findIndex((a) => a.slug === article.slug);
  const prev = idx > 0 ? kbArticles[idx - 1] : null;
  const next = idx >= 0 && idx < kbArticles.length - 1 ? kbArticles[idx + 1] : null;

  return (
    <Page live={live}>
      <Crumbs
        items={[
          { href: "/", label: "Overview" },
          { href: "/help", label: "Docs & Knowledge Base" },
          { label: article.title },
        ]}
      />
      <div className="page-head">
        <div>
          <div className="row" style={{ gap: 8, marginBottom: 8 }}>
            <span className="pill info">{cat.label}</span>
            <span className="pill">
              <Glyph icon={Clock} />
              {article.readMinutes} min read
            </span>
            {article.runbooks.map((rb) => (
              <span key={rb} className="pill">
                <Glyph icon={FileText} />
                {rb}
              </span>
            ))}
          </div>
          <h1>{article.title}</h1>
          <p className="sub">{article.summary}</p>
        </div>
        <Link className="btn quiet sm" to="/help">
          <Glyph icon={ArrowLeft} />
          All guides
        </Link>
      </div>

      <div className="kb-article-grid">
        <article className="panel kb-prose">
          {article.sections.map((section) => (
            <KbArticleSection key={section.id} section={section} />
          ))}

          <nav className="kb-prevnext" aria-label="Adjacent guides">
            {prev ? (
              <Link className="kb-pn-link" to="/help/$slug" params={{ slug: prev.slug }}>
                <span className="cap">Previous guide</span>
                <strong>
                  <Glyph icon={ArrowLeft} /> {prev.title}
                </strong>
              </Link>
            ) : (
              <span />
            )}
            {next ? (
              <Link className="kb-pn-link right" to="/help/$slug" params={{ slug: next.slug }}>
                <span className="cap">Next guide</span>
                <strong>
                  {next.title} <Glyph icon={ArrowRight} />
                </strong>
              </Link>
            ) : null}
          </nav>
        </article>

        <aside className="stack kb-toc" aria-label="Guide outline and links">
          <section className="panel">
            <div className="panel-head">
              <h2>On this page</h2>
            </div>
            <ul className="kb-toc-list">
              {article.sections.map((section) => (
                <li key={section.id}>
                  <a href={`#${section.id}`}>{section.heading}</a>
                </li>
              ))}
            </ul>
          </section>

          {article.consoleLinks.length > 0 ? (
            <section className="panel">
              <div className="panel-head">
                <h2>Open in Console</h2>
              </div>
              <div className="stack" style={{ gap: 8 }}>
                {article.consoleLinks.map((link) => (
                  <Link key={link.to} className="btn sm" to={link.to}>
                    {link.label}
                  </Link>
                ))}
              </div>
            </section>
          ) : null}

          <section className="panel">
            <div className="panel-head">
              <h2>Canonical runbooks</h2>
            </div>
            <p className="muted">
              Full step-by-step procedures ship offline in{" "}
              <span className="mono">docs/operator/</span> so you can always operate sites directly
              over SSH.
            </p>
            <div className="row" style={{ gap: 6, marginTop: 10 }}>
              {article.runbooks.map((rb) => (
                <span key={rb} className="pill">
                  {rb}
                </span>
              ))}
            </div>
          </section>
        </aside>
      </div>
    </Page>
  );
}
