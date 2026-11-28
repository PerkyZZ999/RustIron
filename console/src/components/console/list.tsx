// v0.3 item 64 (owner, 2026-11-28): lists that work for a few entries and for
// hundreds. Search and sorting appear once a list is longer than SMALL_LIST;
// pages appear once it is longer than one page (Settings → Rows per page).
// Filters, search, and sorting go back to page 1. Ported from the prototype
// (docs/mockup/refined/src/components/console/list.tsx).
import { ChevronLeft, ChevronRight, Search, X } from "lucide-react";
import { type ReactNode, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { usePreferences } from "../../prefs";

/** Up to this many entries, a list needs no search or sorting. */
export const SMALL_LIST = 8;

/** Slice `rows` into pages; the page goes back to 1 whenever `resetKey` changes. */
export function usePaged<T>(rows: T[], resetKey: string) {
  const { prefs } = usePreferences();
  const size = prefs.rowsPerPage;
  const key = `${resetKey}|${size}`;
  const [state, setState] = useState({ key, page: 0 });
  const pageCount = Math.max(1, Math.ceil(rows.length / size));
  const page = state.key === key ? Math.min(state.page, pageCount - 1) : 0;
  return {
    rows: rows.slice(page * size, page * size + size),
    page,
    pageCount,
    size,
    total: rows.length,
    setPage: (next: number) => setState({ key, page: next }),
  };
}

type Paged = ReturnType<typeof usePaged>;

/** Page numbers to show: first, last, and the neighbours of the current page. */
export function pageWindow(page: number, pageCount: number): (number | "gap")[] {
  const wanted = new Set(
    [0, pageCount - 1, page - 1, page, page + 1].filter((p) => p >= 0 && p < pageCount),
  );
  const sorted = [...wanted].sort((a, b) => a - b);
  return sorted.flatMap((p, i) =>
    i > 0 && p - (sorted[i - 1] ?? p) > 1 ? (["gap", p] as const) : [p],
  );
}

/** "Showing 51–100 of 148 websites" and the page buttons; nothing for a single page. */
function ListPager({ paged, noun }: { paged: Paged; noun: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const { page, pageCount, size, total } = paged;
  if (pageCount <= 1) return null;
  const first = page * size + 1;
  const last = Math.min(total, first + size - 1);
  // A new page starts at the top of its list, not at the pager.
  const go = (next: number) => {
    paged.setPage(next);
    ref.current?.previousElementSibling?.scrollIntoView({ block: "start" });
  };
  return (
    <div ref={ref} className="mt-3 flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-muted-foreground tabular-nums" aria-live="polite">
        Showing {first}–{last} of {total} {noun}
      </p>
      <nav aria-label={`${noun} pages`}>
        <ul className="flex items-center gap-1">
          <li>
            <Button
              variant="ghost"
              size="sm"
              disabled={page === 0}
              onClick={() => go(page - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft aria-hidden="true" />
              <span className="max-sm:hidden">Previous</span>
            </Button>
          </li>
          {pageWindow(page, pageCount).map((p, i) =>
            p === "gap" ? (
              <li
                key={`gap-${i}`}
                aria-hidden="true"
                className="px-1 text-muted-foreground max-sm:hidden"
              >
                …
              </li>
            ) : (
              <li key={p} className={cn(p !== page && "max-sm:hidden")}>
                <Button
                  variant={p === page ? "outline" : "ghost"}
                  size="icon-sm"
                  aria-current={p === page ? "page" : undefined}
                  aria-label={`Page ${p + 1}`}
                  onClick={() => go(p)}
                  className="tabular-nums"
                >
                  {p + 1}
                </Button>
              </li>
            ),
          )}
          <li>
            <Button
              variant="ghost"
              size="sm"
              disabled={page >= pageCount - 1}
              onClick={() => go(page + 1)}
              aria-label="Next page"
            >
              <span className="max-sm:hidden">Next</span>
              <ChevronRight aria-hidden="true" />
            </Button>
          </li>
        </ul>
      </nav>
    </div>
  );
}

/** The search box above a list, with a clear button. */
function ListSearch({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="input search-input w-full sm:w-72">
      <Search aria-hidden="true" className="size-4" />
      <input
        type="search"
        aria-label={label}
        placeholder={`${label}…`}
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
      {value ? (
        <button
          type="button"
          aria-label="Clear search"
          className="icon-btn"
          onClick={() => onChange("")}
        >
          <X aria-hidden="true" className="size-3.5" />
        </button>
      ) : null}
    </label>
  );
}

/** A "Sort" menu. */
function ListSort<T extends string>({
  value,
  onChange,
  options,
}: {
  value: T;
  onChange: (value: T) => void;
  options: { value: T; label: string }[];
}) {
  return (
    <label className="field">
      Sort
      <select
        className="input"
        aria-label="Sort by"
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

/** A segmented filter with counts. */
export function FilterChips<T extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { value: T; label: string; count: number }[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className="inline-flex flex-wrap items-center gap-1 rounded-lg border border-border bg-subtle p-1"
    >
      {options.map((option) => {
        const active = value === option.value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={active}
            onClick={() => onChange(option.value)}
            className={cn(
              "inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition-colors duration-150",
              active
                ? "border-border-strong/50 bg-raised text-foreground"
                : "border-transparent text-muted-foreground hover:bg-hover hover:text-foreground",
            )}
          >
            {option.label}
            <span className="rounded-full bg-surface/70 px-1.5 py-0.5 text-[11px] leading-none tabular-nums">
              {option.count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

/** Filters on the left; search and sorting on the right (stacked on phones). */
export function ListToolbar({
  filters,
  children,
  hidden = false,
}: {
  filters?: ReactNode;
  children?: ReactNode;
  /** True on a short list that shows no filters, search, or sorting. */
  hidden?: boolean;
}) {
  if (hidden || (!filters && !children)) return null;
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">{filters}</div>
      {children ? (
        <div className="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:items-end">
          {children}
        </div>
      ) : null}
    </div>
  );
}

/** One bordered panel with divided rows: dense enough for hundreds of entries. */
function ListPanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <ul
      aria-label={label}
      className="scroll-mt-24 divide-y divide-border overflow-hidden rounded-panel border border-border bg-surface"
    >
      {children}
    </ul>
  );
}

/** A list row whose name is a link over the whole row; controls stay above it. */
export const rowClass =
  "group relative flex items-center gap-3 px-4 py-3 transition-colors duration-150 hover:bg-hover/60 sm:gap-4 sm:px-5";
export const rowLinkClass =
  "block truncate text-[15px] font-semibold text-foreground after:absolute after:inset-0 focus-visible:outline-none focus-visible:after:outline-2 focus-visible:after:-outline-offset-2 focus-visible:after:outline-focus";

/** Search and sorting, shown only once a list is longer than SMALL_LIST. */
export function ListControls<T extends string>({
  count,
  searchLabel,
  query,
  onQuery,
  sort,
  onSort,
  sorts,
}: {
  count: number;
  searchLabel: string;
  query: string;
  onQuery: (value: string) => void;
  sort: T;
  onSort: (value: T) => void;
  sorts: { value: T; label: string }[];
}) {
  if (count <= SMALL_LIST) return null;
  return (
    <>
      <ListSearch label={searchLabel} value={query} onChange={onQuery} />
      <ListSort value={sort} onChange={onSort} options={sorts} />
    </>
  );
}

/** The rows of one page, the pager, and what sits above and below; "No … match" when empty. */
export function ListArea({
  label,
  noun,
  total,
  paged,
  onReset,
  top,
  bottom,
  children,
}: {
  label: string;
  noun: string;
  total: number;
  paged: Paged;
  onReset: () => void;
  top?: ReactNode;
  bottom?: ReactNode;
  children: ReactNode;
}) {
  if (paged.rows.length === 0) return total > 0 ? <NoMatch noun={noun} onReset={onReset} /> : null;
  return (
    <div>
      {top}
      <ListPanel label={label}>{children}</ListPanel>
      <ListPager paged={paged} noun={noun} />
      {bottom}
    </div>
  );
}

/** Case-insensitive "contains" match on any of the given texts. */
export function matches(query: string, ...texts: string[]): boolean {
  const needle = query.trim().toLowerCase();
  return !needle || texts.some((t) => t.toLowerCase().includes(needle));
}

/** "No … match" with a way back to the whole list. */
function NoMatch({ noun, onReset }: { noun: string; onReset: () => void }) {
  return (
    <div className="rounded-panel border border-dashed border-border px-5 py-8 text-center text-sm text-muted-foreground">
      <p>No {noun} match.</p>
      <button type="button" className="btn quiet sm mt-3" onClick={onReset}>
        Show all {noun}
      </button>
    </div>
  );
}
