// v0.3 item 64 (owner, 2026-11-28): choosing several entries at once, on every
// list with two entries or more. A row checkbox, "Choose all", and a bar with
// the actions. An action never changes the server from the browser: it shows
// one `rustiron plan create` command per chosen entry (each verb names one
// site), to review and sign offline and submit on the Plans page. Removal is
// never offered in bulk.
import { Link } from "@tanstack/react-router";
import { X } from "lucide-react";
import { AnimatePresence, motion } from "motion/react";
import { useState } from "react";

import { useCalmMotion } from "@/components/console/motion-kit";
import {
  AlertDialog,
  AlertDialogClose,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogPopup,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { REVIEW_AND_SIGN_STEPS } from "../../cli-commands";
import { CopyButton } from "../../ui";

export type Selection = {
  ids: ReadonlySet<string>;
  has: (id: string) => boolean;
  toggle: (id: string, on: boolean) => void;
  setMany: (ids: string[], on: boolean) => void;
  clear: () => void;
};

export function useSelection(): Selection {
  const [ids, setIds] = useState<ReadonlySet<string>>(new Set());
  const setMany = (list: string[], on: boolean) =>
    setIds((current) => {
      const next = new Set(current);
      for (const id of list) {
        if (on) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  return {
    ids,
    has: (id) => ids.has(id),
    toggle: (id, on) => setMany([id], on),
    setMany,
    clear: () => setIds(new Set()),
  };
}

/** A row's checkbox; it sits above the row's whole-row link. */
export function RowCheck({
  selection,
  id,
  label,
}: {
  selection: Selection;
  id: string;
  label: string;
}) {
  return (
    <span className="relative z-10 grid size-8 shrink-0 place-items-center">
      <Checkbox
        aria-label={`Choose ${label}`}
        checked={selection.has(id)}
        onCheckedChange={(on) => selection.toggle(id, on)}
      />
    </span>
  );
}

/** "Choose all" above a list ("… on this page" when the list has several pages). */
export function PageCheck({
  selection,
  pageIds,
  noun,
  wholeList,
  enabled = true,
}: {
  selection: Selection;
  pageIds: string[];
  noun: string;
  wholeList: boolean;
  /** False on a list too short for choosing several (fewer than two entries). */
  enabled?: boolean;
}) {
  if (!enabled || pageIds.length === 0) return null;
  const chosen = pageIds.filter((id) => selection.has(id)).length;
  return (
    <label className="flex w-fit cursor-pointer items-center gap-2.5 px-4 text-sm text-muted-foreground sm:px-5">
      <span className="grid size-8 place-items-center">
        <Checkbox
          checked={chosen > 0 && chosen === pageIds.length}
          indeterminate={chosen > 0 && chosen < pageIds.length}
          onCheckedChange={(on) => selection.setMany(pageIds, on)}
        />
      </span>
      {wholeList ? `Choose all ${noun}` : `Choose all ${noun} on this page`}
    </label>
  );
}

export type BulkAction = {
  label: string;
  /** "Back up 3 websites now?" */
  question: (count: number) => string;
  /** One plan command for one chosen entry. */
  command: (id: string) => string;
};

/** One command per entry, each writing its own plan file. */
export function bulkCommands(ids: string[], command: (id: string) => string): string {
  return ids
    .map((id, i) => command(id).replace("> ./plan.json", `> ./plan-${i + 1}.json`))
    .join("\n");
}

/** The bar that appears once entries are chosen. */
export function BulkBar({
  selection,
  matchingIds,
  nameOf,
  noun,
  one,
  actions,
}: {
  selection: Selection;
  /** Every entry that matches the current filter and search, on any page. */
  matchingIds: string[];
  nameOf: (id: string) => string;
  /** Plural and singular names, e.g. "websites" and "website". */
  noun: string;
  one: string;
  actions: BulkAction[];
}) {
  const calm = useCalmMotion();
  const [pending, setPending] = useState<BulkAction | null>(null);
  const count = selection.ids.size;
  const chosen = [...selection.ids];
  const allChosen = matchingIds.every((id) => selection.has(id));
  const named = `${count} ${count === 1 ? one : noun}`;
  const commands = pending ? bulkCommands(chosen, pending.command) : "";

  return (
    <>
      <AnimatePresence>
        {count > 0 ? (
          <motion.div
            role="region"
            aria-label={`Actions for the chosen ${noun}`}
            initial={calm ? false : { opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={calm ? undefined : { opacity: 0, y: 16 }}
            transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
            className="sticky bottom-4 z-20 mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-panel border border-border-strong/60 bg-raised px-4 py-3 shadow-[0_12px_32px_-12px_rgba(0,0,0,0.6)]"
          >
            <p className="text-sm font-medium text-foreground tabular-nums" aria-live="polite">
              {named} chosen
            </p>
            {!allChosen ? (
              <Button
                variant="link"
                size="sm"
                className="px-0"
                onClick={() => selection.setMany(matchingIds, true)}
              >
                Choose all {matchingIds.length}
              </Button>
            ) : null}
            <div className="ms-auto flex flex-wrap items-center gap-2">
              {actions.map((action) => (
                <Button
                  key={action.label}
                  variant="outline"
                  size="sm"
                  onClick={() => setPending(action)}
                >
                  {action.label}
                </Button>
              ))}
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label="Clear the choice"
                onClick={selection.clear}
              >
                <X aria-hidden="true" />
              </Button>
            </div>
          </motion.div>
        ) : null}
      </AnimatePresence>

      <AlertDialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogPopup className="sm:max-w-2xl">
          <AlertDialogHeader>
            <AlertDialogTitle>{pending?.question(count)}</AlertDialogTitle>
            <AlertDialogDescription>
              Nothing changes from here. Run these commands on your workstation: each {one} gets its
              own plan. Review and sign each plan offline, then submit it on the Plans page.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="mx-6 flex min-h-0 flex-col gap-3">
            <p className="text-sm text-foreground">
              {chosen.slice(0, 6).map(nameOf).join(", ")}
              {chosen.length > 6 ? `, and ${chosen.length - 6} more` : ""}
            </p>
            <div
              className="max-h-56 overflow-auto"
              role="region"
              aria-label={`Plan commands for ${named}`}
              // oxlint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- scroll regions must be keyboard reachable
              tabIndex={0}
            >
              <pre className="code signed-bytes">{commands}</pre>
            </div>
            <div className="flex items-center justify-between gap-3">
              <span className="text-xs text-muted-foreground">
                Then review and sign each plan as usual (shown for one file):
              </span>
              <CopyButton text={commands} label={`Copy the ${count} plan commands`} />
            </div>
            <pre className="code signed-bytes">{REVIEW_AND_SIGN_STEPS}</pre>
          </div>
          <AlertDialogFooter>
            <AlertDialogClose render={<Button variant="ghost" />}>Close</AlertDialogClose>
            <Link
              className="btn primary sm"
              to="/plans/new/review"
              onClick={() => selection.clear()}
            >
              Open the Plans page
            </Link>
          </AlertDialogFooter>
        </AlertDialogPopup>
      </AlertDialog>
    </>
  );
}
