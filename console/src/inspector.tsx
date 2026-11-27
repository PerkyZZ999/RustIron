// W714 (pass 33, fix 7): the inspector drawer that several pages open beside a
// list, and the drawer selection that animates it closed.
import { X } from "lucide-react";
import {
  type Dispatch,
  type ReactNode,
  type SetStateAction,
  startTransition,
  useCallback,
  useEffect,
  useState,
  ViewTransition,
} from "react";

import { Glyph } from "./ui";

/**
 * W695: drawer selection whose changes run as transitions, so closing the
 * inspector drawer animates out through its `ViewTransition` (it already
 * slides in with CSS).
 */
export function useDrawerSelection<T>(): [T | null, Dispatch<SetStateAction<T | null>>] {
  const [selected, setSelected] = useState<T | null>(null);
  const select = useCallback<Dispatch<SetStateAction<T | null>>>(
    (next) => startTransition(() => setSelected(next)),
    [],
  );
  return [selected, select];
}

export function InspectorPanel({
  ariaLabel,
  title,
  subtitle,
  monoTitle = false,
  closeLabel,
  onClose,
  children,
}: {
  ariaLabel: string;
  title: string;
  subtitle?: string;
  monoTitle?: boolean;
  closeLabel: string;
  onClose: () => void;
  children: ReactNode;
}) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <>
      <div className="insp-backdrop" aria-hidden="true" onClick={onClose} />
      <ViewTransition enter="none" exit="drawer-out" default="none">
        <aside className="insp-drawer" aria-label={ariaLabel}>
          <div className="insp-head">
            <div style={{ minWidth: 0 }}>
              <h2
                className={monoTitle ? "mono" : undefined}
                style={{ fontSize: monoTitle ? 16 : 18 }}
              >
                {title}
              </h2>
              {subtitle ? <span className="cap">{subtitle}</span> : null}
            </div>
            <button type="button" className="icon-btn" aria-label={closeLabel} onClick={onClose}>
              <Glyph icon={X} />
            </button>
          </div>
          <div className="insp-body">{children}</div>
        </aside>
      </ViewTransition>
    </>
  );
}
