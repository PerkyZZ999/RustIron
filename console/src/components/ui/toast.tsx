// W650: Coss UI Toast primitive built directly on @base-ui/react/toast.
// Uses explicit semantic tokens (zero CSS-variable /opacity color-mix bugs) and
// honors prefers-reduced-motion & :root[data-motion="reduce"].
import { Toast } from "@base-ui/react/toast";
import { CircleAlert, CircleCheck, Info, LoaderCircle, TriangleAlert, X } from "lucide-react";
import type * as React from "react";

import { cn } from "@/lib/utils";

export const toastManager = Toast.createToastManager();

type ToastTone = "success" | "error" | "warning" | "info" | "loading" | "default";

function resolveTone(type: string | undefined): ToastTone {
  if (
    type === "success" ||
    type === "error" ||
    type === "warning" ||
    type === "info" ||
    type === "loading"
  ) {
    return type;
  }
  return "default";
}

function ToastGlyph({ tone }: { tone: ToastTone }) {
  switch (tone) {
    case "success":
      return <CircleCheck aria-hidden="true" className="size-4 shrink-0 text-success" />;
    case "error":
      return <CircleAlert aria-hidden="true" className="size-4 shrink-0 text-destructive" />;
    case "warning":
      return <TriangleAlert aria-hidden="true" className="size-4 shrink-0 text-warning" />;
    case "info":
      return <Info aria-hidden="true" className="size-4 shrink-0 text-info" />;
    case "loading":
      return (
        <LoaderCircle
          aria-hidden="true"
          className="size-4 shrink-0 animate-spin text-muted-foreground"
        />
      );
    default:
      return null;
  }
}

const toneSurfaceClass: Record<ToastTone, string> = {
  success: "ri-toast-success",
  error: "ri-toast-error",
  warning: "ri-toast-warning",
  info: "ri-toast-info",
  loading: "ri-toast-default",
  default: "ri-toast-default",
};

function ToastList() {
  const { toasts } = Toast.useToastManager();

  return (
    <Toast.Portal>
      <Toast.Viewport className="ri-toast-viewport" aria-label="Notifications">
        {toasts.map((toast) => {
          const tone = resolveTone(toast.type);
          return (
            <Toast.Root
              key={toast.id}
              toast={toast}
              className={cn("ri-toast", toneSurfaceClass[tone])}
            >
              <div className="ri-toast-inner">
                <ToastGlyph tone={tone} />
                <div className="ri-toast-content">
                  {toast.title ? (
                    <Toast.Title className="ri-toast-title">{toast.title}</Toast.Title>
                  ) : null}
                  {toast.description ? (
                    <Toast.Description className="ri-toast-desc">
                      {toast.description}
                    </Toast.Description>
                  ) : null}
                </div>
                <Toast.Close aria-label="Dismiss notification" className="ri-toast-close">
                  <X aria-hidden="true" className="size-3.5" />
                </Toast.Close>
              </div>
            </Toast.Root>
          );
        })}
      </Toast.Viewport>
    </Toast.Portal>
  );
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  return (
    <Toast.Provider toastManager={toastManager} timeout={3600} limit={4}>
      {children}
      <ToastList />
    </Toast.Provider>
  );
}
