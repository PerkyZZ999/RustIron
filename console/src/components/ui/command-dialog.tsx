import { Dialog as DialogPrimitive } from "@base-ui/react/dialog";
import type React from "react";

import { cn } from "@/lib/utils";

export const CommandDialog: typeof DialogPrimitive.Root = DialogPrimitive.Root;

export function CommandDialogPopup({
  className,
  children,
  ...props
}: DialogPrimitive.Popup.Props): React.ReactElement {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Backdrop
        className="fixed inset-0 z-[150] bg-scrim backdrop-blur-[2px] transition-opacity duration-150 ease-out data-ending-style:opacity-0 data-starting-style:opacity-0"
        data-slot="command-dialog-backdrop"
      />
      <DialogPrimitive.Viewport
        className="fixed inset-0 z-[200] flex flex-col items-center px-4 py-8 sm:py-[10vh]"
        data-slot="command-dialog-viewport"
      >
        <DialogPrimitive.Popup
          className={cn(
            "relative flex max-h-[min(28rem,80vh)] min-h-0 w-full max-w-xl flex-col overflow-hidden rounded-panel border border-border bg-popover text-popover-foreground shadow-[var(--shadow-float)] matte-surface outline-none transition-[transform,opacity] duration-[240ms] ease-[var(--ease-cinematic)] will-change-transform data-ending-style:scale-[0.97] data-starting-style:translate-y-2 data-starting-style:scale-[0.97] data-ending-style:opacity-0 data-starting-style:opacity-0",
            className,
          )}
          data-slot="command-dialog-popup"
          {...props}
        >
          {children}
        </DialogPrimitive.Popup>
      </DialogPrimitive.Viewport>
    </DialogPrimitive.Portal>
  );
}
