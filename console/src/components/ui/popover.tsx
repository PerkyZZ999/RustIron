import { Popover as PopoverPrimitive } from "@base-ui/react/popover";
import type React from "react";

import { cn } from "@/lib/utils";

export const Popover: typeof PopoverPrimitive.Root = PopoverPrimitive.Root;

export function PopoverTrigger({
  className,
  children,
  ...props
}: PopoverPrimitive.Trigger.Props): React.ReactElement {
  return (
    <PopoverPrimitive.Trigger className={className} data-slot="popover-trigger" {...props}>
      {children}
    </PopoverPrimitive.Trigger>
  );
}

export function PopoverPopup({
  children,
  className,
  side = "bottom",
  align = "center",
  sideOffset = 6,
  alignOffset = 0,
  portalProps,
  ...props
}: PopoverPrimitive.Popup.Props & {
  portalProps?: PopoverPrimitive.Portal.Props;
  side?: PopoverPrimitive.Positioner.Props["side"];
  align?: PopoverPrimitive.Positioner.Props["align"];
  sideOffset?: PopoverPrimitive.Positioner.Props["sideOffset"];
  alignOffset?: PopoverPrimitive.Positioner.Props["alignOffset"];
}): React.ReactElement {
  return (
    <PopoverPrimitive.Portal {...portalProps}>
      <PopoverPrimitive.Positioner
        align={align}
        alignOffset={alignOffset}
        className="z-[200] max-w-[calc(100vw-2rem)]"
        data-slot="popover-positioner"
        side={side}
        sideOffset={sideOffset}
      >
        <PopoverPrimitive.Popup
          className={cn(
            "relative flex origin-(--transform-origin) flex-col rounded-panel border border-border bg-popover text-popover-foreground shadow-[var(--shadow-float)] matte-surface outline-none will-change-transform transition-[opacity,transform] duration-[220ms] ease-[var(--ease-cinematic)] data-starting-style:translate-y-1 data-starting-style:scale-[0.97] data-starting-style:opacity-0 data-ending-style:opacity-0",
            className,
          )}
          data-slot="popover-popup"
          {...props}
        >
          {children}
        </PopoverPrimitive.Popup>
      </PopoverPrimitive.Positioner>
    </PopoverPrimitive.Portal>
  );
}
