import { Switch as SwitchPrimitive } from "@base-ui/react/switch";
import type React from "react";

import { cn } from "@/lib/utils";

export function Switch({ className, ...props }: SwitchPrimitive.Root.Props): React.ReactElement {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border p-0.5 outline-none transition-[background-color,border-color,box-shadow] duration-150 ease-out pointer-coarse:after:absolute pointer-coarse:after:-inset-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus data-disabled:cursor-not-allowed data-disabled:opacity-50 data-checked:border-primary data-checked:bg-primary data-unchecked:border-border-strong data-unchecked:bg-subtle",
        className,
      )}
      data-slot="switch"
      {...props}
    >
      <SwitchPrimitive.Thumb
        className="pointer-events-none block size-4.5 rounded-full bg-white shadow-xs transition-transform duration-150 ease-out data-checked:translate-x-5 data-unchecked:translate-x-0"
        data-slot="switch-thumb"
      />
    </SwitchPrimitive.Root>
  );
}
