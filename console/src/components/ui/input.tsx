import { Input as InputPrimitive } from "@base-ui/react/input";
import type * as React from "react";

import { cn } from "@/lib/utils";

type InputProps = Omit<InputPrimitive.Props & React.RefAttributes<HTMLInputElement>, "size"> & {
  size?: "sm" | "default" | "lg" | number;
};

export function Input({ className, size = "default", ...props }: InputProps): React.ReactElement {
  const inputClassName = cn(
    "h-9.5 w-full min-w-0 rounded-[inherit] bg-transparent px-3 text-sm text-foreground leading-9.5 outline-none placeholder:text-muted-foreground sm:h-8.5 sm:leading-8.5",
    size === "sm" && "h-8 px-2.5 leading-8 sm:h-7.5 sm:leading-7.5",
    size === "lg" && "h-10.5 leading-10.5 sm:h-9.5 sm:leading-9.5",
  );

  return (
    <span
      className={cn(
        "relative inline-flex w-full rounded-control border border-border-strong bg-subtle text-sm transition-[border-color,box-shadow,background-color] duration-150 ease-out hover:border-border-strong has-focus-visible:border-focus has-focus-visible:ring-2 has-focus-visible:ring-focus has-aria-invalid:border-destructive has-disabled:pointer-events-none has-disabled:opacity-50",
        className,
      )}
      data-slot="input-control"
    >
      <InputPrimitive
        className={inputClassName}
        data-slot="input"
        size={typeof size === "number" ? size : undefined}
        {...props}
      />
    </span>
  );
}
