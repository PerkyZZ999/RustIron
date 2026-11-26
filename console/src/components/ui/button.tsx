import { mergeProps } from "@base-ui/react/merge-props";
import { useRender } from "@base-ui/react/use-render";
import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";

import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "relative inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-control border font-medium text-sm leading-5 outline-none transition-[background-color,border-color,color,box-shadow,transform] duration-150 ease-out active:scale-[0.985] pointer-coarse:after:absolute pointer-coarse:after:size-full pointer-coarse:after:min-h-11 pointer-coarse:after:min-w-11 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:pointer-events-none disabled:opacity-50 disabled:active:scale-100 data-loading:select-none data-loading:text-transparent [&_svg:not([class*='opacity-'])]:opacity-85 [&_svg:not([class*='size-'])]:size-4 [&_svg]:pointer-events-none [&_svg]:-mx-0.5 [&_svg]:shrink-0",
  {
    defaultVariants: {
      size: "default",
      variant: "default",
    },
    variants: {
      size: {
        default: "h-10 px-3.5 sm:h-9",
        icon: "size-10 sm:size-9",
        "icon-sm": "size-8",
        lg: "h-11 px-4 sm:h-10",
        sm: "h-8 gap-1.5 px-2.5 text-xs",
      },
      variant: {
        default:
          "border-primary bg-primary text-primary-foreground shadow-[inset_0_1px_0_0_rgba(255,255,255,0.16)] hover:border-primary-hover hover:bg-primary-hover data-pressed:bg-primary-hover *:data-[slot=button-loading-indicator]:text-primary-foreground",
        destructive:
          "border-destructive bg-destructive text-white hover:opacity-90 data-pressed:opacity-90 dark:border-border dark:bg-error-surface dark:text-destructive dark:hover:border-destructive dark:hover:bg-error-surface *:data-[slot=button-loading-indicator]:text-current",
        ghost:
          "border-transparent bg-transparent text-muted-foreground hover:bg-hover hover:text-foreground data-pressed:bg-pressed data-pressed:text-foreground *:data-[slot=button-loading-indicator]:text-foreground",
        link: "border-transparent bg-transparent text-focus underline-offset-4 hover:underline data-pressed:underline active:scale-100 *:data-[slot=button-loading-indicator]:text-focus",
        outline:
          "border-border bg-raised text-foreground matte-surface hover:border-border-strong hover:bg-hover data-pressed:bg-pressed *:data-[slot=button-loading-indicator]:text-foreground",
        secondary:
          "border-border bg-subtle text-foreground hover:border-border-strong hover:bg-hover data-pressed:bg-pressed *:data-[slot=button-loading-indicator]:text-foreground",
      },
    },
  },
);

type ButtonProps = useRender.ComponentProps<"button"> & {
  variant?: VariantProps<typeof buttonVariants>["variant"];
  size?: VariantProps<typeof buttonVariants>["size"];
  loading?: boolean;
};

export function Button({
  className,
  variant,
  size,
  render,
  children,
  loading = false,
  disabled: disabledProp,
  ...props
}: ButtonProps): React.ReactElement {
  const isDisabled = Boolean(loading || disabledProp);
  const typeValue: React.ButtonHTMLAttributes<HTMLButtonElement>["type"] = render
    ? undefined
    : "button";

  const defaultProps = {
    children: (
      <>
        {children}
        {loading ? (
          <Spinner className="pointer-events-none absolute" data-slot="button-loading-indicator" />
        ) : null}
      </>
    ),
    className: cn(buttonVariants({ className, size, variant })),
    "aria-disabled": loading || undefined,
    "data-loading": loading ? "" : undefined,
    "data-slot": "button",
    disabled: isDisabled,
    type: typeValue,
  };

  return useRender({
    defaultTagName: "button",
    props: mergeProps<"button">(defaultProps, props),
    render,
  });
}
