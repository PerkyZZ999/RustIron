import type { CSSProperties, ReactNode } from "react";

import { cn } from "@/lib/utils";

/** Staggered entrance wrapper for top-of-page beats (honors prefers-reduced-motion & data-motion=reduce). */
export function MotionBeat({
  beat = 0,
  className,
  children,
}: {
  beat?: number;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={cn("motion-beat", className)} style={{ "--beat": beat } as CSSProperties}>
      {children}
    </div>
  );
}
