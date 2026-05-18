import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/app/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-medium transition-colors",
  {
    variants: {
      variant: {
        default: "border-border bg-surface-2 text-text",
        emerald:
          "border-emerald/25 bg-emerald-soft text-emerald",
        cyan: "border-cyan/25 bg-cyan-soft text-cyan",
        red: "border-red/25 bg-red-soft text-red",
        amber: "border-amber/25 bg-amber-soft text-amber",
        violet:
          "border-violet/25 bg-violet-soft text-violet",
        outline: "border-border bg-transparent text-text-2",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}
