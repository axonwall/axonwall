import * as React from "react"

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "secondary" | "destructive" | "outline"
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  let variantClasses = ""
  if (variant === "default") variantClasses = "border-transparent bg-primary text-primary-foreground hover:bg-primary/80"
  if (variant === "secondary") variantClasses = "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80"
  if (variant === "destructive") variantClasses = "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80"
  if (variant === "outline") variantClasses = "text-foreground"

  return (
    <div className={`inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 ${variantClasses} ${className}`} {...props} />
  )
}

export { Badge }
