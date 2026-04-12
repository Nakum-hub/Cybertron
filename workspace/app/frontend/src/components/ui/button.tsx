import * as React from 'react';
import { cn } from '@/lib/utils';

type ButtonVariant = 'default' | 'outline' | 'ghost';
type ButtonSize = 'default' | 'lg' | 'sm';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantClasses: Record<ButtonVariant, string> = {
  default:
    'bg-cyan-600 text-white hover:bg-cyan-500 focus-visible:ring-cyan-300 disabled:bg-cyan-900/40 disabled:text-slate-400',
  outline:
    'border border-white/15 bg-white/[0.03] text-slate-100 hover:bg-white/[0.08] focus-visible:ring-white/30 disabled:text-slate-500',
  ghost:
    'bg-transparent text-slate-200 hover:bg-white/[0.06] focus-visible:ring-white/20 disabled:text-slate-500',
};

const sizeClasses: Record<ButtonSize, string> = {
  default: 'h-10 px-4 py-2 text-sm',
  lg: 'h-12 px-5 py-3 text-base',
  sm: 'h-9 px-3 py-2 text-sm',
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', type = 'button', ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(
        'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-[#07080D] disabled:cursor-not-allowed',
        variantClasses[variant],
        sizeClasses[size],
        className
      )}
      {...props}
    />
  )
);

Button.displayName = 'Button';
