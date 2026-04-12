import * as React from 'react';
import { cn } from '@/lib/utils';

export type ToastActionElement = React.ReactElement;

export interface ToastProps extends React.HTMLAttributes<HTMLDivElement> {
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  variant?: 'default' | 'destructive';
}

export const Toast = React.forwardRef<HTMLDivElement, ToastProps>(
  ({ className, variant = 'default', open = true, ...props }, ref) => {
    if (!open) {
      return null;
    }

    return (
      <div
        ref={ref}
        className={cn(
          'pointer-events-auto w-full rounded-xl border px-4 py-3 shadow-[0_18px_60px_rgba(0,0,0,0.35)] backdrop-blur',
          variant === 'destructive'
            ? 'border-red-300/30 bg-red-500/10 text-red-50'
            : 'border-cyan-300/20 bg-[#08101d]/95 text-slate-50',
          className
        )}
        {...props}
      />
    );
  }
);

Toast.displayName = 'Toast';

export function ToastTitle({
  className,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn('text-sm font-semibold', className)} {...props} />;
}

export function ToastDescription({
  className,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('mt-1 text-sm text-slate-200/90', className)} {...props} />;
}

export function ToastAction({
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        'inline-flex rounded-md border border-white/15 bg-white/[0.06] px-3 py-1.5 text-xs font-medium text-slate-50 hover:bg-white/[0.12]',
        className
      )}
      {...props}
    />
  );
}
