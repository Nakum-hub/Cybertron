import { X } from 'lucide-react';
import { toast as pushToast, useToast } from '@/hooks/use-toast';
import { Toast, ToastDescription, ToastTitle } from './toast';

export function Toaster() {
  const { toasts, dismiss } = useToast();

  return (
    <div className="pointer-events-none fixed inset-x-0 top-4 z-[90] flex justify-center px-4">
      <div className="flex w-full max-w-md flex-col gap-3">
        {toasts.map(item => (
          <Toast key={item.id} open={item.open} variant={item.variant}>
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                {item.title ? <ToastTitle>{item.title}</ToastTitle> : null}
                {item.description ? (
                  <ToastDescription>{item.description}</ToastDescription>
                ) : null}
              </div>
              <button
                type="button"
                className="rounded-md p-1 text-slate-300 hover:bg-white/[0.08] hover:text-white"
                onClick={() => dismiss(item.id)}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </Toast>
        ))}
      </div>
    </div>
  );
}

export { pushToast };
