import type { Icon } from '@/components/icons';

export function EmptyState({
  icon: IconCmp,
  title,
  hint
}: {
  icon: Icon;
  title: string;
  hint?: string;
}) {
  return (
    <div className='text-muted-foreground flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed py-16 text-center'>
      <IconCmp className='h-10 w-10 opacity-40' />
      <p className='text-sm font-medium'>{title}</p>
      {hint && <p className='max-w-sm text-xs'>{hint}</p>}
    </div>
  );
}
