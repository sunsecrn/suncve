'use client';

// Render de Markdown (GFM) para as anotações. Sem HTML cru (react-markdown é seguro
// por padrão), estilizado manualmente já que o projeto não usa @tailwindcss/typography.

import Markdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { cn } from '@/lib/utils';

const components: Components = {
  a: ({ node: _node, ...props }) => (
    <a
      {...props}
      target='_blank'
      rel='noopener noreferrer'
      className='text-primary underline underline-offset-2'
    />
  ),
  p: ({ node: _node, ...props }) => (
    <p {...props} className='leading-relaxed' />
  ),
  h1: ({ node: _node, ...props }) => (
    <h1 {...props} className='mt-4 mb-1 text-lg font-bold' />
  ),
  h2: ({ node: _node, ...props }) => (
    <h2 {...props} className='mt-4 mb-1 text-base font-bold' />
  ),
  h3: ({ node: _node, ...props }) => (
    <h3 {...props} className='mt-3 mb-1 text-sm font-semibold' />
  ),
  ul: ({ node: _node, ...props }) => (
    <ul {...props} className='ml-5 list-disc space-y-1' />
  ),
  ol: ({ node: _node, ...props }) => (
    <ol {...props} className='ml-5 list-decimal space-y-1' />
  ),
  blockquote: ({ node: _node, ...props }) => (
    <blockquote
      {...props}
      className='text-muted-foreground border-l-2 pl-3 italic'
    />
  ),
  pre: ({ node: _node, ...props }) => (
    <pre
      {...props}
      className='bg-muted overflow-x-auto rounded-lg border p-3 text-xs'
    />
  ),
  code: ({ node: _node, className, children, ...props }) => {
    const isBlock = /language-/.test(className ?? '');
    return isBlock ? (
      <code {...props} className={cn('font-mono', className)}>
        {children}
      </code>
    ) : (
      <code
        {...props}
        className='bg-muted rounded px-1 py-0.5 font-mono text-xs'
      >
        {children}
      </code>
    );
  },
  table: ({ node: _node, ...props }) => (
    <div className='overflow-x-auto'>
      <table {...props} className='w-full border-collapse text-xs' />
    </div>
  ),
  th: ({ node: _node, ...props }) => (
    <th {...props} className='border px-2 py-1 text-left font-semibold' />
  ),
  td: ({ node: _node, ...props }) => (
    <td {...props} className='border px-2 py-1' />
  )
};

export function MarkdownPreview({ children }: { children: string }) {
  return (
    <div className='space-y-2 text-sm break-words [&>*:first-child]:mt-0'>
      <Markdown remarkPlugins={[remarkGfm]} components={components}>
        {children}
      </Markdown>
    </div>
  );
}
