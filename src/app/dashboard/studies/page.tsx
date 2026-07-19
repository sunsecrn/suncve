'use client';

import dynamic from 'next/dynamic';

// Import dinâmico com SSR desligado: a página reusa o CVEDetailDrawer, que depende
// do sql.js (browser-only) para abrir o detalhe de uma CVE.
const StudyPageContent = dynamic(
  () => import('@/features/study/components/study-page-content'),
  {
    ssr: false,
    loading: () => (
      <div className='flex min-h-[400px] items-center justify-center'>
        <div className='border-primary h-8 w-8 animate-spin rounded-full border-b-2'></div>
      </div>
    )
  }
);

export default function StudiesPage() {
  return <StudyPageContent />;
}
