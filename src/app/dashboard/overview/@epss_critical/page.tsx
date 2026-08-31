'use client';

import dynamic from 'next/dynamic';

const EpssCriticalCVEs = dynamic(
  () =>
    import('@/features/overview/components/epss-critical-cves').then(
      (mod) => mod.EpssCriticalCVEs
    ),
  { ssr: false }
);

export default function EpssCritical() {
  return <EpssCriticalCVEs />;
}
