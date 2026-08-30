'use client';

import { cn } from '@/lib/utils';
import {
  EPSS_LEVEL_META,
  formatEpss,
  getEpssLevel,
  type EpssLevel
} from '@/features/search/types';

// Alturas literais e crescentes (Tailwind v4 não detecta classes montadas por
// template string num build estático). Cinco barras, como sinal de celular.
const BAR_HEIGHTS = ['h-1', 'h-1.5', 'h-2', 'h-2.5', 'h-3'] as const;

interface EpssSignalProps {
  epss: number | null | undefined;
  percentile?: number | null;
  /** Data do score (YYYY-MM-DD), exibida no resumo do title. */
  date?: string | null;
  /** Mostra a probabilidade formatada ao lado das barras. */
  showValue?: boolean;
  /** Locale para formatar a porcentagem (padrão: en). */
  locale?: string;
  /** Rótulo acessível já traduzido, ex.: 'EPSS'. */
  label?: string;
  className?: string;
}

/**
 * Indicador de EPSS em barras de sinal.
 *
 * O EPSS estima a probabilidade [0-1] de a CVE ser explorada nos próximos 30
 * dias. Como a distribuição é fortemente enviesada para perto de zero, as
 * barras usam limiares de probabilidade bruta (ver getEpssLevel), e não
 * percentil — cinco barras significam risco real, não apenas "acima da média".
 *
 * Sem score publicado (`epss` nulo) o componente mostra as cinco barras vazias,
 * o que é diferente de "probabilidade zero".
 */
export function EpssSignal({
  epss,
  percentile,
  date,
  showValue = false,
  locale = 'en',
  label = 'EPSS',
  className
}: EpssSignalProps) {
  const level: EpssLevel = getEpssLevel(epss);
  const meta = EPSS_LEVEL_META[level];
  const value = formatEpss(epss, locale);

  const summary =
    level === 'none'
      ? `${label}: —`
      : [
          `${label} ${value}`,
          percentile !== null && percentile !== undefined
            ? `p${(percentile * 100).toFixed(1)}`
            : null,
          date || null
        ]
          .filter(Boolean)
          .join(' · ');

  return (
    <span
      className={cn('inline-flex items-center gap-1.5', className)}
      title={summary}
    >
      <span
        className='flex items-end gap-[2px]'
        role='img'
        aria-label={summary}
      >
        {BAR_HEIGHTS.map((height, index) => (
          <span
            key={height}
            className={cn(
              'w-1 rounded-[1px]',
              height,
              index < meta.bars ? meta.barClass : 'bg-muted-foreground/25'
            )}
          />
        ))}
      </span>
      {showValue && (
        <span className={cn('font-mono text-xs', meta.textClass)}>{value}</span>
      )}
    </span>
  );
}
