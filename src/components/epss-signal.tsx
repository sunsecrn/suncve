'use client';

import { cn } from '@/lib/utils';
import {
  EPSS_LEVEL_META,
  formatEpss,
  getEpssLevel,
  type EpssLevel
} from '@/features/search/types';

// Cinco células empilhadas, preenchidas de baixo para cima — um medidor de
// nível, não um sinal de celular deitado. As classes são literais porque com
// output:'export' o JIT do Tailwind v4 não detecta classe montada por template
// string.
const CELLS = [0, 1, 2, 3, 4];

interface EpssSignalProps {
  /** Probabilidade EPSS [0-1] da CVE. */
  epss?: number | null;
  percentile?: number | null;
  /** Data do score (YYYY-MM-DD), exibida no resumo do title. */
  date?: string | null;
  /** Mostra a probabilidade formatada ao lado do medidor. */
  showValue?: boolean;
  /** Locale para formatar a porcentagem (padrão: en). */
  locale?: string;
  /** Rótulo acessível já traduzido, ex.: 'EPSS'. */
  label?: string;
  className?: string;
}

/**
 * Indicador de EPSS: medidor vertical de cinco níveis.
 *
 * O EPSS estima a probabilidade [0-1] de a CVE ser explorada nos próximos 30
 * dias. Como a distribuição é fortemente enviesada para perto de zero, os
 * níveis usam limiares de probabilidade bruta (ver getEpssLevel), e não
 * percentil — o medidor cheio significa risco real, não apenas "acima da
 * média".
 *
 * Sem score publicado (`epss` nulo) o medidor fica todo apagado, o que é
 * diferente de "probabilidade zero" — daí a trilha ser bem discreta, para não
 * se confundir com um nível preenchido.
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
            ? `p${Math.round(percentile * 100)}`
            : null,
          date || null
        ]
          .filter(Boolean)
          .join(' · ');

  return (
    <span
      className={cn('inline-flex items-center gap-1.5 align-middle', className)}
      title={summary}
    >
      <span
        className='flex flex-col-reverse gap-[2px]'
        role='img'
        aria-label={summary}
      >
        {CELLS.map((index) => (
          <span
            key={index}
            className={cn(
              'h-[3px] w-2.5 rounded-[1px]',
              index < meta.bars ? meta.barClass : 'bg-muted-foreground/20'
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
