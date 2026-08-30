'use client';

import { cn } from '@/lib/utils';
import {
  EPSS_LEVEL_META,
  formatEpss,
  getEpssLevel,
  type EpssFilterLevel,
  type EpssLevel
} from '@/features/search/types';

// Alturas literais e crescentes (Tailwind v4 não detecta classes montadas por
// template string num build estático). Cinco barras, como sinal de celular.
const BAR_HEIGHTS = ['h-1.5', 'h-2', 'h-2.5', 'h-3', 'h-3.5'] as const;

interface EpssSignalProps {
  /** Probabilidade EPSS [0-1] da CVE. Use isto quando houver dado real. */
  epss?: number | null;
  /**
   * Nível explícito, para legendas e filtros. Diferente de `epss`, não inventa
   * uma porcentagem no resumo — o badge de um filtro representa a faixa
   * inteira, não um valor.
   */
  level?: EpssFilterLevel;
  percentile?: number | null;
  /** Data do score (YYYY-MM-DD), exibida no resumo do title. */
  date?: string | null;
  /** Mostra a probabilidade formatada ao lado das barras. */
  showValue?: boolean;
  /** Locale para formatar a porcentagem (padrão: en). */
  locale?: string;
  /** Rótulo acessível já traduzido, ex.: 'EPSS'. */
  label?: string;
  /** Nome da faixa já traduzido, usado no resumo quando `level` é passado. */
  levelLabel?: string;
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
  level,
  percentile,
  date,
  showValue = false,
  locale = 'en',
  label = 'EPSS',
  levelLabel,
  className
}: EpssSignalProps) {
  const resolved: EpssLevel = level ?? getEpssLevel(epss);
  const meta = EPSS_LEVEL_META[resolved];
  const value = formatEpss(epss, locale);

  let summary: string;
  if (level) {
    // Legenda: descreve a faixa, sem sugerir um valor que não foi medido.
    summary = levelLabel ? `${label}: ${levelLabel}` : label;
  } else if (resolved === 'none') {
    summary = `${label}: —`;
  } else {
    summary = [
      `${label} ${value}`,
      percentile !== null && percentile !== undefined
        ? `p${(percentile * 100).toFixed(1)}`
        : null,
      date || null
    ]
      .filter(Boolean)
      .join(' · ');
  }

  return (
    <span
      className={cn('inline-flex items-center gap-1.5', className)}
      title={summary}
    >
      <span
        className='flex items-end gap-[3px]'
        role='img'
        aria-label={summary}
      >
        {BAR_HEIGHTS.map((height, index) => (
          <span
            key={height}
            className={cn(
              'w-1.5 rounded-[1px]',
              height,
              index < meta.bars ? meta.barClass : 'bg-muted-foreground/40'
            )}
          />
        ))}
      </span>
      {showValue && !level && (
        <span className={cn('font-mono text-xs', meta.textClass)}>{value}</span>
      )}
    </span>
  );
}
