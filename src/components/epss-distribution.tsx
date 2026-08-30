'use client';

import { cn } from '@/lib/utils';
import {
  EPSS_LEVEL_META,
  EPSS_LEVELS,
  type EpssCounts,
  type EpssFilterLevel
} from '@/features/search/types';

// Piso de largura por segmento não vazio. Sem ele a barra fica ilegível: as
// faixas de 3,1% / 1,0% / 0,7% do catálogo virariam 9px, 3px e 2px num card de
// ~300px — justamente as três que importam. O número exato de cada faixa fica
// no title, que é onde ele conta.
const MIN_SEGMENT_PERCENT = 4;

// Da menor para a maior, que é como a barra é lida da esquerda para a direita.
const ORDER: EpssFilterLevel[] = [...EPSS_LEVELS].reverse();

interface EpssDistributionProps {
  counts: EpssCounts;
  locale?: string;
  /** Rótulos das faixas já traduzidos. */
  levelLabels?: Partial<Record<EpssFilterLevel, string>>;
  /** Chamado ao clicar num segmento (leva para a busca filtrada). */
  onSelect?: (level: EpssFilterLevel) => void;
  className?: string;
}

/**
 * Distribuição das CVEs pelas cinco faixas de EPSS, numa barra segmentada.
 *
 * As larguras são proporcionais mas com piso, então a barra não é uma leitura
 * exata de área — é um mapa das faixas. Segmento sem nenhuma CVE não aparece.
 */
export function EpssDistribution({
  counts,
  locale = 'en',
  levelLabels,
  onSelect,
  className
}: EpssDistributionProps) {
  const total = ORDER.reduce((sum, level) => sum + (counts[level] ?? 0), 0);

  if (total === 0) {
    return (
      <div
        className={cn(
          'bg-muted-foreground/20 h-2 w-full rounded-full',
          className
        )}
      />
    );
  }

  const present = ORDER.filter((level) => (counts[level] ?? 0) > 0);

  // Aplica o piso e redistribui o que sobra na proporção original, para a soma
  // continuar batendo 100%.
  const raw = present.map((level) => ((counts[level] ?? 0) / total) * 100);
  const floored = raw.map((pct) => Math.max(pct, MIN_SEGMENT_PERCENT));
  const excess = floored.reduce((a, b) => a + b, 0) - 100;
  const shrinkable = floored.reduce(
    (sum, pct, i) => sum + (raw[i] > MIN_SEGMENT_PERCENT ? pct : 0),
    0
  );

  const widths = floored.map((pct, i) =>
    excess > 0 && shrinkable > 0 && raw[i] > MIN_SEGMENT_PERCENT
      ? pct - (excess * pct) / shrinkable
      : pct
  );

  const nf = new Intl.NumberFormat(locale);

  return (
    <div
      className={cn(
        'bg-muted-foreground/20 flex h-2 w-full overflow-hidden rounded-full',
        className
      )}
    >
      {present.map((level, i) => {
        const count = counts[level] ?? 0;
        const share = ((count / total) * 100).toFixed(1);
        const title = `${levelLabels?.[level] ?? level}: ${nf.format(count)} (${share}%)`;

        return onSelect ? (
          <button
            key={level}
            type='button'
            title={title}
            aria-label={title}
            onClick={() => onSelect(level)}
            style={{ width: `${widths[i]}%` }}
            className={cn(
              'h-full cursor-pointer transition-opacity hover:opacity-70',
              EPSS_LEVEL_META[level].barClass
            )}
          />
        ) : (
          <span
            key={level}
            title={title}
            style={{ width: `${widths[i]}%` }}
            className={cn('h-full', EPSS_LEVEL_META[level].barClass)}
          />
        );
      })}
    </div>
  );
}
