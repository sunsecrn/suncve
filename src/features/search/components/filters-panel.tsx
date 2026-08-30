'use client';

import { useState, useCallback } from 'react';
import { useTranslations } from 'next-intl';
import {
  IconFilter,
  IconChevronDown,
  IconChevronUp,
  IconX,
  IconLoader2,
  IconHelpCircle
} from '@tabler/icons-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Slider } from '@/components/ui/slider';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger
} from '@/components/ui/collapsible';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '@/components/ui/select';
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList
} from '@/components/ui/command';
import {
  Popover,
  PopoverContent,
  PopoverTrigger
} from '@/components/ui/popover';
import {
  type SearchFilters,
  type Severity,
  type DatePeriod,
  type EpssFilterLevel,
  EPSS_LEVELS,
  EPSS_LEVEL_META,
  EPSS_LEVEL_RANGE,
  defaultFilters
} from '@/features/search/types';
import { EpssSignal } from '@/components/epss-signal';
import { CWE_CATEGORIES, getCWEDisplay } from '@/features/search/cwe-data';
import { Input } from '@/components/ui/input';
import { CheckIcon } from '@radix-ui/react-icons';
import { cn } from '@/lib/utils';
import { useLocale } from 'next-intl';

interface FiltersPanelProps {
  filters: SearchFilters;
  filterOptions: {
    cwes: { cwe_id: string; count: number }[];
    languages: { languageMain: string; count: number }[];
  };
  onFiltersChange: (filters: SearchFilters) => void;
  isSearching?: boolean;
}

export function FiltersPanel({
  filters,
  filterOptions,
  onFiltersChange,
  isSearching = false
}: FiltersPanelProps) {
  const t = useTranslations('search.filters');
  const locale = useLocale();
  const [isOpen, setIsOpen] = useState(false);
  const [cweOpen, setCweOpen] = useState(false);
  const [cweCatOpen, setCweCatOpen] = useState(false);
  const [langOpen, setLangOpen] = useState(false);

  const activeFiltersCount = countActiveFilters(filters);

  const handleReset = useCallback(() => {
    onFiltersChange(defaultFilters);
  }, [onFiltersChange]);

  const handleCVSSChange = useCallback(
    (value: number[]) => {
      onFiltersChange({
        ...filters,
        cvssMin: value[0],
        cvssMax: value[1]
      });
    },
    [filters, onFiltersChange]
  );

  const handleSeverityToggle = useCallback(
    (severity: Severity) => {
      const newSeverities = filters.severity.includes(severity)
        ? filters.severity.filter((s) => s !== severity)
        : [...filters.severity, severity];
      onFiltersChange({ ...filters, severity: newSeverities });
    },
    [filters, onFiltersChange]
  );

  const handleEpssToggle = useCallback(
    (level: EpssFilterLevel) => {
      const newLevels = filters.epssLevel.includes(level)
        ? filters.epssLevel.filter((l) => l !== level)
        : [...filters.epssLevel, level];
      onFiltersChange({ ...filters, epssLevel: newLevels });
    },
    [filters, onFiltersChange]
  );

  const handleCWEToggle = useCallback(
    (cwe: string) => {
      const newCWEs = filters.cwes.includes(cwe)
        ? filters.cwes.filter((c) => c !== cwe)
        : [...filters.cwes, cwe];
      onFiltersChange({ ...filters, cwes: newCWEs });
    },
    [filters, onFiltersChange]
  );

  const handleLanguageToggle = useCallback(
    (lang: string) => {
      const newLangs = filters.languages.includes(lang)
        ? filters.languages.filter((l) => l !== lang)
        : [...filters.languages, lang];
      onFiltersChange({ ...filters, languages: newLangs });
    },
    [filters, onFiltersChange]
  );

  const handleBooleanFilter = useCallback(
    (
      key:
        | 'hasExploit'
        | 'hasRepository'
        | 'hasCommitFix'
        | 'hasNuclei'
        | 'hasKev'
        | 'hasMissingTemplate',
      value: boolean | null
    ) => {
      onFiltersChange({ ...filters, [key]: value });
    },
    [filters, onFiltersChange]
  );

  const handleEcosystemChange = useCallback(
    (value: string) => {
      onFiltersChange({
        ...filters,
        ecosystem: value === 'all' ? null : value
      });
    },
    [filters, onFiltersChange]
  );

  const handleDownloadsChange = useCallback(
    (value: number[]) => {
      onFiltersChange({
        ...filters,
        popDownloadsMin: value[0] > 0 ? sliderToDl(value[0]) : null,
        popDownloadsMax: value[1] < DL_STEPS ? sliderToDl(value[1]) : null
      });
    },
    [filters, onFiltersChange]
  );

  const handleStarsChange = useCallback(
    (value: number[]) => {
      onFiltersChange({
        ...filters,
        starsMin: value[0] > 0 ? value[0] : null,
        starsMax: value[1] < 100000 ? value[1] : null
      });
    },
    [filters, onFiltersChange]
  );

  const handleDatePeriodChange = useCallback(
    (period: DatePeriod) => {
      onFiltersChange({
        ...filters,
        datePeriod: period,
        customDate: period === 'custom' ? filters.customDate : null
      });
    },
    [filters, onFiltersChange]
  );

  const handleCustomDateChange = useCallback(
    (date: string) => {
      onFiltersChange({
        ...filters,
        datePeriod: 'custom',
        customDate: date
      });
    },
    [filters, onFiltersChange]
  );

  const handleRepositoryChange = useCallback(
    (repo: string) => {
      onFiltersChange({
        ...filters,
        repository: repo || null
      });
    },
    [filters, onFiltersChange]
  );

  const handleCWECategoryToggle = useCallback(
    (categoryId: string) => {
      onFiltersChange({
        ...filters,
        cweCategory: filters.cweCategory === categoryId ? null : categoryId
      });
    },
    [filters, onFiltersChange]
  );

  // Get category name based on locale
  const getCategoryName = (category: (typeof CWE_CATEGORIES)[number]) => {
    return locale === 'pt-BR' ? category.namePtBR : category.nameEn;
  };

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen} data-tour='cve-filters'>
      <div
        className={cn(
          'bg-card flex items-center justify-between rounded-xl border-2 p-4 shadow-sm transition-all',
          isSearching && 'border-primary/50 ring-primary/10 ring-4',
          !isSearching && 'hover:border-muted-foreground/30'
        )}
      >
        <CollapsibleTrigger asChild>
          <Button
            variant='ghost'
            className='flex items-center gap-2 text-base font-medium'
          >
            {isSearching ? (
              <IconLoader2 className='text-primary h-5 w-5 animate-spin' />
            ) : (
              <IconFilter className='h-5 w-5' />
            )}
            {t('title')}
            {activeFiltersCount > 0 && (
              <Badge variant='default' className='ml-2 rounded-full'>
                {activeFiltersCount}
              </Badge>
            )}
            {isOpen ? (
              <IconChevronUp className='text-muted-foreground h-5 w-5' />
            ) : (
              <IconChevronDown className='text-muted-foreground h-5 w-5' />
            )}
          </Button>
        </CollapsibleTrigger>

        {activeFiltersCount > 0 && (
          <Button
            variant='outline'
            size='sm'
            onClick={handleReset}
            className='rounded-lg'
          >
            <IconX className='mr-1 h-4 w-4' />
            {t('clearAll')}
          </Button>
        )}
      </div>

      <CollapsibleContent className='mt-4'>
        <div className='bg-card grid gap-6 rounded-xl border-2 p-6 shadow-sm md:grid-cols-2 lg:grid-cols-3'>
          {/* CVSS Score Range */}
          <div className='space-y-3'>
            <Label>{t('cvssScore')}</Label>
            <Slider
              min={0}
              max={10}
              step={0.1}
              value={[filters.cvssMin, filters.cvssMax]}
              onValueChange={handleCVSSChange}
            />
            <div className='text-muted-foreground flex justify-between text-sm'>
              <span>{filters.cvssMin.toFixed(1)}</span>
              <span>{filters.cvssMax.toFixed(1)}</span>
            </div>
          </div>

          {/* Severity */}
          <div className='space-y-3'>
            <Label>{t('severity')}</Label>
            <div className='flex flex-wrap gap-2'>
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map(
                (sev) => (
                  <Badge
                    key={sev}
                    variant={
                      filters.severity.includes(sev) ? 'default' : 'outline'
                    }
                    className={cn(
                      'cursor-pointer transition-colors',
                      filters.severity.includes(sev) &&
                        getSeverityBadgeColor(sev)
                    )}
                    onClick={() => handleSeverityToggle(sev)}
                  >
                    {t(`severity_${sev}`)}
                  </Badge>
                )
              )}
            </div>
          </div>

          {/* EPSS — probabilidade de exploração em 30 dias */}
          <div className='space-y-3'>
            <Label>{t('epss')}</Label>
            <div className='flex flex-wrap gap-2'>
              {EPSS_LEVELS.map((level) => {
                const active = filters.epssLevel.includes(level);
                // Valor representativo do bucket só para desenhar as barras.
                const sample = EPSS_LEVEL_RANGE[level].min;
                return (
                  <Badge
                    key={level}
                    variant={active ? 'default' : 'outline'}
                    className={cn(
                      'cursor-pointer gap-1.5 transition-colors',
                      active && EPSS_LEVEL_META[level].textClass
                    )}
                    onClick={() => handleEpssToggle(level)}
                  >
                    <EpssSignal epss={sample} label={t('epss')} />
                    {t(`epss_${level}`)}
                  </Badge>
                );
              })}
            </div>
          </div>

          {/* CWE Category Filter */}
          <div className='space-y-3'>
            <Label>{t('cweCategory')}</Label>
            <Popover open={cweCatOpen} onOpenChange={setCweCatOpen}>
              <PopoverTrigger asChild>
                <Button variant='outline' className='w-full justify-start'>
                  {filters.cweCategory
                    ? getCategoryName(
                        CWE_CATEGORIES.find(
                          (c) => c.id === filters.cweCategory
                        )!
                      )
                    : t('selectCWECategory')}
                </Button>
              </PopoverTrigger>
              <PopoverContent className='w-[320px] p-0' align='start'>
                <Command>
                  <CommandInput placeholder={t('searchCWECategory')} />
                  <CommandList className='max-h-[280px]'>
                    <CommandEmpty>{t('noCWECategoryFound')}</CommandEmpty>
                    <CommandGroup>
                      {CWE_CATEGORIES.map((category) => (
                        <CommandItem
                          key={category.id}
                          onSelect={() => handleCWECategoryToggle(category.id)}
                        >
                          <div
                            className={cn(
                              'mr-2 flex h-4 w-4 items-center justify-center rounded-sm border',
                              filters.cweCategory === category.id
                                ? 'bg-primary text-primary-foreground'
                                : 'opacity-50'
                            )}
                          >
                            {filters.cweCategory === category.id && (
                              <CheckIcon className='h-3 w-3' />
                            )}
                          </div>
                          <div className='flex-1'>
                            <span className='font-medium'>
                              {getCategoryName(category)}
                            </span>
                            <p className='text-muted-foreground text-xs'>
                              {category.cwes.slice(0, 4).join(', ')}
                              {category.cwes.length > 4 && '...'}
                            </p>
                          </div>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
          </div>

          {/* CWE Filter */}
          <div className='space-y-3'>
            <Label>{t('cwe')}</Label>
            <Popover open={cweOpen} onOpenChange={setCweOpen}>
              <PopoverTrigger asChild>
                <Button variant='outline' className='w-full justify-start'>
                  {filters.cwes.length > 0
                    ? `${filters.cwes.length} ${t('selected')}`
                    : t('selectCWE')}
                </Button>
              </PopoverTrigger>
              <PopoverContent className='w-[380px] p-0' align='start'>
                <Command>
                  <CommandInput placeholder={t('searchCWE')} />
                  <CommandList className='max-h-[280px]'>
                    <CommandEmpty>{t('noCWEFound')}</CommandEmpty>
                    <CommandGroup>
                      {filterOptions.cwes.map((cwe) => (
                        <CommandItem
                          key={cwe.cwe_id}
                          onSelect={() => handleCWEToggle(cwe.cwe_id)}
                        >
                          <div
                            className={cn(
                              'mr-2 flex h-4 w-4 shrink-0 items-center justify-center rounded-sm border',
                              filters.cwes.includes(cwe.cwe_id)
                                ? 'bg-primary text-primary-foreground'
                                : 'opacity-50'
                            )}
                          >
                            {filters.cwes.includes(cwe.cwe_id) && (
                              <CheckIcon className='h-3 w-3' />
                            )}
                          </div>
                          <span className='flex-1 truncate'>
                            {getCWEDisplay(cwe.cwe_id)}
                          </span>
                          <span className='text-muted-foreground ml-2 shrink-0 text-xs'>
                            ({cwe.count.toLocaleString()})
                          </span>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
          </div>

          {/* Boolean Filters */}
          <div className='space-y-3'>
            <Label>{t('flags')}</Label>
            <div className='space-y-2'>
              <div className='flex items-center justify-between'>
                <span className='text-sm'>{t('hasExploit')}</span>
                <TriStateSwitch
                  value={filters.hasExploit}
                  onChange={(v) => handleBooleanFilter('hasExploit', v)}
                />
              </div>
              <div className='flex items-center justify-between'>
                <span className='text-sm'>{t('hasRepository')}</span>
                <TriStateSwitch
                  value={filters.hasRepository}
                  onChange={(v) => handleBooleanFilter('hasRepository', v)}
                />
              </div>
              <div className='flex items-center justify-between'>
                <span className='text-sm'>{t('hasCommitFix')}</span>
                <TriStateSwitch
                  value={filters.hasCommitFix}
                  onChange={(v) => handleBooleanFilter('hasCommitFix', v)}
                />
              </div>
              <div className='flex items-center justify-between'>
                <span className='text-sm'>{t('hasNuclei')}</span>
                <TriStateSwitch
                  value={filters.hasNuclei}
                  onChange={(v) => handleBooleanFilter('hasNuclei', v)}
                />
              </div>
              <div className='flex items-center justify-between'>
                <div className='flex items-center gap-1.5'>
                  <span className='text-sm'>{t('hasKev')}</span>
                  <FilterHelp text={t('hasKevHelp')} />
                </div>
                <TriStateSwitch
                  value={filters.hasKev}
                  onChange={(v) => handleBooleanFilter('hasKev', v)}
                />
              </div>
              <div className='flex items-center justify-between'>
                <div className='flex items-center gap-1.5'>
                  <span className='text-sm'>{t('hasMissingTemplate')}</span>
                  <FilterHelp text={t('hasMissingTemplateHelp')} />
                </div>
                <TriStateSwitch
                  value={filters.hasMissingTemplate}
                  onChange={(v) => handleBooleanFilter('hasMissingTemplate', v)}
                />
              </div>
            </div>
          </div>

          {/* Ecosystem Filter */}
          <div className='space-y-3'>
            <Label>{t('ecosystem')}</Label>
            <Select
              value={filters.ecosystem ?? 'all'}
              onValueChange={handleEcosystemChange}
            >
              <SelectTrigger className='w-full'>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value='all'>{t('ecosystemAll')}</SelectItem>
                <SelectItem value='github'>GitHub</SelectItem>
                <SelectItem value='wordpress'>WordPress</SelectItem>
                <SelectItem value='npm'>npm</SelectItem>
                <SelectItem value='packagist'>Packagist</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Downloads Range */}
          <div className='space-y-3'>
            <Label>{t('popDownloads')}</Label>
            <Slider
              min={0}
              max={DL_STEPS}
              step={1}
              value={[
                filters.popDownloadsMin != null
                  ? dlToSlider(filters.popDownloadsMin)
                  : 0,
                filters.popDownloadsMax != null
                  ? dlToSlider(filters.popDownloadsMax)
                  : DL_STEPS
              ]}
              onValueChange={handleDownloadsChange}
            />
            <div className='text-muted-foreground flex justify-between text-sm'>
              <span>{formatCompact(filters.popDownloadsMin ?? 0)}</span>
              <span>
                {filters.popDownloadsMax != null
                  ? formatCompact(filters.popDownloadsMax)
                  : `${formatCompact(DOWNLOADS_MAX)}+`}
              </span>
            </div>
          </div>

          {/* Language Filter */}
          <div className='space-y-3'>
            <Label>{t('language')}</Label>
            <Popover open={langOpen} onOpenChange={setLangOpen}>
              <PopoverTrigger asChild>
                <Button variant='outline' className='w-full justify-start'>
                  {filters.languages.length > 0
                    ? `${filters.languages.length} ${t('selected')}`
                    : t('selectLanguage')}
                </Button>
              </PopoverTrigger>
              <PopoverContent className='w-[300px] p-0' align='start'>
                <Command>
                  <CommandInput placeholder={t('searchLanguage')} />
                  <CommandList className='max-h-[200px]'>
                    <CommandEmpty>{t('noLanguageFound')}</CommandEmpty>
                    <CommandGroup>
                      {filterOptions.languages.map((lang) => (
                        <CommandItem
                          key={lang.languageMain}
                          onSelect={() =>
                            handleLanguageToggle(lang.languageMain)
                          }
                        >
                          <div
                            className={cn(
                              'mr-2 flex h-4 w-4 items-center justify-center rounded-sm border',
                              filters.languages.includes(lang.languageMain)
                                ? 'bg-primary text-primary-foreground'
                                : 'opacity-50'
                            )}
                          >
                            {filters.languages.includes(lang.languageMain) && (
                              <CheckIcon className='h-3 w-3' />
                            )}
                          </div>
                          <span className='flex-1'>{lang.languageMain}</span>
                          <span className='text-muted-foreground text-xs'>
                            ({lang.count.toLocaleString()})
                          </span>
                        </CommandItem>
                      ))}
                    </CommandGroup>
                  </CommandList>
                </Command>
              </PopoverContent>
            </Popover>
          </div>

          {/* Stars Range */}
          <div className='space-y-3'>
            <Label>{t('repoStars')}</Label>
            <Slider
              min={0}
              max={100000}
              step={100}
              value={[filters.starsMin ?? 0, filters.starsMax ?? 100000]}
              onValueChange={handleStarsChange}
            />
            <div className='text-muted-foreground flex justify-between text-sm'>
              <span>{(filters.starsMin ?? 0).toLocaleString()}</span>
              <span>{(filters.starsMax ?? 100000).toLocaleString()}+</span>
            </div>
          </div>

          {/* Repository Filter */}
          <div className='space-y-3'>
            <Label>{t('repository')}</Label>
            <Input
              type='text'
              placeholder={t('repositoryPlaceholder')}
              value={filters.repository || ''}
              onChange={(e) => handleRepositoryChange(e.target.value)}
            />
          </div>

          {/* Date Period Filter */}
          <div className='space-y-3 md:col-span-2 lg:col-span-3'>
            <Label>{t('datePeriod')}</Label>
            <div className='flex flex-wrap items-center gap-2'>
              {(
                [
                  'today',
                  '7d',
                  '30d',
                  '120d',
                  '1y',
                  '5y',
                  'all'
                ] as DatePeriod[]
              ).map((period) => (
                <Badge
                  key={period}
                  variant={
                    filters.datePeriod === period ? 'default' : 'outline'
                  }
                  className='cursor-pointer transition-colors'
                  onClick={() => handleDatePeriodChange(period)}
                >
                  {t(`period_${period}`)}
                </Badge>
              ))}
              <div className='flex items-center gap-2'>
                <Badge
                  variant={
                    filters.datePeriod === 'custom' ? 'default' : 'outline'
                  }
                  className='cursor-pointer transition-colors'
                  onClick={() => handleDatePeriodChange('custom')}
                >
                  {t('period_custom')}
                </Badge>
                {filters.datePeriod === 'custom' && (
                  <Input
                    type='text'
                    placeholder='2024, 2024-07, 2024-07-15'
                    value={filters.customDate || ''}
                    onChange={(e) => handleCustomDateChange(e.target.value)}
                    className='w-44'
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}

// Helper Components

function TriStateSwitch({
  value,
  onChange
}: {
  value: boolean | null;
  onChange: (value: boolean | null) => void;
}) {
  const handleClick = () => {
    if (value === null) {
      onChange(true);
    } else if (value === true) {
      onChange(false);
    } else {
      onChange(null);
    }
  };

  return (
    <Button
      variant='outline'
      size='sm'
      className={cn(
        'w-16',
        value === true && 'border-green-500 bg-green-500/20',
        value === false && 'border-red-500 bg-red-500/20'
      )}
      onClick={handleClick}
    >
      {value === null ? '—' : value ? 'Yes' : 'No'}
    </Button>
  );
}

function FilterHelp({ text }: { text: string }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type='button'
          aria-label={text}
          className='text-muted-foreground hover:text-foreground focus-visible:ring-ring inline-flex shrink-0 rounded-full transition-colors focus-visible:ring-2 focus-visible:outline-none'
        >
          <IconHelpCircle className='h-4 w-4' />
        </button>
      </PopoverTrigger>
      <PopoverContent
        side='top'
        align='start'
        className='w-72 text-sm leading-relaxed'
      >
        <p className='text-muted-foreground'>{text}</p>
      </PopoverContent>
    </Popover>
  );
}

function getSeverityBadgeColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-500 hover:bg-red-600';
    case 'high':
      return 'bg-orange-500 hover:bg-orange-600';
    case 'medium':
      return 'bg-yellow-500 hover:bg-yellow-600 text-black';
    case 'low':
      return 'bg-blue-500 hover:bg-blue-600';
    default:
      return '';
  }
}

function countActiveFilters(filters: SearchFilters): number {
  let count = 0;
  if (filters.query) count++;
  if (filters.cvssMin > 0 || filters.cvssMax < 10) count++;
  if (filters.severity.length > 0) count++;
  if (filters.epssLevel.length > 0) count++;
  if (filters.cwes.length > 0) count++;
  if (filters.cweCategory) count++;
  if (filters.hasExploit !== null) count++;
  if (filters.hasRepository !== null) count++;
  if (filters.hasCommitFix !== null) count++;
  if (filters.hasNuclei !== null) count++;
  if (filters.hasKev !== null) count++;
  if (filters.hasMissingTemplate !== null) count++;
  if (filters.languages.length > 0) count++;
  if (filters.starsMin !== null || filters.starsMax !== null) count++;
  if (filters.repoSizeMin !== null || filters.repoSizeMax !== null) count++;
  if (filters.datePeriod !== 'all') count++;
  if (filters.repository) count++;
  if (filters.ecosystem) count++;
  if (filters.popDownloadsMin !== null || filters.popDownloadsMax !== null)
    count++;
  return count;
}

// Downloads slider helpers — log scale so the 0–1B range stays usable for small values.
const DOWNLOADS_MAX = 1_000_000_000;
const DL_STEPS = 1000; // slider resolution (0..DL_STEPS)
const sliderToDl = (p: number) =>
  Math.round(Math.pow(DOWNLOADS_MAX + 1, p / DL_STEPS) - 1);
const dlToSlider = (n: number) =>
  Math.round((Math.log10(n + 1) / Math.log10(DOWNLOADS_MAX + 1)) * DL_STEPS);
const formatCompact = (n: number) =>
  new Intl.NumberFormat('en', {
    notation: 'compact',
    maximumFractionDigits: 1
  }).format(n);
