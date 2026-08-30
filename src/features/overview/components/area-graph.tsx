'use client';

import * as React from 'react';
import { useEffect, useState, useCallback } from 'react';
import { IconShieldCheck } from '@tabler/icons-react';
import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from 'recharts';
import { useTranslations, useLocale } from 'next-intl';

import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from '@/components/ui/card';
import {
  ChartConfig,
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent
} from '@/components/ui/chart';
import { Button } from '@/components/ui/button';
import {
  useDashboardStats,
  type CWETrendData,
  type ChartPeriod
} from '@/lib/sqlite/use-dashboard-stats';
import { getCWEName } from '@/features/search/cwe-data';

const MONTH_NAMES: Record<string, Record<string, string>> = {
  'pt-BR': {
    '01': 'Jan',
    '02': 'Fev',
    '03': 'Mar',
    '04': 'Abr',
    '05': 'Mai',
    '06': 'Jun',
    '07': 'Jul',
    '08': 'Ago',
    '09': 'Set',
    '10': 'Out',
    '11': 'Nov',
    '12': 'Dez'
  },
  en: {
    '01': 'Jan',
    '02': 'Feb',
    '03': 'Mar',
    '04': 'Apr',
    '05': 'May',
    '06': 'Jun',
    '07': 'Jul',
    '08': 'Aug',
    '09': 'Sep',
    '10': 'Oct',
    '11': 'Nov',
    '12': 'Dec'
  }
};

// Common CWE names for display
const CWE_NAMES: Record<string, string> = {
  'CWE-74': 'Improper Neutralization ',
  'CWE-77': 'Command Injection',
  'CWE-79': 'XSS',
  'CWE-89': 'SQL Injection',
  'CWE-22': 'Path Trav',
  'CWE-20': 'Input Val',
  'CWE-78': 'OS Cmd',
  'CWE-94': 'Code Inj',
  'CWE-98': 'LFI',
  'CWE-119': 'Buffer OF',
  'CWE-125': 'OOB Read',
  'CWE-787': 'OOB Write',
  'CWE-416': 'Use Free',
  'CWE-476': 'NULL Ptr',
  'CWE-190': 'Int OF',
  'CWE-200': 'Info Exp',
  'CWE-269': 'Priv Mgmt',
  'CWE-284': 'Access Control',
  'CWE-287': 'Auth Byp',
  'CWE-352': 'CSRF',
  'CWE-400': 'Resource',
  'CWE-434': 'File Up',
  'CWE-502': 'Deserial',
  'CWE-601': 'Redirect',
  'CWE-611': 'XXE',
  'CWE-798': 'Hard Cred',
  'CWE-862': 'Miss Auth',
  'CWE-863': 'Inc Auth',
  'CWE-918': 'SSRF'
};

/**
 * Rótulo do gráfico: prefere o apelido curto (cabe no tooltip e na legenda);
 * se a CWE não tiver um, usa o nome do catálogo em cwe-data.ts em vez de
 * mostrar o número cru (era o caso da CWE-284, que aparecia só como "284").
 */
function cweLabel(cwe: string): string {
  return CWE_NAMES[cwe] ?? getCWEName(cwe);
}

// Colors for CWEs
const CWE_COLORS = [
  'hsl(0, 84%, 60%)', // Red
  'hsl(25, 95%, 53%)', // Orange
  'hsl(45, 93%, 47%)', // Yellow
  'hsl(142, 71%, 45%)', // Green
  'hsl(200, 80%, 50%)' // Blue
];

const PERIODS: { value: ChartPeriod; label: string }[] = [
  { value: '30d', label: '30d' },
  { value: '1y', label: '1y' },
  { value: '5y', label: '5y' }
];

export function AreaGraph() {
  const t = useTranslations('charts');
  const locale = useLocale();
  const { getCWETrend, isReady } = useDashboardStats();
  const [period, setPeriod] = useState<ChartPeriod>('30d');
  const [data, setData] = useState<CWETrendData[]>([]);
  const [cwes, setCwes] = useState<string[]>([]);

  const loadData = useCallback(() => {
    if (isReady) {
      const result = getCWETrend(period, 5);
      setData(result.data);
      setCwes(result.cwes);
    }
  }, [isReady, getCWETrend, period]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Build dynamic chart config based on CWEs
  const chartConfig: ChartConfig = cwes.reduce((config, cwe, index) => {
    config[cwe] = {
      label: cweLabel(cwe),
      color: CWE_COLORS[index % CWE_COLORS.length]
    };
    return config;
  }, {} as ChartConfig);

  const chartData = data.map((item) => {
    let displayLabel = item.label;

    // Format label based on period
    if (period === '1y') {
      displayLabel =
        MONTH_NAMES[locale]?.[item.label] ??
        MONTH_NAMES['en'][item.label] ??
        item.label;
    }

    return {
      ...item,
      label: displayLabel
    };
  });

  // Calculate totals per CWE
  const totals = cwes
    .map((cwe) => ({
      cwe,
      name: cweLabel(cwe),
      total: chartData.reduce(
        (acc, curr) =>
          acc + (Number((curr as Record<string, unknown>)[cwe]) || 0),
        0
      )
    }))
    .sort((a, b) => b.total - a.total);

  const topCWE = totals[0];

  return (
    <Card className='@container/card flex h-full flex-col'>
      <CardHeader className='flex flex-row items-center justify-between pb-2'>
        <div>
          <CardTitle>{t('cweTrend')}</CardTitle>
          <CardDescription className='mt-1'>
            {t('cweTrendDescription')}
          </CardDescription>
        </div>
        <div className='flex gap-1'>
          {PERIODS.map((p) => (
            <Button
              key={p.value}
              variant={period === p.value ? 'default' : 'ghost'}
              size='sm'
              className='h-7 px-2 text-xs'
              onClick={() => setPeriod(p.value)}
            >
              {p.label}
            </Button>
          ))}
        </div>
      </CardHeader>
      <CardContent className='flex flex-1 flex-col px-2 pt-4 sm:px-6 sm:pt-6'>
        <ChartContainer
          config={chartConfig}
          className='aspect-auto min-h-[250px] w-full flex-1'
        >
          <AreaChart
            data={chartData}
            margin={{
              left: 12,
              right: 12
            }}
          >
            <defs>
              {cwes.map((cwe, index) => (
                <linearGradient
                  key={cwe}
                  id={`fill${cwe.replace('-', '')}`}
                  x1='0'
                  y1='0'
                  x2='0'
                  y2='1'
                >
                  <stop
                    offset='5%'
                    stopColor={CWE_COLORS[index % CWE_COLORS.length]}
                    stopOpacity={0.8}
                  />
                  <stop
                    offset='95%'
                    stopColor={CWE_COLORS[index % CWE_COLORS.length]}
                    stopOpacity={0.1}
                  />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} />
            <XAxis
              dataKey='label'
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              minTickGap={32}
            />
            <YAxis
              tickLine={false}
              axisLine={false}
              tickMargin={8}
              width={50}
              tickFormatter={(value) => {
                if (value >= 1000) {
                  const k = value / 1000;
                  return k % 1 === 0 ? `${k}k` : `${k.toFixed(1)}k`;
                }
                return value;
              }}
            />
            <ChartTooltip
              cursor={false}
              content={<ChartTooltipContent indicator='dot' />}
            />
            {cwes.map((cwe, index) => (
              <Area
                key={cwe}
                dataKey={cwe}
                type='monotone'
                fill={`url(#fill${cwe.replace('-', '')})`}
                stroke={CWE_COLORS[index % CWE_COLORS.length]}
                stackId='a'
              />
            ))}
          </AreaChart>
        </ChartContainer>
      </CardContent>
      <CardFooter>
        <div className='flex w-full items-start gap-2 text-sm'>
          <div className='grid gap-2'>
            <div className='flex items-center gap-2 leading-none font-medium'>
              {topCWE &&
                t('topCWELeader', { cwe: topCWE.name, count: topCWE.total })}
              <IconShieldCheck className='text-primary h-4 w-4' />
            </div>
            <div className='text-muted-foreground flex items-center gap-2 leading-none'>
              {t('cweTrendFooter')}
            </div>
          </div>
        </div>
      </CardFooter>
    </Card>
  );
}
