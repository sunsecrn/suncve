'use client';

import { Skeleton } from '@/components/ui/skeleton';
import {
  Card,
  CardHeader,
  CardContent,
  CardTitle,
  CardDescription
} from '@/components/ui/card';

export function EpssCriticalCVEsSkeleton() {
  return (
    <Card className='h-full'>
      <CardHeader>
        <CardTitle>
          <Skeleton className='h-5 w-64' />
        </CardTitle>
        <CardDescription>
          <Skeleton className='h-4 w-80' />
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className='divide-border grid grid-cols-1 divide-y lg:grid-cols-3 lg:divide-x lg:divide-y-0'>
          {[...Array(3)].map((_, column) => (
            <div
              key={column}
              className='space-y-4 py-4 first:pt-0 last:pb-0 lg:px-6 lg:py-0 lg:first:pl-0 lg:last:pr-0'
            >
              {[...Array(5)].map((_, row) => (
                <div key={row} className='flex items-start gap-3 py-2'>
                  <Skeleton className='h-9 w-9 shrink-0 rounded-full' />
                  <div className='flex-1 space-y-2'>
                    <div className='flex items-center gap-2'>
                      <Skeleton className='h-4 w-28' />
                      <Skeleton className='h-5 w-10' />
                    </div>
                    <Skeleton className='h-3 w-full' />
                  </div>
                  <Skeleton className='h-3 w-12' />
                </div>
              ))}
            </div>
          ))}
        </div>
        <Skeleton className='mt-4 h-4 w-40' />
      </CardContent>
    </Card>
  );
}
