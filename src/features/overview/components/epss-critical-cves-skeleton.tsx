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
        <div className='space-y-1'>
          {[...Array(6)].map((_, index) => (
            <div key={index} className='flex items-center gap-3 px-2 py-2'>
              <Skeleton className='h-4 w-[130px] shrink-0' />
              <Skeleton className='h-5 w-10 shrink-0 rounded-full' />
              <Skeleton className='h-5 w-[86px] shrink-0' />
              <Skeleton className='h-5 w-14 shrink-0' />
              <Skeleton className='h-3 flex-1' />
              <Skeleton className='hidden h-3 w-24 shrink-0 sm:block' />
            </div>
          ))}
        </div>
        <Skeleton className='mt-3 h-4 w-40' />
      </CardContent>
    </Card>
  );
}
