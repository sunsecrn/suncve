import KBar from '@/components/kbar';
import AppSidebar from '@/components/layout/app-sidebar';
import Header from '@/components/layout/header';
import Footer from '@/components/layout/footer';
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar';
import { TourProvider } from '@/components/tour/tour-provider';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'SunCVE Dashboard',
  description: 'SunCVE Dashboard'
};

export default function DashboardLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <KBar>
      <SidebarProvider defaultOpen={true}>
        <TourProvider>
          <AppSidebar />
          <SidebarInset>
            <Header />
            {/* page main content */}
            {/* Área de conteúdo. NUNCA usar flex-1 aqui: flex-basis:0 + min-h
                explícito anula o min-height:auto do flex item, o conteúdo alto
                vaza da caixa e o rodapé (irmão no flex) cai no meio dele — ver
                455e6a7 / 0965a04 / b436f8e. basis auto + shrink-0 => a caixa
                cresce com o conteúdo; min-h => piso de uma tela cheia, então o
                rodapé só aparece ao rolar. */}
            <div className='flex min-h-[calc(100svh-4rem)] shrink-0 flex-col group-has-data-[collapsible=icon]/sidebar-wrapper:min-h-[calc(100svh-3rem)]'>
              {children}
            </div>
            {/* page main content ends */}
            <Footer />
          </SidebarInset>
        </TourProvider>
      </SidebarProvider>
    </KBar>
  );
}
