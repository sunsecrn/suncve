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
            {children}
            {/* page main content ends */}
            <Footer />
          </SidebarInset>
        </TourProvider>
      </SidebarProvider>
    </KBar>
  );
}
