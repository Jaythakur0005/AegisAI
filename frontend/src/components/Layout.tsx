import type { ReactNode } from "react";
import Sidebar from "./Sidebar";

interface LayoutProps {
  activePage: string;
  onNavigate: (key: string) => void;
  pageTitle: string;
  pageSubtitle?: string;
  children: ReactNode;
}

export default function Layout({
  activePage,
  onNavigate,
  pageTitle,
  pageSubtitle,
  children,
}: LayoutProps) {
  return (
    <div className="app-shell">
      <Sidebar activePage={activePage} onNavigate={onNavigate} />

      <div className="main-content">
        <header className="topbar">
          <span className="topbar-title">{pageTitle}</span>
          {pageSubtitle && (
            <span className="topbar-sub">— {pageSubtitle}</span>
          )}
        </header>

        <main className="page-area">
          {children}
        </main>
      </div>
    </div>
  );
}
