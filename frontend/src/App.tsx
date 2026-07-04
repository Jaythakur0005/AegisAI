import { useState } from "react";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import "./App.css";

type Page = "dashboard" | "incidents";

const PAGE_META: Record<Page, { title: string; subtitle: string }> = {
  dashboard: {
    title: "Dashboard",
    subtitle: "Incident overview",
  },
  incidents: {
    title: "Incidents",
    subtitle: "All detected incidents",
  },
};

export default function App() {
  const [activePage, setActivePage] = useState<Page>("dashboard");

  function handleNavigate(key: string) {
    if (key === "dashboard" || key === "incidents") {
      setActivePage(key);
    }
  }

  const meta = PAGE_META[activePage];

  function renderPage() {
    switch (activePage) {
      case "dashboard":
      case "incidents":
        return <DashboardPage />;
    }
  }

  return (
    <Layout
      activePage={activePage}
      onNavigate={handleNavigate}
      pageTitle={meta.title}
      pageSubtitle={meta.subtitle}
    >
      {renderPage()}
    </Layout>
  );
}
