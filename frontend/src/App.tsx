import {
  BrowserRouter,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import Layout from "./components/Layout";
import DashboardPage from "./pages/DashboardPage";
import IncidentDetailPage from "./pages/IncidentDetailPage";
import "./App.css";

function AppShell() {
  const navigate = useNavigate();
  const location = useLocation();

  const isIncidentDetail = location.pathname.startsWith("/incidents/");

  const activePage = isIncidentDetail ? "incidents" : "dashboard";

  const pageTitle = isIncidentDetail ? "Incident Detail" : "Dashboard";

  const pageSubtitle = isIncidentDetail
    ? "Threat investigation and risk analysis"
    : "Incident overview";

  function handleNavigate(key: string): void {
    if (key === "dashboard") {
      navigate("/");
      return;
    }

    if (key === "incidents") {
      navigate("/");
    }
  }

  return (
    <Layout
      activePage={activePage}
      onNavigate={handleNavigate}
      pageTitle={pageTitle}
      pageSubtitle={pageSubtitle}
    >
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route
          path="/incidents/:incidentId"
          element={<IncidentDetailPage />}
        />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}

export default App;
