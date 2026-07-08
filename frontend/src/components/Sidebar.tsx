import {
  Activity,
  LayoutDashboard,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

interface NavItem {
  label: string;
  icon: LucideIcon;
  key: string;
}

const NAV_ITEMS: NavItem[] = [
  {
    label: "Dashboard",
    icon: LayoutDashboard,
    key: "dashboard",
  },
  {
    label: "Incidents",
    icon: ShieldAlert,
    key: "incidents",
  },
  {
    label: "Pipeline",
    icon: Activity,
    key: "pipeline",
  },
];

interface SidebarProps {
  activePage: string;
  onNavigate: (key: string) => void;
}

export default function Sidebar({
  activePage,
  onNavigate,
}: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-mark" aria-hidden="true">
          <ShieldAlert size={21} strokeWidth={2.2} />
        </div>

        <div className="brand-copy">
          <h1>AegisAI</h1>
          <span>SOC Investigation Platform</span>
        </div>
      </div>

      <div className="sidebar-section-label">
        Workspace
      </div>

      <nav className="sidebar-nav" aria-label="Primary navigation">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;

          return (
            <button
              key={item.key}
              type="button"
              className={`nav-item${
                activePage === item.key ? " active" : ""
              }`}
              onClick={() => onNavigate(item.key)}
              aria-current={
                activePage === item.key ? "page" : undefined
              }
            >
              <span className="nav-icon" aria-hidden="true">
                <Icon size={18} strokeWidth={1.9} />
              </span>

              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <span className="system-status-dot" />
        <div>
          <strong>Detection Engine</strong>
          <span>Operational</span>
        </div>
      </div>
    </aside>
  );
}
