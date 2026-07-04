interface NavItem {
  label: string;
  icon: string;
  key: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Dashboard", icon: "⬛", key: "dashboard" },
  { label: "Incidents", icon: "🛡", key: "incidents" },
];

interface SidebarProps {
  activePage: string;
  onNavigate: (key: string) => void;
}

export default function Sidebar({ activePage, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h1>AegisAI</h1>
        <span>SOC Investigation Platform</span>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.key}
            className={`nav-item${activePage === item.key ? " active" : ""}`}
            onClick={() => onNavigate(item.key)}
          >
            <span className="nav-icon">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>
    </aside>
  );
}
