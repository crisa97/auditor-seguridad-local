import { NavLink } from 'react-router-dom';
import { useAuthContext } from '@/context/AuthContext';

interface NavItem {
  to: string;
  label: string;
  icon: string;
  adminOnly?: boolean;
}

const navItems: NavItem[] = [
  { to: '/dashboard', label: 'Panel Principal', icon: '📊' },
  { to: '/dashboard/analysis', label: 'Análisis', icon: '🔍' },
  { to: '/dashboard/vulnerabilities', label: 'Vulnerabilidades', icon: '⚠️', adminOnly: true },
  { to: '/dashboard/api-keys', label: 'API Keys', icon: '🔑' },
  { to: '/dashboard/admin/users', label: 'Usuarios', icon: '👥', adminOnly: true },
];

export function Sidebar() {
  const { isAdmin } = useAuthContext();

  const filteredItems = navItems.filter(
    (item) => !item.adminOnly || isAdmin
  );

  return (
    <aside className="sidebar">
      <nav className="sidebar-nav">
        {filteredItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/dashboard'}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`
            }
          >
            <span className="sidebar-icon">{item.icon}</span>
            <span className="sidebar-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
