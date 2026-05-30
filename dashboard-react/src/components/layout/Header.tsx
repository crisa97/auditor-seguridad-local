import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuthContext } from '@/context/AuthContext';

export function Header() {
  const { user, logout, isAdmin } = useAuthContext();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <header className="app-header">
      <div className="header-left">
        <Link to="/dashboard" className="header-logo">
          <span className="logo-icon">🛡️</span>
          <span className="logo-text">Auditor Seguridad</span>
        </Link>
      </div>

      <div className="header-right">
        <div className="user-info">
          <span className="user-name">{user?.nombre}</span>
          <span className={`rol-badge ${user?.rol}`}>{user?.rol}</span>
        </div>

        <div className="menu-container">
          <button
            className="menu-toggle"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label="Menú de usuario"
            type="button"
          >
            <span className="menu-avatar">
              {user?.nombre?.charAt(0).toUpperCase()}
            </span>
          </button>

          {menuOpen && (
            <div className="dropdown-menu">
              <div className="dropdown-header">
                <strong>{user?.nombre}</strong>
                <span className="text-muted">{user?.email}</span>
              </div>
              <div className="dropdown-divider" />
              <Link
                to="/dashboard/profile"
                className="dropdown-item"
                onClick={() => setMenuOpen(false)}
              >
                Mi Perfil
              </Link>
              {isAdmin && (
                <Link
                  to="/dashboard/admin/users"
                  className="dropdown-item"
                  onClick={() => setMenuOpen(false)}
                >
                  Gestión de Usuarios
                </Link>
              )}
              <div className="dropdown-divider" />
              <button
                className="dropdown-item dropdown-item-danger"
                onClick={() => {
                  setMenuOpen(false);
                  logout();
                }}
                type="button"
              >
                Cerrar Sesión
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
