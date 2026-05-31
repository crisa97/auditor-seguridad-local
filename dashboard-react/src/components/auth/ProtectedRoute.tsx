import { Navigate, useLocation } from 'react-router-dom';
import { useAuthContext } from '@/context/AuthContext';
import { Loading } from '@/components/ui';
import type { User } from '@/types';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRoles?: User['rol'][];
}

export function ProtectedRoute({
  children,
  requiredRoles,
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuthContext();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="auth-loading">
        <Loading size="lg" message="Verificando autenticación..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/dashboard/login" state={{ from: location }} replace />;
  }

  if (requiredRoles && user && !requiredRoles.includes(user.rol)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
}
