import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from 'react';
import { authApi } from '@/api';
import type { User, TokenResponse } from '@/types';
import toast from 'react-hot-toast';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (role: User['rol']) => boolean;
  isAdmin: boolean;
  refreshUser: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => authApi.getStoredUser());
  const [isLoading, setIsLoading] = useState(false);

  const refreshUser = useCallback(() => {
    const stored = authApi.getStoredUser();
    setUser(stored);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const data: TokenResponse = await authApi.login({ email, password });
      setUser(data.user);
      toast.success(`Bienvenido, ${data.user.nombre}`);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Credenciales inválidas';
      toast.error(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    authApi.logout();
    setUser(null);
    toast.success('Sesión cerrada');
  }, []);

  const hasRole = useCallback(
    (role: User['rol']): boolean => user?.rol === role,
    [user]
  );

  useEffect(() => {
    const handleStorage = () => {
      refreshUser();
    };
    window.addEventListener('storage', handleStorage);
    return () => window.removeEventListener('storage', handleStorage);
  }, [refreshUser]);

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    hasRole,
    isAdmin: user?.rol === 'admin',
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuthContext debe usarse dentro de AuthProvider');
  }
  return context;
}
