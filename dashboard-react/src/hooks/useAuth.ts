import { useState, useCallback } from 'react';
import { authApi } from '@/api';
import type { User } from '@/types';

interface UseAuthReturn {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasRole: (role: User['rol']) => boolean;
  isAdmin: boolean;
}

export function useAuth(): UseAuthReturn {
  const [user, setUser] = useState<User | null>(() => authApi.getStoredUser());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await authApi.login({ email, password });
      setUser(data.user);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Error al iniciar sesión';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    authApi.logout();
    setUser(null);
  }, []);

  const hasRole = useCallback(
    (role: User['rol']): boolean => {
      return user?.rol === role;
    },
    [user]
  );

  return {
    user,
    isAuthenticated: !!user,
    isLoading,
    error,
    login,
    logout,
    hasRole,
    isAdmin: user?.rol === 'admin',
  };
}
