import { useState } from 'react';
import { Navigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useAuthContext } from '@/context/AuthContext';
import { loginSchema, type LoginFormData } from '@/utils/validation';
import { Button, Input } from '@/components/ui';

export function LoginPage() {
  const { login, isAuthenticated, isLoading } = useAuthContext();
  const [serverError, setServerError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const onSubmit = async (data: LoginFormData) => {
    setServerError(null);
    try {
      await login(data.email, data.password);
    } catch {
      setServerError('Credenciales inválidas. Intenta de nuevo.');
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <span className="login-logo">🛡️</span>
          <h1>Auditor de Seguridad</h1>
          <p>Inicia sesión para acceder al panel</p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="login-form" noValidate>
          {serverError && (
            <div className="alert alert-error" role="alert">
              {serverError}
            </div>
          )}

          <Input
            label="Email"
            type="email"
            placeholder="tu@email.com"
            autoComplete="email"
            error={errors.email?.message}
            {...register('email')}
          />

          <Input
            label="Contraseña"
            type="password"
            placeholder="••••••••"
            autoComplete="current-password"
            error={errors.password?.message}
            {...register('password')}
          />

          <Button
            type="submit"
            isLoading={isLoading}
            className="login-button"
          >
            Iniciar Sesión
          </Button>
        </form>
      </div>
    </div>
  );
}
