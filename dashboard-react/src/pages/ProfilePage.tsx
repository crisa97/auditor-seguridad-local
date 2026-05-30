import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { authApi } from '@/api';
import { useAuthContext } from '@/context/AuthContext';
import { Card, Button, Input } from '@/components/ui';
import {
  changePasswordSchema,
  type ChangePasswordFormData,
} from '@/utils/validation';
import toast from 'react-hot-toast';

export function ProfilePage() {
  const { user, refreshUser } = useAuthContext();
  const [isEditing, setIsEditing] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ChangePasswordFormData>({
    resolver: zodResolver(changePasswordSchema),
  });

  const {
    register: registerProfile,
    handleSubmit: handleSubmitProfile,
    formState: { errors: profileErrors },
  } = useForm({
    defaultValues: {
      nombre: user?.nombre || '',
      email: user?.email || '',
    },
  });

  const onPasswordSubmit = async (data: ChangePasswordFormData) => {
    try {
      await authApi.changePassword({
        current_password: data.current_password,
        new_password: data.new_password,
      });
      toast.success('Contraseña cambiada exitosamente');
      reset();
    } catch {
      toast.error('Error al cambiar contraseña. Verifica tu contraseña actual.');
    }
  };

  const onProfileSubmit = async (data: { nombre: string; email: string }) => {
    try {
      await authApi.updateProfile(data);
      refreshUser();
      setIsEditing(false);
      toast.success('Perfil actualizado exitosamente');
    } catch {
      toast.error('Error al actualizar perfil');
    }
  };

  return (
    <div className="profile-page">
      <div className="page-header">
        <h1 className="page-title">Mi Perfil</h1>
        <p className="page-subtitle">Gestiona tu información personal</p>
      </div>

      <div className="profile-grid">
        <Card title="Información Personal">
          <form
            onSubmit={handleSubmitProfile(onProfileSubmit)}
            className="profile-form"
          >
            <Input
              label="Nombre"
              disabled={!isEditing}
              error={profileErrors.nombre?.message}
              {...registerProfile('nombre')}
            />
            <Input
              label="Email"
              type="email"
              disabled={!isEditing}
              error={profileErrors.email?.message}
              {...registerProfile('email')}
            />
            <div className="form-group">
              <label className="form-label">Rol</label>
              <input
                type="text"
                className="form-input"
                value={user?.rol || ''}
                disabled
              />
            </div>
            <div className="form-actions">
              {isEditing ? (
                <>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => setIsEditing(false)}
                  >
                    Cancelar
                  </Button>
                  <Button type="submit">Guardar</Button>
                </>
              ) : (
                <Button
                  type="button"
                  onClick={() => setIsEditing(true)}
                >
                  Editar Perfil
                </Button>
              )}
            </div>
          </form>
        </Card>

        <Card title="Cambiar Contraseña">
          <form
            onSubmit={handleSubmit(onPasswordSubmit)}
            className="profile-form"
          >
            <Input
              label="Contraseña Actual"
              type="password"
              placeholder="••••••••"
              error={errors.current_password?.message}
              {...register('current_password')}
            />
            <Input
              label="Nueva Contraseña"
              type="password"
              placeholder="••••••••"
              error={errors.new_password?.message}
              {...register('new_password')}
            />
            <Input
              label="Confirmar Nueva Contraseña"
              type="password"
              placeholder="••••••••"
              error={errors.confirmPassword?.message}
              {...register('confirmPassword')}
            />
            <div className="form-actions">
              <Button type="submit">Cambiar Contraseña</Button>
            </div>
          </form>
        </Card>
      </div>
    </div>
  );
}
