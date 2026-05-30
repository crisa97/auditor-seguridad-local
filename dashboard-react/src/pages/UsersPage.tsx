import { useState, useEffect, useCallback } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { usersApi } from '@/api';
import { useApi } from '@/hooks';
import {
  Card,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableCell,
  Badge,
  Button,
  Modal,
  Input,
  Select,
  Loading,
  EmptyState,
} from '@/components/ui';
import {
  userCreateSchema,
  userUpdateSchema,
  resetPasswordSchema,
  type UserCreateFormData,
  type UserUpdateFormData,
  type ResetPasswordFormData,
} from '@/utils/validation';
import { formatDate } from '@/utils/helpers';
import type { User } from '@/types';
import toast from 'react-hot-toast';

export function UsersPage() {
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isEditOpen, setIsEditOpen] = useState(false);
  const [isResetOpen, setIsResetOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<User | null>(null);

  const fetchUsers = useCallback(() => usersApi.list(), []);

  const {
    data: users,
    isLoading,
    error,
    execute: refetchUsers,
  } = useApi({ fetchFn: fetchUsers, immediate: true });

  const {
    register: registerCreate,
    handleSubmit: handleSubmitCreate,
    reset: resetCreate,
    formState: { errors: errorsCreate },
  } = useForm<UserCreateFormData>({
    resolver: zodResolver(userCreateSchema),
    defaultValues: { rol: 'usuario' },
  });

  const {
    register: registerEdit,
    handleSubmit: handleSubmitEdit,
    reset: resetEdit,
    setValue: setValueEdit,
    formState: { errors: errorsEdit },
  } = useForm<UserUpdateFormData>({
    resolver: zodResolver(userUpdateSchema),
  });

  const {
    register: registerReset,
    handleSubmit: handleSubmitReset,
    reset: resetReset,
    formState: { errors: errorsReset },
  } = useForm<ResetPasswordFormData>({
    resolver: zodResolver(resetPasswordSchema),
  });

  useEffect(() => {
    if (selectedUser && isEditOpen) {
      setValueEdit('email', selectedUser.email);
      setValueEdit('nombre', selectedUser.nombre);
      setValueEdit('rol', selectedUser.rol);
      setValueEdit('activo', selectedUser.activo);
    }
  }, [selectedUser, isEditOpen, setValueEdit]);

  const onCreateSubmit = async (data: UserCreateFormData) => {
    try {
      await usersApi.create({
        email: data.email,
        password: data.password,
        nombre: data.nombre,
        rol: data.rol,
      });
      toast.success('Usuario creado exitosamente');
      resetCreate();
      setIsCreateOpen(false);
      refetchUsers();
    } catch {
      toast.error('Error al crear usuario');
    }
  };

  const onEditSubmit = async (data: UserUpdateFormData) => {
    if (!selectedUser) return;
    try {
      await usersApi.update(selectedUser.id, data);
      toast.success('Usuario actualizado exitosamente');
      resetEdit();
      setIsEditOpen(false);
      setSelectedUser(null);
      refetchUsers();
    } catch {
      toast.error('Error al actualizar usuario');
    }
  };

  const onResetSubmit = async (data: ResetPasswordFormData) => {
    if (!selectedUser) return;
    try {
      await usersApi.resetPassword(selectedUser.id, data.new_password);
      toast.success('Contraseña restablecida exitosamente');
      resetReset();
      setIsResetOpen(false);
      setSelectedUser(null);
    } catch {
      toast.error('Error al restablecer contraseña');
    }
  };

  const handleDeactivate = async (user: User) => {
    if (
      !confirm(
        `¿Estás seguro de desactivar al usuario ${user.nombre}?`
      )
    )
      return;
    try {
      await usersApi.deactivate(user.id);
      toast.success('Usuario desactivado exitosamente');
      refetchUsers();
    } catch {
      toast.error('Error al desactivar usuario');
    }
  };

  const handleToggleActive = async (user: User) => {
    try {
      await usersApi.toggleActive(user.id, !user.activo);
      toast.success(
        `Usuario ${user.activo ? 'desactivado' : 'activado'} exitosamente`
      );
      refetchUsers();
    } catch {
      toast.error('Error al cambiar estado del usuario');
    }
  };

  const openEdit = (user: User) => {
    setSelectedUser(user);
    setIsEditOpen(true);
  };

  const openReset = (user: User) => {
    setSelectedUser(user);
    setIsResetOpen(true);
  };

  return (
    <div className="users-page">
      <div className="page-header">
        <h1 className="page-title">Gestión de Usuarios</h1>
        <p className="page-subtitle">Administrar cuentas de usuario y roles</p>
      </div>

      <Card
        title="Usuarios del Sistema"
        actions={
          <Button onClick={() => setIsCreateOpen(true)}>Nuevo Usuario</Button>
        }
      >
        {isLoading && (!users || users.length === 0) ? (
          <Loading message="Cargando usuarios..." />
        ) : error ? (
          <EmptyState title="Error" description={error} />
        ) : !users || users.length === 0 ? (
          <EmptyState
            title="Sin usuarios"
            description="Crea el primer usuario del sistema"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableCell>Nombre</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Rol</TableCell>
                <TableCell>Estado</TableCell>
                <TableCell>Creado</TableCell>
                <TableCell>Último Login</TableCell>
                <TableCell>Acciones</TableCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>{user.nombre}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    <Badge
                      variant={user.rol === 'admin' ? 'info' : 'default'}
                    >
                      {user.rol}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={user.activo ? 'success' : 'danger'}>
                      {user.activo ? 'Activo' : 'Inactivo'}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatDate(user.creado_en)}</TableCell>
                  <TableCell>
                    {user.ultimo_login
                      ? formatDate(user.ultimo_login)
                      : 'Nunca'}
                  </TableCell>
                  <TableCell>
                    <div className="action-buttons">
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => openEdit(user)}
                      >
                        Editar
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => openReset(user)}
                      >
                        Reset Password
                      </Button>
                      <Button
                        size="sm"
                        variant={user.activo ? 'danger' : 'secondary'}
                        onClick={() => handleToggleActive(user)}
                      >
                        {user.activo ? 'Desactivar' : 'Activar'}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {/* Create User Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Crear Usuario"
      >
        <form
          onSubmit={handleSubmitCreate(onCreateSubmit)}
          className="modal-form"
        >
          <Input
            label="Nombre"
            placeholder="Juan Pérez"
            error={errorsCreate.nombre?.message}
            {...registerCreate('nombre')}
          />
          <Input
            label="Email"
            type="email"
            placeholder="juan@email.com"
            error={errorsCreate.email?.message}
            {...registerCreate('email')}
          />
          <Input
            label="Contraseña"
            type="password"
            placeholder="••••••••"
            error={errorsCreate.password?.message}
            {...registerCreate('password')}
          />
          <Select
            label="Rol"
            options={[
              { value: 'usuario', label: 'Usuario' },
              { value: 'admin', label: 'Administrador' },
            ]}
            error={errorsCreate.rol?.message}
            {...registerCreate('rol')}
          />
          <div className="modal-actions">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsCreateOpen(false)}
            >
              Cancelar
            </Button>
            <Button type="submit" isLoading={isLoading}>
              Crear Usuario
            </Button>
          </div>
        </form>
      </Modal>

      {/* Edit User Modal */}
      <Modal
        isOpen={isEditOpen}
        onClose={() => {
          setIsEditOpen(false);
          setSelectedUser(null);
          resetEdit();
        }}
        title="Editar Usuario"
      >
        <form
          onSubmit={handleSubmitEdit(onEditSubmit)}
          className="modal-form"
        >
          <Input
            label="Nombre"
            error={errorsEdit.nombre?.message}
            {...registerEdit('nombre')}
          />
          <Input
            label="Email"
            type="email"
            error={errorsEdit.email?.message}
            {...registerEdit('email')}
          />
          <Select
            label="Rol"
            options={[
              { value: 'usuario', label: 'Usuario' },
              { value: 'admin', label: 'Administrador' },
            ]}
            error={errorsEdit.rol?.message}
            {...registerEdit('rol')}
          />
          <div className="form-group">
            <label className="form-label">
              <input
                type="checkbox"
                className="form-checkbox"
                {...registerEdit('activo')}
              />
              {' '}Activo
            </label>
          </div>
          <div className="modal-actions">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsEditOpen(false)}
            >
              Cancelar
            </Button>
            <Button type="submit" isLoading={isLoading}>
              Guardar Cambios
            </Button>
          </div>
        </form>
      </Modal>

      {/* Reset Password Modal */}
      <Modal
        isOpen={isResetOpen}
        onClose={() => {
          setIsResetOpen(false);
          setSelectedUser(null);
          resetReset();
        }}
        title={`Restablecer Contraseña - ${selectedUser?.nombre}`}
      >
        <form
          onSubmit={handleSubmitReset(onResetSubmit)}
          className="modal-form"
        >
          <Input
            label="Nueva Contraseña"
            type="password"
            placeholder="••••••••"
            error={errorsReset.new_password?.message}
            {...registerReset('new_password')}
          />
          <Input
            label="Confirmar Contraseña"
            type="password"
            placeholder="••••••••"
            error={errorsReset.confirmPassword?.message}
            {...registerReset('confirmPassword')}
          />
          <div className="modal-actions">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsResetOpen(false)}
            >
              Cancelar
            </Button>
            <Button type="submit" isLoading={isLoading}>
              Restablecer
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
