import { z } from 'zod';

export const loginSchema = z.object({
  email: z
    .string()
    .min(1, 'El email es requerido')
    .email('Email inválido')
    .max(255, 'Email demasiado largo'),
  password: z
    .string()
    .min(1, 'La contraseña es requerida')
    .min(8, 'Mínimo 8 caracteres')
    .max(128, 'Máximo 128 caracteres'),
});

export const registerSchema = z
  .object({
    email: z
      .string()
      .min(1, 'El email es requerido')
      .email('Email inválido')
      .max(255, 'Email demasiado largo'),
    nombre: z
      .string()
      .min(1, 'El nombre es requerido')
      .max(255, 'Nombre demasiado largo'),
    password: z
      .string()
      .min(1, 'La contraseña es requerida')
      .min(8, 'Mínimo 8 caracteres')
      .max(128, 'Máximo 128 caracteres'),
    confirmPassword: z.string().min(1, 'Confirma la contraseña'),
    rol: z.enum(['admin', 'usuario'], {
      errorMap: () => ({ message: 'Rol inválido' }),
    }),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Las contraseñas no coinciden',
    path: ['confirmPassword'],
  });

export const userCreateSchema = z.object({
  email: z
    .string()
    .min(1, 'El email es requerido')
    .email('Email inválido')
    .max(255),
  nombre: z.string().min(1, 'El nombre es requerido').max(255),
  password: z
    .string()
    .min(1, 'La contraseña es requerida')
    .min(8, 'Mínimo 8 caracteres')
    .max(128),
  rol: z.enum(['admin', 'usuario']),
});

export const userUpdateSchema = z.object({
  email: z.string().email('Email inválido').max(255).optional(),
  nombre: z.string().min(1, 'El nombre es requerido').max(255).optional(),
  rol: z.enum(['admin', 'usuario']).optional(),
  activo: z.boolean().optional(),
});

export const apiKeyCreateSchema = z.object({
  nombre_cliente: z
    .string()
    .min(1, 'El nombre es requerido')
    .max(255, 'Nombre demasiado largo'),
  permisos: z
    .string()
    .min(1, 'Los permisos son requeridos')
    .max(100, 'Permisos demasiado largos'),
  dias_validez: z
    .number()
    .int()
    .positive('Debe ser un número positivo')
    .max(365, 'Máximo 365 días')
    .optional(),
});

export const resetPasswordSchema = z
  .object({
    new_password: z
      .string()
      .min(1, 'La contraseña es requerida')
      .min(8, 'Mínimo 8 caracteres')
      .max(128),
    confirmPassword: z.string().min(1, 'Confirma la contraseña'),
  })
  .refine((data) => data.new_password === data.confirmPassword, {
    message: 'Las contraseñas no coinciden',
    path: ['confirmPassword'],
  });

export const changePasswordSchema = z
  .object({
    current_password: z.string().min(1, 'La contraseña actual es requerida'),
    new_password: z
      .string()
      .min(1, 'La contraseña es requerida')
      .min(8, 'Mínimo 8 caracteres')
      .max(128),
    confirmPassword: z.string().min(1, 'Confirma la contraseña'),
  })
  .refine((data) => data.new_password === data.confirmPassword, {
    message: 'Las contraseñas no coinciden',
    path: ['confirmPassword'],
  });

export type LoginFormData = z.infer<typeof loginSchema>;
export type RegisterFormData = z.infer<typeof registerSchema>;
export type UserCreateFormData = z.infer<typeof userCreateSchema>;
export type UserUpdateFormData = z.infer<typeof userUpdateSchema>;
export type ApiKeyCreateFormData = z.infer<typeof apiKeyCreateSchema>;
export type ResetPasswordFormData = z.infer<typeof resetPasswordSchema>;
export type ChangePasswordFormData = z.infer<typeof changePasswordSchema>;
