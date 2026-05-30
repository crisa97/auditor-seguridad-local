import { api } from './client';
import type { User, UserCreate, UserUpdate } from '@/types';

interface UsersParams {
  limit?: number;
  offset?: number;
  rol?: string;
}

export const usersApi = {
  async list(params: UsersParams = {}): Promise<User[]> {
    const response = await api.get<User[]>('/users', {
      params: { limit: 50, ...params },
    });
    return response.data;
  },

  async getById(id: number): Promise<User> {
    const response = await api.get<User>(`/users/${id}`);
    return response.data;
  },

  async create(data: UserCreate): Promise<{ message: string; user: User }> {
    const response = await api.post<{ message: string; user: User }>(
      '/users',
      data
    );
    return response.data;
  },

  async update(
    id: number,
    data: UserUpdate
  ): Promise<{ message: string; user: User }> {
    const response = await api.put<{ message: string; user: User }>(
      `/users/${id}`,
      data
    );
    return response.data;
  },

  async deactivate(id: number): Promise<{ message: string }> {
    const response = await api.delete<{ message: string }>(`/users/${id}`);
    return response.data;
  },

  async resetPassword(
    id: number,
    newPassword: string
  ): Promise<{ message: string }> {
    const response = await api.post<{ message: string }>(
      `/users/${id}/reset-password`,
      { new_password: newPassword }
    );
    return response.data;
  },

  async toggleActive(
    id: number,
    activo: boolean
  ): Promise<{ message: string; user: User }> {
    const response = await api.put<{ message: string; user: User }>(
      `/users/${id}`,
      { activo }
    );
    return response.data;
  },
};
