import { api, storeTokens, clearAuth } from './client';
import type {
  LoginRequest,
  TokenResponse,
  RegisterRequest,
  RegisterResponse,
  User,
} from '@/types';

export const authApi = {
  async login(data: LoginRequest): Promise<TokenResponse> {
    const response = await api.post<TokenResponse>('/auth/login', data);
    storeTokens(response.data);
    return response.data;
  },

  async register(data: RegisterRequest): Promise<RegisterResponse> {
    const response = await api.post<RegisterResponse>('/auth/register', data);
    return response.data;
  },

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const response = await api.post<TokenResponse>('/auth/refresh', {
      refresh_token: refreshToken,
    });
    storeTokens(response.data);
    return response.data;
  },

  logout(): void {
    clearAuth();
    window.location.href = '/dashboard/login';
  },

  getStoredUser(): User | null {
    try {
      const raw = sessionStorage.getItem('user');
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },

  isAuthenticated(): boolean {
    return !!sessionStorage.getItem('access_token');
  },

  async getProfile(): Promise<User> {
    const response = await api.get<User>('/users/me');
    return response.data;
  },

  async updateProfile(data: { nombre?: string; email?: string }): Promise<User> {
    const response = await api.put<User>('/users/me', data);
    return response.data;
  },

  async changePassword(data: {
    current_password: string;
    new_password: string;
  }): Promise<{ message: string }> {
    const response = await api.post<{ message: string }>(
      '/users/me/change-password',
      data
    );
    return response.data;
  },
};
