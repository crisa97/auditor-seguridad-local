import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import type { TokenResponse } from '@/types';

const API_URL = import.meta.env.VITE_API_URL || '/api/v2';

interface StoredTokens {
  access_token: string;
  refresh_token: string;
}

function getStoredTokens(): StoredTokens | null {
  try {
    const access = sessionStorage.getItem('access_token');
    const refresh = sessionStorage.getItem('refresh_token');
    if (access && refresh) {
      return { access_token: access, refresh_token: refresh };
    }
    return null;
  } catch {
    return null;
  }
}

function storeTokens(data: TokenResponse): void {
  sessionStorage.setItem('access_token', data.access_token);
  sessionStorage.setItem('refresh_token', data.refresh_token);
  sessionStorage.setItem('user', JSON.stringify(data.user));
}

function clearAuth(): void {
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('refresh_token');
  sessionStorage.removeItem('user');
}

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
}> = [];

function processQueue(error: unknown, token: string | null): void {
  failedQueue.forEach((prom) => {
    if (error || !token) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
}

const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const tokens = getStoredTokens();
    if (tokens?.access_token && config.headers) {
      config.headers.Authorization = `Bearer ${tokens.access_token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean;
    };

    if (error.response?.status === 401 && !originalRequest._retry) {
      const tokens = getStoredTokens();
      if (!tokens?.refresh_token) {
        clearAuth();
        window.location.href = '/dashboard/login';
        return Promise.reject(error);
      }

      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then((token) => {
            if (originalRequest.headers) {
              originalRequest.headers.Authorization = `Bearer ${token}`;
            }
            return api(originalRequest);
          })
          .catch((err) => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await axios.post<TokenResponse>(
          `${API_URL}/auth/refresh`,
          { refresh_token: tokens.refresh_token }
        );
        storeTokens(data);
        processQueue(null, data.access_token);
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
        }
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        clearAuth();
        window.location.href = '/dashboard/login';
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export { api, storeTokens, clearAuth, getStoredTokens };
export default api;
