import { api } from './client';
import type {
  ApiKeyItem,
  ApiKeyCreateRequest,
  ApiKeyCreateResponse,
} from '@/types';

interface ApiKeysParams {
  limit?: number;
  offset?: number;
}

export const apiKeysApi = {
  async list(params: ApiKeysParams = {}): Promise<ApiKeyItem[]> {
    const response = await api.get<ApiKeyItem[]>('/apikeys', {
      params: { limit: 50, ...params },
    });
    return response.data;
  },

  async create(data: ApiKeyCreateRequest): Promise<ApiKeyCreateResponse> {
    const response = await api.post<ApiKeyCreateResponse>('/apikeys', data);
    return response.data;
  },

  async deactivate(id: number): Promise<{ message: string }> {
    const response = await api.delete<{ message: string }>(`/apikeys/${id}`);
    return response.data;
  },

  async toggleActive(
    id: number,
    activa: boolean
  ): Promise<{ message: string; api_key: ApiKeyItem }> {
    const response = await api.put<{ message: string; api_key: ApiKeyItem }>(
      `/apikeys/${id}/toggle`,
      { activa }
    );
    return response.data;
  },
};
