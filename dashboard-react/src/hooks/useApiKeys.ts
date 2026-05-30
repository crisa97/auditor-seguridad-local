import { useState, useCallback } from 'react';
import { apiKeysApi } from '@/api';
import type { ApiKeyItem, ApiKeyCreateRequest, ApiKeyCreateResponse } from '@/types';

interface UseApiKeysReturn {
  apiKeys: ApiKeyItem[];
  isLoading: boolean;
  error: string | null;
  lastCreatedKey: ApiKeyCreateResponse | null;
  fetchApiKeys: () => Promise<void>;
  createApiKey: (data: ApiKeyCreateRequest) => Promise<ApiKeyCreateResponse>;
  deactivateApiKey: (id: number) => Promise<void>;
  toggleApiKey: (id: number, activa: boolean) => Promise<void>;
  clearLastCreatedKey: () => void;
}

export function useApiKeys(): UseApiKeysReturn {
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastCreatedKey, setLastCreatedKey] =
    useState<ApiKeyCreateResponse | null>(null);

  const fetchApiKeys = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiKeysApi.list();
      setApiKeys(data);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Error al cargar API keys';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const createApiKey = useCallback(
    async (data: ApiKeyCreateRequest): Promise<ApiKeyCreateResponse> => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await apiKeysApi.create(data);
        setLastCreatedKey(result);
        await fetchApiKeys();
        return result;
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : 'Error al crear API key';
        setError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [fetchApiKeys]
  );

  const deactivateApiKey = useCallback(
    async (id: number) => {
      setIsLoading(true);
      setError(null);
      try {
        await apiKeysApi.deactivate(id);
        await fetchApiKeys();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : 'Error al eliminar API key';
        setError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [fetchApiKeys]
  );

  const toggleApiKey = useCallback(
    async (id: number, activa: boolean) => {
      setIsLoading(true);
      setError(null);
      try {
        await apiKeysApi.toggleActive(id, activa);
        await fetchApiKeys();
      } catch (err: unknown) {
        const message =
          err instanceof Error ? err.message : 'Error al actualizar API key';
        setError(message);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [fetchApiKeys]
  );

  const clearLastCreatedKey = useCallback(() => {
    setLastCreatedKey(null);
  }, []);

  return {
    apiKeys,
    isLoading,
    error,
    lastCreatedKey,
    fetchApiKeys,
    createApiKey,
    deactivateApiKey,
    toggleApiKey,
    clearLastCreatedKey,
  };
}
