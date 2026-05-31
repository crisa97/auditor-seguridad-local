import { useState, useEffect, useCallback } from 'react';

interface UseApiOptions<T> {
  fetchFn: () => Promise<T>;
  immediate?: boolean;
}

interface UseApiReturn<T> {
  data: T | null;
  isLoading: boolean;
  error: string | null;
  execute: () => Promise<void>;
  reset: () => void;
}

export function useApi<T>({
  fetchFn,
  immediate = true,
}: UseApiOptions<T>): UseApiReturn<T> {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(immediate);
  const [error, setError] = useState<string | null>(null);

  const execute = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await fetchFn();
      setData(result);
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : 'Error desconocido';
      setError(message);
    } finally {
      setIsLoading(false);
    }
  }, [fetchFn]);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setIsLoading(false);
  }, []);

  useEffect(() => {
    if (immediate) {
      execute();
    }
  }, [immediate, execute]);

  return { data, isLoading, error, execute, reset };
}
