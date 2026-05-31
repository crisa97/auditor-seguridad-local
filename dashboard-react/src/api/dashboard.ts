import { api } from './client';
import type {
  StatsResponse,
  AnalisisItem,
  HallazgoItem,
  CveItem,
  TimelineData,
  TopVulnerabilidad,
} from '@/types';

interface AnalisisParams {
  limit?: number;
  offset?: number;
  estado?: string;
}

interface HallazgosParams {
  limit?: number;
  offset?: number;
  severidad?: string;
  analisis_id?: string;
}

interface VulnerabilidadesParams {
  limit?: number;
  offset?: number;
  severity?: string;
}

export const dashboardApi = {
  async getStats(): Promise<StatsResponse> {
    const response = await api.get<StatsResponse>('/dashboard/stats');
    return response.data;
  },

  async getAnalisis(params: AnalisisParams = {}): Promise<AnalisisItem[]> {
    const response = await api.get<AnalisisItem[]>('/dashboard/analisis', {
      params: { limit: 20, ...params },
    });
    return response.data;
  },

  async getAnalisisDetail(id: string): Promise<AnalisisItem> {
    const response = await api.get<AnalisisItem>(`/dashboard/analisis/${id}`);
    return response.data;
  },

  async getHallazgos(params: HallazgosParams = {}): Promise<HallazgoItem[]> {
    const response = await api.get<HallazgoItem[]>('/dashboard/hallazgos', {
      params: { limit: 50, ...params },
    });
    return response.data;
  },

  async getVulnerabilidades(
    params: VulnerabilidadesParams = {}
  ): Promise<CveItem[]> {
    const response = await api.get<CveItem[]>('/dashboard/vulnerabilidades', {
      params: { limit: 20, ...params },
    });
    return response.data;
  },

  async getTimeline(): Promise<TimelineData[]> {
    const response = await api.get<TimelineData[]>('/dashboard/stats/timeline');
    return response.data;
  },

  async getTopVulnerabilidades(): Promise<TopVulnerabilidad[]> {
    const response = await api.get<TopVulnerabilidad[]>(
      '/dashboard/stats/top-vulnerabilidades'
    );
    return response.data;
  },

  async downloadPdf(reportePath: string): Promise<Blob> {
    const response = await api.get(`/dashboard/reportes/pdf`, {
      params: { path: reportePath },
      responseType: 'blob',
    });
    return response.data;
  },
};
