export type Rol = 'admin' | 'usuario';

export type EstadoAnalisis = 'pendiente' | 'en_proceso' | 'completado' | 'fallido';

export type Severidad = 'Crítica' | 'Alta' | 'Media' | 'Baja';

export interface User {
  id: number;
  email: string;
  nombre: string;
  rol: Rol;
  activo: boolean;
  creado_en: string;
  ultimo_login: string | null;
}

export interface UserCreate {
  email: string;
  password: string;
  nombre: string;
  rol: Rol;
}

export interface UserUpdate {
  email?: string;
  nombre?: string;
  rol?: Rol;
  activo?: boolean;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: {
    id: number;
    email: string;
    nombre: string;
    rol: Rol;
  };
}

export interface RegisterRequest {
  email: string;
  password: string;
  nombre: string;
  rol: Rol;
}

export interface RegisterResponse {
  message: string;
  email: string;
  rol: Rol;
}

export interface StatsResponse {
  total_analisis: number;
  analisis_completados: number;
  analisis_fallidos: number;
  analisis_en_curso: number;
  total_hallazgos: number;
  hallazgos_por_severidad: Record<Severidad, number>;
  total_cves_indexadas: number;
  total_exploits_indexados: number;
}

export interface AnalisisItem {
  id: string;
  projectPath: string;
  timestamp: string;
  estado: EstadoAnalisis;
  totalFiles: number;
  archivosAnalizados: number;
  reportePdf: string | null;
  reporteTxt: string | null;
  error: string;
  usuarioId?: number;
}

export interface HallazgoItem {
  _id?: string;
  analisisId: string;
  filepath: string;
  severidad: Severidad;
  titulo: string;
  descripcion: string;
  mitigacion: string;
  ubicacion: string;
  cve_cwe: string;
  owasp?: string;
  raw_response?: string;
  usuarioId?: number;
}

export interface CveItem {
  id: string;
  description: string;
  severity: string;
  score: string;
}

export interface ApiKeyItem {
  id: number;
  key_prefix: string;
  nombre_cliente: string;
  fecha_creacion: string;
  fecha_expiracion: string | null;
  activa: boolean;
  permisos: string;
  ultimo_uso: string | null;
  usuario_id: number;
}

export interface ApiKeyCreateRequest {
  nombre_cliente: string;
  permisos: string;
  dias_validez?: number;
}

export interface ApiKeyCreateResponse {
  api_key: string;
  key_prefix: string;
  nombre_cliente: string;
  permisos: string;
  fecha_expiracion: string | null;
  advertencia: string;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface TimelineData {
  fecha: string;
  analisis: number;
  hallazgos: number;
}

export interface TopVulnerabilidad {
  cve_cwe: string;
  count: number;
  severidad: Severidad;
}
