import { clsx, type ClassValue } from 'clsx';

export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}

export function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('es-ES', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatDateShort(dateString: string): string {
  return new Date(dateString).toLocaleDateString('es-ES', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength) + '...';
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    Crítica: 'var(--color-critical)',
    Alta: 'var(--color-high)',
    Media: 'var(--color-medium)',
    Baja: 'var(--color-low)',
    CRITICAL: 'var(--color-critical)',
    HIGH: 'var(--color-high)',
    MEDIUM: 'var(--color-medium)',
    LOW: 'var(--color-low)',
  };
  return colors[severity] || 'var(--color-info)';
}

export function getEstadoColor(estado: string): string {
  const colors: Record<string, string> = {
    completado: 'var(--color-success)',
    en_proceso: 'var(--color-info)',
    pendiente: 'var(--color-warning)',
    fallido: 'var(--color-critical)',
  };
  return colors[estado] || 'var(--color-muted)';
}

export function getEstadoLabel(estado: string): string {
  const labels: Record<string, string> = {
    completado: 'Completado',
    en_proceso: 'En Proceso',
    pendiente: 'Pendiente',
    fallido: 'Fallido',
  };
  return labels[estado] || estado;
}

export function sanitizeInput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}
