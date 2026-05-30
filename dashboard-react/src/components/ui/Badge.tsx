import { cn, getSeverityColor, getEstadoColor, getEstadoLabel } from '@/utils/helpers';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  className?: string;
}

export function Badge({ children, variant = 'default', className }: BadgeProps) {
  return (
    <span className={cn('badge', `badge-${variant}`, className)}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const variantMap: Record<string, 'danger' | 'warning' | 'info' | 'success'> = {
    'Crítica': 'danger',
    Alta: 'warning',
    Media: 'info',
    Baja: 'success',
    CRITICAL: 'danger',
    HIGH: 'warning',
    MEDIUM: 'info',
    LOW: 'success',
  };

  return (
    <Badge variant={variantMap[severity] || 'default'}>{severity}</Badge>
  );
}

export function EstadoBadge({ estado }: { estado: string }) {
  const variantMap: Record<string, 'success' | 'info' | 'warning' | 'danger'> = {
    completado: 'success',
    en_proceso: 'info',
    pendiente: 'warning',
    fallido: 'danger',
  };

  return (
    <Badge variant={variantMap[estado] || 'default'}>
      {getEstadoLabel(estado)}
    </Badge>
  );
}
