import { useState, useEffect } from 'react';
import { useApiKeys } from '@/hooks';
import { useAuthContext } from '@/context/AuthContext';
import {
  Card,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableCell,
  Badge,
  Button,
  Modal,
  Input,
  Loading,
  EmptyState,
} from '@/components/ui';
import { apiKeyCreateSchema, type ApiKeyCreateFormData } from '@/utils/validation';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { formatDate } from '@/utils/helpers';

export function ApiKeysPage() {
  const { isAdmin } = useAuthContext();
  const {
    apiKeys,
    isLoading,
    lastCreatedKey,
    fetchApiKeys,
    createApiKey,
    deactivateApiKey,
    toggleApiKey,
    clearLastCreatedKey,
  } = useApiKeys();

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [isRevokeOpen, setIsRevokeOpen] = useState(false);
  const [selectedKeyId, setSelectedKeyId] = useState<number | null>(null);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ApiKeyCreateFormData>({
    resolver: zodResolver(apiKeyCreateSchema),
    defaultValues: {
      permisos: 'rag:leer',
    },
  });

  useEffect(() => {
    fetchApiKeys();
  }, [fetchApiKeys]);

  const onCreateSubmit = async (data: ApiKeyCreateFormData) => {
    try {
      await createApiKey({
        nombre_cliente: data.nombre_cliente,
        permisos: data.permisos,
        dias_validez: data.dias_validez,
      });
      reset();
      setIsCreateOpen(false);
    } catch {
      // Error handled by hook
    }
  };

  const handleRevoke = async () => {
    if (selectedKeyId === null) return;
    try {
      await deactivateApiKey(selectedKeyId);
      setIsRevokeOpen(false);
      setSelectedKeyId(null);
    } catch {
      // Error handled by hook
    }
  };

  const handleToggle = async (id: number, currentActiva: boolean) => {
    try {
      await toggleApiKey(id, !currentActiva);
    } catch {
      // Error handled by hook
    }
  };

  return (
    <div className="apikeys-page">
      <div className="page-header">
        <h1 className="page-title">API Keys</h1>
        <p className="page-subtitle">
          Gestiona las claves de acceso para integrar analizadores externos
        </p>
      </div>

      <Card
        title="Claves de API"
        actions={
          <Button onClick={() => setIsCreateOpen(true)}>Nueva API Key</Button>
        }
      >
        {isLoading && apiKeys.length === 0 ? (
          <Loading message="Cargando API keys..." />
        ) : apiKeys.length === 0 ? (
          <EmptyState
            title="Sin API keys"
            description="Crea una API key para integrar herramientas externas"
            action={
              <Button onClick={() => setIsCreateOpen(true)}>
                Crear primera API key
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableCell>Prefijo</TableCell>
                <TableCell>Nombre</TableCell>
                <TableCell>Permisos</TableCell>
                <TableCell>Estado</TableCell>
                <TableCell>Creación</TableCell>
                <TableCell>Expiración</TableCell>
                <TableCell>Último Uso</TableCell>
                <TableCell>Acciones</TableCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {apiKeys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell>
                    <code className="key-prefix">{key.key_prefix}...</code>
                  </TableCell>
                  <TableCell>{key.nombre_cliente}</TableCell>
                  <TableCell>
                    <code className="permisos-code">{key.permisos}</code>
                  </TableCell>
                  <TableCell>
                    <Badge variant={key.activa ? 'success' : 'danger'}>
                      {key.activa ? 'Activa' : 'Inactiva'}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatDate(key.fecha_creacion)}</TableCell>
                  <TableCell>
                    {key.fecha_expiracion
                      ? formatDate(key.fecha_expiracion)
                      : 'Sin expiración'}
                  </TableCell>
                  <TableCell>
                    {key.ultimo_uso ? formatDate(key.ultimo_uso) : 'Nunca'}
                  </TableCell>
                  <TableCell>
                    <div className="action-buttons">
                      <Button
                        size="sm"
                        variant={key.activa ? 'danger' : 'secondary'}
                        onClick={() => handleToggle(key.id, key.activa)}
                      >
                        {key.activa ? 'Desactivar' : 'Activar'}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Crear Nueva API Key"
      >
        <form onSubmit={handleSubmit(onCreateSubmit)} className="modal-form">
          <Input
            label="Nombre del Cliente"
            placeholder="Equipo de desarrollo"
            error={errors.nombre_cliente?.message}
            {...register('nombre_cliente')}
          />

          <Input
            label="Permisos"
            placeholder="rag:leer"
            error={errors.permisos?.message}
            {...register('permisos')}
          />

          <Input
            label="Días de Validez (opcional)"
            type="number"
            placeholder="365"
            error={errors.dias_validez?.message}
            {...register('dias_validez', { valueAsNumber: true })}
          />

          <div className="modal-actions">
            <Button
              type="button"
              variant="secondary"
              onClick={() => setIsCreateOpen(false)}
            >
              Cancelar
            </Button>
            <Button type="submit" isLoading={isLoading}>
              Crear API Key
            </Button>
          </div>
        </form>
      </Modal>

      <Modal
        isOpen={!!lastCreatedKey}
        onClose={clearLastCreatedKey}
        title="API Key Creada"
      >
        {lastCreatedKey && (
          <div className="created-key-info">
            <div className="alert alert-warning">
              ⚠️ Guarda esta clave. No se volverá a mostrar.
            </div>
            <div className="key-display">
              <label className="form-label">Tu API Key:</label>
              <div className="key-value">
                <code>{lastCreatedKey.api_key}</code>
              </div>
            </div>
            <div className="key-details">
              <p>
                <strong>Prefijo:</strong> {lastCreatedKey.key_prefix}
              </p>
              <p>
                <strong>Permisos:</strong> {lastCreatedKey.permisos}
              </p>
              {lastCreatedKey.fecha_expiracion && (
                <p>
                  <strong>Expira:</strong>{' '}
                  {formatDate(lastCreatedKey.fecha_expiracion)}
                </p>
              )}
            </div>
            <div className="modal-actions">
              <Button onClick={clearLastCreatedKey}>Entendido</Button>
            </div>
          </div>
        )}
      </Modal>

      <Modal
        isOpen={isRevokeOpen}
        onClose={() => setIsRevokeOpen(false)}
        title="Revocar API Key"
      >
        <p>¿Estás seguro de que deseas revocar esta API key?</p>
        <div className="modal-actions">
          <Button
            variant="secondary"
            onClick={() => setIsRevokeOpen(false)}
          >
            Cancelar
          </Button>
          <Button variant="danger" onClick={handleRevoke} isLoading={isLoading}>
            Revocar
          </Button>
        </div>
      </Modal>
    </div>
  );
}
