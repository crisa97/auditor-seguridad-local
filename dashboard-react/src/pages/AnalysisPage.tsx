import { useState, useCallback } from 'react';
import { useApi } from '@/hooks';
import { dashboardApi } from '@/api';
import {
  Card,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableCell,
  SeverityBadge,
  EstadoBadge,
  Button,
  Loading,
  EmptyState,
  Modal,
} from '@/components/ui';
import { formatDate, downloadBlob } from '@/utils/helpers';
import type { AnalisisItem, HallazgoItem } from '@/types';

type TabType = 'analisis' | 'hallazgos';

export function AnalysisPage() {
  const [activeTab, setActiveTab] = useState<TabType>('analisis');
  const [selectedAnalisis, setSelectedAnalisis] = useState<AnalisisItem | null>(null);
  const [hallazgosFilter, setHallazgosFilter] = useState<string>('');
  const [isDetailOpen, setIsDetailOpen] = useState(false);

  const fetchAnalisis = useCallback(
    () => dashboardApi.getAnalisis({ limit: 50 }),
    []
  );

  const fetchHallazgos = useCallback(
    () =>
      dashboardApi.getHallazgos({
        limit: 100,
        severidad: hallazgosFilter || undefined,
      }),
    [hallazgosFilter]
  );

  const {
    data: analisis,
    isLoading: analisisLoading,
    error: analisisError,
    execute: refetchAnalisis,
  } = useApi({ fetchFn: fetchAnalisis, immediate: true });

  const {
    data: hallazgos,
    isLoading: hallazgosLoading,
    error: hallazgosError,
    execute: refetchHallazgos,
  } = useApi({ fetchFn: fetchHallazgos, immediate: true });

  const handleDownloadPdf = async (reportePath: string) => {
    try {
      const blob = await dashboardApi.downloadPdf(reportePath);
      const filename = reportePath.split('/').pop() || 'reporte.pdf';
      downloadBlob(blob, filename);
    } catch {
      // Error handling done by interceptor
    }
  };

  const openDetail = (item: AnalisisItem) => {
    setSelectedAnalisis(item);
    setIsDetailOpen(true);
  };

  return (
    <div className="analysis-page">
      <div className="page-header">
        <h1 className="page-title">Análisis de Seguridad</h1>
        <p className="page-subtitle">Historial de análisis y hallazgos detectados</p>
      </div>

      <div className="tabs">
        <button
          className={`tab ${activeTab === 'analisis' ? 'tab-active' : ''}`}
          onClick={() => setActiveTab('analisis')}
          type="button"
        >
          Análisis
        </button>
        <button
          className={`tab ${activeTab === 'hallazgos' ? 'tab-active' : ''}`}
          onClick={() => setActiveTab('hallazgos')}
          type="button"
        >
          Hallazgos
        </button>
      </div>

      {activeTab === 'analisis' && (
        <Card>
          {analisisLoading ? (
            <Loading message="Cargando análisis..." />
          ) : analisisError ? (
            <EmptyState title="Error" description={analisisError} />
          ) : !analisis || analisis.length === 0 ? (
            <EmptyState
              title="Sin análisis realizados"
              description="Ejecuta un análisis desde la CLI o API para ver resultados aquí"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableCell>Proyecto</TableCell>
                  <TableCell>Fecha</TableCell>
                  <TableCell>Estado</TableCell>
                  <TableCell>Archivos</TableCell>
                  <TableCell>Reportes</TableCell>
                  <TableCell>Acciones</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {analisis.map((item) => (
                  <TableRow key={item.id}>
                    <TableCell>
                      <span className="text-truncate" title={item.projectPath}>
                        {item.projectPath.split('/').pop() || item.projectPath}
                      </span>
                    </TableCell>
                    <TableCell>{formatDate(item.timestamp)}</TableCell>
                    <TableCell>
                      <EstadoBadge estado={item.estado} />
                    </TableCell>
                    <TableCell>
                      {item.archivosAnalizados} / {item.totalFiles}
                    </TableCell>
                    <TableCell>
                      <div className="report-links">
                        {item.reportePdf && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDownloadPdf(item.reportePdf!)}
                          >
                            PDF
                          </Button>
                        )}
                        {item.reporteTxt && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDownloadPdf(item.reporteTxt!)}
                          >
                            TXT
                          </Button>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => openDetail(item)}
                      >
                        Ver Detalle
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      )}

      {activeTab === 'hallazgos' && (
        <Card
          title="Hallazgos de Seguridad"
          actions={
            <div className="filter-group">
              <select
                value={hallazgosFilter}
                onChange={(e) => setHallazgosFilter(e.target.value)}
                className="form-select form-select-sm"
              >
                <option value="">Todas las severidades</option>
                <option value="Crítica">Crítica</option>
                <option value="Alta">Alta</option>
                <option value="Media">Media</option>
                <option value="Baja">Baja</option>
              </select>
            </div>
          }
        >
          {hallazgosLoading ? (
            <Loading message="Cargando hallazgos..." />
          ) : hallazgosError ? (
            <EmptyState title="Error" description={hallazgosError} />
          ) : !hallazgos || hallazgos.length === 0 ? (
            <EmptyState
              title="Sin hallazgos"
              description="No se han encontrado vulnerabilidades"
            />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableCell>Archivo</TableCell>
                  <TableCell>Severidad</TableCell>
                  <TableCell>Título</TableCell>
                  <TableCell>Descripción</TableCell>
                  <TableCell>Ubicación</TableCell>
                  <TableCell>CVE/CWE</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hallazgos.map((item, idx) => (
                  <TableRow key={item._id || idx}>
                    <TableCell>
                      <span className="text-truncate" title={item.filepath}>
                        {item.filepath}
                      </span>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={item.severidad} />
                    </TableCell>
                    <TableCell>{item.titulo}</TableCell>
                    <TableCell>
                      <span className="text-truncate" title={item.descripcion}>
                        {item.descripcion.slice(0, 80)}
                        {item.descripcion.length > 80 && '...'}
                      </span>
                    </TableCell>
                    <TableCell>{item.ubicacion}</TableCell>
                    <TableCell>
                      <code className="cve-code">{item.cve_cwe}</code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Card>
      )}

      <Modal
        isOpen={isDetailOpen}
        onClose={() => setIsDetailOpen(false)}
        title="Detalle del Análisis"
      >
        {selectedAnalisis && (
          <div className="analisis-detail">
            <div className="detail-row">
              <strong>Proyecto:</strong>
              <span>{selectedAnalisis.projectPath}</span>
            </div>
            <div className="detail-row">
              <strong>Fecha:</strong>
              <span>{formatDate(selectedAnalisis.timestamp)}</span>
            </div>
            <div className="detail-row">
              <strong>Estado:</strong>
              <EstadoBadge estado={selectedAnalisis.estado} />
            </div>
            <div className="detail-row">
              <strong>Archivos:</strong>
              <span>
                {selectedAnalisis.archivosAnalizados} / {selectedAnalisis.totalFiles}{' '}
                analizados
              </span>
            </div>
            {selectedAnalisis.error && (
              <div className="detail-row detail-error">
                <strong>Error:</strong>
                <span>{selectedAnalisis.error}</span>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
}
