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
  Loading,
  EmptyState,
} from '@/components/ui';
import { truncate } from '@/utils/helpers';
import type { CveItem } from '@/types';

export function VulnerabilitiesPage() {
  const [severityFilter, setSeverityFilter] = useState<string>('');

  const fetchVulnerabilities = useCallback(
    () =>
      dashboardApi.getVulnerabilidades({
        limit: 50,
        severity: severityFilter || undefined,
      }),
    [severityFilter]
  );

  const {
    data: vulnerabilidades,
    isLoading,
    error,
  } = useApi({ fetchFn: fetchVulnerabilities, immediate: true });

  return (
    <div className="vulnerabilities-page">
      <div className="page-header">
        <h1 className="page-title">Vulnerabilidades Indexadas</h1>
        <p className="page-subtitle">Base de datos de CVEs y vulnerabilidades conocidas</p>
      </div>

      <Card
        title="CVEs en la Base de Datos"
        actions={
          <div className="filter-group">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="form-select form-select-sm"
            >
              <option value="">Todas las severidades</option>
              <option value="CRITICAL">Crítica</option>
              <option value="HIGH">Alta</option>
              <option value="MEDIUM">Media</option>
              <option value="LOW">Baja</option>
            </select>
          </div>
        }
      >
        {isLoading ? (
          <Loading message="Cargando vulnerabilidades..." />
        ) : error ? (
          <EmptyState title="Error" description={error} />
        ) : !vulnerabilidades || vulnerabilidades.length === 0 ? (
          <EmptyState
            title="Sin vulnerabilidades indexadas"
            description="Ejecuta la sincronización NVD para indexar vulnerabilidades"
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableCell>CVE ID</TableCell>
                <TableCell>Descripción</TableCell>
                <TableCell>Severidad</TableCell>
                <TableCell>CVSS Score</TableCell>
              </TableRow>
            </TableHeader>
            <TableBody>
              {vulnerabilidades.map((item) => (
                <TableRow key={item.id}>
                  <TableCell>
                    <code className="cve-code">{item.id}</code>
                  </TableCell>
                  <TableCell>
                    <span className="text-truncate" title={item.description}>
                      {truncate(item.description, 120)}
                    </span>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={item.severity} />
                  </TableCell>
                  <TableCell>
                    <span className="cvss-score">{item.score}</span>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
