import { useMemo } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  Legend,
} from 'recharts';
import { useApi } from '@/hooks';
import { dashboardApi } from '@/api';
import { StatCard, Card, Loading, EmptyState } from '@/components/ui';
import { formatDate } from '@/utils/helpers';
import { useAuthContext } from '@/context/AuthContext';

const SEVERITY_COLORS: Record<string, string> = {
  'Crítica': '#e74c3c',
  Alta: '#e67e22',
  Media: '#f1c40f',
  Baja: '#2ecc71',
};

export function DashboardPage() {
  const { isAdmin } = useAuthContext();

  const { data: stats, isLoading: statsLoading, error: statsError } = useApi({
    fetchFn: dashboardApi.getStats,
  });

  const { data: timeline, isLoading: timelineLoading } = useApi({
    fetchFn: dashboardApi.getTimeline,
    immediate: isAdmin,
  });

  const { data: topVulns, isLoading: topLoading } = useApi({
    fetchFn: dashboardApi.getTopVulnerabilidades,
    immediate: isAdmin,
  });

  const severityData = useMemo(() => {
    if (!stats?.hallazgos_por_severidad) return [];
    return Object.entries(stats.hallazgos_por_severidad).map(([name, value]) => ({
      name,
      value,
      color: SEVERITY_COLORS[name] || '#9ca0b8',
    }));
  }, [stats]);

  if (statsLoading) return <Loading size="lg" message="Cargando dashboard..." />;
  if (statsError) return <EmptyState title="Error al cargar datos" description={statsError} />;
  if (!stats) return <EmptyState title="Sin datos disponibles" />;

  return (
    <div className="dashboard-page">
      <div className="page-header">
        <h1 className="page-title">
          {isAdmin ? 'Panel de Administración' : 'Mi Dashboard'}
        </h1>
        <p className="page-subtitle">Resumen general de seguridad</p>
      </div>

      <div className="stats-grid">
        <StatCard
          label="Total Análisis"
          value={stats.total_analisis}
          icon="🔍"
        />
        <StatCard
          label="Completados"
          value={stats.analisis_completados}
          icon="✅"
        />
        <StatCard
          label="En Curso"
          value={stats.analisis_en_curso}
          icon="⏳"
        />
        <StatCard
          label="Fallidos"
          value={stats.analisis_fallidos}
          icon="❌"
        />
        <StatCard
          label="Total Hallazgos"
          value={stats.total_hallazgos}
          icon="⚠️"
        />
        {isAdmin && (
          <>
            <StatCard
              label="CVEs Indexadas"
              value={stats.total_cves_indexadas.toLocaleString()}
              icon="🗄️"
            />
            <StatCard
              label="Exploits Indexados"
              value={stats.total_exploits_indexados.toLocaleString()}
              icon="💥"
            />
          </>
        )}
      </div>

      <div className="charts-grid">
        <Card title="Hallazgos por Severidad" className="chart-card">
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={5}
                  dataKey="value"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="Sin datos de severidad" />
          )}
        </Card>

        {isAdmin && timeline && timeline.length > 0 && (
          <Card title="Análisis en el Tiempo" className="chart-card">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" stroke="#373b52" />
                <XAxis
                  dataKey="fecha"
                  stroke="#9ca0b8"
                  tick={{ fontSize: 12 }}
                />
                <YAxis stroke="#9ca0b8" tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#232734',
                    border: '1px solid #373b52',
                    borderRadius: '8px',
                  }}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="analisis"
                  stroke="#6c5ce7"
                  strokeWidth={2}
                  name="Análisis"
                />
                <Line
                  type="monotone"
                  dataKey="hallazgos"
                  stroke="#e74c3c"
                  strokeWidth={2}
                  name="Hallazgos"
                />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        )}

        {isAdmin && topVulns && topVulns.length > 0 && (
          <Card title="Top Vulnerabilidades" className="chart-card chart-card-full">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={topVulns.slice(0, 10)}>
                <CartesianGrid strokeDasharray="3 3" stroke="#373b52" />
                <XAxis
                  dataKey="cve_cwe"
                  stroke="#9ca0b8"
                  tick={{ fontSize: 11 }}
                  angle={-45}
                  textAnchor="end"
                  height={80}
                />
                <YAxis stroke="#9ca0b8" tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#232734',
                    border: '1px solid #373b52',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="count" name="Frecuencia" radius={[4, 4, 0, 0]}>
                  {topVulns.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={SEVERITY_COLORS[entry.severidad] || '#6c5ce7'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
        )}
      </div>
    </div>
  );
}
