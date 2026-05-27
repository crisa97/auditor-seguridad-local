async function loadAdminDashboard(user) {
    document.getElementById('dashboard-title').textContent = 'Panel de Administración';
    document.getElementById('admin-only-sections').style.display = 'block';
    document.getElementById('user-only-sections').style.display = 'block';

    await Promise.all([
        loadStats(),
        loadAnalisis(),
        loadVulnerabilidades(),
        loadHallazgos(),
    ]);
}

async function loadStats() {
    const container = document.getElementById('stats-container');
    try {
        const stats = await api.get('/dashboard/stats');
        container.innerHTML = `
            <div class="stat-card">
                <div class="stat-value">${stats.total_analisis}</div>
                <div class="stat-label">Análisis Totales</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--success)">${stats.analisis_completados}</div>
                <div class="stat-label">Completados</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--danger)">${stats.analisis_fallidos}</div>
                <div class="stat-label">Fallidos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--info)">${stats.analisis_en_curso}</div>
                <div class="stat-label">En Curso</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.total_hallazgos}</div>
                <div class="stat-label">Hallazgos</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.total_cves_indexadas}</div>
                <div class="stat-label">CVEs Indexadas</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">${stats.total_exploits_indexados}</div>
                <div class="stat-label">Exploits Indexados</div>
            </div>
        `;

        const sev = stats.hallazgos_por_severidad;
        const sevOrder = ['Crítica', 'Alta', 'Media', 'Baja'];
        sevOrder.forEach(s => {
            if (sev[s]) {
                container.innerHTML += `
                    <div class="stat-card">
                        <div class="stat-value ${s.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '')}">${sev[s]}</div>
                        <div class="stat-label">${s}</div>
                    </div>
                `;
            }
        });
    } catch (e) {
        container.innerHTML = `<div class="alert alert-error">Error al cargar estadísticas: ${e.message}</div>`;
    }
}

async function loadAnalisis() {
    const tbody = document.querySelector('#analisis-table tbody');
    try {
        const list = await api.get('/dashboard/analisis?limit=10');
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No hay análisis registrados.</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(a => `
            <tr>
                <td class="text-truncate" title="${a.projectPath}">${a.projectPath}</td>
                <td>${new Date(a.timestamp).toLocaleDateString()}</td>
                <td><span class="estado-badge ${a.estado}">${a.estado}</span></td>
                <td>${a.archivosAnalizados}/${a.totalFiles}</td>
                <td>${a.reportePdf ? `<a href="/${a.reportePdf}" target="_blank">PDF</a>` : '-'}</td>
                <td class="text-muted">${a.error || '-'}</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="alert alert-error">Error: ${e.message}</td></tr>`;
    }
}

async function loadVulnerabilidades() {
    const tbody = document.querySelector('#vulnerabilidades-table tbody');
    try {
        const list = await api.get('/dashboard/vulnerabilidades?limit=10');
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-muted">No hay CVEs indexadas.</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(c => `
            <tr>
                <td><strong>${c.id}</strong></td>
                <td class="text-truncate" title="${c.description}">${c.description}</td>
                <td><span class="severity-badge ${c.severity}">${c.severity}</span></td>
                <td>${c.score}</td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="4" class="alert alert-error">Error: ${e.message}</td></tr>`;
    }
}

async function loadHallazgos() {
    const tbody = document.querySelector('#hallazgos-table tbody');
    const filterSev = document.getElementById('filter-severidad');
    const filterBtn = document.getElementById('btn-filter');

    async function fetchHallazgos() {
        let url = '/dashboard/hallazgos?limit=50';
        const sev = filterSev.value;
        if (sev) url += `&severidad=${sev}`;
        return api.get(url);
    }

    async function render() {
        try {
            const list = await fetchHallazgos();
            if (list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-muted">No hay hallazgos registrados.</td></tr>';
                return;
            }
            tbody.innerHTML = list.map(h => `
                <tr>
                    <td class="text-truncate" title="${h.filepath}">${h.filepath}</td>
                    <td><span class="severity-badge ${h.severidad}">${h.severidad}</span></td>
                    <td class="text-truncate" title="${h.titulo}">${h.titulo}</td>
                    <td class="text-truncate" title="${h.descripcion}">${h.descripcion}</td>
                    <td class="text-truncate" title="${h.mitigacion}">${h.mitigacion}</td>
                    <td>${h.cve_cwe}</td>
                </tr>
            `).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="6" class="alert alert-error">Error: ${e.message}</td></tr>`;
        }
    }

    filterBtn.addEventListener('click', render);
    await render();
}
