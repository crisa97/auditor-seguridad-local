async function loadUserDashboard(user) {
    document.getElementById('dashboard-title').textContent = 'Panel de Usuario';
    document.getElementById('admin-only-sections').style.display = 'none';
    document.getElementById('user-only-sections').style.display = 'block';

    await Promise.all([
        loadUserHallazgos(),
        setupApiKeyForm(),
    ]);
}

async function loadUserHallazgos() {
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
                tbody.innerHTML = '<tr><td colspan="5" class="text-muted">No hay hallazgos registrados.</td></tr>';
                return;
            }
            tbody.innerHTML = list.map(h => `
                <tr>
                    <td class="text-truncate" title="${h.filepath}">${h.filepath}</td>
                    <td><span class="severity-badge ${h.severidad}">${h.severidad}</span></td>
                    <td class="text-truncate" title="${h.titulo}">${h.titulo}</td>
                    <td class="text-truncate" title="${h.descripcion}">${h.descripcion}</td>
                    <td class="text-truncate" title="${h.mitigacion}">${h.mitigacion}</td>
                </tr>
            `).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="5" class="alert alert-error">Error: ${e.message}</td></tr>`;
        }
    }

    filterBtn.addEventListener('click', render);
    await render();
}

function setupApiKeyForm() {
    const form = document.getElementById('apikey-form');
    const display = document.getElementById('api-key-display');
    const submitBtn = document.getElementById('btn-generate-key');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        submitBtn.disabled = true;
        submitBtn.textContent = 'Generando...';
        display.classList.remove('visible');
        display.textContent = '';

        const nombre = document.getElementById('key-cliente').value.trim();
        const permisos = document.getElementById('key-permisos').value;
        const dias = parseInt(document.getElementById('key-dias').value);

        try {
            const result = await api.post('/apikeys', {
                nombre_cliente: nombre,
                permisos: permisos,
                dias_validez: dias,
            });
            display.textContent = `🔑 API Key generada:\n\n${result.api_key}\n\n⚠️ ${result.advertencia}`;
            display.classList.add('visible');
            form.reset();
        } catch (e) {
            display.textContent = `Error: ${e.message}`;
            display.classList.add('visible');
            display.style.color = 'var(--danger)';
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Generar API Key';
        }
    });
}
