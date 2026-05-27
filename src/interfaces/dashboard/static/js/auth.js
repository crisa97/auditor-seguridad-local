function getStoredUser() {
    const raw = sessionStorage.getItem('user');
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
}

function isAuthenticated() {
    return !!sessionStorage.getItem('access_token');
}

function requireAuth() {
    if (!isAuthenticated()) {
        window.location.href = '/dashboard/login.html';
        return false;
    }
    return true;
}

function logout() {
    sessionStorage.clear();
    window.location.href = '/dashboard/login.html';
}

async function initApp() {
    if (!requireAuth()) return;

    const user = getStoredUser();
    if (!user) {
        logout();
        return;
    }

    document.getElementById('user-name').textContent = user.nombre || user.email;
    const roleBadge = document.getElementById('user-rol');
    roleBadge.textContent = user.rol;
    roleBadge.className = `rol-badge ${user.rol}`;

    document.getElementById('btn-logout').addEventListener('click', logout);

    if (user.rol === 'admin') {
        await loadAdminDashboard(user);
    } else {
        await loadUserDashboard(user);
    }
}
