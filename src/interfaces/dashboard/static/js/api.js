const API_BASE = '/api/v2';

class ApiClient {
    constructor() {
        this.baseUrl = API_BASE;
    }

    getToken() {
        return sessionStorage.getItem('access_token');
    }

    getRefreshToken() {
        return sessionStorage.getItem('refresh_token');
    }

    async request(method, path, body = null, auth = true) {
        const headers = { 'Content-Type': 'application/json' };
        if (auth) {
            const token = this.getToken();
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
        }

        const opts = { method, headers };
        if (body) {
            opts.body = JSON.stringify(body);
        }

        const res = await fetch(`${this.baseUrl}${path}`, opts);

        if (res.status === 401 && auth) {
            const refreshed = await this.tryRefresh();
            if (refreshed) {
                headers['Authorization'] = `Bearer ${this.getToken()}`;
                const retryRes = await fetch(`${this.baseUrl}${path}`, opts);
                if (!retryRes.ok) {
                    const err = await retryRes.json().catch(() => ({ detail: 'Error' }));
                    throw new Error(err.detail || `HTTP ${retryRes.status}`);
                }
                return retryRes.json();
            }
            sessionStorage.clear();
            window.location.href = '/dashboard/login.html';
            return null;
        }

        if (!res.ok) {
            const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        if (res.status === 204) return null;
        return res.json();
    }

    async tryRefresh() {
        const refreshToken = this.getRefreshToken();
        if (!refreshToken) return false;

        try {
            const res = await fetch(`${this.baseUrl}/auth/refresh`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });

            if (!res.ok) return false;

            const data = await res.json();
            sessionStorage.setItem('access_token', data.access_token);
            sessionStorage.setItem('refresh_token', data.refresh_token);
            sessionStorage.setItem('user', JSON.stringify(data.user));
            return true;
        } catch {
            return false;
        }
    }

    get(path, auth = true) {
        return this.request('GET', path, null, auth);
    }

    post(path, body, auth = true) {
        return this.request('POST', path, body, auth);
    }
}

const api = new ApiClient();
