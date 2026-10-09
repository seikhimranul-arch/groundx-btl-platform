// GroundX — Supabase Configuration
// Project URL: https://slussfxakghszgsfxusv.supabase.co

const SUPABASE_CONFIG = {
  url: 'https://slussfxakghszgsfxusv.supabase.co',
  // Paste your Supabase anon (public) key below.
  // Find it at: Supabase Dashboard → Settings → API → anon / public key
  anonKey: 'YOUR_SUPABASE_ANON_KEY_HERE',
};

// ── Supabase Client ────────────────────────────────
// Lightweight client for auth + database calls (no npm required)
const supabase = {
  _headers() {
    const h = {
      'apikey': SUPABASE_CONFIG.anonKey,
      'Content-Type': 'application/json',
    };
    const token = localStorage.getItem('gx_access_token');
    if (token) h['Authorization'] = `Bearer ${token}`;
    return h;
  },

  // ── Auth ───────────────────────────────────
  async signUp(email, password) {
    const res = await fetch(`${SUPABASE_CONFIG.url}/auth/v1/signup`, {
      method: 'POST',
      headers: { 'apikey': SUPABASE_CONFIG.anonKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (data.access_token) {
      localStorage.setItem('gx_access_token', data.access_token);
      localStorage.setItem('gx_user', JSON.stringify(data.user));
    }
    return data;
  },

  async signIn(email, password) {
    const res = await fetch(`${SUPABASE_CONFIG.url}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: { 'apikey': SUPABASE_CONFIG.anonKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (data.access_token) {
      localStorage.setItem('gx_access_token', data.access_token);
      localStorage.setItem('gx_user', JSON.stringify(data.user));
    }
    return data;
  },

  signOut() {
    localStorage.removeItem('gx_access_token');
    localStorage.removeItem('gx_user');
  },

  getUser() {
    const u = localStorage.getItem('gx_user');
    return u ? JSON.parse(u) : null;
  },

  isLoggedIn() {
    return !!localStorage.getItem('gx_access_token');
  },

  // ── Database (PostgREST) ───────────────────
  async select(table, query = '') {
    const res = await fetch(`${SUPABASE_CONFIG.url}/rest/v1/${table}?${query}`, {
      headers: this._headers(),
    });
    return res.json();
  },

  async insert(table, data) {
    const res = await fetch(`${SUPABASE_CONFIG.url}/rest/v1/${table}`, {
      method: 'POST',
      headers: { ...this._headers(), 'Prefer': 'return=representation' },
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async update(table, match, data) {
    const params = Object.entries(match).map(([k, v]) => `${k}=eq.${v}`).join('&');
    const res = await fetch(`${SUPABASE_CONFIG.url}/rest/v1/${table}?${params}`, {
      method: 'PATCH',
      headers: { ...this._headers(), 'Prefer': 'return=representation' },
      body: JSON.stringify(data),
    });
    return res.json();
  },

  async delete(table, match) {
    const params = Object.entries(match).map(([k, v]) => `${k}=eq.${v}`).join('&');
    const res = await fetch(`${SUPABASE_CONFIG.url}/rest/v1/${table}?${params}`, {
      method: 'DELETE',
      headers: this._headers(),
    });
    return res.ok;
  },

  // ── Storage ────────────────────────────────
  async uploadFile(bucket, path, file) {
    const res = await fetch(`${SUPABASE_CONFIG.url}/storage/v1/object/${bucket}/${path}`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_CONFIG.anonKey,
        'Authorization': `Bearer ${localStorage.getItem('gx_access_token')}`,
      },
      body: file,
    });
    return res.json();
  },

  getPublicUrl(bucket, path) {
    return `${SUPABASE_CONFIG.url}/storage/v1/object/public/${bucket}/${path}`;
  },
};
