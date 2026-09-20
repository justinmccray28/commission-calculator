import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';

const directory = dirname(fileURLToPath(import.meta.url));
const origin = process.env.APP_ORIGIN?.replace(/\/$/, '');
const supabase = process.env.SUPABASE_URL?.replace(/\/$/, '');
const key = process.env.SUPABASE_PUBLISHABLE_KEY;
if (!origin || !supabase || !key) throw new Error('APP_ORIGIN, SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY are required');
if (!/^https:\/\//.test(origin) && !/^http:\/\/localhost(?::\d+)?$/.test(origin)) throw new Error('APP_ORIGIN must use HTTPS outside localhost');
if (!/^https:\/\//.test(supabase) && !/^http:\/\/localhost(?::\d+)?$/.test(supabase)) throw new Error('SUPABASE_URL must use HTTPS outside localhost');
const secure = origin.startsWith('https:');
const cookieName = name => `${secure ? '__Host-' : ''}cc-${name}`;
const cookie = (name, value, age) => `${cookieName(name)}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${secure ? '; Secure' : ''}`;
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(part => part.trim().split(/=(.*)/s).slice(0, 2).map(decodeURIComponent)).filter(pair => pair.length === 2));
const setSession = (res, data) => {
  res.appendHeader('Set-Cookie', cookie('access', data.access_token, Math.min(data.expires_in || 3600, 3600)));
  res.appendHeader('Set-Cookie', cookie('refresh', data.refresh_token, 60 * 60 * 24 * 30));
};
const clearSession = res => { res.appendHeader('Set-Cookie', cookie('access', '', 0)); res.appendHeader('Set-Cookie', cookie('refresh', '', 0)); };
const headers = { apikey: key, 'Content-Type': 'application/json' };
async function authRequest(path, options = {}) {
  const response = await fetch(`${supabase}/auth/v1${path}`, { ...options, headers: { ...headers, ...options.headers }, signal: AbortSignal.timeout(8000) });
  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
}
async function userFromRequest(req, res) {
  const current = cookies(req);
  const access = current[cookieName('access')];
  if (access) {
    const result = await authRequest('/user', { headers: { Authorization: `Bearer ${access}` } });
    if (result.ok && result.data.id) return { user: result.data, access };
    if (result.status !== 401 && result.status !== 403) throw new Error('Auth service unavailable');
  }
  const refresh = current[cookieName('refresh')];
  if (!refresh) return null;
  const renewed = await authRequest('/token?grant_type=refresh_token', { method: 'POST', body: JSON.stringify({ refresh_token: refresh }) });
  if (!renewed.ok || !renewed.data.access_token) {
    if (renewed.status >= 500) throw new Error('Auth service unavailable');
    clearSession(res);
    return null;
  }
  const verified = await authRequest('/user', { headers: { Authorization: `Bearer ${renewed.data.access_token}` } });
  if (!verified.ok || !verified.data.id) throw new Error('Auth service unavailable');
  setSession(res, renewed.data);
  return { user: verified.data, access: renewed.data.access_token };
}
function send(res, code, body, type = 'text/html; charset=utf-8') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'private, no-store, max-age=0', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' });
  res.end(body);
}
function redirect(res, path) { res.writeHead(303, { Location: path, 'Cache-Control': 'no-store' }); res.end(); }
function csrfToken(res) {
  const token = randomBytes(32).toString('hex');
  res.appendHeader('Set-Cookie', cookie('csrf', token, 3600));
  return token;
}
function csrfField(token) { return `<input type="hidden" name="csrf" value="${token}">`; }
function validPost(req, data) {
  if (!(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) return false;
  // Some in-app browsers omit Origin or send "null". A real cross-origin
  // Origin is still rejected; the per-visit form token handles the rest.
  if (req.headers.origin && req.headers.origin !== 'null' && req.headers.origin !== origin) return false;
  const expected = cookies(req)[cookieName('csrf')];
  if (!expected || !data.csrf || !/^[a-f0-9]{64}$/.test(expected) || !/^[a-f0-9]{64}$/.test(data.csrf)) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(data.csrf, 'hex'));
}
function escapeHTML(value) { return String(value).replace(/[&<>"']/g, char => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[char]); }
function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHTML(title)} · Commission Calculator</title><style>body{min-height:100vh;margin:0;display:grid;place-items:center;background:radial-gradient(circle at 30% 10%,#164260,#071322 65%);color:#f5f9ff;font:16px/1.5 system-ui,sans-serif}.card{width:min(420px,calc(100vw - 48px));padding:30px;border:1px solid #37607e;border-radius:16px;background:linear-gradient(145deg,#18334d,#0b1c30);box-shadow:0 20px 60px #0006}h1{margin:0 0 8px;font-size:27px}p{color:#b9cde2}label{display:block;margin:16px 0 5px}input{box-sizing:border-box;width:100%;padding:12px;background:#0d2338;border:1px solid #3e6986;border-radius:8px;color:white;font:inherit}button{cursor:pointer;width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:linear-gradient(90deg,#43d9e0,#63e6a5);font:700 15px system-ui;color:#08233b}a{color:#81e7e1}.hint{font-size:13px}</style></head><body><main class="card">${body}</main></body></html>`;
}
function loginPage(message = '', token = '') { return page('Sign in', `<h1>Commission Calculator</h1><p>Sign in to your invited agent account.</p>${message ? `<p role="alert">${escapeHTML(message)}</p>` : ''}<form method="POST" action="/auth/login">${csrfField(token)}<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button>Sign in</button></form><p class="hint"><a href="/recover">Forgot password?</a> · Invite required</p>`); }
async function form(req) {
  let body = '';
  for await (const chunk of req) { body += chunk; if (body.length > 16384) throw new Error('Request too large'); }
  return Object.fromEntries(new URLSearchParams(body));
}

const html = await readFile(join(directory, 'index.html'), 'utf8');
const commissionData = await readFile(join(directory, 'commission-data.json'), 'utf8');
JSON.parse(commissionData);
const protectedHTML = html.replace("fetch('./commission-data.json'", "fetch('/api/commission-data'");

const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, origin).pathname;
    if (req.method === 'GET' && path === '/health') return send(res, 200, 'OK', 'text/plain');
    if (req.method === 'GET' && path === '/') return redirect(res, '/app');
    if (req.method === 'GET' && path === '/login') return send(res, 200, loginPage('', csrfToken(res)));
    const posted = req.method === 'POST' ? await form(req) : null;
    if (posted && !validPost(req, posted)) return send(res, 403, loginPage('Your form expired. Refresh this page and try again.', csrfToken(res)));
    if (req.method === 'POST' && path === '/auth/login') {
      const { email, password } = posted;
      if (!email || !password) return send(res, 400, loginPage('Enter your email and password.', csrfToken(res)));
      const result = await authRequest('/token?grant_type=password', { method: 'POST', body: JSON.stringify({ email, password }) });
      if (!result.ok || !result.data.access_token) return send(res, 401, loginPage('Invalid credentials or account not yet invited.', csrfToken(res)));
      setSession(res, result.data);
      return redirect(res, '/app');
    }
    if (req.method === 'GET' && path === '/auth/callback') {
      const token = csrfToken(res);
      return send(res, 200, page('Confirm account', `<h1>Completing sign-in…</h1><p id="status">Checking your invitation or recovery link.</p><script>const params=new URLSearchParams(location.hash.slice(1));history.replaceState(null,'','/auth/callback');if(!params.get('access_token')||!params.get('refresh_token')){document.getElementById('status').textContent='This link is invalid or expired. Request a new invitation or reset link.'}else fetch('/auth/session',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'${token}',access_token:params.get('access_token'),refresh_token:params.get('refresh_token'),expires_in:params.get('expires_in')||'3600'})}).then(async r=>{if(!r.ok)throw Error('Link expired');location.replace('/account/password')}).catch(()=>document.getElementById('status').textContent='This link is invalid or expired. Request a new invitation or reset link.')</script>`));
    }
    if (req.method === 'POST' && path === '/auth/session') {
      const data = posted;
      if (!data.access_token || !data.refresh_token || data.access_token.length > 8192 || data.refresh_token.length > 8192) return send(res, 400, 'Invalid session', 'text/plain');
      const result = await authRequest('/user', { headers: { Authorization: `Bearer ${data.access_token}` } });
      if (!result.ok || !result.data.id) return send(res, 401, 'Invalid session', 'text/plain');
      setSession(res, { ...data, expires_in: Number(data.expires_in) || 3600 });
      return send(res, 200, 'OK', 'text/plain');
    }
    if (req.method === 'GET' && path === '/recover') return send(res, 200, page('Reset password', `<h1>Reset your password</h1><p>We’ll send a link if your account exists.</p><form method="POST" action="/auth/recover">${csrfField(csrfToken(res))}<label for="email">Email</label><input id="email" name="email" type="email" required><button>Send reset link</button></form><p><a href="/login">Back to sign in</a></p>`));
    if (req.method === 'POST' && path === '/auth/recover') {
      const { email } = posted;
      if (email && email.length < 255) await authRequest(`/recover?redirect_to=${encodeURIComponent(origin + '/auth/callback')}`, { method: 'POST', body: JSON.stringify({ email }) });
      return send(res, 200, page('Check email', '<h1>Check your email</h1><p>If that address has an account, a reset link is on its way.</p><a href="/login">Return to sign in</a>'));
    }
    if (req.method === 'POST' && path === '/auth/logout') { clearSession(res); return redirect(res, '/login'); }
    if (['/app', '/api/commission-data', '/account/password', '/auth/password'].includes(path)) {
      const session = await userFromRequest(req, res);
      if (!session) return path.startsWith('/api/') ? send(res, 401, 'Sign in required', 'text/plain') : redirect(res, '/login');
      if (req.method === 'GET' && path === '/app') return send(res, 200, protectedHTML.replace('<body>', `<body><div style="display:flex;justify-content:flex-end;padding:10px 24px 0"><form method="POST" action="/auth/logout">${csrfField(csrfToken(res))}<button style="border:1px solid #38748e;border-radius:7px;background:#102a40;color:#e5f8ff;padding:7px 14px;cursor:pointer">Sign out</button></form></div>`));
      if (req.method === 'GET' && path === '/api/commission-data') return send(res, 200, commissionData, 'application/json; charset=utf-8');
      if (req.method === 'GET' && path === '/account/password') return send(res, 200, page('Set password', `<h1>Set your password</h1><p>Choose a password for your agent account.</p><form method="POST" action="/auth/password">${csrfField(csrfToken(res))}<label for="password">New password</label><input id="password" name="password" type="password" autocomplete="new-password" minlength="12" required><button>Save password</button></form>`));
      if (req.method === 'POST' && path === '/auth/password') {
        const { password } = posted;
        if (!password || password.length < 12 || password.length > 1024) return send(res, 400, page('Set password', '<h1>Password must be at least 12 characters.</h1><a href="/account/password">Try again</a>'));
        const result = await authRequest('/user', { method: 'PUT', headers: { Authorization: `Bearer ${session.access}` }, body: JSON.stringify({ password }) });
        if (!result.ok) return send(res, 400, page('Set password', '<h1>Could not update your password.</h1><a href="/account/password">Try again</a>'));
        return redirect(res, '/app');
      }
    }
    return send(res, 404, 'Not found', 'text/plain');
  } catch (error) {
    console.error('Request failed:', error);
    return send(res, 503, 'Service temporarily unavailable', 'text/plain');
  }
});

server.listen(Number(process.env.PORT) || 3000, () => console.log(`Protected calculator listening on port ${server.address().port}`));
