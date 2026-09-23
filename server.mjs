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
async function settingsRequest(access, options = {}) {
  return fetch(`${supabase}/rest/v1/agent_settings?select=settings`, {
    ...options,
    headers: { apikey: key, Authorization: `Bearer ${access}`, ...options.headers },
    signal: AbortSignal.timeout(8000)
  });
}
async function savedCasesRequest(access, query = '', options = {}) {
  return fetch(`${supabase}/rest/v1/saved_cases${query}`, {
    ...options,
    headers: { apikey: key, Authorization: `Bearer ${access}`, ...options.headers },
    signal: AbortSignal.timeout(8000)
  });
}
async function organizationRequest(access, path, options = {}) {
  return fetch(`${supabase}/rest/v1${path}`, {
    ...options,
    headers: { apikey: key, Authorization: `Bearer ${access}`, ...options.headers },
    signal: AbortSignal.timeout(8000)
  });
}
function newInviteCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(8);
  const chars = [...bytes].map(byte => alphabet[byte % alphabet.length]);
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
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
function validCsrfHeader(req) {
  if (req.headers.origin && req.headers.origin !== 'null' && req.headers.origin !== origin) return false;
  const expected = cookies(req)[cookieName('csrf')];
  const supplied = req.headers['x-csrf-token'];
  if (!expected || typeof supplied !== 'string' || !/^[a-f0-9]{64}$/.test(expected) || !/^[a-f0-9]{64}$/.test(supplied)) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(supplied, 'hex'));
}
async function binaryBody(req, limit = 2097152) {
  const chunks=[]; let size=0;
  for await (const chunk of req) { size += chunk.length; if (size > limit) throw new Error('Image too large'); chunks.push(chunk); }
  return Buffer.concat(chunks);
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
    const avatarMatch = path.match(/^\/api\/organization\/avatar\/([0-9a-f-]{36})$/i);
    if (req.method === 'GET' && avatarMatch) {
      const session = await userFromRequest(req, res);
      if (!session) return send(res, 401, 'Sign in required', 'text/plain');
      const target = avatarMatch[1];
      const avatar = await fetch(`${supabase}/storage/v1/object/authenticated/agent-avatars/${encodeURIComponent(target)}/avatar`, {
        headers: { apikey:key, Authorization:`Bearer ${session.access}` },
        signal: AbortSignal.timeout(8000)
      });
      if (!avatar.ok) return send(res, avatar.status === 404 ? 404 : 403, 'Avatar unavailable', 'text/plain');
      const bytes=Buffer.from(await avatar.arrayBuffer());
      res.writeHead(200, {'Content-Type':avatar.headers.get('content-type')||'application/octet-stream','Content-Length':bytes.length,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});
      return res.end(bytes);
    }
    if (req.method === 'POST' && path === '/api/organization/avatar') {
      if (!validCsrfHeader(req)) return send(res, 403, 'Invalid form token', 'text/plain');
      const session = await userFromRequest(req, res);
      if (!session) return send(res, 401, 'Sign in required', 'text/plain');
      const contentType=(req.headers['content-type']||'').split(';')[0].trim().toLowerCase();
      if (!['image/jpeg','image/png','image/webp'].includes(contentType)) return send(res, 415, 'Use a JPEG, PNG, or WebP image', 'text/plain');
      const image=await binaryBody(req,2097152);
      if (!image.length) return send(res, 400, 'Choose an image', 'text/plain');
      const validImage=(contentType==='image/jpeg'&&image[0]===0xff&&image[1]===0xd8&&image[2]===0xff) ||
        (contentType==='image/png'&&image.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))) ||
        (contentType==='image/webp'&&image.subarray(0,4).toString()==='RIFF'&&image.subarray(8,12).toString()==='WEBP');
      if(!validImage) return send(res,400,'The optimized profile picture is invalid','text/plain');
      const objectPath=`${session.user.id}/avatar`;
      const uploaded=await fetch(`${supabase}/storage/v1/object/agent-avatars/${objectPath}`, {
        method:'POST',
        headers:{apikey:key,Authorization:`Bearer ${session.access}`,'Content-Type':contentType,'x-upsert':'true'},
        body:image,
        signal:AbortSignal.timeout(12000)
      });
      if (!uploaded.ok) return send(res, 503, 'Could not upload profile picture', 'text/plain');
      const updated=await organizationRequest(session.access,`/agent_profiles?user_id=eq.${encodeURIComponent(session.user.id)}`,{
        method:'PATCH',headers:{'Content-Type':'application/json',Prefer:'return=minimal'},body:JSON.stringify({avatar_path:objectPath,updated_at:new Date().toISOString()})
      });
      return updated.ok ? send(res,200,'Uploaded','text/plain') : send(res,503,'Picture uploaded but profile could not be updated','text/plain');
    }
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
    if (['/app', '/api/commission-data', '/api/settings', '/api/cases', '/api/cases/stage', '/api/cases/delete', '/api/organization', '/api/organization/profile', '/api/organization/invite', '/api/organization/request', '/api/organization/respond', '/account/password', '/auth/password'].includes(path)) {
      const session = await userFromRequest(req, res);
      if (!session) return path.startsWith('/api/') ? send(res, 401, 'Sign in required', 'text/plain') : redirect(res, '/login');
      if (req.method === 'GET' && path === '/app') return send(res, 200, protectedHTML.replace('<body>', `<body><div class="account-bar"><form method="POST" action="/auth/logout">${csrfField(csrfToken(res))}<button class="sign-out-button">Sign out</button></form></div>`));
      if (req.method === 'GET' && path === '/api/commission-data') return send(res, 200, commissionData, 'application/json; charset=utf-8');
      if (path === '/api/settings' && req.method === 'GET') {
        const result = await settingsRequest(session.access);
        if (!result.ok) return send(res, 503, 'Settings unavailable', 'text/plain');
        const rows = await result.json();
        return send(res, 200, JSON.stringify({ settings: rows[0]?.settings ?? null }), 'application/json; charset=utf-8');
      }
      if (path === '/api/settings' && req.method === 'POST') {
        let settings;
        try { settings = JSON.parse(posted.settings); } catch { return send(res, 400, 'Invalid settings', 'text/plain'); }
        if (settings && !Array.isArray(settings) && typeof settings === 'object' && settings.theme === undefined) settings.theme = 'dark';
        const names = ['theme','caseType','carrier','product','option','termLength','writingContract','splitContract','overrideContract','isSplit','splitWithDownline','mySplit','otherSplit','overridePercent'];
        if (!settings || Array.isArray(settings) || typeof settings !== 'object' ||
            Object.keys(settings).some(name => !names.includes(name)) ||
            !['dark','light'].includes(settings.theme) ||
            names.some(name => typeof settings[name] !== (['isSplit','splitWithDownline'].includes(name) ? 'boolean' : 'string') || (typeof settings[name] === 'string' && settings[name].length > 100)))
          return send(res, 400, 'Invalid settings', 'text/plain');
        const result = await settingsRequest(session.access, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Prefer: 'resolution=merge-duplicates,return=minimal' },
          body: JSON.stringify({ user_id: session.user.id, settings })
        });
        return result.ok ? send(res, 200, 'Saved', 'text/plain') : send(res, 503, 'Could not save settings', 'text/plain');
      }
      if (path === '/api/cases' && req.method === 'GET') {
        const result = await savedCasesRequest(session.access, '?select=id,client_name,carrier,product,commission,agent_points,monthly_trail,stage,calculation,created_at&order=created_at.desc');
        if (!result.ok) return send(res, 503, 'Saved cases unavailable', 'text/plain');
        return send(res, 200, await result.text(), 'application/json; charset=utf-8');
      }
      if (path === '/api/cases' && req.method === 'POST') {
        let savedCase;
        try { savedCase = JSON.parse(posted.saved_case); } catch { return send(res, 400, 'Invalid saved case', 'text/plain'); }
        const clean = {
          client_name: typeof savedCase?.client_name === 'string' ? savedCase.client_name.trim() : '',
          carrier: typeof savedCase?.carrier === 'string' ? savedCase.carrier.trim() : '',
          product: typeof savedCase?.product === 'string' ? savedCase.product.trim() : '',
          commission: Number(savedCase?.commission),
          agent_points: Number(savedCase?.agent_points),
          monthly_trail: Number(savedCase?.monthly_trail || 0),
          calculation: savedCase?.calculation,
          stage: 'prospect'
        };
        if (!clean.client_name || clean.client_name.length > 120 || !clean.carrier || clean.carrier.length > 100 ||
            !clean.product || clean.product.length > 160 || !Number.isFinite(clean.commission) || clean.commission < 0 || clean.commission > 100000000 ||
            !Number.isFinite(clean.agent_points) || clean.agent_points < 0 || clean.agent_points > 100000000 ||
            !Number.isFinite(clean.monthly_trail) || clean.monthly_trail < 0 || clean.monthly_trail > 10000000 ||
            !clean.calculation || Array.isArray(clean.calculation) || typeof clean.calculation !== 'object' || Object.keys(clean.calculation).length > 40)
          return send(res, 400, 'Invalid saved case', 'text/plain');
        const result = await savedCasesRequest(session.access, '', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify({ user_id: session.user.id, ...clean })
        });
        return result.ok ? send(res, 201, 'Saved', 'text/plain') : send(res, 503, 'Could not save case', 'text/plain');
      }
      if (path === '/api/cases/stage' && req.method === 'POST') {
        const id = posted.id || '', stage = posted.stage || '';
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id) || !['prospect','submitted','issued','paid','lost'].includes(stage)) return send(res, 400, 'Invalid case stage', 'text/plain');
        const result = await savedCasesRequest(session.access, `?id=eq.${encodeURIComponent(id)}`, { method:'PATCH', headers:{'Content-Type':'application/json','Prefer':'return=minimal'}, body:JSON.stringify({stage}) });
        return result.ok ? send(res, 200, 'Updated', 'text/plain') : send(res, 503, 'Could not update case', 'text/plain');
      }
      if (path === '/api/cases/delete' && req.method === 'POST') {
        const id = posted.id || '';
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) return send(res, 400, 'Invalid case', 'text/plain');
        const result = await savedCasesRequest(session.access, `?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE' });
        return result.ok ? send(res, 200, 'Deleted', 'text/plain') : send(res, 503, 'Could not delete case', 'text/plain');
      }
      if (path === '/api/organization' && req.method === 'GET') {
        const result = await organizationRequest(session.access, '/rpc/get_organization_dashboard', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}'
        });
        if (!result.ok) return send(res, 503, 'Organization unavailable', 'text/plain');
        return send(res, 200, await result.text(), 'application/json; charset=utf-8');
      }
      if (path === '/api/organization/profile' && req.method === 'POST') {
        const displayName = typeof posted.display_name === 'string' ? posted.display_name.trim().replace(/\s+/g, ' ') : '';
        const contractLevel = posted.contract_level || '';
        if (displayName.length < 2 || displayName.length > 100 || !['ta','associate','sa','md','smd'].includes(contractLevel))
          return send(res, 400, 'Invalid agent profile', 'text/plain');
        const existing = await organizationRequest(session.access, `/agent_profiles?select=user_id&user_id=eq.${encodeURIComponent(session.user.id)}`);
        if (!existing.ok) return send(res, 503, 'Could not read agent profile', 'text/plain');
        const rows = await existing.json();
        const result = rows.length ? await organizationRequest(session.access, `/agent_profiles?user_id=eq.${encodeURIComponent(session.user.id)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify({ display_name: displayName, contract_level: contractLevel, updated_at: new Date().toISOString() })
        }) : await organizationRequest(session.access, '/agent_profiles', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify({ user_id: session.user.id, display_name: displayName, contract_level: contractLevel })
        });
        return result.ok ? send(res, 200, 'Saved', 'text/plain') : send(res, 503, 'Could not save agent profile', 'text/plain');
      }
      if (path === '/api/organization/invite' && req.method === 'POST') {
        let result;
        for (let attempt = 0; attempt < 3; attempt++) {
          const code = newInviteCode();
          result = await organizationRequest(session.access, '/organization_invites', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Prefer: 'return=representation' },
            body: JSON.stringify({ created_by: session.user.id, code, expires_at: new Date(Date.now() + 7 * 86400000).toISOString() })
          });
          if (result.ok) return send(res, 201, await result.text(), 'application/json; charset=utf-8');
          if (result.status !== 409) break;
        }
        return send(res, result?.status === 403 ? 400 : 503, 'Could not create invitation', 'text/plain');
      }
      if (path === '/api/organization/request' && req.method === 'POST') {
        const code = String(posted.code || '').trim().toUpperCase();
        if (!/^[A-Z2-9]{4}-[A-Z2-9]{4}$/.test(code)) return send(res, 400, 'Enter a valid invitation code', 'text/plain');
        const result = await organizationRequest(session.access, '/rpc/request_upline_link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ p_code: code })
        });
        return result.ok ? send(res, 200, await result.text(), 'application/json; charset=utf-8') : send(res, 400, 'Invitation could not be requested', 'text/plain');
      }
      if (path === '/api/organization/respond' && req.method === 'POST') {
        const id = posted.id || '';
        const approve = posted.decision === 'approve';
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id) || !['approve','reject'].includes(posted.decision))
          return send(res, 400, 'Invalid upline request', 'text/plain');
        const result = await organizationRequest(session.access, '/rpc/respond_upline_request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ p_request_id: id, p_approve: approve })
        });
        return result.ok ? send(res, 200, await result.text(), 'application/json; charset=utf-8') : send(res, 400, 'Request could not be updated', 'text/plain');
      }
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
