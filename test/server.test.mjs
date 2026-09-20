import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const auth = createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk;
  res.setHeader('Content-Type', 'application/json');
  if (req.url.startsWith('/auth/v1/token?grant_type=password')) {
    const { email, password } = JSON.parse(body);
    res.statusCode = email === 'invited@example.com' && password === 'correct-horse-battery' ? 200 : 400;
    return res.end(res.statusCode === 200 ? JSON.stringify({ access_token: 'valid-token', refresh_token: 'valid-refresh', expires_in: 3600 }) : '{}');
  }
  if (req.url.startsWith('/auth/v1/token?grant_type=refresh_token')) {
    res.statusCode = JSON.parse(body).refresh_token === 'valid-refresh' ? 200 : 401;
    return res.end(res.statusCode === 200 ? JSON.stringify({ access_token: 'valid-token', refresh_token: 'valid-refresh', expires_in: 3600 }) : '{}');
  }
  if (req.url === '/auth/v1/user') {
    res.statusCode = req.headers.authorization === 'Bearer valid-token' ? 200 : 401;
    return res.end(res.statusCode === 200 ? JSON.stringify({ id: 'agent-1' }) : '{}');
  }
  res.statusCode = 200;
  res.end('{}');
});

test('pilot access requires a real authenticated session and survives refresh', async () => {
  auth.listen(0, '127.0.0.1');
  await once(auth, 'listening');
  const authPort = auth.address().port;
  const appPort = authPort + 1;
  const base = `http://localhost:${appPort}`;
  const child = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('..', import.meta.url).pathname,
    env: { ...process.env, APP_ORIGIN: base, SUPABASE_URL: `http://localhost:${authPort}`, SUPABASE_PUBLISHABLE_KEY: 'test-key', PORT: String(appPort) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  try {
    await Promise.race([once(child.stdout, 'data'), once(child, 'exit').then(() => { throw new Error('Server exited'); })]);
    const request = (path, options = {}) => fetch(base + path, { redirect: 'manual', ...options });
    assert.equal((await request('/app')).status, 303);
    assert.equal((await request('/api/commission-data')).status, 401);
    assert.equal((await request('/api/commission-data', { headers: { Cookie: 'cc-access=forged' } })).status, 401);
    const forged = await request('/auth/session', { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ access_token: 'forged', refresh_token: 'valid-refresh' }) });
    assert.equal(forged.status, 401);
    const crossSite = await request('/auth/login', { method: 'POST', headers: { Origin: 'https://attacker.example', 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ email: 'invited@example.com', password: 'correct-horse-battery' }) });
    assert.equal(crossSite.status, 403);
    const login = await request('/auth/login', { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ email: 'invited@example.com', password: 'correct-horse-battery' }) });
    assert.equal(login.status, 303);
    const cookieHeader = login.headers.getSetCookie().map(item => item.split(';')[0]).join('; ');
    const page = await request('/app', { headers: { Cookie: cookieHeader } });
    assert.equal(page.status, 200);
    assert.match(await page.text(), /fetch\('\/api\/commission-data'/);
    const data = await request('/api/commission-data', { headers: { Cookie: cookieHeader } });
    assert.equal(data.status, 200);
    assert.ok((await data.json()).presets);
    const refreshed = await request('/api/commission-data', { headers: { Cookie: 'cc-access=expired; cc-refresh=valid-refresh' } });
    assert.equal(refreshed.status, 200);
    assert.ok(refreshed.headers.getSetCookie().some(item => item.startsWith('cc-access=valid-token')));
    const logout = await request('/auth/logout', { method: 'POST', headers: { Origin: base, 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookieHeader } });
    assert.equal(logout.status, 303);
    assert.ok(logout.headers.getSetCookie().some(item => item.includes('Max-Age=0')));
  } finally {
    child.kill();
    auth.close();
  }
});
