import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';

const storedSettings = new Map();
const agentOne = '11111111-1111-4111-8111-111111111111';
const agentTwo = '22222222-2222-4222-8222-222222222222';
const caseOne = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const caseTwo = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const storedCases = new Map([[agentOne, []], [agentTwo, []]]);
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
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    res.statusCode = id ? 200 : 401;
    return res.end(id ? JSON.stringify({ id }) : '{}');
  }
  if (req.url.startsWith('/rest/v1/agent_settings')) {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if (!id) { res.statusCode = 401; return res.end('{}'); }
    if (req.method === 'GET') return res.end(JSON.stringify(storedSettings.has(id) ? [{ settings: storedSettings.get(id) }] : []));
    const data = JSON.parse(body);
    if (data.user_id !== id) { res.statusCode = 403; return res.end('{}'); }
    storedSettings.set(id, data.settings);
    res.statusCode = 201;
    return res.end('{}');
  }
  if (req.url.startsWith('/rest/v1/saved_cases')) {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if (!id) { res.statusCode = 401; return res.end('{}'); }
    const records = storedCases.get(id);
    if (req.method === 'GET') return res.end(JSON.stringify([...records].reverse()));
    if (req.method === 'POST') {
      const data = JSON.parse(body);
      if (data.user_id !== id) { res.statusCode = 403; return res.end('{}'); }
      records.push({ ...data, id: id === agentOne ? caseOne : caseTwo, created_at: '2026-09-21T12:00:00.000Z' });
      res.statusCode = 201;
      return res.end('{}');
    }
    if (req.method === 'DELETE') {
      const requested = new URL(req.url, 'http://localhost').searchParams.get('id')?.replace(/^eq\./, '');
      const index = records.findIndex(item => item.id === requested);
      if (index >= 0) records.splice(index, 1);
      res.statusCode = 204;
      return res.end();
    }
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
    const loginForm = await request('/login');
    const token = (await loginForm.text()).match(/name="csrf" value="([a-f0-9]{64})"/)?.[1];
    assert.ok(token);
    const csrfCookie = loginForm.headers.getSetCookie().find(item => item.startsWith('cc-csrf='))?.split(';')[0];
    assert.ok(csrfCookie);
    const post = (path, data, headers = {}) => request(path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: csrfCookie, ...headers }, body: new URLSearchParams({ csrf: token, ...data }) });
    const forged = await post('/auth/session', { access_token: 'forged', refresh_token: 'valid-refresh' });
    assert.equal(forged.status, 401);
    const crossSite = await post('/auth/login', { email: 'invited@example.com', password: 'correct-horse-battery' }, { Origin: 'https://attacker.example' });
    assert.equal(crossSite.status, 403);
    const noToken = await request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ email: 'invited@example.com', password: 'correct-horse-battery' }) });
    assert.equal(noToken.status, 403);
    const login = await post('/auth/login', { email: 'invited@example.com', password: 'correct-horse-battery' }, { Origin: 'null' });
    assert.equal(login.status, 303);
    const cookieHeader = [csrfCookie, ...login.headers.getSetCookie().map(item => item.split(';')[0])].join('; ');
    const page = await request('/app', { headers: { Cookie: cookieHeader } });
    assert.equal(page.status, 200);
    const appHTML = await page.text();
    assert.match(appHTML, /fetch\('\/api\/commission-data'/);
    const data = await request('/api/commission-data', { headers: { Cookie: cookieHeader } });
    assert.equal(data.status, 200);
    assert.ok((await data.json()).presets);
    const refreshed = await request('/api/commission-data', { headers: { Cookie: 'cc-access=expired; cc-refresh=valid-refresh' } });
    assert.equal(refreshed.status, 200);
    assert.ok(refreshed.headers.getSetCookie().some(item => item.startsWith('cc-access=valid-token')));
    const appToken = appHTML.match(/name="csrf" value="([a-f0-9]{64})"/)?.[1];
    const appCsrfCookie = page.headers.getSetCookie().find(item => item.startsWith('cc-csrf='))?.split(';')[0];
    assert.ok(appToken && appCsrfCookie);
    const defaults = {caseType:'personal',carrier:'',product:'',option:'1',termLength:'',writingContract:'md',splitContract:'sa',overrideContract:'md',isSplit:false,splitWithDownline:false,mySplit:'50',otherSplit:'50',overridePercent:''};
    const ownCookie = `${cookieHeader}; ${appCsrfCookie}`;
    const settingsPost = (settings, cookie, csrf) => request('/api/settings', { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded', Cookie:cookie }, body:new URLSearchParams({ csrf, settings:JSON.stringify(settings) }) });
    const initial = await request('/api/settings', { headers:{Cookie:ownCookie} });
    assert.deepEqual(await initial.json(), {settings:null});
    assert.equal((await settingsPost(defaults, ownCookie, appToken)).status,200);
    assert.deepEqual(await (await request('/api/settings',{headers:{Cookie:ownCookie}})).json(),{settings:defaults});
    const otherPage = await request('/app',{headers:{Cookie:'cc-access=valid-token-two'}});
    const otherToken = (await otherPage.text()).match(/name="csrf" value="([a-f0-9]{64})"/)?.[1];
    const otherCookie = `cc-access=valid-token-two; ${otherPage.headers.getSetCookie().find(item => item.startsWith('cc-csrf='))?.split(';')[0]}`;
    assert.deepEqual(await (await request('/api/settings',{headers:{Cookie:otherCookie}})).json(),{settings:null});
    assert.equal((await settingsPost({...defaults,writingContract:'sa'},otherCookie,otherToken)).status,200);
    assert.deepEqual((await (await request('/api/settings',{headers:{Cookie:ownCookie}})).json()).settings,defaults);
    assert.equal((await request('/api/settings',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:ownCookie},body:new URLSearchParams({settings:JSON.stringify(defaults)})})).status,403);
    const savedCase = {client_name:'Sample Client',carrier:'Athene',product:'Performance Elite 7',commission:1729.43,monthly_trail:12.25,calculation:{caseType:'personal',productKey:'pe7'}};
    const casePost = (saved_case,cookie=ownCookie,csrf=appToken) => request('/api/cases',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams({csrf,saved_case:JSON.stringify(saved_case)})});
    assert.deepEqual(await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json(),[]);
    assert.equal((await casePost(savedCase)).status,201);
    const ownCases = await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json();
    assert.equal(ownCases.length,1);
    assert.equal(ownCases[0].client_name,'Sample Client');
    assert.deepEqual(await (await request('/api/cases',{headers:{Cookie:otherCookie}})).json(),[]);
    assert.equal((await casePost({...savedCase,client_name:'Other Agent'},otherCookie,otherToken)).status,201);
    assert.equal((await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json()).length,1);
    assert.equal((await request('/api/cases/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:otherCookie},body:new URLSearchParams({csrf:otherToken,id:caseOne})})).status,200);
    assert.equal((await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json()).length,1);
    assert.equal((await request('/api/cases/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:ownCookie},body:new URLSearchParams({csrf:appToken,id:caseOne})})).status,200);
    assert.deepEqual(await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json(),[]);
    assert.equal((await request('/api/cases',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:ownCookie},body:new URLSearchParams({saved_case:JSON.stringify(savedCase)})})).status,403);
    const logout = await request('/auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: `${cookieHeader}; ${appCsrfCookie}` }, body: new URLSearchParams({ csrf: appToken }) });
    assert.equal(logout.status, 303);
    assert.ok(logout.headers.getSetCookie().some(item => item.includes('Max-Age=0')));
  } finally {
    child.kill();
    auth.close();
  }
});
