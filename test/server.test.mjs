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
const inviteOne = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const requestOne = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const storedCases = new Map([[agentOne, []], [agentTwo, []]]);
const profiles = new Map();
const organizationInvites = [];
const uplineRequests = [];
const adminRoles = new Map([[agentOne, 'owner']]);
const adminAudit = [];
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
  if (req.url === '/rest/v1/rpc/get_my_admin_role' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if(!id){ res.statusCode=401; return res.end('{}'); }
    return res.end(JSON.stringify(adminRoles.get(id)||'agent'));
  }
  if (req.url === '/rest/v1/rpc/get_admin_dashboard' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    const role=adminRoles.get(id);
    if(!id||!role){ res.statusCode=403; return res.end('{}'); }
    return res.end(JSON.stringify({role,users:role==='owner'?[{user_id:agentOne,email:'invited@example.com',display_name:'Owner Agent',contract_level:'md',admin_role:'owner'},{user_id:agentTwo,email:'agent@example.com',display_name:'Second Agent',contract_level:'sa',admin_role:adminRoles.get(agentTwo)||'agent'}]:[],audit:role==='owner'?adminAudit:[]}));
  }
  if (req.url === '/rest/v1/rpc/set_admin_user_role' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if(adminRoles.get(id)!=='owner'){ res.statusCode=403; return res.end(JSON.stringify({message:'Owner access required'})); }
    const {p_user_id,p_role}=JSON.parse(body),previous=adminRoles.get(p_user_id)||'agent';
    if(p_role==='agent') adminRoles.delete(p_user_id); else adminRoles.set(p_user_id,p_role);
    adminAudit.unshift({id:adminAudit.length+1,actor_user_id:id,actor_name:'Owner Agent',action:'admin_role_changed',target_user_id:p_user_id,target_name:'Second Agent',previous_value:{role:previous},new_value:{role:p_role},created_at:new Date().toISOString()});
    return res.end(JSON.stringify({user_id:p_user_id,role:p_role}));
  }
  if (req.url.startsWith('/rest/v1/agent_profiles')) {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if (!id) { res.statusCode = 401; return res.end('{}'); }
    if (req.method === 'GET') return res.end(JSON.stringify(profiles.has(id) ? [{ user_id:id }] : []));
    if (req.method === 'POST') {
      const data=JSON.parse(body);
      if(data.user_id!==id){ res.statusCode=403; return res.end('{}'); }
      profiles.set(id,{...data,direct_upline_id:null}); res.statusCode=201; return res.end('{}');
    }
    if (req.method === 'PATCH') {
      const data=JSON.parse(body), current=profiles.get(id);
      if(!current){ res.statusCode=404; return res.end('{}'); }
      profiles.set(id,{...current,...data}); res.statusCode=204; return res.end();
    }
  }
  if (req.url === '/rest/v1/organization_invites' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if (!id || !profiles.has(id)) { res.statusCode=403; return res.end('{}'); }
    const data=JSON.parse(body), invite={...data,id:id===agentOne?inviteOne:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',claimed_by:null,used_at:null,created_at:new Date().toISOString()};
    organizationInvites.push(invite); res.statusCode=201; return res.end(JSON.stringify([invite]));
  }
  if (req.url === '/rest/v1/rpc/request_upline_link' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    const {p_code}=JSON.parse(body), invite=organizationInvites.find(item=>item.code===p_code&&!item.claimed_by&&!item.used_at);
    if(!id||!profiles.has(id)||!invite||invite.created_by===id||profiles.get(id).direct_upline_id){ res.statusCode=400; return res.end('{}'); }
    invite.claimed_by=id;
    const request={id:requestOne,agent_id:id,requested_upline_id:invite.created_by,invite_id:invite.id,status:'pending',created_at:new Date().toISOString()};
    uplineRequests.push(request); return res.end(JSON.stringify({request_id:request.id,status:'pending'}));
  }
  if (req.url === '/rest/v1/rpc/respond_upline_request' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    const {p_request_id,p_approve}=JSON.parse(body), request=uplineRequests.find(item=>item.id===p_request_id&&item.requested_upline_id===id&&item.status==='pending');
    if(!request){ res.statusCode=400; return res.end('{}'); }
    request.status=p_approve?'approved':'rejected';
    const invite=organizationInvites.find(item=>item.id===request.invite_id);
    if(p_approve){ profiles.get(request.agent_id).direct_upline_id=id; invite.used_at=new Date().toISOString(); }
    else invite.claimed_by=null;
    return res.end(JSON.stringify({request_id:request.id,status:request.status}));
  }
  if (req.url === '/rest/v1/rpc/get_organization_dashboard' && req.method === 'POST') {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if(!id){ res.statusCode=401; return res.end('{}'); }
    const own=profiles.get(id)||null, tree=[];
    const add=(user,depth=0)=>{ if(!user)return; tree.push({...user,user_id:user.user_id||[...profiles].find(([,p])=>p===user)?.[0],depth,personal_points:0,saved_case_count:0,descendant_count:0}); for(const [childId,child] of profiles) if(child.direct_upline_id===(user.user_id||id)) add({...child,user_id:childId},depth+1); };
    if(own) add({...own,user_id:id});
    for(const node of tree) node.descendant_count=tree.filter(item=>item.depth>node.depth&&item.user_id!==node.user_id).length;
    const incoming=uplineRequests.filter(item=>item.requested_upline_id===id&&item.status==='pending').map(item=>({id:item.id,agent_id:item.agent_id,agent_name:profiles.get(item.agent_id).display_name,contract_level:profiles.get(item.agent_id).contract_level,created_at:item.created_at}));
    const outgoing=uplineRequests.find(item=>item.agent_id===id&&item.status==='pending');
    const active=organizationInvites.filter(item=>item.created_by===id&&!item.claimed_by&&!item.used_at).at(-1)||null;
    return res.end(JSON.stringify({profile:own?{...own,user_id:id,direct_upline_name:own.direct_upline_id?profiles.get(own.direct_upline_id)?.display_name:null}:null,tree,incoming_requests:incoming,outgoing_request:outgoing?{id:outgoing.id,upline_name:profiles.get(outgoing.requested_upline_id).display_name,status:'pending'}:null,active_invite:active}));
  }
  if (req.url.startsWith('/rest/v1/saved_cases')) {
    const id = req.headers.authorization === 'Bearer valid-token' ? agentOne : req.headers.authorization === 'Bearer valid-token-two' ? agentTwo : null;
    if (!id) { res.statusCode = 401; return res.end('{}'); }
    const records = storedCases.get(id);
    if (req.method === 'GET') return res.end(JSON.stringify([...records].reverse()));
    if (req.method === 'POST') {
      const data = JSON.parse(body);
      if (data.user_id !== id) { res.statusCode = 403; return res.end('{}'); }
      records.push({ ...data, stage:data.stage||'prospect', id: id === agentOne ? caseOne : caseTwo, created_at: '2026-09-21T12:00:00.000Z' });
      res.statusCode = 201;
      return res.end('{}');
    }
    if (req.method === 'PATCH') {
      const requested = new URL(req.url, 'http://localhost').searchParams.get('id')?.replace(/^eq\./, '');
      const record = records.find(item => item.id === requested);
      if (record) Object.assign(record, JSON.parse(body));
      res.statusCode = 204;
      return res.end();
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
    assert.equal((await request('/api/organization')).status, 401);
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
    assert.match(appHTML, /data-admin-role="owner"/);
    const adminDashboard=await request('/api/admin',{headers:{Cookie:cookieHeader}});
    assert.equal(adminDashboard.status,200);
    assert.equal((await adminDashboard.json()).role,'owner');
    const data = await request('/api/commission-data', { headers: { Cookie: cookieHeader } });
    assert.equal(data.status, 200);
    assert.ok((await data.json()).presets);
    const refreshed = await request('/api/commission-data', { headers: { Cookie: 'cc-access=expired; cc-refresh=valid-refresh' } });
    assert.equal(refreshed.status, 200);
    assert.ok(refreshed.headers.getSetCookie().some(item => item.startsWith('cc-access=valid-token')));
    const appToken = appHTML.match(/name="csrf" value="([a-f0-9]{64})"/)?.[1];
    const appCsrfCookie = page.headers.getSetCookie().find(item => item.startsWith('cc-csrf='))?.split(';')[0];
    assert.ok(appToken && appCsrfCookie);
    const defaults = {theme:'dark',caseType:'personal',carrier:'',product:'',option:'1',termLength:'',writingContract:'md',splitContract:'sa',overrideContract:'md',isSplit:false,splitWithDownline:false,mySplit:'50',otherSplit:'50',overridePercent:''};
    const ownCookie = `${cookieHeader}; ${appCsrfCookie}`;
    const adminGrant=await request('/api/admin/role',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:ownCookie},body:new URLSearchParams({csrf:appToken,user_id:agentTwo,role:'data_admin'})});
    assert.equal(adminGrant.status,200);
    const secondAdminPage=await request('/app',{headers:{Cookie:'cc-access=valid-token-two'}});
    assert.equal(secondAdminPage.status,200);
    assert.match(await secondAdminPage.text(),/data-admin-role="data_admin"/);
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
    const organizationPost=(path,data,cookie=ownCookie,csrf=appToken)=>request(path,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams({csrf,...data})});
    assert.deepEqual((await (await request('/api/organization',{headers:{Cookie:ownCookie}})).json()).tree,[]);
    assert.equal((await organizationPost('/api/organization/profile',{display_name:'Test SMD',contract_level:'smd'})).status,200);
    assert.equal((await organizationPost('/api/organization/profile',{display_name:'Test Associate',contract_level:'associate'},otherCookie,otherToken)).status,200);
    const inviteResponse=await organizationPost('/api/organization/invite',{});
    assert.equal(inviteResponse.status,201);
    const inviteCode=(await inviteResponse.json())[0].code;
    assert.match(inviteCode,/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    assert.equal((await organizationPost('/api/organization/request',{code:inviteCode})).status,400);
    assert.equal((await organizationPost('/api/organization/request',{code:inviteCode},otherCookie,otherToken)).status,200);
    const pendingUpline=await (await request('/api/organization',{headers:{Cookie:ownCookie}})).json();
    assert.equal(pendingUpline.incoming_requests.length,1);
    const pendingDownline=await (await request('/api/organization',{headers:{Cookie:otherCookie}})).json();
    assert.equal(pendingDownline.tree.length,1);
    assert.equal(pendingDownline.outgoing_request.upline_name,'Test SMD');
    assert.equal((await organizationPost('/api/organization/respond',{id:requestOne,decision:'approve'},otherCookie,otherToken)).status,400);
    assert.equal((await organizationPost('/api/organization/respond',{id:requestOne,decision:'approve'})).status,200);
    const approvedUpline=await (await request('/api/organization',{headers:{Cookie:ownCookie}})).json();
    assert.equal(approvedUpline.tree.length,2);
    assert.equal(approvedUpline.tree.find(item=>item.user_id===agentTwo).direct_upline_id,agentOne);
    const approvedDownline=await (await request('/api/organization',{headers:{Cookie:otherCookie}})).json();
    assert.equal(approvedDownline.tree.length,1);
    assert.equal(approvedDownline.profile.direct_upline_name,'Test SMD');
    const savedCase = {client_name:'Sample Client',carrier:'Athene',product:'Performance Elite 7',commission:1729.43,agent_points:3458.85,monthly_trail:12.25,calculation:{caseType:'personal',productKey:'pe7'}};
    const casePost = (saved_case,cookie=ownCookie,csrf=appToken) => request('/api/cases',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:cookie},body:new URLSearchParams({csrf,saved_case:JSON.stringify(saved_case)})});
    assert.deepEqual(await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json(),[]);
    assert.equal((await casePost(savedCase)).status,201);
    const ownCases = await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json();
    assert.equal(ownCases.length,1);
    assert.equal(ownCases[0].client_name,'Sample Client');
    assert.equal(ownCases[0].agent_points,3458.85);
    assert.equal(ownCases[0].stage,'prospect');
    assert.equal((await request('/api/cases/stage',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:ownCookie},body:new URLSearchParams({csrf:appToken,id:caseOne,stage:'issued'})})).status,200);
    assert.equal((await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json())[0].stage,'issued');
    assert.equal((await request('/api/cases/stage',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded',Cookie:otherCookie},body:new URLSearchParams({csrf:otherToken,id:caseOne,stage:'paid'})})).status,200);
    assert.equal((await (await request('/api/cases',{headers:{Cookie:ownCookie}})).json())[0].stage,'issued');
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
