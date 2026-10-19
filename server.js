// ================================================================
// MOOE FMIS — local server
// Zero external dependencies (uses only Node's built-in modules),
// so it runs with a plain `node server.js` — no `npm install` needed.
//
// PRIVACY MODEL (important):
//   - Admin and every User account each have their OWN private budget
//     data (categories, allocations, ledger, yearly fund, and the
//     change history for those). No account can see another account's
//     entries — not other Users', and not even Admin's.
//   - What Admin CAN see is account-level activity: who signed up,
//     who signed in (successful or failed) and from what IP, and who
//     is currently signed in right now. That's account security
//     monitoring, kept completely separate from the private budget
//     data itself.
//   - Passwords are hashed on the server (scrypt) and never trusted
//     from — or sent back to — the browser.
//
// Run with:   node server.js
// Then open:  http://localhost:3000
// ================================================================

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; // listen on all interfaces so it also works once deployed
const DATA_FILE = path.join(__dirname, 'data.json');
const INDEX_FILE = path.join(__dirname, 'index.html');

// ----------------------------------------------------------------
// Default categories — mirrors the client's built-in list. Every
// new account (Admin at setup, each User at sign-up) starts with
// its own fresh copy of these.
// ----------------------------------------------------------------
const DEFAULT_CATEGORIES = [
  {code:"2010101000", name:"Accounts Payable"},
  {code:"2020101000", name:"Due to BIR"},
  {code:"5020101000", name:"Traveling Expenses- Local"},
  {code:"5020201000", name:"Training Expenses"},
  {code:"5020301000", name:"Office Supplies Expenses"},
  {code:"5020302000", name:"Accountable Forms Expenses"},
  {code:"5020307000", name:"Drugs and Medicines Expenses"},
  {code:"5020308000", name:"Medical, Dental and Laboratory Supplies Expenses"},
  {code:"5020309000", name:"Fuel, oil and Lubricants Expenses"},
  {code:"5020321000", name:"Semi-Expandable Machinery and Equipment Expenses"},
  {code:"5020321001", name:"Machinery"},
  {code:"5020321002", name:"Office Equipment"},
  {code:"5020321003", name:"Information and Communication Technology Equipment"},
  {code:"5020321010", name:"Medical Equipment"},
  {code:"5020321011", name:"Printing Equipment"},
  {code:"5020321012", name:"Sports Equipment"},
  {code:"5020321099", name:"Other Machinery and Equipment"},
  {code:"5020322000", name:"Semi-Expandable Furniture, Fixtures and Books Expenses"},
  {code:"5020322001", name:"Furniture and Fixtures"},
  {code:"5020399000", name:"Other Supplies and Materials Expenses"},
  {code:"5020401000", name:"Water Expenses"},
  {code:"5020402000", name:"Electricity Expenses"},
  {code:"5020499000", name:"Other Utility Expenses"},
  {code:"5020502000", name:"Telephone Expenses"},
  {code:"5020502001", name:"Mobile"},
  {code:"5020503000", name:"Internet Subscription Expenses"},
  {code:"5021199000", name:"Other Professional Services"},
  {code:"5021202000", name:"Janitorial Services"},
  {code:"5021203000", name:"Security Services"},
  {code:"5021299000", name:"Other General Services"},
  {code:"5021304002", name:"School Buildings"},
  {code:"502130500", name:"Repairs and Maintenance-Machinery and Equipment"},
  {code:"5021321000", name:"Repairs and Maintenance-Semi-Expandable Machinery and Equipment"},
  {code:"5021502000", name:"Fidelity Bond Premiums"},
  {code:"5021601000", name:"Labor and Wages"}
];

function defaultTables(){
  return {
    schoolYear: "2026–2027",
    schoolName: "San Leonardo Elementary School",
    schoolId: "",
    schoolInfoConfirmed: false,
    categories: DEFAULT_CATEGORIES.map(c => ({code:c.code, name:c.name})),
    allocations: {},
    ledger: [],
    auditLog: [],
    yearlyFund: []
  };
}

function defaultData(){
  return {
    schemaVersion: 3,
    admin: null, // { email, salt, hash, tables }
    users: [],   // { id, name, username, email, salt, hash, status, access('full'|'view'), createdAt, statusUpdatedAt, lastSignInAt, lastSignInIp, resetOtp, tables }
    accessLog: [] // admin-only: sign-ups, sign-ins (success/fail), account changes — never budget data
  };
}

// ----------------------------------------------------------------
// Storage — a single JSON file. Simple and dependency-free; fine
// for a small school system with a handful of concurrent users.
// ----------------------------------------------------------------
function loadStore(){
  try{
    if(fs.existsSync(DATA_FILE)){
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      const d = defaultData();
      // Migrating from an older, pre-privacy version of this server
      // (schemaVersion 2) where everyone shared one set of tables:
      // give the Admin account that old shared data as a starting
      // point, and give every existing User a fresh, empty, private
      // set instead of the old shared one (so nothing they didn't
      // enter themselves ends up looking like it's theirs).
      const isLegacy = (parsed.schemaVersion || 2) < 3 && parsed.tables;
      const admin = parsed.admin
        ? Object.assign({}, parsed.admin, {tables: Object.assign(defaultTables(), (parsed.admin.tables) || (isLegacy ? parsed.tables : {}))})
        : d.admin;
      const users = (parsed.users || []).map(u => Object.assign({}, u, {tables: Object.assign(defaultTables(), u.tables || {})}));
      return {
        schemaVersion: d.schemaVersion,
        admin,
        users,
        accessLog: parsed.accessLog || (isLegacy ? (parsed.tables.auditLog || []) : [])
      };
    }
  }catch(e){
    console.error('Could not read data.json, starting fresh:', e.message);
  }
  return defaultData();
}

let store = loadStore();

function persist(){
  try{
    fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2));
  }catch(err){
    console.error('Failed to write data.json:', err.message);
  }
}

// ----------------------------------------------------------------
// Password hashing (scrypt, built into Node — no dependency needed)
// ----------------------------------------------------------------
function hashPassword(password){
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return {salt, hash};
}
function verifyPassword(password, salt, hash){
  if(!salt || !hash) return false;
  const check = crypto.scryptSync(String(password || ''), salt, 64).toString('hex');
  try{
    return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex'));
  }catch(e){ return false; }
}
function genId(prefix){ return (prefix||'e') + crypto.randomBytes(6).toString('hex'); }
function nowISO(){ return new Date().toISOString(); }
function genOtp(){ return String(Math.floor(100000 + Math.random() * 900000)); }

// ----------------------------------------------------------------
// Optional: create the Admin account from environment variables at
// startup, instead of through the browser's first-visit form. Useful
// when deploying somewhere you set config through environment
// variables rather than clicking through a UI (Render, Railway, a
// Docker Compose file, etc.) Only runs if no Admin account exists yet.
//
//   ADMIN_EMAIL=admin@school.edu.ph ADMIN_PASSWORD=your-password node server.js
//
// ----------------------------------------------------------------
if(!store.admin && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD){
  const bootstrapHash = hashPassword(process.env.ADMIN_PASSWORD);
  store.admin = {email: process.env.ADMIN_EMAIL, salt: bootstrapHash.salt, hash: bootstrapHash.hash, tables: defaultTables()};
  logAccessEvent('admin_setup', `Admin account created from server environment variables (${process.env.ADMIN_EMAIL})`, 'Admin');
  persist();
  console.log(`Admin account created from ADMIN_EMAIL/ADMIN_PASSWORD (${process.env.ADMIN_EMAIL}).`);
}

// ----------------------------------------------------------------
// Sessions — an in-memory map from a random cookie token to who is
// signed in. This resets if the server restarts (everyone would need
// to sign in again), but sign-in HISTORY is written into the access
// log below, so that record survives restarts.
// ----------------------------------------------------------------
const sessions = new Map(); // token -> {role, username, userId, ip, loginAt}
const SESSION_COOKIE = 'mooe_session';

function getClientIp(req){
  const fwd = req.headers['x-forwarded-for'];
  if(fwd) return fwd.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}
function parseCookies(req){
  const header = req.headers.cookie;
  const out = {};
  if(!header) return out;
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if(idx > -1) out[part.slice(0,idx).trim()] = decodeURIComponent(part.slice(idx+1).trim());
  });
  return out;
}
function getSession(req){
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];
  if(token && sessions.has(token)) return {token, data: sessions.get(token)};
  return null;
}
function isHttpsRequest(req){
  // Render and most hosts terminate TLS at a proxy and forward plain
  // HTTP internally, so req.socket.encrypted alone won't show it —
  // check the standard forwarded-proto header too.
  if(req.socket && req.socket.encrypted) return true;
  const proto = req.headers['x-forwarded-proto'];
  return !!proto && proto.split(',')[0].trim() === 'https';
}
function createSession(req, res, role, username, ip, userId){
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, {role, username: username || null, userId: userId || null, ip, loginAt: nowISO()});
  const secure = isHttpsRequest(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60*60*12}${secure}`);
  return token;
}
function destroySession(req, res){
  const s = getSession(req);
  if(s) sessions.delete(s.token);
  const secure = isHttpsRequest(req) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`);
}

// Returns the private tables object belonging to whoever this
// session is signed in as — this is the ONLY thing /api/app-data
// ever reads or writes, so one account can never see or touch
// another's budget data.
function getAccountTables(session){
  if(!session) return null;
  if(session.data.role === 'admin') return store.admin ? store.admin.tables : null;
  if(session.data.role === 'user'){
    const user = (store.users||[]).find(u => u.id === session.data.userId);
    if(!user) return null;
    if(usesAdminData(user)) return store.admin ? store.admin.tables : null;
    return user.tables;
  }
  return null;
}

// ----------------------------------------------------------------
// Access log — admin-only visibility into WHO is using the system
// and WHEN (sign-ups, sign-ins, failed attempts, account changes).
// This never contains budget/ledger data — that stays private to
// each account, see getAccountTables() above.
// ----------------------------------------------------------------
function logAccessEvent(action, detail, actor){
  store.accessLog.unshift({id: genId('log'), ts: nowISO(), action, detail, actor: actor || 'System'});
  if(store.accessLog.length > 500) store.accessLog.length = 500;
}

function mergeAuditLogs(existing, incoming){
  const map = new Map();
  (existing||[]).forEach(e => { if(e && e.id) map.set(e.id, e); });
  (incoming||[]).forEach(e => { if(e && e.id) map.set(e.id, e); });
  let merged = Array.from(map.values());
  merged.sort((a,b) => (b.ts||'').localeCompare(a.ts||''));
  if(merged.length > 500) merged = merged.slice(0,500);
  return merged;
}

function findUserByUsername(username){
  const lower = String(username||'').toLowerCase();
  return (store.users||[]).find(u => String(u.username||'').toLowerCase() === lower) || null;
}

const USER_ACTIVE_DAYS_LIMIT = 30;
function autoDeactivateExpiredUsers(){
  const limitMs = USER_ACTIVE_DAYS_LIMIT * 24 * 60 * 60 * 1000;
  const now = Date.now();
  let changed = false;
  (store.users||[]).forEach(u => {
    if(u.status === 'active' && u.statusUpdatedAt){
      const activatedAt = new Date(u.statusUpdatedAt).getTime();
      if(!isNaN(activatedAt) && (now - activatedAt) >= limitMs){
        u.status = 'deactivated';
        u.statusUpdatedAt = nowISO();
        logAccessEvent('user_auto_deactivate', `${u.name||u.username||'User'} (${u.username}) automatically deactivated after ${USER_ACTIVE_DAYS_LIMIT} days`);
        changed = true;
      }
    }
  });
  if(changed) persist();
}

// Accounts whose username is one of these roles work on the ADMIN's records
// (not a private budget of their own). What they may do there — view only or
// full access — is the Admin's choice in System Users. They never get the
// Admin's account-management tools (System Users, monitor, access log).
const ADMIN_DATA_USERNAMES = ['PRINCIPAL', 'SCHOOLHEAD', 'ADMINOFFICERII', 'ADMINASSTIII', 'ADMINASSTII'];
function usesAdminData(u){
  if(!u) return false;
  const key = String(u.username || '').toUpperCase().replace(/[\s_\-\.]+/g, '');
  return ADMIN_DATA_USERNAMES.includes(key);
}

// 'view' = view-only account (can read its own records, cannot change them);
// anything else (including accounts created before this feature) = full access.
function accessOf(u){ return (u && u.access === 'view') ? 'view' : 'full'; }
function sessionAccess(session){
  if(!session || session.data.role !== 'user') return 'full';
  const user = (store.users||[]).find(u => u.id === session.data.userId);
  return accessOf(user);
}

function sessionAdminData(session){
  if(!session || session.data.role !== 'user') return false;
  return usesAdminData((store.users||[]).find(u => u.id === session.data.userId));
}

function publicUser(u){
  // Account metadata only — never credentials, never their private
  // budget data (u.tables is deliberately left out here).
  return {
    id: u.id, name: u.name, username: u.username, email: u.email,
    status: u.status, access: u.access === 'view' ? 'view' : 'full', adminData: usesAdminData(u), createdAt: u.createdAt, statusUpdatedAt: u.statusUpdatedAt,
    lastSignInAt: u.lastSignInAt || null, lastSignInIp: u.lastSignInIp || null
  };
}

// ----------------------------------------------------------------
// Tiny request helpers
// ----------------------------------------------------------------
function readJsonBody(req){
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if(data.length > 10*1024*1024) req.destroy(); });
    req.on('end', () => {
      try{ resolve(data ? JSON.parse(data) : {}); }
      catch(e){ resolve({}); }
    });
  });
}
function sendJson(res, status, obj){
  const body = JSON.stringify(obj);
  res.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body)});
  res.end(body);
}
function requireAuth(req, res){
  const session = getSession(req);
  if(!session){ sendJson(res, 401, {error: 'Not signed in.'}); return null; }
  return session;
}
function requireAdmin(req, res){
  const session = getSession(req);
  if(!session || session.data.role !== 'admin'){ sendJson(res, 403, {error: 'Admin sign-in required.'}); return null; }
  return session;
}

// ----------------------------------------------------------------
// Route handlers
// ----------------------------------------------------------------
async function handleApi(req, res, pathname){
  const ip = getClientIp(req);

  // ---- session / logout ----
  if(pathname === '/api/session' && req.method === 'GET'){
    const session = getSession(req);
    if(!session) return sendJson(res, 200, {loggedIn:false});
    return sendJson(res, 200, {loggedIn:true, role: session.data.role, username: session.data.username, access: sessionAccess(session), adminData: sessionAdminData(session)});
  }
  if(pathname === '/api/logout' && req.method === 'POST'){
    destroySession(req, res);
    return sendJson(res, 200, {ok:true});
  }

  // ---- admin status / setup / login / forgot ----
  if(pathname === '/api/admin/status' && req.method === 'GET'){
    return sendJson(res, 200, {exists: !!store.admin});
  }
  if(pathname === '/api/admin/setup' && req.method === 'POST'){
    if(store.admin) return sendJson(res, 409, {error: 'An Admin account already exists.'});
    const body = await readJsonBody(req);
    const email = String(body.email||'').trim();
    const password = String(body.password||'');
    if(!email) return sendJson(res, 400, {error:'Please enter an email for password recovery.'});
    if(!password || password.length < 4) return sendJson(res, 400, {error:'Please use at least 4 characters.'});
    const {salt, hash} = hashPassword(password);
    store.admin = {email, salt, hash, tables: defaultTables()};
    logAccessEvent('admin_setup', `Admin account created (${email})`, 'Admin');
    createSession(req, res, 'admin', null, ip);
    persist();
    return sendJson(res, 200, {ok:true});
  }
  if(pathname === '/api/admin/login' && req.method === 'POST'){
    if(!store.admin) return sendJson(res, 404, {error:'No Admin account exists yet.'});
    const body = await readJsonBody(req);
    const password = String(body.password||'');
    if(!verifyPassword(password, store.admin.salt, store.admin.hash)){
      logAccessEvent('admin_login_failed', `Failed Admin sign-in attempt from ${ip}`, 'Admin');
      persist();
      return sendJson(res, 401, {error:'Incorrect password. Please try again.'});
    }
    createSession(req, res, 'admin', null, ip);
    logAccessEvent('admin_login', `Admin signed in from ${ip}`, 'Admin');
    persist();
    return sendJson(res, 200, {ok:true});
  }
  if(pathname === '/api/admin/forgot' && req.method === 'POST'){
    if(!store.admin) return sendJson(res, 404, {error:'No Admin account exists yet.'});
    const body = await readJsonBody(req);
    const email = String(body.email||'').trim();
    const newPassword = String(body.newPassword||'');
    if(email.toLowerCase() !== String(store.admin.email||'').toLowerCase()){
      return sendJson(res, 400, {error:'That email does not match our records.'});
    }
    if(!newPassword || newPassword.length < 4) return sendJson(res, 400, {error:'Please use at least 4 characters.'});
    const {salt, hash} = hashPassword(newPassword);
    store.admin.salt = salt; store.admin.hash = hash;
    logAccessEvent('admin_forgot_reset', `Admin password reset from ${ip}`, 'Admin');
    persist();
    return sendJson(res, 200, {ok:true});
  }

  // ---- user sign-up / sign-in / forgot / reset ----
  if(pathname === '/api/users/signup' && req.method === 'POST'){
    const body = await readJsonBody(req);
    const name = String(body.name||'').trim();
    const username = String(body.username||'').trim();
    const email = String(body.email||'').trim();
    const password = String(body.password||'');
    if(!name || !username || !email || !password) return sendJson(res, 400, {error:'Please fill in every field.'});
    if(password.length < 4) return sendJson(res, 400, {error:'Please use at least 4 characters.'});
    if(findUserByUsername(username)) return sendJson(res, 409, {error:'That username is already taken.'});
    const {salt, hash} = hashPassword(password);
    const user = {
      id: genId('u'), name, username, email, salt, hash,
      status: 'pending', createdAt: nowISO(), statusUpdatedAt: null,
      lastSignInAt: null, lastSignInIp: null, resetOtp: null,
      tables: defaultTables() // this account's own private budget data
    };
    store.users.push(user);
    logAccessEvent('user_signup', `${name} (${username}) requested access`, username);
    persist();
    return sendJson(res, 200, {ok:true});
  }
  if(pathname === '/api/users/login' && req.method === 'POST'){
    autoDeactivateExpiredUsers();
    const body = await readJsonBody(req);
    const username = String(body.username||'').trim();
    const password = String(body.password||'');
    const user = findUserByUsername(username);
    if(!user){
      logAccessEvent('user_login_failed', `Failed sign-in attempt for unknown username "${username}" from ${ip}`);
      persist();
      return sendJson(res, 404, {error:'No account found with that username. Please sign up.'});
    }
    if(!verifyPassword(password, user.salt, user.hash)){
      logAccessEvent('user_login_failed', `Failed sign-in attempt for ${username} from ${ip}`, username);
      persist();
      return sendJson(res, 401, {error:'Incorrect password.'});
    }
    if(user.status === 'pending'){ return sendJson(res, 403, {error:'Your account is awaiting admin approval.'}); }
    if(user.status === 'deactivated'){ return sendJson(res, 403, {error:'This account has been deactivated. Please contact the admin.'}); }
    user.lastSignInAt = nowISO();
    user.lastSignInIp = ip;
    createSession(req, res, 'user', user.name || user.username, ip, user.id);
    logAccessEvent('user_signin', `${user.name||user.username} (${user.username}) signed in from ${ip}`, user.username);
    persist();
    return sendJson(res, 200, {ok:true, name: user.name || user.username, access: accessOf(user), adminData: usesAdminData(user)});
  }
  if(pathname === '/api/users/forgot' && req.method === 'POST'){
    const body = await readJsonBody(req);
    const username = String(body.username||'').trim();
    const email = String(body.email||'').trim();
    const user = findUserByUsername(username);
    if(!user || String(user.email||'').toLowerCase() !== email.toLowerCase()){
      return sendJson(res, 400, {error:'That username and email combination does not match our records.'});
    }
    const otp = genOtp();
    user.resetOtp = {code: otp, expiresAt: Date.now() + 10*60*1000};
    persist();
    // No email service is configured on this server, so — same as
    // before — the OTP is simply returned here instead of emailed.
    return sendJson(res, 200, {ok:true, otp, validMinutes: 10, noEmailServer: true});
  }
  if(pathname === '/api/users/reset' && req.method === 'POST'){
    const body = await readJsonBody(req);
    const username = String(body.username||'').trim();
    const otp = String(body.otp||'').trim();
    const newPassword = String(body.newPassword||'');
    const user = findUserByUsername(username);
    if(!user || !user.resetOtp) return sendJson(res, 400, {error:'Please request a new one-time password first.'});
    if(Date.now() > user.resetOtp.expiresAt) return sendJson(res, 400, {error:'That one-time password has expired. Please request a new one.'});
    if(otp !== user.resetOtp.code) return sendJson(res, 400, {error:'Incorrect one-time password.'});
    if(!newPassword || newPassword.length < 4) return sendJson(res, 400, {error:'Please use at least 4 characters.'});
    const {salt, hash} = hashPassword(newPassword);
    user.salt = salt; user.hash = hash; user.resetOtp = null;
    logAccessEvent('user_password_reset', `${user.name||user.username} (${user.username}) reset their password`, user.username);
    persist();
    return sendJson(res, 200, {ok:true});
  }

  // ---- private per-account app data (budget, ledger, categories, yearly fund) ----
  // This is the ONLY place budget data is read or written, and it is
  // always scoped to the caller's own account — see getAccountTables().
  if(pathname === '/api/app-data' && req.method === 'GET'){
    const session = requireAuth(req, res); if(!session) return;
    autoDeactivateExpiredUsers();
    const tables = getAccountTables(session);
    if(!tables) return sendJson(res, 404, {error: 'Account not found.'});
    return sendJson(res, 200, {tables});
  }
  if(pathname === '/api/app-data' && req.method === 'POST'){
    const session = requireAuth(req, res); if(!session) return;
    if(sessionAccess(session) === 'view'){
      return sendJson(res, 403, {error: 'This account has view-only access. Changes are not allowed.'});
    }
    const tables = getAccountTables(session);
    if(!tables) return sendJson(res, 404, {error: 'Account not found.'});
    const body = await readJsonBody(req);
    if(body.schoolYear !== undefined) tables.schoolYear = body.schoolYear;
    if(body.schoolName !== undefined) tables.schoolName = body.schoolName;
    if(body.schoolId !== undefined) tables.schoolId = body.schoolId;
    if(body.schoolInfoConfirmed !== undefined) tables.schoolInfoConfirmed = !!body.schoolInfoConfirmed;
    if(Array.isArray(body.categories)) tables.categories = body.categories;
    if(body.allocations && typeof body.allocations === 'object') tables.allocations = body.allocations;
    if(Array.isArray(body.ledger)) tables.ledger = body.ledger;
    if(Array.isArray(body.yearlyFund)) tables.yearlyFund = body.yearlyFund;
    if(Array.isArray(body.auditLog)) tables.auditLog = mergeAuditLogs(tables.auditLog, body.auditLog);
    persist();
    return sendJson(res, 200, {ok:true});
  }

  // ---- admin: account directory (metadata only — never budget data) ----
  if(pathname === '/api/admin/accounts' && req.method === 'GET'){
    const session = requireAdmin(req, res); if(!session) return;
    autoDeactivateExpiredUsers();
    return sendJson(res, 200, {users: (store.users||[]).map(publicUser)});
  }

  // ---- admin: user management ----
  if(pathname.startsWith('/api/admin/users/') && (req.method === 'POST' || req.method === 'DELETE')){
    const session = requireAdmin(req, res); if(!session) return;
    const parts = pathname.split('/'); // ['', 'api','admin','users', ':id', 'activate'?]
    const id = parts[4];
    const action = parts[5];
    const user = (store.users||[]).find(u => u.id === id);
    if(!user) return sendJson(res, 404, {error:'User not found.'});
    if(req.method === 'DELETE'){
      store.users = store.users.filter(u => u.id !== id);
      logAccessEvent('user_remove', `${user.name||user.username||'User'} (${user.username}) removed`, 'Admin');
      persist();
      return sendJson(res, 200, {ok:true});
    }
    if(action === 'activate'){
      const body = await readJsonBody(req);
      user.access = body.access === 'view' ? 'view' : 'full';
      user.status = 'active'; user.statusUpdatedAt = nowISO();
      logAccessEvent('user_activate', `${user.name||user.username||'User'} (${user.username}) activated with ${user.access === 'view' ? 'view-only access' : 'full access'}`, 'Admin');
      persist();
      return sendJson(res, 200, {ok:true});
    }
    if(action === 'access'){
      const body = await readJsonBody(req);
      user.access = body.access === 'view' ? 'view' : 'full';
      logAccessEvent('user_access_change', `${user.name||user.username||'User'} (${user.username}) set to ${user.access === 'view' ? 'view-only access' : 'full access'}`, 'Admin');
      persist();
      return sendJson(res, 200, {ok:true});
    }
    if(action === 'deactivate'){
      user.status = 'deactivated'; user.statusUpdatedAt = nowISO();
      logAccessEvent('user_deactivate', `${user.name||user.username||'User'} (${user.username}) deactivated`, 'Admin');
      persist();
      return sendJson(res, 200, {ok:true});
    }
    return sendJson(res, 404, {error:'Unknown action.'});
  }

  // ---- admin: live sign-in monitor (who is signed in right now) ----
  if(pathname === '/api/admin/monitor' && req.method === 'GET'){
    const session = requireAdmin(req, res); if(!session) return;
    const active = [];
    sessions.forEach((data) => {
      active.push({role: data.role, username: data.username, ip: data.ip, loginAt: data.loginAt});
    });
    active.sort((a,b) => (b.loginAt||'').localeCompare(a.loginAt||''));
    return sendJson(res, 200, {activeSessions: active});
  }

  // ---- admin: access log (sign-ups, sign-ins, account changes — never budget data) ----
  if(pathname === '/api/admin/access-log' && req.method === 'GET'){
    const session = requireAdmin(req, res); if(!session) return;
    return sendJson(res, 200, {accessLog: store.accessLog || []});
  }

  sendJson(res, 404, {error: 'Not found.'});
}

// ----------------------------------------------------------------
// Server
// ----------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url);
  const pathname = parsed.pathname;

  if(pathname.startsWith('/api/')){
    try{
      await handleApi(req, res, pathname);
    }catch(e){
      console.error('API error:', e);
      sendJson(res, 500, {error: 'Server error.'});
    }
    return;
  }

  // Everything else serves the single-page app.
  fs.readFile(INDEX_FILE, (err, content) => {
    if(err){
      res.writeHead(500, {'Content-Type':'text/plain'});
      res.end('Could not load index.html: ' + err.message);
      return;
    }
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
    res.end(content);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`MOOE FMIS server running at http://localhost:${PORT}`);
  console.log(`Data file: ${DATA_FILE}`);
  console.log(store.admin
    ? `Admin account: already set up (${store.admin.email})`
    : 'Admin account: not set up yet — create it on first visit, or set ADMIN_EMAIL/ADMIN_PASSWORD and restart.');
  console.log('Every account (Admin and each User) has its own private budget data.');
  console.log('Press Ctrl+C to stop.');
});
