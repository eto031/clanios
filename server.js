// ═══════════════════════════════════════════════════════════
//  TENS`1OS KLAN SUNUCUSU  —  server.js
//  Çalıştırmak için: node server.js
// ═══════════════════════════════════════════════════════════

const http    = require('http');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

// ─── AYARLAR ────────────────────────────────────────────────
const PORT       = 3000;
const DB_FILE    = path.join(__dirname, 'db.json');
const JWT_SECRET = 'tens1os_super_secret_2025'; // istersen değiştir

// ─── VERİTABANI (JSON dosyası) ──────────────────────────────
function loadDB() {
  if (!fs.existsSync(DB_FILE)) return { users: [], messages: [], settings: {}, nextId: 1 };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch { return { users: [], messages: [], settings: {}, nextId: 1 }; }
}

function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ─── JWT (basit, imzalı) ────────────────────────────────────
function b64url(s) { return Buffer.from(s).toString('base64url'); }
function makeToken(payload) {
  const header  = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body    = b64url(JSON.stringify({ ...payload, iat: Date.now() }));
  const sig     = crypto.createHmac('sha256', JWT_SECRET).update(header + '.' + body).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyToken(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected  = crypto.createHmac('sha256', JWT_SECRET).update(h + '.' + b).digest('base64url');
    if (s !== expected) return null;
    return JSON.parse(Buffer.from(b, 'base64url').toString());
  } catch { return null; }
}

// ─── ŞİFRELEME ──────────────────────────────────────────────
function hashPass(pass) { return crypto.createHash('sha256').update(pass + JWT_SECRET).digest('hex'); }

// ─── ONLINE TAKİBİ ──────────────────────────────────────────
const onlineSessions = new Map(); // userId -> lastSeen timestamp
function markOnline(userId) { onlineSessions.set(userId, Date.now()); }
function isOnline(userId) { const t = onlineSessions.get(userId); return t && (Date.now() - t) < 60000; }

// ─── YARDIMCI ───────────────────────────────────────────────
function json(res, code, data) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type,Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' });
  res.end(JSON.stringify(data));
}
function err(res, code, msg) { json(res, code, { error: msg }); }

function getBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => data += c);
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
    req.on('error', reject);
  });
}

function authMiddleware(req) {
  const h = req.headers['authorization'] || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return null;
  return verifyToken(token);
}

// ─── SUNUCU ─────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url    = req.url.split('?')[0];
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') { json(res, 204, {}); return; }

  // Statik dosya (index.html, logo.png vs)
  if (!url.startsWith('/api/')) {
    let filePath = path.join(__dirname, url === '/' ? 'index.html' : url);
    // path traversal koruması
    if (!filePath.startsWith(__dirname)) { err(res, 403, 'Yasak'); return; }
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext   = path.extname(filePath).toLowerCase();
      const mimes = { '.html':'text/html', '.css':'text/css', '.js':'application/javascript', '.png':'image/png', '.jpg':'image/jpeg', '.gif':'image/gif', '.ico':'image/x-icon' };
      res.writeHead(200, { 'Content-Type': mimes[ext] || 'application/octet-stream' });
      fs.createReadStream(filePath).pipe(res);
      return;
    }
    // bulunamazsa index.html sun (SPA)
    const idx = path.join(__dirname, 'index.html');
    if (fs.existsSync(idx)) { res.writeHead(200, { 'Content-Type': 'text/html' }); fs.createReadStream(idx).pipe(res); }
    else err(res, 404, 'Bulunamadı');
    return;
  }

  // ── API ROTALARI ──────────────────────────────────────────

  // POST /api/auth/register
  if (url === '/api/auth/register' && method === 'POST') {
    const { username, email, password } = await getBody(req);
    if (!username || !email || !password) { err(res, 400, 'Tüm alanları doldurun'); return; }
    if (password.length < 6) { err(res, 400, 'Şifre en az 6 karakter olmalı'); return; }
    const db = loadDB();
    if (db.users.find(u => u.email === email.toLowerCase())) { err(res, 409, 'Bu e-posta zaten kayıtlı'); return; }
    if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) { err(res, 409, 'Bu kullanıcı adı alınmış'); return; }
    const user = { id: db.nextId++, username, email: email.toLowerCase(), password: hashPass(password), role: db.users.length === 0 ? 'master' : 'member', kills: 0, createdAt: new Date().toISOString() };
    db.users.push(user);
    saveDB(db);
    json(res, 201, { message: 'Kayıt başarılı' });
    return;
  }

  // POST /api/auth/login
  if (url === '/api/auth/login' && method === 'POST') {
    const { email, password } = await getBody(req);
    const db   = loadDB();
    const user = db.users.find(u => u.email === (email||'').toLowerCase() && u.password === hashPass(password||''));
    if (!user) { err(res, 401, 'E-posta veya şifre hatalı'); return; }
    markOnline(user.id);
    const token = makeToken({ id: user.id, username: user.username, email: user.email, role: user.role });
    json(res, 200, { token });
    return;
  }

  // POST /api/auth/logout
  if (url === '/api/auth/logout' && method === 'POST') {
    const me = authMiddleware(req);
    if (me) onlineSessions.delete(me.id);
    json(res, 200, { message: 'Çıkış yapıldı' });
    return;
  }

  // GET /api/members
  if (url === '/api/members' && method === 'GET') {
    const db = loadDB();
    const list = db.users.map(u => ({ Id: u.id, Username: u.username, Role: u.role, Kills: u.kills, IsOnline: isOnline(u.id) }));
    list.sort((a,b) => { const o=['master','admin','member']; return o.indexOf(a.Role)-o.indexOf(b.Role) || b.Kills-a.Kills; });
    json(res, 200, list);
    return;
  }

  // GET /api/members/online
  if (url === '/api/members/online' && method === 'GET') {
    const me = authMiddleware(req);
    if (!me) { err(res, 401, 'Giriş yapın'); return; }
    markOnline(me.id);
    const db   = loadDB();
    const list = db.users.filter(u => isOnline(u.id)).map(u => ({ Id: u.id, Username: u.username, Role: u.role }));
    json(res, 200, list);
    return;
  }

  // GET /api/messages
  if (url === '/api/messages' && method === 'GET') {
    const me = authMiddleware(req);
    if (!me) { err(res, 401, 'Giriş yapın'); return; }
    markOnline(me.id);
    const db   = loadDB();
    const msgs = (db.messages || []).slice(-100).map(m => {
      const u = db.users.find(u => u.id === m.userId);
      return { Id: m.id, Content: m.content, Username: u?.username||'?', UserRole: u?.role||'member', CreatedAt: m.createdAt };
    });
    json(res, 200, msgs);
    return;
  }

  // POST /api/messages
  if (url === '/api/messages' && method === 'POST') {
    const me = authMiddleware(req);
    if (!me) { err(res, 401, 'Giriş yapın'); return; }
    markOnline(me.id);
    const { content } = await getBody(req);
    if (!content || !content.trim()) { err(res, 400, 'Mesaj boş olamaz'); return; }
    if (content.length > 500) { err(res, 400, 'Mesaj çok uzun (max 500 karakter)'); return; }
    const db = loadDB();
    const msg = { id: db.nextId++, userId: me.id, content: content.trim(), createdAt: new Date().toISOString() };
    if (!db.messages) db.messages = [];
    db.messages.push(msg);
    // Son 1000 mesajı tut
    if (db.messages.length > 1000) db.messages = db.messages.slice(-1000);
    saveDB(db);
    json(res, 201, { message: 'Gönderildi' });
    return;
  }

  // GET /api/settings
  if (url === '/api/settings' && method === 'GET') {
    const db = loadDB();
    json(res, 200, db.settings || {});
    return;
  }

  // PUT /api/settings
  if (url === '/api/settings' && method === 'PUT') {
    const me = authMiddleware(req);
    if (!me || (me.role !== 'master' && me.role !== 'admin')) { err(res, 403, 'Yetki yok'); return; }
    const { key, value } = await getBody(req);
    if (!key) { err(res, 400, 'Key gerekli'); return; }
    const db = loadDB();
    if (!db.settings) db.settings = {};
    db.settings[key] = value;
    saveDB(db);
    json(res, 200, { message: 'Kaydedildi' });
    return;
  }

  // GET /api/admin/stats
  if (url === '/api/admin/stats' && method === 'GET') {
    const me = authMiddleware(req);
    if (!me || (me.role !== 'master' && me.role !== 'admin')) { err(res, 403, 'Yetki yok'); return; }
    const db = loadDB();
    json(res, 200, { totalUsers: db.users.length, onlineUsers: db.users.filter(u => isOnline(u.id)).length, totalMessages: (db.messages||[]).length });
    return;
  }

  // GET /api/admin/users
  if (url === '/api/admin/users' && method === 'GET') {
    const me = authMiddleware(req);
    if (!me || (me.role !== 'master' && me.role !== 'admin')) { err(res, 403, 'Yetki yok'); return; }
    const db = loadDB();
    json(res, 200, db.users.map(u => ({ Id: u.id, Username: u.username, Email: u.email, Role: u.role, Kills: u.kills })));
    return;
  }

  // PUT /api/admin/users/:id/role
  const roleMatch = url.match(/^\/api\/admin\/users\/(\d+)\/role$/);
  if (roleMatch && method === 'PUT') {
    const me = authMiddleware(req);
    if (!me || me.role !== 'master') { err(res, 403, 'Sadece master rol değiştirebilir'); return; }
    const { role } = await getBody(req);
    if (!['member','admin','master'].includes(role)) { err(res, 400, 'Geçersiz rol'); return; }
    const db   = loadDB();
    const user = db.users.find(u => u.id === parseInt(roleMatch[1]));
    if (!user) { err(res, 404, 'Kullanıcı bulunamadı'); return; }
    user.role = role;
    saveDB(db);
    json(res, 200, { message: 'Rol güncellendi' });
    return;
  }

  // PUT /api/admin/users/:id/kills
  const killsMatch = url.match(/^\/api\/admin\/users\/(\d+)\/kills$/);
  if (killsMatch && method === 'PUT') {
    const me = authMiddleware(req);
    if (!me || (me.role !== 'master' && me.role !== 'admin')) { err(res, 403, 'Yetki yok'); return; }
    const { kills } = await getBody(req);
    const db   = loadDB();
    const user = db.users.find(u => u.id === parseInt(killsMatch[1]));
    if (!user) { err(res, 404, 'Kullanıcı bulunamadı'); return; }
    user.kills = Number(kills) || 0;
    saveDB(db);
    json(res, 200, { message: 'Kill güncellendi' });
    return;
  }

  // DELETE /api/admin/users/:id
  const delMatch = url.match(/^\/api\/admin\/users\/(\d+)$/);
  if (delMatch && method === 'DELETE') {
    const me = authMiddleware(req);
    if (!me || me.role !== 'master') { err(res, 403, 'Sadece master silebilir'); return; }
    const db  = loadDB();
    const idx = db.users.findIndex(u => u.id === parseInt(delMatch[1]));
    if (idx === -1) { err(res, 404, 'Kullanıcı bulunamadı'); return; }
    db.users.splice(idx, 1);
    saveDB(db);
    json(res, 200, { message: 'Kullanıcı silindi' });
    return;
  }

  err(res, 404, 'Endpoint bulunamadı');
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ████████╗███████╗███╗  ██╗███████╗');
  console.log('  ╚══██╔══╝██╔════╝████╗ ██║██╔════╝');
  console.log('     ██║   █████╗  ██╔██╗██║███████╗');
  console.log('     ██║   ██╔══╝  ██║╚████║╚════██║');
  console.log('     ██║   ███████╗██║ ╚███║███████║');
  console.log('     ╚═╝   ╚══════╝╚═╝  ╚══╝╚══════╝');
  console.log('');
  console.log(`  ✅  Sunucu çalışıyor: http://localhost:${PORT}`);
  console.log(`  📁  Veritabanı:       db.json`);
  console.log('');
  console.log('  İlk kayıt olan kullanıcı otomatik MASTER olur!');
  console.log('');
  console.log('  Durdurmak için: CTRL + C');
  console.log('');
});
