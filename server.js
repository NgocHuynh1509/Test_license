// Web đăng nhập đơn giản + khoá/mở từ xa bằng key (chuỗi bit).
// Chỉ dùng module có sẵn của Node.js, không cần npm install.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const APP_USER = process.env.APP_USER || 'admin';
const APP_PASS = process.env.APP_PASS || '123456';
const KEY_BITS = 64;
const STATE_FILE = path.join(__dirname, 'state.json');

// ---------- Key & trạng thái ----------
function newKey() {
  return [...crypto.randomBytes(KEY_BITS / 8)]
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('');
}

function saveState(s) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(s));
}

function loadState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
  } catch {
    const s = { locked: false, key: process.env.INITIAL_KEY || newKey() };
    saveState(s);
    return s;
  }
}

const state = loadState();
console.log('=== KEY HIỆN TẠI:', state.key);
console.log('=== Trạng thái:', state.locked ? 'ĐANG KHOÁ' : 'ĐANG MỞ');

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// ---------- Chống dò key/mật khẩu đơn giản ----------
const fails = new Map(); // ip -> { count, resetAt }
function tooMany(ip) {
  const f = fails.get(ip);
  return f && f.resetAt > Date.now() && f.count >= 5;
}
function addFail(ip) {
  const f = fails.get(ip);
  if (!f || f.resetAt <= Date.now()) fails.set(ip, { count: 1, resetAt: Date.now() + 60000 });
  else f.count++;
}

// ---------- Session ----------
const sessions = new Map(); // token -> username

function getSession(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  return m && sessions.has(m[1]) ? sessions.get(m[1]) : null;
}

// ---------- Tiện ích ----------
function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 10000) req.destroy();
    });
    req.on('end', () => resolve(data));
  });
}

function send(res, code, body, type = 'text/html; charset=utf-8', headers = {}) {
  res.writeHead(code, { 'Content-Type': type, ...headers });
  res.end(body);
}

const json = (res, code, obj) => send(res, code, JSON.stringify(obj), 'application/json');

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- Giao diện ----------
const style = `
<style>
  body{font-family:system-ui,sans-serif;background:#f3f4f6;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
  .card{background:#fff;padding:32px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);width:340px}
  h1{font-size:20px;margin:0 0 16px}
  input{width:100%;box-sizing:border-box;padding:10px;margin:6px 0 12px;border:1px solid #d1d5db;border-radius:8px}
  button{width:100%;padding:10px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-size:15px;cursor:pointer}
  .err{color:#dc2626;font-size:14px;margin-bottom:8px}
  a{color:#2563eb}
</style>`;

const page = (title, inner) =>
  `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>${style}</head><body><div class="card">${inner}</div></body></html>`;

const loginPage = (err = '') =>
  page('Đăng nhập', `
    <h1>Đăng nhập</h1>
    ${err ? `<div class="err">${esc(err)}</div>` : ''}
    <form method="POST" action="/login">
      <label>Tên đăng nhập</label><input name="username" autofocus required>
      <label>Mật khẩu</label><input name="password" type="password" required>
      <button>Đăng nhập</button>
    </form>`);

const homePage = (user) =>
  page('Trang chủ', `
    <h1>Trang chủ</h1>
    <p>Xin chào, <b>${esc(user)}</b>!</p>
    <p><a href="/logout">Đăng xuất</a></p>`);

const lockedPage = () =>
  page('Website đã bị khoá', `
    <h1>🔒 Website đã bị khoá</h1>
    <p>Nhập key để mở khoá.</p>
    <div class="err" id="err"></div>
    <input id="key" placeholder="Chuỗi bit..." autocomplete="off">
    <button onclick="unlock()">Mở khoá</button>
    <script>
      async function unlock(){
        const r = await fetch('/api/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:document.getElementById('key').value.trim()})});
        if(r.ok) location.href='/'; else document.getElementById('err').textContent='Key không đúng';
      }
    </script>`);

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const ip = req.socket.remoteAddress;

  // --- API khoá / mở khoá (luôn hoạt động) ---
  if (url.pathname === '/api/status' && req.method === 'GET') {
    return json(res, 200, { locked: state.locked });
  }

  if ((url.pathname === '/api/lock' || url.pathname === '/api/unlock') && req.method === 'POST') {
    if (tooMany(ip)) return json(res, 429, { error: 'Thử sai quá nhiều lần, đợi 1 phút' });

    let key = '';
    try {
      key = JSON.parse(await readBody(req)).key || '';
    } catch {}

    if (!safeEqual(key, state.key)) {
      addFail(ip);
      return json(res, 403, { error: 'Key không đúng' });
    }

    if (url.pathname === '/api/lock') {
      if (state.locked) return json(res, 409, { error: 'Web đã bị khoá rồi' });
      state.locked = true;
      state.key = newKey(); // mỗi lần khoá -> đổi key
      saveState(state);
      sessions.clear(); // đăng xuất tất cả
      console.log('=== ĐÃ KHOÁ. KEY MỚI:', state.key);
      return json(res, 200, { locked: true, newKey: state.key });
    }

    state.locked = false;
    saveState(state);
    console.log('=== ĐÃ MỞ KHOÁ');
    return json(res, 200, { locked: false });
  }

  // --- Đang khoá: chặn mọi thứ còn lại ---
  if (state.locked) {
    return send(res, 503, lockedPage());
  }

  // --- Đăng nhập / trang chủ ---
  if (url.pathname === '/login' && req.method === 'GET') {
    return getSession(req) ? send(res, 302, '', 'text/plain', { Location: '/' }) : send(res, 200, loginPage());
  }

  if (url.pathname === '/login' && req.method === 'POST') {
    if (tooMany(ip)) return send(res, 429, loginPage('Thử sai quá nhiều lần, đợi 1 phút'));
    const form = new URLSearchParams(await readBody(req));
    const ok = safeEqual(form.get('username') || '', APP_USER) && safeEqual(form.get('password') || '', APP_PASS);
    if (!ok) {
      addFail(ip);
      return send(res, 401, loginPage('Sai tên đăng nhập hoặc mật khẩu'));
    }
    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, APP_USER);
    return send(res, 302, '', 'text/plain', {
      Location: '/',
      'Set-Cookie': `sid=${token}; HttpOnly; Path=/; SameSite=Lax`,
    });
  }

  if (url.pathname === '/logout') {
    const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
    if (m) sessions.delete(m[1]);
    return send(res, 302, '', 'text/plain', { Location: '/login', 'Set-Cookie': 'sid=; Max-Age=0; Path=/' });
  }

  if (url.pathname === '/') {
    const user = getSession(req);
    return user ? send(res, 200, homePage(user)) : send(res, 302, '', 'text/plain', { Location: '/login' });
  }

  send(res, 404, page('404', '<h1>404</h1><p><a href="/">Về trang chủ</a></p>'));
});

server.listen(PORT, () => console.log(`Server chạy tại http://localhost:${PORT}`));
