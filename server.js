// Server Independent Wallet — tanpa dependensi. Jalankan: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DB = process.env.DB_FILE || path.join(__dirname, 'data.json');
const ALLOW_TOPUP = process.env.ALLOW_TOPUP !== '0'; // set ALLOW_TOPUP=0 untuk mematikan isi saldo gratis

let db = { users: {}, txs: [], notifs: {}, kagets: {}, push: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB, 'utf8'))); } catch (e) {}
let timer = null;
const save = () => { clearTimeout(timer); timer = setTimeout(() => fs.writeFile(DB + '.tmp', JSON.stringify(db), e => { if (!e) fs.rename(DB + '.tmp', DB, () => {}); }), 150); };
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const rnd = n => crypto.randomBytes(n).toString('hex');
const clients = {};
const push = (id, ev, data) => (clients[id] || new Set()).forEach(r => r.write(`event: ${ev}\ndata: ${JSON.stringify(data)}\n\n`));
// ===== Web Push (VAPID, tanpa payload) =====
if (!db.vapid) { const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }); db.vapid = { priv: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), pubJwk: kp.publicKey.export({ format: 'jwk' }) }; save(); }
const VPRIV = crypto.createPrivateKey(db.vapid.priv);
const b64u = b => Buffer.from(b).toString('base64url');
const VPUB = b64u(Buffer.concat([Buffer.from([4]), Buffer.from(db.vapid.pubJwk.x, 'base64url'), Buffer.from(db.vapid.pubJwk.y, 'base64url')]));
async function sendPush(id) {
  for (const s of [...(db.push[id] || [])]) {
    try {
      const u = new URL(s.endpoint), head = b64u(JSON.stringify({ typ: 'JWT', alg: 'ES256' }));
      const body = b64u(JSON.stringify({ aud: u.origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'mailto:admin@example.com' }));
      const sg = crypto.sign('sha256', Buffer.from(head + '.' + body), { key: VPRIV, dsaEncoding: 'ieee-p1363' });
      const r = await fetch(s.endpoint, { method: 'POST', headers: { Authorization: 'vapid t=' + head + '.' + body + '.' + b64u(sg) + ', k=' + VPUB, TTL: '86400', Urgency: 'high' } });
      if (r.status === 404 || r.status === 410) { db.push[id] = db.push[id].filter(x => x.endpoint !== s.endpoint); save(); }
    } catch (e) {}
  }
}
const SW = `self.addEventListener('push',e=>{e.waitUntil((async()=>{let t='Saldo masuk',b='Pengguna Apk mengirim kamu saldo';
try{const l=await clients.matchAll({type:'window',includeUncontrolled:true});if(l.some(c=>c.visibilityState==='visible'&&c.focused))return;
const sub=await self.registration.pushManager.getSubscription();const r=await fetch('/api/peek?e='+encodeURIComponent(sub.endpoint));const j=await r.json();t=j.title||t;b=j.text||b}catch(_){}
await self.registration.showNotification(t,{body:b,tag:'iw',renotify:true,vibrate:[200,100,200]})})())});
self.addEventListener('notificationclick',e=>{e.notification.close();e.waitUntil(clients.matchAll({type:'window'}).then(l=>l.length?l[0].focus():clients.openWindow('/')))});`;
const okAmount = v => Number.isSafeInteger(v) && v > 0 && v <= 1000000000;

function newId() { let id; do { id = 'WALLET-' + crypto.randomBytes(4).toString('hex').slice(0, 6).toUpperCase(); } while (db.users[id]); return id; }
function newRef() { let s = ''; for (let i = 0; i < 12; i++) s += crypto.randomInt(10); return s; }

function auth(req, url) {
  const h = req.headers.authorization || ''; const raw = h.startsWith('Bearer ') ? h.slice(7) : url.searchParams.get('auth') || '';
  const i = raw.lastIndexOf('.'); if (i < 0) return null;
  const id = raw.slice(0, i), tok = raw.slice(i + 1), u = db.users[id];
  if (!u) return null;
  const a = Buffer.from(sha(tok)), b = Buffer.from(u.tokenHash);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? id : null;
}

function addNotif(id, n) {
  const list = db.notifs[id] = db.notifs[id] || [];
  const item = Object.assign({ id: rnd(6), read: false, ts: Date.now() }, n);
  list.unshift(item); db.notifs[id] = list.slice(0, 50);
  push(id, 'notif', item);
  sendPush(id);
}

function transfer(from, to, amount, type) {
  if (!db.users[to]) throw new Error('Penerima tidak ditemukan');
  if (from === to) throw new Error('Tidak bisa mengirim ke diri sendiri');
  if (!okAmount(amount)) throw new Error('Nominal tidak valid');
  if (db.users[from].balance < amount) throw new Error('Saldo tidak cukup');
  db.users[from].balance -= amount; db.users[to].balance += amount;
  const tx = { id: rnd(6), ref: newRef(), type, from, fromName: db.users[from].name, to, toName: db.users[to].name, amount, ts: Date.now() };
  db.txs.push(tx); if (db.txs.length > 20000) db.txs.shift();
  return tx;
}

function me(id) {
  const u = db.users[id];
  return { id, name: u.name, balance: u.balance, notifs: db.notifs[id] || [], txs: db.txs.filter(t => t.from === id || t.to === id).slice(-100).reverse() };
}

const routes = {
  'POST /api/register': (req, body) => {
    const name = String(body.name || '').trim().slice(0, 32);
    if (!name) throw new Error('Isi nama pengguna');
    if (Object.keys(db.users).length >= 20000) throw new Error('Server penuh');
    const id = newId(), token = rnd(16);
    db.users[id] = { name, tokenHash: sha(token), balance: 0, created: Date.now() };
    return { id, token };
  },
  'GET /api/me': (req, body, id) => me(id),
  'POST /api/rename': (req, body, id) => { const n = String(body.name || '').trim().slice(0, 32); if (!n) throw new Error('Nama kosong'); db.users[id].name = n; return { ok: true }; },
  'POST /api/send': (req, body, id) => {
    const tx = transfer(id, String(body.to || ''), Number(body.amount), 'send');
    addNotif(tx.to, { title: 'Saldo masuk', text: `Pengguna Apk mengirim kamu saldo sebesar Rp${tx.amount.toLocaleString('id-ID')}`, txId: tx.id });
    push(id, 'update', {}); return { tx, balance: db.users[id].balance };
  },
  'POST /api/topup': (req, body, id) => {
    if (!ALLOW_TOPUP) throw new Error('Isi saldo dimatikan di server');
    const n = Number(body.amount); if (!okAmount(n)) throw new Error('Nominal tidak valid');
    db.users[id].balance += n; return { balance: db.users[id].balance };
  },
  'POST /api/kaget': (req, body, id) => {
    const amount = Number(body.amount); if (!okAmount(amount)) throw new Error('Nominal tidak valid');
    const kid = rnd(5).toUpperCase(); db.kagets[kid] = { creator: id, amount, claimedBy: null, ts: Date.now() };
    return { kid, amount };
  },
  'POST /api/claim': (req, body, id) => {
    const k = db.kagets[String(body.kid || '')]; if (!k) throw new Error('DANA Kaget tidak ditemukan');
    if (k.claimedBy) throw new Error('DANA Kaget sudah diklaim');
    if (k.creator === id) throw new Error('Tidak bisa klaim DANA Kaget sendiri');
    const tx = transfer(k.creator, id, k.amount, 'kaget'); k.claimedBy = id;
    addNotif(id, { title: 'Saldo masuk', text: `Pengguna Apk mengirim kamu saldo sebesar Rp${tx.amount.toLocaleString('id-ID')}`, txId: tx.id });
    addNotif(k.creator, { title: 'DANA Kaget diklaim', text: `DANA Kaget Rp${tx.amount.toLocaleString('id-ID')} diklaim oleh ${tx.toName}`, txId: tx.id });
    push(k.creator, 'update', {}); return { tx, balance: db.users[id].balance };
  },
  'GET /api/vapid': () => ({ key: VPUB }),
  'POST /api/push': (req, body, id) => {
    const e = String(body.sub && body.sub.endpoint || '');
    if (e.length > 1000 || !(/^https:\/\//.test(e) || process.env.ALLOW_HTTP_PUSH)) throw new Error('Endpoint tidak valid');
    const l = db.push[id] = db.push[id] || [];
    if (!l.some(x => x.endpoint === e)) l.push({ endpoint: e });
    db.push[id] = l.slice(-5); return { ok: true };
  },
  'POST /api/read': (req, body, id) => { (db.notifs[id] || []).forEach(n => n.read = true); return { ok: true }; }
};

function readBody(req) {
  return new Promise((res, rej) => {
    let d = ''; req.on('data', c => { d += c; if (d.length > 10000) { rej(new Error('Terlalu besar')); req.destroy(); } });
    req.on('end', () => { try { res(d ? JSON.parse(d) : {}); } catch (e) { rej(new Error('JSON salah')); } });
  });
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, 'http://x');
  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
  }
  if (req.method === 'GET' && url.pathname === '/sw.js') { res.writeHead(200, { 'Content-Type': 'application/javascript', 'Cache-Control': 'no-cache' }); return res.end(SW); }
  if (req.method === 'GET' && url.pathname === '/api/peek') {
    const e = url.searchParams.get('e') || '', id = Object.keys(db.push).find(k => db.push[k].some(x => x.endpoint === e));
    const n = id && (db.notifs[id] || []).find(x => !x.read);
    return send(res, 200, n ? { title: n.title, text: n.text } : {});
  }
  if (req.method === 'GET' && url.pathname === '/api/ping') return send(res, 200, { ok: true });
  try {
    if (req.method === 'POST' && url.pathname === '/api/register') return send(res, 200, routes['POST /api/register'](req, await readBody(req)));
    const id = auth(req, url);
    if (!id) return send(res, 401, { error: 'Belum masuk' });
    if (req.method === 'GET' && url.pathname === '/api/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
      res.write('retry: 3000\n\n'); (clients[id] = clients[id] || new Set()).add(res);
      const ka = setInterval(() => res.write(': ka\n\n'), 25000);
      req.on('close', () => { clearInterval(ka); clients[id].delete(res); }); return;
    }
    let m = url.pathname.match(/^\/api\/user\/(WALLET-[A-Z0-9]{6})$/);
    if (req.method === 'GET' && m) { const u = db.users[m[1]]; return u ? send(res, 200, { id: m[1], name: u.name }) : send(res, 404, { error: 'Pengguna tidak ditemukan' }); }
    m = url.pathname.match(/^\/api\/kaget\/([A-F0-9]{10})$/);
    if (req.method === 'GET' && m) { const k = db.kagets[m[1]]; return k ? send(res, 200, { kid: m[1], amount: k.amount, claimed: !!k.claimedBy, creatorName: db.users[k.creator]?.name || '' }) : send(res, 404, { error: 'DANA Kaget tidak ditemukan' }); }
    const h = routes[req.method + ' ' + url.pathname];
    if (!h) return send(res, 404, { error: 'Tidak ditemukan' });
    const out = h(req, req.method === 'POST' ? await readBody(req) : {}, id); save(); send(res, 200, out);
  } catch (e) { send(res, 400, { error: e.message }); }
}).listen(PORT, () => console.log('Independent Wallet berjalan di port ' + PORT));
