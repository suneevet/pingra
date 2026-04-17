const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => cb(null, 'av_' + uuidv4() + path.extname(file.originalname))
});
const uploadAvatar = multer({ storage: avatarStorage, limits: { fileSize: 5 * 1024 * 1024 } });

app.use('/uploads', express.static(uploadsDir));
app.use(express.static(path.join(__dirname)));

const db = new Database('messenger.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    avatar TEXT DEFAULT NULL,
    role TEXT DEFAULT 'user',
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    text TEXT NOT NULL,
    file_url TEXT DEFAULT NULL,
    file_name TEXT DEFAULT NULL,
    file_type TEXT DEFAULT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
`);

try { db.exec(`ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL`); } catch {}
try { db.exec(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN file_url TEXT DEFAULT NULL`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN file_name TEXT DEFAULT NULL`); } catch {}
try { db.exec(`ALTER TABLE messages ADD COLUMN file_type TEXT DEFAULT NULL`); } catch {}

const adminHash = bcrypt.hashSync('996633668899', 10);
db.prepare(`INSERT OR IGNORE INTO users (id, username, password_hash, role) VALUES ('0', 'Admin', ?, 'admin')`).run(adminHash);

const clients = new Map();

function getUserByToken(token) {
  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ?').get(token);
  if (!session) return null;
  return db.prepare('SELECT id, username, avatar, role FROM users WHERE id = ?').get(session.user_id);
}

function broadcast(toUserId, payload) {
  for (const [token, ws] of clients) {
    const user = getUserByToken(token);
    if (user && user.id === toUserId && ws.readyState === 1) ws.send(JSON.stringify(payload));
  }
}

app.use(express.json());

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Заполни все поля' });
  if (username.length < 2) return res.status(400).json({ error: 'Имя минимум 2 символа' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (exists) return res.status(400).json({ error: 'Этот логин уже занят' });
  const hash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  db.prepare('INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)').run(id, username, hash);
  const token = uuidv4();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, id);
  res.json({ token, username, id });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Неверный логин или пароль' });
  const token = uuidv4();
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);
  res.json({ token, username: user.username, id: user.id, avatar: user.avatar, role: user.role });
});

app.get('/api/users', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const me = getUserByToken(token);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  const users = db.prepare('SELECT id, username, avatar, role FROM users WHERE id != ?').all(me.id);
  res.json(users);
});

app.get('/api/user/:userId', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const me = getUserByToken(token);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  const user = db.prepare('SELECT id, username, avatar, role, created_at FROM users WHERE id = ?').get(req.params.userId);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(user);
});

app.get('/api/messages/:userId', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const me = getUserByToken(token);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  const other = req.params.userId;
  const messages = db.prepare(`SELECT * FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY created_at ASC LIMIT 200`).all(me.id, other, other, me.id);
  res.json(messages);
});

app.post('/api/upload', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const me = getUserByToken(token);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Файл не найден' });
    res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname, type: req.file.mimetype });
  });
});

app.post('/api/avatar', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const me = getUserByToken(token);
  if (!me) return res.status(401).json({ error: 'Не авторизован' });
  uploadAvatar.single('avatar')(req, res, (err) => {
    if (err) return res.status(400).json({ error: err.message });
    if (!req.file) return res.status(400).json({ error: 'Файл не найден' });
    const avatarUrl = '/uploads/' + req.file.filename;
    db.prepare('UPDATE users SET avatar = ? WHERE id = ?').run(avatarUrl, me.id);
    res.json({ avatar: avatarUrl });
  });
});

wss.on('connection', (ws) => {
  let myToken = null;
  let myUser = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'auth') {
      const user = getUserByToken(msg.token);
      if (!user) { ws.send(JSON.stringify({ type: 'error', text: 'Не авторизован' })); return; }
      myToken = msg.token;
      myUser = user;
      clients.set(myToken, ws);
      ws.send(JSON.stringify({ type: 'auth_ok', username: user.username, id: user.id }));
      return;
    }

    if (!myUser) return;

    if (msg.type === 'message') {
      const toUser = db.prepare('SELECT id, username FROM users WHERE id = ?').get(msg.to);
      if (!toUser) return;
      const id = uuidv4();
      const created_at = Math.floor(Date.now() / 1000);
      const text = msg.text || '';
      const fileUrl = msg.file_url || null;
      const fileName = msg.file_name || null;
      const fileType = msg.file_type || null;
      db.prepare('INSERT INTO messages (id, from_user, to_user, text, file_url, file_name, file_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, myUser.id, toUser.id, text, fileUrl, fileName, fileType, created_at);
      const payload = { type: 'message', id, from_user: myUser.id, from_username: myUser.username, to_user: toUser.id, text, file_url: fileUrl, file_name: fileName, file_type: fileType, created_at };
      broadcast(toUser.id, payload);
      broadcast(myUser.id, payload);
    }

    if (msg.type === 'typing') broadcast(msg.to, { type: 'typing', from: myUser.id, from_username: myUser.username });
  });

  ws.on('close', () => { if (myToken) clients.delete(myToken); });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`\n✅ Pingra → http://localhost:${PORT}\n`));
