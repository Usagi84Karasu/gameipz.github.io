// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const GAMES_DIR = path.join(__dirname, 'games');
const DB_FILE = path.join(__dirname, 'db.sqlite');

if (!fs.existsSync(GAMES_DIR)) fs.mkdirSync(GAMES_DIR);

// init DB
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS games (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER,
    title TEXT,
    description TEXT,
    folder TEXT,
    published INTEGER DEFAULT 0,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`);
});

const app = express();
app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

// helper: auth middleware
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  const hash = await bcrypt.hash(password, 10);
  db.run(`INSERT INTO users (username, password_hash) VALUES (?, ?)`, [username, hash], function (err) {
    if (err) return res.status(400).json({ error: 'username exists' });
    const userId = this.lastID;
    const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username, id: userId });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err || !row) return res.status(400).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(400).json({ error: 'invalid credentials' });
    const token = jwt.sign({ id: row.id, username: row.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, username: row.username, id: row.id });
  });
});

// Create a game (saves HTML string as index.html)
app.post('/api/games', authenticate, (req, res) => {
  const { title, description = '', html } = req.body;
  if (!title || !html) return res.status(400).json({ error: 'title and html required' });
  const folder = uuidv4();
  const folderPath = path.join(GAMES_DIR, folder);
  fs.mkdirSync(folderPath);

  // sanitize filename usage (we control folder)
  const indexPath = path.join(folderPath, 'index.html');
  fs.writeFileSync(indexPath, html, 'utf8');

  const now = new Date().toISOString();
  db.run(
    `INSERT INTO games (owner_id, title, description, folder, published, created_at, updated_at)
     VALUES (?, ?, ?, ?, 0, ?, ?)`,
    [req.user.id, title, description, folder, now, now],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'db error' });
      }
      const id = this.lastID;
      res.json({ id, title, description, published: 0, created_at: now });
    }
  );
});

// Publish / unpublish a game (owner only)
app.post('/api/games/:id/publish', authenticate, (req, res) => {
  const id = Number(req.params.id);
  const { publish } = req.body; // boolean
  db.get(`SELECT * FROM games WHERE id = ?`, [id], (err, game) => {
    if (err || !game) return res.status(404).json({ error: 'game not found' });
    if (game.owner_id !== req.user.id) return res.status(403).json({ error: 'not owner' });
    const now = new Date().toISOString();
    db.run(`UPDATE games SET published = ?, updated_at = ? WHERE id = ?`, [publish ? 1 : 0, now, id], function (err) {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json({ id, published: publish ? 1 : 0 });
    });
  });
});

// Get games list: public games + your own (if auth provided)
app.get('/api/games', (req, res) => {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    // try to decode but don't fail if invalid
    try {
      const payload = jwt.verify(auth.slice(7), JWT_SECRET);
      db.all(
        `SELECT g.*, u.username AS owner_name
         FROM games g JOIN users u ON u.id = g.owner_id
         WHERE g.published = 1 OR g.owner_id = ?
         ORDER BY g.created_at DESC`,
        [payload.id],
        (err, rows) => {
          if (err) return res.status(500).json({ error: 'db' });
          res.json(rows);
        }
      );
      return;
    } catch (e) {
      // fallthrough to public only
    }
  }
  // public only
  db.all(
    `SELECT g.*, u.username AS owner_name
     FROM games g JOIN users u ON u.id = g.owner_id
     WHERE g.published = 1
     ORDER BY g.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'db' });
      res.json(rows);
    }
  );
});

// Get single game metadata
app.get('/api/games/:id', (req, res) => {
  const id = Number(req.params.id);
  db.get(`SELECT g.*, u.username AS owner_name FROM games g JOIN users u ON u.id = g.owner_id WHERE g.id = ?`, [id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not found' });
    // if not published, only owner can view details
    const auth = req.headers.authorization;
    if (!row.published) {
      if (!auth || !auth.startsWith('Bearer ')) return res.status(403).json({ error: 'not published' });
      try {
        const payload = jwt.verify(auth.slice(7), JWT_SECRET);
        if (payload.id !== row.owner_id) return res.status(403).json({ error: 'not owner' });
      } catch (e) {
        return res.status(403).json({ error: 'not owner' });
      }
    }
    res.json(row);
  });
});

// Serve the game HTML for embedding (read index.html from folder)
app.get('/play/:id', (req, res) => {
  const id = Number(req.params.id);
  db.get(`SELECT * FROM games WHERE id = ?`, [id], (err, game) => {
    if (err || !game) return res.status(404).send('Game not found');
    if (!game.published) return res.status(403).send('Game not published');
    const indexPath = path.join(GAMES_DIR, game.folder, 'index.html');
    if (!fs.existsSync(indexPath)) return res.status(404).send('Game file missing');
    // send raw file
    res.sendFile(indexPath);
  });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
                               
