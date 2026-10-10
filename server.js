// Play-money casino: accounts + chips. Run: npm install && node server.js
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const START_CHIPS = 1000;               // chips given to every new account
const SESSION_MS = 7 * 24 * 3600 * 1000; // session lifetime
const PORT = process.env.PORT || 3000;

const db = new Database("casino.db");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  pass_hash TEXT NOT NULL,
  chips INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);`);

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

// --- tiny in-memory rate limit for auth endpoints (10 tries / 15 min per IP) ---
const hits = new Map();
function limit(req, res, next) {
  const now = Date.now(), key = req.ip;
  const arr = (hits.get(key) || []).filter((t) => now - t < 15 * 60 * 1000);
  if (arr.length >= 10) return res.status(429).json({ error: "Too many attempts. Try again later." });
  arr.push(now); hits.set(key, arr); next();
}

function startSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions VALUES (?,?,?)").run(sha(token), userId, Date.now() + SESSION_MS);
  res.cookie("sid", token, { httpOnly: true, sameSite: "strict", maxAge: SESSION_MS,
    secure: process.env.NODE_ENV === "production" });
}

function auth(req, res, next) {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
  if (!m) return res.status(401).json({ error: "Not logged in" });
  const row = db.prepare(`SELECT u.id, u.username, u.chips FROM sessions s
    JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?`).get(sha(m[1]), Date.now());
  if (!row) return res.status(401).json({ error: "Session expired" });
  req.user = row; req.tokenHash = sha(m[1]); next();
}

const validUser = (u) => typeof u === "string" && /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPass = (p) => typeof p === "string" && p.length >= 8 && p.length <= 72;

app.post("/api/signup", limit, (req, res) => {
  const { username, password } = req.body || {};
  if (!validUser(username)) return res.status(400).json({ error: "Username: 3-20 letters, numbers or _" });
  if (!validPass(password)) return res.status(400).json({ error: "Password must be 8-72 characters" });
  try {
    const info = db.prepare("INSERT INTO users(username, pass_hash, chips, created_at) VALUES (?,?,?,?)")
      .run(username, bcrypt.hashSync(password, 12), START_CHIPS, Date.now());
    startSession(res, info.lastInsertRowid);
    res.json({ username, chips: START_CHIPS });
  } catch (e) {
    res.status(409).json({ error: "Username already taken" });
  }
});

app.post("/api/login", limit, (req, res) => {
  const { username, password } = req.body || {};
  const u = validUser(username) && db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  // compare even when user is missing, so timing doesn't reveal which usernames exist
  const ok = bcrypt.compareSync(String(password || ""), u ? u.pass_hash : "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali");
  if (!u || !ok) return res.status(401).json({ error: "Wrong username or password" });
  startSession(res, u.id);
  res.json({ username: u.username, chips: u.chips });
});

app.post("/api/logout", auth, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(req.tokenHash);
  res.clearCookie("sid"); res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => res.json({ username: req.user.username, chips: req.user.chips }));

app.get("/api/leaderboard", (req, res) => {
  res.json(db.prepare("SELECT username, chips FROM users ORDER BY chips DESC LIMIT 10").all());
});

// Game endpoints go here. Keep every bet and random roll SERVER-side:
//   const bal = db.prepare("UPDATE users SET chips = chips + ? WHERE id = ?")...
// and use crypto.randomInt() for outcomes, matching the odds you show players.

app.listen(PORT, () => console.log(`Casino running on http://localhost:${PORT}`));
