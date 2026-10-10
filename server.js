// Casino API and local static-file server. Run: npm install && npm start
const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const database = require("./database");

const START_CHIPS = 1000;
const SESSION_MS = 7 * 24 * 3600 * 1000;
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const asyncRoute = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

// --- tiny in-memory rate limit for auth endpoints (10 tries / 15 min per IP) ---
const hits = new Map();
function limit(req, res, next) {
  const now = Date.now(), key = req.ip;
  const arr = (hits.get(key) || []).filter((t) => now - t < 15 * 60 * 1000);
  if (arr.length >= 10) return res.status(429).json({ error: "Too many attempts. Try again later." });
  arr.push(now); hits.set(key, arr); next();
}

const validUser = (u) => typeof u === "string" && /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPass = (p) => typeof p === "string" && p.length >= 8 && p.length <= 72;

app.post("/api/signup", limit, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!validUser(username)) return res.status(400).json({ error: "Username: 3-20 letters, numbers or _" });
  if (!validPass(password)) return res.status(400).json({ error: "Password must be 8-72 characters" });

  const token = crypto.randomBytes(32).toString("hex");
  try {
    const { rows } = await database.query(
      `WITH new_user AS (
         INSERT INTO users(username, pass_hash, chips, created_at)
         VALUES ($1, $2, $3, $4)
         RETURNING id, username, chips
       ),
       new_session AS (
         INSERT INTO sessions(token_hash, user_id, expires_at)
         SELECT $5, id, $6 FROM new_user
       )
       SELECT username, chips FROM new_user`,
      [
        username,
        bcrypt.hashSync(password, 12),
        START_CHIPS,
        Date.now(),
        sha(token),
        Date.now() + SESSION_MS
      ]
    );
    res.cookie("sid", token, {
      httpOnly: true,
      sameSite: "strict",
      maxAge: SESSION_MS,
      secure: process.env.NODE_ENV === "production"
    });
    res.json({ username: rows[0].username, chips: rows[0].chips });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Username already taken" });
    }
    throw error;
  }
}));

app.post("/api/login", limit, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  const result = validUser(username)
    ? await database.query("SELECT id, username, pass_hash, chips FROM users WHERE LOWER(username) = LOWER($1)", [username])
    : { rows: [] };
  const user = result.rows[0];
  const ok = bcrypt.compareSync(String(password || ""), user ? user.pass_hash : "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali");
  if (!user || !ok) return res.status(401).json({ error: "Wrong username or password" });

  const token = crypto.randomBytes(32).toString("hex");
  await database.query(
    "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES ($1, $2, $3)",
    [sha(token), user.id, Date.now() + SESSION_MS]
  );
  res.cookie("sid", token, {
    httpOnly: true,
    sameSite: "strict",
    maxAge: SESSION_MS,
    secure: process.env.NODE_ENV === "production"
  });
  res.json({ username: user.username, chips: user.chips });
}));

async function authenticate(req, res, next) {
  const match = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
  if (!match) return res.status(401).json({ error: "Not logged in" });

  try {
    const tokenHash = sha(match[1]);
    const { rows } = await database.query(
      `SELECT u.id, u.username, u.chips FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > $2`,
      [tokenHash, Date.now()]
    );
    if (!rows[0]) return res.status(401).json({ error: "Session expired" });
    req.user = rows[0];
    req.tokenHash = tokenHash;
    next();
  } catch (error) {
    next(error);
  }
}

app.post("/api/logout", authenticate, asyncRoute(async (req, res) => {
  await database.query("DELETE FROM sessions WHERE token_hash = $1", [req.tokenHash]);
  res.clearCookie("sid");
  res.json({ ok: true });
}));

app.get("/api/me", authenticate, (req, res) => {
  res.json({ username: req.user.username, chips: req.user.chips });
});

app.get("/api/leaderboard", asyncRoute(async (req, res) => {
  const { rows } = await database.query("SELECT username, chips FROM users ORDER BY chips DESC LIMIT 10");
  res.json(rows);
}));

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON request body" });
  }

  console.error("Request failed:", error);
  if (error.code === "DATABASE_NOT_CONFIGURED") {
    return res.status(503).json({ error: "Database is not configured on this deployment." });
  }
  res.status(500).json({ error: "An internal server error occurred." });
});

app.listen(PORT, () => console.log(`Casino listening on port ${PORT}`));
