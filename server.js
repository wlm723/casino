// Casino API and local static-file server. Run: npm install && npm start
const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const database = require("./database");

const START_BALANCE_CENTS = 10000;
const MIN_WAGER_CENTS = 10;
const MAX_WAGER_CENTS = 10000;
// Universal Pick-a-Box payout ladder: per-safe-pick multiplier by step climbed
// from the base row (step 0) toward the top. Step 0 stays below 1x so the
// first row never returns the full stake; later rows pay big, like a casino
// ladder. Note: this ladder is generous (virtual euros only) — expected
// return exceeds the stake, so balances can grow fast.
const PICK_MULTIPLIERS = [0.8, 1.5, 2.5, 5, 10, 20, 40, 100];
const multiplierForStep = (step) => (
  Number.isInteger(step) && step >= 0 && step < PICK_MULTIPLIERS.length
    ? PICK_MULTIPLIERS[step]
    : 0
);
const SESSION_MS = 7 * 24 * 3600 * 1000;
const PORT = process.env.PORT || 3000;

const app = express();
app.set("trust proxy", 1); // Vercel terminates TLS at its proxy; req.ip must use X-Forwarded-For
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const asyncRoute = (handler) => (req, res, next) => {
  Promise.resolve(handler(req, res, next)).catch(next);
};

// --- layered rate limit for auth endpoints (10 tries / 15 min per IP) ---
// Fast path: bounded in-memory window (per-process). Shared layer: auth_attempts
// table in Neon so limits hold across serverless instances and restarts.
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_MAX_TRIES = 10;
const RATE_MAX_TRACKED_IPS = 5000;
const hits = new Map();
function memoryLimitExceeded(ip, now) {
  const arr = (hits.get(ip) || []).filter((t) => now - t < RATE_WINDOW_MS);
  if (arr.length >= RATE_MAX_TRIES) return true;
  arr.push(now);
  if (!hits.has(ip) && hits.size >= RATE_MAX_TRACKED_IPS) {
    hits.delete(hits.keys().next().value); // evict oldest: map stays bounded
  }
  hits.set(ip, arr);
  return false;
}
async function sharedLimitExceeded(ip, now) {
  const { rows } = await database.query(
    `INSERT INTO auth_attempts(ip, count, window_start)
     VALUES ($1, 1, $2)
     ON CONFLICT (ip) DO UPDATE SET
       count = CASE WHEN auth_attempts.window_start <= $3 THEN 1 ELSE auth_attempts.count + 1 END,
       window_start = CASE WHEN auth_attempts.window_start <= $3 THEN $2 ELSE auth_attempts.window_start END
     RETURNING count`,
    [ip, now, now - RATE_WINDOW_MS]
  );
  return rows[0].count > RATE_MAX_TRIES;
}
let lastCleanup = 0;
function maybeCleanup(now) {
  if (now - lastCleanup < 10 * 60 * 1000) return;
  lastCleanup = now;
  // Fire-and-forget: works on long-running servers and opportunistically on serverless.
  database.query("DELETE FROM sessions WHERE expires_at <= $1", [now]).catch(() => {});
  database.query("DELETE FROM auth_attempts WHERE window_start <= $1", [now - RATE_WINDOW_MS]).catch(() => {});
}
function limit(req, res, next) {
  checkLimit(req, res, next).catch(next);
}
async function checkLimit(req, res, next) {
  const now = Date.now();
  if (memoryLimitExceeded(req.ip, now)) {
    return res.status(429).json({ error: "Too many attempts. Try again later." });
  }
  try {
    if (await sharedLimitExceeded(req.ip, now)) {
      return res.status(429).json({ error: "Too many attempts. Try again later." });
    }
  } catch (error) {
    // Shared counter unavailable: fall back to the in-memory layer above.
  }
  maybeCleanup(now);
  next();
}

const validUser = (u) => typeof u === "string" && /^[A-Za-z0-9_]{3,20}$/.test(u);
const validPass = (p) => typeof p === "string" && p.length >= 8 && p.length <= 72;
const safeCents = (value) => {
  let cents = value;
  if (typeof cents === "string") {
    if (!/^-?\d+$/.test(cents.trim())) {
      throw new Error("The account has an invalid euro balance.");
    }
    cents = Number(cents.trim());
  }
  if (!Number.isSafeInteger(cents) || cents < 0) {
    throw new Error("The account has an invalid euro balance.");
  }
  return cents;
};

app.post("/api/signup", limit, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!validUser(username)) return res.status(400).json({ error: "Username: 3-20 letters, numbers or _" });
  if (!validPass(password)) return res.status(400).json({ error: "Password must be 8-72 characters" });

  const token = crypto.randomBytes(32).toString("hex");
  const passHash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await database.query(
      `WITH new_user AS (
         INSERT INTO users(username, pass_hash, balance_cents, created_at)
         VALUES ($1, $2, $3, $4)
         RETURNING id, username, balance_cents
       ),
       new_session AS (
         INSERT INTO sessions(token_hash, user_id, expires_at)
         SELECT $5, id, $6 FROM new_user
       )
       SELECT username, balance_cents FROM new_user`,
      [
        username,
        passHash,
        START_BALANCE_CENTS,
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
    res.json({ username: rows[0].username, balanceCents: safeCents(rows[0].balance_cents) });
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
    ? await database.query("SELECT id, username, pass_hash, balance_cents FROM users WHERE LOWER(username) = LOWER($1)", [username])
    : { rows: [] };
  const user = result.rows[0];
  let ok = false;
  try {
    ok = await bcrypt.compare(String(password || ""), user ? user.pass_hash : "$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali");
  } catch (error) {
    ok = false; // malformed stored hash: treat as wrong password, not a crash
  }
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
  res.json({ username: user.username, balanceCents: safeCents(user.balance_cents) });
}));

async function authenticate(req, res, next) {
  const match = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
  if (!match) return res.status(401).json({ error: "Not logged in" });

  try {
    const tokenHash = sha(match[1]);
    const { rows } = await database.query(
      `SELECT u.id, u.username, u.balance_cents FROM sessions s
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
  res.json({ username: req.user.username, balanceCents: safeCents(req.user.balance_cents) });
});

app.post("/api/pickbox/rounds", authenticate, asyncRoute(async (req, res) => {
  const { mode, rows, wagerCents } = req.body || {};
  if (!["fixed", "luck"].includes(mode)) {
    return res.status(400).json({ error: "Choose a valid Pick a Box mode." });
  }
  if (!Number.isInteger(rows) || rows < 2 || rows > 8) {
    return res.status(400).json({ error: "Rows must be a whole number from 2 to 8." });
  }
  if (!Number.isSafeInteger(wagerCents) || wagerCents < MIN_WAGER_CENTS || wagerCents > MAX_WAGER_CENTS) {
    return res.status(400).json({ error: "Bet must be between €0.10 and €100.00." });
  }

  const safeColumns = Array.from({ length: rows }, (_, row) => {
    if (mode === "fixed") return row === rows - 1 ? null : -1;
    const columns = Array.from({ length: 2 * (row + 1) }, (_, column) => column);
    for (let index = columns.length - 1; index > 0; index -= 1) {
      const swapIndex = crypto.randomInt(index + 1);
      [columns[index], columns[swapIndex]] = [columns[swapIndex], columns[index]];
    }
    return columns.slice(0, columns.length / 2);
  });
  const now = Date.now();
  const id = crypto.randomUUID();

  const { rows: createdRows } = await database.query(
    `WITH debited AS (
       UPDATE users
       SET balance_cents = balance_cents - $2
       WHERE id = $1 AND balance_cents >= $2
       RETURNING balance_cents
     ),
     abandoned AS (
       UPDATE pickbox_rounds
       SET status = 'abandoned', updated_at = $7
       WHERE user_id = $1 AND status = 'active'
         AND EXISTS (SELECT 1 FROM debited)
       RETURNING id
     ),
     created AS (
       INSERT INTO pickbox_rounds
       (id, user_id, mode, row_count, current_row, wager_cents, status, safe_columns, created_at, updated_at)
       SELECT $3, $1, $4, $5, $6, $2, 'active', $8::jsonb, $7, $7
       FROM debited
       RETURNING id
     )
     SELECT created.id AS round_id, debited.balance_cents
     FROM created CROSS JOIN debited`,
    [req.user.id, wagerCents, id, mode, rows, rows - 1, now, JSON.stringify(safeColumns)]
  );
  if (!createdRows[0]) {
    return res.status(409).json({ error: "Insufficient balance for that bet." });
  }
  res.status(201).json({
    roundId: createdRows[0].round_id,
    currentRow: rows - 1,
    balanceCents: safeCents(createdRows[0].balance_cents),
    multipliers: PICK_MULTIPLIERS.slice(0, rows)
  });
}));

app.post("/api/pickbox/rounds/:roundId/pick", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  const { row, column } = req.body || {};
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }
  if (!Number.isInteger(row) || !Number.isInteger(column) || row < 0 || column < 0) {
    return res.status(400).json({ error: "Choose a valid box." });
  }

  const { rows: roundRows } = await database.query(
    `SELECT id, row_count, current_row, wager_cents, status, safe_columns
     FROM pickbox_rounds WHERE id = $1 AND user_id = $2`,
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round || round.status !== "active") {
    return res.status(409).json({ error: "This round is no longer active. Start a new round." });
  }
  if (row !== Number(round.current_row) || row >= Number(round.row_count) || column >= 2 * (row + 1)) {
    return res.status(400).json({ error: "Choose a box in the active row." });
  }

  const safeColumn = round.safe_columns[row];
  const wonPick = safeColumn === null
    || safeColumn === column
    || (Array.isArray(safeColumn) && safeColumn.includes(column));
  const status = wonPick
    ? (row === 0 ? "won" : "active")
    : "lost";
  const nextRow = wonPick && row > 0 ? row - 1 : row;
  const stepIndex = Number(round.row_count) - 1 - row;
  const multiplier = wonPick ? multiplierForStep(stepIndex) : 0;
  const payoutCents = wonPick ? Math.floor(Number(round.wager_cents) * multiplier) : 0;
  const { rows: updatedRows } = await database.query(
    `WITH changed_round AS (
       UPDATE pickbox_rounds
       SET status = $1, current_row = $2, updated_at = $3
       WHERE id = $4 AND user_id = $5 AND status = 'active' AND current_row = $6
       RETURNING status, current_row
     ),
     credited AS (
       UPDATE users
       SET balance_cents = balance_cents + $7
       WHERE id = $5 AND $8::boolean
         AND EXISTS (SELECT 1 FROM changed_round)
       RETURNING balance_cents
     )
     SELECT changed_round.status, changed_round.current_row,
       COALESCE(
         (SELECT balance_cents FROM credited),
         (SELECT balance_cents FROM users WHERE id = $5)
       ) AS balance_cents
     FROM changed_round`,
    [status, nextRow, Date.now(), roundId, req.user.id, row, payoutCents, wonPick]
  );
  if (!updatedRows[0]) {
    return res.status(409).json({ error: "That pick was already submitted. Please try again." });
  }

  const completed = status !== "active";
  res.json({
    safe: wonPick,
    status,
    currentRow: Number(updatedRows[0].current_row),
    balanceCents: safeCents(updatedRows[0].balance_cents),
    payoutCents: safeCents(payoutCents),
    multiplier,
    safeColumns: completed ? round.safe_columns : undefined
  });
}));

app.post("/api/pickbox/rounds/:roundId/cashout", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }

  const { rows: roundRows } = await database.query(
    `SELECT current_row, row_count, status, safe_columns
     FROM pickbox_rounds WHERE id = $1 AND user_id = $2`,
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round || round.status !== "active") {
    return res.status(409).json({ error: "This round is no longer active. Start a new round." });
  }
  if (Number(round.current_row) >= Number(round.row_count) - 1) {
    return res.status(400).json({ error: "Make a safe pick before ending the round." });
  }

  const { rows: updatedRows } = await database.query(
    `WITH changed_round AS (
       UPDATE pickbox_rounds
       SET status = 'cashed_out', updated_at = $1
       WHERE id = $2 AND user_id = $3 AND status = 'active' AND current_row = $4
       RETURNING status
     )
     SELECT changed_round.status, users.balance_cents
     FROM changed_round JOIN users ON users.id = $3`,
    [Date.now(), roundId, req.user.id, round.current_row]
  );
  if (!updatedRows[0]) {
    return res.status(409).json({ error: "That action was already submitted. Please try again." });
  }
  res.json({
    status: "cashed_out",
    safeColumns: round.safe_columns,
    balanceCents: safeCents(updatedRows[0].balance_cents)
  });
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
