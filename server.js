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
// Cumulative payout across ladder steps 0..lastStep (each step floored,
// matching the pick endpoint). Shared by live credit, bomb revokes, and
// /api/history so the three can never diverge.
function pickboxTotalToStep(wager, lastStep) {
  let total = 0;
  for (let step = 0; step <= lastStep; step += 1) {
    total += Math.floor(wager * multiplierForStep(step));
  }
  return total;
}
const SESSION_SHORT_MS = 24 * 3600 * 1000; // default: browser session, 24h server expiry
const SESSION_LONG_MS = 30 * 24 * 3600 * 1000; // "keep me logged in": 30 days
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
  database.query("DELETE FROM server_logs WHERE created_at <= $1", [now - 7 * 24 * 3600 * 1000]).catch(() => {});
}
// Persistent server log: mirrors to stdout (Vercel picks it up) and stores in
// Neon for `node admin.js logs`. Persisted volume throttled to ~1 row/sec.
let lastLogInsert = 0;
function logEvent(level, message) {
  const text = String(message).slice(0, 500);
  if (level === "error") console.error(text);
  else console.warn(text);
  const now = Date.now();
  if (now - lastLogInsert < 1000) return;
  lastLogInsert = now;
  database.query("INSERT INTO server_logs(level, message, created_at) VALUES ($1, $2, $3)", [level, text, now]).catch(() => {});
}
function limit(req, res, next) {
  checkLimit(req, res, next).catch(next);
}
async function checkLimit(req, res, next) {
  const now = Date.now();
  if (memoryLimitExceeded(req.ip, now)) {
    logEvent("warn", `Auth rate-limited (memory): ip=${req.ip} path=${req.path}`);
    return res.status(429).json({ error: "Too many attempts. Try again later." });
  }
  try {
    if (await sharedLimitExceeded(req.ip, now)) {
      logEvent("warn", `Auth rate-limited (shared): ip=${req.ip} path=${req.path}`);
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
const sessionMeta = (req) => ({
  ip: String(req.ip || "").slice(0, 64),
  agent: String(req.headers["user-agent"] || "").slice(0, 200),
});
function sessionCookie(res, token, persistent) {
  res.cookie("sid", token, {
    httpOnly: true,
    sameSite: "strict",
    ...(persistent ? { maxAge: SESSION_LONG_MS } : {}),
    secure: process.env.NODE_ENV === "production"
  });
}
async function createSession(req, res, userId, persistent) {
  const token = crypto.randomBytes(32).toString("hex");
  const meta = sessionMeta(req);
  const expires = Date.now() + (persistent ? SESSION_LONG_MS : SESSION_SHORT_MS);
  await database.query(
    "INSERT INTO sessions(token_hash, user_id, expires_at, created_at, user_agent, ip, persistent) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [sha(token), userId, expires, Date.now(), meta.agent, meta.ip, persistent ? 1 : 0]
  );
  sessionCookie(res, token, persistent);
}
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
// Signed per-action delta (a bomb/crash revokes earlier payouts as a
// negative number). Balances themselves stay guarded by safeCents.
const safeDelta = (value) => {
  if (!Number.isSafeInteger(value)) {
    throw new Error("The payout amount is invalid.");
  }
  return value;
};

app.post("/api/signup", limit, asyncRoute(async (req, res) => {
  const { username, password, remember } = req.body || {};
  if (!validUser(username)) return res.status(400).json({ error: "Username: 3-20 letters, numbers or _" });
  if (!validPass(password)) return res.status(400).json({ error: "Password must be 8-72 characters" });

  const persistent = remember === true;
  const passHash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await database.query(
      "INSERT INTO users(username, pass_hash, balance_cents, created_at) VALUES ($1, $2, $3, $4) RETURNING id, username, balance_cents",
      [username, passHash, START_BALANCE_CENTS, Date.now()]
    );
    await createSession(req, res, rows[0].id, persistent);
    res.json({ username: rows[0].username, balanceCents: safeCents(rows[0].balance_cents) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Username already taken" });
    }
    throw error;
  }
}));

app.post("/api/login", limit, asyncRoute(async (req, res) => {
  const { username, password, remember } = req.body || {};
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
  if (!user || !ok) {
    logEvent("warn", `Auth failed: login username="${username}" ip=${req.ip}`);
    return res.status(401).json({ error: "Wrong username or password" });
  }

  await createSession(req, res, user.id, remember === true);
  res.json({ username: user.username, balanceCents: safeCents(user.balance_cents) });
}));

async function authenticate(req, res, next) {
  const match = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
  if (!match) return res.status(401).json({ error: "Not logged in" });

  try {
    const tokenHash = sha(match[1]);
    const now = Date.now();
    const { rows } = await database.query(
      `SELECT u.id, u.username, u.balance_cents, s.expires_at, s.persistent FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > $2`,
      [tokenHash, now]
    );
    if (!rows[0]) return res.status(401).json({ error: "Session expired" });
    req.user = rows[0];
    req.tokenHash = tokenHash;
    // Sliding refresh: extend sessions in their last day without extra reads.
    if (rows[0].expires_at - now < 24 * 3600 * 1000) {
      const persistent = Number(rows[0].persistent) === 1;
      const fresh = now + (persistent ? SESSION_LONG_MS : SESSION_SHORT_MS);
      await database.query("UPDATE sessions SET expires_at = $1 WHERE token_hash = $2", [fresh, tokenHash]);
      sessionCookie(res, match[1], persistent);
    }
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

async function listSessions(userId) {
  const { rows } = await database.query(
    "SELECT token_hash, created_at, expires_at, ip, user_agent FROM sessions WHERE user_id = $1 AND expires_at > $2 ORDER BY created_at DESC",
    [userId, Date.now()]
  );
  return rows.map((row) => ({
    tokenHash: row.token_hash,
    createdAt: Number(row.created_at) || 0,
    expiresAt: Number(row.expires_at),
    ip: row.ip || "",
    agent: row.user_agent || ""
  }));
}

app.get("/api/sessions", authenticate, asyncRoute(async (req, res) => {
  res.json({ current: req.tokenHash, sessions: await listSessions(req.user.id) });
}));

app.get("/api/history", authenticate, asyncRoute(async (req, res) => {
  const userId = req.user.id;

  const [pbRes, chRes, plRes, avRes] = await Promise.all([
    database.query(
      `SELECT id, wager_cents, status, row_count, current_row, created_at
       FROM pickbox_rounds WHERE user_id = $1 AND status != 'active'
       ORDER BY created_at DESC LIMIT 25`,
      [userId]
    ),
    database.query(
      `SELECT id, wager_cents, status, lane_count, current_lane, difficulty, created_at
       FROM chicken_rounds WHERE user_id = $1 AND status != 'active'
       ORDER BY created_at DESC LIMIT 25`,
      [userId]
    ),
    database.query(
      `SELECT id, wager_cents, multiplier, payout_cents, row_count, risk, created_at
       FROM plinko_rounds WHERE user_id = $1
       ORDER BY created_at DESC LIMIT 25`,
      [userId]
    ),
    database.query(
      `SELECT id, wager_cents, status, crash_point, cashout_mult, payout_cents, created_at
       FROM aviator_rounds WHERE user_id = $1 AND status != 'active'
       ORDER BY created_at DESC LIMIT 25`,
      [userId]
    )
  ]);

  const items = [];

  pbRes.rows.forEach((r) => {
    const wager = Number(r.wager_cents) || 0;
    let payout = 0;
    let outcome = "Lost";
    let badgeClass = "loss";

    // Picks credit cumulatively (see pickboxTotalToStep): history reports
    // the same total the live endpoint paid.
    if (r.status === "won") {
      const lastStep = Number(r.row_count) - 1;
      const mult = multiplierForStep(lastStep);
      payout = pickboxTotalToStep(wager, lastStep);
      outcome = `${mult}x Won`;
      badgeClass = "win";
    } else if (r.status === "cashed_out") {
      const lastStep = Math.max(0, Number(r.row_count) - 1 - (Number(r.current_row) + 1));
      const mult = multiplierForStep(lastStep);
      payout = pickboxTotalToStep(wager, lastStep);
      outcome = `${mult}x Cashed out`;
      badgeClass = "cash";
    } else if (r.status === "abandoned") {
      outcome = "Abandoned";
    }

    items.push({
      id: r.id,
      game: "Pick a Box",
      wagerCents: wager,
      payoutCents: payout,
      outcome,
      badgeClass,
      createdAt: Number(r.created_at) || 0
    });
  });

  chRes.rows.forEach((r) => {
    const wager = Number(r.wager_cents) || 0;
    let payout = 0;
    let outcome = "Crashed";
    let badgeClass = "loss";

    // Crossings credit cumulatively (see chickenTotalToLanes): history
    // reports the same total the live endpoint paid.
    if (r.status === "won") {
      const crossed = Number(r.lane_count);
      const mult = chickenMultiplierForStep(r.difficulty, crossed - 1);
      payout = chickenTotalToLanes(wager, r.difficulty, crossed);
      outcome = `${mult}x Won`;
      badgeClass = "win";
    } else if (r.status === "cashed_out") {
      const crossed = Math.max(0, Number(r.current_lane));
      const mult = chickenMultiplierForStep(r.difficulty, crossed - 1);
      payout = chickenTotalToLanes(wager, r.difficulty, crossed);
      outcome = `${mult}x Cashed out`;
      badgeClass = "cash";
    } else if (r.status === "abandoned") {
      outcome = "Abandoned";
    }

    items.push({
      id: r.id,
      game: "Chicken Road",
      wagerCents: wager,
      payoutCents: payout,
      outcome,
      badgeClass,
      createdAt: Number(r.created_at) || 0
    });
  });

  plRes.rows.forEach((r) => {
    const wager = Number(r.wager_cents) || 0;
    const payout = Number(r.payout_cents) || 0;
    const mult = Number(r.multiplier) || 0;
    items.push({
      id: r.id,
      game: "Plinko",
      wagerCents: wager,
      payoutCents: payout,
      outcome: `${mult}x (${r.risk})`,
      badgeClass: payout > wager ? "win" : (payout === wager ? "cash" : "loss"),
      createdAt: Number(r.created_at) || 0
    });
  });

  avRes.rows.forEach((r) => {
    const wager = Number(r.wager_cents) || 0;
    const payout = Number(r.payout_cents) || 0;
    let outcome = `Crashed @ ${Number(r.crash_point).toFixed(2)}x`;
    let badgeClass = "loss";

    if (r.status === "cashed_out") {
      const mult = Number(r.cashout_mult) || 0;
      outcome = `${mult.toFixed(2)}x Cashed out`;
      badgeClass = "win";
    } else if (r.status === "abandoned") {
      outcome = "Abandoned";
    }

    items.push({
      id: r.id,
      game: "Aviator",
      wagerCents: wager,
      payoutCents: payout,
      outcome,
      badgeClass,
      createdAt: Number(r.created_at) || 0
    });
  });

  items.sort((a, b) => b.createdAt - a.createdAt);

  res.json({ history: items.slice(0, 50) });
}));


app.delete("/api/sessions", authenticate, asyncRoute(async (req, res) => {
  const { tokenHash, allOthers } = req.body || {};
  if (allOthers === true) {
    await database.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [req.user.id, req.tokenHash]);
  } else {
    if (typeof tokenHash !== "string" || !/^[a-f0-9]{64}$/.test(tokenHash)) {
      return res.status(400).json({ error: "Choose a valid session." });
    }
    await database.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash = $2", [req.user.id, tokenHash]);
  }
  res.json({ current: req.tokenHash, sessions: await listSessions(req.user.id) });
}));

async function haveSuffix(req, wagerCents) {
  try {
    const { rows } = await database.query("SELECT balance_cents FROM users WHERE id = $1", [req.user.id]);
    if (!rows[0] || rows[0].balance_cents == null) return "";
    return ` Bet was €${(Number(wagerCents) / 100).toFixed(2)}, balance is €${(Number(rows[0].balance_cents) / 100).toFixed(2)}.`;
  } catch {
    return "";
  }
}

function logShortfall(req, wagerCents) {  // Fire-and-forget diagnostic for 409s: records what the ledger actually held.
  database.query("SELECT balance_cents FROM users WHERE id = $1", [req.user.id]).then(
    ({ rows }) => logEvent(
      "warn",
      `Insufficient balance: user=${req.user.username} bet=${wagerCents} ` +
      `have=${rows[0] ? rows[0].balance_cents : "unknown"} ip=${req.ip}`
    ),
    () => {}
  );
}

app.post("/api/pickbox/rounds", authenticate, asyncRoute(async (req, res) => {
  const { mode, rows, wagerCents } = req.body || {};
  if (!["fixed", "luck"].includes(mode)) {
    return res.status(400).json({ error: "Couldn't start that round. Please try again." });
  }
  if (!Number.isInteger(rows) || rows < 2 || rows > 8) {
    return res.status(400).json({ error: "Rows must be a whole number from 2 to 8." });
  }
  if (!Number.isSafeInteger(wagerCents) || wagerCents < MIN_WAGER_CENTS || wagerCents > MAX_WAGER_CENTS) {
    return res.status(400).json({ error: "Bet must be between €0.10 and €100.00." });
  }

  const now = Date.now();
  const id = crypto.randomUUID();
  const safeColumns = Array.from({ length: rows }, (_, row) => {
    if (mode === "fixed") return row === rows - 1 ? null : -1;
    const columns = Array.from({ length: 2 * (row + 1) }, (_, column) => column);
    for (let index = columns.length - 1; index > 0; index -= 1) {
      const swapIndex = crypto.randomInt(index + 1);
      [columns[index], columns[swapIndex]] = [columns[swapIndex], columns[index]];
    }
    // Luck mode is generous: 3 in 4 boxes are safe per row (fixed mode and
    // dark theme keep the strict house odds).
    const safeCount = mode === "luck"
      ? Math.floor(columns.length * 3 / 4)
      : columns.length / 2;
    return columns.slice(0, safeCount);
  });

  // Plain sequential debit: one statement, matched rows checked directly.
  const { rows: debitedRows } = await database.query(
    `UPDATE users
     SET balance_cents = balance_cents - $2
     WHERE id = $1 AND balance_cents >= $2
     RETURNING balance_cents`,
    [req.user.id, wagerCents]
  );
  if (!debitedRows[0]) {
    logShortfall(req, wagerCents);
    return res.status(409).json({ error: `Insufficient balance for that bet.${await haveSuffix(req, wagerCents)}` });
  }
  try {
    // One round trip: retire any live round and record the new one together.
    await database.query(
      `WITH abandoned AS (
         UPDATE pickbox_rounds
         SET status = 'abandoned', updated_at = $2
         WHERE user_id = $1 AND status = 'active'
       )
       INSERT INTO pickbox_rounds
       (id, user_id, mode, row_count, current_row, wager_cents, status, safe_columns, created_at, updated_at)
       VALUES ($3, $1, $4, $5, $6, $7, 'active', $8::jsonb, $9, $9)`,
      [req.user.id, now, id, mode, rows, rows - 1, wagerCents, JSON.stringify(safeColumns), now]
    );
  } catch (error) {
    // Never take money without recording the round: refund the debit.
    await database.query(
      "UPDATE users SET balance_cents = balance_cents + $1 WHERE id = $2",
      [wagerCents, req.user.id]
    ).catch(() => {});
    throw error;
  }
  res.status(201).json({
    roundId: id,
    currentRow: rows - 1,
    balanceCents: safeCents(debitedRows[0].balance_cents),
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
  const wager = Number(round.wager_cents) || 0;
  const multiplier = wonPick ? multiplierForStep(stepIndex) : 0;
  let payoutCents = wonPick ? Math.floor(wager * multiplier) : 0;
  if (!wonPick) {
    // Bomb revokes everything this round already paid, so losing always
    // costs exactly the stake instead of profiting from earlier picks.
    payoutCents -= pickboxTotalToStep(wager, Number(round.row_count) - 2 - row);
  }
  // One round trip: resolve the round and credit the payout together. The
  // credit only applies when the round row actually changes, so a duplicate
  // submit still 409s without ever paying twice. GREATEST keeps a large
  // revoke from driving the balance below zero (e.g. winnings spent
  // mid-round on another game).
  const { rows: settledRows } = await database.query(
    `WITH changed_round AS (
       UPDATE pickbox_rounds
       SET status = $1, current_row = $2, updated_at = $3
       WHERE id = $4 AND user_id = $5 AND status = 'active' AND current_row = $6
       RETURNING status, current_row
     )
     UPDATE users
     SET balance_cents = GREATEST(0, balance_cents + $7)
     WHERE id = $5 AND EXISTS (SELECT 1 FROM changed_round)
     RETURNING balance_cents,
       (SELECT status FROM changed_round) AS status,
       (SELECT current_row FROM changed_round) AS current_row`,
    [status, nextRow, Date.now(), roundId, req.user.id, row, payoutCents]
  );
  if (!settledRows[0]) {
    return res.status(409).json({ error: "That pick was already submitted. Please try again." });
  }

  const completed = status !== "active";
  res.json({
    safe: wonPick,
    status,
    currentRow: Number(settledRows[0].current_row),
    balanceCents: safeCents(settledRows[0].balance_cents),
    payoutCents: safeDelta(payoutCents),
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

const CHICKEN_MIN_LANES = 5;
const CHICKEN_MAX_LANES = 10;
// Per-difficulty crash chance and payout ladder. Lane 0 stays below 1x in
// every ladder: the first crossing never returns the full stake.
// Generous ladders (virtual euros only).
const CHICKEN_DIFFICULTIES = {
  easy:     { crashPercent: 30, multipliers: [0.95, 1.08, 1.2, 1.35, 1.55, 1.8, 2.1, 2.5, 3.0, 3.6] },
  medium:   { crashPercent: 50, multipliers: [0.9, 1.15, 1.45, 1.85, 2.4, 3.1, 4.0, 5.2, 6.8, 9.0] },
  hard:     { crashPercent: 65, multipliers: [0.8, 1.3, 1.9, 2.8, 4.2, 6.3, 9.5, 14, 21, 32] },
  hardcore: { crashPercent: 80, multipliers: [0.7, 1.5, 2.8, 5, 9, 16, 28, 50, 90, 160] },
};
const chickenLadder = (difficulty) => (
  (CHICKEN_DIFFICULTIES[difficulty] || CHICKEN_DIFFICULTIES.medium).multipliers
);
const chickenMultiplierForStep = (difficulty, step) => {
  const mult = chickenLadder(difficulty)[step];
  return typeof mult === "number" && mult > 0 ? mult : 0;
};
// Cumulative payout across lanes 0..crossed-1 (each lane floored, matching
// the cross endpoint). Shared by live credit, crash revokes, and
// /api/history so the three can never diverge.
function chickenTotalToLanes(wager, difficulty, crossed) {
  let total = 0;
  for (let step = 0; step < crossed; step += 1) {
    total += Math.floor(wager * chickenMultiplierForStep(difficulty, step));
  }
  return total;
}

app.post("/api/chicken/rounds", authenticate, asyncRoute(async (req, res) => {
  const { mode, difficulty, lanes, wagerCents } = req.body || {};
  if (!["fixed", "luck"].includes(mode)) {
    return res.status(400).json({ error: "Couldn't start that round. Please try again." });
  }
  if (!Object.prototype.hasOwnProperty.call(CHICKEN_DIFFICULTIES, difficulty)) {
    return res.status(400).json({ error: "Choose a valid difficulty." });
  }
  if (!Number.isInteger(lanes) || lanes < CHICKEN_MIN_LANES || lanes > CHICKEN_MAX_LANES) {
    return res.status(400).json({ error: "Lanes must be a whole number from 5 to 10." });
  }
  if (!Number.isSafeInteger(wagerCents) || wagerCents < MIN_WAGER_CENTS || wagerCents > MAX_WAGER_CENTS) {
    return res.status(400).json({ error: "Bet must be between €0.10 and €100.00." });
  }

  // Luck mode is generous: the per-lane crash chance is halved (fixed mode
  // and dark theme keep the strict house odds).
  const crashPercent = mode === "luck"
    ? Math.floor(CHICKEN_DIFFICULTIES[difficulty].crashPercent / 2)
    : CHICKEN_DIFFICULTIES[difficulty].crashPercent;
  const laneSafe = mode === "fixed"
    ? Array.from({ length: lanes }, (_, lane) => lane === 0)
    : Array.from({ length: lanes }, () => crypto.randomInt(100) >= crashPercent);
  const now = Date.now();
  const id = crypto.randomUUID();

  // Plain sequential debit: one statement, matched rows checked directly.
  const { rows: debitedRows } = await database.query(
    `UPDATE users
     SET balance_cents = balance_cents - $2
     WHERE id = $1 AND balance_cents >= $2
     RETURNING balance_cents`,
    [req.user.id, wagerCents]
  );
  if (!debitedRows[0]) {
    logShortfall(req, wagerCents);
    return res.status(409).json({ error: `Insufficient balance for that bet.${await haveSuffix(req, wagerCents)}` });
  }
  try {
    // One round trip: retire any live round and record the new one together.
    await database.query(
      `WITH abandoned AS (
         UPDATE chicken_rounds
         SET status = 'abandoned', updated_at = $2
         WHERE user_id = $1 AND status = 'active'
       )
       INSERT INTO chicken_rounds
       (id, user_id, lane_count, current_lane, wager_cents, status, lanes, created_at, updated_at, mode, difficulty)
       VALUES ($3, $1, $4, 0, $5, 'active', $6::jsonb, $7, $7, $8, $9)`,
      [req.user.id, now, id, lanes, wagerCents, JSON.stringify(laneSafe), now, mode, difficulty]
    );
  } catch (error) {
    // Never take money without recording the round: refund the debit.
    await database.query(
      "UPDATE users SET balance_cents = balance_cents + $1 WHERE id = $2",
      [wagerCents, req.user.id]
    ).catch(() => {});
    throw error;
  }
  res.status(201).json({
    roundId: id,
    currentLane: 0,
    balanceCents: safeCents(debitedRows[0].balance_cents),
    difficulty,
    multipliers: chickenLadder(difficulty).slice(0, lanes)
  });
}));

app.post("/api/chicken/rounds/:roundId/cross", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }

  const { rows: roundRows } = await database.query(
    `SELECT id, lane_count, current_lane, wager_cents, status, lanes, difficulty
     FROM chicken_rounds WHERE id = $1 AND user_id = $2`,
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round || round.status !== "active") {
    return res.status(409).json({ error: "This round is no longer active. Start a new round." });
  }
  const lane = Number(round.current_lane);
  if (!Number.isInteger(lane) || lane < 0 || lane >= Number(round.lane_count)) {
    return res.status(409).json({ error: "This round is no longer active. Start a new round." });
  }

  const safe = round.lanes[lane] === true;
  const status = safe
    ? (lane === Number(round.lane_count) - 1 ? "won" : "active")
    : "lost";
  const nextLane = safe ? lane + 1 : lane;
  const wager = Number(round.wager_cents) || 0;
  const multiplier = safe ? chickenMultiplierForStep(round.difficulty, lane) : 0;
  let payoutCents = safe ? Math.floor(wager * multiplier) : 0;
  if (!safe) {
    // Crash revokes everything this round already paid, so losing always
    // costs exactly the stake instead of profiting from earlier lanes.
    payoutCents -= chickenTotalToLanes(wager, round.difficulty, lane);
  }
  // One round trip: resolve the lane and credit the payout together. The
  // credit only applies when the round row actually changes, so a duplicate
  // submit still 409s without ever paying twice. GREATEST keeps a large
  // revoke from driving the balance below zero (e.g. winnings spent
  // mid-round on another game).
  const { rows: settledRows } = await database.query(
    `WITH changed_round AS (
       UPDATE chicken_rounds
       SET status = $1, current_lane = $2, updated_at = $3
       WHERE id = $4 AND user_id = $5 AND status = 'active' AND current_lane = $6
       RETURNING status, current_lane
     )
     UPDATE users
     SET balance_cents = GREATEST(0, balance_cents + $7)
     WHERE id = $5 AND EXISTS (SELECT 1 FROM changed_round)
     RETURNING balance_cents,
       (SELECT status FROM changed_round) AS status,
       (SELECT current_lane FROM changed_round) AS current_lane`,
    [status, nextLane, Date.now(), roundId, req.user.id, lane, payoutCents]
  );
  if (!settledRows[0]) {
    return res.status(409).json({ error: "That crossing was already submitted. Please try again." });
  }

  const completed = status !== "active";
  res.json({
    safe,
    status,
    currentLane: Number(settledRows[0].current_lane),
    balanceCents: safeCents(settledRows[0].balance_cents),
    payoutCents: safeDelta(payoutCents),
    multiplier,
    lanes: completed ? round.lanes : undefined
  });
}));

app.post("/api/chicken/rounds/:roundId/cashout", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }

  const { rows: roundRows } = await database.query(
    `SELECT current_lane, lane_count, status, lanes
     FROM chicken_rounds WHERE id = $1 AND user_id = $2`,
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round || round.status !== "active") {
    return res.status(409).json({ error: "This round is no longer active. Start a new round." });
  }
  if (Number(round.current_lane) <= 0) {
    return res.status(400).json({ error: "Cross at least one lane before cashing out." });
  }

  const { rows: updatedRows } = await database.query(
    `WITH changed_round AS (
       UPDATE chicken_rounds
       SET status = 'cashed_out', updated_at = $1
       WHERE id = $2 AND user_id = $3 AND status = 'active' AND current_lane = $4
       RETURNING status
     )
     SELECT changed_round.status, users.balance_cents
     FROM changed_round JOIN users ON users.id = $3`,
    [Date.now(), roundId, req.user.id, round.current_lane]
  );
  if (!updatedRows[0]) {
    return res.status(409).json({ error: "That action was already submitted. Please try again." });
  }
  res.json({
    status: "cashed_out",
    lanes: round.lanes,
    balanceCents: safeCents(updatedRows[0].balance_cents)
  });
}));

// Plinko: binomial board. Ball takes `rows` 50/50 bounces; slot multipliers
// are fixed per (risk, rows). Outcome decided server-side per drop.
const PLINKO_TABLES = {
  low: {
    8:  [5.6, 2.1, 1.1, 1, 0.5, 1, 1.1, 2.1, 5.6],
    12: [10, 3, 1.6, 1.4, 1.1, 1, 0.5, 1, 1.1, 1.4, 1.6, 3, 10],
    16: [16, 9, 2, 1.4, 1.4, 1.2, 1.1, 1, 0.5, 1, 1.1, 1.2, 1.4, 1.4, 2, 9, 16],
  },
  medium: {
    8:  [13, 3, 1.3, 0.7, 0.4, 0.7, 1.3, 3, 13],
    12: [33, 4, 2, 1.1, 0.6, 0.4, 0.3, 0.4, 0.6, 1.1, 2, 4, 33],
    16: [110, 41, 10, 5, 3, 1.5, 1, 0.5, 0.3, 0.5, 1, 1.5, 3, 5, 10, 41, 110],
  },
  high: {
    8:  [29, 4, 1.5, 0.3, 0.2, 0.3, 1.5, 4, 29],
    12: [170, 24, 8.1, 2, 0.7, 0.2, 0.2, 0.2, 0.7, 2, 8.1, 24, 170],
    16: [1000, 130, 26, 9, 4, 2, 0.2, 0.2, 0.2, 0.2, 0.2, 2, 4, 9, 26, 130, 1000],
  },
};

app.post("/api/plinko/drop", authenticate, asyncRoute(async (req, res) => {
  const { rows, risk, mode, wagerCents } = req.body || {};
  if (![8, 12, 16].includes(rows)) {
    return res.status(400).json({ error: "Rows must be 8, 12 or 16." });
  }
  if (!Object.prototype.hasOwnProperty.call(PLINKO_TABLES, risk)) {
    return res.status(400).json({ error: "Choose a valid risk level." });
  }
  if (!["fixed", "luck"].includes(mode)) {
    return res.status(400).json({ error: "Couldn't start that round. Please try again." });
  }
  if (!Number.isSafeInteger(wagerCents) || wagerCents < MIN_WAGER_CENTS || wagerCents > MAX_WAGER_CENTS) {
    return res.status(400).json({ error: "Bet must be between €0.10 and €100.00." });
  }

  const table = PLINKO_TABLES[risk][rows];
  const now = Date.now();
  const id = crypto.randomUUID();
  let path;
  let slot;
  if (mode === "fixed") {
    // Predetermined outcome: slot drawn from the losing slots only
    // (multiplier strictly below 1x), weighted 1/multiplier and seeded by the
    // drop id; then a matching path is shuffled with the same seed. Dark
    // drops can never return the stake. The animation still looks real.
    const rand = (function seeded() {
      let state = crypto.createHash("sha256").update(id).digest().readUInt32BE(0) >>> 0;
      return () => {
        state |= 0; state = (state + 0x6D2B79F5) | 0;
        let t = Math.imul(state ^ (state >>> 15), 1 | state);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
      };
    })();
    let total = 0;
    const weights = table.map((mult) => {
      const weight = mult < 1 ? 1 / mult : 0;
      total += weight;
      return weight;
    });
    if (!(total > 0)) {
      slot = Math.floor(table.length / 2);
    } else {
      let roll = rand() * total;
      slot = table.length - 1;
      for (let index = 0; index < weights.length; index += 1) {
        roll -= weights[index];
        if (roll < 0) {
          slot = index;
          break;
        }
      }
    }
    path = Array.from({ length: rows }, (_, index) => (index < slot ? 1 : 0));
    for (let index = path.length - 1; index > 0; index -= 1) {
      const swap = Math.floor(rand() * (index + 1));
      [path[index], path[swap]] = [path[swap], path[index]];
    }
  } else {
    path = Array.from({ length: rows }, () => crypto.randomInt(2));
    slot = path.reduce((sum, step) => sum + step, 0);
    // Luck mode is generous: a sub-half-stake landing earns a second-chance
    // redraw, keeping the better of the two (dark theme keeps one fair draw).
    if (table[slot] < 0.5) {
      const retryPath = Array.from({ length: rows }, () => crypto.randomInt(2));
      const retrySlot = retryPath.reduce((sum, step) => sum + step, 0);
      if (table[retrySlot] > table[slot]) {
        path = retryPath;
        slot = retrySlot;
      }
    }
  }
  const multiplier = table[slot];
  const payoutCents = Math.floor(wagerCents * multiplier);

  // Plain sequential debit: one statement, matched rows checked directly.
  const { rows: debitedRows } = await database.query(
    `UPDATE users
     SET balance_cents = balance_cents - $2
     WHERE id = $1 AND balance_cents >= $2
     RETURNING balance_cents`,
    [req.user.id, wagerCents]
  );
  if (!debitedRows[0]) {
    logShortfall(req, wagerCents);
    return res.status(409).json({ error: `Insufficient balance for that bet.${await haveSuffix(req, wagerCents)}` });
  }
  try {
    // One round trip: record the round and credit the payout together.
    const { rows: creditedRows } = await database.query(
      `WITH new_round AS (
         INSERT INTO plinko_rounds
         (id, user_id, row_count, risk, wager_cents, multiplier, payout_cents, created_at, mode)
         VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8, $9)
         RETURNING payout_cents
       )
       UPDATE users
       SET balance_cents = balance_cents + (SELECT payout_cents FROM new_round)
       WHERE id = $2
       RETURNING balance_cents`,
      [id, req.user.id, rows, risk, wagerCents, String(multiplier), payoutCents, now, mode]
    );
    res.status(201).json({
      slot,
      multiplier,
      payoutCents: safeCents(payoutCents),
      path,
      balanceCents: safeCents(creditedRows[0].balance_cents)
    });
  } catch (error) {
    // Never take money without recording the round: refund the debit.
    await database.query(
      "UPDATE users SET balance_cents = balance_cents + $1 WHERE id = $2",
      [wagerCents, req.user.id]
    ).catch(() => {});
    throw error;
  }
}));

// Aviator (crash): multiplier climbs as mult = e^(RATE * seconds) from 1.00x.
// The crash point is sealed server-side at round start; cash-outs resolve
// against server time, never the client's word.
const AVIATOR_RATE = 0.06;
const AVIATOR_MAX_CRASH = 500;
const AVIATOR_INSTANT_CRASH_PROB = 0.03; // instant bust at x1.00
const AVIATOR_HOUSE_FACTOR = 0.99; // 1% house edge: crash = floor(0.99 / (1 - roll) * 100) / 100
function aviatorCrashPoint() {
  const roll = crypto.randomInt(2 ** 32) / 2 ** 32;
  if (roll < AVIATOR_INSTANT_CRASH_PROB) return 1;
  return Math.min(AVIATOR_MAX_CRASH, Math.floor((AVIATOR_HOUSE_FACTOR / (1 - roll)) * 100) / 100);
}
const aviatorMultAt = (elapsedMs) => Math.exp(AVIATOR_RATE * (elapsedMs / 1000));

app.post("/api/aviator/rounds", authenticate, asyncRoute(async (req, res) => {
  const { wagerCents } = req.body || {};
  if (!Number.isSafeInteger(wagerCents) || wagerCents < MIN_WAGER_CENTS || wagerCents > MAX_WAGER_CENTS) {
    return res.status(400).json({ error: "Bet must be between €0.10 and €100.00." });
  }

  const crash = aviatorCrashPoint();
  const now = Date.now();
  const id = crypto.randomUUID();

  // Plain sequential debit: one statement, matched rows checked directly.
  const { rows: debitedRows } = await database.query(
    `UPDATE users
     SET balance_cents = balance_cents - $2
     WHERE id = $1 AND balance_cents >= $2
     RETURNING balance_cents`,
    [req.user.id, wagerCents]
  );
  if (!debitedRows[0]) {
    logShortfall(req, wagerCents);
    return res.status(409).json({ error: `Insufficient balance for that bet.${await haveSuffix(req, wagerCents)}` });
  }
  try {
    // One round trip: retire any live round and record the new one together.
    await database.query(
      `WITH abandoned AS (
         UPDATE aviator_rounds
         SET status = 'abandoned', updated_at = $2
         WHERE user_id = $1 AND status = 'active'
       )
       INSERT INTO aviator_rounds
       (id, user_id, wager_cents, crash_point, status, created_at, updated_at)
       VALUES ($3, $1, $4, $5::numeric, 'active', $6, $6)`,
      [req.user.id, now, id, wagerCents, String(crash), now]
    );
  } catch (error) {
    // Never take money without recording the round: refund the debit.
    await database.query(
      "UPDATE users SET balance_cents = balance_cents + $1 WHERE id = $2",
      [wagerCents, req.user.id]
    ).catch(() => {});
    throw error;
  }
  res.status(201).json({ roundId: id, startedAt: now, balanceCents: safeCents(debitedRows[0].balance_cents) });
}));

app.post("/api/aviator/rounds/:roundId/cashout", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }

  const { rows: roundRows } = await database.query(
    "SELECT wager_cents, crash_point, status, created_at FROM aviator_rounds WHERE id = $1 AND user_id = $2",
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round || round.status !== "active") {
    return res.status(409).json({ error: "This round is already over. Start a new one." });
  }
  const liveMult = Math.floor(aviatorMultAt(Date.now() - Number(round.created_at)) * 100) / 100;
  const crash = Number(round.crash_point);
  if (liveMult >= crash) {
    // One round trip: mark the crash and read the balance together.
    const { rows: lostRows } = await database.query(
      `WITH lost_round AS (
         UPDATE aviator_rounds
         SET status = 'lost', payout_cents = 0, updated_at = $1
         WHERE id = $2 AND user_id = $3 AND status = 'active'
         RETURNING id
       )
       SELECT balance_cents FROM users WHERE id = $3`,
      [Date.now(), roundId, req.user.id]
    );
    return res.json({ crashed: true, crashPoint: crash, balanceCents: safeCents(lostRows[0].balance_cents) });
  }

  const payoutCents = Math.floor(Number(round.wager_cents) * liveMult);
  // One round trip: cash out and credit together. The credit only applies
  // when the round row actually changes, so a duplicate submit still 409s
  // without ever paying twice.
  const { rows: settledRows } = await database.query(
    `WITH changed_round AS (
       UPDATE aviator_rounds
       SET status = 'cashed_out', cashout_mult = $1::numeric, payout_cents = $2, updated_at = $3
       WHERE id = $4 AND user_id = $5 AND status = 'active'
       RETURNING id
     )
     UPDATE users
     SET balance_cents = balance_cents + $2
     WHERE id = $5 AND EXISTS (SELECT 1 FROM changed_round)
     RETURNING balance_cents`,
    [String(liveMult), payoutCents, Date.now(), roundId, req.user.id]
  );
  if (!settledRows[0]) {
    return res.status(409).json({ error: "That action was already submitted. Please try again." });
  }
  res.json({
    crashed: false,
    cashMult: liveMult,
    payoutCents: safeCents(payoutCents),
    balanceCents: safeCents(settledRows[0].balance_cents)
  });
}));

app.get("/api/aviator/recent", authenticate, asyncRoute(async (req, res) => {
  const { rows } = await database.query(
    "SELECT crash_point FROM aviator_rounds WHERE status IN ('lost', 'cashed_out') ORDER BY created_at DESC LIMIT 12"
  );
  res.json(rows.map((row) => ({ crash: Number(row.crash_point) })));
}));

app.get("/api/aviator/rounds/:roundId/status", authenticate, asyncRoute(async (req, res) => {
  const { roundId } = req.params;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(roundId)) {
    return res.status(400).json({ error: "Invalid round identifier." });
  }

  const { rows: roundRows } = await database.query(
    "SELECT crash_point, status, created_at FROM aviator_rounds WHERE id = $1 AND user_id = $2",
    [roundId, req.user.id]
  );
  const round = roundRows[0];
  if (!round) return res.status(404).json({ error: "Round not found." });
  const { rows: balRows } = await database.query(
    "SELECT balance_cents FROM users WHERE id = $1",
    [req.user.id]
  );
  const balance = safeCents(balRows[0].balance_cents);
  if (round.status === "lost") {
    return res.json({ crashed: true, crashPoint: Number(round.crash_point), balanceCents: balance });
  }
  if (round.status !== "active") {
    return res.json({ crashed: false, status: round.status, balanceCents: balance });
  }
  const liveMult = Math.floor(aviatorMultAt(Date.now() - Number(round.created_at)) * 100) / 100;
  const crash = Number(round.crash_point);
  if (liveMult < crash) return res.json({ crashed: false });
  await database.query(
    "UPDATE aviator_rounds SET status = 'lost', payout_cents = 0, updated_at = $1 WHERE id = $2 AND user_id = $3 AND status = 'active'",
    [Date.now(), roundId, req.user.id]
  );
  res.json({ crashed: true, crashPoint: crash, balanceCents: balance });
}));

app.get("/healthz", asyncRoute(async (req, res) => {
  try {
    await database.query("SELECT 1");
    res.json({ ok: true, db: true });
  } catch (error) {
    res.status(503).json({ ok: false, db: false });
  }
}));

app.use((error, req, res, next) => {  if (res.headersSent) return next(error);
  if (error.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON request body" });
  }

  logEvent("error", `Request ${req.method} ${req.path} failed: ${error && error.message ? error.message : error}`);
  if (error.code === "DATABASE_NOT_CONFIGURED") {
    return res.status(503).json({ error: "Database is not configured on this deployment." });
  }
  res.status(500).json({ error: "An internal server error occurred." });
});

const server = app.listen(PORT, () => console.log(`Casino listening on port ${PORT}`));

// Graceful shutdown: stop accepting connections, then exit so deploys
// don't drop in-flight requests mid-round.
for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  });
}
