const { neon } = require("@neondatabase/serverless");

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  chips INTEGER NOT NULL DEFAULT 1000 CHECK (chips >= 0),
  balance_cents BIGINT,
  created_at BIGINT NOT NULL
);`,
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS balance_cents BIGINT;",
  `DO $migration$
  BEGIN
    IF EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_schema = current_schema()
        AND table_name = 'users'
        AND column_name = 'chips'
    ) THEN
      UPDATE users SET balance_cents = chips::bigint * 10 WHERE balance_cents IS NULL;
      ALTER TABLE users DROP COLUMN chips;
    ELSE
      UPDATE users SET balance_cents = 10000 WHERE balance_cents IS NULL;
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM pg_constraint
      WHERE conname = 'users_balance_cents_nonnegative'
    ) THEN
      ALTER TABLE users
      ADD CONSTRAINT users_balance_cents_nonnegative CHECK (balance_cents >= 0);
    END IF;
  END;
  $migration$;`,
  "ALTER TABLE users ALTER COLUMN balance_cents SET DEFAULT 10000;",
  "ALTER TABLE users ALTER COLUMN balance_cents SET NOT NULL;",
  `CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique
  ON users (LOWER(username));`,
  `CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL
);`,
  "CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);",
  "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS created_at BIGINT NOT NULL DEFAULT 0;",
  "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';",
  "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT '';",
  "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS persistent INTEGER NOT NULL DEFAULT 0;",
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT;",
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER NOT NULL DEFAULT 0;",
  "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_recovery TEXT;",
  `CREATE TABLE IF NOT EXISTS login_tickets (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL
 );`,
  `CREATE TABLE IF NOT EXISTS auth_attempts (
  ip TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  window_start BIGINT NOT NULL DEFAULT 0
 );`,
  `CREATE TABLE IF NOT EXISTS pickbox_rounds (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('fixed', 'luck')),
  row_count INTEGER NOT NULL CHECK (row_count BETWEEN 2 AND 8),
  current_row INTEGER NOT NULL,
  wager_cents BIGINT NOT NULL DEFAULT 0 CHECK (wager_cents >= 0),
  status TEXT NOT NULL CHECK (status IN ('active', 'lost', 'won', 'cashed_out', 'abandoned')),
  safe_columns JSONB NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);`,
  "ALTER TABLE pickbox_rounds ADD COLUMN IF NOT EXISTS wager_cents BIGINT NOT NULL DEFAULT 0;",
  "UPDATE pickbox_rounds SET status = 'abandoned', updated_at = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint WHERE status = 'active' AND wager_cents = 0;",
  "CREATE INDEX IF NOT EXISTS pickbox_rounds_user_id_idx ON pickbox_rounds (user_id, created_at DESC);",
  `CREATE TABLE IF NOT EXISTS chicken_rounds (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  mode TEXT NOT NULL CHECK (mode IN ('fixed', 'luck')),
  difficulty TEXT NOT NULL DEFAULT 'medium' CHECK (difficulty IN ('easy', 'medium', 'hard', 'hardcore')),
  lane_count INTEGER NOT NULL CHECK (lane_count BETWEEN 5 AND 10),
  current_lane INTEGER NOT NULL DEFAULT 0,
  wager_cents BIGINT NOT NULL DEFAULT 0 CHECK (wager_cents >= 0),
  status TEXT NOT NULL CHECK (status IN ('active', 'lost', 'won', 'cashed_out', 'abandoned')),
  lanes JSONB NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);`,
  "ALTER TABLE chicken_rounds ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'luck';",
  "ALTER TABLE chicken_rounds ADD COLUMN IF NOT EXISTS difficulty TEXT NOT NULL DEFAULT 'medium';",
  "CREATE INDEX IF NOT EXISTS chicken_rounds_user_id_idx ON chicken_rounds (user_id, created_at DESC);",
  `CREATE TABLE IF NOT EXISTS plinko_rounds (
  id UUID PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  row_count INTEGER NOT NULL CHECK (row_count IN (8, 12, 16)),
  risk TEXT NOT NULL CHECK (risk IN ('low', 'medium', 'high')),
  mode TEXT NOT NULL DEFAULT 'luck' CHECK (mode IN ('fixed', 'luck')),
  wager_cents BIGINT NOT NULL CHECK (wager_cents >= 0),
  multiplier NUMERIC NOT NULL,
  payout_cents BIGINT NOT NULL CHECK (payout_cents >= 0),
  created_at BIGINT NOT NULL
);`,
  "CREATE INDEX IF NOT EXISTS plinko_rounds_user_id_idx ON plinko_rounds (user_id, created_at DESC);",
  "ALTER TABLE plinko_rounds ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'luck';",
  `CREATE TABLE IF NOT EXISTS server_logs (
  id BIGSERIAL PRIMARY KEY,
  level TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at BIGINT NOT NULL
);`,
  "CREATE INDEX IF NOT EXISTS server_logs_created_idx ON server_logs (created_at DESC);"
];

let sql;
let databaseUrl;
let schemaSetup;

function getSql() {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    const error = new Error("Database is not configured. Set the DATABASE_URL environment variable.");
    error.code = "DATABASE_NOT_CONFIGURED";
    throw error;
  }

  if (!sql || connectionString !== databaseUrl) {
    databaseUrl = connectionString;
    sql = neon(connectionString);
    schemaSetup = undefined;
  }
  return sql;
}

async function ensureSchema() {
  const client = getSql();
  if (!schemaSetup) {
    schemaSetup = SCHEMA_STATEMENTS.reduce(
      (setup, statement) => setup.then(() => client.query(statement)),
      Promise.resolve()
    ).catch((error) => {
      schemaSetup = undefined;
      throw error;
    });
  }
  await schemaSetup;
  return client;
}

async function query(text, values) {
  const client = await ensureSchema();
  const rows = await client.query(text, values || []);
  return { rows };
}

module.exports = { query, migrate: ensureSchema };
