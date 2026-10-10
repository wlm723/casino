const { neon } = require("@neondatabase/serverless");

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  chips INTEGER NOT NULL CHECK (chips >= 0),
  created_at BIGINT NOT NULL
);`,
  `CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_unique
  ON users (LOWER(username));`,
  `CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at BIGINT NOT NULL
);`,
  "CREATE INDEX IF NOT EXISTS sessions_user_id_idx ON sessions (user_id);"
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

module.exports = { query };
