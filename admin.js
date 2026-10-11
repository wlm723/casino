// Admin tool for the casino. Run from the project folder: node admin.js <command> ...
// Universal balance: all amounts are euros (up to 2 decimals) stored as balance_cents (BIGINT).
const bcrypt = require("bcryptjs");
const database = require("./database");

const MAX_BALANCE_CENTS = 214748364700; // legacy 2_147_483_647 chips * 100 cents
const [command, username, argument] = process.argv.slice(2);

function parseEurosToCents(value) {
  const text = String(value === undefined ? "" : value).trim();
  const match = /^(-?\d+)(?:\.(\d{1,2}))?$/.exec(text);
  if (!match) {
    throw new Error(`Amount must be euros like 10 or 10.50 (got "${value}").`);
  }
  // Sign-safe: handle "-0.50" correctly (Number("-0") is -0).
  const sign = text.startsWith("-") ? -1 : 1;
  const absCents = Math.abs(Number(match[1])) * 100 + Number((match[2] || "").padEnd(2, "0") || 0);
  const total = sign * absCents;
  if (!Number.isSafeInteger(total) || Math.abs(total) > MAX_BALANCE_CENTS) {
    throw new Error(`Amount must be between -${formatCents(MAX_BALANCE_CENTS)} and ${formatCents(MAX_BALANCE_CENTS)}.`);
  }
  return total;
}

function formatCents(cents) {
  return `€${(Number(cents) / 100).toFixed(2)}`;
}

function toCents(value) {
  const cents = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (!Number.isSafeInteger(cents) || cents < 0) {
    throw new Error("The account has an invalid euro balance.");
  }
  return cents;
}

async function getUser(name) {
  const { rows } = await database.query(
    "SELECT id, username, balance_cents, created_at FROM users WHERE LOWER(username) = LOWER($1)",
    [name || ""]
  );
  if (!rows[0]) throw new Error(`User "${name}" not found.`);
  rows[0].balance_cents = toCents(rows[0].balance_cents);
  return rows[0];
}

function showUsage() {
  console.log(`Usage: node admin.js <command>

  list                       all users and balances
  show <user>                one user's balance and sessions
  give <user> <euros>        add euros (negative removes, e.g. -5.50)
  set <user> <euros>         set exact balance in euros (e.g. 100.00)
  passwd <user> <newpass>    reset a password (logs them out)
  kick <user>                end all their sessions
  delete <user> --yes        permanently remove an account

Amounts are euros with up to 2 decimals and are stored as balance_cents.
Use the Neon console to manage database backups.`);
}

async function run() {
  switch (command) {
    case "list": {
      const { rows } = await database.query(
        "SELECT username, balance_cents, created_at FROM users ORDER BY balance_cents DESC"
      );
      rows.forEach((user) => {
        const joined = new Date(Number(user.created_at)).toISOString().slice(0, 10);
        const balance = formatCents(toCents(user.balance_cents));
        console.log(`${user.username.padEnd(20)} ${balance.padStart(12)}  joined ${joined}`);
      });
      console.log(`${rows.length} user(s)`);
      return;
    }
    case "show": {
      const user = await getUser(username);
      const { rows } = await database.query(
        "SELECT COUNT(*)::int AS count FROM sessions WHERE user_id = $1 AND expires_at > $2",
        [user.id, Date.now()]
      );
      console.log(`${user.username}: ${formatCents(user.balance_cents)}, ${rows[0].count} active session(s)`);
      return;
    }
    case "give": {
      const user = await getUser(username);
      const amountCents = parseEurosToCents(argument);
      const balance = Math.max(0, user.balance_cents + amountCents);
      if (balance > MAX_BALANCE_CENTS) throw new Error(`Balance cannot exceed ${formatCents(MAX_BALANCE_CENTS)}.`);
      await database.query("UPDATE users SET balance_cents = $1 WHERE id = $2", [balance, user.id]);
      console.log(`${user.username}: ${formatCents(user.balance_cents)} -> ${formatCents(balance)}`);
      return;
    }
    case "set": {
      const user = await getUser(username);
      const balance = parseEurosToCents(argument);
      if (balance < 0) throw new Error("Balance can't be negative.");
      await database.query("UPDATE users SET balance_cents = $1 WHERE id = $2", [balance, user.id]);
      console.log(`${user.username}: ${formatCents(user.balance_cents)} -> ${formatCents(balance)}`);
      return;
    }
    case "passwd": {
      const user = await getUser(username);
      if (!argument || argument.length < 8 || argument.length > 72) {
        throw new Error("Password must be 8-72 characters.");
      }
      await database.query(
        `WITH password_change AS (
           UPDATE users SET pass_hash = $1 WHERE id = $2
         )
         DELETE FROM sessions WHERE user_id = $2`,
        [await bcrypt.hash(argument, 12), user.id]
      );
      console.log(`Password changed for ${user.username}; their sessions were ended.`);
      return;
    }
    case "kick": {
      const user = await getUser(username);
      await database.query("DELETE FROM sessions WHERE user_id = $1", [user.id]);
      console.log(`${user.username} logged out everywhere.`);
      return;
    }
    case "delete": {
      const user = await getUser(username);
      if (argument !== "--yes") {
        throw new Error(`This permanently deletes ${user.username}. Re-run with --yes to confirm.`);
      }
      await database.query("DELETE FROM users WHERE id = $1", [user.id]);
      console.log(`Deleted ${user.username}.`);
      return;
    }
    case "help":
    case undefined:
      showUsage();
      return;
    default:
      showUsage();
      throw new Error(`Unknown command "${command}".`);
  }
}

run().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
