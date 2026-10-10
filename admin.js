// Admin tool for the casino. Run from the project folder: node admin.js <command> ...
const bcrypt = require("bcryptjs");
const database = require("./database");

const MAX_CHIPS = 2_147_483_647;
const [command, username, argument] = process.argv.slice(2);

async function getUser(name) {
  const { rows } = await database.query(
    "SELECT id, username, chips, created_at FROM users WHERE LOWER(username) = LOWER($1)",
    [name || ""]
  );
  if (!rows[0]) throw new Error(`User "${name}" not found.`);
  return rows[0];
}

function needAmount(value) {
  const amount = Number(value);
  if (!Number.isSafeInteger(amount) || Math.abs(amount) > MAX_CHIPS) {
    throw new Error(`Amount must be a whole number between -${MAX_CHIPS} and ${MAX_CHIPS}.`);
  }
  return amount;
}

function showUsage() {
  console.log(`Usage: node admin.js <command>

  list                       all users and balances
  show <user>                one user's balance and sessions
  give <user> <amount>       add chips (negative removes)
  set <user> <amount>        set exact balance
  passwd <user> <newpass>    reset a password (logs them out)
  kick <user>                end all their sessions
  delete <user> --yes        permanently remove an account

Use the Neon console to manage database backups.`);
}

async function run() {
  switch (command) {
    case "list": {
      const { rows } = await database.query(
        "SELECT username, chips, created_at FROM users ORDER BY chips DESC"
      );
      rows.forEach((user) => {
        const joined = new Date(Number(user.created_at)).toISOString().slice(0, 10);
        console.log(`${user.username.padEnd(20)} ${String(user.chips).padStart(10)}  joined ${joined}`);
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
      console.log(`${user.username}: ${user.chips} chips, ${rows[0].count} active session(s)`);
      return;
    }
    case "give": {
      const user = await getUser(username);
      const amount = needAmount(argument);
      const balance = Math.max(0, user.chips + amount);
      if (balance > MAX_CHIPS) throw new Error(`Balance cannot exceed ${MAX_CHIPS} chips.`);
      await database.query("UPDATE users SET chips = $1 WHERE id = $2", [balance, user.id]);
      console.log(`${user.username}: ${user.chips} -> ${balance}`);
      return;
    }
    case "set": {
      const user = await getUser(username);
      const balance = needAmount(argument);
      if (balance < 0) throw new Error("Chips can't be negative.");
      await database.query("UPDATE users SET chips = $1 WHERE id = $2", [balance, user.id]);
      console.log(`${user.username}: ${user.chips} -> ${balance}`);
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
        [bcrypt.hashSync(argument, 12), user.id]
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
