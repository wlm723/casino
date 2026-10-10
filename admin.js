// Admin tool for the play-money casino. Run from the project folder:  node admin.js <command> ...
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");
const fs = require("fs");

const DB_FILE = process.env.DB || "casino.db";
if (!fs.existsSync(DB_FILE)) { console.error(`No ${DB_FILE} here. Run this from the project folder.`); process.exit(1); }
const db = new DatabaseSync(DB_FILE);
const [cmd, name, arg] = process.argv.slice(2);

const getUser = (n) => {
  const u = n && db.prepare("SELECT id, username, chips FROM users WHERE username = ?").get(n);
  if (!u) { console.error(`User "${n}" not found.`); process.exit(1); }
  return u;
};
const needInt = (v) => {
  const n = Number(v);
  if (!Number.isInteger(n)) { console.error("Amount must be a whole number."); process.exit(1); }
  return n;
};

switch (cmd) {
  case "list": {
    const rows = db.prepare("SELECT username, chips, created_at FROM users ORDER BY chips DESC").all();
    rows.forEach((r) => console.log(`${r.username.padEnd(20)} ${String(r.chips).padStart(10)}  joined ${new Date(r.created_at).toISOString().slice(0, 10)}`));
    console.log(`${rows.length} user(s)`);
    break;
  }
  case "show": {
    const u = getUser(name);
    const s = db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE user_id = ? AND expires_at > ?").get(u.id, Date.now());
    console.log(`${u.username}: ${u.chips} chips, ${s.n} active session(s)`);
    break;
  }
  case "give": {            // add (or subtract with a negative number)
    const u = getUser(name), amt = needInt(arg);
    const chips = Math.max(0, u.chips + amt);
    db.prepare("UPDATE users SET chips = ? WHERE id = ?").run(chips, u.id);
    console.log(`${u.username}: ${u.chips} -> ${chips}`);
    break;
  }
  case "set": {
    const u = getUser(name), amt = needInt(arg);
    if (amt < 0) { console.error("Chips can't be negative."); process.exit(1); }
    db.prepare("UPDATE users SET chips = ? WHERE id = ?").run(amt, u.id);
    console.log(`${u.username}: ${u.chips} -> ${amt}`);
    break;
  }
  case "passwd": {
    const u = getUser(name);
    if (!arg || arg.length < 8 || arg.length > 72) { console.error("Password must be 8-72 characters."); process.exit(1); }
    db.prepare("UPDATE users SET pass_hash = ? WHERE id = ?").run(bcrypt.hashSync(arg, 12), u.id);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(u.id); // log them out everywhere
    console.log(`Password changed for ${u.username}; their sessions were ended.`);
    break;
  }
  case "kick": {            // end all of a user's login sessions
    const u = getUser(name);
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(u.id);
    console.log(`${u.username} logged out everywhere.`);
    break;
  }
  case "delete": {
    const u = getUser(name);
    if (arg !== "--yes") { console.error(`This permanently deletes ${u.username}. Re-run with --yes to confirm.`); process.exit(1); }
    db.prepare("DELETE FROM sessions WHERE user_id = ?").run(u.id);
    db.prepare("DELETE FROM users WHERE id = ?").run(u.id);
    console.log(`Deleted ${u.username}.`);
    break;
  }
  case "backup": {
    const out = `casino-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.db`;
    db.exec(`VACUUM INTO '${out}'`);   // safe copy even while the server is running
    console.log(`Saved ${out}`);
    break;
  }
  default:
    console.log(`Usage: node admin.js <command>

  list                       all users and balances
  show <user>                one user's balance and sessions
  give <user> <amount>       add chips (negative removes)
  set <user> <amount>        set exact balance
  passwd <user> <newpass>    reset a password (logs them out)
  kick <user>                end all their sessions
  delete <user> --yes        permanently remove an account
  backup                     save a timestamped copy of the database`);
}
