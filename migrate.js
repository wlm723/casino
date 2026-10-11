// One-shot database migration. Run at deploy (needs DATABASE_URL):
//   node migrate.js  (or: npm run migrate)
// The server still ensures the schema at runtime as a fallback for
// serverless cold starts, but the deploy step is the controlled path:
// run it once per deploy, against a backup/staging DB first for risky changes.
const database = require("./database");

database.migrate().then(
  () => console.log("Migrations applied."),
  (error) => {
    console.error("Migration failed:", error.message);
    process.exitCode = 1;
  }
);
