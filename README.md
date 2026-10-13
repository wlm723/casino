# TAX Casino

An Express casino lobby served locally with `npm start` and deployed to Vercel.
Account and session data are stored in Neon Postgres.

## Run locally

1. Create a Neon project and copy its PostgreSQL connection string.
2. Set `DATABASE_URL` in the shell where the server will run.
3. Run `npm install`, then `npm start`.
4. Open <http://localhost:3000>.

The server creates the required tables and indexes on the first database request.
Existing accounts in a local SQLite database are not copied automatically; the Neon database starts with no accounts.

Pick a Box, Chicken Road and Plinko use a global light/dark theme switch (set from the ☰ slide-in menu or Account → Account & Theme, applied across all pages) that also changes game behavior. Light theme plays in "luck" mode with boosted odds: 3 in 4 boxes safe per Pick-a-Box row, halved Chicken Road crash chance per lane, and a second-chance redraw on sub-half-stake Plinko landings; dark theme plays in "fixed" mode with house-favoring predetermined outcomes. Ladders are deliberately generous — luck mode has a positive expected value. This is virtual euros only, never real money: do not reuse these payout tables for anything with stakes. Payout ladders are server-authoritative and start below the stake: Pick a Box rows 1-8 pay ×0.8, ×1.5, ×2.5, ×5, ×10, ×20, ×40, ×100. Chicken Road has Easy/Medium/Hard/Hardcore difficulties (30/50/65/80% crash per lane) with ladders up to ×3.6, ×9.0, ×32 and ×160 on lane 10. Plinko drops one ball down 8, 12 or 16 rows of 50/50 pegs into multiplier slots (Low/Medium/High risk, edges up to ×1000 on 16-row High). Aviator climbs at 6%/sec from ×1.00 with a server-sealed crash point (3% instant bust, capped ×500); cash-outs resolve against server time. Bets are stepper-only in €0.10 intervals starting at €0.10 (no free entry; MIN/MAX and fixed presets included); the server enforces €0.10–€100 per bet. Includes a recent crash strip, own history, and optional auto cash-out at a chosen multiplier.

## Deploy to Vercel

1. Import this repository into Vercel.
2. In the Vercel project settings, add `DATABASE_URL` for Production (and Preview if needed). Use the connection string from Neon.
3. Run the migration once per deploy from a shell with `DATABASE_URL` set: `npm run migrate`. (The server also ensures the schema at runtime as a fallback.)
4. Redeploy so the environment variable is available to the serverless function.
5. Open the deployment URL. The root `server.js` serves the static files from `public/` and handles `/api/*`.

Keep the database URL private. Do not add it to source control or expose it in frontend code. Neon owns database backups; use its console for backup and restore operations.

## Admin commands

Run admin commands from a shell with `DATABASE_URL` set:

```text
node admin.js list
node admin.js show <username>
node admin.js give <username> <euros>
node admin.js set <username> <euros>
node admin.js bonus <username> [euros]
node admin.js bonus --all [euros]
node admin.js economy
node admin.js logs [warn|error|all] [n]
node admin.js passwd <username> <new-password>
node admin.js kick <username>
node admin.js delete <username> --yes
```

Amounts are euros (up to 2 decimals) stored as `balance_cents`.
The API returns the universal balance as `balanceCents`.
