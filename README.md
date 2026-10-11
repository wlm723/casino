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

Pick a Box uses one combined theme-and-mode switch: light theme selects Luck mode, while dark theme selects Fixed outcomes. Each safe pick pays a multiplier on the bet that climbs from the base row toward the top (×0.8, ×1.5, ×2.5, ×5, ×10, ×20, ×40, ×100 for rows 1-8; the base row always pays less than the stake), and the game displays the odds and payout ladder before play.

## Deploy to Vercel

1. Import this repository into Vercel.
2. In the Vercel project settings, add `DATABASE_URL` for Production (and Preview if needed). Use the connection string from Neon.
3. Redeploy so the environment variable is available to the serverless function.
4. Open the deployment URL. The root `server.js` serves the static files from `public/` and handles `/api/*`.

Keep the database URL private. Do not add it to source control or expose it in frontend code. Neon owns database backups; use its console for backup and restore operations.

## Admin commands

Run admin commands from a shell with `DATABASE_URL` set:

```text
node admin.js list
node admin.js show <username>
node admin.js give <username> <euros>
node admin.js set <username> <euros>
node admin.js passwd <username> <new-password>
node admin.js kick <username>
node admin.js delete <username> --yes
```

Amounts are euros (up to 2 decimals) stored as `balance_cents`.
The API returns the universal balance as `balanceCents`.
