```markdown
# Lumina Diamond POS — Backend API

Node/Express API for **Lumina Diamond POS**, a full-stack Point of Sale system for a diamond/jewelry store, built as an Oracle PL/SQL final project (BBU).

This is one half of the system. The Angular frontend that consumes this API lives here: **[oracle-project-frontend](https://github.com/pichchanthorn/oracle-project-frontend)**

## Architecture

```
Angular            →  Node/Express API  →  Oracle Database
oracle-project-frontend    (this repo)         (Docker)
```

This server sits between the Angular frontend and the Oracle database, since a browser app can never connect to Oracle directly.

## Tech stack

- Node.js / Express
- `oracledb`, `cors`, `dotenv`
- Oracle Database Free (Docker)

## Setup (run on the same computer as your Oracle Docker container)

```bash
npm install
copy .env.example .env
npm start
```

You should see:

```
Oracle connection pool created
API running on http://localhost:3000
```

## Test it

Open `http://localhost:3000/api/categories` in a browser — you should see the 4 seeded categories (Diamonds, Emeralds, Rubies, Sapphires) as JSON.

> To use the full app, also run the [frontend](https://github.com/pichchanthorn/oracle-project-frontend) (`ng serve`) — it will call this API for its data.
```
