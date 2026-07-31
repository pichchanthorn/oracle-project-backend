# Lumina Diamond API

Small Node/Express server that sits between the Angular frontend and the
Oracle database, since a browser app can never connect to Oracle directly.

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

Open http://localhost:3000/api/categories in a browser — you should see the
4 seeded categories (Diamonds, Emeralds, Rubies, Sapphires) as JSON.
