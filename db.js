const { Pool } = require("pg");

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn("⚠️ DATABASE_URL não definido. Configure no .env (local) e no Render (Environment).");
}

const pool = new Pool({
  connectionString,
  ssl: connectionString && connectionString.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : false,
});

module.exports = pool;
