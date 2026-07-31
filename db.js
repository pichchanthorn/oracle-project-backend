const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

let pool;

async function initPool() {
  pool = await oracledb.createPool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectString: process.env.DB_CONNECT_STRING,
    poolMin: 1,
    poolMax: 5,
    poolIncrement: 1,
  });
  console.log('Oracle connection pool created');
}

async function getConnection() {
  if (!pool) {
    throw new Error('Connection pool not initialized — call initPool() first');
  }
  return pool.getConnection();
}

module.exports = { initPool, getConnection };
