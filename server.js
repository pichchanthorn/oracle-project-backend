require('dotenv').config();
const app = require('./app');
const { initPool } = require('./db');
const jwtService = require('./services/jwtService');
const cryptoService = require('./services/cryptoService');

try {
  jwtService.validateConfig();
} catch (err) {
  console.error('Invalid JWT configuration:', err.message);
  process.exit(1);
}

try {
  cryptoService.validateConfig();
} catch (err) {
  console.error('Invalid TOTP encryption configuration:', err.message);
  process.exit(1);
}

const PORT = process.env.PORT || 3000;

initPool()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`API running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to start server — could not connect to Oracle DB:');
    console.error(err);
    process.exit(1);
  });
