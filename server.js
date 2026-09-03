require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initPool } = require('./db');
const categoriesRouter = require('./routes/categories');
const unitsRouter = require('./routes/units');
const productsRouter = require('./routes/products');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'lumina-diamond-api' });
});

app.use('/api/categories', categoriesRouter);
app.use('/api/units', unitsRouter);
app.use('/api/products', productsRouter);

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
