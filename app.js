const express = require('express');
const cors = require('cors');
const categoriesRouter = require('./routes/categories');
const unitsRouter = require('./routes/units');
const productsRouter = require('./routes/products');
const authRouter = require('./routes/auth');
const { requireAccessToken } = require('./middleware/auth');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'lumina-diamond-api' });
});

// Public auth routes (register, login) are mounted before the blanket
// access-token guard below, so they never pass through it. Everything else
// under /api is protected by default — a future router that forgets to
// add its own auth check is still safe, rather than silently open.
app.use('/api/auth', authRouter);

app.use('/api', requireAccessToken);

app.use('/api/categories', categoriesRouter);
app.use('/api/units', unitsRouter);
app.use('/api/products', productsRouter);

module.exports = app;
