const express = require('express');
const cors = require('cors');
const categoriesRouter = require('./routes/categories');
const unitsRouter = require('./routes/units');
const productsRouter = require('./routes/products');
const inventoryRouter = require('./routes/inventory');
const usersRouter = require('./routes/users');
const authRouter = require('./routes/auth');
const twoFactorRouter = require('./routes/twoFactor');
const { requireAccessToken } = require('./middleware/auth');
const corsService = require('./services/corsService');

const app = express();
app.use(cors({ origin: corsService.getOrigin() }));
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'lumina-diamond-api' });
});

// Public auth routes (register, login) are mounted before the blanket
// access-token guard below, so they never pass through it. Everything else
// under /api is protected by default — a future router that forgets to
// add its own auth check is still safe, rather than silently open.
app.use('/api/auth', authRouter);

// /api/auth/2fa/* is nested under the public /api/auth prefix above, so it
// would NOT inherit the blanket guard mounted below — it needs its own
// explicit requireAccessToken here. Mounted before the blanket guard so
// this is unambiguous regardless of ordering changes to /api/auth.
app.use('/api/auth/2fa', requireAccessToken, twoFactorRouter);

app.use('/api', requireAccessToken);

app.use('/api/categories', categoriesRouter);
app.use('/api/units', unitsRouter);
app.use('/api/products', productsRouter);
app.use('/api/inventory', inventoryRouter);
app.use('/api/users', usersRouter);

module.exports = app;
