const express = require('express');
const cors = require('cors');
const categoriesRouter = require('./routes/categories');
const unitsRouter = require('./routes/units');
const productsRouter = require('./routes/products');
const authRouter = require('./routes/auth');

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'lumina-diamond-api' });
});

app.use('/api/categories', categoriesRouter);
app.use('/api/units', unitsRouter);
app.use('/api/products', productsRouter);
app.use('/api/auth', authRouter);

module.exports = app;
