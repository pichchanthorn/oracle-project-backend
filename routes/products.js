const express = require('express');
const oracledb = require('oracledb');
const router = express.Router();
const { getConnection } = require('../db');

const ORA_UNIQUE_VIOLATION = 1;
const ORA_FK_VIOLATION_CHILD = 2291; // parent key not found (invalid category/unit)

// GET /api/products — list every product
router.get('/', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT p.product_id, p.sku, p.name, p.category_id, p.unit_id,
              p.unit_price, p.description, p.is_active,
              c.name AS category_name, u.name AS unit_name
       FROM products p
       JOIN categories c ON c.category_id = p.category_id
       JOIN units u ON u.unit_id = p.unit_id
       ORDER BY p.product_id`
    );

    const products = result.rows.map((row) => ({
      id: row.PRODUCT_ID,
      sku: row.SKU,
      name: row.NAME,
      categoryId: row.CATEGORY_ID,
      unitId: row.UNIT_ID,
      unitPrice: row.UNIT_PRICE,
      description: row.DESCRIPTION,
      active: row.IS_ACTIVE === 1,
      categoryName: row.CATEGORY_NAME,
      unitName: row.UNIT_NAME,
    }));

    res.json(products);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch products' });
  } finally {
    if (conn) await conn.close();
  }
});

// POST /api/products — create a new product
router.post('/', async (req, res) => {
  const { sku, name, categoryId, unitId, unitPrice, description, active } = req.body;

  if (!sku || !sku.trim()) {
    return res.status(400).json({ error: 'sku is required' });
  }
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }
  if (categoryId === undefined || categoryId === null || categoryId === '') {
    return res.status(400).json({ error: 'categoryId is required' });
  }
  if (unitId === undefined || unitId === null || unitId === '') {
    return res.status(400).json({ error: 'unitId is required' });
  }
  if (unitPrice === undefined || unitPrice === null || unitPrice === '') {
    return res.status(400).json({ error: 'unitPrice is required' });
  }
  if (isNaN(Number(unitPrice)) || Number(unitPrice) < 0) {
    return res.status(400).json({ error: 'unitPrice must be a number >= 0' });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO products (sku, name, category_id, unit_id, unit_price, description, is_active)
       VALUES (:sku, :name, :categoryId, :unitId, :unitPrice, :description, :active)
       RETURNING product_id INTO :id`,
      {
        sku,
        name,
        categoryId,
        unitId,
        unitPrice,
        description: description || null,
        active: active === false ? 0 : 1,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
      },
      { autoCommit: true }
    );

    res.status(201).json({
      id: result.outBinds.id[0],
      sku,
      name,
      categoryId,
      unitId,
      unitPrice: Number(unitPrice),
      description: description || null,
      active: active !== false,
    });
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      return res.status(400).json({ error: 'A product with this sku already exists' });
    }
    if (err.errorNum === ORA_FK_VIOLATION_CHILD) {
      return res.status(400).json({ error: 'Invalid categoryId or unitId' });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to create product' });
  } finally {
    if (conn) await conn.close();
  }
});

// PATCH /api/products/:id — partial update
router.patch('/:id', async (req, res) => {
  const { id } = req.params;
  const { sku, name, categoryId, unitId, unitPrice, description, active } = req.body;

  if (sku !== undefined && !sku.trim()) {
    return res.status(400).json({ error: 'sku cannot be empty' });
  }
  if (name !== undefined && !name.trim()) {
    return res.status(400).json({ error: 'name cannot be empty' });
  }
  if (categoryId !== undefined && (categoryId === null || categoryId === '')) {
    return res.status(400).json({ error: 'categoryId cannot be empty' });
  }
  if (unitId !== undefined && (unitId === null || unitId === '')) {
    return res.status(400).json({ error: 'unitId cannot be empty' });
  }
  if (unitPrice !== undefined) {
    if (unitPrice === null || unitPrice === '' || isNaN(Number(unitPrice)) || Number(unitPrice) < 0) {
      return res.status(400).json({ error: 'unitPrice must be a number >= 0' });
    }
  }
  if (
    sku === undefined &&
    name === undefined &&
    categoryId === undefined &&
    unitId === undefined &&
    unitPrice === undefined &&
    description === undefined &&
    active === undefined
  ) {
    return res.status(400).json({ error: 'At least one field is required' });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE products
       SET sku = COALESCE(:sku, sku),
           name = COALESCE(:name, name),
           category_id = COALESCE(:categoryId, category_id),
           unit_id = COALESCE(:unitId, unit_id),
           unit_price = COALESCE(:unitPrice, unit_price),
           description = COALESCE(:description, description),
           is_active = COALESCE(:active, is_active)
       WHERE product_id = :id`,
      {
        sku: sku !== undefined ? sku : null,
        name: name !== undefined ? name : null,
        categoryId: { val: categoryId !== undefined ? categoryId : null, type: oracledb.NUMBER },
        unitId: { val: unitId !== undefined ? unitId : null, type: oracledb.NUMBER },
        unitPrice: { val: unitPrice !== undefined ? unitPrice : null, type: oracledb.NUMBER },
        description: description !== undefined ? description : null,
        active: {
          val: active !== undefined ? (active === false ? 0 : 1) : null,
          type: oracledb.NUMBER,
        },
        id,
      },
      { autoCommit: true }
    );

    if (result.rowsAffected === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ success: true });
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      return res.status(400).json({ error: 'A product with this sku already exists' });
    }
    if (err.errorNum === ORA_FK_VIOLATION_CHILD) {
      return res.status(400).json({ error: 'Invalid categoryId or unitId' });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to update product' });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;
