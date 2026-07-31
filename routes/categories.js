const express = require('express');
const oracledb = require('oracledb');
const router = express.Router();
const { getConnection } = require('../db');

// GET /api/categories — list every category
router.get('/', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT category_id, name, description, is_active FROM categories ORDER BY category_id`
    );

    const categories = result.rows.map((row) => ({
      id: row.CATEGORY_ID,
      name: row.NAME,
      description: row.DESCRIPTION,
      active: row.IS_ACTIVE === 1,
    }));

    res.json(categories);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch categories' });
  } finally {
    if (conn) await conn.close();
  }
});

// POST /api/categories — create a new category
router.post('/', async (req, res) => {
  const { name, description, active } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO categories (name, description, is_active)
       VALUES (:name, :description, :active)
       RETURNING category_id INTO :id`,
      {
        name,
        description: description || null,
        active: active === false ? 0 : 1,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
      },
      { autoCommit: true }
    );

    res.status(201).json({
      id: result.outBinds.id[0],
      name,
      description,
      active: active !== false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create category' });
  } finally {
    if (conn) await conn.close();
  }
});

// PATCH /api/categories/:id/toggle — flip active/inactive
router.patch('/:id/toggle', async (req, res) => {
  const { id } = req.params;

  let conn;
  try {
    conn = await getConnection();
    await conn.execute(
      `UPDATE categories SET is_active = 1 - is_active WHERE category_id = :id`,
      { id },
      { autoCommit: true }
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update category' });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;
