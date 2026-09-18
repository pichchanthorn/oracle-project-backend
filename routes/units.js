const express = require('express');
const oracledb = require('oracledb');
const router = express.Router();
const { getConnection } = require('../db');
const { requireRole } = require('../middleware/roles');
const { parsePositiveIntegerId } = require('../utils/validateId');

const ORA_UNIQUE_VIOLATION = 1;

// GET /api/units — list every unit
router.get('/', async (req, res) => {
  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT unit_id, name, symbol FROM units ORDER BY unit_id`
    );

    const units = result.rows.map((row) => ({
      id: row.UNIT_ID,
      name: row.NAME,
      symbol: row.SYMBOL,
    }));

    res.json(units);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch units' });
  } finally {
    if (conn) await conn.close();
  }
});

// POST /api/units — create a new unit (ADMIN only)
router.post('/', requireRole('ADMIN'), async (req, res) => {
  const { name, symbol } = req.body;

  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }
  if (!symbol || !symbol.trim()) {
    return res.status(400).json({ error: 'symbol is required' });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `INSERT INTO units (name, symbol)
       VALUES (:name, :symbol)
       RETURNING unit_id INTO :id`,
      {
        name,
        symbol,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
      },
      { autoCommit: true }
    );

    res.status(201).json({
      id: result.outBinds.id[0],
      name,
      symbol,
    });
  } catch (err) {
    if (err.errorNum === ORA_UNIQUE_VIOLATION) {
      return res.status(409).json({ error: 'A unit with this name already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to create unit' });
  } finally {
    if (conn) await conn.close();
  }
});

// PATCH /api/units/:id — update name and/or symbol (ADMIN only)
router.patch('/:id', requireRole('ADMIN'), async (req, res) => {
  const id = parsePositiveIntegerId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }
  const { name, symbol } = req.body;

  if (name !== undefined && !name.trim()) {
    return res.status(400).json({ error: 'name cannot be empty' });
  }
  if (symbol !== undefined && !symbol.trim()) {
    return res.status(400).json({ error: 'symbol cannot be empty' });
  }
  if (name === undefined && symbol === undefined) {
    return res.status(400).json({ error: 'name or symbol is required' });
  }

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `UPDATE units
       SET name = COALESCE(:name, name),
           symbol = COALESCE(:symbol, symbol)
       WHERE unit_id = :id`,
      {
        name: name !== undefined ? name : null,
        symbol: symbol !== undefined ? symbol : null,
        id,
      },
      { autoCommit: true }
    );

    if (result.rowsAffected === 0) {
      return res.status(404).json({ error: 'Unit not found' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update unit' });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;
