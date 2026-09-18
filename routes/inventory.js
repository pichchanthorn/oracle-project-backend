const express = require('express');
const oracledb = require('oracledb');
const router = express.Router();
const { getConnection } = require('../db');
const { requireRole } = require('../middleware/roles');
const { parsePositiveIntegerId } = require('../utils/validateId');

const ALLOWED_CREATE_REASONS = ['RESTOCK', 'ADJUSTMENT', 'RETURN'];
const ALL_REASONS = ['RESTOCK', 'SALE', 'ADJUSTMENT', 'RETURN'];
const POSITIVE_ONLY_REASONS = ['RESTOCK', 'RETURN'];

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

// Strict integer check: JSON numbers only (typeof === 'number'), finite,
// a whole number, and never zero. Rejects booleans, arrays, null, numeric
// strings, whitespace strings, Infinity, NaN, and decimals — all of which
// are otherwise "truthy-ish" under Number(value) coercion.
function isValidNonZeroInteger(value) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value !== 0
  );
}

function toFiniteNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function serializeMovementRow(row) {
  return {
    id: row.ID,
    productId: row.PRODUCT_ID,
    quantityChange: row.QUANTITY_CHANGE,
    reason: row.REASON,
    changedBy: row.CHANGED_BY,
    changedAt: row.CHANGED_AT,
  };
}

// POST /api/inventory/movements — record a stock movement (ADMIN, MANAGER)
router.post('/movements', requireRole('ADMIN', 'MANAGER'), async (req, res) => {
  const { productId, quantityChange, reason } = req.body;

  const parsedProductId =
    typeof productId === 'number' && Number.isInteger(productId) && productId > 0
      ? productId
      : null;
  if (parsedProductId === null) {
    return res.status(400).json({ error: 'productId must be a positive integer' });
  }

  if (typeof reason !== 'string' || !ALL_REASONS.includes(reason)) {
    return res.status(400).json({ error: 'reason must be one of RESTOCK, SALE, ADJUSTMENT, RETURN' });
  }
  if (reason === 'SALE') {
    return res.status(400).json({
      error: 'SALE movements are not supported by this API in Phase 9',
    });
  }
  if (!ALLOWED_CREATE_REASONS.includes(reason)) {
    return res.status(400).json({ error: 'reason must be one of RESTOCK, ADJUSTMENT, RETURN' });
  }

  if (!isValidNonZeroInteger(quantityChange)) {
    return res.status(400).json({ error: 'quantityChange must be a non-zero integer' });
  }
  if (POSITIVE_ONLY_REASONS.includes(reason) && quantityChange < 0) {
    return res.status(400).json({ error: `quantityChange must be positive for ${reason}` });
  }

  // req.user.id comes exclusively from the verified JWT (see
  // middleware/auth.js's claimsToReqUser) — never from req.body/query/params,
  // so a caller can never spoof CHANGED_BY.
  const changedByUserId = toFiniteNumber(req.user && req.user.id);
  if (changedByUserId === null) {
    console.error('inventory movement: req.user.id is not a finite number', req.user);
    return res.status(500).json({ error: 'Failed to record inventory movement' });
  }

  let conn;
  try {
    conn = await getConnection();

    // Explicit transaction (autoCommit: false on every statement below,
    // committed/rolled back explicitly): the PRODUCTS row lock is the
    // serialization point for concurrent movements against the same
    // product, so two concurrent requests can never both read the same
    // pre-movement stock total and both decide a movement is safe.
    const productRes = await conn.execute(
      `SELECT product_id, is_active FROM products WHERE product_id = :productId FOR UPDATE`,
      { productId: parsedProductId },
      { autoCommit: false }
    );

    if (productRes.rows.length === 0) {
      await conn.rollback();
      return res.status(404).json({ error: 'Product not found' });
    }

    const isActive = productRes.rows[0].IS_ACTIVE;
    if (isActive !== 1) {
      await conn.rollback();
      return res.status(409).json({ error: 'Product is inactive' });
    }

    const stockRes = await conn.execute(
      `SELECT NVL(SUM(quantity_change), 0) AS current_stock
       FROM inventory WHERE product_id = :productId`,
      { productId: parsedProductId },
      { autoCommit: false }
    );
    const currentStock = stockRes.rows[0].CURRENT_STOCK;
    const resultingStock = currentStock + quantityChange;

    if (resultingStock < 0) {
      await conn.rollback();
      return res.status(409).json({ error: 'Movement would result in negative stock' });
    }

    const insertRes = await conn.execute(
      `INSERT INTO inventory (product_id, quantity_change, reason, changed_by)
       VALUES (:productId, :quantityChange, :reason, :changedBy)
       RETURNING inventory_id, changed_at INTO :id, :changedAt`,
      {
        productId: parsedProductId,
        quantityChange,
        reason,
        changedBy: changedByUserId,
        id: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        changedAt: { dir: oracledb.BIND_OUT, type: oracledb.DATE },
      },
      { autoCommit: false }
    );

    await conn.commit();

    res.status(201).json({
      id: insertRes.outBinds.id[0],
      productId: parsedProductId,
      quantityChange,
      reason,
      changedBy: changedByUserId,
      changedAt: insertRes.outBinds.changedAt[0],
      resultingStock,
    });
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (rollbackErr) {
        console.error('Failed to roll back inventory movement transaction:', rollbackErr);
      }
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to record inventory movement' });
  } finally {
    if (conn) await conn.close();
  }
});

// GET /api/inventory/movements — movement history (any authenticated role)
router.get('/movements', async (req, res) => {
  const { productId, reason, from, to, limit, offset } = req.query;

  const filters = [];
  const binds = {};

  if (productId !== undefined) {
    const parsed = parsePositiveIntegerId(String(productId));
    if (parsed === null) {
      return res.status(400).json({ error: 'productId must be a positive integer' });
    }
    filters.push('product_id = :productId');
    binds.productId = parsed;
  }

  if (reason !== undefined) {
    if (typeof reason !== 'string' || !ALL_REASONS.includes(reason)) {
      return res.status(400).json({ error: 'reason must be one of RESTOCK, SALE, ADJUSTMENT, RETURN' });
    }
    filters.push('reason = :reason');
    binds.reason = reason;
  }

  if (from !== undefined) {
    const fromDate = new Date(from);
    if (Number.isNaN(fromDate.getTime())) {
      return res.status(400).json({ error: 'from must be a valid date' });
    }
    filters.push('changed_at >= :fromDate');
    binds.fromDate = fromDate;
  }

  if (to !== undefined) {
    const toDate = new Date(to);
    if (Number.isNaN(toDate.getTime())) {
      return res.status(400).json({ error: 'to must be a valid date' });
    }
    filters.push('changed_at <= :toDate');
    binds.toDate = toDate;
  }

  let parsedLimit = DEFAULT_LIST_LIMIT;
  if (limit !== undefined) {
    if (!/^[1-9][0-9]*$/.test(String(limit)) || Number(limit) > MAX_LIST_LIMIT) {
      return res.status(400).json({ error: `limit must be a positive integer up to ${MAX_LIST_LIMIT}` });
    }
    parsedLimit = Number(limit);
  }

  let parsedOffset = 0;
  if (offset !== undefined) {
    if (!/^[0-9]+$/.test(String(offset))) {
      return res.status(400).json({ error: 'offset must be a non-negative integer' });
    }
    parsedOffset = Number(offset);
  }

  binds.limitVal = parsedLimit;
  binds.offsetVal = parsedOffset;

  const whereClause = filters.length > 0 ? `WHERE ${filters.join(' AND ')}` : '';

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT inventory_id, product_id, quantity_change, reason, changed_by, changed_at
       FROM inventory
       ${whereClause}
       ORDER BY changed_at DESC, inventory_id DESC
       OFFSET :offsetVal ROWS FETCH NEXT :limitVal ROWS ONLY`,
      binds
    );

    const movements = result.rows.map((row) =>
      serializeMovementRow({
        ID: row.INVENTORY_ID,
        PRODUCT_ID: row.PRODUCT_ID,
        QUANTITY_CHANGE: row.QUANTITY_CHANGE,
        REASON: row.REASON,
        CHANGED_BY: row.CHANGED_BY,
        CHANGED_AT: row.CHANGED_AT,
      })
    );

    res.json(movements);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch inventory movements' });
  } finally {
    if (conn) await conn.close();
  }
});

// GET /api/inventory/products/:productId/stock — current stock (any authenticated role)
router.get('/products/:productId/stock', async (req, res) => {
  const productId = parsePositiveIntegerId(req.params.productId);
  if (productId === null) {
    return res.status(400).json({ error: 'productId must be a positive integer' });
  }

  let conn;
  try {
    conn = await getConnection();

    const productRes = await conn.execute(
      `SELECT product_id FROM products WHERE product_id = :productId`,
      { productId }
    );
    if (productRes.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const stockRes = await conn.execute(
      `SELECT NVL(SUM(quantity_change), 0) AS current_stock
       FROM inventory WHERE product_id = :productId`,
      { productId }
    );

    res.json({
      productId,
      currentStock: stockRes.rows[0].CURRENT_STOCK,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch current stock' });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;
