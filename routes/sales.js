const express = require('express');
const oracledb = require('oracledb');
const router = express.Router();
const { getConnection } = require('../db');
const { requireRole } = require('../middleware/roles');
const { parsePositiveIntegerId } = require('../utils/validateId');

const PAYMENT_METHODS = ['CASH', 'CARD', 'BANK_TRANSFER', 'QR'];
const ORA_FK_VIOLATION_CHILD = 2291; // parent key not found (invalid customerId/productId)

const DEFAULT_LIST_LIMIT = 50;
const MAX_LIST_LIMIT = 200;

// Strict integer check: JSON numbers only (typeof === 'number'), finite,
// a whole number, and strictly positive. Same shape as the productId/
// quantityChange checks in routes/inventory.js — rejects booleans, arrays,
// null, numeric strings, decimals, Infinity, and NaN.
function isValidPositiveInteger(value) {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isInteger(value) &&
    value > 0
  );
}

function toFiniteNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

// Rounds to 2 decimal places to match SALE_ITEMS.UNIT_PRICE/SUBTOTAL and
// SALES.TOTAL_AMOUNT (NUMBER(12,2)/NUMBER(14,2) in Oracle) — avoids binding
// floating-point artifacts like 19.999999999998.
function round2(n) {
  return Math.round(n * 100) / 100;
}

// Validates the request body shape before any DB work. Returns an error
// string, or null if the body is well-formed. Money fields (unitPrice,
// subtotal, totalAmount) and cashierId are intentionally never read from
// the body at all below — there is no code path that could forward them
// even if a client sent them.
function validateSaleRequest(body) {
  const { customerId, paymentMethod, items } = body || {};

  if (customerId !== undefined && customerId !== null && !isValidPositiveInteger(customerId)) {
    return 'customerId must be a positive integer';
  }

  if (typeof paymentMethod !== 'string' || !PAYMENT_METHODS.includes(paymentMethod)) {
    return `paymentMethod must be one of ${PAYMENT_METHODS.join(', ')}`;
  }

  if (!Array.isArray(items) || items.length === 0) {
    return 'items must be a non-empty array';
  }

  const seenProductIds = new Set();
  for (const item of items) {
    if (!item || typeof item !== 'object') {
      return 'each item must be an object with productId and quantity';
    }
    if (!isValidPositiveInteger(item.productId)) {
      return 'each item.productId must be a positive integer';
    }
    if (!isValidPositiveInteger(item.quantity)) {
      return 'each item.quantity must be a positive integer';
    }
    if (seenProductIds.has(item.productId)) {
      return 'duplicate productId in items';
    }
    seenProductIds.add(item.productId);
  }

  return null;
}

function serializeSaleRow(row) {
  return {
    saleId: row.SALE_ID,
    customerId: row.CUSTOMER_ID,
    cashierId: row.CASHIER_ID,
    saleDate: row.SALE_DATE,
    totalAmount: row.TOTAL_AMOUNT,
    paymentMethod: row.PAYMENT_METHOD,
  };
}

function serializeSaleItemRow(row) {
  return {
    saleItemId: row.SALE_ITEM_ID,
    saleId: row.SALE_ID,
    productId: row.PRODUCT_ID,
    quantity: row.QUANTITY,
    unitPrice: row.UNIT_PRICE,
    subtotal: row.SUBTOTAL,
  };
}

// POST /api/sales — create a sale with one or more line items
// (ADMIN, MANAGER, ASSOCIATE).
router.post('/', requireRole('ADMIN', 'MANAGER', 'ASSOCIATE'), async (req, res) => {
  const validationError = validateSaleRequest(req.body);
  if (validationError) {
    return res.status(400).json({ error: validationError });
  }

  const { customerId, paymentMethod, items } = req.body;

  // req.user.id comes exclusively from the verified JWT (see
  // middleware/auth.js's claimsToReqUser) — never from req.body/query/params,
  // so a caller can never spoof CASHIER_ID. Same conversion pattern as
  // routes/inventory.js's changedByUserId.
  const cashierId = toFiniteNumber(req.user && req.user.id);
  if (cashierId === null) {
    console.error('sale creation: req.user.id is not a finite number', req.user);
    return res.status(500).json({ error: 'Failed to record sale' });
  }

  // Lock product rows in a deterministic ascending order to reduce
  // deadlock risk when two sales share products (same strategy note as
  // routes/inventory.js's single-row FOR UPDATE, extended to N rows).
  const sortedProductIds = [...new Set(items.map((item) => item.productId))].sort((a, b) => a - b);

  let conn;
  try {
    conn = await getConnection();

    const productInfoById = new Map();
    for (const productId of sortedProductIds) {
      const productRes = await conn.execute(
        `SELECT product_id, is_active, unit_price FROM products WHERE product_id = :productId FOR UPDATE`,
        { productId },
        { autoCommit: false }
      );

      if (productRes.rows.length === 0) {
        await conn.rollback();
        return res.status(404).json({ error: 'Product not found' });
      }

      const row = productRes.rows[0];
      if (row.IS_ACTIVE !== 1) {
        await conn.rollback();
        return res.status(409).json({ error: 'Product is inactive' });
      }

      productInfoById.set(productId, { unitPrice: row.UNIT_PRICE });
    }

    // Stock check per distinct product: sum requested quantity across any
    // (deduplicated) line items referencing it, same ledger-sum approach as
    // routes/inventory.js's currentStock query.
    const requestedQuantityByProductId = new Map();
    for (const item of items) {
      requestedQuantityByProductId.set(
        item.productId,
        (requestedQuantityByProductId.get(item.productId) || 0) + item.quantity
      );
    }

    for (const productId of sortedProductIds) {
      const stockRes = await conn.execute(
        `SELECT NVL(SUM(quantity_change), 0) AS current_stock
         FROM inventory WHERE product_id = :productId`,
        { productId },
        { autoCommit: false }
      );
      const currentStock = stockRes.rows[0].CURRENT_STOCK;
      const requestedQuantity = requestedQuantityByProductId.get(productId);

      if (currentStock - requestedQuantity < 0) {
        await conn.rollback();
        return res.status(409).json({ error: 'Movement would result in negative stock' });
      }
    }

    // Authoritative pricing: PRODUCTS.UNIT_PRICE locked above, never the
    // client-supplied body (unitPrice/subtotal/totalAmount are never read
    // from req.body at all in this handler).
    const lineItems = items.map((item) => {
      const unitPrice = productInfoById.get(item.productId).unitPrice;
      const subtotal = round2(unitPrice * item.quantity);
      return { ...item, unitPrice, subtotal };
    });
    const totalAmount = round2(lineItems.reduce((sum, item) => sum + item.subtotal, 0));

    const saleInsertRes = await conn.execute(
      `INSERT INTO sales (customer_id, cashier_id, total_amount, payment_method)
       VALUES (:customerId, :cashierId, :totalAmount, :paymentMethod)
       RETURNING sale_id, sale_date INTO :saleId, :saleDate`,
      {
        customerId: { val: customerId !== undefined && customerId !== null ? customerId : null, type: oracledb.NUMBER },
        cashierId,
        totalAmount,
        paymentMethod,
        saleId: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        saleDate: { dir: oracledb.BIND_OUT, type: oracledb.DATE },
      },
      { autoCommit: false }
    );

    const saleId = saleInsertRes.outBinds.saleId[0];
    const saleDate = saleInsertRes.outBinds.saleDate[0];

    const createdSaleItems = [];
    for (const item of lineItems) {
      // SALE_ITEMS.SUBTOTAL is an Oracle virtual generated column
      // (GENERATED ALWAYS AS (QUANTITY*UNIT_PRICE)) — it cannot be an INSERT
      // target (ORA-54013), so it is never bound here. It is still always
      // equal to our own computed item.subtotal (same formula), and is read
      // back via RETURNING so the response reflects the DB's own value.
      const itemInsertRes = await conn.execute(
        `INSERT INTO sale_items (sale_id, product_id, quantity, unit_price)
         VALUES (:saleId, :productId, :quantity, :unitPrice)
         RETURNING sale_item_id, subtotal INTO :saleItemId, :subtotal`,
        {
          saleId,
          productId: item.productId,
          quantity: item.quantity,
          unitPrice: item.unitPrice,
          saleItemId: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
          subtotal: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER },
        },
        { autoCommit: false }
      );

      createdSaleItems.push({
        saleItemId: itemInsertRes.outBinds.saleItemId[0],
        saleId,
        productId: item.productId,
        quantity: item.quantity,
        unitPrice: item.unitPrice,
        subtotal: itemInsertRes.outBinds.subtotal[0],
      });

      // Direct INVENTORY write within this same transaction/connection —
      // never via POST /api/inventory/movements, which intentionally
      // rejects reason: 'SALE' (see routes/inventory.js). Same INSERT
      // shape as that route uses for RESTOCK/ADJUSTMENT/RETURN.
      await conn.execute(
        `INSERT INTO inventory (product_id, quantity_change, reason, changed_by)
         VALUES (:productId, :quantityChange, 'SALE', :changedBy)`,
        {
          productId: item.productId,
          quantityChange: -item.quantity,
          changedBy: cashierId,
        },
        { autoCommit: false }
      );
    }

    await conn.commit();

    res.status(201).json({
      sale: {
        saleId,
        customerId: customerId !== undefined && customerId !== null ? customerId : null,
        cashierId,
        saleDate,
        totalAmount,
        paymentMethod,
      },
      items: createdSaleItems,
    });
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (rollbackErr) {
        console.error('Failed to roll back sale transaction:', rollbackErr);
      }
    }
    if (err.errorNum === ORA_FK_VIOLATION_CHILD) {
      return res.status(400).json({ error: 'Invalid customerId' });
    }
    console.error(err);
    res.status(500).json({ error: 'Failed to record sale' });
  } finally {
    if (conn) await conn.close();
  }
});

// GET /api/sales — sale header list (any authenticated role), paginated.
router.get('/', async (req, res) => {
  const { limit, offset } = req.query;

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

  let conn;
  try {
    conn = await getConnection();
    const result = await conn.execute(
      `SELECT sale_id, customer_id, cashier_id, sale_date, total_amount, payment_method
       FROM sales
       ORDER BY sale_date DESC, sale_id DESC
       OFFSET :offsetVal ROWS FETCH NEXT :limitVal ROWS ONLY`,
      { offsetVal: parsedOffset, limitVal: parsedLimit }
    );

    res.json(result.rows.map(serializeSaleRow));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sales' });
  } finally {
    if (conn) await conn.close();
  }
});

// GET /api/sales/:id — sale header + items (any authenticated role).
router.get('/:id', async (req, res) => {
  const id = parsePositiveIntegerId(req.params.id);
  if (id === null) {
    return res.status(400).json({ error: 'id must be a positive integer' });
  }

  let conn;
  try {
    conn = await getConnection();

    const saleRes = await conn.execute(
      `SELECT sale_id, customer_id, cashier_id, sale_date, total_amount, payment_method
       FROM sales WHERE sale_id = :id`,
      { id }
    );

    if (saleRes.rows.length === 0) {
      return res.status(404).json({ error: 'Sale not found' });
    }

    const itemsRes = await conn.execute(
      `SELECT sale_item_id, sale_id, product_id, quantity, unit_price, subtotal
       FROM sale_items WHERE sale_id = :id ORDER BY sale_item_id`,
      { id }
    );

    res.json({
      sale: serializeSaleRow(saleRes.rows[0]),
      items: itemsRes.rows.map(serializeSaleItemRow),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch sale' });
  } finally {
    if (conn) await conn.close();
  }
});

module.exports = router;
