require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const jwtService = require('../services/jwtService');
const { createUser } = require('../services/userService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

jest.setTimeout(30000);

const RUN_ID = Date.now();

// Tracks every row this suite creates via real write routes, so cleanup can
// remove exactly those rows without touching pre-existing business data.
const createdCategoryIds = [];
const createdUnitIds = [];
const createdProductIds = [];
const createdInventoryIds = [];
const createdUserIds = [];

// INVENTORY.CHANGED_BY is NOT NULL with FK_INVENTORY_USER -> USERS.USER_ID
// (Phase 9 migration 003), so — unlike the auth/role suites, which only sign
// JWTs with a fake numeric id and never actually write to INVENTORY — every
// test that creates an inventory movement needs a JWT whose subject is a
// real row in USERS. One real user per role is created once in beforeAll and
// reused (synchronous token helpers below); a couple of ownership-specific
// tests create an extra dedicated user inline.
const testUsers = {}; // role -> { id, username, email }

async function createTestUser(label, role) {
  const username = `inv_test_${RUN_ID}_${label}`;
  const email = `${username}@example.com`;
  const user = await createUser({
    username,
    password: 'CorrectHorse123',
    fullName: `Inventory Test ${label}`,
    email,
  });
  createdUserIds.push(user.id);
  if (role !== 'ASSOCIATE') {
    const conn = await getConnection();
    try {
      await conn.execute(
        `UPDATE users SET role = :role WHERE user_id = :id`,
        { role, id: user.id },
        { autoCommit: true }
      );
    } finally {
      await conn.close();
    }
  }
  return { id: user.id, username, email };
}

function signAccessTokenFor(user, role) {
  return jwtService.signAccessToken({
    id: user.id,
    username: user.username,
    email: user.email,
    role,
  });
}

const adminToken = () => signAccessTokenFor(testUsers.ADMIN, 'ADMIN');
const managerToken = () => signAccessTokenFor(testUsers.MANAGER, 'MANAGER');
const associateToken = () => signAccessTokenFor(testUsers.ASSOCIATE, 'ASSOCIATE');

function signChallengeToken() {
  return jwtService.signTwoFactorChallengeToken({
    id: testUsers.ADMIN.id,
    username: testUsers.ADMIN.username,
    email: testUsers.ADMIN.email,
    role: 'ADMIN',
  });
}

let sharedCategoryId;
let sharedUnitId;

async function createProduct(overrides = {}) {
  const res = await request(app)
    .post('/api/products')
    .set('Authorization', `Bearer ${adminToken()}`)
    .send({
      sku: `INV-${RUN_ID}-${Math.random().toString(36).slice(2, 8)}`,
      name: 'Inventory Test Product',
      categoryId: sharedCategoryId,
      unitId: sharedUnitId,
      unitPrice: 100,
      ...overrides,
    });
  createdProductIds.push(res.body.id);
  return res.body.id;
}

async function restock(productId, quantityChange, token = adminToken()) {
  const res = await request(app)
    .post('/api/inventory/movements')
    .set('Authorization', `Bearer ${token}`)
    .send({ productId, quantityChange, reason: 'RESTOCK' });
  if (res.status === 201) createdInventoryIds.push(res.body.id);
  return res;
}

beforeAll(async () => {
  await initPool();
  jwtService.validateConfig();

  testUsers.ADMIN = await createTestUser('admin', 'ADMIN');
  testUsers.MANAGER = await createTestUser('manager', 'MANAGER');
  testUsers.ASSOCIATE = await createTestUser('associate', 'ASSOCIATE');

  const catRes = await request(app)
    .post('/api/categories')
    .set('Authorization', `Bearer ${adminToken()}`)
    .send({ name: `inv_shared_category_${RUN_ID}` });
  sharedCategoryId = catRes.body.id;
  createdCategoryIds.push(sharedCategoryId);

  const unitRes = await request(app)
    .post('/api/units')
    .set('Authorization', `Bearer ${adminToken()}`)
    .send({ name: `inv_shared_unit_${RUN_ID}`, symbol: 'isu' });
  sharedUnitId = unitRes.body.id;
  createdUnitIds.push(sharedUnitId);
});

afterAll(async () => {
  const conn = await getConnection();
  try {
    for (const id of createdInventoryIds) {
      await conn.execute(`DELETE FROM inventory WHERE inventory_id = :id`, { id });
    }
    for (const id of createdProductIds) {
      await conn.execute(`DELETE FROM inventory WHERE product_id = :id`, { id });
      await conn.execute(`DELETE FROM products WHERE product_id = :id`, { id });
    }
    for (const id of createdCategoryIds) {
      await conn.execute(`DELETE FROM categories WHERE category_id = :id`, { id });
    }
    for (const id of createdUnitIds) {
      await conn.execute(`DELETE FROM units WHERE unit_id = :id`, { id });
    }
    for (const id of createdUserIds) {
      await conn.execute(`DELETE FROM inventory WHERE changed_by = :id`, { id });
      await conn.execute(`DELETE FROM users WHERE user_id = :id`, { id });
    }
    await conn.commit();
  } finally {
    await conn.close();
  }
  await closePool();
});

describe('POST /api/inventory/movements — creation & authorization', () => {
  test('1. RESTOCK by ADMIN returns 201', async () => {
    const productId = await createProduct();
    const res = await restock(productId, 10, adminToken());
    expect(res.status).toBe(201);
    expect(res.body.resultingStock).toBe(10);
  });

  test('2. RESTOCK by MANAGER returns 201', async () => {
    const productId = await createProduct();
    const res = await restock(productId, 10, managerToken());
    expect(res.status).toBe(201);
  });

  test('3. RESTOCK by ASSOCIATE returns 403', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${associateToken()}`)
      .send({ productId, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(403);
  });

  test('4. RETURN by ADMIN returns 201', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 5, reason: 'RETURN' });
    expect(res.status).toBe(201);
    if (res.status === 201) createdInventoryIds.push(res.body.id);
  });

  test('5. RETURN by MANAGER returns 201', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${managerToken()}`)
      .send({ productId, quantityChange: 5, reason: 'RETURN' });
    expect(res.status).toBe(201);
    if (res.status === 201) createdInventoryIds.push(res.body.id);
  });

  test('6. RETURN by ASSOCIATE returns 403', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${associateToken()}`)
      .send({ productId, quantityChange: 5, reason: 'RETURN' });
    expect(res.status).toBe(403);
  });

  test('7. ADJUSTMENT positive returns 201', async () => {
    const productId = await createProduct();
    await restock(productId, 20, adminToken());
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 3, reason: 'ADJUSTMENT' });
    expect(res.status).toBe(201);
    if (res.status === 201) createdInventoryIds.push(res.body.id);
  });

  test('8. ADJUSTMENT negative returns 201 when stock remains >= 0', async () => {
    const productId = await createProduct();
    await restock(productId, 20, adminToken());
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -5, reason: 'ADJUSTMENT' });
    expect(res.status).toBe(201);
    expect(res.body.resultingStock).toBe(15);
    if (res.status === 201) createdInventoryIds.push(res.body.id);
  });

  test('9. ADJUSTMENT causing negative stock returns 409', async () => {
    const productId = await createProduct();
    await restock(productId, 5, adminToken());
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -10, reason: 'ADJUSTMENT' });
    expect(res.status).toBe(409);
  });

  test('10. negative RESTOCK returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -10, reason: 'RESTOCK' });
    expect(res.status).toBe(400);
  });

  test('11. negative RETURN returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -5, reason: 'RETURN' });
    expect(res.status).toBe(400);
  });

  test('12. zero quantityChange returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 0, reason: 'RESTOCK' });
    expect(res.status).toBe(400);
  });

  test('13. decimal quantityChange returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 1.5, reason: 'RESTOCK' });
    expect(res.status).toBe(400);
  });

  test('14. numeric-string quantityChange returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: '10', reason: 'RESTOCK' });
    expect(res.status).toBe(400);
  });

  test('14b. Infinity/NaN/null/boolean quantityChange all return 400', async () => {
    const productId = await createProduct();
    for (const bad of [Infinity, -Infinity, null, true, false, undefined]) {
      const res = await request(app)
        .post('/api/inventory/movements')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ productId, quantityChange: bad, reason: 'RESTOCK' });
      expect(res.status).toBe(400);
    }
  });

  test('15. invalid reason returns 400', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 10, reason: 'NOT_A_REASON' });
    expect(res.status).toBe(400);
  });

  test('16. SALE reason returns 400 as unsupported in Phase 9', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 5, reason: 'SALE' });
    expect(res.status).toBe(400);
  });

  test('17. nonexistent product returns 404', async () => {
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId: 999999999, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(404);
  });

  test('18. inactive product returns 409', async () => {
    const productId = await createProduct();
    await request(app)
      .patch(`/api/products/${productId}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ active: false });

    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(409);
  });

  test('19. malformed productId returns 400', async () => {
    for (const badId of ['abc', -1, 0, 1.5, '1.5', null]) {
      const res = await request(app)
        .post('/api/inventory/movements')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ productId: badId, quantityChange: 10, reason: 'RESTOCK' });
      expect(res.status).toBe(400);
    }
  });

  test('20. missing Authorization returns 401', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .send({ productId, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(401);
  });

  test('21. a 2FA challenge token cannot access inventory (401)', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${signChallengeToken()}`)
      .send({ productId, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(401);
  });

  test('22. wrong role (ASSOCIATE) returns 403', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${associateToken()}`)
      .send({ productId, quantityChange: 10, reason: 'ADJUSTMENT' });
    expect(res.status).toBe(403);
  });

  test('29. changedBy equals the authenticated JWT user id', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.status).toBe(201);
    expect(res.body.changedBy).toBe(testUsers.ADMIN.id);
    createdInventoryIds.push(res.body.id);
  });

  test('30. changedBy cannot be supplied/overridden by request body', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: 10, reason: 'RESTOCK', changedBy: 1, userId: 1 });
    expect(res.status).toBe(201);
    expect(res.body.changedBy).toBe(testUsers.ADMIN.id);
    expect(res.body.changedBy).not.toBe(1);
    createdInventoryIds.push(res.body.id);
  });

  test('31. transaction rollback leaves no partial movement on 409', async () => {
    const productId = await createProduct();
    await restock(productId, 5, adminToken());

    const before = await request(app)
      .get('/api/inventory/movements')
      .query({ productId })
      .set('Authorization', `Bearer ${adminToken()}`);
    const countBefore = before.body.length;

    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -100, reason: 'ADJUSTMENT' });
    expect(res.status).toBe(409);

    const after = await request(app)
      .get('/api/inventory/movements')
      .query({ productId })
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(after.body.length).toBe(countBefore);

    const stockRes = await request(app)
      .get(`/api/inventory/products/${productId}/stock`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(stockRes.body.currentStock).toBe(5);
  });
});

describe('GET /api/inventory/products/:productId/stock', () => {
  test('23. returns correct SUM of movements', async () => {
    const productId = await createProduct();
    await restock(productId, 10, adminToken());
    await restock(productId, 5, adminToken());
    const adjustRes = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -3, reason: 'ADJUSTMENT' });
    if (adjustRes.status === 201) createdInventoryIds.push(adjustRes.body.id);

    const res = await request(app)
      .get(`/api/inventory/products/${productId}/stock`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.currentStock).toBe(12);
  });

  test('24. returns 0 for a product with no movements', async () => {
    const productId = await createProduct();
    const res = await request(app)
      .get(`/api/inventory/products/${productId}/stock`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.currentStock).toBe(0);
  });

  test('nonexistent product returns 404', async () => {
    const res = await request(app)
      .get('/api/inventory/products/999999999/stock')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(404);
  });

  test('malformed productId returns 400', async () => {
    const res = await request(app)
      .get('/api/inventory/products/abc/stock')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(400);
  });

  test('accessible to all three authenticated roles', async () => {
    const productId = await createProduct();
    for (const token of [adminToken(), managerToken(), associateToken()]) {
      const res = await request(app)
        .get(`/api/inventory/products/${productId}/stock`)
        .set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
    }
  });

  test('missing Authorization returns 401', async () => {
    const productId = await createProduct();
    const res = await request(app).get(`/api/inventory/products/${productId}/stock`);
    expect(res.status).toBe(401);
  });
});

describe('GET /api/inventory/movements — history & filtering', () => {
  test('25. returns created history', async () => {
    const productId = await createProduct();
    const created = await restock(productId, 7, adminToken());

    const res = await request(app)
      .get('/api/inventory/movements')
      .query({ productId })
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.some((m) => m.id === created.body.id)).toBe(true);
  });

  test('26. filters by productId', async () => {
    const productA = await createProduct();
    const productB = await createProduct();
    await restock(productA, 4, adminToken());
    await restock(productB, 9, adminToken());

    const res = await request(app)
      .get('/api/inventory/movements')
      .query({ productId: productA })
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.every((m) => m.productId === productA)).toBe(true);
  });

  test('27. filters by reason', async () => {
    const productId = await createProduct();
    await restock(productId, 20, adminToken());
    const adjustRes = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId, quantityChange: -2, reason: 'ADJUSTMENT' });
    if (adjustRes.status === 201) createdInventoryIds.push(adjustRes.body.id);

    const res = await request(app)
      .get('/api/inventory/movements')
      .query({ productId, reason: 'ADJUSTMENT' })
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(200);
    expect(res.body.every((m) => m.reason === 'ADJUSTMENT')).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });

  test('28. invalid query returns 400', async () => {
    const cases = [
      { productId: 'abc' },
      { reason: 'NOT_A_REASON' },
      { limit: 'abc' },
      { limit: '0' },
      { limit: '99999' },
      { offset: '-1' },
      { from: 'not-a-date' },
      { to: 'not-a-date' },
    ];
    for (const query of cases) {
      const res = await request(app)
        .get('/api/inventory/movements')
        .query(query)
        .set('Authorization', `Bearer ${adminToken()}`);
      expect(res.status).toBe(400);
    }
  });

  test('accessible to all three authenticated roles', async () => {
    for (const token of [adminToken(), managerToken(), associateToken()]) {
      const res = await request(app).get('/api/inventory/movements').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
    }
  });

  test('missing Authorization returns 401', async () => {
    const res = await request(app).get('/api/inventory/movements');
    expect(res.status).toBe(401);
  });

  test('does not leak Oracle internals on error paths', async () => {
    const res = await request(app)
      .post('/api/inventory/movements')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ productId: 999999999, quantityChange: 10, reason: 'RESTOCK' });
    expect(res.body.error).not.toMatch(/ORA-|SYS_C|constraint/i);
  });
});

describe('Concurrency — serialized movements on the same product', () => {
  test('32. concurrent RESTOCKs on the same product are both applied correctly (serialized)', async () => {
    const productId = await createProduct();

    const [res1, res2] = await Promise.all([
      restock(productId, 10, adminToken()),
      restock(productId, 15, managerToken()),
    ]);

    expect(res1.status).toBe(201);
    expect(res2.status).toBe(201);

    const stockRes = await request(app)
      .get(`/api/inventory/products/${productId}/stock`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(stockRes.body.currentStock).toBe(25);
  });

  test('33. two concurrent stock-consuming movements exceeding stock: exactly one succeeds, stock never negative', async () => {
    const productId = await createProduct();
    await restock(productId, 10, adminToken());

    const [res1, res2] = await Promise.all([
      request(app)
        .post('/api/inventory/movements')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ productId, quantityChange: -8, reason: 'ADJUSTMENT' }),
      request(app)
        .post('/api/inventory/movements')
        .set('Authorization', `Bearer ${managerToken()}`)
        .send({ productId, quantityChange: -8, reason: 'ADJUSTMENT' }),
    ]);

    const statuses = [res1.status, res2.status].sort();
    expect(statuses).toEqual([201, 409]);

    if (res1.status === 201) createdInventoryIds.push(res1.body.id);
    if (res2.status === 201) createdInventoryIds.push(res2.body.id);

    const stockRes = await request(app)
      .get(`/api/inventory/products/${productId}/stock`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(stockRes.body.currentStock).toBeGreaterThanOrEqual(0);
    expect(stockRes.body.currentStock).toBe(2);
  });
});
