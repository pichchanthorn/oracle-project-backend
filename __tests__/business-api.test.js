require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const jwtService = require('../services/jwtService');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

jest.setTimeout(30000);

const RUN_ID = Date.now();

// Tracks every row this suite creates via real write routes, so cleanup can
// remove exactly those rows without touching pre-existing business data
// (categories/units/products have no per-test-run scoping the way the auth
// tables do — every created id must be recorded explicitly).
const createdCategoryIds = [];
const createdUnitIds = [];
const createdProductIds = [];

// These tests only need syntactically valid, correctly-signed JWT claims
// with a chosen role — requireAccessToken/requireRole inspect only the
// verified token's claims, never the database, so the "user" does not need
// to actually exist in USERS.
function signAccessTokenWithRole(role) {
  return jwtService.signAccessToken({
    id: 999999,
    username: 'business_api_test_user',
    email: 'business_api_test_user@example.com',
    role,
  });
}

const adminToken = () => signAccessTokenWithRole('ADMIN');
const managerToken = () => signAccessTokenWithRole('MANAGER');
const associateToken = () => signAccessTokenWithRole('ASSOCIATE');

let sharedCategoryId;
let sharedUnitId;

beforeAll(async () => {
  await initPool();
  jwtService.validateConfig();

  const catRes = await request(app)
    .post('/api/categories')
    .set('Authorization', `Bearer ${adminToken()}`)
    .send({ name: `biz_api_shared_category_${RUN_ID}` });
  sharedCategoryId = catRes.body.id;
  createdCategoryIds.push(sharedCategoryId);

  const unitRes = await request(app)
    .post('/api/units')
    .set('Authorization', `Bearer ${adminToken()}`)
    .send({ name: `biz_api_shared_unit_${RUN_ID}`, symbol: 'bsu' });
  sharedUnitId = unitRes.body.id;
  createdUnitIds.push(sharedUnitId);
});

afterAll(async () => {
  const conn = await getConnection();
  try {
    for (const id of createdProductIds) {
      await conn.execute(`DELETE FROM products WHERE product_id = :id`, { id });
    }
    for (const id of createdCategoryIds) {
      await conn.execute(`DELETE FROM categories WHERE category_id = :id`, { id });
    }
    for (const id of createdUnitIds) {
      await conn.execute(`DELETE FROM units WHERE unit_id = :id`, { id });
    }
    await conn.commit();
  } finally {
    await conn.close();
  }
  await closePool();
});

describe('Categories — business API hardening', () => {
  test('successful create returns 201', async () => {
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: `biz_cat_create_${RUN_ID}`, description: 'test' });
    expect(res.status).toBe(201);
    expect(typeof res.body.id).toBe('number');
    createdCategoryIds.push(res.body.id);
  });

  test('validation failure: missing name returns 400', async () => {
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ description: 'no name' });
    expect(res.status).toBe(400);
  });

  test('duplicate name returns 409 without leaking Oracle constraint details', async () => {
    const name = `biz_cat_dup_${RUN_ID}`;
    const first = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name });
    expect(first.status).toBe(201);
    createdCategoryIds.push(first.body.id);

    const second = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name });
    expect(second.status).toBe(409);
    expect(second.body.error).not.toMatch(/ORA-|SYS_C|constraint/i);
  });

  test('toggle on nonexistent-but-valid numeric ID returns 404, not silent success', async () => {
    const res = await request(app)
      .patch('/api/categories/999999999/toggle')
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(res.status).toBe(404);
  });

  test('toggle on malformed ID returns 400', async () => {
    // '' is intentionally excluded: an empty path segment never matches
    // Express's /:id/toggle route pattern at all, so it is rejected by
    // Express's own routing (404) before reaching this handler — it is not
    // a case this validation logic is responsible for.
    const cases = ['abc', '1.5', '-1', '0', ' ', '1e5', 'NaN'];
    for (const badId of cases) {
      const res = await request(app)
        .patch(`/api/categories/${encodeURIComponent(badId)}/toggle`)
        .set('Authorization', `Bearer ${adminToken()}`);
      expect(res.status).toBe(400);
    }
  });

  test('successful toggle flips active state and returns 200', async () => {
    const createRes = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: `biz_cat_toggle_${RUN_ID}` });
    createdCategoryIds.push(createRes.body.id);
    const id = createRes.body.id;

    const before = await request(app).get('/api/categories').set('Authorization', `Bearer ${adminToken()}`);
    const beforeActive = before.body.find((c) => c.id === id).active;

    const toggleRes = await request(app)
      .patch(`/api/categories/${id}/toggle`)
      .set('Authorization', `Bearer ${adminToken()}`);
    expect(toggleRes.status).toBe(200);

    const after = await request(app).get('/api/categories').set('Authorization', `Bearer ${adminToken()}`);
    const afterActive = after.body.find((c) => c.id === id).active;
    expect(afterActive).toBe(!beforeActive);
  });

  test('401 unauthenticated regression: no token on POST', async () => {
    const res = await request(app).post('/api/categories').send({ name: 'no-auth' });
    expect(res.status).toBe(401);
  });

  test('403 unauthorized-role regression: ASSOCIATE on POST', async () => {
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${associateToken()}`)
      .send({ name: 'assoc-forbidden' });
    expect(res.status).toBe(403);
  });

  test('GET remains accessible to all authenticated roles', async () => {
    for (const token of [adminToken(), managerToken(), associateToken()]) {
      const res = await request(app).get('/api/categories').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
    }
  });
});

describe('Units — business API hardening', () => {
  test('successful create returns 201', async () => {
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: `biz_unit_create_${RUN_ID}`, symbol: 'buc' });
    expect(res.status).toBe(201);
    createdUnitIds.push(res.body.id);
  });

  test('validation failure: missing symbol returns 400', async () => {
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: `biz_unit_nosymbol_${RUN_ID}` });
    expect(res.status).toBe(400);
  });

  test('duplicate name returns 409 without leaking Oracle constraint details', async () => {
    const name = `biz_unit_dup_${RUN_ID}`;
    const first = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name, symbol: 'bud' });
    expect(first.status).toBe(201);
    createdUnitIds.push(first.body.id);

    const second = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name, symbol: 'bu2' });
    expect(second.status).toBe(409);
    expect(second.body.error).not.toMatch(/ORA-|SYS_C|constraint/i);
  });

  test('successful update returns 200', async () => {
    const createRes = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: `biz_unit_update_${RUN_ID}`, symbol: 'buu' });
    createdUnitIds.push(createRes.body.id);

    const patchRes = await request(app)
      .patch(`/api/units/${createRes.body.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ symbol: 'upd' });
    expect(patchRes.status).toBe(200);
  });

  test('valid-but-nonexistent ID returns 404', async () => {
    const res = await request(app)
      .patch('/api/units/999999999')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ symbol: 'xx' });
    expect(res.status).toBe(404);
  });

  test('malformed ID returns 400', async () => {
    const cases = ['abc', '1.5', '-1', '0'];
    for (const badId of cases) {
      const res = await request(app)
        .patch(`/api/units/${encodeURIComponent(badId)}`)
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ symbol: 'xx' });
      expect(res.status).toBe(400);
    }
  });

  test('401 unauthenticated regression: no token on POST', async () => {
    const res = await request(app).post('/api/units').send({ name: 'no-auth', symbol: 'na' });
    expect(res.status).toBe(401);
  });

  test('403 unauthorized-role regression: MANAGER on POST (units are ADMIN-only)', async () => {
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${managerToken()}`)
      .send({ name: 'manager-forbidden', symbol: 'mf' });
    expect(res.status).toBe(403);
  });

  test('GET remains accessible to all authenticated roles', async () => {
    for (const token of [adminToken(), managerToken(), associateToken()]) {
      const res = await request(app).get('/api/units').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
    }
  });
});

describe('Products — business API hardening', () => {
  test('successful create returns 201', async () => {
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        sku: `BIZ-CREATE-${RUN_ID}`,
        name: 'Biz Create Product',
        categoryId: sharedCategoryId,
        unitId: sharedUnitId,
        unitPrice: 100,
      });
    expect(res.status).toBe(201);
    createdProductIds.push(res.body.id);
  });

  test('successful update returns 200', async () => {
    const createRes = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        sku: `BIZ-UPDATE-${RUN_ID}`,
        name: 'Biz Update Product',
        categoryId: sharedCategoryId,
        unitId: sharedUnitId,
        unitPrice: 50,
      });
    createdProductIds.push(createRes.body.id);

    const patchRes = await request(app)
      .patch(`/api/products/${createRes.body.id}`)
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ unitPrice: 75 });
    expect(patchRes.status).toBe(200);
  });

  test('validation failure: missing sku returns 400', async () => {
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ name: 'no sku', categoryId: sharedCategoryId, unitId: sharedUnitId, unitPrice: 10 });
    expect(res.status).toBe(400);
  });

  test('duplicate SKU returns 400 (existing behavior, unchanged)', async () => {
    const sku = `BIZ-DUP-${RUN_ID}`;
    const first = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ sku, name: 'First', categoryId: sharedCategoryId, unitId: sharedUnitId, unitPrice: 10 });
    expect(first.status).toBe(201);
    createdProductIds.push(first.body.id);

    const second = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ sku, name: 'Second', categoryId: sharedCategoryId, unitId: sharedUnitId, unitPrice: 10 });
    expect(second.status).toBe(400);
    expect(second.body.error).not.toMatch(/ORA-|SYS_C|constraint/i);
  });

  test('invalid foreign key (nonexistent categoryId) returns 400', async () => {
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({
        sku: `BIZ-BADFK-${RUN_ID}`,
        name: 'Bad FK',
        categoryId: 999999999,
        unitId: sharedUnitId,
        unitPrice: 10,
      });
    expect(res.status).toBe(400);
  });

  test('valid-but-nonexistent ID returns 404', async () => {
    const res = await request(app)
      .patch('/api/products/999999999')
      .set('Authorization', `Bearer ${adminToken()}`)
      .send({ unitPrice: 10 });
    expect(res.status).toBe(404);
  });

  test('malformed ID returns 400', async () => {
    const cases = ['abc', '1.5', '-1', '0'];
    for (const badId of cases) {
      const res = await request(app)
        .patch(`/api/products/${encodeURIComponent(badId)}`)
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ unitPrice: 10 });
      expect(res.status).toBe(400);
    }
  });

  describe('unitPrice validation (POST and PATCH)', () => {
    // SKU is VARCHAR2(30) — keep generated SKUs short and unique via a
    // monotonic counter rather than a long timestamp+random suffix.
    const shortRunId = RUN_ID.toString(36).slice(-6);
    let priceTestCounter = 0;
    function nextPriceTestSku(label) {
      priceTestCounter += 1;
      return `PT-${label}-${shortRunId}-${priceTestCounter}`;
    }

    async function expectCreateRejected(unitPrice) {
      const res = await request(app)
        .post('/api/products')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({
          sku: nextPriceTestSku('C'),
          name: 'Price Test',
          categoryId: sharedCategoryId,
          unitId: sharedUnitId,
          unitPrice,
        });
      expect(res.status).toBe(400);
      return res;
    }

    async function expectPatchRejected(unitPrice) {
      const createRes = await request(app)
        .post('/api/products')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({
          sku: nextPriceTestSku('P'),
          name: 'Price Patch Test',
          categoryId: sharedCategoryId,
          unitId: sharedUnitId,
          unitPrice: 1,
        });
      createdProductIds.push(createRes.body.id);

      const res = await request(app)
        .patch(`/api/products/${createRes.body.id}`)
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ unitPrice });
      expect(res.status).toBe(400);
      return res;
    }

    test('negative number rejected on create and update', async () => {
      await expectCreateRejected(-1);
      await expectPatchRejected(-1);
    });

    test('zero is valid (accepted) on create and update', async () => {
      const createRes = await request(app)
        .post('/api/products')
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({
          sku: `BIZ-PRICEZERO-${RUN_ID}`,
          name: 'Zero Price',
          categoryId: sharedCategoryId,
          unitId: sharedUnitId,
          unitPrice: 0,
        });
      expect(createRes.status).toBe(201);
      createdProductIds.push(createRes.body.id);

      const patchRes = await request(app)
        .patch(`/api/products/${createRes.body.id}`)
        .set('Authorization', `Bearer ${adminToken()}`)
        .send({ unitPrice: 0 });
      expect(patchRes.status).toBe(200);
    });

    test('boolean rejected on create and update', async () => {
      await expectCreateRejected(true);
      await expectPatchRejected(false);
    });

    test('array rejected on create and update', async () => {
      await expectCreateRejected([10]);
      await expectPatchRejected([]);
    });

    test('null rejected on create', async () => {
      await expectCreateRejected(null);
    });

    test('numeric string rejected on create and update', async () => {
      await expectCreateRejected('10');
      await expectPatchRejected('10');
    });

    test('whitespace string rejected on create and update', async () => {
      await expectCreateRejected('   ');
      await expectPatchRejected('   ');
    });

    test('hex string rejected on create and update', async () => {
      await expectCreateRejected('0x10');
      await expectPatchRejected('0x10');
    });

    test('plain object rejected on create and update (another type-confused value)', async () => {
      await expectCreateRejected({});
      await expectPatchRejected({ not: 'a number' });
    });
  });

  test('401 unauthenticated regression: no token on POST', async () => {
    const res = await request(app).post('/api/products').send({ sku: 'no-auth', name: 'x' });
    expect(res.status).toBe(401);
  });

  test('403 unauthorized-role regression: ASSOCIATE on POST', async () => {
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${associateToken()}`)
      .send({
        sku: `BIZ-ASSOC-${RUN_ID}`,
        name: 'Associate Forbidden',
        categoryId: sharedCategoryId,
        unitId: sharedUnitId,
        unitPrice: 10,
      });
    expect(res.status).toBe(403);
  });

  test('authorized-role success regression: MANAGER can create and update', async () => {
    const createRes = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${managerToken()}`)
      .send({
        sku: `BIZ-MGR-${RUN_ID}`,
        name: 'Manager Product',
        categoryId: sharedCategoryId,
        unitId: sharedUnitId,
        unitPrice: 10,
      });
    expect(createRes.status).toBe(201);
    createdProductIds.push(createRes.body.id);

    const patchRes = await request(app)
      .patch(`/api/products/${createRes.body.id}`)
      .set('Authorization', `Bearer ${managerToken()}`)
      .send({ unitPrice: 20 });
    expect(patchRes.status).toBe(200);
  });

  test('GET remains accessible to all authenticated roles', async () => {
    for (const token of [adminToken(), managerToken(), associateToken()]) {
      const res = await request(app).get('/api/products').set('Authorization', `Bearer ${token}`);
      expect(res.status).toBe(200);
    }
  });
});

describe('unitPrice validator — direct unit checks for Infinity/NaN', () => {
  // True Infinity/NaN cannot be transmitted as JSON over HTTP
  // (JSON.stringify(Infinity) === JSON.stringify(NaN) === 'null'), so the
  // route-level tests above cover every value a real client can actually
  // send. isValidUnitPrice is attached as a property on the exported router
  // (see routes/products.js) specifically so these two values — the ones
  // that motivated the Number.isFinite() check — can still be verified
  // directly.
  const { isValidUnitPrice } = require('../routes/products');

  test('Infinity is rejected', () => {
    expect(isValidUnitPrice(Infinity)).toBe(false);
    expect(isValidUnitPrice(-Infinity)).toBe(false);
  });

  test('NaN is rejected', () => {
    expect(isValidUnitPrice(NaN)).toBe(false);
  });

  test('valid finite numbers (including zero) are accepted', () => {
    expect(isValidUnitPrice(0)).toBe(true);
    expect(isValidUnitPrice(0.01)).toBe(true);
    expect(isValidUnitPrice(999999)).toBe(true);
  });

  test('negative finite numbers are rejected', () => {
    expect(isValidUnitPrice(-0.01)).toBe(false);
  });
});
