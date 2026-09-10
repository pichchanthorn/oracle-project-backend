require('dotenv').config();
const request = require('supertest');
const oracledb = require('oracledb');
const app = require('../app');
const { initPool, getConnection, closePool } = require('../db');
const jwtService = require('../services/jwtService');
const { requireRole } = require('../middleware/roles');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

jest.setTimeout(30000);

const RUN_ID = Date.now();

// Tracks rows this suite creates via real write routes, so they can be
// cleaned up afterward without touching any pre-existing business data
// (categories/units/products have no per-test-run scoping the way the auth
// tables do, so every created row's id is recorded explicitly).
const createdCategoryIds = [];
const createdUnitIds = [];
const createdProductIds = [];

// A fixed, valid 2FA-enabled test user id is not needed here — this suite
// only needs syntactically well-formed JWT claims with a chosen role; it
// never needs the "user" to actually exist in USERS, because requireRole
// and requireAccessToken only inspect the verified token's claims, not the
// database. Using a fixed, clearly-fake id keeps every test independent.
function signAccessTokenWithRole(role) {
  return jwtService.signAccessToken({
    id: 999999,
    username: 'role_test_user',
    email: 'role_test_user@example.com',
    role,
  });
}

async function getChallengeTokenForRoleTest() {
  return jwtService.signTwoFactorChallengeToken({
    id: 999999,
    username: 'role_test_user',
    email: 'role_test_user@example.com',
    role: 'ADMIN',
  });
}

beforeAll(async () => {
  await initPool();
  jwtService.validateConfig();
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

describe('middleware/roles.js — requireRole() unit behavior', () => {
  function runMiddleware(req) {
    return new Promise((resolve) => {
      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(body) {
          resolve({ statusCode: this.statusCode, body, calledNext: false });
        },
      };
      requireRole('ADMIN', 'MANAGER')(req, res, () => resolve({ calledNext: true }));
    });
  }

  test('1. allows ADMIN where ADMIN is required', async () => {
    const result = await runMiddleware({ user: { role: 'ADMIN' } });
    expect(result.calledNext).toBe(true);
  });

  test('2. allows MANAGER where MANAGER is allowed', async () => {
    const result = await runMiddleware({ user: { role: 'MANAGER' } });
    expect(result.calledNext).toBe(true);
  });

  test('3. rejects ASSOCIATE with 403 when only ADMIN is allowed', async () => {
    const result = await new Promise((resolve) => {
      const res = {
        status(code) {
          this.statusCode = code;
          return this;
        },
        json(body) {
          resolve({ statusCode: this.statusCode, body });
        },
      };
      requireRole('ADMIN')({ user: { role: 'ASSOCIATE' } }, res, () => resolve({ calledNext: true }));
    });
    expect(result.statusCode).toBe(403);
  });

  test('4. rejects ASSOCIATE with 403 when ADMIN/MANAGER are allowed', async () => {
    const result = await runMiddleware({ user: { role: 'ASSOCIATE' } });
    expect(result.statusCode).toBe(403);
  });

  test('5. missing role is rejected with 403', async () => {
    const result = await runMiddleware({ user: {} });
    expect(result.statusCode).toBe(403);
  });

  test('5b. missing req.user entirely is rejected with 403 (never throws)', async () => {
    const result = await runMiddleware({});
    expect(result.statusCode).toBe(403);
  });

  test('6. unknown role is rejected with 403', async () => {
    const result = await runMiddleware({ user: { role: 'SUPERUSER' } });
    expect(result.statusCode).toBe(403);
  });

  test('7. role matching is exact (case, whitespace, substrings all rejected)', async () => {
    const cases = ['admin', 'Admin', ' ADMIN', 'ADMIN ', 'ADMINISTRATOR', 'AD'];
    for (const role of cases) {
      const result = await new Promise((resolve) => {
        const res = {
          status(code) {
            this.statusCode = code;
            return this;
          },
          json(body) {
            resolve({ statusCode: this.statusCode, body });
          },
        };
        requireRole('ADMIN')({ user: { role } }, res, () => resolve({ calledNext: true }));
      });
      expect(result.statusCode).toBe(403);
    }
  });
});

describe('Authorization — HTTP-level enforcement', () => {
  test('8. role supplied in request body cannot override req.user.role', async () => {
    const associateToken = signAccessTokenWithRole('ASSOCIATE');

    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${associateToken}`)
      .send({ name: `role_override_attempt_${RUN_ID}`, role: 'ADMIN' });

    // The body's role:"ADMIN" must have no effect — the token's real role
    // (ASSOCIATE) is what governs, so this must still be rejected.
    expect(res.status).toBe(403);
  });

  test('9. no-token request remains 401 on a role-protected route', async () => {
    const res = await request(app).post('/api/categories').send({ name: 'no-token-attempt' });
    expect(res.status).toBe(401);
  });

  test('10. invalid access token remains 401 on a role-protected route', async () => {
    const adminToken = signAccessTokenWithRole('ADMIN');
    const tampered = adminToken.slice(0, -2) + 'xx';

    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${tampered}`)
      .send({ name: 'tampered-token-attempt' });
    expect(res.status).toBe(401);
  });

  test('11. a 2FA challenge token remains rejected with 401 on a role-protected route', async () => {
    const challengeToken = await getChallengeTokenForRoleTest();

    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${challengeToken}`)
      .send({ name: 'challenge-token-attempt' });
    // Must be 401 (rejected by requireAccessToken's token_type check),
    // never 403 — authorization must not even be reached for a token that
    // fails authentication.
    expect(res.status).toBe(401);
  });

  test('12. GET routes remain accessible to all three valid roles', async () => {
    for (const role of ['ADMIN', 'MANAGER', 'ASSOCIATE']) {
      const token = signAccessTokenWithRole(role);

      const categoriesRes = await request(app).get('/api/categories').set('Authorization', `Bearer ${token}`);
      expect(categoriesRes.status).toBe(200);

      const unitsRes = await request(app).get('/api/units').set('Authorization', `Bearer ${token}`);
      expect(unitsRes.status).toBe(200);

      const productsRes = await request(app).get('/api/products').set('Authorization', `Bearer ${token}`);
      expect(productsRes.status).toBe(200);
    }
  });
});

describe('Category privileged routes — role matrix', () => {
  test('13a. ADMIN can create a category', async () => {
    const token = signAccessTokenWithRole('ADMIN');
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_category_admin_${RUN_ID}` });
    expect(res.status).toBe(201);
    createdCategoryIds.push(res.body.id);
  });

  test('13b. MANAGER is rejected from creating a category with 403', async () => {
    const token = signAccessTokenWithRole('MANAGER');
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_category_manager_${RUN_ID}` });
    expect(res.status).toBe(403);
  });

  test('13c. ASSOCIATE is rejected from creating a category with 403', async () => {
    const token = signAccessTokenWithRole('ASSOCIATE');
    const res = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_category_associate_${RUN_ID}` });
    expect(res.status).toBe(403);
  });

  test('13d. ADMIN can toggle a category; MANAGER/ASSOCIATE are rejected with 403', async () => {
    const adminToken = signAccessTokenWithRole('ADMIN');
    const createRes = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: `role_test_category_toggle_${RUN_ID}` });
    expect(createRes.status).toBe(201);
    createdCategoryIds.push(createRes.body.id);
    const categoryId = createRes.body.id;

    const managerToggle = await request(app)
      .patch(`/api/categories/${categoryId}/toggle`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('MANAGER')}`);
    expect(managerToggle.status).toBe(403);

    const associateToggle = await request(app)
      .patch(`/api/categories/${categoryId}/toggle`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('ASSOCIATE')}`);
    expect(associateToggle.status).toBe(403);

    const adminToggle = await request(app)
      .patch(`/api/categories/${categoryId}/toggle`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(adminToggle.status).toBe(200);
  });
});

describe('Unit privileged routes — role matrix', () => {
  test('14a. ADMIN can create a unit', async () => {
    const token = signAccessTokenWithRole('ADMIN');
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_unit_admin_${RUN_ID}`, symbol: 'rta' });
    expect(res.status).toBe(201);
    createdUnitIds.push(res.body.id);
  });

  test('14b. MANAGER is rejected from creating a unit with 403', async () => {
    const token = signAccessTokenWithRole('MANAGER');
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_unit_manager_${RUN_ID}`, symbol: 'rtm' });
    expect(res.status).toBe(403);
  });

  test('14c. ASSOCIATE is rejected from creating a unit with 403', async () => {
    const token = signAccessTokenWithRole('ASSOCIATE');
    const res = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: `role_test_unit_associate_${RUN_ID}`, symbol: 'rts' });
    expect(res.status).toBe(403);
  });

  test('14d. ADMIN can update a unit; MANAGER/ASSOCIATE are rejected with 403', async () => {
    const adminToken = signAccessTokenWithRole('ADMIN');
    const createRes = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: `role_test_unit_patch_${RUN_ID}`, symbol: 'rtp' });
    expect(createRes.status).toBe(201);
    createdUnitIds.push(createRes.body.id);
    const unitId = createRes.body.id;

    const managerPatch = await request(app)
      .patch(`/api/units/${unitId}`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('MANAGER')}`)
      .send({ symbol: 'mgr' });
    expect(managerPatch.status).toBe(403);

    const associatePatch = await request(app)
      .patch(`/api/units/${unitId}`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('ASSOCIATE')}`)
      .send({ symbol: 'aso' });
    expect(associatePatch.status).toBe(403);

    const adminPatch = await request(app)
      .patch(`/api/units/${unitId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ symbol: 'upd' });
    expect(adminPatch.status).toBe(200);
  });
});

describe('Product write routes — role matrix', () => {
  let categoryId;
  let unitId;

  beforeAll(async () => {
    const adminToken = signAccessTokenWithRole('ADMIN');
    const categoryRes = await request(app)
      .post('/api/categories')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: `role_test_product_category_${RUN_ID}` });
    categoryId = categoryRes.body.id;
    createdCategoryIds.push(categoryId);

    const unitRes = await request(app)
      .post('/api/units')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ name: `role_test_product_unit_${RUN_ID}`, symbol: 'rtu' });
    unitId = unitRes.body.id;
    createdUnitIds.push(unitId);
  });

  test('15a. ADMIN can create a product', async () => {
    const token = signAccessTokenWithRole('ADMIN');
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${token}`)
      .send({ sku: `RT-ADMIN-${RUN_ID}`, name: 'Role Test Product Admin', categoryId, unitId, unitPrice: 10 });
    expect(res.status).toBe(201);
    createdProductIds.push(res.body.id);
  });

  test('15b. MANAGER can create a product', async () => {
    const token = signAccessTokenWithRole('MANAGER');
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${token}`)
      .send({ sku: `RT-MANAGER-${RUN_ID}`, name: 'Role Test Product Manager', categoryId, unitId, unitPrice: 10 });
    expect(res.status).toBe(201);
    createdProductIds.push(res.body.id);
  });

  test('15c. ASSOCIATE is rejected from creating a product with 403', async () => {
    const token = signAccessTokenWithRole('ASSOCIATE');
    const res = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${token}`)
      .send({ sku: `RT-ASSOCIATE-${RUN_ID}`, name: 'Role Test Product Associate', categoryId, unitId, unitPrice: 10 });
    expect(res.status).toBe(403);
  });

  test('15d. ADMIN and MANAGER can update a product; ASSOCIATE is rejected with 403', async () => {
    const adminToken = signAccessTokenWithRole('ADMIN');
    const createRes = await request(app)
      .post('/api/products')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ sku: `RT-PATCH-${RUN_ID}`, name: 'Role Test Product Patch', categoryId, unitId, unitPrice: 10 });
    expect(createRes.status).toBe(201);
    createdProductIds.push(createRes.body.id);
    const productId = createRes.body.id;

    const associatePatch = await request(app)
      .patch(`/api/products/${productId}`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('ASSOCIATE')}`)
      .send({ unitPrice: 20 });
    expect(associatePatch.status).toBe(403);

    const managerPatch = await request(app)
      .patch(`/api/products/${productId}`)
      .set('Authorization', `Bearer ${signAccessTokenWithRole('MANAGER')}`)
      .send({ unitPrice: 20 });
    expect(managerPatch.status).toBe(200);

    const adminPatch = await request(app)
      .patch(`/api/products/${productId}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ unitPrice: 30 });
    expect(adminPatch.status).toBe(200);
  });
});
