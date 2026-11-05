// Challenger 2.1 Empirical Stress Harness for Pre-Auth & API Lifecycle
// Validates concurrency, authorization, session immutability, and idempotency properties

import test, { describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Database, MerchantRepository, CustomerRepository, CustomerSessionRepository } from '@youpi/db';
import { createPaymentApp } from '../index.js';
import { PaymentStatus } from '@youpi/common';

describe('Challenger 2.1 API Lifecycle Stress Harness', () => {
  let app;
  let testDb;
  let serverInstance;
  let serverPort;
  let baseUrl;
  let merchantId;
  let merchantSecret;
  let ipCounter = 300;

  before(async () => {
    process.env.ENCRYPTION_MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    process.env.NODE_ENV = 'test';

    testDb = new Database({ inMemory: true });
    app = createPaymentApp(testDb, { otpCooldownMs: 0 });

    serverInstance = await new Promise((resolve) => {
      const s = app.rawServer.listen(0, '127.0.0.1', () => resolve(s));
    });

    serverPort = serverInstance.address().port;
    baseUrl = `http://127.0.0.1:${serverPort}`;

    const seededMerchant = new MerchantRepository(testDb).findAll()[0];
    merchantId = seededMerchant.id;
    merchantSecret = seededMerchant.webhookSecret;
  });

  beforeEach(() => {
    if (testDb) {
      testDb.execute("UPDATE payment_sessions SET status = 'EXPIRED' WHERE status IN ('ACTIVE', 'PROCESSING', 'QUEUED')");
      testDb.execute("UPDATE payment_receiving_accounts SET is_slot_busy = 0, current_active_session_id = NULL");
    }
  });

  after(async () => {
    if (app) app.destroy();
    if (serverInstance) await new Promise((resolve) => serverInstance.close(resolve));
    if (testDb) testDb.close();
  });

  async function postPayment(body, extraHeaders = {}) {
    const localIp = `127.0.0.${(ipCounter++ % 200) + 2}`;
    const payload = JSON.stringify(body);
    return new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port: serverPort,
        path: '/api/v1/payments',
        method: 'POST',
        localAddress: localIp,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'X-Merchant-Id': merchantId,
          'X-Merchant-Key': merchantSecret,
          'Idempotency-Key': body.orderId || `CHALLENGE-${Date.now()}-${Math.random()}`,
          ...extraHeaders
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            text: data,
            json: async () => {
              try { return JSON.parse(data); } catch { return null; }
            }
          });
        });
      });
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  async function getCheckoutState(paymentId, token = null) {
    const headers = {};
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(`${baseUrl}/api/v1/checkout/${paymentId}/state`, { headers });
  }

  async function bindCustomer(paymentId, customerId, token, extraHeaders = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...extraHeaders
    };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(`${baseUrl}/api/v1/checkout/${paymentId}/bind-customer`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ token, customerId })
    });
  }

  function getDbSession(paymentId) {
    return testDb.queryOne('SELECT * FROM payment_sessions WHERE id = ?', [paymentId]);
  }

  describe('Property 1: Unauthenticated /bind-customer requests', () => {
    test('1.1 Rejection with 401 across varied unauthenticated vectors leaves INITIATED session intact', async () => {
      const res = await postPayment({
        orderId: `CHALLENGE-P1-01-${Date.now()}`,
        amount: '120.00',
        method: 'MANUAL_UPI',
        customer: { name: 'P1 Customer', phoneNumber: '9881000001' }
      });
      assert.equal(res.status, 201);
      const json = await res.json();
      const initialDb = getDbSession(json.paymentId);
      assert.equal(initialDb.status, PaymentStatus.INITIATED);

      // Vector A: No token header or body
      const resA = await fetch(`${baseUrl}/api/v1/checkout/${json.paymentId}/bind-customer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert.equal(resA.status, 401);

      // Vector B: Invalid token string
      const resB = await fetch(`${baseUrl}/api/v1/checkout/${json.paymentId}/bind-customer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'csess_invalid_garbage_token' })
      });
      assert.equal(resB.status, 401);

      // Vector C: Authorization Bearer header with nonexistent token
      const resC = await fetch(`${baseUrl}/api/v1/checkout/${json.paymentId}/bind-customer`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer csess_nonexistent_token_000000000'
        },
        body: JSON.stringify({})
      });
      assert.equal(resC.status, 401);

      // Verify DB state is still INITIATED and not mutated or corrupted
      const finalDb = getDbSession(json.paymentId);
      assert.equal(finalDb.status, PaymentStatus.INITIATED);
      assert.equal(finalDb.customer_id, initialDb.customer_id);
    });

    test('1.2 50 unauthenticated bursts on a separate session do NOT affect an ACTIVE session', async () => {
      // Create and activate Session A
      const resA = await postPayment({
        orderId: `CHALLENGE-P1-02-A-${Date.now()}`,
        amount: '250.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Active User A', phoneNumber: '9881000002' }
      });
      assert.equal(resA.status, 201);
      const jsonA = await resA.json();
      const custA = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9881000002']);
      const bindA = await bindCustomer(jsonA.paymentId, custA.id, jsonA.customerSessionToken);
      assert.equal(bindA.status, 200);

      const dbA1 = getDbSession(jsonA.paymentId);
      assert.equal(dbA1.status, PaymentStatus.ACTIVE);

      // Create Session B
      const resB = await postPayment({
        orderId: `CHALLENGE-P1-02-B-${Date.now()}`,
        amount: '350.00',
        method: 'MANUAL_UPI'
      });
      const jsonB = await resB.json();

      // Fire 50 concurrent unauthenticated /bind-customer requests at Session B
      const burstRequests = Array.from({ length: 50 }, (_, i) =>
        fetch(`${baseUrl}/api/v1/checkout/${jsonB.paymentId}/bind-customer`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: `invalid_${i}`, customerId: `fake_id_${i}` })
        })
      );
      const burstResults = await Promise.all(burstRequests);
      for (const r of burstResults) {
        assert.equal(r.status, 401);
      }

      // Assert Session A is STILL ACTIVE
      const dbA2 = getDbSession(jsonA.paymentId);
      assert.equal(dbA2.status, PaymentStatus.ACTIVE, 'Session A must remain ACTIVE despite 50 unauthenticated requests on Session B');
    });
  });

  describe('Property 2: Concurrent checkouts on the same receiving account', () => {
    test('2.1 Concurrent checkouts remain in ACTIVE or QUEUED status without premature termination', async () => {
      // Initiate 4 sessions for 4 distinct customers
      const sessions = [];
      for (let i = 1; i <= 4; i++) {
        const phone = `988200000${i}`;
        const res = await postPayment({
          orderId: `CHALLENGE-CONC-${i}-${Date.now()}`,
          amount: `${100 * i}.00`,
          method: 'MANUAL_UPI',
          customer: { name: `Conc Customer ${i}`, phoneNumber: phone }
        });
        assert.equal(res.status, 201);
        const json = await res.json();
        const cust = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', [phone]);
        sessions.push({ ...json, customer: cust });
      }

      // Concurrently bind all 4 sessions
      const bindPromises = sessions.map(s =>
        bindCustomer(s.paymentId, s.customer.id, s.customerSessionToken)
      );
      const bindResults = await Promise.all(bindPromises);

      for (let i = 0; i < 4; i++) {
        assert.equal(bindResults[i].status, 200, `Binding session ${i + 1} must succeed`);
      }

      // Inspect DB status for all 4 sessions
      const statuses = sessions.map(s => getDbSession(s.paymentId).status);
      console.log('Concurrent session statuses:', statuses);

      // Verify that no session was killed prematurely (neither EXPIRED nor FAILED)
      for (let i = 0; i < 4; i++) {
        assert.ok(
          statuses[i] === PaymentStatus.ACTIVE || statuses[i] === PaymentStatus.QUEUED,
          `Session ${i + 1} status must be ACTIVE or QUEUED, got: ${statuses[i]}`
        );
      }

      // Exactly one session should hold the single active slot (status === ACTIVE)
      const activeCount = statuses.filter(st => st === PaymentStatus.ACTIVE).length;
      const queuedCount = statuses.filter(st => st === PaymentStatus.QUEUED).length;
      assert.equal(activeCount, 1, 'Exactly 1 session must be ACTIVE on a single receiving account');
      assert.equal(queuedCount, 3, 'Remaining 3 sessions must be QUEUED');
    });
  });

  describe('Property 3: Session hijacking prevention and token authorization boundary', () => {
    test('3.1 Customer B presenting own token cannot bind Customer A session and receives 409', async () => {
      // Customer A creates payment
      const resA = await postPayment({
        orderId: `CHALLENGE-HIJACK-A-${Date.now()}`,
        amount: '888.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Victim Customer A', phoneNumber: '9883000001' }
      });
      assert.equal(resA.status, 201);
      const jsonA = await resA.json();
      const custA = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9883000001']);

      // Customer B creates payment
      const resB = await postPayment({
        orderId: `CHALLENGE-HIJACK-B-${Date.now()}`,
        amount: '111.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Attacker Customer B', phoneNumber: '9883000002' }
      });
      assert.equal(resB.status, 201);
      const jsonB = await resB.json();
      const custB = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9883000002']);

      // Customer B attempts to bind Customer A's session presenting B's token & B's customerId
      const hijackAttempt = await bindCustomer(jsonA.paymentId, custB.id, jsonB.customerSessionToken);

      // Expected: 409 Conflict because session is already bound to Customer A
      assert.equal(hijackAttempt.status, 409, 'Attacker B must be rejected with HTTP 409 Conflict');
      const errJson = await hijackAttempt.json();
      assert.ok(errJson.error, 'Response must include error message');

      // Verify DB session A customer_id is unchanged
      const dbA = getDbSession(jsonA.paymentId);
      assert.equal(dbA.customer_id, custA.id, 'Session A must remain strictly bound to Customer A');
    });

    test('3.2 Customer B presenting token with mismatched customerId receives 401', async () => {
      // Customer A
      const resA = await postPayment({
        orderId: `CHALLENGE-MISMATCH-A-${Date.now()}`,
        amount: '500.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Target A', phoneNumber: '9883000003' }
      });
      const jsonA = await resA.json();
      const custA = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9883000003']);

      // Customer B
      const resB = await postPayment({
        orderId: `CHALLENGE-MISMATCH-B-${Date.now()}`,
        amount: '50.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Impersonator B', phoneNumber: '9883000004' }
      });
      const jsonB = await resB.json();

      // Attacker presents B's token but A's customerId
      const mismatchAttempt = await bindCustomer(jsonA.paymentId, custA.id, jsonB.customerSessionToken);
      assert.equal(mismatchAttempt.status, 401, 'Mismatched token subject must return 401');
      const errJson = await mismatchAttempt.json();
      assert.equal(errJson.code, 'CUSTOMER_SESSION_MISMATCH');
    });

    test('3.3 Customer B querying Customer A session state shields Customer A PII and invalid token yields null', async () => {
      const resA = await postPayment({
        orderId: `CHALLENGE-STATE-A-${Date.now()}`,
        amount: '950.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Secret Name A', phoneNumber: '9883000005' }
      });
      const jsonA = await resA.json();
      const custA = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9883000005']);

      const resB = await postPayment({
        orderId: `CHALLENGE-STATE-B-${Date.now()}`,
        amount: '50.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Spy Customer B', phoneNumber: '9883000006' }
      });
      const jsonB = await resB.json();

      // Customer B queries Customer A's session
      const stateRes = await getCheckoutState(jsonA.paymentId, jsonB.customerSessionToken);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      // Crucial security invariant: Customer A's PII must NEVER be leaked to Customer B!
      if (state.customer) {
        assert.notEqual(state.customer.id, custA.id, 'PII LEAK: Customer A id disclosed to Customer B');
        assert.notEqual(state.customer.name, 'Secret Name A', 'PII LEAK: Customer A name disclosed to Customer B');
        assert.notEqual(state.customer.mobileNumber, '9883000005', 'PII LEAK: Customer A phone disclosed to Customer B');
      }

      // Query with tampered/invalid token
      const tamperedRes = await getCheckoutState(jsonA.paymentId, 'csess_tampered_invalid_hex_token');
      assert.equal(tamperedRes.status, 200);
      const tamperedState = await tamperedRes.json();
      assert.equal(tamperedState.customer, null, 'Invalid token must yield customer: null');
    });
  });

  describe('Property 4: Idempotency replaying a session', () => {
    test('4.1 Replay preserves customerSessionToken and returns tokenized checkoutUrl across multiple replays', async () => {
      const orderId = `CHALLENGE-IDEMP-01-${Date.now()}`;
      const payload = {
        orderId,
        amount: '999.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Persistent User',
          phoneNumber: '9884000001'
        }
      };

      // 1st request: creation
      const res1 = await postPayment(payload, { 'Idempotency-Key': orderId });
      assert.equal(res1.status, 201);
      const json1 = await res1.json();
      assert.ok(json1.customerSessionToken, 'First response must include customerSessionToken');
      assert.ok(json1.checkoutUrl.includes(`auth_token=${json1.customerSessionToken}`));

      // Replays 2 through 10
      for (let replay = 2; replay <= 10; replay++) {
        const resR = await postPayment(payload, { 'Idempotency-Key': orderId });
        assert.equal(resR.status, 200, `Replay ${replay} must return 200`);
        const jsonR = await resR.json();
        assert.equal(jsonR.paymentId, json1.paymentId);
        assert.equal(jsonR.orderId, orderId);
        assert.equal(jsonR.activeSessionDetected, true);
        assert.ok(jsonR.customerSessionToken, `Replay ${replay} must preserve customerSessionToken`);
        assert.ok(
          jsonR.checkoutUrl.includes(`auth_token=${encodeURIComponent(jsonR.customerSessionToken)}`) ||
          jsonR.checkoutUrl.includes(`auth_token=${jsonR.customerSessionToken}`),
          `Replay ${replay} checkoutUrl must include auth_token`
        );
      }
    });

    test('4.2 Replaying guest session preserves bare checkoutUrl without injecting token', async () => {
      const orderId = `CHALLENGE-GUEST-IDEMP-${Date.now()}`;
      const payload = {
        orderId,
        amount: '300.00',
        currency: 'INR',
        method: 'MANUAL_UPI'
      };

      const res1 = await postPayment(payload, { 'Idempotency-Key': orderId });
      assert.equal(res1.status, 201);
      const json1 = await res1.json();
      assert.equal(json1.customerSessionToken, undefined);
      assert.ok(!json1.checkoutUrl.includes('auth_token='));

      const res2 = await postPayment(payload, { 'Idempotency-Key': orderId });
      assert.equal(res2.status, 200);
      const json2 = await res2.json();
      assert.equal(json2.customerSessionToken, undefined);
      assert.ok(!json2.checkoutUrl.includes('auth_token='), 'Replayed guest checkoutUrl must remain bare');
    });
  });
});
