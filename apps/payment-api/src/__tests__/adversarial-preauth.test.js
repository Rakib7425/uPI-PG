// Adversarial Challenge & Stress-Test Suite for Pre-Authentication (Milestone 2)
// Testing: Rapid session creation, idempotency replay, input fuzzing,
// token tampering & expiry, cross-token boundary, and slot vacancy guard concurrency.

import test, { describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Database, MerchantRepository, CustomerRepository, CustomerSessionRepository } from '@youpi/db';
import { createPaymentApp } from '../index.js';
import { PaymentStatus, blindIndex } from '@youpi/common';

describe('Adversarial Pre-Auth & Session Lifecycle Stress Suite', () => {
  let app;
  let testDb;
  let serverInstance;
  let serverPort;
  let baseUrl;
  let merchantId;
  let merchantSecret;
  let ipCounter = 100;

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

  // Helper to post payments with isolated loopback address
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
          'Idempotency-Key': body.orderId || `ADV-IDEMP-${Date.now()}-${Math.random()}`,
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

  // Helper to query checkout state
  async function getCheckoutState(paymentId, token = null, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(`${baseUrl}/api/v1/checkout/${paymentId}/state`, { headers });
  }

  // Helper to bind customer
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

  // Helper to query payment status directly from DB
  function getDbSession(paymentId) {
    return testDb.queryOne('SELECT * FROM payment_sessions WHERE id = ?', [paymentId]);
  }

  // ==========================================
  // AREA 1: RAPID SESSION CREATION STRESS
  // ==========================================
  describe('Area 1: Rapid Consecutive Payment Session Creation', () => {
    test('1.1 Rapid sequential creation of 30 sessions for same customer deduplicates customer row', async () => {
      const phone = '9870000001';
      const tokens = [];

      for (let i = 0; i < 30; i++) {
        const res = await postPayment({
          orderId: `ADV-SEQ-${i}-${Date.now()}`,
          amount: '100.00',
          method: 'MANUAL_UPI',
          customer: {
            name: `User ${i}`,
            phoneNumber: phone
          }
        });
        assert.equal(res.status, 201, `Session ${i} should return 201`);
        const json = await res.json();
        assert.ok(json.customerSessionToken, `Session ${i} must have token`);
        tokens.push(json.customerSessionToken);
      }

      // Verify customer table has exactly 1 row for this mobile number
      const custRows = testDb.query('SELECT * FROM customers WHERE mobile_number = ?', [phone]);
      assert.equal(custRows.length, 1, 'Exactly one customer row must exist despite 30 creations');
      assert.equal(tokens.length, 30, '30 tokens must be issued');
    });

    test('1.2 Concurrent parallel creation of 20 sessions for distinct customers', async () => {
      const requests = Array.from({ length: 20 }, (_, i) => {
        const phone = `98710000${String(i).padStart(2, '0')}`;
        return postPayment({
          orderId: `ADV-PAR-${i}-${Date.now()}`,
          amount: `${(i + 1) * 50}.00`,
          method: 'MANUAL_UPI',
          customer: {
            name: `Parallel User ${i}`,
            phoneNumber: phone
          }
        });
      });

      const results = await Promise.all(requests);
      assert.equal(results.length, 20);

      for (let i = 0; i < 20; i++) {
        assert.equal(results[i].status, 201, `Parallel session ${i} should succeed`);
        const json = await results[i].json();
        assert.ok(json.customerSessionToken, `Parallel session ${i} should have token`);
        assert.ok(json.checkoutUrl.includes(json.customerSessionToken), `checkoutUrl must contain token`);
      }

      const totalCustomers = testDb.queryOne("SELECT COUNT(*) as cnt FROM customers WHERE mobile_number LIKE '98710000%'");
      assert.equal(totalCustomers.cnt, 20, 'All 20 distinct customers must be provisioned');
    });
  });

  // ==========================================
  // AREA 2: IDEMPOTENCY REPLAY STRESS
  // ==========================================
  describe('Area 2: Idempotency Replay Stress', () => {
    test('2.1 Replaying identical session: does replay return customerSessionToken and tokenized URL?', async () => {
      const orderId = `ADV-IDEMP-${Date.now()}`;
      const payload = {
        orderId,
        amount: '750.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Idempotent User',
          phoneNumber: '9872000001'
        }
      };

      const res1 = await postPayment(payload);
      assert.equal(res1.status, 201);
      const json1 = await res1.json();
      assert.ok(json1.customerSessionToken, 'Original response must include customerSessionToken');
      assert.ok(json1.checkoutUrl.includes('auth_token='), 'Original checkoutUrl must carry auth_token');

      // Replay with identical payload and idempotency key
      const res2 = await postPayment(payload, { 'Idempotency-Key': orderId });
      assert.equal(res2.status, 200);
      const json2 = await res2.json();
      assert.equal(json2.paymentId, json1.paymentId);
      assert.equal(json2.activeSessionDetected, true);

      // Verify whether the replay preserves customerSessionToken
      // If customerSessionToken is missing, this demonstrates that idempotent retries drop pre-auth!
      assert.ok(json2.customerSessionToken, 'Replay MUST preserve customerSessionToken');
      assert.ok(json2.checkoutUrl.includes('auth_token='), 'Replayed checkoutUrl MUST carry auth_token');
    });

    test('2.2 Replay with amount mismatch returns 409 ORDER_AMOUNT_MISMATCH', async () => {
      const orderId = `ADV-IDEMP-MISMATCH-${Date.now()}`;
      const res1 = await postPayment({
        orderId,
        amount: '500.00',
        method: 'MANUAL_UPI',
        customer: { phoneNumber: '9872000002' }
      });
      assert.equal(res1.status, 201);

      const res2 = await postPayment({
        orderId,
        amount: '999.00',
        method: 'MANUAL_UPI',
        customer: { phoneNumber: '9872000002' }
      }, { 'Idempotency-Key': orderId });
      assert.equal(res2.status, 409);
      const json2 = await res2.json();
      assert.equal(json2.code, 'ORDER_AMOUNT_MISMATCH');
    });

    test('2.3 Replay for guest session returns 200 without token and with bare checkoutUrl', async () => {
      const orderId = `ADV-GUEST-IDEMP-${Date.now()}`;
      const payload = {
        orderId,
        amount: '300.00',
        method: 'MANUAL_UPI'
      };

      const res1 = await postPayment(payload);
      assert.equal(res1.status, 201);
      const json1 = await res1.json();
      assert.equal(json1.customerSessionToken, undefined);
      assert.ok(!json1.checkoutUrl.includes('auth_token='));

      const res2 = await postPayment(payload, { 'Idempotency-Key': orderId });
      assert.equal(res2.status, 200);
      const json2 = await res2.json();
      assert.equal(json2.customerSessionToken, undefined);
      assert.ok(!json2.checkoutUrl.includes('auth_token='));
    });
  });

  // ==========================================
  // AREA 3: INPUT FUZZING
  // ==========================================
  describe('Area 3: Input Fuzzing (Phones, Names, Special Chars)', () => {
    test('3.1 Phone number variations and normalization', async () => {
      const testCases = [
        { input: '+919873000001', expectToken: true, desc: 'Country prefix +91 without space' },
        { input: '+91 98730 00002', expectToken: true, desc: 'Country prefix +91 with spaces' },
        { input: '9873000003', expectToken: true, desc: 'Standard 10 digit phone' },
        { input: '  9873000004  ', expectToken: true, desc: 'Phone with leading/trailing whitespace' },
        { input: '09873000005', expectToken: true, desc: 'Indian trunk prefix 0 normalized to 10 digits' },
        { input: '123', expectToken: false, desc: 'Short phone string' },
        { input: 'notaphonenumber', expectToken: false, desc: 'Alphabetic string' },
        { input: '+1-212-555-0199', expectToken: false, desc: 'US phone number format (starts with 2)' },
        { input: '\' OR \'1\'=\'1', expectToken: false, desc: 'SQL injection string' },
        { input: '<script>alert("xss")</script>', expectToken: false, desc: 'XSS script tag in phone' },
        { input: '📱9873000006', expectToken: true, desc: 'Emoji prefix stripped by normalizeMobile' },
        { input: '', expectToken: false, desc: 'Empty phone string' }
      ];

      for (let i = 0; i < testCases.length; i++) {
        const tc = testCases[i];
        const res = await postPayment({
          orderId: `ADV-FUZZ-PH-${i}-${Date.now()}`,
          amount: '150.00',
          method: 'MANUAL_UPI',
          customer: {
            name: 'Fuzz User',
            phoneNumber: tc.input
          }
        });

        assert.equal(res.status, 201, `Phone test [${tc.desc}] should return 201, got ${res.status}`);
        const json = await res.json();
        if (tc.expectToken) {
          assert.ok(json.customerSessionToken, `Expected token for ${tc.desc}`);
          assert.ok(json.checkoutUrl.includes('auth_token='), `Expected tokenized URL for ${tc.desc}`);
        } else {
          assert.equal(json.customerSessionToken, undefined, `Expected guest fallback for ${tc.desc}`);
          assert.ok(!json.checkoutUrl.includes('auth_token='), `Expected bare URL for ${tc.desc}`);
        }
      }
    });

    test('3.2 Customer name fuzzing: Unicode, Emoji, HTML, Whitespace', async () => {
      const nameCases = [
        { name: 'रमेश शर्मा', expectedStored: 'रमेश शर्मा', desc: 'Hindi Devanagari Unicode' },
        { name: 'محمد عبد الله', expectedStored: 'محمد عبد الله', desc: 'Arabic Unicode' },
        { name: '🚀 Super Member ⭐', expectedStored: '🚀 Super Member ⭐', desc: 'Emoji in name' },
        { name: 'O\'Connor & "Smith" <b style="color:red">Test</b>', expectedStored: 'O\'Connor & "Smith" <b style="color:red">Test</b>', desc: 'Quotes and HTML' },
        { name: '   ', expectedStored: 'Member', desc: 'Whitespace name defaults to Member' },
        { name: null, expectedStored: 'Member', desc: 'Null name defaults to Member' },
        { name: undefined, expectedStored: 'Member', desc: 'Undefined name defaults to Member' }
      ];

      for (let i = 0; i < nameCases.length; i++) {
        const tc = nameCases[i];
        const phone = `98740000${String(i).padStart(2, '0')}`;
        const res = await postPayment({
          orderId: `ADV-FUZZ-NM-${i}-${Date.now()}`,
          amount: '200.00',
          method: 'MANUAL_UPI',
          customer: {
            name: tc.name,
            phoneNumber: phone
          }
        });

        assert.equal(res.status, 201, `Name test [${tc.desc}] should return 201`);
        const json = await res.json();
        assert.ok(json.customerSessionToken);

        const cust = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', [phone]);
        assert.ok(cust, `Customer row should exist for ${tc.desc}`);
        assert.equal(cust.name, tc.expectedStored, `Stored name mismatch for ${tc.desc}`);
      }
    });
  });

  // ==========================================
  // AREA 4: TOKEN TAMPERING, EXPIRY & PRIVACY
  // ==========================================
  describe('Area 4: Token Tamper Resistance, Expiry & Boundary Protections', () => {
    test('4.1 Tampered token on /state query yields customer: null without leaking data', async () => {
      const res = await postPayment({
        orderId: `ADV-TAMPER-01-${Date.now()}`,
        amount: '400.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Private Customer',
          phoneNumber: '9875000001'
        }
      });
      const json = await res.json();

      // Attempt state query with forged/tampered token
      const stateRes = await getCheckoutState(json.paymentId, 'csess_forged_random_hex_00000000');
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.equal(state.customer, null, 'Tampered token must result in customer: null');
    });

    test('4.2 Expired token on /state query returns customer: null', async () => {
      const res = await postPayment({
        orderId: `ADV-EXP-01-${Date.now()}`,
        amount: '450.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Expiring User',
          phoneNumber: '9875000002'
        }
      });
      const json = await res.json();
      const token = json.customerSessionToken;

      // Force-expire token using blindIndex
      const hashedToken = blindIndex(token, 'csess');
      const pastTime = new Date(Date.now() - 3600000).toISOString();
      testDb.execute('UPDATE customer_sessions SET expires_at = ? WHERE token = ?', [pastTime, hashedToken]);

      // State query with expired token
      const stateRes = await getCheckoutState(json.paymentId, token);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.equal(state.customer, null, 'Expired token must not authorize customer details');
    });

    test('4.3 Cross-Customer Privacy: Customer A token cannot inspect Customer B session', async () => {
      // Create session for Customer A
      const resA = await postPayment({
        orderId: `ADV-PRIV-A-${Date.now()}`,
        amount: '100.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Customer A', phoneNumber: '9875000003' }
      });
      const jsonA = await resA.json();

      // Create session for Customer B
      const resB = await postPayment({
        orderId: `ADV-PRIV-B-${Date.now()}`,
        amount: '200.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Customer B', phoneNumber: '9875000004' }
      });
      const jsonB = await resB.json();

      // Bind Customer B to Session B
      const custB = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9875000004']);
      await bindCustomer(jsonB.paymentId, custB.id, jsonB.customerSessionToken);

      // Customer A queries Session B using Customer A's token
      const stateRes = await getCheckoutState(jsonB.paymentId, jsonA.customerSessionToken);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();

      // CRITICAL PRIVACY ASSERTION:
      // Session B is bound to Customer B. Customer A's token MUST NOT receive Customer B's PII!
      if (state.customer) {
        assert.notEqual(state.customer.mobileNumber, '9875000004', 'PII LEAK: Customer A saw Customer B phone!');
        assert.notEqual(state.customer.name, 'Customer B', 'PII LEAK: Customer A saw Customer B name!');
      }
    });
  });

  // ==========================================
  // AREA 5: SLOT VACANCY GUARD & CONCURRENCY
  // ==========================================
  describe('Area 5: Slot Vacancy Guard and Concurrency Vulnerabilities', () => {
    test('5.1 Pre-route slot vacancy guard: Does unauthenticated /bind-customer expire legitimate active sessions?', async () => {
      // Step 1: Customer 1 creates and binds Session 1
      const res1 = await postPayment({
        orderId: `ADV-SLOT-01-${Date.now()}`,
        amount: '600.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Customer 1', phoneNumber: '9876000001' }
      });
      const json1 = await res1.json();
      const cust1 = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9876000001']);
      const bind1 = await bindCustomer(json1.paymentId, cust1.id, json1.customerSessionToken);
      assert.equal(bind1.status, 200);

      // Verify Session 1 is ACTIVE in DB
      let session1 = getDbSession(json1.paymentId);
      assert.equal(session1.status, PaymentStatus.ACTIVE, 'Session 1 must be ACTIVE initially');

      // Step 2: Attacker sends an UNAUTHENTICATED /bind-customer request to a different session
      const res2 = await postPayment({
        orderId: `ADV-SLOT-02-${Date.now()}`,
        amount: '700.00',
        method: 'MANUAL_UPI'
      });
      const json2 = await res2.json();

      // Attacker posts to bind-customer with invalid token
      const attackerBind = await fetch(`${baseUrl}/api/v1/checkout/${json2.paymentId}/bind-customer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: 'fake_attacker_token', customerId: 'fake_id' })
      });

      // The route handler must reject with 401
      assert.equal(attackerBind.status, 401, 'Attacker bind must return 401');

      // Step 3: EMPIRICAL VERIFICATION: Check whether Session 1 was killed/expired by the pre-route middleware!
      session1 = getDbSession(json1.paymentId);
      console.log(`[SLOT GUARD CHECK] Session 1 status after attacker 401 request: ${session1.status}`);
      assert.equal(session1.status, PaymentStatus.ACTIVE,
        `VULNERABILITY DETECTED: An unauthenticated 401 request expired legitimate Session 1! Actual status: ${session1.status}`);
    });

    test('5.2 Concurrent customers on same receiving account: Does binding Session 2 prematurely kill Session 1?', async () => {
      // Customer 1 initiates and binds Session 1
      const res1 = await postPayment({
        orderId: `ADV-CONC-01-${Date.now()}`,
        amount: '800.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Customer 1', phoneNumber: '9876000002' }
      });
      const json1 = await res1.json();
      const cust1 = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9876000002']);
      await bindCustomer(json1.paymentId, cust1.id, json1.customerSessionToken);

      let session1 = getDbSession(json1.paymentId);
      assert.equal(session1.status, PaymentStatus.ACTIVE, 'Session 1 should be ACTIVE');

      // Customer 2 initiates and binds Session 2 on the same merchant account
      const res2 = await postPayment({
        orderId: `ADV-CONC-02-${Date.now()}`,
        amount: '900.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Customer 2', phoneNumber: '9876000003' }
      });
      const json2 = await res2.json();
      const cust2 = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9876000003']);
      await bindCustomer(json2.paymentId, cust2.id, json2.customerSessionToken);

      // Check Session 1 status
      session1 = getDbSession(json1.paymentId);
      console.log(`[CONCURRENCY CHECK] Session 1 status after Customer 2 bound Session 2: ${session1.status}`);
      assert.equal(session1.status, PaymentStatus.ACTIVE,
        `CONCURRENCY DEFECT: Legitimate Customer 1 was terminated when Customer 2 opened checkout! Actual status: ${session1.status}`);
    });

    test('5.3 Unbound Session Hijack: Can Customer B bind an unbound session created for Customer A?', async () => {
      // Teller initiates payment for Member A (phone 9877000001)
      const resA = await postPayment({
        orderId: `ADV-HIJACK-${Date.now()}`,
        amount: '1000.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Member A', phoneNumber: '9877000001' }
      });
      const jsonA = await resA.json();
      const custA = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9877000001']);

      // Customer B (phone 9877000002) has their own account and token
      const resB = await postPayment({
        orderId: `ADV-CUSTB-${Date.now()}`,
        amount: '50.00',
        method: 'MANUAL_UPI',
        customer: { name: 'Member B', phoneNumber: '9877000002' }
      });
      const jsonB = await resB.json();
      const custB = testDb.queryOne('SELECT * FROM customers WHERE mobile_number = ?', ['9877000002']);

      // Customer B tries to bind Customer A's session using Customer B's token & ID
      const hijackRes = await bindCustomer(jsonA.paymentId, custB.id, jsonB.customerSessionToken);
      const hijackedSession = getDbSession(jsonA.paymentId);

      // A secure implementation MUST NOT allow Customer B to bind a session provisioned for Member A!
      assert.notEqual(hijackedSession.customer_id, custB.id,
        'SECURITY VULNERABILITY: Customer B successfully bound and hijacked Customer A\'s payment session!');
    });
  });
});
