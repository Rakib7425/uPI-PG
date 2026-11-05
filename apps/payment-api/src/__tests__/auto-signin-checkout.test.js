// Auto Sign-In & Pre-Authentication E2E Test Suite
// Opaque-box requirement-driven tests covering Tiers 1-4 for Payment Core API
// Authoritative sources: ORIGINAL_REQUEST.md, PROJECT.md, TEST_INFRA.md

import test, { describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Database, MerchantRepository, CustomerRepository, CustomerSessionRepository } from '@youpi/db';
import { createPaymentApp } from '../index.js';
import { PaymentStatus } from '@youpi/common';

describe('Auto Sign-In Checkout Core API E2E Suite', () => {
  let app;
  let testDb;
  let serverInstance;
  let serverPort;
  let baseUrl;
  let merchantId;
  let merchantSecret;
  let ipCounter = 10;

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

  // Helper to initiate payments with merchant credentials and isolated loopback IP
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
          'Idempotency-Key': body.orderId || `IDEMP-${Date.now()}-${Math.random()}`,
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

  // Helper to query checkout payment state
  async function getCheckoutState(paymentId, token = null, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return fetch(`${baseUrl}/api/v1/checkout/${paymentId}/state`, { headers });
  }

  // Helper to bind customer to payment session
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

  // ==========================================
  // TIER 1: CORE FEATURE CONTRACTS (F1 - F4)
  // ==========================================

  describe('Tier 1: Core Feature Contracts', () => {
    // Feature 1: Auto Sign-In / Pre-Authentication on Payment Checkout (R1)
    test('1.1 [F1] Session creation with member details returns HTTP 201, token, and tokenized checkoutUrl', async () => {
      const res = await postPayment({
        orderId: 'ORD-T1-001',
        amount: '1250.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Rohan Sharma',
          phoneNumber: '9876543210'
        },
        metadata: {
          targetType: 'DEPOSIT',
          targetAccountId: 'acc-dep-001',
          memberId: 'mem-001'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.paymentId, 'Response must include paymentId');
      assert.equal(data.orderId, 'ORD-T1-001');
      assert.equal(data.status, PaymentStatus.INITIATED);
      assert.ok(data.customerSessionToken, 'Pre-authenticated customer session token must be issued');
      assert.ok(data.customerSessionToken.startsWith('csess_'), 'Session token must follow csess_ format');
      assert.ok(data.checkoutUrl.includes(`auth_token=${data.customerSessionToken}`), 'checkoutUrl must carry auth_token parameter');
    });

    test('1.2 [F1] Customer record is auto-provisioned or retrieved in database with verified status', async () => {
      const res = await postPayment({
        orderId: 'ORD-T1-002',
        amount: '500.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Sunita Rao',
          phoneNumber: '9811122233'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);

      const custRepo = new CustomerRepository(testDb);
      const customer = custRepo.findByMobile('9811122233');
      assert.ok(customer, 'Customer record must exist in customers table');
      assert.equal(customer.name, 'Sunita Rao');
      assert.equal(customer.isPhoneVerified, 1);
    });

    // Feature 2: Bypass Manual Sign-in & OTP Verification (R2)
    test('1.3 [F2] State query with Authorization Bearer token reveals full customer profile (self-caller)', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T1-003',
        amount: '800.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Amit Verma',
          phoneNumber: '9822233344'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const stateRes = await getCheckoutState(created.paymentId, created.customerSessionToken);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.ok(state.customer, 'Customer object must be disclosed to authenticated self-caller');
      assert.equal(state.customer.name, 'Amit Verma');
      assert.equal(state.customer.mobileNumber, '9822233344');
    });

    test('1.4 [F2] State query with x-customer-token header also reveals customer profile', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T1-004',
        amount: '1000.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Deepak Kumar',
          phoneNumber: '9833344455'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const stateRes = await fetch(`${baseUrl}/api/v1/checkout/${created.paymentId}/state`, {
        headers: { 'x-customer-token': created.customerSessionToken }
      });
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.ok(state.customer);
      assert.equal(state.customer.mobileNumber, '9833344455');
    });

    // Feature 3: Fallback for Guest Sessions Without Member Details (R3)
    test('1.5 [F3] Session creation without customer details returns bare checkoutUrl and no token', async () => {
      const res = await postPayment({
        orderId: 'ORD-T1-005',
        amount: '600.00',
        method: 'MANUAL_UPI'
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.paymentId);
      assert.equal(data.customerSessionToken, undefined, 'Guest payment must not issue session token');
      assert.equal(data.checkoutUrl.includes('auth_token='), false, 'Guest checkoutUrl must not have auth_token');
    });

    test('1.6 [F3] Unauthenticated state query for guest payment returns customer: null', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T1-006',
        amount: '450.00',
        method: 'MANUAL_UPI'
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const stateRes = await getCheckoutState(created.paymentId);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.equal(state.customer, null, 'Unauthenticated guest query must return customer null');
    });

    // Feature 4: Session Activation & Auto-Binding (AC1)
    test('1.7 [F4] Customer auto-binding transitions session to ACTIVE status and starts expiry timer', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T1-007',
        amount: '1500.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Pooja Hegde',
          phoneNumber: '9844455566'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const custRepo = new CustomerRepository(testDb);
      const customer = custRepo.findByMobile('9844455566');

      const bindRes = await bindCustomer(created.paymentId, customer.id, created.customerSessionToken);
      assert.equal(bindRes.status, 200);
      const bindData = await bindRes.json();
      assert.equal(bindData.success, true);
      assert.equal(bindData.status, PaymentStatus.ACTIVE);
      assert.ok(bindData.expiresAt, 'Active session must have an expiration timestamp');
    });

    test('1.8 [F4] Subsequent state query after binding reflects ACTIVE status and countdown validity', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T1-008',
        amount: '2000.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Karan Mehra',
          phoneNumber: '9855566677'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const custRepo = new CustomerRepository(testDb);
      const customer = custRepo.findByMobile('9855566677');
      await bindCustomer(created.paymentId, customer.id, created.customerSessionToken);

      const stateRes = await getCheckoutState(created.paymentId, created.customerSessionToken);
      const state = await stateRes.json();
      assert.equal(state.status, PaymentStatus.ACTIVE);
      assert.ok(state.expiresAt);
      assert.equal(state.canClickPaymentDone, true);
    });
  });

  // ==========================================
  // TIER 2: BOUNDARY, CORNER & ERROR CASES
  // ==========================================

  describe('Tier 2: Boundary & Corner Cases', () => {
    test('2.1 [Boundary] Phone number with country prefix (+91) and spaces is normalized and accepted', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-001',
        amount: '350.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Meera Sen',
          phoneNumber: '+91 98666 77788'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);
      assert.ok(data.checkoutUrl.includes(`auth_token=${data.customerSessionToken}`));

      const custRepo = new CustomerRepository(testDb);
      const cust = custRepo.findByMobile('9866677788');
      assert.ok(cust, 'Customer must be stored with clean 10-digit mobile');
    });

    test('2.2 [Boundary] Missing customer name defaults gracefully to Member without error', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-002',
        amount: '400.00',
        method: 'MANUAL_UPI',
        customer: {
          phoneNumber: '9877788899'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);

      const custRepo = new CustomerRepository(testDb);
      const cust = custRepo.findByMobile('9877788899');
      assert.ok(cust);
      assert.equal(cust.name, 'Member', 'Default name should be Member when omitted');
    });

    test('2.3 [Boundary] Customer name with special characters and HTML is safely stored', async () => {
      const specialName = 'O\'Connor <script>alert("xss")</script> & Sons';
      const res = await postPayment({
        orderId: 'ORD-T2-003',
        amount: '750.00',
        method: 'MANUAL_UPI',
        customer: {
          name: specialName,
          phoneNumber: '9888899900'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);

      const stateRes = await getCheckoutState(data.paymentId, data.customerSessionToken);
      const state = await stateRes.json();
      assert.equal(state.customer.name, specialName);
    });

    test('2.4 [Corner] Empty customer object ({}) falls back to guest checkout', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-004',
        amount: '900.00',
        method: 'MANUAL_UPI',
        customer: {}
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.customerSessionToken, undefined);
      assert.equal(data.checkoutUrl.includes('auth_token='), false);
    });

    test('2.5 [Corner] Customer object with empty phoneNumber string falls back to guest checkout', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-005',
        amount: '250.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Empty Phone User',
          phoneNumber: ''
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.customerSessionToken, undefined);
      assert.equal(data.checkoutUrl.includes('auth_token='), false);
    });

    test('2.6 [Corner] Malformed short phone (123) falls back to guest checkout without 500 error', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-006',
        amount: '300.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Bad Phone User',
          phoneNumber: '123'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.customerSessionToken, undefined);
      assert.equal(data.checkoutUrl.includes('auth_token='), false);
    });

    test('2.7 [Corner] Alphabetic non-numeric phone falls back to guest checkout', async () => {
      const res = await postPayment({
        orderId: 'ORD-T2-007',
        amount: '320.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Alpha Phone User',
          phoneNumber: 'notanumber'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.customerSessionToken, undefined);
      assert.equal(data.checkoutUrl.includes('auth_token='), false);
    });

    test('2.8 [Security] Tampered token on state query returns customer: null', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T2-008',
        amount: '650.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Secure User',
          phoneNumber: '9899900011'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const fakeToken = 'csess_0000000000000000000000000000000000000000000000000000000000000000';
      const stateRes = await getCheckoutState(created.paymentId, fakeToken);
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.equal(state.customer, null, 'Tampered token must not yield customer PII');
    });

    test('2.9 [Security] Malformed authorization header format handles gracefully', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T2-009',
        amount: '420.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Header Test User',
          phoneNumber: '9800011122'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const stateRes = await fetch(`${baseUrl}/api/v1/checkout/${created.paymentId}/state`, {
        headers: { 'Authorization': 'NotBearerInvalidFormat' }
      });
      assert.equal(stateRes.status, 200);
      const state = await stateRes.json();
      assert.equal(state.customer, null);
    });

    test('2.10 [Security] Customer binding with mismatched customerId returns HTTP 401', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T2-010',
        amount: '1100.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Customer A',
          phoneNumber: '9811100001'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const wrongCustId = '00000000-0000-0000-0000-000000000099';
      const bindRes = await bindCustomer(created.paymentId, wrongCustId, created.customerSessionToken);
      assert.equal(bindRes.status, 401);
      const err = await bindRes.json();
      assert.ok(err.error);
    });

    test('2.11 [Security] Customer binding without token returns HTTP 401', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T2-011',
        amount: '1150.00',
        method: 'MANUAL_UPI'
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();

      const bindRes = await fetch(`${baseUrl}/api/v1/checkout/${created.paymentId}/bind-customer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ customerId: 'any-id' })
      });
      assert.equal(bindRes.status, 401);
    });

    test('2.12 [Corner] Banned member mobile number triggers HTTP 403 BLOCKED', async () => {
      const custRepo = new CustomerRepository(testDb);
      const bannedCust = custRepo.create({
        name: 'Fraud Suspect',
        mobileNumber: '9999900000',
        isPhoneVerified: 1
      });
      custRepo.banCustomer(bannedCust.id, 'FRAUDULENT_PAYMENT_INJECTION');

      const res = await postPayment({
        orderId: 'ORD-T2-012',
        amount: '9999.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Fraud Suspect',
          phoneNumber: '9999900000'
        }
      });

      assert.equal(res.status, 403);
      const data = await res.json();
      assert.equal(data.status, 'BLOCKED');
      assert.equal(data.isBanned, true);
    });
  });

  // ==========================================
  // TIER 3: COMBINATORIAL INTERACTIONS
  // ==========================================

  describe('Tier 3: Combinatorial & Cross-Feature Interactions', () => {
    test('3.1 Full Pre-Auth Journey: Creation -> Token Auth -> Slot Binding -> Confirmation', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T3-001',
        amount: '2500.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Anita Roy',
          phoneNumber: '9870011223'
        }
      });
      assert.equal(createRes.status, 201);
      const created = await createRes.json();
      const token = created.customerSessionToken;
      assert.ok(token);

      const state1 = await (await getCheckoutState(created.paymentId, token)).json();
      assert.equal(state1.status, PaymentStatus.INITIATED);
      assert.equal(state1.customer.name, 'Anita Roy');

      const custRepo = new CustomerRepository(testDb);
      const cust = custRepo.findByMobile('9870011223');

      const bindRes = await bindCustomer(created.paymentId, cust.id, token);
      assert.equal(bindRes.status, 200);

      const state2 = await (await getCheckoutState(created.paymentId, token)).json();
      assert.equal(state2.status, PaymentStatus.ACTIVE);
      assert.ok(state2.expiresAt);
    });

    test('3.2 Re-authentication: Existing member initiating 2nd payment reuses customer ID and issues new token', async () => {
      const res1 = await postPayment({
        orderId: 'ORD-T3-002A',
        amount: '100.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Vikram Seth',
          phoneNumber: '9871122334'
        }
      });
      const data1 = await res1.json();

      const res2 = await postPayment({
        orderId: 'ORD-T3-002B',
        amount: '200.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Vikram Seth',
          phoneNumber: '9871122334'
        }
      });
      assert.equal(res2.status, 201);
      const data2 = await res2.json();

      assert.ok(data2.customerSessionToken);
      const custRepo = new CustomerRepository(testDb);
      const matches = testDb.query('SELECT * FROM customers WHERE mobile_number = ?', ['9871122334']);
      assert.equal(matches.length, 1, 'Should not create duplicate customer records for same mobile');
    });

    test('3.3 Idempotency: Retrying payment creation with same Idempotency-Key returns identical response', async () => {
      const idempKey = 'IDEMP-COMB-003';
      const payload = {
        orderId: 'ORD-T3-003',
        amount: '750.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Radha Mohan',
          phoneNumber: '9872233445'
        }
      };

      const res1 = await postPayment(payload, { 'Idempotency-Key': idempKey });
      assert.equal(res1.status, 201);
      const body1 = await res1.json();

      const res2 = await postPayment(payload, { 'Idempotency-Key': idempKey });
      assert.ok([200, 201].includes(res2.status), 'Idempotent replay should return 200 or 201');
      const body2 = await res2.json();

      assert.equal(body1.paymentId, body2.paymentId);
      assert.equal(body1.orderId, body2.orderId);
    });

    test('3.4 Guest checkout followed by manual OTP verification and binding succeeds', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-T3-004',
        amount: '850.00',
        method: 'MANUAL_UPI'
      });
      const created = await createRes.json();

      const stateGuest = await (await getCheckoutState(created.paymentId)).json();
      assert.equal(stateGuest.customer, null);

      const custRepo = new CustomerRepository(testDb);
      const sessionRepo = new CustomerSessionRepository(testDb, custRepo);
      const guestCust = custRepo.create({
        name: 'Manual Guest',
        mobileNumber: '9873344556',
        isPhoneVerified: 1
      });
      const sessionRec = sessionRepo.create({ customerId: guestCust.id });

      const bindRes = await bindCustomer(created.paymentId, guestCust.id, sessionRec.token);
      assert.equal(bindRes.status, 200);

      const stateAuth = await (await getCheckoutState(created.paymentId, sessionRec.token)).json();
      assert.equal(stateAuth.status, PaymentStatus.ACTIVE);
      assert.equal(stateAuth.customer.mobileNumber, '9873344556');
    });
  });

  // ==========================================
  // TIER 4: REAL-WORLD BANKING APPLICATION SCENARIOS
  // ==========================================

  describe('Tier 4: Real-World Banking Application Scenarios', () => {
    test('4.1 Scenario 1: Member initiates UPI Deposit collection from RD TCCS with full metadata', async () => {
      const res = await postPayment({
        orderId: 'DEP-UPI-20261104-001',
        amount: '5000.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Naveen Jindal',
          phoneNumber: '9874455667'
        },
        description: 'Deposit account DEP-009182',
        metadata: {
          targetType: 'DEPOSIT',
          targetAccountId: '6a7b8c9d-1111-2222-3333-000000000001',
          memberId: '1a2b3c4d-1111-2222-3333-000000000001',
          branchId: '9f8e7d6c-1111-2222-3333-000000000001'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);
      assert.ok(data.checkoutUrl.includes(`auth_token=${data.customerSessionToken}`));

      const state = await (await getCheckoutState(data.paymentId, data.customerSessionToken)).json();
      assert.equal(state.customer.name, 'Naveen Jindal');
      assert.equal(state.customer.mobileNumber, '9874455667');
      assert.equal(state.amount, '5000.00');
    });

    test('4.2 Scenario 2: Teller initiates UPI Loan Repayment collection for member', async () => {
      const res = await postPayment({
        orderId: 'LOAN-REPAY-20261104-002',
        amount: '12450.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Bhavna Joshi',
          phoneNumber: '9875566778'
        },
        description: 'Loan EMI payment LN-55412',
        metadata: {
          targetType: 'LOAN_REPAYMENT',
          targetAccountId: '6a7b8c9d-4444-5555-6666-000000000002',
          memberId: '1a2b3c4d-4444-5555-6666-000000000002',
          branchId: '9f8e7d6c-4444-5555-6666-000000000002'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);
      assert.ok(data.checkoutUrl.includes(`auth_token=${data.customerSessionToken}`));

      const state = await (await getCheckoutState(data.paymentId, data.customerSessionToken)).json();
      assert.equal(state.amount, '12450.00');
      assert.equal(state.customer.mobileNumber, '9875566778');
    });

    test('4.3 Scenario 3: Guest customer visits checkout link without pre-filled member details', async () => {
      const res = await postPayment({
        orderId: 'GUEST-CHECKOUT-003',
        amount: '150.00',
        method: 'MANUAL_UPI'
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.equal(data.customerSessionToken, undefined);
      assert.equal(data.checkoutUrl.includes('auth_token='), false);

      const state = await (await getCheckoutState(data.paymentId)).json();
      assert.equal(state.customer, null);
    });

    test('4.4 Scenario 4: Member checkout link with tampered token recovers cleanly without crashing', async () => {
      const createRes = await postPayment({
        orderId: 'ORD-TAMPER-004',
        amount: '920.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Tamper Victim',
          phoneNumber: '9876677889'
        }
      });
      const created = await createRes.json();

      const tamperedToken = created.customerSessionToken ? `${created.customerSessionToken}corrupted` : 'csess_corrupted';
      const stateRes = await getCheckoutState(created.paymentId, tamperedToken);
      assert.equal(stateRes.status, 200, 'Endpoint must not throw 500 when presented with corrupted token');
      const state = await stateRes.json();
      assert.equal(state.customer, null, 'Must fall back to null customer when token is invalid');
    });

    test('4.5 Scenario 5: Returning member with existing account completes payment seamlessly', async () => {
      const custRepo = new CustomerRepository(testDb);
      const preExisting = custRepo.create({
        name: 'Pre Registered Member',
        mobileNumber: '9877788990',
        isPhoneVerified: 1
      });

      const res = await postPayment({
        orderId: 'RETURNING-MEM-005',
        amount: '3100.00',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Pre Registered Member',
          phoneNumber: '9877788990'
        }
      });

      assert.equal(res.status, 201);
      const data = await res.json();
      assert.ok(data.customerSessionToken);

      const state = await (await getCheckoutState(data.paymentId, data.customerSessionToken)).json();
      assert.ok(state.customer);
      assert.equal(state.customer.id, preExisting.id, 'Session must bind to the existing customer ID');
      assert.equal(state.customer.mobileNumber, '9877788990');
    });
  });
});
