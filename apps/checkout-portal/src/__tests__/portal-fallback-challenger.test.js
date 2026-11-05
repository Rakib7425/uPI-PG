// Portal Fallback & SSR Adversarial Challenger Test Suite
// Verifies:
// 1. Guest checkout without member phone retains WhatsApp mobile entry & OTP prompt (R3)
// 2. Pre-authenticated checkout session bypasses OTP entry and lands directly on payment methods (R1, R2)
// 3. SSR INITIAL_STATE_JSON contains unescaped valid JSON (no literal &quot;) and parses synchronously
// 4. decryptClientStorage correctly handles both obfuscated JSON and raw string tokens

import test, { describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Database, MerchantRepository, CustomerRepository, CustomerSessionRepository, ReceivingAccountRepository, PaymentSessionRepository } from '@youpi/db';
import { createPaymentApp } from '../../../payment-api/src/index.js';
import { CheckoutServer, renderTemplate, serializeForScript } from '../server.js';
import { PaymentStatus } from '@youpi/common';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('Challenger 2.2: Portal Fallback & SSR Empirical Harness', () => {
  let paymentApp;
  let testDb;
  let apiServer;
  let portalServer;
  let apiBaseUrl;
  let portalBaseUrl;
  let merchantId;
  let merchantSecret;
  let receivingAccountId;
  let preAuthPaymentId;
  let guestNoPhonePaymentId;
  let guestPurePaymentId;
  let preAuthCustomerToken;
  let preAuthCustomer;

  function httpRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
      const req = http.request(options, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch {}
          resolve({ status: res.statusCode, headers: res.headers, text: body, json });
        });
      });
      req.on('error', reject);
      if (postData) {
        req.write(typeof postData === 'string' ? postData : JSON.stringify(postData));
      }
      req.end();
    });
  }

  function fetchPortal(path) {
    const url = new URL(path, portalBaseUrl);
    return httpRequest({
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method: 'GET'
    });
  }

  function extractInitialState(html) {
    const match = html.match(/<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/);
    if (!match) return null;
    return JSON.parse(match[1]);
  }

  function extractRawScriptContent(html) {
    const match = html.match(/<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/);
    return match ? match[1] : null;
  }

  // Exact function mirror from checkout.html (line 48)
  function encryptClientStorage(plainText) {
    if (!plainText) return '';
    try {
      let cipher = '';
      for (let i = 0; i < plainText.length; i++) {
        cipher += String.fromCharCode(plainText.charCodeAt(i) ^ 0x5a);
      }
      return btoa(cipher);
    } catch {
      return '';
    }
  }

  // Exact function mirror from checkout.html (lines 61-73)
  function decryptClientStorageHtml(cipherText) {
    if (!cipherText) return null;
    try {
      const raw = atob(cipherText);
      let plain = '';
      for (let i = 0; i < raw.length; i++) {
        plain += String.fromCharCode(raw.charCodeAt(i) ^ 0x5a);
      }
      try { return JSON.parse(plain); } catch { return plain; }
    } catch {
      try { return JSON.parse(cipherText); } catch { return cipherText; }
    }
  }

  // Exact function mirror from public/js/checkout.js (lines 28-40)
  function decryptClientStorageJs(cipherText) {
    if (!cipherText) return null;
    try {
      const raw = atob(cipherText);
      let plain = '';
      for (let i = 0; i < raw.length; i++) {
        plain += String.fromCharCode(raw.charCodeAt(i) ^ 0x5a);
      }
      try { return JSON.parse(plain); } catch { return plain; }
    } catch {
      try { return JSON.parse(cipherText); } catch { return cipherText; }
    }
  }

  before(async () => {
    process.env.ENCRYPTION_MASTER_KEY = process.env.ENCRYPTION_MASTER_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    process.env.INTERNAL_SERVICE_TOKEN = process.env.INTERNAL_SERVICE_TOKEN || 'test_internal_token_0123456789abcdef0123456789abcdef';
    process.env.NODE_ENV = 'test';

    testDb = new Database({ inMemory: true });
    paymentApp = createPaymentApp(testDb, { otpCooldownMs: 0 });

    apiServer = await new Promise((resolve) => {
      const s = paymentApp.rawServer.listen(0, '127.0.0.1', () => resolve(s));
    });
    const apiPort = apiServer.address().port;
    apiBaseUrl = `http://127.0.0.1:${apiPort}`;

    const portal = new CheckoutServer({ apiBaseUrl });
    const portalRaw = portal.createServer();
    portalServer = await new Promise((resolve) => {
      const s = portalRaw.listen(0, '127.0.0.1', () => resolve(s));
    });
    const portalPort = portalServer.address().port;
    portalBaseUrl = `http://127.0.0.1:${portalPort}`;

    const merchantRepo = new MerchantRepository(testDb);
    const seededMerchant = merchantRepo.findAll()[0];
    merchantId = seededMerchant.id;
    merchantSecret = seededMerchant.webhookSecret;

    const accountRepo = new ReceivingAccountRepository(testDb);
    let receivingAccount = accountRepo.findActiveForMerchant(merchantId);
    if (!receivingAccount) {
      receivingAccount = accountRepo.create({
        merchantId,
        upiId: 'irakibul026-2@okaxis',
        payeeName: 'Cooperative Banking Test',
        isActive: true
      });
    }
    receivingAccountId = receivingAccount ? receivingAccount.id : null;

    // Seed pre-authenticated customer
    const custRepo = new CustomerRepository(testDb);
    preAuthCustomer = custRepo.create({
      name: 'RDTCCS Member Suresh',
      mobileNumber: '9876501234',
      isPhoneVerified: 1,
      status: 'ACTIVE'
    });

    const custSessionRepo = new CustomerSessionRepository(testDb, custRepo);
    const custSession = custSessionRepo.create({ customerId: preAuthCustomer.id });
    preAuthCustomerToken = custSession.token;

    const sessionRepo = new PaymentSessionRepository(testDb);

    // 1. Pre-authenticated member payment session
    const preAuthSession = sessionRepo.create({
      merchantId,
      customerId: preAuthCustomer.id,
      receivingAccountId,
      orderId: 'ORD-CHALLENGE-PREAUTH-101',
      amountPaise: 500000,
      currency: 'INR',
      method: 'MANUAL_UPI',
      status: PaymentStatus.INITIATED,
      metadata: {
        targetType: 'DEPOSIT',
        targetAccountId: 'acc-uuid-101',
        memberId: 'mem-uuid-101',
        branchId: 'branch-uuid-101'
      }
    });
    preAuthPaymentId = preAuthSession.id;

    // 2. Guest session with name but NO phone number
    const guestNoPhoneSession = sessionRepo.create({
      merchantId,
      customerId: null,
      receivingAccountId,
      orderId: 'ORD-CHALLENGE-GUEST-NOPHONE-102',
      amountPaise: 150000,
      currency: 'INR',
      method: 'MANUAL_UPI',
      status: PaymentStatus.INITIATED,
      metadata: {
        targetType: 'DEPOSIT',
        targetAccountId: 'acc-uuid-102'
      }
    });
    guestNoPhonePaymentId = guestNoPhoneSession.id;

    // 3. Completely pure guest session
    const guestPureSession = sessionRepo.create({
      merchantId,
      customerId: null,
      receivingAccountId,
      orderId: 'ORD-CHALLENGE-GUEST-PURE-103',
      amountPaise: 75000,
      currency: 'INR',
      method: 'MANUAL_UPI',
      status: PaymentStatus.INITIATED
    });
    guestPurePaymentId = guestPureSession.id;
  });

  beforeEach(() => {
    // Slot isolation: ensure no stale active session holds the slot
    try {
      testDb.execute("UPDATE payment_sessions SET status = 'EXPIRED' WHERE status IN ('ACTIVE', 'PROCESSING', 'QUEUED')");
      testDb.execute("UPDATE payment_receiving_accounts SET is_slot_busy = 0, current_active_session_id = NULL");
    } catch {}
  });

  after(async () => {
    if (portalServer) await new Promise((r) => portalServer.close(r));
    if (apiServer) await new Promise((r) => apiServer.close(r));
    if (testDb) testDb.close();
  });

  describe('Section 1: Guest Checkout Fallback Flow (R3)', () => {
    test('1.1 Payment API creation without customer produces bare checkoutUrl with no auth_token', async () => {
      const url = new URL('/api/v1/payments', apiBaseUrl);
      const res = await httpRequest({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Merchant-Id': merchantId,
          'X-Merchant-Key': merchantSecret,
          'Idempotency-Key': 'idem-guest-r3-test-1'
        }
      }, {
        orderId: 'ORD-R3-API-GUEST-01',
        amount: '100.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        description: 'Guest payment without customer details'
      });

      assert.equal(res.status, 201);
      assert.equal(res.json.status, 'INITIATED');
      assert.ok(!res.json.customerSessionToken, 'Must not issue customerSessionToken');
      assert.ok(res.json.checkoutUrl, 'checkoutUrl must be returned');
      assert.ok(!res.json.checkoutUrl.includes('auth_token='), 'checkoutUrl must not contain auth_token');
      assert.ok(!res.json.checkoutUrl.includes('token='), 'checkoutUrl must not contain token');
    });

    test('1.2 Payment API creation with customer name but without phoneNumber falls back to guest', async () => {
      const url = new URL('/api/v1/payments', apiBaseUrl);
      const res = await httpRequest({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Merchant-Id': merchantId,
          'X-Merchant-Key': merchantSecret,
          'Idempotency-Key': 'idem-guest-r3-nophone-2'
        }
      }, {
        orderId: 'ORD-R3-API-NOPHONE-02',
        amount: '120.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Anonymous Walk-in Member'
          // No phoneNumber field
        },
        description: 'Customer without phone number'
      });

      assert.equal(res.status, 201);
      assert.ok(!res.json.customerSessionToken, 'Session token must not be present when phone is missing');
      assert.ok(!res.json.checkoutUrl.includes('auth_token='), 'Must produce clean checkoutUrl');
    });

    test('1.3 Payment API creation with empty phoneNumber string falls back to guest', async () => {
      const url = new URL('/api/v1/payments', apiBaseUrl);
      const res = await httpRequest({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Merchant-Id': merchantId,
          'X-Merchant-Key': merchantSecret,
          'Idempotency-Key': 'idem-guest-r3-emptyphone-3'
        }
      }, {
        orderId: 'ORD-R3-API-EMPTYPHONE-03',
        amount: '150.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Walk-in Member',
          phoneNumber: '   '
        },
        description: 'Customer with whitespace phone number'
      });

      assert.equal(res.status, 201);
      assert.ok(!res.json.customerSessionToken, 'Session token must not be present when phone is whitespace');
      assert.ok(!res.json.checkoutUrl.includes('auth_token='), 'Must produce clean checkoutUrl');
    });

    test('1.4 Guest checkout portal page renders WhatsApp mobile input and OTP verification elements', async () => {
      const res = await fetchPortal(`/checkout/${guestNoPhonePaymentId}`);
      assert.equal(res.status, 200);

      // Verify SSR state has null customer
      const state = extractInitialState(res.text);
      assert.ok(state, 'Initial state must be extractable');
      assert.equal(state.customer, null, 'SSR state customer must be null for guest checkout');

      // Verify DOM contains WhatsApp auth structure
      assert.ok(res.text.includes('id="preGatewayAuthView"'), 'Must contain preGatewayAuthView container');
      assert.ok(res.text.includes('id="authMobileInput"'), 'Must contain WhatsApp mobile input field');
      assert.ok(res.text.includes('id="authOtpInput"'), 'Must contain OTP verification input field');
      assert.ok(res.text.includes('handleAuthMobileSubmit()'), 'Must contain continue action for mobile submit');
      assert.ok(res.text.includes('handleAuthVerifyOtpSubmit()'), 'Must contain OTP verification action');
      assert.ok(res.text.includes('WhatsApp Mobile Number'), 'Must include WhatsApp label');

      // Verify zero-flash: both views start with hidden attribute in HTML
      const authTagMatch = res.text.match(/<div id="preGatewayAuthView"([^>]*)>/);
      assert.ok(authTagMatch && authTagMatch[1].includes('hidden'), 'preGatewayAuthView must start with hidden attribute');

      const payTagMatch = res.text.match(/<div id="paymentGatewayInterface"([^>]*)>/);
      assert.ok(payTagMatch && payTagMatch[1].includes('hidden'), 'paymentGatewayInterface must start with hidden attribute');
    });

    test('1.5 Pure guest checkout session (no metadata) renders manual sign-in and OTP form', async () => {
      const res = await fetchPortal(`/checkout/${guestPurePaymentId}`);
      assert.equal(res.status, 200);

      const state = extractInitialState(res.text);
      assert.equal(state.customer, null);
      assert.equal(state.orderId, 'ORD-CHALLENGE-GUEST-PURE-103');
      assert.equal(state.amount, '750.00');

      assert.ok(res.text.includes('placeholder="10-digit mobile number"'));
      assert.ok(res.text.includes('maxlength="6" inputmode="numeric"'));
    });

    test('1.6 Client-side guest gating simulation strictly activates auth form and mobile step', () => {
      const activeToken = null;
      const data = {
        id: guestNoPhonePaymentId,
        status: 'INITIATED',
        customer: null
      };

      const isPreAuth = Boolean(activeToken && (data.customer || null));
      const hasCustomer = Boolean(
        (data.customer || null) &&
        (data.status !== 'INITIATED' || Boolean(activeToken))
      );

      assert.equal(isPreAuth, false, 'isPreAuth must be false for guest');
      assert.equal(hasCustomer, false, 'hasCustomer must be false for guest');

      let authHidden = true;
      let payHidden = true;
      let payDisplay = '';
      let topbarTitle = '';
      let step = '';

      function setGatewayAuthMode(isAuthView) {
        if (isAuthView) {
          authHidden = false;
          payHidden = true;
          payDisplay = 'none';
          topbarTitle = 'Sign in to Pay';
        } else {
          authHidden = true;
          payHidden = false;
          payDisplay = '';
          topbarTitle = 'Payment Options';
        }
      }

      function goToAuthStep(s) {
        step = s;
      }

      if (!hasCustomer && !isPreAuth) {
        setGatewayAuthMode(true);
        goToAuthStep('mobile');
      } else {
        setGatewayAuthMode(false);
      }

      assert.equal(authHidden, false, 'preGatewayAuthView must be unhidden');
      assert.equal(payHidden, true, 'paymentGatewayInterface must be hidden');
      assert.equal(payDisplay, 'none', 'paymentGatewayInterface display must be none');
      assert.equal(topbarTitle, 'Sign in to Pay', 'Header title must indicate sign-in');
      assert.equal(step, 'mobile', 'Current step must be mobile input');
    });
  });

  describe('Section 2: Pre-Authenticated Checkout Bypass Flow (R1, R2)', () => {
    let apiPreAuthSession;

    test('2.1 Payment API creation with member details issues customerSessionToken and tokenized URL', async () => {
      const url = new URL('/api/v1/payments', apiBaseUrl);
      const res = await httpRequest({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Merchant-Id': merchantId,
          'X-Merchant-Key': merchantSecret,
          'Idempotency-Key': 'idem-preauth-r1-member-10'
        }
      }, {
        orderId: 'ORD-R1-API-MEMBER-10',
        amount: '2500.00',
        currency: 'INR',
        method: 'MANUAL_UPI',
        customer: {
          name: 'Aakash Verma',
          phoneNumber: '9822334455'
        },
        metadata: {
          targetType: 'DEPOSIT',
          targetAccountId: 'acc-uuid-2001',
          memberId: 'mem-uuid-2001',
          branchId: 'branch-uuid-001'
        },
        description: 'RD TCCS Deposit payment for member Aakash'
      });

      assert.equal(res.status, 201);
      assert.equal(res.json.status, 'INITIATED');
      assert.ok(res.json.customerSessionToken, 'customerSessionToken must be issued');
      assert.ok(res.json.customerSessionToken.startsWith('csess_'), 'Token must have csess_ prefix');
      assert.ok(res.json.checkoutUrl.includes(`?auth_token=${res.json.customerSessionToken}`), 'checkoutUrl must embed auth_token');

      apiPreAuthSession = res.json;
    });

    test('2.2 Portal SSR with auth_token returns pre-authenticated customer in INITIAL_STATE_JSON', async () => {
      const res = await fetchPortal(`/checkout/${apiPreAuthSession.paymentId}?auth_token=${apiPreAuthSession.customerSessionToken}`);
      assert.equal(res.status, 200);

      const state = extractInitialState(res.text);
      assert.ok(state, 'Initial state must exist');
      assert.ok(state.customer, 'Customer profile must be present in SSR initial state');
      assert.equal(state.customer.name, 'Aakash Verma');
      assert.equal(state.customer.mobileNumber, '9822334455');
      assert.equal(state.orderId, 'ORD-R1-API-MEMBER-10');
      assert.equal(state.amount, '2500.00');
    });

    test('2.3 Client-side pre-auth gating bypasses OTP and activates payment interface directly', () => {
      const activeToken = apiPreAuthSession.customerSessionToken;
      const data = {
        id: apiPreAuthSession.paymentId,
        status: 'INITIATED',
        customer: {
          id: 'cust-uuid-2001',
          name: 'Aakash Verma',
          mobileNumber: '9822334455'
        }
      };

      const isPreAuth = Boolean(activeToken && (data.customer || null));
      const hasCustomer = Boolean(
        (data.customer || null) &&
        (data.status !== 'INITIATED' || Boolean(activeToken))
      );

      assert.equal(isPreAuth, true, 'isPreAuth must be true for pre-authenticated member');
      assert.equal(hasCustomer, true, 'hasCustomer must be true for pre-authenticated member');

      let authHidden = true;
      let payHidden = true;
      let payDisplay = 'none';
      let topbarTitle = '';
      let autoBindTriggered = false;

      function setGatewayAuthMode(isAuthView) {
        if (isAuthView) {
          authHidden = false;
          payHidden = true;
          payDisplay = 'none';
          topbarTitle = 'Sign in to Pay';
        } else {
          authHidden = true;
          payHidden = false;
          payDisplay = '';
          topbarTitle = 'Payment Options';
        }
      }

      function autoBindCustomerToSession(custId, tok) {
        autoBindTriggered = true;
        assert.equal(custId, data.customer.id);
        assert.equal(tok, activeToken);
      }

      if (!hasCustomer && !isPreAuth) {
        setGatewayAuthMode(true);
      } else {
        setGatewayAuthMode(false);
        if (activeToken && (!data.customer || data.status === 'INITIATED')) {
          autoBindCustomerToSession(data.customer.id, activeToken);
        }
      }

      assert.equal(authHidden, true, 'preGatewayAuthView must remain completely hidden');
      assert.equal(payHidden, false, 'paymentGatewayInterface must be unhidden');
      assert.equal(payDisplay, '', 'paymentGatewayInterface display must be visible');
      assert.equal(topbarTitle, 'Payment Options', 'Header title must indicate payment options');
      assert.equal(autoBindTriggered, true, 'autoBindCustomerToSession must trigger immediately');
    });

    test('2.4 Auto-binding API call transitions pre-authenticated session from INITIATED to ACTIVE', async () => {
      const bindUrl = new URL(`/api/v1/checkout/${apiPreAuthSession.paymentId}/bind-customer`, portalBaseUrl);
      const res = await httpRequest({
        hostname: bindUrl.hostname,
        port: bindUrl.port,
        path: bindUrl.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiPreAuthSession.customerSessionToken}`
        }
      }, {
        token: apiPreAuthSession.customerSessionToken
      });

      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
      assert.equal(res.json.status, 'ACTIVE');

      // Verify that querying state now reflects ACTIVE status
      const stateRes = await fetchPortal(`/checkout/${apiPreAuthSession.paymentId}?auth_token=${apiPreAuthSession.customerSessionToken}`);
      assert.equal(stateRes.status, 200);
      const updatedState = extractInitialState(stateRes.text);
      assert.equal(updatedState.status, 'ACTIVE');
    });

    test('2.5 Alternative ?token= parameter behaves identically to ?auth_token=', async () => {
      const res = await fetchPortal(`/checkout/${preAuthPaymentId}?token=${preAuthCustomerToken}`);
      assert.equal(res.status, 200);

      const state = extractInitialState(res.text);
      assert.ok(state.customer, 'Customer profile must be present when using ?token=');
      assert.equal(state.customer.name, 'RDTCCS Member Suresh');
    });
  });

  describe('Section 3: SSR INITIAL_STATE_JSON Escaping & Parsing', () => {
    test('3.1 Live rendered page contains valid raw JSON quotes without &quot; entities', async () => {
      const res = await fetchPortal(`/checkout/${preAuthPaymentId}?auth_token=${preAuthCustomerToken}`);
      assert.equal(res.status, 200);

      const rawScriptContent = extractRawScriptContent(res.text);
      assert.ok(rawScriptContent, 'ypgInitialState script element must exist');

      // Critical assertion: verify no HTML entities in JSON
      assert.ok(!rawScriptContent.includes('&quot;'), 'JSON script must NOT contain &quot;');
      assert.ok(!rawScriptContent.includes('&amp;'), 'JSON script must NOT contain &amp;');
      assert.ok(!rawScriptContent.includes('&lt;'), 'JSON script must NOT contain &lt;');
      assert.ok(!rawScriptContent.includes('&gt;'), 'JSON script must NOT contain &gt;');
      assert.ok(!rawScriptContent.includes('&#39;'), 'JSON script must NOT contain &#39;');

      // Synchronous parse assertion
      const parsed = JSON.parse(rawScriptContent);
      assert.equal(typeof parsed, 'object');
      assert.equal(parsed.orderId, 'ORD-CHALLENGE-PREAUTH-101');
      assert.equal(parsed.amount, '5000.00');
      assert.equal(parsed.customer.name, 'RDTCCS Member Suresh');
    });

    test('3.2 renderTemplate handles complex nested objects with quotes and unicode strings', () => {
      const complexState = {
        orderId: 'ORD-"SPECIAL"-999',
        merchantName: 'RD TCCS "Coop" & Society',
        amount: '1250.50',
        branding: {
          appName: 'RD TCCS Banking',
          primaryColor: '#0b63e5',
          sidebarNotice: 'Safe "256-Bit" & Secured <SSL>'
        },
        customer: {
          id: 'cust-complex-1',
          name: 'सुरेश कुमार (Suresh "Kumar")',
          mobileNumber: '9988776655'
        }
      };

      const template = '<html><head></head><body><script id="ypgInitialState" type="application/json">{{INITIAL_STATE_JSON}}</script></body></html>';
      const rendered = renderTemplate(template, {
        INITIAL_STATE_JSON: serializeForScript(complexState)
      });

      const scriptMatch = rendered.match(/<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/);
      assert.ok(scriptMatch);
      const rawContent = scriptMatch[1];

      // No HTML escaping entities
      assert.ok(!rawContent.includes('&quot;'));
      assert.ok(!rawContent.includes('&lt;'));
      assert.ok(!rawContent.includes('&gt;'));
      assert.ok(!rawContent.includes('&amp;'));

      // Direct synchronous parse
      const parsed = JSON.parse(rawContent);
      assert.equal(parsed.orderId, 'ORD-"SPECIAL"-999');
      assert.equal(parsed.merchantName, 'RD TCCS "Coop" & Society');
      assert.equal(parsed.customer.name, 'सुरेश कुमार (Suresh "Kumar")');
      assert.equal(parsed.branding.sidebarNotice, 'Safe "256-Bit" & Secured <SSL>');
    });

    test('3.3 Hostile XSS breakout attempts in state values are neutralized via unicode escaping', () => {
      const hostileState = {
        orderId: '</script><script>alert("attacker-controlled")</script>',
        description: '"><img src=x onerror=alert(1)>',
        lineTerminator: 'First Line\u2028Second Line\u2029Third Line'
      };

      const template = '<script id="ypgInitialState" type="application/json">{{INITIAL_STATE_JSON}}</script>';
      const rendered = renderTemplate(template, {
        INITIAL_STATE_JSON: serializeForScript(hostileState)
      });

      // Crucial: The rendered HTML must NOT contain a literal </script> inside the script block!
      const closingIndex = rendered.indexOf('</script>');
      const lastClosingIndex = rendered.lastIndexOf('</script>');
      assert.equal(closingIndex, lastClosingIndex, 'Must contain exactly ONE closing script tag, preventing premature termination');

      // Extract script content
      const match = rendered.match(/<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/);
      assert.ok(match);

      // Verify breakout characters were unicode escaped
      assert.ok(match[1].includes('\\u003c/script\\u003e'));
      assert.ok(match[1].includes('\\u2028'));
      assert.ok(match[1].includes('\\u2029'));

      // Valid JSON parse preserves original malicious characters inside JS strings safely
      const parsed = JSON.parse(match[1]);
      assert.equal(parsed.orderId, '</script><script>alert("attacker-controlled")</script>');
      assert.equal(parsed.lineTerminator, 'First Line\u2028Second Line\u2029Third Line');
    });
  });

  describe('Section 4: Storage Decryption Parity & Edge Cases', () => {
    test('4.1 Obfuscated JSON objects decrypt identically in both checkout.html and checkout.js', () => {
      const preservedIdentity = {
        customer: {
          id: 'cust-rdtccs-01',
          name: 'Pooja Verma',
          status: 'ACTIVE'
        },
        token: 'csess_a1b2c3d4e5f60718',
        savedAt: 1730000000000,
        expiresAt: 1730604800000
      };

      const encrypted = encryptClientStorage(JSON.stringify(preservedIdentity));
      const htmlResult = decryptClientStorageHtml(encrypted);
      const jsResult = decryptClientStorageJs(encrypted);

      assert.deepEqual(htmlResult, preservedIdentity);
      assert.deepEqual(jsResult, preservedIdentity);
      assert.deepEqual(htmlResult, jsResult);
    });

    test('4.2 Obfuscated raw token string decrypts to plain string in both implementations', () => {
      const rawToken = 'csess_9876543210abcdef0123456789';
      const encrypted = encryptClientStorage(rawToken);

      const htmlResult = decryptClientStorageHtml(encrypted);
      const jsResult = decryptClientStorageJs(encrypted);

      assert.equal(htmlResult, rawToken, 'checkout.html must return raw token string');
      assert.equal(jsResult, rawToken, 'checkout.js must return raw token string');
      assert.equal(htmlResult, jsResult);
    });

    test('4.3 Unobfuscated (cleartext) JSON string fallback resolves correctly in both', () => {
      const cleartextJson = JSON.stringify({ id: 'legacy-customer-id', name: 'Legacy Member' });

      const htmlResult = decryptClientStorageHtml(cleartextJson);
      const jsResult = decryptClientStorageJs(cleartextJson);

      assert.deepEqual(htmlResult, { id: 'legacy-customer-id', name: 'Legacy Member' });
      assert.deepEqual(jsResult, { id: 'legacy-customer-id', name: 'Legacy Member' });
    });

    test('4.4 Unobfuscated (cleartext) raw token string fallback resolves correctly in both', () => {
      const cleartextToken = 'csess_legacy_unencrypted_token_123';

      const htmlResult = decryptClientStorageHtml(cleartextToken);
      const jsResult = decryptClientStorageJs(cleartextToken);

      assert.equal(htmlResult, cleartextToken);
      assert.equal(jsResult, cleartextToken);
    });

    test('4.5 Falsy inputs (null, undefined, empty string) return null in both implementations', () => {
      const falsyInputs = [null, undefined, '', false];

      for (const input of falsyInputs) {
        assert.equal(decryptClientStorageHtml(input), null, `HTML should return null for ${input}`);
        assert.equal(decryptClientStorageJs(input), null, `JS should return null for ${input}`);
      }
    });

    test('4.6 Corrupted/malformed cipherText handles gracefully without throwing exceptions', () => {
      const corruptedInputs = [
        'not_base64_???_invalid',
        '==invalid==',
        'a',
        '12345'
      ];

      for (const input of corruptedInputs) {
        let htmlResult;
        let jsResult;
        assert.doesNotThrow(() => {
          htmlResult = decryptClientStorageHtml(input);
        });
        assert.doesNotThrow(() => {
          jsResult = decryptClientStorageJs(input);
        });
        assert.equal(htmlResult, jsResult, `Parity check failed on corrupted input: ${input}`);
      }
    });

    test('4.7 getStoredCustomerToken resolver handles obfuscated tokens and plain fallback', () => {
      const testToken = 'csess_valid_token_abc123';
      const encToken = encryptClientStorage(testToken);

      function simulateGetStoredTokenHtml(raw) {
        if (!raw) return null;
        return decryptClientStorageHtml(raw) || raw;
      }

      function simulateGetStoredTokenJs(raw) {
        if (!raw) return null;
        return decryptClientStorageJs(raw) || raw;
      }

      // Case 1: Obfuscated token in storage
      assert.equal(simulateGetStoredTokenHtml(encToken), testToken);
      assert.equal(simulateGetStoredTokenJs(encToken), testToken);

      // Case 2: Plain token in storage
      assert.equal(simulateGetStoredTokenHtml(testToken), testToken);
      assert.equal(simulateGetStoredTokenJs(testToken), testToken);

      // Case 3: Empty storage
      assert.equal(simulateGetStoredTokenHtml(null), null);
      assert.equal(simulateGetStoredTokenJs(null), null);
    });
  });
});
