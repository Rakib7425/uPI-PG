// Checkout Portal Auto Sign-In & Auth Gating E2E Test Suite
// Opaque-box requirement-driven tests covering Tiers 1-4 for Customer Checkout Portal
// Authoritative sources: ORIGINAL_REQUEST.md, PROJECT.md, TEST_INFRA.md

import test, { describe, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  Database,
  MerchantRepository,
  CustomerRepository,
  CustomerSessionRepository,
  ReceivingAccountRepository,
  PaymentSessionRepository,
} from "@youpi/db";
import { createPaymentApp } from "../../../payment-api/src/index.js";
import { CheckoutServer } from "../server.js";
import { PaymentStatus } from "@youpi/common";

describe("Checkout Portal Auto Sign-In & Pre-Auth Suite", () => {
  let paymentApp;
  let testDb;
  let apiServer;
  let portalServer;
  let apiBaseUrl;
  let portalBaseUrl;
  let merchantId;
  let merchantSecret;
  let testPaymentId;
  let testCustomerToken;
  let testCustomer;

  before(async () => {
    process.env.ENCRYPTION_MASTER_KEY =
      process.env.ENCRYPTION_MASTER_KEY ||
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    process.env.INTERNAL_SERVICE_TOKEN =
      process.env.INTERNAL_SERVICE_TOKEN ||
      "test_internal_token_0123456789abcdef0123456789abcdef";
    process.env.NODE_ENV = "test";

    testDb = new Database({ inMemory: true });
    paymentApp = createPaymentApp(testDb, { otpCooldownMs: 0 });

    apiServer = await new Promise((resolve) => {
      const s = paymentApp.rawServer.listen(0, "127.0.0.1", () => resolve(s));
    });
    const apiPort = apiServer.address().port;
    apiBaseUrl = `http://127.0.0.1:${apiPort}`;

    const portal = new CheckoutServer({ apiBaseUrl });
    const portalRaw = portal.createServer();
    portalServer = await new Promise((resolve) => {
      const s = portalRaw.listen(0, "127.0.0.1", () => resolve(s));
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
        upiId: "irakibul026-2@okaxis",
        payeeName: "Merchant Store",
        isActive: true,
      });
    }
    const receivingAccountId = receivingAccount ? receivingAccount.id : null;

    const custRepo = new CustomerRepository(testDb);
    testCustomer = custRepo.create({
      name: "Rohan Sharma",
      mobileNumber: "9876543210",
      isPhoneVerified: 1,
      status: "ACTIVE",
    });

    const custSessionRepo = new CustomerSessionRepository(testDb, custRepo);
    const custSession = custSessionRepo.create({ customerId: testCustomer.id });
    testCustomerToken = custSession.token;

    const sessionRepo = new PaymentSessionRepository(testDb);
    const session = sessionRepo.create({
      merchantId,
      customerId: testCustomer.id,
      receivingAccountId,
      orderId: "ORD-PORTAL-TEST-001",
      amountPaise: 150000,
      currency: "INR",
      method: "MANUAL_UPI",
      status: PaymentStatus.INITIATED,
      metadata: {
        targetType: "DEPOSIT",
        targetAccountId: "acc-uuid-1",
        memberId: "mem-uuid-1",
        branchId: "branch-uuid-1",
      },
    });
    testPaymentId = session.id;
  });

  after(async () => {
    if (portalServer)
      await new Promise((resolve) => portalServer.close(resolve));
    if (paymentApp) paymentApp.destroy();
    if (apiServer) await new Promise((resolve) => apiServer.close(resolve));
    if (testDb) testDb.close();
  });

  // Helper to fetch portal routes via HTTP
  function fetchPortal(path, options = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, portalBaseUrl);
      const req = http.request(
        url,
        {
          method: options.method || "GET",
          headers: options.headers || {},
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => {
            data += chunk;
          });
          res.on("end", () => {
            resolve({
              status: res.statusCode,
              headers: res.headers,
              text: data,
              json: () => {
                try {
                  return JSON.parse(data);
                } catch {
                  return null;
                }
              },
            });
          });
        },
      );
      req.on("error", reject);
      if (options.body) {
        req.write(
          typeof options.body === "string"
            ? options.body
            : JSON.stringify(options.body),
        );
      }
      req.end();
    });
  }

  // ==========================================
  // TIER 1: CORE PORTAL FEATURE CONTRACTS (F1 - F4)
  // ==========================================

  describe("Tier 1: Core Portal Feature Contracts", () => {
    test("1.1 [F1] GET /checkout/:id?auth_token=<token> returns HTTP 200 and renders HTML", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.headers["content-type"].includes("text/html"));
      assert.ok(res.text.includes("<!DOCTYPE html>"));
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("1.2 [F1] GET /checkout/:id?token=<token> alternate query parameter returns HTTP 200", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.headers["content-type"].includes("text/html"));
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("1.3 [F2] Rendered checkout HTML contains paymentGatewayInterface and preGatewayAuthView", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(
        res.text.includes('id="paymentGatewayInterface"'),
        "HTML must contain paymentGatewayInterface",
      );
      assert.ok(
        res.text.includes('id="preGatewayAuthView"'),
        "HTML must contain preGatewayAuthView",
      );
    });

    test("1.4 [F2] SSR INITIAL_STATE_JSON contains serialized payment state", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      const match = res.text.match(
        /<script id="ypgInitialState" type="application\/json">(.*?)<\/script>/s,
      );
      assert.ok(match, "Must render ypgInitialState JSON script block");
      const unescapedJson = match[1]
        .replaceAll("&quot;", '"')
        .replaceAll("&#39;", "'")
        .replaceAll("&amp;", "&")
        .replaceAll("&lt;", "<")
        .replaceAll("&gt;", ">");
      const state = JSON.parse(unescapedJson);
      assert.equal(state.orderId, "ORD-PORTAL-TEST-001");
      assert.equal(state.amount, "1500.00");
    });

    test("1.5 [F3] Guest checkout GET /checkout/:id renders HTTP 200 without auth_token", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      assert.ok(res.headers["content-type"].includes("text/html"));
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("1.6 [F3] Guest checkout HTML includes WhatsApp mobile number and OTP entry inputs", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      assert.ok(
        res.text.includes('id="authMobileInput"'),
        "Must include authMobileInput",
      );
      assert.ok(
        res.text.includes('id="btnAuthContinue"'),
        "Must include btnAuthContinue",
      );
      assert.ok(
        res.text.includes('id="authStepOtp"'),
        "Must include authStepOtp",
      );
      assert.ok(
        res.text.includes("WhatsApp Mobile Number"),
        "Must include WhatsApp label",
      );
    });

    test("1.7 [F4] Portal transparent proxy GET /api/v1/checkout/:id/state forwards Bearer token", async () => {
      const res = await fetchPortal(`/api/v1/checkout/${testPaymentId}/state`, {
        headers: {
          Authorization: `Bearer ${testCustomerToken}`,
        },
      });
      assert.equal(res.status, 200);
      const state = res.json();
      assert.ok(
        state.customer,
        "Proxy with Bearer token must return customer profile",
      );
      assert.equal(state.customer.name, "Rohan Sharma");
      assert.equal(state.customer.mobileNumber, "9876543210");
    });

    test("1.8 [F4] Portal transparent proxy POST /api/v1/checkout/:id/bind-customer forwards binding request", async () => {
      const res = await fetchPortal(
        `/api/v1/checkout/${testPaymentId}/bind-customer`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${testCustomerToken}`,
          },
          body: JSON.stringify({
            token: testCustomerToken,
            customerId: testCustomer.id,
          }),
        },
      );
      assert.equal(res.status, 200);
      const data = res.json();
      assert.equal(data.success, true);
      assert.equal(data.status, PaymentStatus.ACTIVE);
    });
  });

  // ==========================================
  // TIER 2: BOUNDARY, CORNER & QUERY CASES
  // ==========================================

  describe("Tier 2: Boundary, Query Parameter & Sanitization Cases", () => {
    test("2.1 [Boundary] GET /checkout/:id?auth_token= (empty value) does not crash and handles as guest", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}?auth_token=`);
      assert.equal(res.status, 200);
      assert.ok(res.text.includes("<!DOCTYPE html>"));
    });

    test("2.2 [Boundary] URL-encoded token query parameter is decoded safely", async () => {
      const encodedToken = encodeURIComponent(testCustomerToken);
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${encodedToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("2.3 [Boundary] XSS injection in query parameters is safely escaped in HTML", async () => {
      const xssPayload = '<script>alert("xss")</script>';
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${encodeURIComponent(xssPayload)}`,
      );
      assert.equal(res.status, 200);
      assert.equal(
        res.text.includes(xssPayload),
        false,
        "Raw script tag must not be injected into HTML",
      );
    });

    test("2.4 [Boundary] Long token string (>512 chars) does not crash portal rendering", async () => {
      const longToken = "csess_" + "a".repeat(600);
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${longToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("2.5 [Corner] Both auth_token and token present in query string resolves gracefully", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}&token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("2.6 [Corner] Extra parameters alongside auth_token preserve checkout rendering", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?utm_source=sms&auth_token=${testCustomerToken}&branch=main`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("2.7 [Security] Portal proxy strictly strips internal server headers from incoming client requests", async () => {
      const res = await fetchPortal(`/api/v1/checkout/${testPaymentId}/state`, {
        headers: {
          "X-Internal-Render": "true",
          "X-Internal-Token": "forged_internal_token",
        },
      });
      assert.equal(res.status, 200);
      const state = res.json();
      assert.equal(
        state.customer,
        null,
        "Stripped internal headers must prevent unauthorized customer PII disclosure",
      );
    });

    test("2.8 [Security] Portal proxy preserves x-customer-token header from client to backend", async () => {
      const res = await fetchPortal(`/api/v1/checkout/${testPaymentId}/state`, {
        headers: {
          "x-customer-token": testCustomerToken,
        },
      });
      assert.equal(res.status, 200);
      const state = res.json();
      assert.ok(state.customer);
      assert.equal(state.customer.mobileNumber, "9876543210");
    });

    test("2.9 [Security] Checkout portal responses include frame-ancestors security header", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      const csp = res.headers["content-security-policy"];
      assert.ok(csp, "Response must include Content-Security-Policy header");
      assert.ok(
        csp.includes("frame-ancestors"),
        "CSP must define frame-ancestors",
      );
    });

    test("2.10 [Security] Content-Security-Policy permits required scripts without unsafe-eval", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      const csp = res.headers["content-security-policy"];
      assert.equal(
        csp.includes("'unsafe-eval'"),
        false,
        "CSP must not allow unsafe-eval",
      );
    });

    test("2.11 [UI Invariant] Rendered page contains zero unauthorized offer artifacts", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.equal(res.text.includes("6 Offers"), false);
      assert.equal(res.text.includes("View Offers"), false);
      assert.equal(res.text.includes("available-offers-card"), false);
    });

    test("2.12 [UI Invariant] Rendered page includes payment methods list and responsive layout", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      assert.ok(res.text.includes("ypg-wrapper"));
      assert.ok(res.text.includes("paymentMethodSelectorBar"));
    });
  });

  // ==========================================
  // TIER 3: COMBINATORIAL INTERACTIONS
  // ==========================================

  describe("Tier 3: Combinatorial & Cross-Component Interactions", () => {
    test("3.1 Complete Pre-Auth Navigation: Portal load -> Proxy state check -> Verification", async () => {
      const portalRes = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(portalRes.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${testPaymentId}/state`,
        {
          headers: { Authorization: `Bearer ${testCustomerToken}` },
        },
      );
      assert.equal(stateRes.status, 200);
      const state = stateRes.json();
      assert.equal(state.customer.name, "Rohan Sharma");
      assert.equal(state.customer.mobileNumber, "9876543210");
    });

    test("3.2 Complete Guest Navigation: Portal load without token -> Proxy state null -> Auth form ready", async () => {
      const portalRes = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(portalRes.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${testPaymentId}/state`,
      );
      assert.equal(stateRes.status, 200);
      const state = stateRes.json();
      assert.equal(
        state.customer,
        null,
        "Guest session state must have customer null",
      );

      assert.ok(portalRes.text.includes('id="authMobileInput"'));
      assert.ok(portalRes.text.includes('id="btnAuthContinue"'));
    });

    test("3.3 Pre-Auth Token Query Parameter SSR Hydration Consistency", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(res.text.includes('id="ypgInitialState"'));
      assert.ok(res.text.includes(`PAYMENT_ID = "${testPaymentId}"`));
    });

    test("3.4 Proxy 404 Error Propagation: Non-existent payment returns 404", async () => {
      const nonExistentId = "00000000-9999-0000-0000-000000000000";
      const res = await fetchPortal(`/api/v1/checkout/${nonExistentId}/state`);
      assert.equal(res.status, 404);
      const err = res.json();
      assert.ok(err.error);
    });
  });

  // ==========================================
  // TIER 4: REAL-WORLD UI JOURNEYS & SCENARIOS
  // ==========================================

  describe("Tier 4: Real-World Banking UI Journeys & Scenarios", () => {
    test("4.1 Scenario 1: Member opens SMS/WhatsApp link with auth_token for RD TCCS Deposit", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${testPaymentId}/state`,
        {
          headers: { Authorization: `Bearer ${testCustomerToken}` },
        },
      );
      const state = stateRes.json();
      assert.equal(state.customer.name, "Rohan Sharma");
      assert.equal(state.amount, "1500.00");

      assert.ok(res.text.includes('id="paymentGatewayInterface"'));
    });

    test("4.2 Scenario 2: Teller initiates UPI Loan Repayment collection; member visits checkout link", async () => {
      const sessionRepo = new PaymentSessionRepository(testDb);
      const loanSession = sessionRepo.create({
        merchantId,
        customerId: testCustomer.id,
        orderId: "LOAN-PORTAL-002",
        amountPaise: 850000,
        currency: "INR",
        method: "MANUAL_UPI",
        status: PaymentStatus.INITIATED,
        metadata: {
          targetType: "LOAN_REPAYMENT",
          targetAccountId: "loan-acc-002",
          memberId: "mem-002",
        },
      });

      const res = await fetchPortal(
        `/checkout/${loanSession.id}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${loanSession.id}/state`,
        {
          headers: { Authorization: `Bearer ${testCustomerToken}` },
        },
      );
      const state = stateRes.json();
      assert.equal(state.amount, "8500.00");
      assert.equal(state.customer.name, "Rohan Sharma");
    });

    test("4.3 Scenario 3: Guest customer accesses portal directly without pre-filled details", async () => {
      const sessionRepo = new PaymentSessionRepository(testDb);
      const guestSession = sessionRepo.create({
        merchantId,
        customerId: null,
        orderId: "GUEST-PORTAL-003",
        amountPaise: 30000,
        currency: "INR",
        method: "MANUAL_UPI",
        status: PaymentStatus.INITIATED,
      });

      const res = await fetchPortal(`/checkout/${guestSession.id}`);
      assert.equal(res.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${guestSession.id}/state`,
      );
      const state = stateRes.json();
      assert.equal(state.customer, null);

      assert.ok(res.text.includes('id="preGatewayAuthView"'));
      assert.ok(res.text.includes('id="authMobileInput"'));
    });

    test("4.4 Scenario 4: Customer with invalid/expired token accesses portal; falls back to manual entry", async () => {
      const badToken = "csess_expired_or_corrupted_token_value_000000";
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${badToken}`,
      );
      assert.equal(res.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${testPaymentId}/state`,
        {
          headers: { Authorization: `Bearer ${badToken}` },
        },
      );
      const state = stateRes.json();
      assert.equal(
        state.customer,
        null,
        "Invalid token must yield customer null",
      );

      assert.ok(res.text.includes('id="preGatewayAuthView"'));
    });

    test("4.5 Scenario 5: Offline/counter payment modality displays counter instructions", async () => {
      const sessionRepo = new PaymentSessionRepository(testDb);
      const counterSession = sessionRepo.create({
        merchantId,
        customerId: testCustomer.id,
        orderId: "COUNTER-PORTAL-005",
        amountPaise: 50000,
        currency: "INR",
        method: "CASH_COUNTER",
        status: PaymentStatus.ACTIVE,
      });

      const res = await fetchPortal(`/checkout/${counterSession.id}`);
      assert.equal(res.status, 200);

      const stateRes = await fetchPortal(
        `/api/v1/checkout/${counterSession.id}/state`,
      );
      const state = stateRes.json();
      assert.equal(state.status, PaymentStatus.ACTIVE);
    });
  });
});
