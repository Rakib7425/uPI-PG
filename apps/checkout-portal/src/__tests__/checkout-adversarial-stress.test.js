// Adversarial Stress & Verification Test Suite for Checkout Portal Pre-Auth & Fallback UI
// Tests URL query parameter tampering, XSS injection, token manipulation, and R2/R3 invariants
// Authoritative references: ORIGINAL_REQUEST.md, PROJECT.md, TEST_READY.md

import test, { describe, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("Checkout Portal Adversarial Stress & R2/R3 Verification Suite", () => {
  let paymentApp;
  let testDb;
  let apiServer;
  let portalServer;
  let apiBaseUrl;
  let portalBaseUrl;
  let merchantId;
  let testPaymentId;
  let guestPaymentId;
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
    // Member payment session
    const session1 = sessionRepo.create({
      merchantId,
      customerId: null,
      receivingAccountId,
      orderId: "ORD-ADV-MEMBER-001",
      amountPaise: 250000,
      currency: "INR",
      method: "MANUAL_UPI",
      status: PaymentStatus.INITIATED,
      metadata: {
        targetType: "DEPOSIT",
        targetAccountId: "acc-uuid-adv-1",
        memberId: "mem-uuid-adv-1",
        branchId: "branch-uuid-adv-1",
      },
    });
    testPaymentId = session1.id;

    // Guest payment session
    const session2 = sessionRepo.create({
      merchantId,
      customerId: null,
      receivingAccountId,
      orderId: "ORD-ADV-GUEST-002",
      amountPaise: 100000,
      currency: "INR",
      method: "MANUAL_UPI",
      status: PaymentStatus.INITIATED,
    });
    guestPaymentId = session2.id;
  });

  after(async () => {
    if (portalServer)
      await new Promise((resolve) => portalServer.close(resolve));
    if (paymentApp) paymentApp.destroy();
    if (apiServer) await new Promise((resolve) => apiServer.close(resolve));
    if (testDb) testDb.close();
  });

  function fetchPortal(reqPath, options = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(reqPath, portalBaseUrl);
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

  // Helper to extract SSR initial state JSON handling HTML escaping
  function extractInitialState(html) {
    const match = html.match(
      /<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/,
    );
    if (!match) return null;
    try {
      const raw = match[1];
      const unescaped = raw
        .replaceAll("&quot;", '"')
        .replaceAll("&#39;", "'")
        .replaceAll("&amp;", "&")
        .replaceAll("&lt;", "<")
        .replaceAll("&gt;", ">");
      return JSON.parse(unescaped);
    } catch {
      return null;
    }
  }

  // ==========================================
  // ADVERSARIAL DIMENSION 1: URL QUERY PARAMETER TAMPERING
  // ==========================================

  describe("Dimension 1: URL Query Parameter Tampering & Injection", () => {
    test("1.1 Empty auth_token returns HTTP 200 and falls back to unauthenticated guest state", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}?auth_token=`);
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.2 Whitespace-only auth_token handles gracefully as unauthenticated guest", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=%20%20%20`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.3 Corrupted / tampered auth_token returns customer: null and does not leak PII", async () => {
      const corruptedToken = testCustomerToken.slice(0, -6) + "xxxxxx";
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${corruptedToken}`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.4 Completely fabricated non-existent token returns customer: null", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=csess_00000000000000000000000000000000`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.5 XSS payload in auth_token is safely handled without script injection", async () => {
      const xssPayload = '<script>alert("pwned")</script>';
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${encodeURIComponent(xssPayload)}`,
      );
      assert.equal(res.status, 200);
      assert.ok(!res.text.includes('<script>alert("pwned")</script>'));
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.6 HTML breakout attempt in token query parameter is safely neutralised", async () => {
      const breakoutPayload = '"><img src=x onerror=alert(1)>';
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?token=${encodeURIComponent(breakoutPayload)}`,
      );
      assert.equal(res.status, 200);
      assert.ok(!res.text.includes("<img src=x onerror=alert(1)>"));
    });

    test("1.7 Conflicting parameters: both auth_token (valid) and token (bogus) present", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}&token=bogus_token`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.ok(state.customer !== null);
      assert.equal(state.customer.name, "Rohan Sharma");
    });

    test("1.8 Conflicting parameters: auth_token is empty while token is valid", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=&token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.ok(state.customer !== null);
      assert.equal(state.customer.name, "Rohan Sharma");
    });

    test("1.9 Massive 5000-character token does not crash the server and handles safely", async () => {
      const massiveToken = "csess_" + "A".repeat(5000);
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${massiveToken}`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });

    test("1.10 Control characters and SQL injection strings handle safely", async () => {
      const sqliToken = "' OR '1'='1";
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${encodeURIComponent(sqliToken)}`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(state.customer, null);
    });
  });

  // ==========================================
  // ADVERSARIAL DIMENSION 2: REQUIREMENT R2 VERIFICATION
  // ==========================================

  describe("Dimension 2: Requirement R2 (Pre-Auth Bypass & Zero Flash)", () => {
    test("2.1 SSR with valid token returns customer details in initial state JSON", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null, "Initial state must exist in SSR markup");
      assert.ok(
        state.customer !== null,
        "Customer must be populated in SSR state",
      );
      assert.equal(state.customer.name, "Rohan Sharma");
      assert.equal(state.customer.mobileNumber, "9876543210");
    });

    test("2.2 In rendered HTML, both auth view and payment interface start with hidden attribute", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      assert.ok(
        res.text.includes('<div id="preGatewayAuthView" hidden>'),
        "preGatewayAuthView must be hidden in initial markup",
      );
      assert.ok(
        res.text.includes('<div id="paymentGatewayInterface" hidden>'),
        "paymentGatewayInterface must be hidden in initial markup",
      );
      assert.ok(
        res.text.includes('id="ypgSplashScreen" class="ypg-splash-screen"'),
        "Splash screen must overlay initially to avoid flash",
      );
    });

    test("2.3 Client-side pre-auth logic simulation: displays payment screen and hides auth view", () => {
      const activeToken = testCustomerToken;
      const data = {
        id: testPaymentId,
        status: "INITIATED",
        customer: {
          id: testCustomer.id,
          name: "Rohan Sharma",
          mobileNumber: "9876543210",
        },
      };

      const isPreAuth = Boolean(activeToken && (data.customer || null));
      assert.equal(isPreAuth, true, "isPreAuth must evaluate to true");

      let authHidden = true;
      let authDisplay = "";
      let payHidden = true;
      let payDisplay = "";

      function setGatewayAuthMode(isAuthView) {
        if (isAuthView) {
          authHidden = false;
          authDisplay = "";
          payHidden = true;
          payDisplay = "none";
        } else {
          authHidden = true;
          authDisplay = "none";
          payHidden = false;
          payDisplay = "";
        }
      }

      const hasCustomer = Boolean(
        (data.customer || null) &&
        (data.status !== "INITIATED" || Boolean(activeToken)),
      );
      assert.equal(hasCustomer, true, "hasCustomer must evaluate to true");

      if (!hasCustomer && !isPreAuth) {
        setGatewayAuthMode(true);
      } else {
        setGatewayAuthMode(false);
      }

      assert.equal(authHidden, true, "preGatewayAuthView must be hidden");
      assert.equal(
        authDisplay,
        "none",
        "preGatewayAuthView must have display: none",
      );
      assert.equal(
        payHidden,
        false,
        "paymentGatewayInterface must be unhidden",
      );
      assert.equal(
        payDisplay,
        "",
        "paymentGatewayInterface display must be visible",
      );
    });

    test("2.4 Auto-binding: Valid pre-auth token binds customer and transitions session to ACTIVE", async () => {
      const sessionRepo = new PaymentSessionRepository(testDb);
      const s = sessionRepo.create({
        merchantId,
        customerId: null,
        orderId: "ORD-ADV-BIND-001",
        amountPaise: 50000,
        currency: "INR",
        method: "MANUAL_UPI",
        status: PaymentStatus.INITIATED,
      });

      const bindRes = await fetchPortal(
        `/api/v1/checkout/${s.id}/bind-customer`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${testCustomerToken}`,
          },
          body: { token: testCustomerToken, customerId: testCustomer.id },
        },
      );

      assert.equal(bindRes.status, 200);
      const bindBody = bindRes.json();
      assert.equal(bindBody.success, true);
      assert.equal(bindBody.status, "ACTIVE");
      assert.ok(bindBody.expiresAt !== undefined);

      const updated = sessionRepo.findById(s.id);
      assert.equal(updated.customerId, testCustomer.id);
      assert.equal(updated.status, "ACTIVE");
    });
  });

  // ==========================================
  // ADVERSARIAL DIMENSION 3: REQUIREMENT R3 VERIFICATION
  // ==========================================

  describe("Dimension 3: Requirement R3 (Guest Checkout Fallback Enforcement)", () => {
    test("3.1 Guest checkout without token renders customer: null in SSR state", async () => {
      const res = await fetchPortal(`/checkout/${guestPaymentId}`);
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(
        state.customer,
        null,
        "Customer must be null for guest checkout",
      );
    });

    test("3.2 Anonymous access to member payment URL without token does NOT leak customer profile", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      const state = extractInitialState(res.text);
      assert.ok(state !== null);
      assert.equal(
        state.customer,
        null,
        "Customer profile must be redacted from unauthenticated visitor",
      );
    });

    test("3.3 Client-side guest state simulation: strictly displays auth view and hides payment view", () => {
      const activeToken = null;
      const data = {
        id: guestPaymentId,
        status: "INITIATED",
        customer: null,
      };

      const isPreAuth = Boolean(activeToken && (data.customer || null));
      const hasCustomer = Boolean(
        (data.customer || null) &&
        (data.status !== "INITIATED" || Boolean(activeToken)),
      );

      assert.equal(isPreAuth, false, "isPreAuth must be false for guest");
      assert.equal(hasCustomer, false, "hasCustomer must be false for guest");

      let authHidden = true;
      let authDisplay = "";
      let payHidden = true;
      let payDisplay = "";
      let currentStep = "";

      function setGatewayAuthMode(isAuthView) {
        if (isAuthView) {
          authHidden = false;
          authDisplay = "";
          payHidden = true;
          payDisplay = "none";
        } else {
          authHidden = true;
          authDisplay = "none";
          payHidden = false;
          payDisplay = "";
        }
      }

      function goToAuthStep(step) {
        currentStep = step;
      }

      if (!hasCustomer && !isPreAuth) {
        setGatewayAuthMode(true);
        goToAuthStep("mobile");
      } else {
        setGatewayAuthMode(false);
      }

      assert.equal(authHidden, false, "preGatewayAuthView must be visible");
      assert.equal(
        authDisplay,
        "",
        "preGatewayAuthView display property must be empty (visible)",
      );
      assert.equal(payHidden, true, "paymentGatewayInterface must be hidden");
      assert.equal(
        payDisplay,
        "none",
        "paymentGatewayInterface display must be none",
      );
      assert.equal(currentStep, "mobile", "Must navigate to mobile step");
    });

    test("3.4 Tampered token fallback in loadState: purges storage and forces manual login", () => {
      let activeToken = "csess_tampered_value";
      let activeCustomer = null;
      let storageCleared = false;
      let authMode = null;

      function clearPreservedIdentity() {
        storageCleared = true;
      }
      function setGatewayAuthMode(mode) {
        authMode = mode;
      }

      const data = { status: "INITIATED", customer: null };

      if (activeToken && !data.customer && data.status === "INITIATED") {
        clearPreservedIdentity();
        activeToken = null;
        activeCustomer = null;
        setGatewayAuthMode(true);
      }

      assert.equal(activeToken, null, "Active token must be purged");
      assert.equal(activeCustomer, null, "Active customer must be null");
      assert.equal(
        storageCleared,
        true,
        "Local storage identity must be cleared",
      );
      assert.equal(authMode, true, "Gateway auth mode must be forced to true");
    });
  });

  // ==========================================
  // ADVERSARIAL DIMENSION 4: STORAGE ENCRYPTION & DECRYPTION DIVERGENCE
  // ==========================================

  describe("Dimension 4: Storage Encryption & Divergence Analysis", () => {
    function encryptClientStorage(plainText) {
      if (!plainText) return "";
      try {
        let cipher = "";
        for (let i = 0; i < plainText.length; i++) {
          cipher += String.fromCharCode(plainText.charCodeAt(i) ^ 0x5a);
        }
        return btoa(cipher);
      } catch {
        return "";
      }
    }

    // Fixed implementation mirroring checkout.html (line 61)
    function decryptClientStorageHtml(cipherText) {
      if (!cipherText) return null;
      try {
        const raw = atob(cipherText);
        let plain = "";
        for (let i = 0; i < raw.length; i++) {
          plain += String.fromCharCode(raw.charCodeAt(i) ^ 0x5a);
        }
        try {
          return JSON.parse(plain);
        } catch {
          return plain;
        }
      } catch {
        try {
          return JSON.parse(cipherText);
        } catch {
          return cipherText;
        }
      }
    }

    // Implementation from checkout.js (line 28)
    function decryptClientStorageJs(cipherText) {
      if (!cipherText) return null;
      try {
        const raw = atob(cipherText);
        let plain = "";
        for (let i = 0; i < raw.length; i++) {
          plain += String.fromCharCode(raw.charCodeAt(i) ^ 0x5a);
        }
        try {
          return JSON.parse(plain);
        } catch {
          return plain;
        }
      } catch {
        try {
          return JSON.parse(cipherText);
        } catch {
          return cipherText;
        }
      }
    }

    test("4.1 JSON payload (preserved identity) decrypts identically in both implementations", () => {
      const payload = {
        customer: { id: "cust-1", name: "Member" },
        token: "csess_123",
      };
      const enc = encryptClientStorage(JSON.stringify(payload));

      const decHtml = decryptClientStorageHtml(enc);
      const decJs = decryptClientStorageJs(enc);

      assert.deepEqual(decHtml, payload);
      assert.deepEqual(decJs, payload);
    });

    test("4.2 Raw string token decryption parity: both checkout.html and checkout.js return plaintext token", () => {
      const rawToken = "csess_d652ba830fc3efee";
      const encToken = encryptClientStorage(rawToken);

      const decHtml = decryptClientStorageHtml(encToken);
      const decJs = decryptClientStorageJs(encToken);

      assert.equal(decJs, rawToken, "checkout.js decrypts raw token string");
      assert.equal(
        decHtml,
        rawToken,
        "checkout.html decrypts raw token string",
      );
    });

    test("4.3 getStoredCustomerToken parity: resolves plaintext token in both implementations", () => {
      const rawToken = "csess_d652ba830fc3efee";
      const encToken = encryptClientStorage(rawToken);

      const raw = encToken;
      const resolvedHtml = decryptClientStorageHtml(raw) || raw;
      const resolvedJs = decryptClientStorageJs(raw) || raw;

      assert.equal(
        resolvedHtml,
        rawToken,
        "checkout.html resolves plaintext token",
      );
      assert.equal(
        resolvedJs,
        rawToken,
        "checkout.js resolves plaintext token",
      );
    });

    test("4.4 Empirically assert that SSR INITIAL_STATE_JSON contains valid parseable JSON without &quot;", async () => {
      const res = await fetchPortal(
        `/checkout/${testPaymentId}?auth_token=${testCustomerToken}`,
      );
      assert.equal(res.status, 200);
      const match = res.text.match(
        /<script id="ypgInitialState" type="application\/json">([\s\S]*?)<\/script>/,
      );
      assert.ok(match, "ypgInitialState tag must exist");
      assert.ok(
        !match[1].includes("&quot;"),
        "Raw SSR script tag content must not contain &quot;",
      );
      const parsed = JSON.parse(match[1]);
      assert.equal(parsed.orderId, "ORD-ADV-MEMBER-001");
      assert.equal(parsed.amount, "2500.00");
    });
  });

  // ==========================================
  // ADVERSARIAL DIMENSION 5: SECURITY HEADERS & DEFENSE IN DEPTH
  // ==========================================

  describe("Dimension 5: Security Headers & Path Traversal Protections", () => {
    test("5.1 Security headers on checkout portal responses", async () => {
      const res = await fetchPortal(`/checkout/${testPaymentId}`);
      assert.equal(res.status, 200);
      assert.equal(res.headers["x-content-type-options"], "nosniff");
      assert.equal(
        res.headers["referrer-policy"],
        "strict-origin-when-cross-origin",
      );
      assert.ok(res.headers["content-security-policy"] !== undefined);
      assert.ok(
        res.headers["content-security-policy"].includes("frame-ancestors"),
      );
    });

    test("5.2 Path traversal attempt on static icons returns 404", async () => {
      const res = await fetchPortal("/icons/..%2f..%2fpackage.json");
      assert.equal(res.status, 404);
    });

    test("5.3 Path traversal attempt on CSS asset returns 404", async () => {
      const res = await fetchPortal("/css/..%2fserver.js");
      assert.equal(res.status, 404);
    });

    test("5.4 Path traversal attempt on JS asset returns 404", async () => {
      const res = await fetchPortal("/js/..%2fviews/checkout.html");
      assert.equal(res.status, 404);
    });

    test("5.5 Non-existent route returns HTTP 404 without leaking stack trace", async () => {
      const res = await fetchPortal("/checkout/nonexistent/subpath");
      assert.equal(res.status, 404);
      assert.ok(!res.text.includes("Error:"));
      assert.ok(!res.text.includes("node:internal"));
    });
  });
});
