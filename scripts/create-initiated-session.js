import { getDatabase } from "../packages/db/src/index.js";
const db = getDatabase();

const nowIso = new Date().toISOString();

const sql = `
  INSERT OR REPLACE INTO payment_sessions (
    id, merchant_id, receiving_account_id, order_id, amount_paise, status, created_at, updated_at
  ) VALUES (
    'test-initiated-session-999',
    'e0f1926c-fbd0-4992-a9ea-c1aa22ae8485',
    '00000000-0000-0000-0000-000000000002',
    'ORD-INIT-999',
    100,
    'INITIATED',
    ?,
    ?
  );
`;

db.execute(sql, [nowIso, nowIso]);
console.log(
  "Initiated session test-initiated-session-999 created for 100 paise",
);
