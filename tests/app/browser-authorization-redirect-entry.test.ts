import { describe, expect, it } from "vitest";

import worker from "../../src/index";

type D1StatementRecord = { sql: string; params: unknown[]; method: string };

const platformConfigRows = [
  { key: "admin_bootstrap_password_hash", value: "100000:salt:hash" },
  { key: "admin_whitelist", value: "ops@example.test" },
  { key: "management_api_token", value: "tok_test" },
  { key: "root_domain", value: "example.test" }
];

const createRecordingD1 = (platformConfigured: boolean) => {
  const statements: D1StatementRecord[] = [];
  const buildStatement = (sql: string, params: unknown[]) => {
    const execute = (method: string) => {
      statements.push({ sql, params, method });
      const results =
        platformConfigured && sql.includes("platform_config") && params.includes("root_domain")
          ? platformConfigRows
          : [];
      if (method === "run") {
        return { success: true, meta: {}, results: [] };
      }
      if (method === "first") {
        return results[0] ?? null;
      }
      if (method === "raw") {
        return results.map((row) => Object.values(row));
      }
      return { results, success: true, meta: {} };
    };
    return {
      sql,
      params,
      bind: (...bound: unknown[]) => buildStatement(sql, bound),
      all: async () => execute("all"),
      first: async () => execute("first"),
      raw: async () => execute("raw"),
      run: async () => execute("run")
    };
  };
  const db = {
    prepare: (sql: string) => buildStatement(sql, []),
    // One record per batch call, so a batched write cannot bypass the zero-I/O assertions.
    batch: async (stmts: unknown[]) => {
      const batched = stmts as Array<{ sql: string; params: unknown[] }>;
      statements.push({
        sql: batched.map((stmt) => stmt.sql).join("; "),
        params: batched.flatMap((stmt) => stmt.params),
        method: "batch"
      });
      return batched.map(() => ({ success: true, results: [] }));
    },
    exec: async (sql: string) => {
      statements.push({ sql, params: [], method: "exec" });
      return { count: 0, duration: 0 };
    }
  } as unknown as D1Database;
  return { db, statements };
};

const createRecordingKv = (binding: string, calls: string[]) =>
  ({
    get: async () => {
      calls.push(`${binding}.get`);
      return null;
    },
    getWithMetadata: async () => {
      calls.push(`${binding}.getWithMetadata`);
      return { value: null, metadata: null };
    },
    put: async () => {
      calls.push(`${binding}.put`);
    },
    delete: async () => {
      calls.push(`${binding}.delete`);
    },
    list: async () => {
      calls.push(`${binding}.list`);
      return { keys: [], list_complete: true, cacheStatus: null };
    }
  }) as unknown as KVNamespace;

const createRecordingR2 = () => {
  const calls: string[] = [];
  const bucket = {
    get: async () => {
      calls.push("get");
      return { arrayBuffer: async () => new Uint8Array(32).buffer };
    },
    put: async () => {
      calls.push("put");
      return {};
    },
    head: async () => {
      calls.push("head");
      return null;
    },
    delete: async () => {
      calls.push("delete");
    },
    list: async () => {
      calls.push("list");
      return { objects: [], truncated: false, delimitedPrefixes: [] };
    }
  } as unknown as R2Bucket;
  return { bucket, calls };
};

const createInstrumentedEnv = ({ platformConfigured = true } = {}) => {
  const d1 = createRecordingD1(platformConfigured);
  const r2 = createRecordingR2();
  // Every KV binding appends to this one array. Callers hold the reference before
  // the request runs, so it must stay live; a copy taken at construction would miss later calls.
  const kvCalls: string[] = [];
  const env = {
    ADMIN_SESSIONS_KV: createRecordingKv("ADMIN_SESSIONS_KV", kvCalls),
    DB: d1.db,
    KEY_MATERIAL_R2: r2.bucket,
    REGISTRATION_TOKENS_KV: createRecordingKv("REGISTRATION_TOKENS_KV", kvCalls),
    USER_SESSIONS_KV: createRecordingKv("USER_SESSIONS_KV", kvCalls)
  };
  return {
    env,
    d1Statements: d1.statements,
    r2Calls: r2.calls,
    kvCalls
  };
};

const executionContext = {} as ExecutionContext;

describe("worker fetch entry: o-host browser authorize redirect", () => {
  it("returns the 302 before content policy, signing-key, TOTP, and session-store init", async () => {
    const { env, d1Statements, r2Calls, kvCalls } = createInstrumentedEnv();
    const requestUrl =
      "https://o.example.test/t/acme/authorize?client_id=web&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&state=a%2Bb&resource=https%3A%2F%2Fauth.example.test%2Fops";

    const response = await worker.fetch(
      new Request(requestUrl),
      env,
      executionContext
    );

    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(
      "https://auth.example.test/api/t/acme/authorize?client_id=web&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcb&state=a%2Bb&resource=https%3A%2F%2Fauth.example.test%2Fops"
    );
    expect(response.headers.get("cache-control")).toBe("no-store");

    // The only storage I/O allowed on this path is the platform_config read.
    expect(d1Statements).toHaveLength(1);
    expect(d1Statements[0]!.sql).toContain("platform_config");
    expect(d1Statements[0]!.params).toEqual([
      "admin_bootstrap_password_hash",
      "admin_whitelist",
      "management_api_token",
      "root_domain"
    ]);
    expect(r2Calls).toEqual([]);
    expect(kvCalls).toEqual([]);
  });

  it("keeps the setup wizard ahead of the redirect when platform config is missing", async () => {
    const { env, d1Statements, r2Calls, kvCalls } = createInstrumentedEnv({
      platformConfigured: false
    });

    const response = await worker.fetch(
      new Request("https://o.example.test/t/acme/authorize?client_id=web"),
      env,
      executionContext
    );

    // The setup app has no route for this path, so it answers 404 and never redirects.
    expect(response.status).toBe(404);
    expect(response.headers.get("location")).toBeNull();
    // Only the platform_config probe runs; no repositories, keys, or sessions are built.
    expect(d1Statements).toHaveLength(1);
    expect(d1Statements[0]!.sql).toContain("platform_config");
    expect(r2Calls).toEqual([]);
    expect(kvCalls).toEqual([]);
  });

  it("still runs full repository init for non-matching requests on the o host", async () => {
    const { env, d1Statements, r2Calls } = createInstrumentedEnv();

    const response = await worker.fetch(
      new Request("https://o.example.test/t/acme/jwks.json"),
      env,
      executionContext
    );

    expect(d1Statements.length).toBeGreaterThan(1);
    expect(r2Calls).toContain("get");
    const location = response.headers.get("location") ?? "";
    expect(location).not.toContain("/api/t/acme/authorize");
  });

  it("does not take the early path for non-GET requests on the authorize path", async () => {
    const { env, d1Statements, r2Calls } = createInstrumentedEnv();

    const response = await worker.fetch(
      new Request("https://o.example.test/t/acme/authorize?client_id=web", {
        method: "POST"
      }),
      env,
      executionContext
    );

    expect(d1Statements.length).toBeGreaterThan(1);
    expect(r2Calls).toContain("get");
    const location = response.headers.get("location") ?? "";
    expect(location).not.toContain("/api/t/acme/authorize");
  });
});

describe("instrumented env negative controls", () => {
  it("reports a KV read made after the env was built", async () => {
    const { env, kvCalls } = createInstrumentedEnv();

    await env.USER_SESSIONS_KV.get("user_session:negative-control");

    expect(kvCalls).toEqual(["USER_SESSIONS_KV.get"]);
  });

  it("reports a D1 batch as one statement record", async () => {
    const { env, d1Statements } = createInstrumentedEnv();

    await env.DB.batch([env.DB.prepare("INSERT INTO probe (id) VALUES (?)").bind("p_1")]);

    expect(d1Statements).toEqual([
      { sql: "INSERT INTO probe (id) VALUES (?)", params: ["p_1"], method: "batch" }
    ]);
  });
});
