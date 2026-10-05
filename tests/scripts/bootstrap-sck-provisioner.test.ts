// bootstrap-sck-provisioner.sh 的管线语义测试：用 fake pnpm（→ fake-d1.mjs 维
// 护 JSON 状态的 D1 假件）与 fake gh（捕获 stdin 的 secret 值）跑真实脚本，
// 验证幂等跳过、无条件 mint、注入失败补偿吊销、明文不出现在输出里。
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SCRIPT = join(__dirname, "../../scripts/bootstrap-sck-provisioner.sh");
const FAKE_BIN = join(__dirname, "fake-bin");

interface State {
  admin_service_principals: Array<{
    id: string;
    label: string;
    token_hash: string;
    scopes: string;
    status: string;
    created_at: string;
    revoked_at: string | null;
    created_by: string;
  }>;
  audit_events: Array<{
    id: string;
    actor_type: string;
    actor_id: string | null;
    event_type: string;
    target_id: string | null;
    payload: string;
    occurred_at: string;
  }>;
}

const run = (state: State, env: Record<string, string> = {}) => {
  const dir = mkdtempSync(join(tmpdir(), "bootstrap-"));
  const statePath = join(dir, "d1.json");
  const ghDir = join(dir, "gh");
  writeFileSync(statePath, JSON.stringify(state));
  const result = spawnSync("bash", [SCRIPT], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${FAKE_BIN}:${process.env.PATH}`,
      CLOUDFLARE_API_TOKEN: "cf-token",
      CLOUDFLARE_ACCOUNT_ID: "cf-account",
      FAKE_D1_STATE: statePath,
      FAKE_GH_CAPTURE_DIR: ghDir,
      ...env
    }
  });
  const readState = () => JSON.parse(readFileSync(statePath, "utf8")) as State;
  const capturedSecrets = () => {
    try {
      return Object.fromEntries(
        readdirSync(ghDir).map((name) => [name, readFileSync(join(ghDir, name), "utf8")])
      );
    } catch {
      return {} as Record<string, string>;
    }
  };
  return { ...result, output: `${result.stdout}${result.stderr}`, readState, capturedSecrets };
};

const emptyState = (): State => ({ admin_service_principals: [], audit_events: [] });

describe("bootstrap-sck-provisioner.sh", () => {
  it("bash -n 语法干净", () => {
    expect(() => execFileSync("bash", ["-n", SCRIPT])).not.toThrow();
  });

  it("已有 active principal 时幂等跳过：不写 D1、不碰 secret", () => {
    const state = emptyState();
    state.admin_service_principals.push({
      id: "existing-1",
      label: "hand-minted",
      token_hash: "h",
      scopes: '["tenant.read"]',
      status: "active",
      created_at: "2026-01-01T00:00:00.000Z",
      revoked_at: null,
      created_by: "ops:qa"
    });
    const r = run(state, { SCK_REPO_TOKEN: "sck-token" });
    expect(r.status).toBe(0);
    expect(r.output).toContain("跳过");
    const after = r.readState();
    expect(after.admin_service_principals).toHaveLength(1);
    expect(after.audit_events).toHaveLength(0);
    expect(r.capturedSecrets()).toEqual({});
  });

  it("无 active 且未配置 SCK_REPO_TOKEN 时告警跳过、不 mint（部署不失败）", () => {
    const r = run(emptyState());
    expect(r.status).toBe(0);
    expect(r.output).toContain("SCK_REPO_TOKEN");
    expect(r.readState().admin_service_principals).toHaveLength(0);
  });

  it("无 active 时 mint + 写审计 + 注入 env secret，明文不出现在输出里", () => {
    const r = run(emptyState(), { SCK_REPO_TOKEN: "sck-token" });
    expect(r.status).toBe(0);
    const state = r.readState();
    expect(state.admin_service_principals).toHaveLength(1);
    const p = state.admin_service_principals[0];
    expect(p).toMatchObject({
      label: "sck-provisioner",
      scopes: '["tenant.read","user.read","user.provision"]',
      status: "active",
      created_by: "deploy:ma_hono-pipeline",
      revoked_at: null
    });
    const audit = state.audit_events.find((e) => e.event_type === "admin.service_principal.minted");
    expect(audit).toMatchObject({ actor_type: "management_token", actor_id: "deploy:ma_hono-pipeline", target_id: p.id });

    const secrets = r.capturedSecrets();
    const token = secrets.ORIGIN_ENV_IDP_PROVISION_TOKEN;
    expect(token).toBeTruthy();
    // 注入值即 principal 的明文 token：sha256/base64url 与 D1 存行一致
    expect(createHash("sha256").update(token).digest("base64url")).toBe(p.token_hash);
    // 明文不出现在脚本 stdout/stderr（不落 CI 日志）
    expect(r.output).not.toContain(token);

    // 重放幂等：第二次运行直接跳过，不新增
    const replay = run(state, { SCK_REPO_TOKEN: "sck-token" });
    expect(replay.status).toBe(0);
    expect(replay.readState().admin_service_principals).toHaveLength(1);
    expect(replay.capturedSecrets()).toEqual({});
  });

  it("注入失败时补偿吊销新 principal 并以非零退出", () => {
    const r = run(emptyState(), { SCK_REPO_TOKEN: "sck-token", FAKE_GH_EXIT: "1" });
    expect(r.status).toBe(1);
    const p = r.readState().admin_service_principals[0];
    expect(p.status).toBe("revoked");
    expect(p.revoked_at).toBeTruthy();
  });
});
