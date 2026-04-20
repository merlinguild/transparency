import { join } from "path";
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { describe, it, expect, beforeAll, beforeEach, afterEach } from "bun:test";

import { MockWorkerServer } from "@/utils/mock";
import {
  ensureTestKey,
  loadManifest,
  loadSignature,
  setupTestDir,
  cleanupTestDir,
  createTestInstaller,
  createTestJwt,
  runInstaller,
  generateAllFixtures,
  TEST_PORT,
  type TestContext,
} from "@/integration/fixtures";

describe("rollback protection", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("rollback"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest-v2"),
      manifestSig: loadSignature("test-manifest-v2"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("rollback is blocked when stored sequence is higher", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    await writeFile(join(ctx.merlinDir, ".sequence"), "format 1\nwindows_x64=5\n", "utf-8");

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("Rollback blocked");
    expect(output).toContain("not greater than the stored sequence 5");
    expect(result.exitCode).toBe(1);
  });

  it("install succeeds when sequence increases and persists new sequence", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const sequencePath = join(ctx.merlinDir, ".sequence");
    await writeFile(sequencePath, "format 1\nwindows_x64=1\n", "utf-8");

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 15000,
    });

    const output = result.stdout + result.stderr;
    expect(output).not.toContain("Rollback blocked");
    expect(result.exitCode).toBe(0);

    const persisted = await readFile(sequencePath, "utf-8");
    expect(persisted).toContain("windows_x64=2");
    expect(persisted).not.toContain("windows_x64=1");
  });

  it("embedded minimum sequence blocks manifests below the floor", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key, TEST_PORT, {
      minimumSequence: 10,
    });
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("Rollback blocked");
    expect(output).toContain("below the embedded minimum");
    expect(result.exitCode).toBe(1);
  });
});
