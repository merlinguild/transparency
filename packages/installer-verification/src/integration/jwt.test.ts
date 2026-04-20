import { describe, it, expect, beforeAll, beforeEach, afterEach } from "bun:test";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { join } from "path";
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

describe("JWT validation", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("jwt"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "expired_jwt",
      manifestJson: loadManifest("test-manifest"),
      manifestSig: loadSignature("test-manifest"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("expired JWT triggers license rejection", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const expiredJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) - 3600 });
    await writeFile(join(ctx.merlinDir, "license"), expiredJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("Worker rejected the license");
    expect(result.exitCode).toBe(1);
  });

  it("missing license file triggers interactive prompt", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 5000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("license JWT is required");
  });
});

describe("License file lifecycle", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("license-lifecycle"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest"),
      manifestSig: loadSignature("test-manifest"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("pre-existing license file is preserved byte-exact across a successful run", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    const licensePath = join(ctx.merlinDir, "license");
    await writeFile(licensePath, validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 15000,
    });

    expect(result.exitCode).toBe(0);
    const afterContent = await readFile(licensePath, "utf-8");
    expect(afterContent).toBe(validJwt);
  });
});
