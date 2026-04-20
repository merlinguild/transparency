import { describe, it, expect, beforeAll, beforeEach, afterEach } from "bun:test";
import { mkdir } from "node:fs/promises";
import { join } from "path";
import { MockWorkerServer } from "@/utils/mock";
import {
  ensureTestKey,
  loadManifest,
  loadSignature,
  setupTestDir,
  cleanupTestDir,
  createTestInstaller,
  runInstaller,
  generateAllFixtures,
  TEST_PORT,
  type TestContext,
} from "@/integration/fixtures";

describe("manifest signature verification", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("manifest"),
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

  it("valid manifest passes signature verification", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      args: ["-Channel", "nonexistent"],
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("Manifest signature verified");
    expect(output).toContain("Channel 'nonexistent' not found");
    expect(result.exitCode).toBe(1);
  });

  it("tampered manifest is blocked with signature failure", async () => {
    const key = await ensureTestKey();
    await worker.stop();

    const tamperedWorker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest-tampered"),
      manifestSig: loadSignature("test-manifest-tampered"),
      revokedJtis: new Set(),
    });
    await tamperedWorker.start();

    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("signature verification failed");
    expect(result.exitCode).toBe(1);

    await tamperedWorker.stop();
  });
});

describe("expiry validation", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("expiry"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest-expired"),
      manifestSig: loadSignature("test-manifest-expired"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("expired manifest fails with clear error message", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      timeoutMs: 10000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("Manifest expired");
    expect(output).toContain("A new release is pending");
    expect(result.exitCode).toBe(1);
  });
});
