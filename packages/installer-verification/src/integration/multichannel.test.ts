import { describe, it, expect, beforeAll, beforeEach, afterEach } from "bun:test";
import { mkdir, writeFile } from "node:fs/promises";
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

describe("Multi-channel manifest", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("multichannel"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest-multichannel"),
      manifestSig: loadSignature("test-manifest-multichannel"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("installer selects the windows_x64 channel and ignores beta's wrong hash", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 15000,
    });

    expect(result.exitCode).toBe(0);
    const output = result.stdout + result.stderr;
    expect(output).toContain("Manifest signature verified");
    expect(output).toContain("MSI SHA-256 matches manifest");
    expect(output).not.toContain("hash mismatch");
  });

  it("explicit -Channel beta picks the beta channel and fails on its wrong hash", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 15000,
      args: ["-Channel", "beta"],
    });

    expect(result.exitCode).toBe(1);
    const output = result.stdout + result.stderr;
    expect(output).toContain("MSI hash mismatch");
  });

  it("nonexistent channel produces a clear error", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      skipInstall: true,
      timeoutMs: 15000,
      args: ["-Channel", "nonexistent"],
    });

    expect(result.exitCode).toBe(1);
    const output = result.stdout + result.stderr;
    expect(output).toContain("Channel 'nonexistent' not found");
  });
});
