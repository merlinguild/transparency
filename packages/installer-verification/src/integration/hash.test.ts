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

describe("MSI hash validation", () => {
  let ctx: TestContext;
  let worker: MockWorkerServer;

  beforeAll(async () => {
    await generateAllFixtures();
  });

  beforeEach(async () => {
    ctx = {
      testDir: await setupTestDir("hash-mismatch"),
      merlinDir: "",
      installPs1: "",
    };
    ctx.merlinDir = join(ctx.testDir, ".merlinguild");

    worker = new MockWorkerServer({
      port: TEST_PORT,
      failMode: "none",
      manifestJson: loadManifest("test-manifest-wronghash"),
      manifestSig: loadSignature("test-manifest-wronghash"),
      revokedJtis: new Set(),
    });
    await worker.start();
  });

  afterEach(async () => {
    await worker.stop();
    await cleanupTestDir(ctx.testDir);
  });

  it("MSI hash mismatch is blocked", async () => {
    const key = await ensureTestKey();
    ctx.installPs1 = await createTestInstaller(ctx.testDir, key);
    await mkdir(ctx.merlinDir, { recursive: true });

    const validJwt = createTestJwt({ exp: Math.floor(Date.now() / 1000) + 3600 });
    await writeFile(join(ctx.merlinDir, "license"), validJwt, "utf-8");

    const result = await runInstaller(ctx.testDir, ctx.installPs1, {
      timeoutMs: 15000,
    });

    const output = result.stdout + result.stderr;
    expect(output).toContain("hash mismatch");
    expect(result.exitCode).toBe(1);
  });
});
