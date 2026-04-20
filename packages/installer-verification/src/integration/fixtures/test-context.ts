import { spawn } from "node:child_process";
import { mkdir, rm, writeFile, readFile, cp } from "node:fs/promises";
import { join } from "path";
import type { KeyPair } from "./keys.js";

const INSTALL_PS1 = join(
  import.meta.dirname,
  "..",
  "..",
  "..",
  "..",
  "..",
  "install.ps1"
);

export interface InstallerResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface TestContext {
  testDir: string;
  merlinDir: string;
  installPs1: string;
}

export const setupTestDir = async (name: string): Promise<string> => {
  const timestamp = Date.now();
  const dir = join(import.meta.dirname, "..", "..", "..", ".tmp", `${name}-${timestamp}`);
  await mkdir(dir, { recursive: true });
  return dir;
};

export const cleanupTestDir = async (dir: string): Promise<void> => {
  try {
    await rm(dir, { recursive: true, force: true });
  } catch {
  }
};

const replaceBetweenMarkers = (
  source: string,
  beginMarker: string,
  endMarker: string,
  replacement: string
): string => {
  const pattern = new RegExp(
    `(# ${beginMarker}[^\\n]*\\n)[\\s\\S]*?(# ${endMarker}[^\\n]*)`
  );
  if (!pattern.test(source)) {
    throw new Error(
      `Marker pair ${beginMarker} / ${endMarker} not found in install.ps1. ` +
      `Tests require sentinel markers to inject configuration safely.`
    );
  }
  return source.replace(pattern, `$1${replacement}\n$2`);
};

export interface CreateTestInstallerOptions {
  minimumSequence?: number;
}

export const createTestInstaller = async (
  testDir: string,
  key: KeyPair,
  port = 9876,
  options: CreateTestInstallerOptions = {}
): Promise<string> => {
  const originalPs1 = await readFile(INSTALL_PS1, "utf-8");

  let modifiedPs1 = replaceBetweenMarkers(
    originalPs1,
    "BEGIN_TRUSTED_KEYS",
    "END_TRUSTED_KEYS",
    `$Script:TrustedManifestKeys = @(${key.psHashTable})`
  );

  modifiedPs1 = replaceBetweenMarkers(
    modifiedPs1,
    "BEGIN_BOOTSTRAP_HOST",
    "END_BOOTSTRAP_HOST",
    `$Script:BootstrapHost = 'localhost:${port}'`
  );

  if (options.minimumSequence !== undefined) {
    modifiedPs1 = replaceBetweenMarkers(
      modifiedPs1,
      "BEGIN_MINIMUM_SEQUENCE",
      "END_MINIMUM_SEQUENCE",
      `$Script:MinimumSequence = ${options.minimumSequence}`
    );
  }

  modifiedPs1 = modifiedPs1
    .replace(
      /"https:\/\/\$Script:BootstrapHost\/manifest\.json"/g,
      `"http://$Script:BootstrapHost/manifest.json"`
    )
    .replace(
      /"https:\/\/\$Script:BootstrapHost\/manifest\.json\.sig"/g,
      `"http://$Script:BootstrapHost/manifest.json.sig"`
    );

  const testInstallerPath = join(testDir, "install-test.ps1");
  await writeFile(testInstallerPath, modifiedPs1, "utf-8");
  return testInstallerPath;
};

export const runInstaller = async (
  testDir: string,
  installPs1Path: string,
  options: {
    args?: string[];
    env?: Record<string, string>;
    timeoutMs?: number;
    backupPath?: string;
    skipInstall?: boolean;
  } = {}
): Promise<InstallerResult> => {
  const args = [
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    installPs1Path,
  ];

  const userArgs = options.args || [];
  const hasChannel = userArgs.some((a) => a === "-Channel");

  if (options.backupPath) {
    args.push("-BackupPath", options.backupPath);
  } else if (!hasChannel) {
    args.push("-Channel", "windows_x64");
  }

  if (options.skipInstall) {
    args.push("-SkipInstall");
  }

  args.push(...userArgs);

  const env = {
    ...process.env,
    USERPROFILE: testDir,
    HOME: testDir,
    BACKUP_PATH: "",
    BACKUP_URL: "",
    ...(options.env || {}),
  };

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error(`Timeout after ${options.timeoutMs || 30000}ms`));
    }, options.timeoutMs || 30000);

    const child = spawn("powershell.exe", args, { env });
    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (exitCode) => {
      clearTimeout(timeout);
      resolve({ exitCode: exitCode || 0, stdout, stderr });
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
};

export const createTestJwt = (payload: { exp: number; jti?: string }): string => {
  const header = { alg: "PS256", typ: "JWT" };
  const fullPayload = {
    ...payload,
    sub: "test-subject",
    aud: "merlinguild-installer",
    iat: Math.floor(Date.now() / 1000),
  };

  const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
  const payloadB64 = Buffer.from(JSON.stringify(fullPayload)).toString("base64url");
  const signature = "test-signature-placeholder";

  return `${headerB64}.${payloadB64}.${signature}`;
};
