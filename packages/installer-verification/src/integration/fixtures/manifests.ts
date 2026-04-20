import { writeFileSync, readFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { signManifest, modifyManifestBytes } from "./crypto";
import { ensureTestKey } from "./keys";

const TMP_DIR = join(import.meta.dirname, "..", "..", "..", ".tmp", "manifests");

export interface ManifestOptions {
  sequence: number;
  msiSha256: string;
  msiSize: number;
  workerUrl: string;
  channel: string;
  expiresAt?: Date;
}

export interface Manifest {
  created_at: string;
  expires_at: string;
  channels: Record<string, {
    sequence: number;
    artifacts: Record<string, {
      url: string;
      sha256: string;
      size: number;
    }>;
  }>;
}

const createManifestObject = (options: ManifestOptions): Manifest => {
  const createdAt = new Date();
  const expiresAt = options.expiresAt || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const formatDate = (date: Date) => {
    const iso = date.toISOString();
    return iso.endsWith('Z') ? iso : iso.replace(/\.\d+Z$/, 'Z');
  };

  return {
    created_at: formatDate(createdAt),
    expires_at: formatDate(expiresAt),
    channels: {
      [options.channel]: {
        sequence: options.sequence,
        artifacts: {
          windows_x64: {
            url: options.workerUrl,
            sha256: options.msiSha256,
            size: options.msiSize,
          },
        },
      },
    },
  };
};

let fixturesReady = false;

const FIXTURE_NAMES = [
  "test-manifest",
  "test-manifest-v2",
  "test-manifest-expired",
  "test-manifest-tampered",
  "test-manifest-wronghash",
] as const;

const allFixturesOnDisk = (): boolean =>
  FIXTURE_NAMES.every((name) =>
    existsSync(join(TMP_DIR, `${name}.json`)) &&
    existsSync(join(TMP_DIR, `${name}.sig`))
  ) && existsSync(join(TMP_DIR, "test-manifest-multichannel.json"));

export const generateAllFixtures = async (): Promise<void> => {
  if (fixturesReady) return;

  if (!existsSync(TMP_DIR)) {
    mkdirSync(TMP_DIR, { recursive: true });
  }

  if (allFixturesOnDisk()) {
    fixturesReady = true;
    return;
  }

  const key = await ensureTestKey();
  const mockMsiContent = "mock-msi-content-v1-fixed-bytes-for-testing";
  const mockMsiHash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(mockMsiContent)
  );
  const mockMsiSha256 = Array.from(new Uint8Array(mockMsiHash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const saveManifest = async (
    name: string,
    options: ManifestOptions,
    tampered = false
  ): Promise<void> => {
    const manifest = createManifestObject(options);
    const bytes = new TextEncoder().encode(JSON.stringify(manifest, null, 2));
    const finalBytes = tampered ? modifyManifestBytes(bytes) : bytes;
    const sig = tampered
      ? await signManifest(bytes, key.privateKey)
      : await signManifest(finalBytes, key.privateKey);

    writeFileSync(join(TMP_DIR, `${name}.json`), finalBytes);
    writeFileSync(join(TMP_DIR, `${name}.sig`), sig);
  };

  await saveManifest("test-manifest", {
    sequence: 1,
    msiSha256: mockMsiSha256,
    msiSize: mockMsiContent.length,
    workerUrl: "http://localhost:9876/download/test-msi",
    channel: "windows_x64",
  });

  await saveManifest("test-manifest-v2", {
    sequence: 2,
    msiSha256: mockMsiSha256,
    msiSize: mockMsiContent.length,
    workerUrl: "http://localhost:9876/download/test-msi",
    channel: "windows_x64",
  });

  await saveManifest("test-manifest-expired", {
    sequence: 3,
    msiSha256: mockMsiSha256,
    msiSize: mockMsiContent.length,
    workerUrl: "http://localhost:9876/download/test-msi",
    channel: "windows_x64",
    expiresAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
  });

  await saveManifest("test-manifest-tampered", {
    sequence: 1,
    msiSha256: mockMsiSha256,
    msiSize: mockMsiContent.length,
    workerUrl: "http://localhost:9876/download/test-msi",
    channel: "windows_x64",
  }, true);

  await saveManifest("test-manifest-wronghash", {
    sequence: 4,
    msiSha256: "b".repeat(64),
    msiSize: mockMsiContent.length,
    workerUrl: "http://localhost:9876/download/test-msi",
    channel: "windows_x64",
  });

  const multiChannelManifest: Manifest = {
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    channels: {
      windows_x64: {
        sequence: 1,
        artifacts: {
          windows_x64: {
            url: "http://localhost:9876/download/test-msi",
            sha256: mockMsiSha256,
            size: mockMsiContent.length,
          },
        },
      },
      beta: {
        sequence: 99,
        artifacts: {
          windows_x64: {
            url: "http://localhost:9876/download/test-msi",
            sha256: "c".repeat(64),
            size: mockMsiContent.length,
          },
        },
      },
    },
  };
  const multiBytes = new TextEncoder().encode(JSON.stringify(multiChannelManifest, null, 2));
  const multiSig = await signManifest(multiBytes, key.privateKey);
  writeFileSync(join(TMP_DIR, "test-manifest-multichannel.json"), multiBytes);
  writeFileSync(join(TMP_DIR, "test-manifest-multichannel.sig"), multiSig);

  fixturesReady = true;
};

export const loadManifest = (name: string): string => {
  return readFileSync(join(TMP_DIR, `${name}.json`), "utf-8");
};

export const loadSignature = (name: string): string => {
  return readFileSync(join(TMP_DIR, `${name}.sig`), "utf-8");
};
