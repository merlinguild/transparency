export type ManifestKey = string | Uint8Array;

export interface Manifest {
  expires_at: string;
  channels: Record<string, ChannelData>;
}

export interface ChannelData {
  sequence: number;
  artifacts: Record<string, Artifact>;
}

export interface Artifact {
  url: string;
  sha256: string;
}

export interface VerificationResult {
  success: boolean;
  error?: string;
}

export async function verifyManifestSignature(
  manifestBytes: Uint8Array,
  signatureB64url: string,
  trustedKeys: ManifestKey[]
): Promise<VerificationResult> {

  if (trustedKeys.length === 0) {
    return { success: false, error: "No trusted keys configured" };
  }

  const b64 = signatureB64url.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  const paddedB64 = b64 + (pad === 0 ? "" : "=".repeat(4 - pad));

  let sigBytes: Uint8Array;
  try {
    sigBytes = Uint8Array.from(atob(paddedB64), c => c.charCodeAt(0));
  } catch {
    return { success: false, error: "Invalid base64 encoding in signature" };
  }

  if (sigBytes.length !== 256) {
    return { success: false, error: `Invalid signature length: ${sigBytes.length} bytes (expected 256)` };
  }

  for (const key of trustedKeys) {
    if (typeof key === "string" && key.includes("TODO_REPLACE_WITH")) {
      return { success: false, error: "Trusted manifest key material is not configured" };
    }

    try {
      let publicKey: Uint8Array;
      if (typeof key === "string") {
        publicKey = await parseRSA2048PublicKey(key);
      } else if (key instanceof Uint8Array) {
        publicKey = key;
      } else {
        throw new Error("Invalid key type");
      }

      const verified = await verifyRSA2048PSS(sigBytes, manifestBytes, publicKey);

      if (verified) {
        return { success: true };
      }
    } catch (e) {
      const error = e as Error;
      if (error.message.startsWith("Invalid PEM key") || error.message === "Invalid PEM format" || error.message === "Invalid key type") {
        return { success: false, error: `Corrupt trusted key material` };
      }
      continue;
    }
  }

  return { success: false, error: "Manifest signature verification failed against all trusted keys" };
}

export async function parseRSA2048PublicKey(pem: string): Promise<Uint8Array> {
  const pemHeader = "-----BEGIN PUBLIC KEY-----";
  const pemFooter = "-----END PUBLIC KEY-----";

  if (!pem.includes(pemHeader) || !pem.includes(pemFooter)) {
    throw new Error("Invalid PEM format");
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      "spki",
      new TextEncoder().encode(pem),
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const spki = await crypto.subtle.exportKey("spki", publicKey);
    return new Uint8Array(spki);
  } catch (e) {
    const error = e as Error;
    throw new Error(`Invalid PEM key: ${error.message}`);
  }
}

async function verifyRSA2048PSS(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "spki",
      publicKey as unknown as BufferSource,
      { name: "RSA-PSS", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const verified = await crypto.subtle.verify(
      { name: "RSA-PSS", hash: "SHA-256", saltLength: 32 },
      key,
      signature as unknown as BufferSource,
      message as unknown as BufferSource
    );
    return verified;
  } catch {
    return false;
  }
}

export function checkManifestExpiry(
  expiresAt: string,
  nowSeconds?: number,
  skewHours: number = 24
): VerificationResult {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  const exp = new Date(expiresAt).getTime() / 1000;
  const skew = skewHours * 3600;

  if (isNaN(exp)) {
    return { success: false, error: "Invalid expiry date format" };
  }

  if (now - exp > skew) {
    return { success: false, error: "Manifest expired" };
  }

  return { success: true };
}

export function checkRollbackProtection(
  manifestSequence: number,
  storedSequence: number | null,
  minimumSequence: number
): VerificationResult {
  if (manifestSequence < minimumSequence) {
    return { 
      success: false, 
      error: `Rollback blocked: manifest sequence ${manifestSequence} is below minimum ${minimumSequence}` 
    };
  }

  if (storedSequence !== null && manifestSequence <= storedSequence) {
    return { 
      success: false, 
      error: `Rollback blocked: manifest sequence ${manifestSequence} is not greater than stored sequence ${storedSequence}` 
    };
  }

  return { success: true };
}

export function validateManifestSchema(manifest: unknown): VerificationResult {
  if (typeof manifest !== "object" || manifest === null) {
    return { success: false, error: "Manifest must be an object" };
  }

  const m = manifest as Record<string, unknown>;

  if (typeof m.expires_at !== "string") {
    return { success: false, error: "Missing or invalid expires_at field" };
  }

  if (typeof m.channels !== "object" || m.channels === null) {
    return { success: false, error: "Missing or invalid channels field" };
  }

  const channels = m.channels as Record<string, unknown>;
  for (const [channelName, channelData] of Object.entries(channels)) {
    if (typeof channelData !== "object" || channelData === null) {
      return { success: false, error: `Channel "${channelName}" must be an object` };
    }

    const c = channelData as Record<string, unknown>;
    if (typeof c.sequence !== "number" || !Number.isInteger(c.sequence) || c.sequence < 0) {
      return { success: false, error: `Channel "${channelName}" has invalid sequence` };
    }

    if (typeof c.artifacts !== "object" || c.artifacts === null) {
      return { success: false, error: `Channel "${channelName}" missing artifacts` };
    }

    const artifacts = c.artifacts as Record<string, unknown>;
    for (const [artifactName, artifact] of Object.entries(artifacts)) {
      if (typeof artifact !== "object" || artifact === null) {
        return { success: false, error: `Artifact "${artifactName}" in channel "${channelName}" must be an object` };
      }

      const a = artifact as Record<string, unknown>;
      if (typeof a.url !== "string" || !a.url) {
        return { success: false, error: `Artifact "${artifactName}" missing or invalid url` };
      }

      if (typeof a.sha256 !== "string" || !a.sha256) {
        return { success: false, error: `Artifact "${artifactName}" missing or invalid sha256` };
      }

      if (!/^[a-f0-9]{64}$/i.test(a.sha256)) {
        return { success: false, error: `Artifact "${artifactName}" has invalid sha256 format` };
      }
    }
  }

  return { success: true };
}
