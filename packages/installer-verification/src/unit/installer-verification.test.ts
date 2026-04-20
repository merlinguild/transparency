import { describe, it, expect, beforeAll } from "bun:test";
import {
  verifyManifestSignature,
  checkManifestExpiry,
  checkRollbackProtection,
  validateManifestSchema,
  parseRSA2048PublicKey,
  type ManifestKey,
} from "@/installer-verification";

describe("installer-verification", () => {
  describe("verifyManifestSignature", () => {
    let validKey: ManifestKey;
    let validManifest: Uint8Array;
    let validSignature: string;
    let wrongSignature: string;

    beforeAll(async () => {
      const { privateKey, publicKey } = await generateRSA2048KeyPair();

      validManifest = new TextEncoder().encode(`{"test":"data"}`);

      const signature = await signWithRSA2048PSS(validManifest, privateKey);
      validSignature = btoa(String.fromCharCode(...signature))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

      validKey = publicKey;

      wrongSignature = btoa(String.fromCharCode(...Array(256).fill(0xBB)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    });

    it("no trusted keys returns error", async () => {
      const result = await verifyManifestSignature(validManifest, validSignature, []);
      expect(result.success).toBe(false);
      expect(result.error).toBe("No trusted keys configured");
    });

    it("todo placeholder key returns error", async () => {
      const todoKey: ManifestKey = "-----BEGIN PUBLIC KEY-----\nTODO_REPLACE_WITH_BASE64_X\n-----END PUBLIC KEY-----";
      const result = await verifyManifestSignature(validManifest, validSignature, [todoKey]);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Trusted manifest key material is not configured");
    });

    it("invalid base64 signature returns error", async () => {
      const result = await verifyManifestSignature(validManifest, "!!!invalid!!!", [validKey]);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid base64 encoding in signature");
    });

    it("wrong signature length returns error", async () => {
      const shortSig = btoa(String.fromCharCode(...Array(64).fill(0xAA)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      const result = await verifyManifestSignature(validManifest, shortSig, [validKey]);
      expect(result.success).toBe(false);
      expect(result.error).toContain("Invalid signature length");
    });

    it("corrupt key material returns error", async () => {
      const corruptKey: ManifestKey = "-----BEGIN PUBLIC KEY-----\n!!!invalid!!!\n-----END PUBLIC KEY-----";
      const result = await verifyManifestSignature(validManifest, validSignature, [corruptKey]);
      expect(result.success).toBe(false);
      expect(result.error).toContain("Corrupt trusted key material");
    });

    it("key with wrong length returns error", async () => {
      const shortKey: ManifestKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQ=\n-----END PUBLIC KEY-----";
      const result = await verifyManifestSignature(validManifest, validSignature, [shortKey]);
      expect(result.success).toBe(false);
      expect(result.error).toContain("Corrupt trusted key material");
    });

    it("signature verification failure returns error", async () => {
      const result = await verifyManifestSignature(validManifest, wrongSignature, [validKey]);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Manifest signature verification failed against all trusted keys");
    });

    it("valid signature verification succeeds", async () => {
      const result = await verifyManifestSignature(validManifest, validSignature, [validKey]);
      expect(result.success).toBe(true);
    });
  });

  describe("checkManifestExpiry", () => {
    const now = Math.floor(Date.now() / 1000);

    it("valid future expiry returns success", () => {
      const future = new Date((now + 86400) * 1000).toISOString();
      const result = checkManifestExpiry(future, now);
      expect(result.success).toBe(true);
    });

    it("expiry within 24h skew returns success", () => {
      const expiredBy23h = new Date((now - 82800) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy23h, now);
      expect(result.success).toBe(true);
    });

    it("expiry exactly at skew boundary returns success", () => {
      const expiredBy24h = new Date((now - 86400) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy24h, now);
      expect(result.success).toBe(true);
    });

    it("expiry beyond 24h skew returns error", () => {
      const expiredBy25h = new Date((now - 90000) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy25h, now);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Manifest expired");
    });

    it("far past expiry returns error", () => {
      const expiredBy7d = new Date((now - 604800) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy7d, now);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Manifest expired");
    });

    it("invalid date format returns error", () => {
      const result = checkManifestExpiry("invalid-date", now);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid expiry date format");
    });

    it("custom skew hours parameter works", () => {
      const expiredBy12h = new Date((now - 43200) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy12h, now, 12);
      expect(result.success).toBe(true);
    });

    it("custom skew hours rejects beyond threshold", () => {
      const expiredBy13h = new Date((now - 46800) * 1000).toISOString();
      const result = checkManifestExpiry(expiredBy13h, now, 12);
      expect(result.success).toBe(false);
    });
  });

  describe("checkRollbackProtection", () => {
    it("first install (null stored) returns success", () => {
      const result = checkRollbackProtection(5, null, 1);
      expect(result.success).toBe(true);
    });

    it("sequence above minimum returns success", () => {
      const result = checkRollbackProtection(10, null, 5);
      expect(result.success).toBe(true);
    });

    it("sequence at minimum returns success", () => {
      const result = checkRollbackProtection(5, null, 5);
      expect(result.success).toBe(true);
    });

    it("sequence below minimum returns error", () => {
      const result = checkRollbackProtection(3, null, 5);
      expect(result.success).toBe(false);
      expect(result.error).toContain("below minimum");
    });

    it("sequence above stored returns success", () => {
      const result = checkRollbackProtection(15, 10, 1);
      expect(result.success).toBe(true);
    });

    it("sequence equal to stored returns error", () => {
      const result = checkRollbackProtection(10, 10, 1);
      expect(result.success).toBe(false);
      expect(result.error).toContain("not greater than stored sequence");
    });

    it("sequence below stored returns error", () => {
      const result = checkRollbackProtection(5, 10, 1);
      expect(result.success).toBe(false);
      expect(result.error).toContain("not greater than stored sequence");
    });

    it("monotonic increase across multiple installs", () => {
      let stored: number | null = null;
      const minimum = 1;

      let result = checkRollbackProtection(5, stored, minimum);
      expect(result.success).toBe(true);
      stored = 5;

      result = checkRollbackProtection(10, stored, minimum);
      expect(result.success).toBe(true);
      stored = 10;

      result = checkRollbackProtection(5, stored, minimum);
      expect(result.success).toBe(false);
    });
  });

  describe("validateManifestSchema", () => {
    const validManifest = {
      expires_at: "2026-12-31T23:59:59Z",
      channels: {
        stable: {
          sequence: 10,
          artifacts: {
            windows_x64: {
              url: "https://example.com/app.msi",
              sha256: "a".repeat(64),
            },
          },
        },
      },
    };

    it("valid manifest returns success", () => {
      const result = validateManifestSchema(validManifest);
      expect(result.success).toBe(true);
    });

    it("null manifest returns error", () => {
      const result = validateManifestSchema(null);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Manifest must be an object");
    });

    it("non-object manifest returns error", () => {
      const result = validateManifestSchema("string");
      expect(result.success).toBe(false);
      expect(result.error).toBe("Manifest must be an object");
    });

    it("missing expires_at returns error", () => {
      const { expires_at, ...rest } = validManifest;
      const result = validateManifestSchema(rest);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Missing or invalid expires_at field");
    });

    it("non-string expires_at returns error", () => {
      const invalid = { ...validManifest, expires_at: 123 };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Missing or invalid expires_at field");
    });

    it("missing channels returns error", () => {
      const { channels, ...rest } = validManifest;
      const result = validateManifestSchema(rest);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Missing or invalid channels field");
    });

    it("non-object channels returns error", () => {
      const invalid = { ...validManifest, channels: "not an object" };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toBe("Missing or invalid channels field");
    });

    it("channel with invalid sequence returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: "not a number",
            artifacts: validManifest.channels.stable.artifacts,
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sequence");
    });

    it("channel with negative sequence returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: -1,
            artifacts: validManifest.channels.stable.artifacts,
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sequence");
    });

    it("channel with float sequence returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10.5,
            artifacts: validManifest.channels.stable.artifacts,
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sequence");
    });

    it("channel missing artifacts returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("missing artifacts");
    });

    it("artifact missing url returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                sha256: "a".repeat(64),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("missing or invalid url");
    });

    it("artifact with empty url returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "",
                sha256: "a".repeat(64),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("missing or invalid url");
    });

    it("artifact missing sha256 returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("missing or invalid sha256");
    });

    it("artifact with invalid sha256 format returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
                sha256: "not-64-hex-chars",
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sha256 format");
    });

    it("artifact with sha256 too short returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
                sha256: "a".repeat(63),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sha256 format");
    });

    it("artifact with sha256 too long returns error", () => {
      const invalid = {
        ...validManifest,
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
                sha256: "a".repeat(65),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(invalid);
      expect(result.success).toBe(false);
      expect(result.error).toContain("invalid sha256 format");
    });

    it("multiple channels validated successfully", () => {
      const multiChannel = {
        expires_at: "2026-12-31T23:59:59Z",
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
                sha256: "a".repeat(64),
              },
            },
          },
          beta: {
            sequence: 15,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app-beta.msi",
                sha256: "b".repeat(64),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(multiChannel);
      expect(result.success).toBe(true);
    });

    it("multiple artifacts per channel validated successfully", () => {
      const multiArtifact = {
        expires_at: "2026-12-31T23:59:59Z",
        channels: {
          stable: {
            sequence: 10,
            artifacts: {
              windows_x64: {
                url: "https://example.com/app.msi",
                sha256: "a".repeat(64),
              },
              darwin_x64: {
                url: "https://example.com/app.dmg",
                sha256: "b".repeat(64),
              },
            },
          },
        },
      };
      const result = validateManifestSchema(multiArtifact);
      expect(result.success).toBe(true);
    });
  });

  describe("parseRSA2048PublicKey", () => {
    it("missing PEM headers throws error", async () => {
      const invalidKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
      await expect(parseRSA2048PublicKey(invalidKey)).rejects.toThrow("Invalid PEM format");
    });

    it("invalid base64 throws error", async () => {
      const invalidKey = "-----BEGIN PUBLIC KEY-----\n!!!invalid!!!\n-----END PUBLIC KEY-----";
      await expect(parseRSA2048PublicKey(invalidKey)).rejects.toThrow("Invalid PEM key");
    });

    it("TODO placeholder throws error", async () => {
      const todoKey = "-----BEGIN PUBLIC KEY-----\nTODO_REPLACE_WITH_BASE64_X\n-----END PUBLIC KEY-----";
      await expect(parseRSA2048PublicKey(todoKey)).rejects.toThrow("Invalid PEM key");
    });
  });
});

async function generateRSA2048KeyPair(): Promise<{ privateKey: JsonWebKey, publicKey: Uint8Array }> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );

  const publicKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  const publicKeySpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);

  return {
    privateKey: privateKeyJwk as JsonWebKey,
    publicKey: new Uint8Array(publicKeySpki),
  };
}

async function signWithRSA2048PSS(message: Uint8Array, privateKey: JsonWebKey): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateKey,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    message as unknown as BufferSource
  );

  return new Uint8Array(signature);
}
