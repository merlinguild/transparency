import { writeFileSync, readFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";

const TMP_DIR = join(import.meta.dirname, "..", "..", "..", ".tmp", "keys");

export interface KeyPair {
  privateKey: JsonWebKey;
  publicKey: Uint8Array;
  publicKeyPem: string;
  psHashTable: string;
}

const b64urlToB64 = (b64url: string): string => {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return b64;
};

const generateKeyPair = async (): Promise<KeyPair> => {
  const keyPair = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"]
  );

  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey) as JsonWebKey;
  const publicKeySpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyPem = await spkiToPem(new Uint8Array(publicKeySpki));

  const modulus = b64urlToB64(privateKeyJwk.n!);
  const exponent = b64urlToB64(privateKeyJwk.e!);
  const psHashTable = `\n  @{ Modulus = '${modulus}'; Exponent = '${exponent}' }\n`;

  return {
    psHashTable,
    privateKey: privateKeyJwk,
    publicKey: new Uint8Array(publicKeySpki),
    publicKeyPem,
  };
};

async function spkiToPem(spki: Uint8Array): Promise<string> {
  const b64 = Buffer.from(spki).toString("base64");
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----`;
}

interface SerializedKeyPair {
  privateKey: JsonWebKey;
  publicKeyBase64: string;
  publicKeyPem: string;
  psHashTable: string;
}

const serialize = (key: KeyPair): SerializedKeyPair => ({
  privateKey: key.privateKey,
  publicKeyBase64: Buffer.from(key.publicKey).toString("base64"),
  publicKeyPem: key.publicKeyPem,
  psHashTable: key.psHashTable,
});

const deserialize = (data: SerializedKeyPair): KeyPair => ({
  privateKey: data.privateKey,
  publicKey: new Uint8Array(Buffer.from(data.publicKeyBase64, "base64")),
  publicKeyPem: data.publicKeyPem,
  psHashTable: data.psHashTable,
});

export const ensureTestKey = async (): Promise<KeyPair> => {
  if (!existsSync(TMP_DIR)) {
    mkdirSync(TMP_DIR, { recursive: true });
  }

  const keyPath = join(TMP_DIR, "test-key.json");

  if (existsSync(keyPath)) {
    const data = JSON.parse(readFileSync(keyPath, "utf-8")) as SerializedKeyPair;
    return deserialize(data);
  }

  const key = await generateKeyPair();
  writeFileSync(keyPath, JSON.stringify(serialize(key), null, 2));
  return key;
};
