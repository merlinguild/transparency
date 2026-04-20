export const sha256Bytes = async (data: Uint8Array): Promise<Uint8Array> => {
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return new Uint8Array(hashBuffer);
};

export const signManifest = async (
  manifestBytes: Uint8Array,
  privateKeyJwk: JsonWebKey
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "jwk",
    privateKeyJwk,
    { name: "RSA-PSS", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    manifestBytes as unknown as BufferSource
  );

  return Buffer.from(signature).toString("base64url").replace(/=+$/, "");
};

export const modifyManifestBytes = (manifestBytes: Uint8Array): Uint8Array => {
  const modified = new Uint8Array(manifestBytes);
  modified[Math.floor(modified.length / 2)] ^= 0xff;
  return modified;
};
