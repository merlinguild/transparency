import type { IncomingMessage, ServerResponse } from "node:http";
import type { MockServerOptions } from "@/utils/mock/types";

const UNAUTHORIZED = 401;
const FOUND = 302;
const OK = 200;

const parseJwtPayload = (jwt: string): Record<string, unknown> | null => {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const decoded = Buffer.from(parts[1], "base64url").toString();
    return JSON.parse(decoded);
  } catch {
    return null;
  }
};

export const createDownloadHandler = (
  baseUrl: string,
  options: MockServerOptions
) => {
  const mockMsi = Buffer.from("mock-msi-content-v1-fixed-bytes-for-testing");

  return {
    handleDownload: (req: IncomingMessage, res: ServerResponse): void => {
      const auth = req.headers.authorization || "";
      const jwt = auth.replace(/^Bearer\s+/i, "");

      if (!jwt) {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("Missing Authorization header");
        return;
      }

      if (jwt.split(".").length !== 3) {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("Invalid JWT format");
        return;
      }

      if (options.failMode === "invalid_jwt") {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("Invalid JWT signature");
        return;
      }

      if (options.failMode === "expired_jwt") {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("JWT expired");
        return;
      }

      const payload = parseJwtPayload(jwt);
      if (!payload) {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("Invalid JWT payload");
        return;
      }

      if (options.revokedJtis.has(String(payload.jti))) {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("JTI revoked");
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      if (payload.exp && Number(payload.exp) < now) {
        res.writeHead(UNAUTHORIZED, { "Content-Type": "text/plain" });
        res.end("JWT expired");
        return;
      }

      res.writeHead(FOUND, { Location: `${baseUrl}/mock-msi` });
      res.end();
    },

    serveMockMsi: (res: ServerResponse): void => {
      res.writeHead(OK, {
        "Content-Type": "application/octet-stream",
        "Content-Length": mockMsi.length.toString(),
      });
      res.end(mockMsi);
    },
  };
};
