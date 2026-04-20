import type { IncomingMessage, ServerResponse } from "node:http";

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";

export type RouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  params: Record<string, string>
) => void | Promise<void>;

export interface Route {
  method: HttpMethod;
  pattern: RegExp;
  handler: RouteHandler;
  paramNames?: string[];
}

export interface RequestLogEntry {
  method: string;
  path: string;
  headers: Record<string, string>;
}

export interface MockServerOptions {
  port: number;
  failMode: "none" | "unreachable" | "invalid_jwt" | "expired_jwt" | "revoked_jti";
  manifestJson: string;
  manifestSig: string;
  revokedJtis: Set<string>;
}

export interface MockServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  getRequestLog(): readonly RequestLogEntry[];
  clearRequestLog(): void;
}
