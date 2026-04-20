import { URL } from "node:url";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { SimpleRouter } from "@/utils/mock/router";
import { createManifestHandlers } from "@/utils/mock/handlers/manifest";
import { createDownloadHandler } from "@/utils/mock/handlers/download";
import type { MockServer, MockServerOptions, RequestLogEntry } from "@/utils/mock/types";

const NOT_FOUND = 404;
const METHOD_NOT_ALLOWED = 405;

export class MockWorkerServer implements MockServer {
  readonly #port: number;
  readonly #options: MockServerOptions;
  readonly #requestLog: RequestLogEntry[] = [];
  #server: Server | null = null;
  #router = new SimpleRouter();

  constructor(options: MockServerOptions) {
    this.#port = options.port;
    this.#options = options;
    this.#setupRoutes();
  }

  #setupRoutes(): void {
    const manifest = createManifestHandlers(this.#options);
    const download = createDownloadHandler(
      `http://localhost:${this.#port}`,
      this.#options
    );

    this.#router.get("/manifest.json", (_, res) => {
      manifest.serveManifestJson(res);
    });

    this.#router.get("/manifest.json.sig", (_, res) => {
      manifest.serveManifestSig(res);
    });

    this.#router.get("/download/:msiName", (req, res) => {
      download.handleDownload(req, res);
    });

    this.#router.get("/mock-msi", (_, res) => {
      download.serveMockMsi(res);
    });
  }

  async start(): Promise<void> {
    if (this.#options.failMode === "unreachable") {
      return;
    }

    this.#server = createServer((req, res) => {
      this.#logRequest(req);
      this.#handleRequest(req, res);
    });

    return new Promise((resolve) => {
      this.#server!.listen(this.#port, () => {
        console.log(`[MockWorker] Listening on http://localhost:${this.#port}`);
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    if (!this.#server) {
      console.log("[MockWorker] Stopped");
      return;
    }

    return new Promise((resolve) => {
      this.#server!.close(() => {
        console.log("[MockWorker] Stopped");
        this.#server = null;
        resolve();
      });
    });
  }

  getRequestLog(): readonly RequestLogEntry[] {
    return [...this.#requestLog];
  }

  clearRequestLog(): void {
    this.#requestLog.length = 0;
  }

  #logRequest(req: IncomingMessage): void {
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string") headers[key] = value;
    }
    this.#requestLog.push({
      method: req.method || "GET",
      path: req.url || "/",
      headers,
    });
  }

  #handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url || "/", `http://localhost:${this.#port}`);
    const method = req.method || "GET";

    if (this.#router.handle(method, url.pathname, req, res)) {
      return;
    }

    if (method !== "GET") {
      res.writeHead(METHOD_NOT_ALLOWED, { "Content-Type": "text/plain" });
      res.end("Method Not Allowed");
      return;
    }

    res.writeHead(NOT_FOUND, { "Content-Type": "text/plain" });
    res.end("Not Found");
  }
}
