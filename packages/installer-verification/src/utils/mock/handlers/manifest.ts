import type { IncomingMessage, ServerResponse } from "node:http";
import type { MockServerOptions } from "@/utils/mock/types";

export const createManifestHandlers = (options: MockServerOptions) => ({
  serveManifestJson: (res: ServerResponse): void => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(options.manifestJson);
  },

  serveManifestSig: (res: ServerResponse): void => {
    res.writeHead(200, { "Content-Type": "application/octet-stream" });
    res.end(options.manifestSig);
  },
});
