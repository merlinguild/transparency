import type { IncomingMessage, ServerResponse } from "node:http";
import type { HttpMethod, Route, RouteHandler } from "./types";

export class SimpleRouter {
  readonly #routes: Route[] = [];

  add(method: HttpMethod, pattern: string, handler: RouteHandler): void {
    const paramNames = (pattern.match(/:\w+/g) ?? []).map((token) =>
      token.slice(1),
    );
    const regex = new RegExp(`^${pattern.replace(/:\w+/g, "([^/]+)")}$`);
    this.#routes.push({ method, pattern: regex, handler, paramNames });
  }

  get(pattern: string, handler: RouteHandler): void {
    this.add("GET", pattern, handler);
  }

  post(pattern: string, handler: RouteHandler): void {
    this.add("POST", pattern, handler);
  }

  handle(
    method: string,
    path: string,
    req: IncomingMessage,
    res: ServerResponse
  ): boolean {
    for (const route of this.#routes) {
      if (route.method !== method) continue;

      const match = path.match(route.pattern);
      if (!match) continue;

      const params: Record<string, string> = {};
      const names = route.paramNames ?? [];
      for (let i = 0; i < names.length; i++) {
        params[names[i]] = match[i + 1];
      }

      route.handler(req, res, params);
      return true;
    }

    return false;
  }
}
