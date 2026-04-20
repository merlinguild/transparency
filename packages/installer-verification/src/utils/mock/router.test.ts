import { describe, it, expect } from "bun:test";

import { SimpleRouter } from "./router";

describe("SimpleRouter", () => {
  it("populates route params for :name segments", () => {
    const router = new SimpleRouter();
    let seen: Record<string, string> | null = null;
    router.get("/download/:msiName", (_req, _res, params) => {
      seen = params;
    });

    const handled = router.handle(
      "GET",
      "/download/merlinguild-26.4.1.msi",
      {} as never,
      {} as never,
    );

    expect(handled).toBe(true);
    expect(seen).toEqual({ msiName: "merlinguild-26.4.1.msi" });
  });

  it("returns an empty params object for static routes", () => {
    const router = new SimpleRouter();
    let seen: Record<string, string> | null = null;
    router.get("/manifest.json", (_req, _res, params) => {
      seen = params;
    });

    router.handle("GET", "/manifest.json", {} as never, {} as never);

    expect(seen).toEqual({});
  });

  it("does not match unknown paths", () => {
    const router = new SimpleRouter();
    router.get("/download/:msiName", () => {});

    expect(router.handle("GET", "/other", {} as never, {} as never)).toBe(false);
    expect(router.handle("POST", "/download/x.msi", {} as never, {} as never)).toBe(false);
  });
});
