import { describe, it, expect } from "bun:test";

import { checkAdvisoryAppendOnly } from "./check-advisory-append-only.mjs";

const entry = (id: string, title = "t") => ({
  id,
  severity: "high",
  title,
  summary: "s",
  affected_versions: [],
  published_at: "2026-08-01T00:00:00Z",
  details_url: "https://example.com",
  cve_ids: [],
  cwe_ids: [],
});

describe("checkAdvisoryAppendOnly", () => {
  it("accepts a pure append", () => {
    const prev = [entry("MG-SEC-2026-0001")];
    const curr = [...prev, entry("MG-SEC-2026-0002")];
    const result = checkAdvisoryAppendOnly(prev, curr);
    expect(result.ok).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("rejects a modified existing entry", () => {
    const prev = [entry("MG-SEC-2026-0001", "old title")];
    const curr = [entry("MG-SEC-2026-0001", "edited title")];
    const result = checkAdvisoryAppendOnly(prev, curr);
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain("MG-SEC-2026-0001");
  });

  it("rejects a removed entry", () => {
    const prev = [entry("MG-SEC-2026-0001"), entry("MG-SEC-2026-0002")];
    const curr = [entry("MG-SEC-2026-0001")];
    const result = checkAdvisoryAppendOnly(prev, curr);
    expect(result.ok).toBe(false);
    expect(result.errors[0]).toContain("MG-SEC-2026-0002");
  });

  it("accepts an identical feed", () => {
    const prev = [entry("MG-SEC-2026-0001")];
    expect(checkAdvisoryAppendOnly(prev, [...prev]).ok).toBe(true);
  });
});
