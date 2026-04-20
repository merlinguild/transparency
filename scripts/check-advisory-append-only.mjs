#!/usr/bin/env node

export function checkAdvisoryAppendOnly(prev, curr) {
  const errors = [];
  const prevById = new Map(prev.map((a) => [a.id, a]));

  for (const [id, oldEntry] of prevById) {
    const next = curr.find((a) => a.id === id);
    if (!next) {
      errors.push(`Advisory ${id} was removed (feed is append-only).`);
      continue;
    }
    if (JSON.stringify(oldEntry) !== JSON.stringify(next)) {
      errors.push(`Advisory ${id} was modified (feed is append-only).`);
    }
  }

  return { ok: errors.length === 0, errors };
}

if (import.meta.main) {
  const [prevPath, currPath] = process.argv.slice(2);
  if (!prevPath || !currPath) {
    console.error("usage: node check-advisory-append-only.mjs <prev.json> <curr.json>");
    process.exit(2);
  }
  const { readFileSync } = await import("node:fs");
  const prev = JSON.parse(readFileSync(prevPath, "utf-8"));
  const curr = JSON.parse(readFileSync(currPath, "utf-8"));

  const { ok, errors } = checkAdvisoryAppendOnly(prev, curr);
  for (const e of errors) console.error(e);
  if (!ok) process.exit(1);
  console.log(`Append-only check passed (${prev.length} -> ${curr.length}).`);
}
