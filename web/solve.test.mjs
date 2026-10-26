import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

test("CLI solver meets the requested difficulty", () => {
  const salt = "000102030405060708090a0b0c0d0e0f";
  const answer = execFileSync(process.execPath, ["solve.mjs", salt, "12"], { encoding: "utf8" });
  assert.match(answer, /^[0-9a-f]{16}$/);
});
