import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import test from "node:test";

import { hex, leadingZeroBits, sha256 } from "./sha256.js";

test("matches node:crypto for single-block inputs", () => {
  for (const length of [0, 1, 13, 32, 37, 55]) {
    for (let i = 0; i < 25; i++) {
      const input = randomBytes(length);
      assert.equal(hex(sha256(input)), createHash("sha256").update(input).digest("hex"));
    }
  }
});

test("rejects inputs above one block", () => {
  assert.throws(() => sha256(new Uint8Array(56)), RangeError);
});

test("counts leading zero bits", () => {
  assert.equal(leadingZeroBits(new Uint8Array(32)), 256);
  assert.equal(leadingZeroBits(Uint8Array.from([0, 0, 0x80])), 16);
  assert.equal(leadingZeroBits(Uint8Array.from([0x01])), 7);
});
