// CLI used by the Go cross-language test: prints the answer for a salt/degree.
import { hex, leadingZeroBits, sha256 } from "./sha256.js";

const TAG = new TextEncoder().encode("bouncer/pow/v1");
const [saltHex, degreeArg] = process.argv.slice(2);
const degree = Number.parseInt(degreeArg, 10);
const preimage = new Uint8Array(TAG.length + 16 + 8);
preimage.set(TAG, 0);
preimage.set(hexToBytes(saltHex), TAG.length);
const view = new DataView(preimage.buffer);

for (let nonce = 1; ; nonce++) {
  view.setUint32(TAG.length + 16, Math.floor(nonce / 0x100000000));
  view.setUint32(TAG.length + 20, nonce >>> 0);
  if (leadingZeroBits(sha256(preimage)) >= degree) {
    const out = new Uint8Array(8);
    const outView = new DataView(out.buffer);
    outView.setUint32(0, Math.floor(nonce / 0x100000000));
    outView.setUint32(4, nonce >>> 0);
    process.stdout.write(hex(out));
    break;
  }
}

function hexToBytes(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
