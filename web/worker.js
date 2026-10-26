// Proof-of-work worker. One block per attempt, no allocations in the loop.
//
// Start nonces are randomized per worker so that several tabs or workers do not
// duplicate work.
import { hex, leadingZeroBits, sha256 } from "./sha256.js";

const TAG = new TextEncoder().encode("bouncer/pow/v1");
const PREIMAGE = new Uint8Array(TAG.length + 16 + 8);
PREIMAGE.set(TAG, 0);

self.onmessage = (event) => {
  const { salt, degree } = event.data;
  PREIMAGE.set(salt, TAG.length);
  const view = new DataView(PREIMAGE.buffer);
  let nonce = 1 + Math.floor(Math.random() * 0xffff);

  for (;;) {
    view.setUint32(TAG.length + 16, Math.floor(nonce / 0x100000000));
    view.setUint32(TAG.length + 20, nonce >>> 0);
    if (leadingZeroBits(sha256(PREIMAGE)) >= degree) {
      self.postMessage({ answer: hex(toBytes(nonce)) });
      return;
    }
    nonce += 1;
  }
};

function toBytes(nonce) {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setUint32(0, Math.floor(nonce / 0x100000000));
  view.setUint32(4, nonce >>> 0);
  return out;
}
