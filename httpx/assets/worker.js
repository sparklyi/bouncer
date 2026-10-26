// Classic worker for the bouncer widget: single-block SHA-256 plus the nonce
// loop. Served from the same origin as the page, so no blob: or CSP exception
// is needed.
"use strict";

var K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

var H0 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

var TAG = new TextEncoder().encode("bouncer/pow/v1");
var PREIMAGE = new Uint8Array(TAG.length + 16 + 8);
PREIMAGE.set(TAG, 0);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function sha256(bytes) {
  var block = new Uint8Array(64);
  block.set(bytes);
  block[bytes.length] = 0x80;
  var view = new DataView(block.buffer);
  var bits = bytes.length * 8;
  view.setUint32(56, Math.floor(bits / 0x100000000));
  view.setUint32(60, bits >>> 0);

  var w = new Uint32Array(64);
  var i;
  for (i = 0; i < 16; i++) w[i] = view.getUint32(i * 4);
  for (i = 16; i < 64; i++) {
    var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
    var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  var a = H0[0], b = H0[1], c = H0[2], d = H0[3];
  var e = H0[4], f = H0[5], g = H0[6], h = H0[7];
  for (i = 0; i < 64; i++) {
    var t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) >>> 0;
    var t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + t1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (t1 + t2) >>> 0;
  }

  var out = new Uint8Array(32);
  var outView = new DataView(out.buffer);
  var state = [a, b, c, d, e, f, g, h];
  for (i = 0; i < 8; i++) outView.setUint32(i * 4, (H0[i] + state[i]) >>> 0);
  return out;
}

function leadingZeroBits(digest) {
  var total = 0;
  for (var i = 0; i < digest.length; i++) {
    var byte = digest[i];
    if (byte === 0) {
      total += 8;
      continue;
    }
    return total + Math.clz32(byte) - 24;
  }
  return total;
}

function hex(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, "0");
  return out;
}

self.onmessage = function (event) {
  var salt = event.data.salt;
  var degree = event.data.degree;
  PREIMAGE.set(salt, TAG.length);
  var view = new DataView(PREIMAGE.buffer);
  var nonce = 1 + Math.floor(Math.random() * 0xffff);

  for (;;) {
    view.setUint32(TAG.length + 16, Math.floor(nonce / 0x100000000));
    view.setUint32(TAG.length + 20, nonce >>> 0);
    if (leadingZeroBits(sha256(PREIMAGE)) >= degree) {
      var raw = new Uint8Array(8);
      var rawView = new DataView(raw.buffer);
      rawView.setUint32(0, Math.floor(nonce / 0x100000000));
      rawView.setUint32(4, nonce >>> 0);
      self.postMessage({ answer: hex(raw) });
      return;
    }
    nonce += 1;
  }
};
