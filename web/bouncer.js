// Browser helper for bouncer: fetch a challenge, solve it in a worker, verify.
//
// Usage:
//   import { solveChallenge } from "./bouncer.js";
//   await solveChallenge();            // sets the bouncer_pass cookie
//   await solveChallenge("/api");      // mount point prefix
//
// The pass cookie is issued by the server; this module never sees a secret.

const DEFAULT_BASE = "/";

export async function challenge(base = DEFAULT_BASE, tier) {
  const response = await fetch(new URL(`${trimBase(base)}_bouncer/challenge`, location.origin), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(tier ? { tier } : {}),
    credentials: "same-origin",
  });
  if (!response.ok) throw new Error(`bouncer: challenge failed (${response.status})`);
  return response.json();
}

export async function verify(token, answer, base = DEFAULT_BASE) {
  const response = await fetch(new URL(`${trimBase(base)}_bouncer/verify`, location.origin), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, answer }),
    credentials: "same-origin",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(`bouncer: ${body.error || "verification failed"}`);
  }
  return response.json();
}

// solve computes the proof of work in a dedicated worker so the UI thread
// stays responsive.
export function solve(params, workerUrl = new URL("./worker.js", import.meta.url)) {
  if (params.alg !== "sha256") return Promise.reject(new Error(`bouncer: unsupported algorithm ${params.alg}`));
  if (params.degree > 24) return Promise.reject(new Error("bouncer: difficulty above the browser budget"));
  const salt = hexToBytes(params.salt);
  const worker = new Worker(workerUrl, { type: "module" });
  return new Promise((resolve, reject) => {
    worker.onmessage = (event) => {
      worker.terminate();
      resolve(event.data.answer);
    };
    worker.onerror = (error) => {
      worker.terminate();
      reject(error);
    };
    worker.postMessage({ salt, degree: params.degree });
  });
}

export async function solveChallenge(base = DEFAULT_BASE, tier) {
  const issued = await challenge(base, tier);
  const answer = await solve(issued.params);
  return verify(issued.token, answer, base);
}

function trimBase(base) {
  if (!base) return DEFAULT_BASE;
  return base.endsWith("/") ? base : `${base}/`;
}

function hexToBytes(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
