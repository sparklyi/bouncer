# bouncer

> Human verification for Go: zero dependencies, no images, server-side cost of one SHA-256 per check.

**Status: design phase.** This repository currently contains the design and research notes.
Implementation starts after the research review.

## Why

Existing Go CAPTCHA libraries share three structural weaknesses:

1. They hand the answer to the client (`Block.DX`/`DY`, or `Generate()` returning `answer`).
2. They have no attempt budget and no atomic one-time redemption.
3. Their difficulty is a constant, so attackers face a fixed, purchasable cost.

`bouncer` is a verification core that fixes all three, plus a measured attack baseline
so that "better" is a number, not an adjective.

## Layers

| Layer | Mechanism | Stops |
| --- | --- | --- |
| L0 state | Sealed ticket, answer never leaves the server, one-time redemption, attempt budget, subject binding, TTL | replay, brute force, cross-session reuse |
| L1 cost | Proof of work, degree 18 → 24 as failures accumulate | cheap scripts, credential stuffing, form spam |
| L2 interaction | Slide challenge scored server-side on trajectory features | headless browsers, coordinate-replay scripts |

L1 is a rate limiter, not an economic wall: 18 bits costs a browser ~0.3 s and a 4090
~40 µs. The README will publish measured cost per 1,000 successful breaks instead of
adjectives.

## Honest limits

It raises the cost of automated abuse; it does not stop a funded, targeted attacker
with residential proxies and human solvers, and it does not detect "human or AI".
Worst-case numbers go in the attack baseline, not in a marketing sentence.

## Non-goals

Not an image CAPTCHA library. Not a WAF or a risk engine. No behavioral profiling,
no fingerprinting, no third-party calls. It proves computational work, not humanity.

## Documentation

- [`docs/design.md`](docs/design.md) — approved design, protocol, public API
- [`docs/research/`](docs/research/) — research notes per stage, including the
  corrections they forced on the design

## License

MIT
