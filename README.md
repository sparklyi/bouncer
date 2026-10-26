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
| L1 cost | Proof of work with an escalation ladder (16 → 28 bits) | cheap scripts, credential stuffing, form spam |
| L2 interaction | Slide challenge scored server-side on trajectory features | headless browsers, coordinate-replay scripts |

## Non-goals

Not an image CAPTCHA library. Not a WAF or a risk engine. No behavioral profiling,
no fingerprinting, no third-party calls. It proves computational work, not humanity.

## Documentation

- [`docs/design.md`](docs/design.md) — approved design, protocol, public API
- [`docs/research/`](docs/research/) — research notes per stage

## License

MIT
