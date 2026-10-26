# Go library architecture for bouncer

## Verdict

- Keep public contracts in `bouncer`; `pow` and `store/memory` are stdlib-only leaves that never import root, so a default memory store avoids a cycle.
- Use sealed functional options; `New` returns `*Gate`; no registry, `init()`, or mutable globals.
- Inject `Clock`/`Store`; use `challengetest`; synctest only for goroutines; golden JSON rejects `answer`/`x`/`target`.
- `gofmt`, `go vet`, staticcheck 2026.2.2, govulncheck v1.9.0; one Linux CI job plus a weekly cron.
- Freeze v1 after two unchanged minors; deprecate one minor ahead; after v1 no methods added to `Store`/`Challenger`.

## Facts

Read at Go 1.26.0, chi v5.2.1, go-redis v9.22.0, client_golang v1.24.1, grpc-go v1.83.1. Latest tags on 2026-10-27 were chi v5.5.0, go-redis v9.23.0, client_golang v1.25.0, grpc-go v1.84.0 (version metadata only; newer code unverified).

- **net/http** pairs a one-method consumer interface (`Handler`) with a function adapter (`HandlerFunc`), concrete `*ServeMux`, a consumer-side `RoundTripper`, and optional capability interfaces (`Flusher`, `Hijacker`). Test helpers live in `httptest`, not the core package. Go 1.22 changed mux patterns, not this shape.
- **io/fs** has one-method `FS`, separate capability interfaces (`ReadFileFS`, `ReadDirFS`, `StatFS`) found by type assertion, and `testing/fstest.TestFS` as a reusable contract suite — the best small-interface model.
- **database/sql** puts driver contracts in the leaf `database/sql/driver` package to avoid cycles, but wires drivers through global `sql.Register` plus blank imports. `sql.Open` returns concrete `*DB`; the registry cannot be unregistered outside tests.
- **grpc-go** seals `DialOption` with an unexported `apply(*dialOptions)` and returns `*ClientConn`; `resolver.Builder` is open but selected through global `resolver.Register`. Functional options scale; registries hide state.
- **redis/go-redis** uses a public `Options` struct and `NewClient(*Options) *Client`. `UniversalClient` returns an interface hiding three clients, but embeds the enormous `Cmdable` method set — a warning on interface width.
- **prometheus/client_golang** defines open `Collector`, `Registerer`, and `Gatherer`; `NewRegistry() *Registry` is concrete. Docs recommend accepting `Registerer` for testability, while `DefaultRegisterer`/`MustRegister` remain global. **chi** returns concrete `*Mux` from `NewRouter()` while documenting `Router`; middleware is stdlib `func(http.Handler) http.Handler`; its `go.mod` is dependency-free and declares `go 1.20`.
- **Go modules**: v0.x has no compatibility promise; v1+ breaking changes need a `/v2` path. Deprecation is a doc paragraph starting `Deprecated:`. `testing/synctest` is GA since Go 1.25 but fakes `time`, not an injected `Clock`.

## Options

| Decision | Alternatives | Trade-off | Choice |
| --- | --- | --- | --- |
| Layout | Flat root; root + adapters; micro-packages | Flat hides boundaries; micro-packages multiply paths | Root + four adapters |
| Config | Options; public struct; globals | Options preserve invariants; struct exposes knobs; globals are untestable | 7 options + 1 verify option |
| Contracts | Root; leaf `store`; producer | Root matches design; leaf avoids cycles but adds aliases; producer forces deps | Root, structural leaves |
| Default store | Built-in memory; required `WithStore`; global | Built-in is ergonomic but must be bounded; required store adds setup; global leaks tests | Bounded built-in memory |
| Lint | Vet; staticcheck; golangci-lint | Vet is zero-install; staticcheck high signal; golangci-lint adds config churn | Vet + staticcheck |
| Modules | One; nested Redis | One leaks Redis deps; nested needs tags/CI | Nested `store/redis` |

## Recommendation

### Layout and direction

```
bouncer/
  doc.go bouncer.go option.go types.go
  challenger.go interaction.go store.go clock.go
  internal/ticket/   AEAD/HKDF/codec
  internal/score/    trajectory
  pow/               primitives
  store/memory/      bounded store
  store/storetest/   contract suite
  httpx/             net/http
  challengetest/     fakes
  web/               embedded assets
  attack/ bench/     experiments (not stable)
  store/redis/       own go.mod
```

`bouncer` imports only stdlib, `internal/*`, `pow`, `store/memory`; never `httpx`, `challengetest`, `store/storetest`, `store/redis`, `web`, `attack`, `bench`. `pow` and `store/memory` import only stdlib and cannot import root. Root asserts `var _ Store = (*memory.Store)(nil)`; `memory.Store` satisfies `Store` structurally because `Store` uses only `context`, `string`, `time.Duration`, `int32`. Adapters import root; `httpx` takes `*bouncer.Gate`. No `pkg/`, `util/`, `common/`, or `types/`.

`Challenger`, `Store`, `Clock`, `InteractionValidator` live in root because `Gate` consumes them; `Option`/`VerifyOption` are sealed. `pow` exposes functions, not `Challenger` (that would import root). `memory.New() *Store` is concrete; `challengetest` is the fake set; `store/storetest` the contract suite.

### API and errors

`New(opts ...Option) (*Gate, error)` returns concrete. Options apply once; `Gate` is immutable and concurrency-safe. `WithSecret` requires 32+ bytes; nil store/challenger/clock returns an error, not a panic. `WithTTL`/`WithDegree` clamp to documented ranges. Default `memory.New()` is capped at 100,000 entries (~20–30 MB), evicting expired first; unbounded memory is a DoS.

Expose sentinel errors (`ErrInvalidToken`, `ErrExpired`, `ErrSubjectMismatch`, `ErrConsumed`, `ErrAttemptsExceeded`, `ErrClosed`, `ErrStore`) wrapped with `%w`; use `errors.Is`, never strings. `Verify` returns `(*Verdict, error)`, never a partial verdict. `Solution` implements `slog.LogValuer`; `String()` and logs are redacted. `Close` is idempotent and does not close an injected `Store`. `Tier` has `String()` and stable numeric values; unknown values are rejected at `Issue`.

Core stays stdlib-only because it handles secrets and users cannot replace it: no third-party crypto, no `go.sum`, no transitive CVE surface, no dependency major breakage. CI asserts `go list -m all` prints only the root module. Optional integrations pay their own dependency cost.

### Testing

Use external `bouncer_test` for the public surface, internal tests for `internal/ticket`/`internal/score`. Inject `Clock`, `Store`, and `Challenger`; inject `io.Reader` only into the unexported ticket constructor so public `New` always uses `crypto/rand.Reader`. Table tests cover escalation, TTL boundaries, subject binding, consume-after-verify, store fail-closed/fail-open, and every sentinel error. `store/storetest.Run` checks memory and Redis identically; `challengetest` supplies a fake clock, fixed challenger, and assertions.

`synctest.Test` suits the memory cleanup goroutine, concurrent `Attempt`, and cancellation; never combine it with an injected fake clock, since synctest fakes `time`, not `Clock`. `ExampleEscalate`/`ExampleTier_String` have deterministic output. Golden tests use an in-package deterministic reader and `testdata/challenge.golden.json`; HTTP tests use `httptest.NewRecorder`. A recursive key-walker over challenge/response JSON rejects `answer`, `x`, `target`; a reflection test rejects `Challenge.Answer`. Normalize random tokens externally. Fuzz `FuzzTicketParse`/`FuzzPoWVerify` 30s nightly, not per PR. Gate root coverage 85%, ticket codec 95% at v1.

### Tooling and CI

Use `gofmt -l` (fail on output), `go vet ./...`, staticcheck 2026.2.2, govulncheck v1.9.0. Skip golangci-lint while small; if contributors grow, v2.15.0 with `govet`, `staticcheck`, `errcheck`, `ineffassign`, `unused` is the alternative.

One workflow: `push` to main, `pull_request` ignoring `docs/**`, weekly govulncheck cron. One `ubuntu-latest` job, `timeout-minutes: 10`, `contents: read`, concurrency cancel-in-progress, `setup-go` with `go-version-file: go.mod`, pinned tool versions and action SHAs. Steps: gofmt, vet, `go test -race -shuffle=on -count=1 ./...`, staticcheck, govulncheck, `go list -m all` guard. Add a `store/redis` job only when it changes; its Redis service stays off the default PR path. No OS matrix; add a release-tag cross-compile if desired. Public-repo runners are free: minutes per PR plus four cron runs monthly.

### Stability

`v0.1.0` starts the series. Break only in minors (`v0.2.0`, never `v0.1.1`), announce in the changelog, deprecate one minor before removal. `v1.0.0` requires two unchanged minors, reviewed API diff against `v0.9.0`, two external integrations, a clean one-hour fuzz run, and clean govulncheck. After v1: semver; `Deprecated:` lasts one minor and six months; removal only in v2 at `/v2`. Interfaces are frozen: adding a method to `Store`/`Challenger` is breaking, so new capabilities become optional interfaces asserted by `Gate`. Exported structs are keyed-literal-only; rely on `go vet` composites. A new `Tier` constant may break exhaustive switches; document it. Raising `go` is a minor with notice; support the latest two Go minors.

## Risks & unknowns

- Structural `store/memory` is subtle: root catches drift, but a contributor may import root and create a cycle. If confusing, add a `bouncer/store` contract package and alias `bouncer.Store`.
- A default memory store is a DoS surface; cap, eviction, and cleanup need measurement. Fail-closed makes a low cap visible.
- `Challenger` may need a fourth method; validate with two non-PoW implementations before v1.
- Golden JSON is encoder-sensitive; keep semantic assertions beside each file.
- The nested Redis module is invisible to root `go test ./...`; without CI it rots. Tags need `store/redis/vX.Y.Z`.
- `Solution` has exported fields; `json.Marshal` leaks the answer. Test that handlers never serialize it; document it as input-only.
- Tool/quota changes need pin checks; Go 1.26 minimum limits adoption.

## Sources

1. Go 1.26.0 net/http: https://cs.opensource.google/go/go/+/refs/tags/go1.26.0:src/net/http/server.go and `client.go`
2. Go 1.26.0 io/fs: https://cs.opensource.google/go/go/+/refs/tags/go1.26.0:src/io/fs/fs.go
3. Go 1.26.0 database/sql: https://cs.opensource.google/go/go/+/refs/tags/go1.26.0:src/database/sql/sql.go
4. Go 1.26.0 database/sql/driver: https://cs.opensource.google/go/go/+/refs/tags/go1.26.0:src/database/sql/driver/driver.go
5. grpc-go v1.83.1 dialoptions: https://github.com/grpc/grpc-go/blob/v1.83.1/dialoptions.go
6. grpc-go v1.83.1 resolver: https://github.com/grpc/grpc-go/blob/v1.83.1/resolver/resolver.go
7. go-redis v9.22.0 options: https://github.com/redis/go-redis/blob/v9.22.0/options.go
8. go-redis v9.22.0 universal: https://github.com/redis/go-redis/blob/v9.22.0/universal.go
9. client_golang v1.24.1 registry: https://github.com/prometheus/client_golang/blob/v1.24.1/prometheus/registry.go
10. client_golang v1.24.1 collector: https://github.com/prometheus/client_golang/blob/v1.24.1/prometheus/collector.go
11. chi v5.2.1 router: https://github.com/go-chi/chi/blob/v5.2.1/chi.go
12. Go 1.22 ServeMux: https://go.dev/doc/go1.22
13. Go 1.25 release notes: https://go.dev/doc/go1.25
14. testing/synctest: https://pkg.go.dev/testing/synctest
15. Go module versions: https://go.dev/ref/mod#versions
16. Deprecation convention: https://go.dev/wiki/Deprecated
17. staticcheck: https://staticcheck.dev/
18. govulncheck v1.9.0: https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
19. golangci-lint v2.15.0: https://github.com/golangci/golangci-lint/releases/tag/v2.15.0
20. GitHub Actions billing: https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions
