# Example

```
go run ./example
```

Open <http://127.0.0.1:8090>. The first navigation hits the interstitial, the
widget solves an 18-bit challenge in a worker, the pass cookie is set, and the
page reloads. The key is created at `data/bouncer.key` on first run (mode 0600).

Integration surface: one `httpx.NewGuard`, one `guard.Protect`, one script tag.
