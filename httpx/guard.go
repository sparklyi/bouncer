package httpx

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/sparklyi/bouncer"
)

//go:embed assets/widget.js
var widgetJS []byte

//go:embed assets/worker.js
var workerJS []byte

// Guard is the drop-in integration: it serves the challenge endpoints and the
// browser widget, and gates any handler behind a pass.
//
//	guard := httpx.NewGuard(g)
//	http.Handle("/", guard.Protect(mux))
//
//	A page without a pass receives an interstitial that solves the challenge and
//	reloads; API calls receive 403 JSON and can await window.bouncer.verify().
type Guard struct {
	gate *bouncer.Gate
	opts options
	mux  *http.ServeMux
}

// NewGuard wraps an existing Gate with the default plugin behaviour.
func NewGuard(g *bouncer.Gate, opts ...Option) *Guard {
	o := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	o.prefix = normalizePrefix(o.prefix)
	guard := &Guard{gate: g, opts: o, mux: http.NewServeMux()}

	guard.mux.HandleFunc("POST "+o.prefix+"/challenge", func(w http.ResponseWriter, r *http.Request) {
		ChallengeHandler(g, WithDefaultTier(o.tier)).ServeHTTP(w, r)
	})
	guard.mux.HandleFunc("POST "+o.prefix+"/verify", func(w http.ResponseWriter, r *http.Request) {
		verifyOpts := []Option{WithCookieName(o.cookieName), WithPassTTL(o.passTTL), WithCookiePath(o.path), WithSecure(o.secure)}
		if !o.singleUse {
			verifyOpts = append(verifyOpts, WithReusablePass())
		}
		VerifyHandler(g, verifyOpts...).ServeHTTP(w, r)
	})
	guard.mux.HandleFunc("GET "+o.prefix+"/widget.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(widgetJS)
	})
	guard.mux.HandleFunc("GET "+o.prefix+"/worker.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(workerJS)
	})
	return guard
}

// Handler serves only the challenge endpoints and the widget assets. Use it
// when the application mounts them itself; otherwise prefer Protect.
func (g *Guard) Handler() http.Handler { return g.mux }

// Prefix reports the mount point, for templates and documentation.
func (g *Guard) Prefix() string { return g.opts.prefix }

// Protect serves the plugin endpoints and requires a pass for everything else.
func (g *Guard) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, g.opts.prefix+"/") {
			g.mux.ServeHTTP(w, r)
			return
		}
		if g.opts.exempt != nil && g.opts.exempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := VerifyPass(g.gate, r, passOptions(g.opts)...); err != nil {
			g.reject(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middleware is Protect as a standard middleware.
func (g *Guard) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return g.Protect(next) }
}

// RequirePass checks the pass and is meant for framework handlers (Gin, Echo)
// that want to keep their own error format on protected endpoints.
func (g *Guard) RequirePass(r *http.Request) (*bouncer.Verdict, error) {
	return VerifyPass(g.gate, r, passOptions(g.opts)...)
}

var interstitial = template.Must(template.New("bouncer").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 15px/1.5 system-ui, sans-serif; }
  main { text-align: center; max-width: 22rem; padding: 2rem; }
  .spinner { width: 28px; height: 28px; margin: 0 auto 1rem; border-radius: 50%;
             border: 3px solid currentColor; border-right-color: transparent;
             animation: spin .8s linear infinite; opacity: .5; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .failed .spinner { display: none; }
</style>
</head>
<body>
<main id="box">
  <div class="spinner" aria-hidden="true"></div>
  <p id="status">Checking your browser before continuing…</p>
  <noscript>JavaScript is required to verify this browser. Enable it and reload.</noscript>
</main>
<script src="{{.Prefix}}/widget.js" data-auto="false"></script>
<script>
  bouncer.verify().then(function () { location.reload(); }).catch(function () {
    document.getElementById("box").className = "failed";
    document.getElementById("status").textContent = "Verification failed. Reload the page to try again.";
  });
</script>
</body>
</html>
`))

func (g *Guard) reject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if wantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = interstitial.Execute(w, struct{ Prefix string }{Prefix: g.opts.prefix})
		return
	}
	writeError(w, http.StatusForbidden, "challenge_required", "human verification required")
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func normalizePrefix(prefix string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(prefix), "/")
	if trimmed == "" {
		return defaultPrefix
	}
	if !strings.HasPrefix(trimmed, "/") {
		return "/" + trimmed
	}
	return trimmed
}

// Guard reuses a pass for its whole TTL by default, like a browser-check
// cookie: a page load with many subresources must not consume the pass on the
// first request. WithPassSingleUse opts into one verification per request.
func passOptions(o options) []Option {
	opts := []Option{WithCookieName(o.cookieName), WithPassTTL(o.passTTL), WithCookiePath(o.path), WithSecure(o.secure)}
	if !o.singleUse {
		opts = append(opts, WithReusablePass())
	}
	return opts
}

// WithDefaultTier sets the challenge tier used when the client does not ask for
// one.
func WithDefaultTier(t bouncer.Tier) Option {
	return func(o *options) { o.tier = t }
}

// WithPrefix sets the mount point of the plugin endpoints. Default /_bouncer.
func WithPrefix(prefix string) Option {
	return func(o *options) { o.prefix = prefix }
}

// WithExempt marks requests that never require a pass, such as health checks.
func WithExempt(fn func(*http.Request) bool) Option {
	return func(o *options) { o.exempt = fn }
}
