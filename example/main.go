// Command example is the smallest possible bouncer integration: one guard and
// one script tag. Run it with `go run ./example` and open
// http://127.0.0.1:8090. The first request shows the interstitial, solves a
// challenge in the browser, and then the page appears.
package main

import (
	"log"
	"net/http"

	"github.com/sparklyi/bouncer"
	"github.com/sparklyi/bouncer/httpx"
)

func main() {
	gate, err := bouncer.New(bouncer.WithSecretFile("data/bouncer.key"))
	if err != nil {
		log.Fatal(err)
	}
	defer gate.Close()

	guard := httpx.NewGuard(gate)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html>
<meta charset="utf-8">
<title>bouncer example</title>
<h1>Verified.</h1>
<p>This page is behind <code>guard.Protect</code>. The script tag below keeps a
fresh pass cookie so navigations stay instant.</p>
<script src="/_bouncer/widget.js" defer></script>
`))
	})
	mux.HandleFunc("POST /action", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	log.Println("listening on http://127.0.0.1:8090")
	if err := http.ListenAndServe("127.0.0.1:8090", guard.Protect(mux)); err != nil {
		log.Fatal(err)
	}
}
