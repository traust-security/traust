package rules

import (
	"context"
	"net/http"
	"net/url"
)

func ssrf(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-ssrf-request-taint
	http.Get("https://" + r.URL.Query().Get("host") + "/status")

	// ruleid: traust-go-ssrf-request-taint
	http.NewRequest("GET", r.FormValue("url"), nil)

	// ruleid: traust-go-ssrf-request-taint
	http.NewRequestWithContext(context.TODO(), "POST", r.PostFormValue("target"), nil)

	// ok: traust-go-ssrf-request-taint
	http.Get("https://api.openshift.com/healthz")
}

func parsedAndValidated(w http.ResponseWriter, r *http.Request) {
	// sanitizer: structured parse precedes host validation — the
	// parse-then-validate idiom is the judge's business, not a raw taint
	u, err := url.Parse(r.URL.Query().Get("endpoint"))
	if err != nil || u.Hostname() != "api.openshift.com" {
		return
	}
	// ok: traust-go-ssrf-request-taint
	http.Get(u.String())
}

// Generated-client false positives (*.gen.go, *_gen.go, *generated*) are
// excluded by paths filters at scan time, not in opengrep test fixtures.
