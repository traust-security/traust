package rules

import (
	"context"
	"net/http"
	"net/url"
	"strings"
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
	// Parsing alone is not validation. This fixture checks a trusted host,
	// scheme and authority, and disables redirects to preserve that boundary.
	// DNS/egress policy must also prevent rebinding of the trusted hostname.
	u, err := url.Parse(r.URL.Query().Get("endpoint"))
	if err != nil || u.Scheme != "https" || u.Host != "api.openshift.com" || u.User != nil {
		return
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	// ok: traust-go-ssrf-request-taint
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return
	}
	client.Do(req)
}

// Generated-client false positives (*.gen.go, *_gen.go, *generated*) are
// excluded by paths filters at scan time, not in opengrep test fixtures.

func submitContent(w http.ResponseWriter, r *http.Request) {
	// Request-controlled body content must not taint the fixed URL sink.
	// ok: traust-go-ssrf-request-taint
	http.Post("https://api.openshift.com/submit", "text/plain", strings.NewReader(r.FormValue("content")))
	// ok: traust-go-ssrf-request-taint
	http.NewRequest("POST", "https://api.openshift.com/submit", strings.NewReader(r.FormValue("content")))
}
