package rules

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func proxyPassthrough(w http.ResponseWriter, r *http.Request) {
	out, _ := http.NewRequest("GET", "http://upstream.svc", nil)

	// ruleid: traust-go-authentication-forwarded-identity-passthrough
	out.Header = r.Header

	// ruleid: traust-go-authentication-forwarded-identity-passthrough
	out.Header.Set("X-Forwarded-Access-Token", r.Header.Get("X-Forwarded-Access-Token"))

	// ruleid: traust-go-authentication-forwarded-identity-passthrough
	out.Header.Add("X-Forwarded-Email", r.Header.Get("X-Forwarded-Email"))
}

func proxyStripped(w http.ResponseWriter, r *http.Request) {
	out, _ := http.NewRequest("GET", "http://upstream.svc", nil)
	r.Header.Del("X-Forwarded-Access-Token")

	// ok: traust-go-authentication-forwarded-identity-passthrough
	out.Header = r.Header
}

func proxyLoopStripped(w http.ResponseWriter, r *http.Request) {
	out, _ := http.NewRequest("GET", "http://upstream.svc", nil)
	for _, h := range []string{"X-Forwarded-User", "X-Forwarded-Email", "X-Forwarded-Access-Token"} {
		r.Header.Del(h)
	}

	// ok: traust-go-authentication-forwarded-identity-passthrough
	out.Header = r.Header
}

func benignHeaderRead(r *http.Request) string {
	// ok: traust-go-authentication-forwarded-identity-passthrough
	return r.Header.Get("X-Forwarded-User")
}

func strippedReverseProxy(target *url.URL) {
	// this FILE deletes identity headers (proxyStripped/proxyLoopStripped
	// above), so the reverse-proxy co-occurrence branch stays silent
	// ok: traust-go-authentication-forwarded-identity-passthrough
	proxy := httputil.NewSingleHostReverseProxy(target)
	_ = proxy
}
