package rules

import "net/url"

// The fixture only needs to parse — `prometheus.Labels{...}` and the
// metric calls are matched by shape, not by import resolution.

func metrics(password string, webhookToken string, tokenURL string, reason string, secretName string) {
	// ruleid: traust-go-secrets-management-credential-in-metric-label
	counter.With(prometheus.Labels{"webhook_password": password})

	// ruleid: traust-go-secrets-management-credential-in-metric-label
	counter.With(prometheus.Labels{"reason": reason, "auth_token": webhookToken})

	// ruleid: traust-go-secrets-management-credential-in-metric-label
	counter.With(prometheus.Labels{"target": password})

	// ruleid: traust-go-secrets-management-credential-in-metric-label
	gauge.WithLabelValues(webhookToken, reason)

	// ok: traust-go-secrets-management-credential-in-metric-label
	counter.With(prometheus.Labels{"reason": reason})

	// ok: traust-go-secrets-management-credential-in-metric-label
	counter.With(prometheus.Labels{"endpoint": tokenURL})

	// ok: traust-go-secrets-management-credential-in-metric-label
	gauge.WithLabelValues(secretName, reason)
}

func urlLabels(h urlShim, level levelShim, statusCode string) {
	// url.URL.String() preserves embedded userinfo — webhook URL label shape
	// ruleid: traust-go-secrets-management-credential-in-metric-label
	counter.WithLabelValues(h.String(), statusCode)

	// Matching boundary only: Redacted() masks a userinfo password, not
	// usernames or tokens carried in query parameters.
	// ok: traust-go-secrets-management-credential-in-metric-label
	counter.WithLabelValues(h.Redacted(), statusCode)

	// non-URL Stringer receivers are out of the name-constrained shape
	// ok: traust-go-secrets-management-credential-in-metric-label
	gauge.WithLabelValues(level.String())
}

func hostLabels(h *url.URL, statusCode string) {
	// A hostname-only label drops userinfo, path and query credential material.
	// The hostname itself must still be appropriate for metrics publication.
	// ok: traust-go-secrets-management-credential-in-metric-label
	counter.WithLabelValues(h.Hostname(), statusCode)
}
