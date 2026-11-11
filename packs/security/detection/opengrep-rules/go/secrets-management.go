package rules

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

	// fixed shape: Redacted() masks the password — no longer matches
	// ok: traust-go-secrets-management-credential-in-metric-label
	counter.WithLabelValues(h.Redacted(), statusCode)

	// non-URL Stringer receivers are out of the name-constrained shape
	// ok: traust-go-secrets-management-credential-in-metric-label
	gauge.WithLabelValues(level.String())
}
