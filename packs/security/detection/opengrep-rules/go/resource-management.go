package rules

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func clients() {
	// ruleid: traust-go-resource-management-http-client-no-timeout
	c1 := &http.Client{}

	// ruleid: traust-go-resource-management-http-client-no-timeout
	c2 := http.Client{Transport: http.DefaultTransport}

	// ok: traust-go-resource-management-http-client-no-timeout
	c3 := &http.Client{Timeout: 30 * time.Second}

	c4 := &http.Client{Transport: http.DefaultTransport}
	// sanitizer: Timeout assigned after construction
	c4.Timeout = 30 * time.Second

	_, _, _, _ = c1, c2, c3, c4
}

func servers(mux *http.ServeMux) {
	// ruleid: traust-go-resource-management-http-server-no-timeouts
	s1 := &http.Server{Addr: ":8080", Handler: mux}

	// ok: traust-go-resource-management-http-server-no-timeouts
	s2 := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second}

	// ok: traust-go-resource-management-http-server-no-timeouts
	s3 := http.Server{Addr: ":8080", WriteTimeout: 30 * time.Second}

	s4 := &http.Server{Addr: ":8080", Handler: mux}
	// sanitizer: timeout assigned after construction
	s4.IdleTimeout = 60 * time.Second

	_, _, _, _ = s1, s2, s3, s4
}

func handlerUnbounded(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-resource-management-unbounded-request-body-read
	body, _ := io.ReadAll(r.Body)

	// ruleid: traust-go-resource-management-unbounded-request-body-read
	legacy, _ := ioutil.ReadAll(r.Body)

	var buf bytes.Buffer
	// ruleid: traust-go-resource-management-unbounded-request-body-read
	io.Copy(&buf, r.Body)

	_, _ = body, legacy
}

func handlerBounded(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	// ok: traust-go-resource-management-unbounded-request-body-read
	body, _ := io.ReadAll(r.Body)
	_ = body
}

func clientResponse(resp *http.Response) {
	// ok: traust-go-resource-management-unbounded-request-body-read
	body, _ := io.ReadAll(resp.Body)
	_ = body
}
