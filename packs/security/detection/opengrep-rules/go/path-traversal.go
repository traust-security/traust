package rules

import (
	"archive/tar"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	// ruleid: traust-go-path-traversal-taint
	os.ReadFile("/data/" + r.URL.Query().Get("name"))

	// ruleid: traust-go-path-traversal-taint
	http.ServeFile(w, r, filepath.Join("/reports", r.FormValue("file")))

	// ok: traust-go-path-traversal-taint
	os.ReadFile(filepath.Join("/data", filepath.Base(r.URL.Query().Get("name"))))

	// ok: traust-go-path-traversal-taint
	os.ReadFile("/etc/config/static.yaml")
}

func extract(dst string, hdr *tar.Header) {
	// ruleid: traust-go-path-traversal-tar-slip
	target := filepath.Join(dst, hdr.Name)
	_ = target

	if strings.HasPrefix(filepath.Clean(filepath.Join(dst, hdr.Name)), dst) {
		// ok: traust-go-path-traversal-tar-slip
		safe := filepath.Join(dst, hdr.Name)
		_ = safe
	}
}
