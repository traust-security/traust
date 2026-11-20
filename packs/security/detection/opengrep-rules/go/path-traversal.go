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
	_ = os.WriteFile(target, []byte("archive payload"), 0o600)

	// A directory-separator boundary rejects sibling prefixes such as
	// /srv/uploads-other. This lexical check assumes no untrusted symlinks.
	root, err := filepath.Abs(dst)
	if err != nil {
		return
	}
	if strings.HasPrefix(filepath.Clean(filepath.Join(root, hdr.Name)), root+string(os.PathSeparator)) {
		// ok: traust-go-path-traversal-tar-slip
		safe := filepath.Join(root, hdr.Name)
		_ = os.WriteFile(safe, []byte("archive payload"), 0o600)
	}
}

func saveBody(w http.ResponseWriter, r *http.Request) {
	// Content is request controlled, but the filesystem path is fixed.
	// ok: traust-go-path-traversal-taint
	os.WriteFile("/data/current.txt", []byte(r.FormValue("content")), 0o600)
}
