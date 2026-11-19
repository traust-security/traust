package rules

// ruleid: traust-go-network-exposure-pprof-import
import _ "net/http/pprof"

import "net/http"

func serve() {
	// A dedicated production mux does not inherit pprof's default-mux routes.
	// The import remains an inventory hit; it does not prove public exposure.
	// ok: traust-go-network-exposure-pprof-import
	http.ListenAndServe(":8443", http.NewServeMux())
}

func debugLocal() {
	// ok: traust-go-network-exposure-pprof-import
	http.ListenAndServe("127.0.0.1:6060", nil)
}
