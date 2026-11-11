package rules

// ruleid: traust-go-network-exposure-pprof-import
import _ "net/http/pprof"

import "net/http"

func serve() {
	// ok: traust-go-network-exposure-pprof-import
	http.ListenAndServe(":8443", nil)
}
