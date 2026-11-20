package web

import "net/http"

func login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: traust-go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
	// ruleid: traust-go-open-redirect-taint
	w.Header().Set("Location", r.FormValue("return_to"))
	// ok: traust-go-open-redirect-taint
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func ginLogin(c *gin.Context) {
	// ruleid: traust-go-open-redirect-taint
	c.Redirect(http.StatusFound, c.Query("next"))
	// ok: traust-go-open-redirect-taint
	c.Redirect(http.StatusFound, "/home")
}

func fixedDestination(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("next") {
	case "settings":
		// Untrusted input selects a fixed local destination.
		// ok: traust-go-open-redirect-taint
		http.Redirect(w, r, "/settings", http.StatusFound)
	default:
		// ok: traust-go-open-redirect-taint
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}
