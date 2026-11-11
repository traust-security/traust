package ledger

import (
	"net/http"

	ginCors "github.com/gin-contrib/cors"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/cors"
)

func Setup() {
	// ruleid: traust-go-cors-any-origin-with-credentials
	_ = cors.New(cors.Options{AllowedOrigins: []string{"*"}, AllowCredentials: true})
	// ruleid: traust-go-cors-any-origin-with-credentials
	_ = cors.New(cors.Options{AllowCredentials: true, AllowOriginFunc: func(origin string) bool { return true }})
	// ok: traust-go-cors-any-origin-with-credentials
	_ = cors.New(cors.Options{AllowedOrigins: []string{"https://app.example.org"}, AllowCredentials: true})
	// ok: traust-go-cors-any-origin-with-credentials
	_ = cors.New(cors.Options{AllowedOrigins: []string{"*"}})
	// ruleid: traust-go-cors-any-origin-with-credentials
	_ = ginCors.New(ginCors.Config{AllowOriginFunc: func(origin string) bool { return true }, AllowCredentials: true})
	// ruleid: traust-go-cors-any-origin-with-credentials
	_ = middleware.CORSWithConfig(middleware.CORSConfig{AllowOrigins: []string{"*"}, AllowCredentials: true, UnsafeWildcardOriginWithAllowCredentials: true})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ruleid: traust-go-cors-any-origin-with-credentials
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}
