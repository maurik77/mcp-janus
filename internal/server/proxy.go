// internal/server/proxy.go
package server

import (
	"net/http"
)

type Proxy interface {
	ProxyHandler(w http.ResponseWriter, r *http.Request)
	AuthMiddleware() func(http.Handler) http.Handler
}
