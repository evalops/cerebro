package api

import (
	"fmt"
	"net/http"
)

const deprecatedRouteSunset = "Wed, 30 Sep 2026 00:00:00 GMT"

func (s *Server) deprecatedAlias(successorPath string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		markDeprecatedRoute(w, successorPath)
		next(w, r)
	}
}

func markDeprecatedRoute(w http.ResponseWriter, successorPath string) {
	if successorPath == "" {
		return
	}
	w.Header().Set("Deprecation", "true")
	w.Header().Set("Sunset", deprecatedRouteSunset)
	w.Header().Add("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"", successorPath))
	w.Header().Add("Warning", fmt.Sprintf("299 - \"Deprecated API; use %s before %s\"", successorPath, deprecatedRouteSunset))
}
