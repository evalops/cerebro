package providers

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func retryAfterDelay(headers http.Header) time.Duration {
	if raw := strings.TrimSpace(headers.Get("Retry-After")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil {
			return time.Duration(seconds) * time.Second
		}
		if retryAt, err := http.ParseTime(raw); err == nil {
			return time.Until(retryAt)
		}
	}
	return rateLimitResetDelay(headers)
}

func rateLimitResetDelay(headers http.Header) time.Duration {
	resetSeconds, err := strconv.ParseInt(headers.Get("X-Rate-Limit-Reset"), 10, 64)
	if err != nil {
		return 0
	}
	return time.Until(time.Unix(resetSeconds, 0))
}
