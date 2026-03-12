package functionscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func openHTTPArtifact(ctx context.Context, client *http.Client, rawURL string) (io.ReadCloser, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("artifact download url is empty")
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s", operatorSafeErrorMessage(err))
	}
	if resp.StatusCode >= 400 {
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		return nil, fmt.Errorf("artifact download failed %d: %s", resp.StatusCode, sanitizeEmbeddedURL(strings.TrimSpace(string(body))))
	}
	return resp.Body, nil
}
