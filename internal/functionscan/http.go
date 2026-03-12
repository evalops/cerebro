package functionscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/evalops/cerebro/internal/webhooks"
)

var artifactURLValidator = webhooks.ValidateWebhookURL

const maxArtifactRedirects = 10

func openHTTPArtifact(ctx context.Context, client *http.Client, rawURL string) (io.ReadCloser, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, fmt.Errorf("artifact download url is empty")
	}
	if err := artifactURLValidator(rawURL); err != nil {
		return nil, fmt.Errorf("validate artifact download url: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	cloned := *client
	existingRedirectPolicy := cloned.CheckRedirect
	cloned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxArtifactRedirects {
			return fmt.Errorf("stopped after %d redirects", maxArtifactRedirects)
		}
		if err := artifactURLValidator(req.URL.String()); err != nil {
			return err
		}
		if existingRedirectPolicy != nil {
			return existingRedirectPolicy(req, via)
		}
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cloned.Do(req)
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
