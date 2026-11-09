package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource obtains a service token with the client-credentials grant and
// caches it until exp - max(60 s, MinValidity). When a refresh fails the cached token is used
// until its exp and service_token_refresh_failed is logged.
type TokenSource struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scope        string // e.g. "aud:file-service"
	HTTPClient   *http.Client
	// MinValidity is the lifetime a returned token must still have; a cached
	// token closer to exp is refreshed. k8s-scheduler sets it to the longest
	// job deadline so every injected job token outlives its job. Default 60 s.
	MinValidity time.Duration

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSourceFromEnv reads IDENTITY_TOKEN_URL, IDENTITY_CLIENT_ID and
// IDENTITY_CLIENT_SECRET. It returns nil when any of them is unset, so callers
// can keep their transport unchanged where no client is configured.
func NewTokenSourceFromEnv(scope string) *TokenSource {
	ts := &TokenSource{TokenURL: os.Getenv("IDENTITY_TOKEN_URL"), ClientID: os.Getenv("IDENTITY_CLIENT_ID"),
		ClientSecret: os.Getenv("IDENTITY_CLIENT_SECRET"), Scope: scope}
	if ts.TokenURL == "" || ts.ClientID == "" || ts.ClientSecret == "" {
		return nil
	}
	return ts
}

// Token returns a valid access token, fetching a new one when needed.
func (t *TokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	margin := max(t.MinValidity, 60*time.Second)
	if t.token != "" && now.Before(t.expires.Add(-margin)) {
		return t.token, nil
	}
	tok, exp, err := t.fetch(ctx)
	if err != nil {
		if t.token != "" && now.Before(t.expires) {
			slog.Warn("service_token_refresh_failed", "client_id", t.ClientID, "error", err.Error(), "cached_until", t.expires)
			return t.token, nil
		}
		slog.Error("service_token_refresh_failed", "client_id", t.ClientID, "error", err.Error())
		return "", err
	}
	t.token, t.expires = tok, exp
	return tok, nil
}

func (t *TokenSource) fetch(ctx context.Context) (string, time.Time, error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {t.ClientID}, "client_secret": {t.ClientSecret}}
	if t.Scope != "" {
		form.Set("scope", t.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := t.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("token endpoint status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", time.Time{}, err
	}
	if body.AccessToken == "" || body.ExpiresIn <= 0 {
		return "", time.Time{}, fmt.Errorf("token endpoint returned no token")
	}
	return body.AccessToken, time.Now().Add(time.Duration(body.ExpiresIn) * time.Second), nil
}

// Transport sets Authorization: Bearer from Source on every request. A nil
// Base uses http.DefaultTransport; a nil Source sends requests unchanged.
// A token error fails the request (never falls back to forged headers).
type Transport struct {
	Base   http.RoundTripper
	Source *TokenSource
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if t.Source == nil {
		return base.RoundTrip(req)
	}
	tok, err := t.Source.Token(req.Context())
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+tok)
	return base.RoundTrip(req)
}
