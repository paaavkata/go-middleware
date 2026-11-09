package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Header is the gateway-signed identity assertion.
const Header = "X-Gateway-Identity"

// leeway applied to exp of assertions and service tokens.
const leeway = 30 * time.Second

// claims of X-Gateway-Identity (traefik-plugin jws.go).
type claims struct {
	AppID     string   `json:"app_id"`
	UserID    string   `json:"user_id"`
	UserUID   string   `json:"user_uid"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	IsAdmin   bool     `json:"is_admin"`
	Plan      string   `json:"plan"`
	IAT       int64    `json:"iat"`
	EXP       int64    `json:"exp"`
	KID       string   `json:"kid"`
	RequestID string   `json:"request_id"`
	Method    string   `json:"method"`
	PathHash  string   `json:"path_hash"`
}

// keySet maps kid to HMAC key.
type keySet map[string][]byte

// parseKeys reads comma-separated "<kid>:<base64url key>" pairs from each value.
func parseKeys(values ...string) (keySet, error) {
	ks := keySet{}
	for _, v := range values {
		for _, pair := range strings.Split(v, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			kid, enc, ok := strings.Cut(pair, ":")
			if !ok || kid == "" {
				return nil, fmt.Errorf("identity key %q: want <kid>:<base64url key>", kid)
			}
			key, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(enc, "="))
			if err != nil || len(key) < 32 {
				return nil, fmt.Errorf("identity key %q: not base64url or shorter than 32 bytes", kid)
			}
			ks[kid] = key
		}
	}
	return ks, nil
}

func pathHash(method, path string) string {
	h := sha256.Sum256([]byte(method + " " + path))
	return hex.EncodeToString(h[:])
}

// gatewayPath rebuilds the path the gateway signed: Traefik's stripPrefix
// records the removed prefix in X-Forwarded-Prefix.
func gatewayPath(r *http.Request) string {
	return r.Header.Get("X-Forwarded-Prefix") + r.URL.Path
}

// splitJWS decodes a compact JWS into header JSON, payload JSON, signing input
// and signature.
func splitJWS(tok string) (hdr, payload []byte, signing string, sig []byte, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("malformed")
	}
	if hdr, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, "", nil, errors.New("malformed")
	}
	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, "", nil, errors.New("malformed")
	}
	if sig, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return nil, nil, "", nil, errors.New("malformed")
	}
	return hdr, payload, parts[0] + "." + parts[1], sig, nil
}

// verifyAssertion checks signature, kid, exp (with leeway), method and
// path_hash of an assertion against r. The error text is the log reason.
func verifyAssertion(tok string, keys keySet, r *http.Request, now time.Time) (claims, error) {
	var c claims
	hdrJSON, payload, signing, sig, err := splitJWS(tok)
	if err != nil {
		return c, err
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hdrJSON, &hdr) != nil || hdr.Alg != "HS256" {
		return c, errors.New("bad_header")
	}
	key, ok := keys[hdr.Kid]
	if !ok {
		return c, errors.New("unknown_kid")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return c, errors.New("bad_signature")
	}
	if json.Unmarshal(payload, &c) != nil {
		return c, errors.New("bad_claims")
	}
	if now.After(time.Unix(c.EXP, 0).Add(leeway)) {
		return c, errors.New("expired")
	}
	if c.Method != r.Method {
		return c, errors.New("wrong_method")
	}
	if c.PathHash != pathHash(r.Method, gatewayPath(r)) {
		return c, errors.New("wrong_path")
	}
	return c, nil
}
