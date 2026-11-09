package identity

// JWKS cache and RS256 service-token verification. The cache moved here from
// conversion-status-service (internal/auth/keycloak.go), which now imports it.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	jwksRefetchCooldown = 30 * time.Second
	// jwksMaxAge bounds how long a key removed from the realm keeps validating.
	jwksMaxAge  = 10 * time.Minute
	maxJWKSBody = 1 << 20
)

// JWKS caches the RSA signing keys of one Keycloak realm by kid. Keys are
// fetched lazily; the set is replaced only on a fully successful fetch, so a
// Keycloak outage keeps serving the last-good keys.
type JWKS struct {
	url    string
	client *http.Client

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastAttempt time.Time
	lastSuccess time.Time
}

// NewJWKS returns a lazily populated key cache for a realm's certs endpoint.
func NewJWKS(url string) *JWKS {
	return &JWKS{url: url, client: &http.Client{Timeout: 5 * time.Second}}
}

// Key returns the key for kid, refetching (at most every 30 s) on a miss or
// when the cached set is older than 10 minutes.
func (j *JWKS) Key(kid string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	key, last, ok := j.keys[kid], j.lastAttempt, j.lastSuccess
	j.mu.RUnlock()
	if key != nil && time.Since(ok) <= jwksMaxAge {
		return key, nil
	}
	if time.Since(last) >= jwksRefetchCooldown {
		_ = j.refresh() // failure keeps last-good keys
		j.mu.RLock()
		key = j.keys[kid]
		j.mu.RUnlock()
	}
	if key == nil {
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	return key, nil
}

func (j *JWKS) refresh() error {
	j.mu.Lock()
	j.lastAttempt = time.Now()
	j.mu.Unlock()

	resp, err := j.client.Get(j.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct{ Kid, Kty, Alg, Use, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBody)).Decode(&doc); err != nil {
		return err
	}
	parsed := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		// Keycloak also publishes an RSA-OAEP encryption key; signing keys only.
		if k.Kid == "" || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if pub, err := parseRSAJWK(k.N, k.E); err == nil {
			parsed[k.Kid] = pub
		}
	}
	if len(parsed) == 0 {
		return errors.New("jwks contained no usable RS256 signing keys")
	}
	j.mu.Lock()
	j.keys, j.lastSuccess = parsed, time.Now()
	j.mu.Unlock()
	return nil
}

// parseRSAJWK builds an *rsa.PublicKey from base64url n/e (RFC 7518 6.3).
func parseRSAJWK(n64, e64 string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(n64)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(e64)
	if err != nil || len(eb) == 0 || len(eb) > 4 {
		return nil, errors.New("bad exponent")
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	n := new(big.Int).SetBytes(nb)
	if e < 3 || e%2 == 0 || n.BitLen() < 2048 {
		return nil, errors.New("weak or invalid RSA key")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// audience accepts the JWT "aud" as a string or a list.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = audience{s}
		return nil
	}
	var l []string
	if err := json.Unmarshal(b, &l); err != nil {
		return err
	}
	*a = l
	return nil
}

// serviceClaims are the parts of a Keycloak client-credentials token we use.
type serviceClaims struct {
	Iss         string   `json:"iss"`
	Aud         audience `json:"aud"`
	Exp         int64    `json:"exp"`
	Azp         string   `json:"azp"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
}

// verifyServiceToken checks an RS256 token against the realm keys, issuer,
// audience and exp, and returns the client id (azp) and realm roles.
func verifyServiceToken(tok string, jwks *JWKS, issuer, aud string, now time.Time) (string, []string, error) {
	hdrJSON, payload, signing, sig, err := splitJWS(tok)
	if err != nil {
		return "", nil, err
	}
	var hdr struct{ Alg, Kid string }
	if json.Unmarshal(hdrJSON, &hdr) != nil || hdr.Alg != "RS256" || hdr.Kid == "" {
		return "", nil, errors.New("bad_header")
	}
	key, err := jwks.Key(hdr.Kid)
	if err != nil {
		return "", nil, errors.New("unknown_kid")
	}
	h := sha256.Sum256([]byte(signing))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) != nil {
		return "", nil, errors.New("bad_signature")
	}
	var c serviceClaims
	if json.Unmarshal(payload, &c) != nil {
		return "", nil, errors.New("bad_claims")
	}
	if c.Iss != issuer {
		return "", nil, errors.New("wrong_issuer")
	}
	if now.After(time.Unix(c.Exp, 0).Add(leeway)) {
		return "", nil, errors.New("expired")
	}
	okAud := false
	for _, a := range c.Aud {
		okAud = okAud || (a == aud && aud != "")
	}
	if !okAud {
		return "", nil, errors.New("wrong_audience")
	}
	if c.Azp == "" {
		return "", nil, errors.New("no_azp")
	}
	return c.Azp, c.RealmAccess.Roles, nil
}
