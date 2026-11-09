package identity

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var (
	key1 = []byte("0123456789abcdef0123456789abcdef")
	key0 = []byte("fedcba9876543210fedcba9876543210")
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(c claims, kid string, key []byte) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "HS256", "kid": kid})
	body, _ := json.Marshal(c)
	s := b64(hdr) + "." + b64(body)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(s))
	return s + "." + b64(mac.Sum(nil))
}

// gwClaims are the claims the gateway signs for GET /api/file/v1/x.
func gwClaims(user string, admin bool) claims {
	now := time.Now().Unix()
	return claims{AppID: "fileconvert", UserID: user, UserUID: "uid-" + user, Roles: []string{"user"}, IsAdmin: admin,
		Plan: "pro", IAT: now, EXP: now + 60, KID: "k1", RequestID: "rid", Method: "GET",
		PathHash: pathHash("GET", "/api/file/v1/x")}
}

// plainHeaders are the headers the gateway stamps next to c.
func plainHeaders(c claims) map[string]string {
	h := map[string]string{"X-App-Id": c.AppID, "X-User-Id": c.UserID, "X-User-Uid": c.UserUID,
		"X-User-Roles": strings.Join(c.Roles, ","), "X-User-Plan": c.Plan, "X-Forwarded-Prefix": "/api/file"}
	if c.IsAdmin {
		h["X-Is-Admin"] = "true"
	}
	return h
}

func setKeys(t *testing.T, mode string) {
	t.Setenv("GATEWAY_IDENTITY_MODE", mode)
	t.Setenv("GATEWAY_IDENTITY_KEYS", "k1:"+b64(key1))
	t.Setenv("GATEWAY_IDENTITY_KEYS_PREVIOUS", "k0:"+b64(key0))
	t.Setenv("IDENTITY_ACCEPT_BRIDGE", "")
	t.Setenv("IDENTITY_SERVICE_JWKS_URL", "")
	t.Setenv("INTERNAL_TOKEN_PLATFORM", "")
	t.Setenv("INTERNAL_TOKEN_JOBS", "")
	t.Setenv("INTERNAL_TOKEN_GATEWAY", "")
	t.Setenv("INTERNAL_TOKEN_FRONTEND", "")
}

type result struct {
	code int
	body string
	hdr  http.Header
	id   Identity
}

// run serves one request through Middleware (plus route guards) on a fresh
// registry and returns the outcome and the counter value of wantResult.
func run(t *testing.T, method, path string, hdr map[string]string, guards ...echo.MiddlewareFunc) (result, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	e := echo.New()
	e.Use(Middleware(Config{Service: "file-service", Registerer: reg}))
	var res result
	h := func(c echo.Context) error {
		res.hdr = c.Request().Header.Clone()
		res.id = From(c)
		return c.NoContent(http.StatusNoContent)
	}
	e.Add(method, path, h, guards...)
	req := httptest.NewRequest(method, path, nil)
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	res.code, res.body = rec.Code, rec.Body.String()
	return res, reg
}

func count(reg *prometheus.Registry, result string) float64 {
	cv := counter(reg)
	return testutil.ToFloat64(cv.WithLabelValues("file-service", result))
}

func TestAllows(t *testing.T) {
	admin := Identity{Kind: KindUser, IsAdmin: true}
	svc := Identity{Kind: KindService, Tags: []string{"files.pin", "tenant.scantinel"}}
	bare := Identity{Kind: KindService, Tags: []string{"files.write"}}
	if !admin.Allows("files.pin") || !svc.Allows("files.pin") || bare.Allows("files.pin") {
		t.Fatal("Allows: admin and tagged service allowed, untagged service denied")
	}
	if !svc.AllowsTenant("scantinel") || svc.AllowsTenant("fileconvert") ||
		!(Identity{Tags: []string{"tenant.*"}}).AllowsTenant("fileconvert") {
		t.Fatal("AllowsTenant")
	}
}

func TestVerifyAssertion(t *testing.T) {
	keys, err := parseKeys("k1:"+b64(key1), "k0:"+b64(key0))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(method, path, prefix string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		if prefix != "" {
			r.Header.Set("X-Forwarded-Prefix", prefix)
		}
		return r
	}
	now := time.Now()
	good := gwClaims("42", false)
	expired := good
	expired.EXP = now.Add(-31 * time.Second).Unix()
	inLeeway := good
	inLeeway.EXP = now.Add(-20 * time.Second).Unix()
	for _, tc := range []struct {
		name, tok string
		req       *http.Request
		want      string
	}{
		{"valid", sign(good, "k1", key1), mk("GET", "/v1/x", "/api/file"), ""},
		{"valid previous kid", sign(good, "k0", key0), mk("GET", "/v1/x", "/api/file"), ""},
		{"exp within leeway", sign(inLeeway, "k1", key1), mk("GET", "/v1/x", "/api/file"), ""},
		{"unknown kid", sign(good, "k9", key1), mk("GET", "/v1/x", "/api/file"), "unknown_kid"},
		{"bad signature", sign(good, "k1", key0), mk("GET", "/v1/x", "/api/file"), "bad_signature"},
		{"expired", sign(expired, "k1", key1), mk("GET", "/v1/x", "/api/file"), "expired"},
		{"wrong method", sign(good, "k1", key1), mk("DELETE", "/v1/x", "/api/file"), "wrong_method"},
		{"wrong path", sign(good, "k1", key1), mk("GET", "/v1/y", "/api/file"), "wrong_path"},
		{"missing prefix", sign(good, "k1", key1), mk("GET", "/v1/x", ""), "wrong_path"},
		{"unstripped path without prefix", sign(good, "k1", key1), mk("GET", "/api/file/v1/x", ""), ""},
		{"malformed", "abc", mk("GET", "/v1/x", "/api/file"), "malformed"},
	} {
		_, err := verifyAssertion(tc.tok, keys, tc.req, now)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestShadow(t *testing.T) {
	setKeys(t, "shadow")
	c := gwClaims("42", false)
	hdr := plainHeaders(c)
	hdr[Header] = sign(c, "k1", key1)

	res, reg := run(t, "GET", "/v1/x", hdr)
	if res.code != 204 || count(reg, "ok") != 1 || res.id.Kind != KindUser || res.id.UserID != 42 {
		t.Fatalf("agreement: code=%d ok=%v id=%+v", res.code, count(reg, "ok"), res.id)
	}
	hdr["X-Is-Admin"] = "true"
	res, reg = run(t, "GET", "/v1/x", hdr)
	if res.code != 204 || count(reg, "mismatch") != 1 || res.hdr.Get("X-Is-Admin") != "true" {
		t.Fatalf("mismatch must be served unchanged and counted: code=%d", res.code)
	}
	delete(hdr, "X-Is-Admin")
	hdr[Header] = sign(c, "k1", key0)
	res, reg = run(t, "GET", "/v1/x", hdr)
	if res.code != 204 || count(reg, "invalid") != 1 {
		t.Fatalf("invalid: code=%d", res.code)
	}
	delete(hdr, Header)
	res, reg = run(t, "GET", "/v1/x", hdr)
	if res.code != 204 || count(reg, "missing") != 1 || res.hdr.Get("X-User-Id") != "42" {
		t.Fatalf("missing: code=%d", res.code)
	}
}

func TestEnforce(t *testing.T) {
	setKeys(t, "enforce")
	c := gwClaims("42", false)
	hdr := plainHeaders(c)
	hdr[Header] = sign(c, "k1", key1)
	// Forged extras the gateway did not assert are overwritten or removed.
	hdr["X-Is-Admin"] = "true"
	hdr["X-User-Email"] = "evil@example.com"
	hdr["X-User-Id"] = "1"
	res, reg := run(t, "GET", "/v1/x", hdr)
	if res.code != 204 || count(reg, "ok") != 1 {
		t.Fatalf("valid: code=%d %s", res.code, res.body)
	}
	if res.hdr.Get("X-User-Id") != "42" || res.hdr.Get("X-Is-Admin") != "" || res.hdr.Get("X-User-Email") != "" ||
		res.hdr.Get("X-App-Id") != "fileconvert" || res.hdr.Get("X-User-Plan") != "pro" {
		t.Fatalf("headers not rewritten from claims: %v", res.hdr)
	}

	// Anonymous assertion: user headers deleted, app kept.
	anon := gwClaims("", false)
	anon.UserUID, anon.Roles, anon.Plan = "", nil, ""
	res, _ = run(t, "GET", "/v1/x", map[string]string{Header: sign(anon, "k1", key1), "X-User-Id": "7", "X-Forwarded-Prefix": "/api/file"})
	if res.code != 204 || res.hdr.Get("X-User-Id") != "" || res.id.Kind != KindAnonymous {
		t.Fatalf("anonymous: code=%d hdr=%v", res.code, res.hdr)
	}

	// No credential: 401 with the spec body.
	res, reg = run(t, "GET", "/v1/x", map[string]string{"X-App-Id": "fileconvert", "X-Is-Admin": "true"})
	if res.code != 401 || !strings.Contains(res.body, `"message":"gateway identity required"`) || count(reg, "missing") != 1 {
		t.Fatalf("missing: code=%d body=%s", res.code, res.body)
	}

	// Replay: expired or other route.
	old := c
	old.IAT, old.EXP = time.Now().Add(-150*time.Second).Unix(), time.Now().Add(-90*time.Second).Unix()
	for name, h := range map[string]map[string]string{
		"expired":     {Header: sign(old, "k1", key1), "X-Forwarded-Prefix": "/api/file"},
		"other route": {Header: sign(c, "k1", key1), "X-Forwarded-Prefix": "/api/scan"},
	} {
		res, reg = run(t, "GET", "/v1/x", h)
		if res.code != 401 || count(reg, "invalid") != 1 {
			t.Fatalf("%s replay: code=%d", name, res.code)
		}
	}

	// OPTIONS passes.
	res, _ = run(t, "OPTIONS", "/v1/x", nil)
	if res.code == 401 {
		t.Fatal("OPTIONS must pass through")
	}
}

func TestModeOffIsNoop(t *testing.T) {
	setKeys(t, "")
	res, _ := run(t, "GET", "/v1/x", map[string]string{"X-User-Id": "9", Header: "garbage"})
	if res.code != 204 || res.hdr.Get("X-User-Id") != "9" || res.id.Kind != "" {
		t.Fatalf("off: code=%d", res.code)
	}
}

// --- service principals ------------------------------------------------------

type realm struct {
	key  *rsa.PrivateKey
	srv  *httptest.Server
	hits atomic.Int32
}

const testIssuer = "https://auth.example/realms/infra"

func newRealm(t *testing.T) *realm {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	r := &realm{key: k}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "rk", "kty": "RSA", "alg": "RS256", "use": "sig",
			"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}}})
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *realm) mint(key *rsa.PrivateKey, aud any, exp time.Time, azp string, roles ...string) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "rk", "typ": "JWT"})
	body, _ := json.Marshal(map[string]any{"iss": testIssuer, "aud": aud, "exp": exp.Unix(), "azp": azp,
		"realm_access": map[string]any{"roles": roles}})
	s := b64(hdr) + "." + b64(body)
	h := sha256.Sum256([]byte(s))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	return s + "." + b64(sig)
}

func setService(t *testing.T, mode string, r *realm) {
	setKeys(t, mode)
	t.Setenv("IDENTITY_SERVICE_ISSUER", testIssuer)
	t.Setenv("IDENTITY_SERVICE_JWKS_URL", r.srv.URL)
	t.Setenv("IDENTITY_SERVICE_AUDIENCE", "file-service")
}

func TestVerifyServiceToken(t *testing.T) {
	r := newRealm(t)
	j := NewJWKS(r.srv.URL)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	exp := time.Now().Add(time.Hour)
	for _, tc := range []struct{ name, tok, want string }{
		{"valid list aud", r.mint(r.key, []string{"file-service", "x"}, exp, "finding-service", "files.pin"), ""},
		{"valid string aud", r.mint(r.key, "file-service", exp, "finding-service"), ""},
		{"wrong aud", r.mint(r.key, "finding-service", exp, "agent-service"), "wrong_audience"},
		{"expired", r.mint(r.key, "file-service", time.Now().Add(-time.Minute), "finding-service"), "expired"},
		{"bad signature", r.mint(other, "file-service", exp, "finding-service"), "bad_signature"},
	} {
		svc, _, err := verifyServiceToken(tc.tok, j, testIssuer, "file-service", time.Now())
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want || (got == "" && svc != "finding-service") {
			t.Errorf("%s: got %q svc=%q want %q", tc.name, got, svc, tc.want)
		}
	}
}

func TestServicePrincipalEnforce(t *testing.T) {
	r := newRealm(t)
	setService(t, "enforce", r)
	exp := time.Now().Add(time.Hour)
	pin := r.mint(r.key, "file-service", exp, "finding-service", "files.pin", "files.write", "tenant.scantinel")
	write := r.mint(r.key, "file-service", exp, "job-wrapper", "files.write", "tenant.fileconvert")
	pinGuard := Require("files.pin")

	res, reg := run(t, "PUT", "/v1/pin", map[string]string{"Authorization": "Bearer " + pin, "X-App-Id": "scantinel", "X-User-Id": "42"}, pinGuard)
	if res.code != 204 || res.id.Service != "finding-service" || res.id.IsAdmin || res.hdr.Get("X-User-Id") != "" || count(reg, "service") != 1 {
		t.Fatalf("pin with tag: code=%d id=%+v hdr=%v", res.code, res.id, res.hdr)
	}
	if res, _ = run(t, "PUT", "/v1/pin", map[string]string{"Authorization": "Bearer " + write, "X-App-Id": "fileconvert"}, pinGuard); res.code != 403 {
		t.Fatalf("pin without tag: %d", res.code)
	}
	if res, _ = run(t, "PUT", "/v1/pin", map[string]string{"Authorization": "Bearer " + write, "X-App-Id": "scantinel"}); res.code != 403 || !strings.Contains(res.body, "tenant_not_allowed") {
		t.Fatalf("tenant: %d %s", res.code, res.body)
	}
	if res, _ = run(t, "PUT", "/v1/pin", map[string]string{"Authorization": "Bearer " + pin, "X-App-Id": "scantinel", "X-Is-Admin": "true"}); res.code != 400 || !strings.Contains(res.body, "impersonation_header") {
		t.Fatalf("impersonation: %d %s", res.code, res.body)
	}
	// Wrong audience is treated as no credential.
	wrongAud := r.mint(r.key, "finding-service", exp, "agent-service", "tenant.*")
	if res, _ = run(t, "GET", "/v1/x", map[string]string{"Authorization": "Bearer " + wrongAud}); res.code != 401 {
		t.Fatalf("wrong aud: %d", res.code)
	}
	// Internal routes: service principal with internal.call only.
	internal := RequireService("internal.call")
	call := r.mint(r.key, "file-service", exp, "agent-service", "internal.call", "tenant.*")
	if res, _ = run(t, "GET", "/internal/v1/x", map[string]string{"Authorization": "Bearer " + call}, internal); res.code != 204 {
		t.Fatalf("internal with tag: %d", res.code)
	}
	if res, _ = run(t, "GET", "/internal/v1/x", map[string]string{"Authorization": "Bearer " + pin, "X-App-Id": "scantinel"}, internal); res.code != 403 {
		t.Fatalf("internal without tag: %d", res.code)
	}
	c := gwClaims("42", true)
	h := plainHeaders(c)
	h[Header] = sign(c, "k1", key1)
	c.PathHash = pathHash("GET", "/api/file/internal/v1/x")
	h[Header] = sign(c, "k1", key1)
	if res, _ = run(t, "GET", "/internal/v1/x", h, internal); res.code != 401 {
		t.Fatalf("internal from an admin user: %d", res.code)
	}
}

func TestServicePrincipalShadowChangesNothing(t *testing.T) {
	r := newRealm(t)
	setService(t, "shadow", r)
	tok := r.mint(r.key, "file-service", time.Now().Add(time.Hour), "cms-service", "files.write", "tenant.*")
	res, reg := run(t, "PUT", "/v1/pin", map[string]string{"Authorization": "Bearer " + tok, "X-Is-Admin": "true"}, Require("files.pin"))
	if res.code != 204 || res.hdr.Get("X-Is-Admin") != "true" || count(reg, "service") != 1 {
		t.Fatalf("shadow: code=%d", res.code)
	}
}

func TestBridge(t *testing.T) {
	for _, accept := range []string{"", "false"} {
		setKeys(t, "enforce")
		t.Setenv("IDENTITY_ACCEPT_BRIDGE", accept)
		t.Setenv("INTERNAL_TOKEN_JOBS", "jobs-secret")
		res, reg := run(t, "GET", "/internal/v1/x", map[string]string{"X-Internal-Token": "jobs-secret", "X-App-Id": "scantinel", "X-User-Id": "5"}, RequireService("internal.call"))
		if accept == "" {
			if res.code != 204 || res.id.Kind != KindBridge || res.id.Service != "bridge" || res.hdr.Get("X-User-Id") != "" || count(reg, "bridge") != 1 {
				t.Fatalf("bridge on: code=%d id=%+v", res.code, res.id)
			}
		} else if res.code != 401 || count(reg, "bridge") != 0 {
			t.Fatalf("bridge off: code=%d", res.code)
		}
	}
	setKeys(t, "enforce")
	t.Setenv("INTERNAL_TOKEN_JOBS", "jobs-secret")
	if res, _ := run(t, "GET", "/x", map[string]string{"X-Internal-Token": "wrong"}); res.code != 401 {
		t.Fatalf("wrong bridge token: %d", res.code)
	}
}

// --- client -------------------------------------------------------------------

func TestTokenSource(t *testing.T) {
	var calls atomic.Int32
	var fail atomic.Bool
	kc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "finding-service" || r.Form.Get("scope") != "aud:file-service" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":3600}`, calls.Load())
	}))
	defer kc.Close()
	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	defer api.Close()

	ts := &TokenSource{TokenURL: kc.URL, ClientID: "finding-service", ClientSecret: "s", Scope: "aud:file-service"}
	hc := &http.Client{Transport: &Transport{Source: ts}}
	for i := 0; i < 100; i++ {
		resp, err := hc.Get(api.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if calls.Load() != 1 || seen[99] != "Bearer tok-1" {
		t.Fatalf("token requests=%d last=%q", calls.Load(), seen[99])
	}
	// Refresh window reached while Keycloak is down: cached token until exp.
	ts.expires = time.Now().Add(30 * time.Second)
	fail.Store(true)
	if tok, err := ts.Token(t.Context()); err != nil || tok != "tok-1" {
		t.Fatalf("offline fallback: %q %v", tok, err)
	}
	ts.expires = time.Now().Add(-time.Second)
	if _, err := ts.Token(t.Context()); err == nil {
		t.Fatal("expired cached token must not be used")
	}
}
