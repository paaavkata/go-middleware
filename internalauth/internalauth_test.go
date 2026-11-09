package internalauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func run(t *testing.T, mw []echo.MiddlewareFunc, hdr map[string]string) (int, Class) {
	t.Helper()
	e := echo.New()
	var got Class
	e.POST("/x", func(c echo.Context) error {
		got = CallerClass(c)
		return c.NoContent(http.StatusNoContent)
	}, mw...)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec.Code, got
}

func setEnv(t *testing.T) {
	t.Setenv("INTERNAL_AUTH_ENFORCE", "")
	t.Setenv("INTERNAL_TOKEN_PLATFORM", "plat-new,plat-old")
	t.Setenv("INTERNAL_TOKEN_GATEWAY", "gw")
	t.Setenv("INTERNAL_TOKEN_JOBS", "")
	t.Setenv("INTERNAL_TOKEN_FRONTEND", "")
}

func TestRequire(t *testing.T) {
	setEnv(t)
	mw := []echo.MiddlewareFunc{Require(Platform)}
	cases := []struct {
		name  string
		token string
		code  int
		class Class
	}{
		{"current", "plat-new", 204, Platform},
		{"previous", "plat-old", 204, Platform},
		{"missing", "", 401, None},
		{"wrong", "nope", 401, None},
		{"other class not accepted", "gw", 401, None},
	}
	for _, tc := range cases {
		code, class := run(t, mw, map[string]string{Header: tc.token})
		if code != tc.code || class != tc.class {
			t.Errorf("%s: got %d/%q want %d/%q", tc.name, code, class, tc.code, tc.class)
		}
	}
	code, class := run(t, []echo.MiddlewareFunc{Require(Platform, Gateway)}, map[string]string{Header: "gw"})
	if code != 204 || class != Gateway {
		t.Errorf("multi-class: got %d/%q", code, class)
	}
}

func TestRequireFailsClosedWhenUnconfigured(t *testing.T) {
	setEnv(t)
	if code, _ := run(t, []echo.MiddlewareFunc{Require(Jobs)}, map[string]string{Header: "x"}); code != 503 {
		t.Errorf("unconfigured class: got %d want 503", code)
	}
	if code, _ := run(t, []echo.MiddlewareFunc{Require(Platform, Jobs)}, map[string]string{Header: "x"}); code != 503 {
		t.Errorf("partially configured, no match: got %d want 503", code)
	}
	if code, _ := run(t, []echo.MiddlewareFunc{Require(Platform, Jobs)}, map[string]string{Header: "plat-new"}); code != 204 {
		t.Errorf("partially configured, match: got %d want 204", code)
	}
}

func TestLogOnly(t *testing.T) {
	setEnv(t)
	t.Setenv("INTERNAL_AUTH_ENFORCE", "false")
	code, class := run(t, []echo.MiddlewareFunc{Require(Platform)}, nil)
	if code != 204 || class != None {
		t.Errorf("log-only: got %d/%q", code, class)
	}
}

func TestRequireGatewayIdentity(t *testing.T) {
	setEnv(t)
	admin := []echo.MiddlewareFunc{Require(Gateway), RequireGatewayIdentity(true)}
	if code, _ := run(t, admin, map[string]string{Header: "gw", "X-Is-Admin": "true"}); code != 204 {
		t.Errorf("gateway admin: got %d", code)
	}
	if code, _ := run(t, admin, map[string]string{Header: "gw", "X-User-Id": "u1"}); code != 401 {
		t.Errorf("gateway non-admin: got %d", code)
	}
	user := []echo.MiddlewareFunc{Require(Platform, Gateway), RequireGatewayIdentity(false)}
	if code, _ := run(t, user, map[string]string{Header: "gw"}); code != 401 {
		t.Errorf("gateway anonymous: got %d", code)
	}
	if code, _ := run(t, user, map[string]string{Header: "gw", "X-User-Id": "u1"}); code != 204 {
		t.Errorf("gateway user: got %d", code)
	}
	if code, _ := run(t, user, map[string]string{Header: "plat-new"}); code != 204 {
		t.Errorf("platform pod: got %d", code)
	}
}

func TestStampAndTransport(t *testing.T) {
	t.Setenv("INTERNAL_TOKEN", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	Stamp(req)
	if req.Header.Get(Header) != "" {
		t.Fatal("stamped with empty INTERNAL_TOKEN")
	}
	t.Setenv("INTERNAL_TOKEN", "cur,prev")
	Stamp(req)
	if req.Header.Get(Header) != "cur" {
		t.Fatalf("Stamp: got %q", req.Header.Get(Header))
	}

	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Get(Header) }))
	defer srv.Close()
	resp, err := (&http.Client{Transport: &Transport{}}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen != "cur" {
		t.Fatalf("Transport: got %q", seen)
	}
}
