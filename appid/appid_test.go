package appid

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestAppIDMiddleware(t *testing.T) {
	cases := []struct {
		name       string
		header     string // header name to set ("" = none)
		value      string
		wantStatus int
		wantBody   string
		wantAppID  string
	}{
		{"missing header", "", "", http.StatusBadRequest,
			`{"message":"X-App-Id header is required","status":"error"}` + "\n", ""},
		{"empty value", "X-App-Id", "", http.StatusBadRequest,
			`{"message":"X-App-Id header is required","status":"error"}` + "\n", ""},
		{"canonical header", "X-App-Id", "fileconvert", http.StatusOK, "ok", "fileconvert"},
		{"legacy casing X-App-ID", "X-App-ID", "scantinel", http.StatusOK, "ok", "scantinel"},
		{"lowercase", "x-app-id", "platform", http.StatusOK, "ok", "platform"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if c.header != "" {
				req.Header.Set(c.header, c.value)
			}
			rec := httptest.NewRecorder()
			ctx := e.NewContext(req, rec)

			var seen string
			called := false
			h := AppIDMiddleware()(func(ctx echo.Context) error {
				called = true
				seen = AppID(ctx)
				if AppIDFromContext(ctx) != seen {
					t.Errorf("AppIDFromContext != AppID")
				}
				if raw, _ := ctx.Get("app_id").(string); raw != seen {
					t.Errorf("context key %q = %q, want %q", "app_id", raw, seen)
				}
				return ctx.String(http.StatusOK, "ok")
			})
			if err := h(ctx); err != nil {
				t.Fatalf("handler error: %v", err)
			}
			if rec.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if rec.Body.String() != c.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), c.wantBody)
			}
			if called != (c.wantStatus == http.StatusOK) {
				t.Errorf("next called = %v", called)
			}
			if seen != c.wantAppID {
				t.Errorf("AppID = %q, want %q", seen, c.wantAppID)
			}
		})
	}
}

func TestAppIDOutsideMiddleware(t *testing.T) {
	e := echo.New()
	ctx := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), httptest.NewRecorder())
	if got := AppID(ctx); got != "" {
		t.Errorf("AppID without middleware = %q", got)
	}
	ctx.Set(AppIDContextKey, 42) // wrong type must not panic
	if got := AppID(ctx); got != "" {
		t.Errorf("AppID with non-string value = %q", got)
	}
}

func TestConstants(t *testing.T) {
	if AppIDContextKey != "app_id" || AppIDHeader != "X-App-Id" {
		t.Fatalf("contract constants changed: %q %q", AppIDContextKey, AppIDHeader)
	}
}
