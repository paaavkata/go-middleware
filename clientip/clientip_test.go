package clientip

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
)

func TestFromRequest(t *testing.T) {
	cases := []struct {
		name, header, want string
	}{
		{"stamped header wins over XFF", "203.0.113.9", "203.0.113.9"},
		{"stamped IPv6", "2001:db8::1", "2001:db8::1"},
		{"non-IP header falls back", "evil, 1.2.3.4", "10.0.2.4"},
		{"absent header falls back", "", "10.0.2.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "10.0.2.4:51234"
			r.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.9")
			if tc.header != "" {
				r.Header.Set(Header, tc.header)
			}
			if got := FromRequest(r); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if got := FromEcho(echo.New().NewContext(r, httptest.NewRecorder())); got != tc.want {
				t.Fatalf("FromEcho got %q, want %q", got, tc.want)
			}
		})
	}
}
