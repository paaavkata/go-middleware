// Package identity verifies who a request comes from: the Traefik gateway
// (signed X-Gateway-Identity assertion), a service principal (Keycloak
// client-credentials bearer from the operator realm), or, during the
// transition, the phase-6 bridge credential (X-Internal-Token).
//
// Register Middleware once on the Echo instance. GATEWAY_IDENTITY_MODE selects
// off (default, no-op), shadow (verify, compare with the plain headers, count,
// always serve) or enforce (rewrite the plain headers from the verified
// assertion, reject unauthenticated callers). Handlers read From(c) or keep
// reading the plain headers, which in enforce mode only the verifier writes.
package identity

import (
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// Kind of caller.
type Kind string

const (
	KindAnonymous Kind = "anonymous"
	KindUser      Kind = "user"
	KindService   Kind = "service"
	KindBridge    Kind = "bridge"
)

// Mode values of GATEWAY_IDENTITY_MODE.
const (
	ModeOff     = "off"
	ModeShadow  = "shadow"
	ModeEnforce = "enforce"
)

// Identity is the verified caller. The zero value (Kind "") means nothing was
// verified (mode off, or a missing/invalid credential in shadow mode).
type Identity struct {
	Kind      Kind
	AppID     string
	UserID    int64
	UserUID   string
	Email     string
	Roles     []string
	IsAdmin   bool // always false for service and bridge principals
	Plan      string
	Service   string   // principal name (client id or "bridge")
	Tags      []string // permission tags of a service principal
	RequestID string
}

const contextKey = "identity.identity"

// From returns the identity Middleware verified for this request.
func From(c echo.Context) Identity {
	v, _ := c.Get(contextKey).(Identity)
	return v
}

// IsService reports whether the caller is a service or bridge principal.
func (i Identity) IsService() bool { return i.Kind == KindService || i.Kind == KindBridge }

// Allows reports whether the caller holds tag: an admin user always does, a
// service principal when tag is among its Tags.
func (i Identity) Allows(tag string) bool {
	if i.IsAdmin {
		return true
	}
	for _, t := range i.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AllowsTenant reports whether a service principal may act in app (tag
// tenant.<app> or tenant.*).
func (i Identity) AllowsTenant(app string) bool {
	return i.Allows("tenant.*") || i.Allows("tenant."+app)
}

// Mode returns the effective GATEWAY_IDENTITY_MODE (off when unset or unknown).
func Mode() string {
	switch m := strings.ToLower(strings.TrimSpace(os.Getenv("GATEWAY_IDENTITY_MODE"))); m {
	case ModeShadow, ModeEnforce:
		return m
	}
	return ModeOff
}

// Enforced reports whether GATEWAY_IDENTITY_MODE is enforce. Handlers that keep
// a legacy branch until enforcement (file-service machine access) consult it.
func Enforced() bool { return Mode() == ModeEnforce }

func deny(c echo.Context, status int, msg string) error {
	return c.JSON(status, map[string]string{"status": "error", "message": msg})
}

// gate builds a route guard that is active in enforce mode only; in shadow and
// off it passes every request so a route can be annotated before enforcement.
func gate(ok func(Identity) (int, string)) echo.MiddlewareFunc {
	enforce := Enforced()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if !enforce {
				return next(c)
			}
			if status, msg := ok(From(c)); status != 0 {
				return deny(c, status, msg)
			}
			return next(c)
		}
	}
}

// RequireAdmin allows only an admin user (enforce mode only).
func RequireAdmin() echo.MiddlewareFunc {
	return gate(func(i Identity) (int, string) {
		switch {
		case i.Kind == "":
			return http.StatusUnauthorized, "gateway identity required"
		case i.Kind != KindUser || !i.IsAdmin:
			return http.StatusForbidden, "admin required"
		}
		return 0, ""
	})
}

// Require allows an admin user or a principal holding tag (enforce mode only).
func Require(tag string) echo.MiddlewareFunc {
	return gate(func(i Identity) (int, string) {
		switch {
		case i.Kind == "" || i.Kind == KindAnonymous:
			return http.StatusUnauthorized, "gateway identity required"
		case !i.Allows(tag):
			return http.StatusForbidden, "insufficient permissions"
		}
		return 0, ""
	})
}

// RequireService allows only a service or bridge principal holding tag
// (enforce mode only). Used on /internal/v1 groups with "internal.call".
func RequireService(tag string) echo.MiddlewareFunc {
	return gate(func(i Identity) (int, string) {
		switch {
		case !i.IsService():
			return http.StatusUnauthorized, "service credential required"
		case !i.Allows(tag):
			return http.StatusForbidden, "insufficient permissions"
		}
		return 0, ""
	})
}
