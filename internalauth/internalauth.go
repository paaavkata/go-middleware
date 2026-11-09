// Package internalauth verifies the X-Internal-Token header that identifies an
// in-cluster caller class (gateway, platform, frontend, jobs).
//
// Verifiers wrap routes with Require(classes...). Each accepted class reads its
// secret from INTERNAL_TOKEN_<CLASS> (for example INTERNAL_TOKEN_PLATFORM),
// holding "current" or "current,previous" so a rotation is a two-step redeploy.
// Callers stamp their own class secret from INTERNAL_TOKEN with Stamp or
// Transport. The Traefik gateway plugin strips any client copy of the header
// and stamps the gateway class.
//
// This is the single seam that phase 7 (gateway-signed identity, Keycloak
// client-credentials for pods) re-implements; services keep calling Require
// and CallerClass.
package internalauth

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// Header carries the caller class secret.
const Header = "X-Internal-Token"

// Class is an internal caller class.
type Class string

const (
	None     Class = ""
	Gateway  Class = "gateway"
	Platform Class = "platform"
	Frontend Class = "frontend"
	Jobs     Class = "jobs"
)

const contextKey = "internalauth.class"

// enforced reports whether rejections are enforced. INTERNAL_AUTH_ENFORCE=false
// switches to log-only mode for the rollout window only.
func enforced() bool {
	return !strings.EqualFold(os.Getenv("INTERNAL_AUTH_ENFORCE"), "false")
}

func secrets(c Class) [][]byte {
	var out [][]byte
	for _, v := range strings.Split(os.Getenv("INTERNAL_TOKEN_"+strings.ToUpper(string(c))), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, []byte(v))
		}
	}
	return out
}

// Require accepts a request whose X-Internal-Token matches the secret of one
// of the given classes and records that class for CallerClass. It responds 401
// on a missing or wrong token and 503 when an accepted class has no secret
// configured (fail closed). Secrets are read once, when Require is called.
func Require(classes ...Class) echo.MiddlewareFunc {
	type entry struct {
		class   Class
		secrets [][]byte
	}
	var known []entry
	unconfigured := false
	for _, c := range classes {
		s := secrets(c)
		if len(s) == 0 {
			unconfigured = true
			continue
		}
		known = append(known, entry{c, s})
	}
	enforce := enforced()

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			token := []byte(c.Request().Header.Get(Header))
			matched := None
			if len(token) > 0 {
				for _, e := range known {
					for _, s := range e.secrets {
						if subtle.ConstantTimeCompare(token, s) == 1 {
							matched = e.class
						}
					}
				}
			}
			if matched != None {
				c.Set(contextKey, matched)
				if !enforce {
					logLine(c, matched, "accepted")
				}
				return next(c)
			}
			status, reason := http.StatusUnauthorized, "missing or invalid internal token"
			if unconfigured && len(known) == 0 {
				status, reason = http.StatusServiceUnavailable, "internal auth not configured"
			} else if unconfigured {
				// Some accepted class has no secret: fail closed loudly so the
				// misconfiguration is visible instead of looking like a bad caller.
				status, reason = http.StatusServiceUnavailable, "internal auth partially configured"
			}
			logLine(c, None, reason)
			if !enforce {
				return next(c)
			}
			return c.JSON(status, map[string]string{"status": "error", "message": reason})
		}
	}
}

// RequireGatewayIdentity runs after Require. When the caller class is gateway
// it also requires the gateway-stamped identity: X-Is-Admin: true when admin is
// set, otherwise a non-empty X-User-Id. Pod classes pass unchanged.
func RequireGatewayIdentity(admin bool) echo.MiddlewareFunc {
	enforce := enforced()
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if CallerClass(c) != Gateway {
				return next(c)
			}
			h := c.Request().Header
			ok := h.Get("X-User-Id") != ""
			reason := "gateway request without user identity"
			if admin {
				ok = h.Get("X-Is-Admin") == "true"
				reason = "gateway request without admin identity"
			}
			if ok {
				return next(c)
			}
			logLine(c, Gateway, reason)
			if !enforce {
				return next(c)
			}
			return c.JSON(http.StatusUnauthorized, map[string]string{"status": "error", "message": reason})
		}
	}
}

// CallerClass returns the class Require accepted, or None.
func CallerClass(c echo.Context) Class {
	v, _ := c.Get(contextKey).(Class)
	return v
}

func logLine(c echo.Context, class Class, msg string) {
	r := c.Request()
	cls := string(class)
	if cls == "" {
		cls = "none"
	}
	level := slog.LevelWarn
	if msg == "accepted" {
		level = slog.LevelInfo
	}
	slog.Log(c.Request().Context(), level, "internalauth", "route", c.Path(), "method", r.Method, "class", cls,
		"result", msg, "enforce", enforced(), "user_agent", r.UserAgent(), "remote", c.RealIP())
}

// token returns the caller's own class secret (first value of INTERNAL_TOKEN).
func token() string {
	v, _, _ := strings.Cut(os.Getenv("INTERNAL_TOKEN"), ",")
	return strings.TrimSpace(v)
}

// Stamp sets X-Internal-Token from INTERNAL_TOKEN. It does nothing when
// INTERNAL_TOKEN is unset.
func Stamp(req *http.Request) {
	if t := token(); t != "" {
		req.Header.Set(Header, t)
	}
}

// Transport stamps every outgoing request. A nil Base uses
// http.DefaultTransport.
type Transport struct {
	Base http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if tok := token(); tok != "" {
		req = req.Clone(req.Context())
		req.Header.Set(Header, tok)
	}
	return base.RoundTrip(req)
}
