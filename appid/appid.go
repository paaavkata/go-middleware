// Package appid is the shared Echo middleware for the trusted X-App-Id header
// (multi-app platform guide §10). It replaces the per-service copies of
// internal/middleware/app_id.go; identifiers, header, context key, status and
// error body are byte-compatible with those copies, so migrating is an import
// swap.
//
// The gateway (Traefik + traefik-plugin) derives app_id from the request host
// and stamps/strips the trusted X-App-Id header before the request reaches a
// service (guide §4/§10); internal service-to-service callers stamp it from
// their own config. Services never read app_id from the body or query.
package appid

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// AppIDContextKey is the echo-context key under which the resolved app_id is stored.
const AppIDContextKey = "app_id"

// AppIDHeader is the canonical, gateway-stamped app identity header (guide §10).
const AppIDHeader = "X-App-Id"

// AppIDMiddleware extracts the X-App-Id header and stores it in the echo context.
// Returns 400 {"status":"error","message":"X-App-Id header is required"} if the
// header is missing or empty.
func AppIDMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			appID := c.Request().Header.Get(AppIDHeader)
			if appID == "" {
				return c.JSON(http.StatusBadRequest, map[string]string{
					"status":  "error",
					"message": "X-App-Id header is required",
				})
			}
			c.Set(AppIDContextKey, appID)
			return next(c)
		}
	}
}

// AppID returns the app_id set by AppIDMiddleware, or "" on a route the
// middleware does not wrap.
func AppID(c echo.Context) string {
	v, _ := c.Get(AppIDContextKey).(string)
	return v
}

// AppIDFromContext is AppID under the name some services already use.
func AppIDFromContext(c echo.Context) string {
	return AppID(c)
}
