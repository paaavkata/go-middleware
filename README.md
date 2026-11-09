# Go HTTP Middleware Library

A shared library of `labstack/echo/v4` middleware components. Pkg `gomiddleware`.

> **Optional library, not part of the core platform stack.** Per the platform docs audit (2026-09-21), only conversion-service and k8s-scheduler import this within `backend_apps` (a few SecScanApp services also use it); identity-service, usage-service, cms-service, mcp-service, and payment-service do not. Importer counts are sourced from that audit and were not independently re-verified as part of this doc fix.

## Features

- Logging, recovery, timeout, request-ID, gzip, body-limit, secure-headers, and error-handling middleware for echo
- Viper configuration integration for timeout/body-limit settings
- Default values with overrides

There is **no rate-limiting middleware**. `MiddlewareConfig` still carries a `RateLimit` struct (`Requests`, `Duration`, `Store`, `RedisAddr`) populated by `NewMiddlewareConfigFromViper`, but no `RateLimitMiddleware` function exists in the code — those fields are currently unused.

## Configuration

The library uses Viper for configuration management, via `NewMiddlewareConfigFromViper()`.

### Environment Variables

#### Timeout Configuration
- `MIDDLEWARE_TIMEOUT`: Request timeout duration (default: "30s")

#### Body Limit Configuration
- `MIDDLEWARE_BODY_LIMIT`: Maximum request body size (default: "2M")

The `RateLimit` sub-config (`MIDDLEWARE_RATE_LIMIT_*`) is also read from Viper for forward-compatibility, but nothing in this library currently consumes it (no rate-limiting middleware exists).

## Usage

```go
import (
    gomiddleware "github.com/paaavkata/go-middleware"
    "github.com/labstack/echo/v4"
    "github.com/spf13/viper"
)

func main() {
    viper.AutomaticEnv()

    e := echo.New()

    config := gomiddleware.NewMiddlewareConfigFromViper()

    e.Use(gomiddleware.LoggingMiddleware())
    e.Use(gomiddleware.RecoverMiddleware())
    e.Use(gomiddleware.RequestIDMiddleware())
    e.Use(gomiddleware.TimeoutMiddleware(config))
    e.Use(gomiddleware.BodyLimitMiddleware(config))
    e.Use(gomiddleware.GzipMiddleware())
    e.Use(gomiddleware.SecureMiddleware())
    e.Use(gomiddleware.ErrorHandlerMiddleware())
}
```

## Middleware Components

- `LoggingMiddleware()` — request logging
- `RecoverMiddleware()` — panic recovery
- `TimeoutMiddleware(config *MiddlewareConfig)` — request timeout (default 30s)
- `RequestIDMiddleware()` — unique request IDs
- `GzipMiddleware()` — response compression
- `BodyLimitMiddleware(config *MiddlewareConfig)` — limits request body size (default "2M")
- `SecureMiddleware()` — security-related response headers
- `ErrorHandlerMiddleware()` — consistent error response formatting

## Note

This library is designed to be used behind an API gateway. CORS and JWT handling are managed at the gateway level (Traefik + `traefik-plugin`), so those are not included here. If a request reaches a backend service, it has already been authenticated and authorized by the gateway.

## `appid` subpackage — shared X-App-Id middleware

`import "github.com/paaavkata/go-middleware/appid"` replaces the per-service
`internal/middleware/app_id.go` copies. Byte-compatible: header `X-App-Id`,
context key `app_id`, `400 {"status":"error","message":"X-App-Id header is required"}`.

- `appid.AppIDMiddleware() echo.MiddlewareFunc`
- `appid.AppID(c echo.Context) string` (alias `appid.AppIDFromContext`) — `""` when the route is not wrapped
- `appid.AppIDContextKey = "app_id"`, `appid.AppIDHeader = "X-App-Id"`

## `clientip` subpackage: gateway-stamped client IP

`import "github.com/paaavkata/go-middleware/clientip"` gives every service the same
answer for "which IP is this request from". The gateway plugin strips inbound
`X-Client-Ip` and stamps the address it derived per entrypoint (`Cf-Connecting-Ip`
on the public Cloudflare entrypoint, the connection address on the VPN entrypoint).

- `clientip.Header = "X-Client-Ip"`
- `clientip.FromRequest(r *http.Request) string`: the header value when it is a valid IP,
  else the host of `r.RemoteAddr` (direct in-cluster calls)
- `clientip.FromEcho(c echo.Context) string`: same, for Echo handlers

It never reads `X-Forwarded-For`; the leftmost entry of that header is client-chosen.

## `internalauth` subpackage: internal caller classes (since v0.4.0)

`import "github.com/paaavkata/go-middleware/internalauth"` verifies the `X-Internal-Token`
header (`internalauth.Header`) that identifies an in-cluster caller class:
`internalauth.Gateway`, `Platform`, `Frontend`, `Jobs`.

Verifier side:

- `internalauth.Require(classes ...Class) echo.MiddlewareFunc`: accepts a token matching one of
  the classes, 401 otherwise, 503 when an accepted class has no secret configured (fail closed).
  Secrets come from `INTERNAL_TOKEN_<CLASS>` (`INTERNAL_TOKEN_GATEWAY`, `_PLATFORM`,
  `_FRONTEND`, `_JOBS`), value `current` or `current,previous` for rotation. Compared in
  constant time, read once when `Require` is called.
- `internalauth.RequireGatewayIdentity(admin bool)`: chain after `Require`; when the caller is
  the gateway class it also requires `X-Is-Admin: true` (admin) or a non-empty `X-User-Id`.
  Pod classes pass unchanged.
- `internalauth.CallerClass(c) Class`: the accepted class, or `None`.
- `INTERNAL_AUTH_ENFORCE=false`: log-only mode for the rollout window (logs route, class,
  user agent; never rejects). Removed once every verifier enforces in prod.

Caller side: `internalauth.Stamp(req)` or `&http.Client{Transport: &internalauth.Transport{}}`
stamp the caller's own class secret from `INTERNAL_TOKEN` (first value of a comma list).

Secrets are SealedSecrets `internal-auth` per namespace (keys = class names) in
`infra/infra-gitops/platform/`; the gateway class lives only in `gateway-internal-auth` in `infra`
for Traefik and in the verifier namespaces. Phase 7 replaces the implementation behind
`Require`/`CallerClass` with gateway-signed identity and client-credentials tokens; call sites stay.
