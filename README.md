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
