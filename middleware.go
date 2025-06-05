package gomiddleware

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
)

const (
	// Default values
	DefaultTimeout           = 30 * time.Second
	DefaultBodyLimit         = "2M"
	DefaultRateLimitRequests = 100
	DefaultRateLimitDuration = 1 * time.Minute
)

// MiddlewareConfig holds the configuration for all middleware components
type MiddlewareConfig struct {
	Timeout struct {
		Duration time.Duration
	}
	BodyLimit struct {
		Limit string
	}
	RateLimit struct {
		Requests  int
		Duration  time.Duration
		Store     string // memory, redis
		RedisAddr string
	}
}

// NewMiddlewareConfigFromViper creates a new middleware configuration from Viper
func NewMiddlewareConfigFromViper() *MiddlewareConfig {
	config := &MiddlewareConfig{}

	// Timeout configuration
	config.Timeout.Duration = viper.GetDuration("middleware.timeout")
	if config.Timeout.Duration == 0 {
		config.Timeout.Duration = DefaultTimeout
	}

	// Body limit configuration
	config.BodyLimit.Limit = viper.GetString("middleware.body_limit")
	if config.BodyLimit.Limit == "" {
		config.BodyLimit.Limit = DefaultBodyLimit
	}

	// Rate limit configuration
	config.RateLimit.Requests = viper.GetInt("middleware.rate_limit.requests")
	if config.RateLimit.Requests == 0 {
		config.RateLimit.Requests = DefaultRateLimitRequests
	}

	config.RateLimit.Duration = viper.GetDuration("middleware.rate_limit.duration")
	if config.RateLimit.Duration == 0 {
		config.RateLimit.Duration = DefaultRateLimitDuration
	}

	config.RateLimit.Store = viper.GetString("middleware.rate_limit.store")
	if config.RateLimit.Store == "" {
		config.RateLimit.Store = "memory"
	}

	config.RateLimit.RedisAddr = viper.GetString("middleware.rate_limit.redis_addr")
	if config.RateLimit.RedisAddr == "" {
		config.RateLimit.RedisAddr = "localhost:6379"
	}

	return config
}

// LoggingMiddleware returns a logging middleware
func LoggingMiddleware() echo.MiddlewareFunc {
	return middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "${time_rfc3339} ${remote_ip} ${method} ${uri} ${status} ${latency_human}\n",
		Output: os.Stdout,
	})
}

// RecoverMiddleware returns a recovery middleware
func RecoverMiddleware() echo.MiddlewareFunc {
	return middleware.Recover()
}

// TimeoutMiddleware returns a timeout middleware
func TimeoutMiddleware(config *MiddlewareConfig) echo.MiddlewareFunc {
	if config == nil {
		config = NewMiddlewareConfigFromViper()
	}

	return middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: config.Timeout.Duration,
	})
}

// RequestIDMiddleware returns a request ID middleware
func RequestIDMiddleware() echo.MiddlewareFunc {
	return middleware.RequestID()
}

// GzipMiddleware returns a gzip compression middleware
func GzipMiddleware() echo.MiddlewareFunc {
	return middleware.Gzip()
}

// BodyLimitMiddleware returns a body limit middleware
func BodyLimitMiddleware(config *MiddlewareConfig) echo.MiddlewareFunc {
	if config == nil {
		config = NewMiddlewareConfigFromViper()
	}

	return middleware.BodyLimit(config.BodyLimit.Limit)
}

// SecureMiddleware returns a secure middleware
func SecureMiddleware() echo.MiddlewareFunc {
	return middleware.Secure()
}

// ErrorHandlerMiddleware returns an error handling middleware
func ErrorHandlerMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if err != nil {
				var statusCode int
				var message string

				switch e := err.(type) {
				case *echo.HTTPError:
					statusCode = e.Code
					message = fmt.Sprint(e.Message)
				default:
					statusCode = http.StatusInternalServerError
					message = "Internal Server Error"
				}

				return c.JSON(statusCode, map[string]interface{}{
					"error": message,
				})
			}
			return nil
		}
	}
}
