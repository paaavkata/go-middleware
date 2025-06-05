# Go HTTP Middleware Library

A shared library for HTTP middleware components across FileConvert microservices.

## Features

- Rate limiting middleware
- Logging middleware
- Error handling middleware
- Request validation middleware
- Viper configuration integration
- Default values with overrides

## Configuration

The library uses Viper for configuration management. Configuration can be provided through environment variables, configuration files, or direct configuration structs.

### Environment Variables

#### Timeout Configuration
- `MIDDLEWARE_TIMEOUT`: Request timeout duration (default: "30s")

#### Body Limit Configuration
- `MIDDLEWARE_BODY_LIMIT`: Maximum request body size (default: "2M")

#### Rate Limit Configuration
- `MIDDLEWARE_RATE_LIMIT_REQUESTS`: Maximum number of requests (default: 100)
- `MIDDLEWARE_RATE_LIMIT_DURATION`: Time window for rate limiting (default: "1m")
- `MIDDLEWARE_RATE_LIMIT_STORE`: Rate limit store type (memory, redis) (default: "memory")
- `MIDDLEWARE_RATE_LIMIT_REDIS_ADDR`: Redis address for rate limiting (default: "localhost:6379")

## Usage

### Basic Usage

```go
import (
    "github.com/file-convert/go-middleware"
    "github.com/labstack/echo/v4"
    "github.com/spf13/viper"
)

func main() {
    // Initialize Viper
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AutomaticEnv()
    
    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
            panic(fmt.Errorf("fatal error config file: %w", err))
        }
    }

    e := echo.New()
    
    // Create middleware configuration
    config := gomiddleware.NewMiddlewareConfigFromViper()
    
    // Add rate limiting middleware
    e.Use(gomiddleware.RateLimitMiddleware(config))
    
    // Add logging middleware
    e.Use(gomiddleware.LoggingMiddleware())
    
    // Add error handling middleware
    e.Use(gomiddleware.ErrorHandlerMiddleware())
}
```

### Custom Configuration

You can also provide custom configuration instead of using Viper:

```go
config := &gomiddleware.MiddlewareConfig{}

// Timeout configuration
config.Timeout.Duration = 60 * time.Second

// Body limit configuration
config.BodyLimit.Limit = "10M"

// Rate limit configuration
config.RateLimit.Requests = 1000
config.RateLimit.Duration = 5 * time.Minute
config.RateLimit.Store = "redis"
config.RateLimit.RedisAddr = "redis:6379"

// Use the configuration
e.Use(gomiddleware.RateLimitMiddleware(config))
```

## Middleware Components

### Rate Limit Middleware
Implements request rate limiting with configurable limits and storage backends.

### Logging Middleware
Provides request logging with configurable format and output.

### Error Handler Middleware
Provides consistent error handling and response formatting.

### Body Limit Middleware
Limits the size of incoming request bodies.

### Timeout Middleware
Adds request timeout handling.

### Request ID Middleware
Adds unique request IDs to each request.

### Gzip Middleware
Provides response compression using gzip.

### Secure Middleware
Adds security-related headers to responses.

## Note

This library is designed to be used in conjunction with an API gateway. CORS and JWT handling are managed at the API gateway level, so these middleware components are not included in this library. If a request reaches a backend service, it has already been authenticated and authorized by the API gateway. 