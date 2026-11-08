// Package clientip returns the client IP for a request that reached the service
// through the gateway. The gateway strips any inbound X-Client-Ip and stamps the
// address it derived from the entrypoint (Cf-Connecting-Ip on the public
// entrypoint, the connection address on the VPN one). Services must not parse
// X-Forwarded-For themselves: its leftmost entry is client-chosen.
package clientip

import (
	"net"
	"net/http"

	"github.com/labstack/echo/v4"
)

// Header is the gateway-stamped client IP header.
const Header = "X-Client-Ip"

// FromRequest returns the X-Client-Ip value when it is a valid IP, otherwise
// the host part of r.RemoteAddr (direct in-cluster calls).
func FromRequest(r *http.Request) string {
	if v := r.Header.Get(Header); net.ParseIP(v) != nil {
		return v
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// FromEcho is FromRequest for an Echo context.
func FromEcho(c echo.Context) string {
	return FromRequest(c.Request())
}
