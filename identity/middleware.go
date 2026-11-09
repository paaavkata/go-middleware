package identity

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/paaavkata/go-middleware/internalauth"
	"github.com/prometheus/client_golang/prometheus"
)

// Config of Middleware. Everything else comes from the environment.
type Config struct {
	// Service is the metric label; default IDENTITY_SERVICE_AUDIENCE.
	Service string
	// Registerer for gateway_identity_checks_total; pass goserver's
	// mgr.Registry() so the counter is scraped. Default prometheus.DefaultRegisterer.
	Registerer prometheus.Registerer
}

// Plain identity headers the gateway stamps; enforce mode rewrites them from
// the verified assertion and deletes them for service principals.
const (
	hAppID   = "X-App-Id"
	hUserID  = "X-User-Id"
	hUserUID = "X-User-Uid"
	hEmail   = "X-User-Email"
	hIsAdmin = "X-Is-Admin"
	hRoles   = "X-User-Roles"
	hPlan    = "X-User-Plan"
)

var userHeaders = []string{hUserID, hUserUID, hEmail, hIsAdmin, hRoles, hPlan}

// Check results (label result of gateway_identity_checks_total).
const (
	resultOK       = "ok"
	resultMissing  = "missing"
	resultInvalid  = "invalid"
	resultMismatch = "mismatch"
	resultService  = "service"
	resultBridge   = "bridge"
)

func counter(reg prometheus.Registerer) *prometheus.CounterVec {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	cv := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "gateway_identity_checks_total",
		Help: "Gateway identity verification outcomes by service and result.",
	}, []string{"service", "result"})
	if err := reg.Register(cv); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if existing, ok := are.ExistingCollector.(*prometheus.CounterVec); ok {
				return existing
			}
		}
		slog.Error("gateway identity metric not registered", "error", err)
	}
	return cv
}

// Middleware verifies the caller; see the package doc. Configuration:
//
//	GATEWAY_IDENTITY_MODE           off | shadow | enforce (default off)
//	GATEWAY_IDENTITY_KEYS           kid:base64url[,kid:base64url] (active)
//	GATEWAY_IDENTITY_KEYS_PREVIOUS  same format (previous, rotation window)
//	IDENTITY_SERVICE_ISSUER         operator realm issuer
//	IDENTITY_SERVICE_JWKS_URL       operator realm certs URL
//	IDENTITY_SERVICE_AUDIENCE       this service's name (aud of service tokens)
//	IDENTITY_ACCEPT_BRIDGE          accept X-Internal-Token as principal bridge (default true)
func Middleware(cfg Config) echo.MiddlewareFunc {
	mode := Mode()
	if mode == ModeOff {
		return func(next echo.HandlerFunc) echo.HandlerFunc { return next }
	}
	m := &verifier{
		enforce:  mode == ModeEnforce,
		issuer:   os.Getenv("IDENTITY_SERVICE_ISSUER"),
		audience: os.Getenv("IDENTITY_SERVICE_AUDIENCE"),
		bridge:   !strings.EqualFold(os.Getenv("IDENTITY_ACCEPT_BRIDGE"), "false"),
		now:      time.Now,
	}
	m.service = cfg.Service
	if m.service == "" {
		m.service = m.audience
	}
	m.checks = counter(cfg.Registerer)
	keys, err := parseKeys(os.Getenv("GATEWAY_IDENTITY_KEYS"), os.Getenv("GATEWAY_IDENTITY_KEYS_PREVIOUS"))
	if err != nil {
		slog.Error("gateway identity keys unusable, every assertion is invalid", "error", err)
	}
	if len(keys) == 0 {
		slog.Error("gateway identity: no GATEWAY_IDENTITY_KEYS configured, every assertion is invalid", "mode", mode)
	}
	m.keys = keys
	if u := os.Getenv("IDENTITY_SERVICE_JWKS_URL"); u != "" && m.issuer != "" && m.audience != "" {
		m.jwks = NewJWKS(u)
	}
	return m.handle
}

type verifier struct {
	enforce  bool
	keys     keySet
	jwks     *JWKS
	issuer   string
	audience string
	bridge   bool
	service  string
	checks   *prometheus.CounterVec
	now      func() time.Time
}

func (m *verifier) count(result string) { m.checks.WithLabelValues(m.service, result).Inc() }

func (m *verifier) log(c echo.Context, result, reason, claim string, extra ...any) {
	r := c.Request()
	args := append([]any{"result", result, "reason", reason, "claim", claim, "path", r.URL.Path,
		"method", r.Method, "enforce", m.enforce}, extra...)
	slog.Warn("gateway identity", args...)
}

func (m *verifier) unauthorized(c echo.Context) error {
	return deny(c, http.StatusUnauthorized, "gateway identity required")
}

func (m *verifier) handle(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		if r.Method == http.MethodOptions {
			return next(c)
		}
		// 1. Gateway assertion: present means it decides, valid or not.
		if tok := r.Header.Get(Header); tok != "" {
			cl, err := verifyAssertion(tok, m.keys, r, m.now())
			if err != nil {
				m.count(resultInvalid)
				m.log(c, resultInvalid, err.Error(), "")
				if m.enforce {
					return m.unauthorized(c)
				}
				return next(c)
			}
			id := identityFromClaims(cl)
			c.Set(contextKey, id)
			if m.enforce {
				rewriteHeaders(r.Header, cl)
				m.count(resultOK)
				return next(c)
			}
			if claim := mismatch(r.Header, cl); claim != "" {
				m.count(resultMismatch)
				m.log(c, resultMismatch, "header_differs", claim)
			} else {
				m.count(resultOK)
				slog.Debug("gateway identity", "result", resultOK, "path", r.URL.Path, "app_id", cl.AppID, "user_id", cl.UserID)
			}
			return next(c)
		}
		// 2. Service principal bearer.
		if m.jwks != nil {
			if raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && raw != "" {
				svc, tags, err := verifyServiceToken(strings.TrimSpace(raw), m.jwks, m.issuer, m.audience, m.now())
				if err == nil {
					return m.principal(c, next, Identity{Kind: KindService, Service: svc, Tags: tags}, resultService)
				}
				m.log(c, resultMissing, "service_token_rejected", "", "error", err.Error())
			}
		}
		// 3. Bridge fallback (phase-6 internal credential).
		if m.bridge {
			if class := internalauth.Match(r); class != internalauth.None {
				id := Identity{Kind: KindBridge, Service: "bridge", Tags: []string{"internal.call", "tenant.*"}}
				return m.principal(c, next, id, resultBridge, "class", string(class))
			}
		}
		// 4. Nothing verified.
		m.count(resultMissing)
		m.log(c, resultMissing, "no_credential", "")
		if m.enforce {
			return m.unauthorized(c)
		}
		return next(c)
	}
}

// principal applies the service-principal rules: never admin, no user headers,
// no X-Is-Admin, X-App-Id only within the tenant tags. Shadow mode logs the
// violations and changes nothing.
func (m *verifier) principal(c echo.Context, next echo.HandlerFunc, id Identity, result string, extra ...any) error {
	h := c.Request().Header
	id.AppID = h.Get(hAppID)
	id.RequestID = h.Get("X-Request-ID")
	c.Set(contextKey, id)
	m.count(result)
	extra = append(extra, "principal", id.Service)
	if h.Get(hIsAdmin) != "" {
		m.log(c, result, "impersonation_header", hIsAdmin, extra...)
		if m.enforce {
			return deny(c, http.StatusBadRequest, "impersonation_header")
		}
	}
	if id.AppID != "" && !id.AllowsTenant(id.AppID) {
		m.log(c, result, "tenant_not_allowed", hAppID, extra...)
		if m.enforce {
			return deny(c, http.StatusForbidden, "tenant_not_allowed")
		}
	}
	if m.enforce {
		for _, k := range userHeaders {
			h.Del(k)
		}
	}
	return next(c)
}

func identityFromClaims(cl claims) Identity {
	id := Identity{Kind: KindAnonymous, AppID: cl.AppID, UserUID: cl.UserUID, Email: cl.Email,
		Roles: cl.Roles, IsAdmin: cl.IsAdmin, Plan: cl.Plan, RequestID: cl.RequestID}
	if cl.UserID != "" {
		id.Kind = KindUser
		id.UserID, _ = strconv.ParseInt(cl.UserID, 10, 64)
	}
	return id
}

func claimHeaders(cl claims) [][2]string {
	admin := ""
	if cl.IsAdmin {
		admin = "true"
	}
	return [][2]string{{hAppID, cl.AppID}, {hUserID, cl.UserID}, {hUserUID, cl.UserUID}, {hEmail, cl.Email},
		{hIsAdmin, admin}, {hRoles, strings.Join(cl.Roles, ",")}, {hPlan, cl.Plan}}
}

// rewriteHeaders makes the plain headers exactly what the gateway asserted.
func rewriteHeaders(h http.Header, cl claims) {
	for _, kv := range claimHeaders(cl) {
		if kv[1] == "" {
			h.Del(kv[0])
		} else {
			h.Set(kv[0], kv[1])
		}
	}
}

// mismatch returns the first header that differs from its claim, or "".
func mismatch(h http.Header, cl claims) string {
	for _, kv := range claimHeaders(cl) {
		got := h.Get(kv[0])
		if kv[0] == hIsAdmin && got != "true" {
			got = ""
		}
		if got != kv[1] {
			return kv[0]
		}
	}
	return ""
}
