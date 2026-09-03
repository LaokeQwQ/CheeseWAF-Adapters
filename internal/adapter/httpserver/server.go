package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/config"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/coreclient"
)

const (
	maxHeaderValueBytes  = 16 * 1024
	maxHeaderCount       = 256
	maxHeaderBytes       = 64 * 1024
	maxRequestIDBytes    = 256
	maxAuthorityBytes    = 4 * 1024
	maxPathBytes         = 16 * 1024
	maxQueryBytes        = 64 * 1024
	maxResponseHeaders   = 32
	maxResponseHeadBytes = 16 * 1024
	maxTelemetryPerSec   = 100
	maxTelemetryBytes    = 256 * 1024
)

type Server struct {
	cfg            config.Config
	core           *coreclient.Client
	readyMu        sync.Mutex
	readyAt        time.Time
	readyOK        bool
	telemetryMu    sync.Mutex
	telemetryAt    time.Time
	telemetryCount int
}

func New(cfg config.Config, core *coreclient.Client) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if core == nil {
		return nil, errors.New("core client is required")
	}
	return &Server{cfg: cfg, core: core}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.Handle("/v1/authz", s.protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authz(w, r, inspectionv1.SourceGeneric)
	})))
	mux.Handle("/nginx/auth", s.protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authz(w, r, inspectionv1.SourceNginxAuth)
	})))
	mux.Handle("/envoy/check", s.protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.authz(w, r, inspectionv1.SourceEnvoyAuth)
	})))
	mux.Handle("/v1/telemetry", s.protected(http.HandlerFunc(s.telemetry)))
	return securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.HealthCheckEnabled {
		writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
		return
	}
	if strings.TrimSpace(s.cfg.CoreURL) == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": "core URL is not configured"})
		return
	}
	if s.coreReady(r.Context()) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready", "reason": "core unavailable"})
}

func (s *Server) authz(w http.ResponseWriter, r *http.Request, source inspectionv1.Source) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	request, err := requestFromGateway(r, source, s.cfg)
	if err != nil {
		s.writeClosedFailure(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()
	decision, err := s.core.Inspect(ctx, request)
	if err != nil {
		// A truncated body is an incomplete security decision input. Never let
		// transport fail-open turn it into an implicit allow; the gateway must
		// retry/reject the request instead.
		if request.BodyTruncated {
			s.writeBodyLimitFailure(w)
			return
		}
		s.writeFailure(w, err, request.Source)
		return
	}
	if request.BodyTruncated && (decision.Action == inspectionv1.ActionAllow || decision.Action == inspectionv1.ActionLog) {
		s.writeBodyLimitFailure(w)
		return
	}
	s.writeDecision(w, decision, request.RequestID, request.Source)
}

func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.allowTelemetry(time.Now()) {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "telemetry rate limit exceeded"})
		return
	}
	var event coreclient.TelemetryEvent
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTelemetryBytes))
	if err := decoder.Decode(&event); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid telemetry payload"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "telemetry payload must contain one JSON object"})
		return
	}
	if err := event.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid telemetry payload"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.TelemetryTimeout)
	defer cancel()
	if err := s.core.EmitTelemetry(ctx, event); err != nil {
		// Telemetry is intentionally best effort. It must not turn an already
		// completed gateway decision into a request failure.
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "telemetry unavailable"})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) writeFailure(w http.ResponseWriter, err error, source inspectionv1.Source) {
	if s.cfg.FailMode == "open" && coreclient.IsTransportError(err) && !coreclient.IsProtocolError(err) {
		w.Header().Set("X-CheeseWAF-Adapter-Error", "core-unavailable")
		if source == inspectionv1.SourceEnvoyAuth || source == inspectionv1.SourceEnvoyExtProc {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	s.writeClosedFailure(w)
}

func (s *Server) writeClosedFailure(w http.ResponseWriter) {
	// Closed mode returns 503 instead of a synthetic block page. NGINX
	// auth_request and Envoy authorization filters can then apply their own
	// configured failure policy without treating infrastructure errors as a
	// WAF match.
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "inspection unavailable"})
}

func (s *Server) writeBodyLimitFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body exceeds inspection limit"})
}

func (s *Server) writeDecision(w http.ResponseWriter, decision inspectionv1.Decision, requestID string, source inspectionv1.Source) {
	decision = decision.Normalized()
	if err := decision.Validate(); err != nil {
		s.writeClosedFailure(w)
		return
	}
	responseHeaders := make(map[string]string, len(decision.Headers))
	totalHeaderBytes := 0
	for key, value := range decision.Headers {
		canonical, ok := validResponseHeader(key)
		if !ok || len(value) > maxHeaderValueBytes || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
			s.writeClosedFailure(w)
			return
		}
		if len(responseHeaders) >= maxResponseHeaders || totalHeaderBytes+len(canonical)+len(value) > maxResponseHeadBytes {
			s.writeClosedFailure(w)
			return
		}
		if _, exists := responseHeaders[canonical]; exists {
			s.writeClosedFailure(w)
			return
		}
		responseHeaders[canonical] = value
		totalHeaderBytes += len(canonical) + len(value)
	}
	for key, value := range responseHeaders {
		w.Header().Set(key, value)
	}
	w.Header().Set("X-CheeseWAF-Decision", string(decision.Action))
	if requestID != "" {
		w.Header().Set("X-CheeseWAF-Request-ID", requestID)
	}
	switch decision.Action {
	case inspectionv1.ActionAllow, inspectionv1.ActionLog:
		if source == inspectionv1.SourceEnvoyAuth || source == inspectionv1.SourceEnvoyExtProc {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	case inspectionv1.ActionChallenge, inspectionv1.ActionBlock:
		status := decision.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
	default:
		s.writeClosedFailure(w)
	}
}

func (s *Server) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(s.cfg.AdapterToken)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		values := r.Header.Values("X-CheeseWAF-Adapter-Token")
		provided := ""
		if len(values) == 1 {
			provided = strings.TrimSpace(values[0])
		}
		if provided == "" || strings.ContainsAny(provided, "\r\n") || subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "adapter authentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) coreReady(ctx context.Context) bool {
	now := time.Now()
	s.readyMu.Lock()
	defer s.readyMu.Unlock()
	if !s.readyAt.IsZero() && now.Sub(s.readyAt) < time.Second {
		return s.readyOK
	}

	probeTimeout := s.cfg.RequestTimeout
	if probeTimeout > 500*time.Millisecond {
		probeTimeout = 500 * time.Millisecond
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	err := s.core.Ready(probeCtx)
	cancel()

	s.readyAt = now
	s.readyOK = err == nil
	return err == nil
}

func (s *Server) allowTelemetry(now time.Time) bool {
	s.telemetryMu.Lock()
	defer s.telemetryMu.Unlock()
	if s.telemetryAt.IsZero() || now.Sub(s.telemetryAt) >= time.Second {
		s.telemetryAt = now
		s.telemetryCount = 0
	}
	if s.telemetryCount >= maxTelemetryPerSec {
		return false
	}
	s.telemetryCount++
	return true
}

func requestFromGateway(r *http.Request, source inspectionv1.Source, cfg config.Config) (inspectionv1.Request, error) {
	trusted := trustedPeer(r.RemoteAddr, cfg.TrustedProxyCIDRs)
	requestID := ""
	if trusted {
		raw, present, err := singleHeader(r.Header, "X-Request-ID")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if present && strings.TrimSpace(raw) != "" {
			requestID = safeRequestID(raw)
			if requestID == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Request-ID")
			}
		}
	}
	if requestID == "" {
		requestID = newRequestID()
	}
	pathValue := ""
	method := r.Method
	clientIP := remoteIP(r.RemoteAddr)
	authority := r.Host
	scheme := directScheme(r)
	envoyPartialBody := false
	if trusted {
		rawURI, uriPresent, err := singleHeader(r.Header, "X-Original-URI")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if source == inspectionv1.SourceEnvoyAuth && !uriPresent {
			rawURI, uriPresent, err = singleHeader(r.Header, "X-Envoy-Original-Path")
			if err != nil {
				return inspectionv1.Request{}, err
			}
		}
		if uriPresent {
			if strings.TrimSpace(rawURI) == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid original URI")
			}
			pathValue = rawURI
		}
		rawMethod, methodPresent, err := singleHeader(r.Header, "X-Original-Method")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if source == inspectionv1.SourceEnvoyAuth && !methodPresent {
			rawMethod, methodPresent, err = singleHeader(r.Header, "X-Envoy-Original-Method")
			if err != nil {
				return inspectionv1.Request{}, err
			}
		}
		if methodPresent {
			originalMethod := strings.TrimSpace(rawMethod)
			if originalMethod == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid original method")
			}
			method = originalMethod
		}
		if source == inspectionv1.SourceEnvoyAuth || source == inspectionv1.SourceEnvoyExtProc {
			rawPartial, partialPresent, err := singleHeader(r.Header, "X-Envoy-Auth-Partial-Body")
			if err != nil {
				return inspectionv1.Request{}, err
			}
			if partialPresent {
				switch strings.ToLower(strings.TrimSpace(rawPartial)) {
				case "true":
					envoyPartialBody = true
				case "", "false":
					// An absent/false marker means the body is not known to be partial.
				default:
					return inspectionv1.Request{}, fmt.Errorf("invalid X-Envoy-Auth-Partial-Body")
				}
			}
		}
		rawRealIP, realPresent, err := singleHeader(r.Header, "X-Real-IP")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		rawXFF, xffPresent, err := singleHeader(r.Header, "X-Forwarded-For")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if xffPresent {
			if forwardedIP := forwardedClientIP(rawXFF, cfg.TrustedProxyCIDRs); forwardedIP != "" {
				clientIP = forwardedIP
			} else {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Forwarded-For")
			}
		} else if realPresent {
			if forwardedIP := validForwardedIP(rawRealIP); forwardedIP != "" {
				clientIP = forwardedIP
			} else {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Real-IP")
			}
		}
		rawHost, hostPresent, err := singleHeader(r.Header, "X-Forwarded-Host")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if hostPresent {
			forwardedHostRaw, ok := singleForwardedValue(rawHost)
			forwardedHost := safeAuthority(forwardedHostRaw)
			if !ok || forwardedHost == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Forwarded-Host")
			}
			authority = forwardedHost
		}
		rawScheme, schemePresent, err := singleHeader(r.Header, "X-Forwarded-Proto")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if schemePresent {
			forwardedSchemeRaw, ok := singleForwardedValue(rawScheme)
			forwardedSchemeValue := strings.ToLower(forwardedSchemeRaw)
			if !ok || (forwardedSchemeValue != "http" && forwardedSchemeValue != "https") {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Forwarded-Proto")
			}
			scheme = forwardedSchemeValue
		}
	}
	if pathValue == "" {
		pathValue = r.URL.RequestURI()
	}
	path, query, err := parseRequestURI(pathValue)
	if err != nil {
		return inspectionv1.Request{}, err
	}
	if !validGatewayMethod(method) {
		return inspectionv1.Request{}, fmt.Errorf("invalid gateway method %q", method)
	}
	request := inspectionv1.Request{
		ContractVersion: inspectionv1.Version,
		RequestID:       requestID,
		Source:          source,
		Method:          method,
		Scheme:          scheme,
		Authority:       safeAuthority(authority),
		Path:            path,
		Query:           query,
		Headers:         nil,
		Client: inspectionv1.ClientContext{
			IP:        clientIP,
			UserAgent: "",
		},
		ObservedAt: time.Now().UTC(),
	}
	if request.Authority == "" {
		return inspectionv1.Request{}, fmt.Errorf("invalid request authority")
	}
	if rawUserAgent, present, err := singleHeader(r.Header, "User-Agent"); err != nil {
		return inspectionv1.Request{}, err
	} else if present && rawUserAgent != "" {
		userAgent := safeHeaderText(rawUserAgent, maxHeaderValueBytes)
		if userAgent == "" {
			return inspectionv1.Request{}, fmt.Errorf("invalid User-Agent")
		}
		request.Client.UserAgent = userAgent
	}
	request.Headers, err = copiedHeaders(r.Header, cfg.ForwardSensitiveHeaders, cfg.ForwardBody)
	if err != nil {
		return inspectionv1.Request{}, err
	}
	if cfg.ForwardBody {
		body, truncated, err := boundedBody(r, cfg.MaxBodyBytes)
		if err != nil {
			return inspectionv1.Request{}, fmt.Errorf("read request body: %w", err)
		}
		request.Body = body
		request.BodyTruncated = truncated || envoyPartialBody
		request.BodyForwarded = true
	} else if err := rejectUnexpectedBody(r); err != nil {
		return inspectionv1.Request{}, err
	}
	if envoyPartialBody && !cfg.ForwardBody {
		// The v1 contract requires BodyTruncated to accompany a forwarded body;
		// reject rather than silently presenting Envoy's partial input as whole.
		return inspectionv1.Request{}, fmt.Errorf("Envoy request body is partial but body forwarding is disabled")
	}
	return request, nil
}

func rejectUnexpectedBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	if r.ContentLength == 0 {
		return nil
	}
	if r.ContentLength > 0 {
		return fmt.Errorf("request body forwarding is disabled")
	}
	var one [1]byte
	n, err := r.Body.Read(one[:])
	if n > 0 {
		return fmt.Errorf("request body forwarding is disabled")
	}
	if err != nil && err != io.EOF {
		return fmt.Errorf("read request body: %w", err)
	}
	return nil
}

func boundedBody(r *http.Request, maxBytes int64) ([]byte, bool, error) {
	if maxBytes <= 0 || r.Body == nil || r.Body == http.NoBody {
		return nil, false, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > maxBytes {
		return body[:maxBytes], true, nil
	}
	return body, false, nil
}

func copiedHeaders(input http.Header, forwardSensitiveHeaders, forwardBody bool) (map[string][]string, error) {
	output := make(map[string][]string)
	count := 0
	totalBytes := 0
	for key, values := range input {
		if !validHeaderName(key) {
			return nil, fmt.Errorf("invalid request header name")
		}
		canonical := http.CanonicalHeaderKey(key)
		if canonical == "" || strings.HasPrefix(strings.ToLower(canonical), "x-cheesewaf-") || hopByHopHeader(canonical) {
			continue
		}
		if forwardedHeader(canonical) || canonical == "X-CheeseWAF-Adapter-Token" {
			continue
		}
		if !forwardBody && bodyOnlyHeader(canonical) {
			continue
		}
		if !forwardSensitiveHeaders && sensitiveHeader(canonical) {
			continue
		}
		if count >= maxHeaderCount {
			return nil, fmt.Errorf("request header count exceeds %d", maxHeaderCount)
		}
		clean := make([]string, 0, len(values))
		for _, value := range values {
			if len(value) > maxHeaderValueBytes {
				return nil, fmt.Errorf("request header %q exceeds %d bytes", canonical, maxHeaderValueBytes)
			}
			if strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
				return nil, fmt.Errorf("request header %q contains control characters", canonical)
			}
			if totalBytes+len(canonical)+len(value) > maxHeaderBytes {
				return nil, fmt.Errorf("request headers exceed %d bytes", maxHeaderBytes)
			}
			clean = append(clean, value)
			totalBytes += len(canonical) + len(value)
		}
		if len(clean) > 0 {
			if _, exists := output[canonical]; exists {
				return nil, fmt.Errorf("duplicate request header after canonicalization")
			}
			output[canonical] = clean
			count++
		}
	}
	return output, nil
}

func parseRequestURI(value string) (string, string, error) {
	if value == "" {
		return "/", "", nil
	}
	if strings.TrimSpace(value) != value {
		return "", "", fmt.Errorf("request URI contains leading or trailing whitespace")
	}
	if !strings.HasPrefix(value, "/") {
		return "", "", fmt.Errorf("request URI must start with /")
	}
	if len(value) > maxPathBytes+maxQueryBytes+1 || strings.ContainsAny(value, "#\\\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return "", "", fmt.Errorf("request URI exceeds adapter limits or contains control characters")
	}
	if index := strings.IndexByte(value, '?'); index >= 0 {
		path, query := value[:index], value[index+1:]
		if path == "" || len(path) > maxPathBytes || len(query) > maxQueryBytes {
			return "", "", fmt.Errorf("request URI path or query exceeds adapter limits")
		}
		if !validPercentEncoding(path, true) || !validPercentEncoding(query, false) {
			return "", "", fmt.Errorf("request URI contains invalid percent encoding")
		}
		if hasDotSegment(path) {
			return "", "", fmt.Errorf("request URI contains dot segments")
		}
		return path, query, nil
	}
	if len(value) > maxPathBytes {
		return "", "", fmt.Errorf("request URI path exceeds %d bytes", maxPathBytes)
	}
	if !validPercentEncoding(value, true) {
		return "", "", fmt.Errorf("request URI contains invalid percent encoding")
	}
	if hasDotSegment(value) {
		return "", "", fmt.Errorf("request URI contains dot segments")
	}
	return value, "", nil
}

func validPercentEncoding(value string, rejectPathSeparators bool) bool {
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			continue
		}
		if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
			return false
		}
		decoded := (hexValue(value[index+1]) << 4) | hexValue(value[index+2])
		if decoded == 0 || (rejectPathSeparators && (decoded == '/' || decoded == '\\' || decoded == '.')) {
			return false
		}
		index += 2
	}
	return true
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func hexValue(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}

func hasDotSegment(path string) bool {
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func singleForwardedValue(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsRune(value, ',') {
		return "", false
	}
	return value, true
}

func singleHeader(input http.Header, key string) (string, bool, error) {
	values := input.Values(key)
	if len(values) > 1 {
		return "", true, fmt.Errorf("duplicate %s header", key)
	}
	if len(values) == 1 {
		return values[0], true, nil
	}
	return "", false, nil
}

func trustedPeer(remote string, cidrs []string) bool {
	addr, err := netip.ParseAddr(remoteIP(remote))
	if err != nil {
		return false
	}
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func validForwardedIP(value string) string {
	var ok bool
	value, ok = singleForwardedValue(value)
	if !ok {
		return ""
	}
	addr, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil {
		return ""
	}
	return addr.String()
}

func forwardedClientIP(value string, cidrs []string) string {
	parts := strings.Split(value, ",")
	leftmost := ""
	for _, part := range parts {
		candidate := validForwardedIP(part)
		if candidate == "" {
			return ""
		}
		if leftmost == "" {
			leftmost = candidate
		}
	}
	for index := len(parts) - 1; index >= 0; index-- {
		candidate := validForwardedIP(parts[index])
		if candidate == "" {
			continue
		}
		if !trustedAddress(candidate, cidrs) {
			return candidate
		}
	}
	// A fully trusted chain is valid but does not expose an external client
	// address. Preserve the leftmost asserted address instead of treating the
	// complete chain as malformed; the caller still knows the peer was trusted.
	return leftmost
}

func trustedAddress(value string, cidrs []string) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func safeHeaderText(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func safeRequestID(value string) string {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxRequestIDBytes || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func safeAuthority(value string) string {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxAuthorityBytes || strings.ContainsAny(value, "\r\n/?#\\") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func remoteIP(remote string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remote))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remote)
}

func validGatewayMethod(method string) bool {
	return inspectionv1.Request{
		ContractVersion: inspectionv1.Version,
		Source:          inspectionv1.SourceGeneric,
		Method:          method,
		Path:            "/",
	}.Validate() == nil
}

func directScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func forwardedHeader(key string) bool {
	lower := strings.ToLower(key)
	return lower == "forwarded" || lower == "x-real-ip" || lower == "x-request-id" || strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-original-") || strings.HasPrefix(lower, "x-envoy-")
}

func hopByHopHeader(key string) bool {
	switch strings.ToLower(key) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func bodyOnlyHeader(key string) bool {
	switch strings.ToLower(key) {
	case "content-length", "content-encoding", "content-range":
		return true
	default:
		return false
	}
}

func validResponseHeader(key string) (string, bool) {
	if !validHeaderName(key) {
		return "", false
	}
	canonical := http.CanonicalHeaderKey(key)
	if canonical == "" || canonical == "Connection" || canonical == "Transfer-Encoding" || canonical == "Content-Length" {
		return "", false
	}
	lower := strings.ToLower(canonical)
	if strings.HasPrefix(lower, "x-cheesewaf-") || canonical == "WWW-Authenticate" || canonical == "Retry-After" || canonical == "Location" {
		return canonical, true
	}
	return "", false
}

func validHeaderName(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if r <= ' ' || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
			return false
		}
	}
	return true
}

func sensitiveHeader(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key":
		return true
	default:
		return false
	}
}

func newRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err == nil {
		return hex.EncodeToString(value[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
