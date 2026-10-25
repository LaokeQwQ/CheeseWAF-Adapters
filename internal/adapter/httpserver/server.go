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
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	maxResponseHeaders   = 64
	maxResponseHeadBytes = 64 * 1024
	maxTelemetryPerSec   = 100
	maxTelemetryBytes    = 256 * 1024
)

type Server struct {
	cfg            config.Config
	core           *coreclient.Client
	logger         *slog.Logger
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
	return &Server{cfg: cfg, core: core, logger: slog.Default()}, nil
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
	mux.Handle("/nginx/body-check", s.protected(http.HandlerFunc(s.nginxBodyCheck)))
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
	s.handleAuthz(w, r, source, false)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, source inspectionv1.Source, bodyRequired bool) {
	if !validGatewayMethod(r.Method) {
		w.Header().Set("Allow", "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	request, err := requestFromGateway(r, source, s.cfg, bodyRequired)
	if err != nil {
		s.logger.Warn("gateway request rejected", "source", source, "error", err)
		s.writeBadRequest(w)
		return
	}
	if bodyRequired && len(request.Body) == 0 && !request.BodyTruncated {
		s.logger.Warn("body inspection request has no body", "source", source, "request_id", request.RequestID)
		s.writeBadRequest(w)
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
			s.logger.Warn("body inspection truncated; refusing decision", "source", source, "request_id", request.RequestID)
			s.writeBodyLimitFailure(w)
			return
		}
		s.writeFailure(w, err, request.Source, request.RequestID)
		return
	}
	if request.BodyTruncated && (decision.Action == inspectionv1.ActionAllow || decision.Action == inspectionv1.ActionLog) {
		s.logger.Warn("body inspection truncated; refusing allow", "source", source, "request_id", request.RequestID)
		s.writeBodyLimitFailure(w)
		return
	}
	s.writeDecision(w, decision, request.RequestID, request.Source)
}

func (s *Server) nginxBodyCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.cfg.ForwardBody {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "body inspection is disabled"})
		return
	}
	s.handleAuthz(w, r, inspectionv1.SourceNginxAuth, true)
}

func (s *Server) telemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if strings.TrimSpace(s.cfg.CoreTelemetryPath) == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "telemetry is disabled"})
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
	if event.ContractVersion == "" {
		event.ContractVersion = inspectionv1.Version
	}
	if event.Source == "" {
		event.Source = inspectionv1.SourceGeneric
	}
	if err := event.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid telemetry payload"})
		return
	}
	if !s.allowTelemetry(time.Now()) {
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "telemetry rate limit exceeded"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.TelemetryTimeout)
	defer cancel()
	if err := s.core.EmitTelemetry(ctx, event); err != nil {
		// Telemetry is intentionally best effort. It must not turn an already
		// completed gateway decision into a request failure.
		s.logger.Warn("telemetry delivery failed", "source", event.Source, "request_id", event.RequestID, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "telemetry unavailable"})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) writeFailure(w http.ResponseWriter, err error, source inspectionv1.Source, requestID string) {
	if s.cfg.FailMode == "open" && coreclient.IsTransportError(err) && !coreclient.IsProtocolError(err) {
		s.logger.Warn("core inspection unavailable; failing open", "source", source, "request_id", requestID, "error", err)
		w.Header().Set("X-CheeseWAF-Adapter-Error", "core-unavailable")
		if source == inspectionv1.SourceEnvoyAuth || source == inspectionv1.SourceEnvoyExtProc {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
		return
	}
	s.logger.Warn("core inspection failed; failing closed", "source", source, "request_id", requestID, "error", err)
	s.writeClosedFailure(w)
}

func (s *Server) writeBadRequest(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid gateway request"})
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
		s.logger.Warn("invalid core decision", "source", source, "request_id", requestID, "error", err)
		s.writeClosedFailure(w)
		return
	}
	totalHeaderBytes := 0
	headerCount := 0
	for key, value := range decision.Headers {
		canonical, ok := validResponseHeader(key)
		if !ok {
			s.logger.Warn("dropping unsupported decision header", "source", source, "request_id", requestID, "header", key)
			continue
		}
		if !validResponseHeaderValue(value) {
			s.logger.Warn("dropping invalid decision header", "source", source, "request_id", requestID, "header", key)
			continue
		}
		if headerCount >= maxResponseHeaders || totalHeaderBytes+len(canonical)+len(value) > maxResponseHeadBytes {
			s.logger.Warn("decision headers exceed adapter limits", "source", source, "request_id", requestID)
			s.writeClosedFailure(w)
			return
		}
		if strings.EqualFold(canonical, "Set-Cookie") {
			w.Header().Add(canonical, value)
		} else {
			w.Header().Set(canonical, value)
		}
		headerCount++
		totalHeaderBytes += len(canonical) + len(value)
	}
	for _, cookie := range decision.SetCookies {
		if !validResponseHeaderValue(cookie) {
			s.logger.Warn("dropping invalid set-cookie", "source", source, "request_id", requestID)
			continue
		}
		if headerCount >= maxResponseHeaders || totalHeaderBytes+len("Set-Cookie")+len(cookie) > maxResponseHeadBytes {
			s.logger.Warn("decision cookies exceed adapter limits", "source", source, "request_id", requestID)
			s.writeClosedFailure(w)
			return
		}
		w.Header().Add("Set-Cookie", cookie)
		headerCount++
		totalHeaderBytes += len("Set-Cookie") + len(cookie)
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
		if len(decision.Body) > 0 {
			if !validResponseContentType(decision.BodyContentType) {
				s.logger.Warn("invalid decision body content type", "source", source, "request_id", requestID, "content_type", decision.BodyContentType)
				s.writeClosedFailure(w)
				return
			}
			w.Header().Set("Content-Type", decision.BodyContentType)
			w.WriteHeader(status)
			_, _ = w.Write(decision.Body)
			return
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

	probeTimeout := s.cfg.HealthCheckTimeout
	if probeTimeout <= 0 {
		probeTimeout = 2 * time.Second
	}
	if probeTimeout > 5*time.Second {
		probeTimeout = 5 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probeTimeout)
	err := s.core.Ready(probeCtx)
	cancel()

	s.readyAt = time.Now()
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

func requestFromGateway(r *http.Request, source inspectionv1.Source, cfg config.Config, bodyRequired bool) (inspectionv1.Request, error) {
	trusted := trustedPeer(r.RemoteAddr, cfg.TrustedProxyCIDRs)
	gatewaySource := source == inspectionv1.SourceNginxAuth || source == inspectionv1.SourceEnvoyAuth || source == inspectionv1.SourceEnvoyExtProc
	if gatewaySource && !trusted {
		return inspectionv1.Request{}, fmt.Errorf("gateway metadata requires a trusted proxy")
	}

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
		if gatewaySource && !uriPresent {
			return inspectionv1.Request{}, fmt.Errorf("missing original URI")
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
		if gatewaySource && !methodPresent {
			return inspectionv1.Request{}, fmt.Errorf("missing original method")
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
			forwardedIP := forwardedClientIP(rawXFF, cfg.TrustedProxyCIDRs)
			if forwardedIP == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Forwarded-For")
			}
			clientIP = forwardedIP
		} else if realPresent {
			forwardedIP := validForwardedIP(rawRealIP)
			if forwardedIP == "" {
				return inspectionv1.Request{}, fmt.Errorf("invalid X-Real-IP")
			}
			clientIP = forwardedIP
		} else if gatewaySource {
			return inspectionv1.Request{}, fmt.Errorf("missing client address metadata")
		}

		rawHost, hostPresent, err := singleHeader(r.Header, "X-Forwarded-Host")
		if err != nil {
			return inspectionv1.Request{}, err
		}
		if gatewaySource && !hostPresent {
			return inspectionv1.Request{}, fmt.Errorf("missing forwarded host")
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
		if gatewaySource && !schemePresent {
			return inspectionv1.Request{}, fmt.Errorf("missing forwarded scheme")
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
		if gatewaySource {
			return inspectionv1.Request{}, fmt.Errorf("missing original URI")
		}
		pathValue = r.URL.RequestURI()
	}
	path, query, err := parseRequestURI(pathValue)
	if err != nil {
		return inspectionv1.Request{}, err
	}
	if !validGatewayMethod(method) {
		return inspectionv1.Request{}, fmt.Errorf("invalid gateway method %q", method)
	}
	authorityValue := safeAuthority(authority)
	if authorityValue == "" {
		return inspectionv1.Request{}, fmt.Errorf("invalid request authority")
	}
	request := inspectionv1.Request{
		ContractVersion: inspectionv1.Version,
		RequestID:       requestID,
		Source:          source,
		Method:          method,
		Scheme:          scheme,
		Authority:       authorityValue,
		Path:            path,
		Query:           query,
		Headers:         nil,
		Client: inspectionv1.ClientContext{
			IP:        clientIP,
			UserAgent: "",
		},
		ObservedAt: time.Now().UTC(),
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
		truncated = truncated || envoyPartialBody
		switch {
		case truncated:
			request.BodyState = inspectionv1.BodyStateTruncated
			request.BodyForwarded = true
			request.BodyTruncated = true
			request.Body = body
		case len(body) > 0 || bodyRequired || source == inspectionv1.SourceGeneric:
			request.BodyState = inspectionv1.BodyStateForwarded
			request.BodyForwarded = true
			request.Body = body
		default:
			request.BodyState = inspectionv1.BodyStateWithheld
		}
		if request.BodyForwarded {
			encoding, err := requestBodyEncoding(r.Header)
			if err != nil {
				return inspectionv1.Request{}, err
			}
			request.BodyEncoding = encoding
		}
	} else {
		if err := rejectUnexpectedBody(r); err != nil {
			return inspectionv1.Request{}, err
		}
		if source == inspectionv1.SourceGeneric {
			request.BodyState = inspectionv1.BodyStateAbsent
		} else {
			request.BodyState = inspectionv1.BodyStateWithheld
		}
	}
	if envoyPartialBody && !cfg.ForwardBody {
		// The v1 contract requires BodyTruncated to accompany a forwarded body;
		// reject rather than silently presenting Envoy's partial input as whole.
		return inspectionv1.Request{}, fmt.Errorf("Envoy request body is partial but body forwarding is disabled")
	}
	if err := request.Validate(); err != nil {
		return inspectionv1.Request{}, fmt.Errorf("validate gateway request: %w", err)
	}
	return request, nil
}

func requestBodyEncoding(header http.Header) (string, error) {
	raw := strings.TrimSpace(header.Get("Content-Encoding"))
	if raw == "" {
		return "", nil
	}
	encoding := strings.ToLower(raw)
	if encoding == "identity" {
		return "", nil
	}
	if !validHeaderToken(encoding) {
		return "", fmt.Errorf("invalid Content-Encoding")
	}
	return encoding, nil
}

func rejectUnexpectedBody(r *http.Request) error {
	if r.Body == nil || r.Body == http.NoBody {
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
	connectionTokens := connectionHeaderTokens(input)
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
		if _, nominated := connectionTokens[canonical]; nominated {
			continue
		}
		if forwardedHeader(canonical) || canonical == "X-CheeseWAF-Adapter-Token" {
			continue
		}
		if canonical == "Content-Length" || canonical == "Content-Range" {
			continue
		}
		if !forwardBody && canonical == "Content-Encoding" {
			continue
		}
		if !forwardSensitiveHeaders && sensitiveHeader(canonical) {
			continue
		}
		if isSingleValueHeader(canonical) && len(values) > 1 {
			return nil, fmt.Errorf("request header %q must have a single value", canonical)
		}
		if count >= maxHeaderCount {
			return nil, fmt.Errorf("request header count exceeds %d", maxHeaderCount)
		}
		clean := make([]string, 0, len(values))
		for _, value := range values {
			if len(value) > maxHeaderValueBytes {
				return nil, fmt.Errorf("request header %q exceeds %d bytes", canonical, maxHeaderValueBytes)
			}
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
				return nil, fmt.Errorf("request header %q contains invalid characters", canonical)
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

func connectionHeaderTokens(input http.Header) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, value := range input.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			tokens[http.CanonicalHeaderKey(token)] = struct{}{}
		}
	}
	return tokens
}

func isSingleValueHeader(key string) bool {
	switch strings.ToLower(key) {
	case "content-type", "content-encoding", "content-length", "content-range",
		"authorization", "proxy-authorization", "x-user", "x-email",
		"x-http-method-override", "x-rewrite-url":
		return true
	default:
		return false
	}
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
	if !utf8.ValidString(value) {
		return "", "", fmt.Errorf("request URI contains invalid UTF-8")
	}
	if len(value) > maxPathBytes+maxQueryBytes+1 || strings.ContainsAny(value, "#\\") || strings.IndexFunc(value, func(r rune) bool { return r <= ' ' || r == 127 }) >= 0 {
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
		if decoded < ' ' || decoded == 127 {
			return false
		}
		if rejectPathSeparators && (decoded == '/' || decoded == '\\' || decoded == '.') {
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
		if segment == "." || segment == ".." || strings.HasPrefix(segment, "..;") || strings.HasPrefix(segment, ".;") {
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
	addr = addr.Unmap()
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
	// A fully trusted chain with more than one address is ambiguous: the
	// leftmost value may be client-controlled. Only a single trusted address
	// can be trusted as the gateway's asserted client identity.
	if len(parts) == 1 {
		return leftmost
	}
	return ""
}

func trustedAddress(value string, cidrs []string) bool {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
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
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func safeRequestID(value string) string {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxRequestIDBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return ""
	}
	return value
}

func safeAuthority(value string) string {
	if value == "" || strings.TrimSpace(value) != value || len(value) > maxAuthorityBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n/?#\\@, ") || strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
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
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
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
	lower := strings.ToLower(canonical)
	switch lower {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade", "content-length", "content-range":
		return "", false
	}
	if strings.HasPrefix(lower, "x-cheesewaf-") || lower == "www-authenticate" || lower == "retry-after" || lower == "location" || lower == "set-cookie" {
		return canonical, true
	}
	return "", false
}

func validResponseHeaderValue(value string) bool {
	return len(value) <= maxHeaderValueBytes &&
		utf8.ValidString(value) &&
		!strings.ContainsAny(value, "\r\n") &&
		strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) < 0
}

func validResponseContentType(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "text/plain", "text/plain; charset=utf-8",
		"text/html", "text/html; charset=utf-8",
		"application/json", "application/json; charset=utf-8":
		return true
	default:
		return false
	}
}

func validHeaderToken(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r <= ' ' || r == 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) {
			return false
		}
	}
	return true
}

func validHeaderName(key string) bool {
	if key == "" || !utf8.ValidString(key) {
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
