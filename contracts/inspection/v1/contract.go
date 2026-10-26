// Package inspectionv1 contains the versioned contract shared by gateway
// adapters and the CheeseWAF core service.
package inspectionv1

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const Version = "v1"

const (
	maxRequestIDBytes         = 256
	maxAuthorityBytes         = 4 * 1024
	maxHeaderCount            = 256
	maxHeaderValueBytes       = 16 * 1024
	maxHeadersBytes           = 64 * 1024
	maxBodyEncodingBytes      = 64
	maxDecisionBodyBytes      = 64 * 1024
	maxDecisionContentType    = 256
	maxDecisionHeaders        = 32
	maxDecisionHeadersBytes   = 16 * 1024
	maxSetCookies             = 8
	maxSetCookieBytes         = 4 * 1024
	maxUserAgentBytes         = 16 * 1024
	maxTLSFingerprintBytes    = 256
	maxDecisionReasonBytes    = 4 * 1024
	maxDecisionPolicyBytes    = 256
	maxDecisionHeaderValueLen = maxHeaderValueBytes
)

// Action is the policy result returned by the core service.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionLog       Action = "log"
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
)

// Source identifies the gateway protocol that produced an inspection.
type Source string

const (
	SourceGeneric      Source = "generic"
	SourceNginxAuth    Source = "nginx-auth-request"
	SourceEnvoyAuth    Source = "envoy-ext-authz"
	SourceEnvoyExtProc Source = "envoy-ext-proc"
	SourceOOBMirror    Source = "oob-mirror"
)

// BodyState tells the core whether the original request body is absent,
// withheld by the gateway protocol, or present in this inspection.
type BodyState string

const (
	BodyStateAbsent      BodyState = "absent"
	BodyStateWithheld    BodyState = "withheld"
	BodyStateForwarded   BodyState = "forwarded"
	BodyStateTruncated   BodyState = "truncated"
	BodyStateUnsupported BodyState = "unsupported"
)

// Request is intentionally gateway-neutral. Adapters translate their native
// request context into this structure and never import CheeseWAF internals.
type Request struct {
	ContractVersion string              `json:"contract_version"`
	RequestID       string              `json:"request_id,omitempty"`
	Source          Source              `json:"source"`
	Method          string              `json:"method"`
	Scheme          string              `json:"scheme,omitempty"`
	Authority       string              `json:"authority,omitempty"`
	Path            string              `json:"path"`
	Query           string              `json:"query,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	BodyState       BodyState           `json:"body_state,omitempty"`
	BodyForwarded   bool                `json:"body_forwarded,omitempty"`
	Body            []byte              `json:"body,omitempty"`
	BodyTruncated   bool                `json:"body_truncated,omitempty"`
	BodyEncoding    string              `json:"body_encoding,omitempty"`
	Client          ClientContext       `json:"client,omitempty"`
	TLS             TLSContext          `json:"tls,omitempty"`
	Response        *ResponseContext    `json:"response,omitempty"`
	ObservedAt      time.Time           `json:"observed_at,omitempty"`
}

type ClientContext struct {
	IP        string `json:"ip,omitempty"`
	Port      string `json:"port,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type TLSContext struct {
	JA3 string `json:"ja3,omitempty"`
	JA4 string `json:"ja4,omitempty"`
}

type ResponseContext struct {
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Latency    time.Duration       `json:"latency_ns,omitempty"`
}

// Decision is the only object a gateway adapter needs to interpret.
type Decision struct {
	ContractVersion string            `json:"contract_version"`
	Action          Action            `json:"action"`
	StatusCode      int               `json:"status_code,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	RuleID          string            `json:"rule_id,omitempty"`
	PolicyVersion   string            `json:"policy_version,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	SetCookies      []string          `json:"set_cookies,omitempty"`
	Body            []byte            `json:"body,omitempty"`
	BodyContentType string            `json:"body_content_type,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

func (r Request) Validate() error {
	if r.ContractVersion != "" && r.ContractVersion != Version {
		return fmt.Errorf("unsupported contract version %q", r.ContractVersion)
	}
	if strings.TrimSpace(r.Method) == "" {
		return fmt.Errorf("method is required")
	}
	if !validMethod(r.Method) {
		// Validation errors are logged by callers, so they describe the failure
		// mode without echoing the rejected value.
		return fmt.Errorf("invalid method")
	}
	if r.Source != "" && !validSource(r.Source) {
		return fmt.Errorf("unsupported source %q", r.Source)
	}
	if !validPath(r.Path) {
		return fmt.Errorf("path must start with / and contain no raw control, space, query, fragment, or backslash characters")
	}
	if !validQuery(r.Query) {
		return fmt.Errorf("query contains control characters or an invalid fragment delimiter")
	}
	if r.Authority != "" && !validAuthority(r.Authority) {
		return fmt.Errorf("invalid authority")
	}
	if r.Scheme != "" && r.Scheme != "http" && r.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if r.RequestID != "" && !validRequestID(r.RequestID) {
		return fmt.Errorf("invalid request id")
	}
	if err := validateHeaderMap(r.Headers); err != nil {
		return err
	}
	if r.BodyEncoding != "" {
		if !validToken(r.BodyEncoding) || len(r.BodyEncoding) > maxBodyEncodingBytes {
			return fmt.Errorf("invalid body encoding")
		}
		if !r.BodyForwarded {
			return fmt.Errorf("body encoding requires a forwarded body")
		}
	}
	if err := validateBodyState(r); err != nil {
		return err
	}
	if r.Client.UserAgent != "" && !validHeaderText(r.Client.UserAgent, maxUserAgentBytes) {
		return fmt.Errorf("invalid user agent")
	}
	if r.Client.IP != "" {
		if _, err := netip.ParseAddr(r.Client.IP); err != nil {
			return fmt.Errorf("invalid client ip")
		}
	}
	if r.Client.Port != "" && !validPort(r.Client.Port) {
		return fmt.Errorf("invalid client port")
	}
	if r.TLS.JA3 != "" && !validHeaderText(r.TLS.JA3, maxTLSFingerprintBytes) {
		return fmt.Errorf("invalid ja3")
	}
	if r.TLS.JA4 != "" && !validHeaderText(r.TLS.JA4, maxTLSFingerprintBytes) {
		return fmt.Errorf("invalid ja4")
	}
	if r.Response != nil {
		if err := validateResponseContext(*r.Response); err != nil {
			return err
		}
	}
	return nil
}

func validateBodyState(r Request) error {
	if r.BodyState == "" {
		if len(r.Body) > 0 && !r.BodyForwarded {
			return fmt.Errorf("body is present but body forwarding is not marked")
		}
		if r.BodyTruncated && !r.BodyForwarded {
			return fmt.Errorf("truncated body must be marked as forwarded")
		}
		return nil
	}

	switch r.BodyState {
	case BodyStateAbsent, BodyStateWithheld, BodyStateUnsupported:
		if r.BodyForwarded || r.BodyTruncated || len(r.Body) > 0 {
			return fmt.Errorf("%s body must not be forwarded", r.BodyState)
		}
	case BodyStateForwarded:
		if !r.BodyForwarded || r.BodyTruncated {
			return fmt.Errorf("forwarded body state requires body_forwarded and no truncation")
		}
	case BodyStateTruncated:
		if !r.BodyForwarded || !r.BodyTruncated {
			return fmt.Errorf("truncated body state requires body_forwarded and body_truncated")
		}
	default:
		return fmt.Errorf("unsupported body state %q", r.BodyState)
	}
	return nil
}

func (d Decision) Validate() error {
	if d.ContractVersion != "" && d.ContractVersion != Version {
		return fmt.Errorf("unsupported contract version %q", d.ContractVersion)
	}
	switch d.Action {
	case ActionAllow, ActionLog, ActionBlock, ActionChallenge:
	default:
		return fmt.Errorf("unsupported action %q", d.Action)
	}
	if d.StatusCode != 0 {
		switch d.Action {
		case ActionAllow, ActionLog:
			if d.StatusCode < 200 || d.StatusCode >= 300 {
				return fmt.Errorf("allow/log status code must be 2xx, got %d", d.StatusCode)
			}
		case ActionBlock, ActionChallenge:
			if d.StatusCode < 400 || d.StatusCode >= 500 {
				return fmt.Errorf("block/challenge status code must be 4xx, got %d", d.StatusCode)
			}
		}
	}
	if err := validateDecisionHeaders(d.Headers); err != nil {
		return err
	}
	if len(d.SetCookies) > maxSetCookies {
		return fmt.Errorf("too many set-cookie values")
	}
	for _, cookie := range d.SetCookies {
		if !validSetCookie(cookie) {
			return fmt.Errorf("invalid set-cookie value")
		}
	}
	if len(d.Body) > maxDecisionBodyBytes {
		return fmt.Errorf("decision body exceeds %d bytes", maxDecisionBodyBytes)
	}
	if d.BodyContentType != "" && !validContentType(d.BodyContentType) {
		return fmt.Errorf("invalid body content type")
	}
	if d.Reason != "" && !validHeaderText(d.Reason, maxDecisionReasonBytes) {
		return fmt.Errorf("invalid reason")
	}
	if d.RuleID != "" && !validHeaderText(d.RuleID, maxDecisionReasonBytes) {
		return fmt.Errorf("invalid rule id")
	}
	if d.PolicyVersion != "" && !validHeaderText(d.PolicyVersion, maxDecisionPolicyBytes) {
		return fmt.Errorf("invalid policy version")
	}
	for key, value := range d.Metadata {
		if !validHeaderName(key) || !validHeaderText(value, maxHeaderValueBytes) {
			return fmt.Errorf("invalid decision metadata")
		}
	}
	return nil
}

func validSource(source Source) bool {
	switch source {
	case SourceGeneric, SourceNginxAuth, SourceEnvoyAuth, SourceEnvoyExtProc, SourceOOBMirror:
		return true
	default:
		return false
	}
}

func (d Decision) Normalized() Decision {
	if d.ContractVersion == "" {
		d.ContractVersion = Version
	}
	if d.Action == ActionBlock && d.StatusCode == 0 {
		d.StatusCode = http.StatusForbidden
	}
	if d.Action == ActionChallenge && d.StatusCode == 0 {
		d.StatusCode = http.StatusUnauthorized
	}
	if len(d.Body) > 0 && d.BodyContentType == "" {
		d.BodyContentType = "text/plain; charset=utf-8"
	}
	return d
}

func validMethod(method string) bool {
	if method == "" || strings.TrimSpace(method) != method || !utf8.ValidString(method) {
		return false
	}

	for _, r := range method {
		if r <= ' ' || r == 127 || r == '\\' || r == '"' || strings.ContainsRune("()<>@,;:/[]?={}\t", r) {
			return false
		}
	}
	return true
}

func validPath(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") || !utf8.ValidString(path) {
		return false
	}
	if strings.ContainsAny(path, "\r\n?#\\") {
		return false
	}
	for _, r := range path {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

func validQuery(query string) bool {
	if query == "" {
		return true
	}
	if !utf8.ValidString(query) || strings.ContainsAny(query, "\r\n#") {
		return false
	}
	for _, r := range query {
		if r <= ' ' || r == 127 {
			return false
		}
	}
	return true
}

func validAuthority(authority string) bool {
	if authority == "" || len(authority) > maxAuthorityBytes || !utf8.ValidString(authority) {
		return false
	}
	if strings.TrimSpace(authority) != authority {
		return false
	}
	if strings.ContainsAny(authority, "\r\n/?#\\@, ") {
		return false
	}
	for _, r := range authority {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}

func validRequestID(value string) bool {
	return value != "" &&
		len(value) <= maxRequestIDBytes &&
		strings.TrimSpace(value) == value &&
		validHeaderText(value, maxRequestIDBytes)
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 0 && port <= 65535
}

func validToken(value string) bool {
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

func validHeaderName(name string) bool {
	if name == "" || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r <= ' ' || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
			return false
		}
	}
	return true
}

func validHeaderText(value string, maxBytes int) bool {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}

func validateHeaderMap(headers map[string][]string) error {
	if len(headers) > maxHeaderCount {
		return fmt.Errorf("request header count exceeds %d", maxHeaderCount)
	}
	totalBytes := 0
	for name, values := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid request header name")
		}
		if isForbiddenHopHeader(name) {
			return fmt.Errorf("request header is hop-by-hop")
		}
		if len(values) == 0 {
			return fmt.Errorf("request header has no values")
		}
		for _, value := range values {
			if !validHeaderText(value, maxHeaderValueBytes) {
				return fmt.Errorf("invalid request header value")
			}
			totalBytes += len(name) + len(value)
			if totalBytes > maxHeadersBytes {
				return fmt.Errorf("request headers exceed %d bytes", maxHeadersBytes)
			}
		}
	}
	return nil
}

func validateDecisionHeaders(headers map[string]string) error {
	if len(headers) > maxDecisionHeaders {
		return fmt.Errorf("decision header count exceeds %d", maxDecisionHeaders)
	}
	seen := make(map[string]struct{}, len(headers))
	totalBytes := 0
	for name, value := range headers {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid decision header name")
		}
		canonical := http.CanonicalHeaderKey(name)
		if isForbiddenHopHeader(canonical) || canonical == "Content-Length" {
			return fmt.Errorf("decision header %q is not allowed", name)
		}
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("duplicate decision header after canonicalization")
		}
		seen[canonical] = struct{}{}
		if !validHeaderText(value, maxDecisionHeaderValueLen) {
			return fmt.Errorf("invalid decision header value")
		}
		totalBytes += len(canonical) + len(value)
		if totalBytes > maxDecisionHeadersBytes {
			return fmt.Errorf("decision headers exceed %d bytes", maxDecisionHeadersBytes)
		}
	}
	return nil
}

func isForbiddenHopHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Content-Range":
		return true
	default:
		return false
	}
}

func validSetCookie(value string) bool {
	return value != "" && len(value) <= maxSetCookieBytes && validHeaderText(value, maxSetCookieBytes)
}

func validContentType(value string) bool {
	return value != "" && len(value) <= maxDecisionContentType && validHeaderText(value, maxDecisionContentType)
}

func validateResponseContext(response ResponseContext) error {
	if response.StatusCode != 0 && (response.StatusCode < 100 || response.StatusCode > 599) {
		return fmt.Errorf("invalid response status code %d", response.StatusCode)
	}
	if response.Latency < 0 {
		return fmt.Errorf("response latency must be non-negative")
	}
	if err := validateHeaderMap(response.Headers); err != nil {
		return fmt.Errorf("invalid response headers: %w", err)
	}
	return nil
}
