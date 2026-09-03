// Package inspectionv1 contains the versioned contract shared by gateway
// adapters and the CheeseWAF core service.
package inspectionv1

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const Version = "v1"

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
	BodyForwarded   bool                `json:"body_forwarded,omitempty"`
	Body            []byte              `json:"body,omitempty"`
	BodyTruncated   bool                `json:"body_truncated,omitempty"`
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
		return fmt.Errorf("invalid method %q", r.Method)
	}
	if r.Source != "" && !validSource(r.Source) {
		return fmt.Errorf("unsupported source %q", r.Source)
	}
	if strings.TrimSpace(r.Path) == "" || !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path must start with /")
	}
	if strings.ContainsAny(r.Path, "\r\n") || strings.IndexFunc(r.Path, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return fmt.Errorf("path contains control characters")
	}
	if len(r.Body) > 0 && !r.BodyForwarded {
		return fmt.Errorf("body is present but body forwarding is not marked")
	}
	if r.BodyTruncated && !r.BodyForwarded {
		return fmt.Errorf("truncated body must be marked as forwarded")
	}
	if strings.ContainsAny(r.Query, "\r\n") || strings.IndexFunc(r.Query, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return fmt.Errorf("query contains control characters")
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
	return d
}

func validMethod(method string) bool {
	method = strings.TrimSpace(method)
	if method == "" {
		return false
	}
	for _, r := range method {
		if r <= ' ' || r == 127 || r == '\\' || r == '"' || strings.ContainsRune("()<>@,;:/[]?={}\t", r) {
			return false
		}
	}
	return true
}
