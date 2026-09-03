package coreclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
)

type Config struct {
	BaseURL          string
	InspectPath      string
	TelemetryPath    string
	HealthPath       string
	Token            string
	HTTPClient       *http.Client
	MaxResponseBytes int64
}

type Client struct {
	baseURL       *url.URL
	inspectPath   string
	telemetryPath string
	healthPath    string
	token         string
	httpClient    *http.Client
	maxResponse   int64
}

type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

func IsTransportError(err error) bool {
	var target *transportError
	return errors.As(err, &target)
}

type protocolError struct{ err error }

func (e *protocolError) Error() string { return e.err.Error() }
func (e *protocolError) Unwrap() error { return e.err }

func IsProtocolError(err error) bool {
	var target *protocolError
	return errors.As(err, &target)
}

func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil {
		return nil, fmt.Errorf("parse core URL: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("core URL must use http or https")
	}
	if base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, fmt.Errorf("core URL must contain a host and no user info")
	}
	token := strings.TrimSpace(cfg.Token)
	if token != "" && !validHeaderValue(token) {
		return nil, fmt.Errorf("core token contains invalid header characters")
	}
	if token != "" && base.Scheme == "http" && !loopbackHost(base.Hostname()) {
		return nil, fmt.Errorf("core token requires https for non-loopback core URL")
	}
	for name, path := range map[string]string{
		"inspect":   cfg.InspectPath,
		"telemetry": cfg.TelemetryPath,
		"health":    cfg.HealthPath,
	} {
		if name == "inspect" && strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("inspect path is required")
		}
		if path != "" {
			if err := validatePath(name+" path", path); err != nil {
				return nil, err
			}
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: rejectRedirects}
	} else {
		copy := *client
		if copy.Timeout <= 0 {
			copy.Timeout = 2 * time.Second
		}
		// Core calls must never follow redirects: a redirect can move the
		// bearer token to an unintended host and is not a valid core response.
		copy.CheckRedirect = rejectRedirects
		client = &copy
	}
	maxResponse := cfg.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = 1 << 20
	}
	return &Client{
		baseURL:       base,
		inspectPath:   cfg.InspectPath,
		telemetryPath: cfg.TelemetryPath,
		healthPath:    cfg.HealthPath,
		token:         token,
		httpClient:    client,
		maxResponse:   maxResponse,
	}, nil
}

func validHeaderValue(value string) bool {
	return value != "" && len(value) <= 16*1024 && !strings.ContainsAny(value, "\r\n") && strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) < 0
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func validatePath(name, path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%s must start with /", name)
	}
	if strings.ContainsAny(path, "?#\r\n") || strings.IndexFunc(path, func(r rune) bool { return r < ' ' || r == 127 }) >= 0 {
		return fmt.Errorf("%s contains invalid characters", name)
	}
	return nil
}

func rejectRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) Ready(ctx context.Context) error {
	if c.healthPath == "" {
		return nil
	}
	target := *c.baseURL
	target.Path = strings.TrimSuffix(c.baseURL.Path, "/") + c.healthPath
	target.RawQuery = ""
	target.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return fmt.Errorf("create core health request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &transportError{err: fmt.Errorf("check core health: %w", err)}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxResponse+1))
	if err != nil {
		return &transportError{err: fmt.Errorf("read core health response: %w", err)}
	}
	if int64(len(body)) > c.maxResponse {
		return &protocolError{err: fmt.Errorf("core health response exceeds %d bytes", c.maxResponse)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &protocolError{err: fmt.Errorf("core health returned HTTP %d", resp.StatusCode)}
	}
	return nil
}

func (c *Client) Inspect(ctx context.Context, request inspectionv1.Request) (inspectionv1.Decision, error) {
	if request.Source == "" {
		request.Source = inspectionv1.SourceGeneric
	}
	if err := request.Validate(); err != nil {
		return inspectionv1.Decision{}, fmt.Errorf("validate inspection request: %w", err)
	}
	request.ContractVersion = inspectionv1.Version
	var decision inspectionv1.Decision
	if err := c.postJSON(ctx, c.inspectPath, request, &decision); err != nil {
		return inspectionv1.Decision{}, err
	}
	decision = decision.Normalized()
	if err := decision.Validate(); err != nil {
		return inspectionv1.Decision{}, &protocolError{err: fmt.Errorf("validate core decision: %w", err)}
	}
	return decision, nil
}

func (c *Client) EmitTelemetry(ctx context.Context, event TelemetryEvent) error {
	if c.telemetryPath == "" {
		return nil
	}
	if event.Source == "" {
		event.Source = inspectionv1.SourceGeneric
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate telemetry event: %w", err)
	}
	return c.postJSON(ctx, c.telemetryPath, event, nil)
}

type TelemetryEvent struct {
	ContractVersion string              `json:"contract_version"`
	RequestID       string              `json:"request_id,omitempty"`
	Source          inspectionv1.Source `json:"source"`
	Action          inspectionv1.Action `json:"action"`
	Path            string              `json:"path,omitempty"`
	StatusCode      int                 `json:"status_code,omitempty"`
	LatencyNanos    int64               `json:"latency_ns,omitempty"`
	PolicyVersion   string              `json:"policy_version,omitempty"`
}

const (
	maxTelemetryIDBytes     = 256
	maxTelemetryPathBytes   = 16 * 1024
	maxTelemetryPolicyBytes = 256
)

func (event TelemetryEvent) Validate() error {
	if event.ContractVersion != inspectionv1.Version {
		return fmt.Errorf("unsupported contract version %q", event.ContractVersion)
	}
	if event.Source == "" {
		return fmt.Errorf("source is required")
	}
	switch event.Source {
	case inspectionv1.SourceGeneric, inspectionv1.SourceNginxAuth, inspectionv1.SourceEnvoyAuth, inspectionv1.SourceEnvoyExtProc, inspectionv1.SourceOOBMirror:
	default:
		return fmt.Errorf("unsupported source %q", event.Source)
	}
	switch event.Action {
	case inspectionv1.ActionAllow, inspectionv1.ActionLog, inspectionv1.ActionBlock, inspectionv1.ActionChallenge:
	default:
		return fmt.Errorf("unsupported action %q", event.Action)
	}
	if event.StatusCode != 0 && (event.StatusCode < 200 || event.StatusCode > 599) {
		return fmt.Errorf("invalid status code %d", event.StatusCode)
	}
	if event.RequestID != "" && !validTelemetryText(event.RequestID, maxTelemetryIDBytes) {
		return fmt.Errorf("invalid request id")
	}
	if event.Path != "" {
		if !strings.HasPrefix(event.Path, "/") || !validTelemetryText(event.Path, maxTelemetryPathBytes) {
			return fmt.Errorf("invalid path")
		}
	}
	if event.PolicyVersion != "" && !validTelemetryText(event.PolicyVersion, maxTelemetryPolicyBytes) {
		return fmt.Errorf("invalid policy version")
	}
	if event.LatencyNanos < 0 {
		return fmt.Errorf("latency must be non-negative")
	}
	return nil
}

func validTelemetryText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && !strings.ContainsAny(value, "\r\n") && strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) < 0
}

func (c *Client) postJSON(ctx context.Context, path string, payload any, output any) error {
	target := *c.baseURL
	target.Path = strings.TrimSuffix(c.baseURL.Path, "/") + path
	target.RawQuery = ""
	target.RawPath = ""
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal core request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create core request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &transportError{err: fmt.Errorf("call core: %w", err)}
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, c.maxResponse+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return &protocolError{err: fmt.Errorf("read core response: %w", err)}
	}
	if int64(len(responseBody)) > c.maxResponse {
		return &protocolError{err: fmt.Errorf("core response exceeds %d bytes", c.maxResponse)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &protocolError{err: fmt.Errorf("core returned HTTP %d", resp.StatusCode)}
	}
	if output == nil || len(bytes.TrimSpace(responseBody)) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, output); err != nil {
		return &protocolError{err: fmt.Errorf("decode core response: %w", err)}
	}
	return nil
}
