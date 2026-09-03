package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/config"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/coreclient"
)

func TestAuthzMapsAllowAndOriginalContext(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request inspectionv1.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodPost || request.Path != "/login" || request.Client.IP != "203.0.113.10" {
			t.Fatalf("unexpected request: %+v", request)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Original-Method", http.MethodPost)
	req.Header.Set("X-Original-URI", "/login?next=%2F")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set("Authorization", "Bearer secret")
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent || resp.Header().Get("X-CheeseWAF-Decision") != "allow" {
		t.Fatalf("unexpected response: code=%d headers=%v body=%s", resp.Code, resp.Header(), resp.Body.String())
	}
}

func TestAuthzDoesNotForwardSensitiveHeadersByDefault(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request inspectionv1.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if _, ok := request.Headers["Authorization"]; ok {
			t.Fatal("authorization header was forwarded by default")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://adapter/nginx/auth", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Original-URI", "/")
	req.Header.Set("Authorization", "Bearer secret")
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", resp.Code)
	}
}

func TestAuthzClosedOnCoreFailure(t *testing.T) {
	client, err := coreclient.New(coreclient.Config{BaseURL: "http://127.0.0.1:1", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = "http://127.0.0.1:1"
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed mode status = %d, want 503", resp.Code)
	}
}

func TestAuthzOpenOnCoreFailure(t *testing.T) {
	client, err := coreclient.New(coreclient.Config{BaseURL: "http://127.0.0.1:1", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = "http://127.0.0.1:1"
	cfg.FailMode = "open"
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if resp.Code != http.StatusNoContent || resp.Header().Get("X-CheeseWAF-Adapter-Error") != "core-unavailable" {
		t.Fatalf("open mode response = %d %v", resp.Code, resp.Header())
	}
}

func TestAuthzIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request inspectionv1.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Method != http.MethodGet || request.Path != "/v1/authz" || request.Client.IP != "198.51.100.20" {
			t.Fatalf("untrusted proxy headers changed request: %+v", request)
		}
		if request.RequestID == "spoofed" {
			t.Fatal("untrusted request id was accepted")
		}
		if _, ok := request.Headers["X-Original-URI"]; ok {
			t.Fatal("untrusted original URI was forwarded")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"action\":\"allow\"}"))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	req.RemoteAddr = "198.51.100.20:1234"
	req.Header.Set("X-Original-Method", http.MethodPost)
	req.Header.Set("X-Original-URI", "/admin")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set("X-Request-ID", "spoofed")
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAuthzForwardsBoundedBody(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request inspectionv1.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if string(request.Body) != "abcd" || !request.BodyTruncated {
			t.Fatalf("unexpected bounded body: body=%q truncated=%v", request.Body, request.BodyTruncated)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"action\":\"allow\"}"))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	cfg.ForwardBody = true
	cfg.MaxBodyBytes = 4
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://adapter/v1/authz", bytes.NewBufferString("abcdef"))
	req.RemoteAddr = "127.0.0.1:1234"
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("unexpected status: %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAuthzBodyTruncationNeverFailsOpenOnCoreTransportError(t *testing.T) {
	client, err := coreclient.New(coreclient.Config{BaseURL: "http://127.0.0.1:1", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = "http://127.0.0.1:1"
	cfg.FailMode = "open"
	cfg.ForwardBody = true
	cfg.MaxBodyBytes = 4
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://adapter/v1/authz", bytes.NewBufferString("abcdef"))
	req.RemoteAddr = "127.0.0.1:1234"
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("truncated body was fail-opened: status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestEnvoyPartialBodyMarkerIsForwardedAsTruncated(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request inspectionv1.Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Source != inspectionv1.SourceEnvoyAuth || !request.BodyForwarded || !request.BodyTruncated {
			t.Fatalf("Envoy partial body marker was lost: source=%q forwarded=%v truncated=%v", request.Source, request.BodyForwarded, request.BodyTruncated)
		}
		if string(request.Body) != "body" {
			t.Fatalf("unexpected forwarded body: %q", request.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"action\":\"allow\"}"))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	cfg.ForwardBody = true
	cfg.MaxBodyBytes = 64
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://adapter/envoy/check", bytes.NewBufferString("body"))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Envoy-Auth-Partial-Body", "true")
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("partial body marker was treated as complete: status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAuthzProtocolErrorNeverFailsOpen(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"action\":\"unknown\"}"))
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	cfg.FailMode = "open"
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("protocol error was fail-opened: status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAuthzCoreHTTPErrorNeverFailsOpen(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	cfg.FailMode = "open"
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("core HTTP error was fail-opened: status=%d body=%s", resp.Code, resp.Body.String())
	}
}

func TestAdapterTokenRequired(t *testing.T) {
	client, err := coreclient.New(coreclient.Config{BaseURL: "http://127.0.0.1:1", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = "http://127.0.0.1:1"
	cfg.AdapterToken = "adapter-secret"
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if resp.Code != http.StatusUnauthorized || resp.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing token response = %d %v", resp.Code, resp.Header())
	}
}

func TestTelemetryRejectsTrailingJSON(t *testing.T) {
	called := false
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", TelemetryPath: "/telemetry", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	body := "{\"contract_version\":\"v1\",\"source\":\"generic\",\"action\":\"allow\"} {\"action\":\"allow\"}"
	req := httptest.NewRequest(http.MethodPost, "http://adapter/v1/telemetry", bytes.NewBufferString(body))
	resp := httptest.NewRecorder()
	server.Handler().ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest || called {
		t.Fatalf("trailing JSON response=%d called=%v", resp.Code, called)
	}
}

func TestReadyProbesCoreAndCaches(t *testing.T) {
	probes := 0
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("unexpected health path %s", r.URL.Path)
		}
		probes++
		w.WriteHeader(http.StatusOK)
	}))
	defer core.Close()
	client, err := coreclient.New(coreclient.Config{BaseURL: core.URL, InspectPath: "/inspect", HealthPath: "/healthz", HTTPClient: core.Client()})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		resp := httptest.NewRecorder()
		server.Handler().ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://adapter/readyz", nil))
		if resp.Code != http.StatusOK {
			t.Fatalf("ready response=%d body=%s", resp.Code, resp.Body.String())
		}
	}
	if probes != 1 {
		t.Fatalf("ready probe count=%d, want cached single probe", probes)
	}
}

func TestTelemetryLimiter(t *testing.T) {
	s := &Server{}
	now := time.Now()
	for i := 0; i < maxTelemetryPerSec; i++ {
		if !s.allowTelemetry(now) {
			t.Fatalf("request %d unexpectedly rate limited", i)
		}
	}
	if s.allowTelemetry(now) {
		t.Fatal("telemetry limiter allowed request beyond per-second budget")
	}
	if !s.allowTelemetry(now.Add(time.Second)) {
		t.Fatal("telemetry limiter did not reset after one second")
	}
}
