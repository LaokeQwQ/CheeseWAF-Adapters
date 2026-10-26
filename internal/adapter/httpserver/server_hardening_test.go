package httpserver

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/config"
	"github.com/LaokeQwQ/CheeseWAF-Adapters/internal/coreclient"
)

func newHardeningServer(t *testing.T, coreHandler http.HandlerFunc, mutate func(*config.Config)) *Server {
	t.Helper()
	core := httptest.NewServer(coreHandler)
	t.Cleanup(core.Close)
	client, err := coreclient.New(coreclient.Config{
		BaseURL:     core.URL,
		InspectPath: "/inspect",
		HTTPClient:  core.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.CoreURL = core.URL
	if mutate != nil {
		mutate(&cfg)
	}
	server, err := New(cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func serve(t *testing.T, server *Server, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestChallengeResponseCarriesAuthCookieAndBody(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"action":"challenge",
			"status_code":401,
			"headers":{"WWW-Authenticate":"Basic realm=\"waf\"","X-Unknown":"drop-me"},
			"set_cookies":["cw_session=abc; Path=/; HttpOnly"],
			"body":"dmVyaWZ5",
			"body_content_type":"text/plain; charset=utf-8"
		}`))
	}, nil)

	response := serve(t, server, httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("WWW-Authenticate"); got != `Basic realm="waf"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	if got := response.Header().Values("Set-Cookie"); len(got) != 1 || !strings.Contains(got[0], "cw_session=abc") {
		t.Fatalf("Set-Cookie = %v", got)
	}
	if response.Body.String() != "verify" {
		t.Fatalf("body = %q", response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header().Get("X-Unknown"); got != "" {
		t.Fatalf("unknown header leaked: %q", got)
	}
	if got := response.Header().Get("X-CheeseWAF-Decision"); got != "challenge" {
		t.Fatalf("decision header = %q", got)
	}
}

func TestAuthzAcceptsAnyValidMethod(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}, nil)

	request := httptest.NewRequest(http.MethodPut, "http://adapter/envoy/check", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Original-Method", http.MethodPut)
	request.Header.Set("X-Original-URI", "/api/item/1")
	request.Header.Set("X-Forwarded-Host", "app.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	response := serve(t, server, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", response.Code, response.Body.String())
	}
}

func TestAuthzRequiresTrustedGatewayMetadata(t *testing.T) {
	called := false
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/nginx/auth", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	if called {
		t.Fatal("core was called without required gateway metadata")
	}
}

func TestMetadataRouteReportsWithheldBody(t *testing.T) {
	var got inspectionv1.Request
	server := newHardeningServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}, func(cfg *config.Config) { cfg.ForwardBody = false })

	request := httptest.NewRequest(http.MethodPost, "http://adapter/nginx/auth", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Original-Method", http.MethodPost)
	request.Header.Set("X-Original-URI", "/upload")
	request.Header.Set("X-Forwarded-Host", "app.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	response := serve(t, server, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
	if got.BodyState != inspectionv1.BodyStateWithheld {
		t.Fatalf("body_state = %q, want withheld", got.BodyState)
	}
	if got.BodyForwarded {
		t.Fatal("metadata route claimed a forwarded body")
	}
}

func TestBodyCheckRequiresBody(t *testing.T) {
	called := false
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}, func(cfg *config.Config) { cfg.ForwardBody = true; cfg.MaxBodyBytes = 1024 })

	request := httptest.NewRequest(http.MethodPost, "http://adapter/nginx/body-check", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Original-Method", http.MethodPost)
	request.Header.Set("X-Original-URI", "/upload")
	request.Header.Set("X-Forwarded-Host", "app.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	if called {
		t.Fatal("core was called for an empty body-check request")
	}
}

func TestTruncatedBodyStripsContentLength(t *testing.T) {
	var got inspectionv1.Request
	server := newHardeningServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"block","status_code":403}`))
	}, func(cfg *config.Config) { cfg.ForwardBody = true; cfg.MaxBodyBytes = 4 })

	request := httptest.NewRequest(http.MethodPost, "http://adapter/nginx/body-check", bytes.NewBufferString("abcdef"))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Content-Length", "6")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Original-Method", http.MethodPost)
	request.Header.Set("X-Original-URI", "/upload")
	request.Header.Set("X-Forwarded-Host", "app.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	response := serve(t, server, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", response.Code, response.Body.String())
	}
	if _, exists := got.Headers["Content-Length"]; exists {
		t.Fatalf("Content-Length leaked to core: %v", got.Headers["Content-Length"])
	}
	if string(got.Body) != "abcd" || !got.BodyTruncated {
		t.Fatalf("body=%q truncated=%v", got.Body, got.BodyTruncated)
	}
	if got.BodyState != inspectionv1.BodyStateTruncated {
		t.Fatalf("body_state = %q", got.BodyState)
	}
}

func TestDuplicateSingleValueHeaderRejected(t *testing.T) {
	called := false
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Add("Content-Type", "multipart/form-data; boundary=x")
	request.Header.Add("Content-Type", "application/json")
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
	if called {
		t.Fatal("core was called with ambiguous single-value headers")
	}
}

func TestPercentEncodedControlRejected(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Original-URI", "/a%0d%0ab")
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Original-URI", "/a\xffb")
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestConnectionNominatedHeaderStripped(t *testing.T) {
	var got inspectionv1.Request
	server := newHardeningServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("Connection", "X-Hop-Only")
	request.Header.Set("X-Hop-Only", "should-not-reach-core")
	response := serve(t, server, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
	if _, exists := got.Headers["X-Hop-Only"]; exists {
		t.Fatalf("connection-nominated header leaked: %v", got.Headers["X-Hop-Only"])
	}
}

func TestAmbiguousTrustedXFFRejected(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "127.0.0.1, 127.0.0.1")
	response := serve(t, server, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}
}

func TestSingleTrustedXFFAccepted(t *testing.T) {
	var got inspectionv1.Request
	server := newHardeningServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "127.0.0.1")
	response := serve(t, server, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
	if got.Client.IP != "127.0.0.1" {
		t.Fatalf("client ip = %q", got.Client.IP)
	}
}

func TestIPv4MappedTrustedPeer(t *testing.T) {
	var got inspectionv1.Request
	server := newHardeningServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}, nil)

	request := httptest.NewRequest(http.MethodGet, "http://adapter/v1/authz", nil)
	request.RemoteAddr = "[::ffff:127.0.0.1]:1234"
	request.Header.Set("X-Original-URI", "/mapped")
	request.Header.Set("X-Original-Method", http.MethodGet)
	response := serve(t, server, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", response.Code, response.Body.String())
	}
	if got.Path != "/mapped" {
		t.Fatalf("path = %q, want /mapped", got.Path)
	}
}

func TestGatewayRequestIDIsRedactedInLogs(t *testing.T) {
	server := newHardeningServer(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("core was called for a rejected request")
	}, func(cfg *config.Config) { cfg.ForwardBody = true; cfg.MaxBodyBytes = 1024 })

	var logs bytes.Buffer
	server.logger = slog.New(slog.NewTextHandler(&logs, nil))

	const marker = "gw-req-9f2b7c1d"
	request := httptest.NewRequest(http.MethodPost, "http://adapter/nginx/body-check", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Header.Set("X-Request-ID", marker)
	request.Header.Set("X-Original-Method", http.MethodPost)
	request.Header.Set("X-Original-URI", "/upload")
	request.Header.Set("X-Forwarded-Host", "app.example")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Real-IP", "203.0.113.10")
	if response := serve(t, server, request); response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", response.Code, response.Body.String())
	}

	if logs.Len() == 0 {
		t.Fatal("no log line captured")
	}
	if strings.Contains(logs.String(), marker) {
		t.Fatalf("gateway request id reached the log stream: %s", logs.String())
	}
	if !strings.Contains(logs.String(), redactRequestID(marker)) {
		t.Fatalf("log line lost request correlation: %s", logs.String())
	}
}
