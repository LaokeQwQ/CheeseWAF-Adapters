package coreclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
)

func TestNewRejectsPlaintextRemoteCoreWithoutToken(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://core.example", InspectPath: "/inspect"}); err == nil {
		t.Fatal("plaintext remote core without token unexpectedly accepted")
	}
}

func TestNewAllowsPlaintextLoopbackCore(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8080", InspectPath: "/inspect"}); err != nil {
		t.Fatalf("loopback core rejected: %v", err)
	}
}

func TestNewRedactsUserinfoFromParseError(t *testing.T) {
	_, err := New(Config{BaseURL: "http://user:supersecret@[::1", InspectPath: "/inspect"})
	if err == nil {
		t.Fatal("malformed URL unexpectedly accepted")
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("error leaked userinfo: %v", err)
	}
	if !strings.Contains(err.Error(), "***@") {
		t.Fatalf("error did not keep a redacted authority: %v", err)
	}
}

func TestNewDefaultTransportDisablesProxyAndUsesNoGlobalTimeout(t *testing.T) {
	client, err := New(Config{BaseURL: "https://core.example", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	if client.httpClient.Timeout != 0 {
		t.Fatalf("default client timeout = %s, want 0 (context governed)", client.httpClient.Timeout)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport type = %T", client.httpClient.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("default transport must not inherit environment proxies")
	}
	if transport.MaxIdleConnsPerHost < 16 || transport.MaxConnsPerHost < 64 {
		t.Fatalf("unexpected pool limits: idle=%d max=%d", transport.MaxIdleConnsPerHost, transport.MaxConnsPerHost)
	}
}

func TestNewAppliesTLSConfig(t *testing.T) {
	client, err := New(Config{
		BaseURL:     "https://core.example",
		InspectPath: "/inspect",
		TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.httpClient.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS config not applied: %+v", transport.TLSClientConfig)
	}
}

func TestEmitTelemetryDefaultsContractVersion(t *testing.T) {
	var got TelemetryEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode telemetry: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client, err := New(Config{
		BaseURL:       server.URL,
		InspectPath:   "/inspect",
		TelemetryPath: "/telemetry",
		HTTPClient:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.EmitTelemetry(context.Background(), TelemetryEvent{Action: inspectionv1.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if got.ContractVersion != inspectionv1.Version {
		t.Fatalf("contract version = %q", got.ContractVersion)
	}
	if got.Source != inspectionv1.SourceGeneric {
		t.Fatalf("source = %q", got.Source)
	}
}

func TestEmitTelemetryDisabledReturnsSentinel(t *testing.T) {
	client, err := New(Config{BaseURL: "http://127.0.0.1:8080", InspectPath: "/inspect", TelemetryPath: ""})
	if err != nil {
		t.Fatal(err)
	}
	err = client.EmitTelemetry(context.Background(), TelemetryEvent{
		ContractVersion: inspectionv1.Version,
		Source:          inspectionv1.SourceGeneric,
		Action:          inspectionv1.ActionAllow,
	})
	if !errors.Is(err, ErrTelemetryDisabled) {
		t.Fatalf("error = %v, want ErrTelemetryDisabled", err)
	}
}
