package coreclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	inspectionv1 "github.com/LaokeQwQ/CheeseWAF-Adapters/contracts/inspection/v1"
)

func TestInspect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inspect" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected request: path=%s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"block","reason":"test","policy_version":"p1"}`))
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:     server.URL,
		InspectPath: "/inspect",
		Token:       "test-token",
		HTTPClient:  server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Inspect(context.Background(), inspectionv1.Request{
		Method: "GET",
		Path:   "/admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Action != inspectionv1.ActionBlock || decision.StatusCode != http.StatusForbidden {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestInspectRejectsInvalidRequest(t *testing.T) {
	client, err := New(Config{BaseURL: "http://core.test", InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inspect(context.Background(), inspectionv1.Request{Method: "GET", Path: "relative"}); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestTelemetry(t *testing.T) {
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/telemetry" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		called <- struct{}{}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, InspectPath: "/inspect", TelemetryPath: "/telemetry", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.EmitTelemetry(ctx, TelemetryEvent{ContractVersion: inspectionv1.Version, Action: inspectionv1.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestInspectRejectsUnknownDecisionAsProtocolError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"action\":\"not-a-real-action\"}"))
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, InspectPath: "/inspect", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inspect(context.Background(), inspectionv1.Request{Method: http.MethodGet, Path: "/"})
	if err == nil || !IsProtocolError(err) {
		t.Fatalf("error=%v, want protocol error", err)
	}
}

func TestReadyUsesHealthPathAndToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected health request: method=%s path=%s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client, err := New(Config{BaseURL: server.URL, InspectPath: "/inspect", HealthPath: "/healthz", Token: "test-token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNewRejectsRedirects(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client, err := New(Config{BaseURL: redirect.URL, InspectPath: "/inspect"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inspect(context.Background(), inspectionv1.Request{Method: http.MethodGet, Path: "/"})
	if err == nil || !IsProtocolError(err) {
		t.Fatalf("redirect error=%v, want protocol error", err)
	}
}

func TestNewRejectsTokenOverPlaintextRemoteURL(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://core.example", InspectPath: "/inspect", Token: "secret"}); err == nil {
		t.Fatal("expected plaintext remote token rejection")
	}
}

func TestNewRejectsTokenWithControlCharacters(t *testing.T) {
	if _, err := New(Config{BaseURL: "http://127.0.0.1:8080", InspectPath: "/inspect", Token: "bad\nvalue"}); err == nil {
		t.Fatal("expected invalid token rejection")
	}
}

func TestInspectDoesNotClassifyLocalRoundTripperErrorAsTransport(t *testing.T) {
	client, err := New(Config{
		BaseURL:     "http://127.0.0.1:8080",
		InspectPath: "/inspect",
		HTTPClient:  &http.Client{Transport: failingRoundTripper{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inspect(context.Background(), inspectionv1.Request{Method: http.MethodGet, Path: "/"})
	if err == nil || !IsProtocolError(err) || IsTransportError(err) {
		t.Fatalf("round tripper error=%v, protocol=%v transport=%v; want protocol only", err, IsProtocolError(err), IsTransportError(err))
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("invalid header field value")
}

func TestTelemetryRejectsInvalidMetadata(t *testing.T) {
	client, err := New(Config{BaseURL: "http://127.0.0.1:8080", InspectPath: "/inspect", TelemetryPath: "/telemetry"})
	if err != nil {
		t.Fatal(err)
	}
	base := TelemetryEvent{ContractVersion: inspectionv1.Version, Source: inspectionv1.SourceGeneric, Action: inspectionv1.ActionAllow}
	for name, event := range map[string]TelemetryEvent{
		"negative latency": baseWith(base, func(e *TelemetryEvent) { e.LatencyNanos = -1 }),
		"bad path":         baseWith(base, func(e *TelemetryEvent) { e.Path = "relative" }),
		"control id":       baseWith(base, func(e *TelemetryEvent) { e.RequestID = "bad\nvalue" }),
	} {
		if err := client.EmitTelemetry(context.Background(), event); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func baseWith(base TelemetryEvent, mutate func(*TelemetryEvent)) TelemetryEvent {
	mutate(&base)
	return base
}
