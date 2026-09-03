package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxConfiguredBodyBytes int64 = 16 << 20

type Config struct {
	ListenAddr              string
	CoreURL                 string
	CoreInspectPath         string
	CoreTelemetryPath       string
	CoreHealthPath          string
	CoreToken               string
	AdapterToken            string
	RequestTimeout          time.Duration
	TelemetryTimeout        time.Duration
	MaxBodyBytes            int64
	FailMode                string
	ForwardBody             bool
	ForwardSensitiveHeaders bool
	TrustedProxyCIDRs       []string
	HealthCheckEnabled      bool
}

func Default() Config {
	return Config{
		ListenAddr:              "127.0.0.1:9080",
		CoreURL:                 "",
		CoreInspectPath:         "/api/v1/adapter/inspect",
		CoreTelemetryPath:       "/api/v1/adapter/telemetry",
		CoreHealthPath:          "/healthz",
		RequestTimeout:          100 * time.Millisecond,
		TelemetryTimeout:        500 * time.Millisecond,
		MaxBodyBytes:            64 * 1024,
		FailMode:                "closed",
		ForwardBody:             false,
		ForwardSensitiveHeaders: false,
		TrustedProxyCIDRs:       []string{"127.0.0.1/32", "::1/128"},
		HealthCheckEnabled:      true,
	}
}

func FromEnv() (Config, error) {
	cfg := Default()
	readString("CHEESEWAF_ADAPTER_LISTEN", &cfg.ListenAddr)
	readString("CHEESEWAF_CORE_URL", &cfg.CoreURL)
	readString("CHEESEWAF_CORE_INSPECT_PATH", &cfg.CoreInspectPath)
	if value, present := os.LookupEnv("CHEESEWAF_CORE_TELEMETRY_PATH"); present {
		cfg.CoreTelemetryPath = strings.TrimSpace(value)
	}
	if value, present := os.LookupEnv("CHEESEWAF_CORE_HEALTH_PATH"); present {
		cfg.CoreHealthPath = strings.TrimSpace(value)
	}
	readString("CHEESEWAF_CORE_TOKEN", &cfg.CoreToken)
	readString("CHEESEWAF_ADAPTER_TOKEN", &cfg.AdapterToken)
	readString("CHEESEWAF_ADAPTER_FAIL_MODE", &cfg.FailMode)
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_REQUEST_TIMEOUT")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse CHEESEWAF_ADAPTER_REQUEST_TIMEOUT: %w", err)
		}
		cfg.RequestTimeout = value
	}
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_TELEMETRY_TIMEOUT")); raw != "" {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse CHEESEWAF_ADAPTER_TELEMETRY_TIMEOUT: %w", err)
		}
		cfg.TelemetryTimeout = value
	}
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_MAX_BODY_BYTES")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return Config{}, fmt.Errorf("CHEESEWAF_ADAPTER_MAX_BODY_BYTES must be a non-negative integer")
		}
		cfg.MaxBodyBytes = value
	}
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_FORWARD_BODY")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse CHEESEWAF_ADAPTER_FORWARD_BODY: %w", err)
		}
		cfg.ForwardBody = value
	}
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_FORWARD_SENSITIVE_HEADERS")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse CHEESEWAF_ADAPTER_FORWARD_SENSITIVE_HEADERS: %w", err)
		}
		cfg.ForwardSensitiveHeaders = value
	}
	if raw, present := os.LookupEnv("CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS"); present {
		cfg.TrustedProxyCIDRs = cfg.TrustedProxyCIDRs[:0]
		for _, value := range strings.Split(raw, ",") {
			value = strings.TrimSpace(value)
			if value != "" {
				cfg.TrustedProxyCIDRs = append(cfg.TrustedProxyCIDRs, value)
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv("CHEESEWAF_ADAPTER_HEALTH_CHECK")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse CHEESEWAF_ADAPTER_HEALTH_CHECK: %w", err)
		}
		cfg.HealthCheckEnabled = value
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.ListenAddr) == "" {
		return fmt.Errorf("listen address is required")
	}
	if requiresAdapterToken(c.ListenAddr) && strings.TrimSpace(c.AdapterToken) == "" {
		return fmt.Errorf("adapter token is required when listening beyond loopback")
	}
	if strings.TrimSpace(c.CoreURL) == "" {
		return fmt.Errorf("core URL is required")
	}
	if c.CoreToken != "" && !validSecret(c.CoreToken) {
		return fmt.Errorf("core token contains invalid header characters")
	}
	if c.AdapterToken != "" && !validSecret(c.AdapterToken) {
		return fmt.Errorf("adapter token contains invalid header characters")
	}
	for name, path := range map[string]string{
		"core inspect path":   c.CoreInspectPath,
		"core telemetry path": c.CoreTelemetryPath,
		"core health path":    c.CoreHealthPath,
	} {
		if path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("%s must start with /", name)
		}
	}
	if c.RequestTimeout <= 0 || c.TelemetryTimeout <= 0 {
		return fmt.Errorf("timeouts must be positive")
	}
	if c.MaxBodyBytes < 0 {
		return fmt.Errorf("max body bytes must be non-negative")
	}
	if c.MaxBodyBytes > maxConfiguredBodyBytes {
		return fmt.Errorf("max body bytes must not exceed %d", maxConfiguredBodyBytes)
	}
	if c.ForwardBody && c.MaxBodyBytes == 0 {
		return fmt.Errorf("max body bytes must be positive when body forwarding is enabled")
	}
	if c.FailMode != "closed" && c.FailMode != "open" {
		return fmt.Errorf("fail mode must be closed or open")
	}
	for _, raw := range c.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
	}
	return nil
}

func requiresAdapterToken(listenAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(listenAddr))
	if err != nil {
		return true
	}
	if host == "" {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return true
	}
	return !addr.IsLoopback()
}

func validSecret(value string) bool {
	return len(value) <= 16*1024 && !strings.ContainsAny(value, "\r\n") && strings.IndexFunc(value, func(r rune) bool { return r < ' ' || r == 127 }) < 0
}

func readString(name string, target *string) {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		*target = value
	}
}
