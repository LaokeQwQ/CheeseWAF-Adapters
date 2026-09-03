package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultIsFailClosed(t *testing.T) {
	cfg := Default()
	if cfg.FailMode != "closed" {
		t.Fatalf("default fail mode = %q, want closed", cfg.FailMode)
	}
	if cfg.ForwardBody {
		t.Fatal("request bodies must be opt-in")
	}
	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[0] != "127.0.0.1/32" {
		t.Fatalf("unexpected trusted proxy defaults: %v", cfg.TrustedProxyCIDRs)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("CHEESEWAF_ADAPTER_LISTEN", "127.0.0.1:9999")
	t.Setenv("CHEESEWAF_CORE_URL", "http://core.test")
	t.Setenv("CHEESEWAF_ADAPTER_REQUEST_TIMEOUT", "250ms")
	t.Setenv("CHEESEWAF_ADAPTER_FORWARD_BODY", "true")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" || cfg.CoreURL != "http://core.test" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.RequestTimeout != 250*time.Millisecond || !cfg.ForwardBody {
		t.Fatalf("unexpected parsed values: %+v", cfg)
	}
	_ = os.Unsetenv("CHEESEWAF_ADAPTER_LISTEN")
}

func TestValidateRejectsInvalidFailMode(t *testing.T) {
	cfg := Default()
	cfg.CoreURL = "http://core.test"
	cfg.FailMode = "sometimes"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid fail mode error")
	}
}

func TestValidateRejectsUnboundedBodyConfig(t *testing.T) {
	cfg := Default()
	cfg.CoreURL = "http://core.test"
	cfg.MaxBodyBytes = 17 << 20
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected body size limit error")
	}
}

func TestValidateRequiresTokenForPublicListen(t *testing.T) {
	cfg := Default()
	cfg.CoreURL = "http://core.test"
	cfg.ListenAddr = ":9080"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected adapter token requirement")
	}
	cfg.AdapterToken = "adapter-secret"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFromEnvCanClearHealthAndTrustedProxyDefaults(t *testing.T) {
	t.Setenv("CHEESEWAF_CORE_URL", "http://core.test")
	t.Setenv("CHEESEWAF_CORE_HEALTH_PATH", "")
	t.Setenv("CHEESEWAF_ADAPTER_TRUSTED_PROXY_CIDRS", "")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CoreHealthPath != "" || len(cfg.TrustedProxyCIDRs) != 0 {
		t.Fatalf("empty env values did not clear defaults: %+v", cfg)
	}
}

func TestValidateRejectsInvalidTrustedProxyCIDR(t *testing.T) {
	cfg := Default()
	cfg.CoreURL = "http://core.test"
	cfg.TrustedProxyCIDRs = []string{"not-a-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected trusted proxy CIDR error")
	}
}
