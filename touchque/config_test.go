package touchque

import "testing"

func TestSanitize_PanicsWhenAPIKeyMissingTqPrefix(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected sanitize() to panic on an invalid apiKey prefix")
		}
	}()
	c := &Config{APIKey: "wrong_prefix", APISecret: "shh"}
	c.sanitize()
}

func TestSanitize_FillsDefaultsWhenUnset(t *testing.T) {
	c := &Config{APIKey: "tq_auth_x", APISecret: "shh"}
	c.sanitize()
	if c.BaseURL != "https://api.touchque.com" {
		t.Fatalf("expected default BaseURL, got %q", c.BaseURL)
	}
	if c.TimeoutMs != 10000 {
		t.Fatalf("expected default TimeoutMs 10000, got %d", c.TimeoutMs)
	}
}

func TestSanitize_StripsTrailingSlashFromBaseURL(t *testing.T) {
	c := &Config{APIKey: "tq_auth_x", APISecret: "shh", BaseURL: "http://localhost:9999/"}
	c.sanitize()
	if c.BaseURL != "http://localhost:9999" {
		t.Fatalf("expected trailing slash stripped, got %q", c.BaseURL)
	}
}

func TestSanitize_PanicsOnPlaintextHTTPToNonLocalhost(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected sanitize() to panic on a plaintext http:// non-localhost BaseURL")
		}
	}()
	c := &Config{APIKey: "tq_auth_x", APISecret: "shh", BaseURL: "http://api.example.com"}
	c.sanitize()
}

func TestSanitize_AllowsPlaintextHTTPForLoopback(t *testing.T) {
	c := &Config{APIKey: "tq_auth_x", APISecret: "shh", BaseURL: "http://127.0.0.1:9999"}
	c.sanitize()
	if c.BaseURL != "http://127.0.0.1:9999" {
		t.Fatalf("expected loopback http to be allowed, got %q", c.BaseURL)
	}
}

func TestDefaultConfig_ReturnsExpectedShape(t *testing.T) {
	c := DefaultConfig("tq_auth_x", "shh")
	if c.APIKey != "tq_auth_x" || c.APISecret != "shh" {
		t.Fatal("DefaultConfig did not preserve provided credentials")
	}
	if c.BaseURL != "https://api.touchque.com" || c.TimeoutMs != 10000 {
		t.Fatal("DefaultConfig did not apply expected defaults")
	}
}

func TestConfigFromEnv_ReadsCredentialsAndURL(t *testing.T) {
	t.Setenv("TQ_API_KEY", "tq_env_key")
	t.Setenv("TQ_API_SECRET", "env_secret")
	t.Setenv("TQ_API_URL", "https://custom.example.com")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey != "tq_env_key" || cfg.APISecret != "env_secret" || cfg.BaseURL != "https://custom.example.com" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestConfigFromEnv_MissingCredentialsReturnsConfigError(t *testing.T) {
	t.Setenv("TQ_API_KEY", "")
	t.Setenv("TQ_API_SECRET", "")
	_, err := ConfigFromEnv()
	if _, ok := err.(*ConfigError); !ok {
		t.Fatalf("expected *ConfigError, got %T (%v)", err, err)
	}
}
