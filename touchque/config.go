package touchque

import (
	"net/url"
	"os"
	"strings"
)

// DefaultBaseURL is used when Config.BaseURL and TQ_API_URL are both unset.
const DefaultBaseURL = "https://api.touchque.com"

// Config holds the configuration options for the TouchQue SDK.
type Config struct {
	APIKey    string
	APISecret string
	BaseURL   string
	TimeoutMs int
}

// DefaultConfig creates a new Config with standard defaults.
func DefaultConfig(apiKey, apiSecret string) *Config {
	return &Config{
		APIKey:    apiKey,
		APISecret: apiSecret,
		BaseURL:   DefaultBaseURL,
		TimeoutMs: 10000,
	}
}

// ConfigFromEnv builds a Config from TQ_API_KEY / TQ_API_SECRET / TQ_API_URL.
func ConfigFromEnv() (*Config, error) {
	apiKey := os.Getenv("TQ_API_KEY")
	apiSecret := os.Getenv("TQ_API_SECRET")
	if apiKey == "" || apiSecret == "" {
		return nil, &ConfigError{Message: "touchque: set TQ_API_KEY and TQ_API_SECRET (or pass a *Config to NewClient)"}
	}
	baseURL := os.Getenv("TQ_API_URL")
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	cfg := &Config{APIKey: apiKey, APISecret: apiSecret, BaseURL: baseURL, TimeoutMs: 10000}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var localHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// assertSafeBaseURL allows plaintext http only for localhost / loopback.
func assertSafeBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &ConfigError{Message: "touchque: BaseURL is not a valid URL: " + raw}
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if localHosts[strings.ToLower(u.Hostname())] {
			return nil
		}
		return &ConfigError{Message: "touchque: refusing a plaintext http:// BaseURL for \"" + u.Hostname() +
			"\" — the API key and request signature would be sent in the clear; use https://"}
	default:
		return &ConfigError{Message: "touchque: BaseURL must be http(s): " + raw}
	}
}

// Validate checks the config and fills in defaults (BaseURL, TimeoutMs), without panicking.
func (c *Config) Validate() error {
	if !strings.HasPrefix(c.APIKey, "tq_") {
		return &ConfigError{Message: "touchque: APIKey must start with 'tq_'. Did you accidentally swap APIKey and APISecret?"}
	}
	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if err := assertSafeBaseURL(c.BaseURL); err != nil {
		return err
	}
	if c.TimeoutMs <= 0 {
		c.TimeoutMs = 10000
	}
	return nil
}

// sanitize keeps NewClient's original panicking behavior for existing callers.
func (c *Config) sanitize() {
	if err := c.Validate(); err != nil {
		panic(err.Error())
	}
}
