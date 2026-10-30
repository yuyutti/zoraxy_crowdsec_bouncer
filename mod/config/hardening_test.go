package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictConfigAndSecrets(t *testing.T) {
	for _, yaml := range []string{"api_key: fixture-secret\nunknown: fixture-secret\n", "api_key: fixture-secret\napi_key: fixture-secret\n", "block_response:\n    status_code: 666\n", "stream_update_frequency: -1s\n", "block_response:\n    status_code: 0\n", "log_level: fixture-secret\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte(yaml), 0600)
		c := PluginConfig{ConfigPath: path}
		err := c.LoadConfig()
		if err == nil {
			t.Fatalf("accepted invalid config: %s", yaml)
		}
		if strings.Contains(err.Error(), "fixture-secret") {
			t.Fatal("secret in configuration error")
		}
	}
}
func TestBlockConfigValidation(t *testing.T) {
	for _, cfg := range []BlockResponseConfig{{StatusCode: 666}, {StatusCode: 401}, {StatusCode: 407}, {StatusCode: 200}, {StatusCode: 302}, {StatusCode: 600}, {StatusCode: -1}, {Page: "unknown"}, {Page: "custom"}, {CustomPage: "file.html"}} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
	for _, status := range []int{403, 418, 451, 503} {
		cfg := BlockResponseConfig{StatusCode: status, Page: "evil"}
		if err := cfg.Validate(); err != nil || cfg.StatusCode != status {
			t.Fatal("page changed status")
		}
	}
}
