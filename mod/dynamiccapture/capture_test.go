package dynamiccapture

import (
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlockResponses(t *testing.T) {
	for _, tt := range []struct {
		cfg      config.BlockResponseConfig
		status   int
		contains string
	}{
		{config.BlockResponseConfig{}, 403, "Forbidden"},
		{config.BlockResponseConfig{Page: "default"}, 403, "Forbidden"},
		{config.BlockResponseConfig{StatusCode: 418, Page: "evil"}, 418, "666 Evil"},
		{config.BlockResponseConfig{Page: "evil"}, 403, "HTTP 403"},
	} {
		h, err := NewBlockHandler(tt.cfg, "config.yaml")
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, "http://example.com/path?secret=hidden", nil))
			resp := w.Result()
			if resp.StatusCode != tt.status || resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(resp.Header.Get("Content-Type"), "charset=utf-8") {
				t.Fatalf("bad response: %#v", resp)
			}
			if method == http.MethodHead {
				if w.Body.Len() != 0 {
					t.Fatal("HEAD body")
				}
			} else if !strings.Contains(w.Body.String(), tt.contains) {
				t.Fatal(w.Body.String())
			}
			if tt.cfg.Page != "evil" && method == http.MethodGet && w.Body.String() != "Forbidden" {
				t.Fatal("default body changed")
			}
		}
	}
}
func TestCustomPageLoadedOnceAndFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.html")
	if err := os.WriteFile(path, []byte("<!doctype html><h1>Blocked</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.BlockResponseConfig{Page: "custom", CustomPage: "blocked.html"}
	h, err := NewBlockHandler(cfg, filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), "Blocked") {
		t.Fatal("page wasn't preloaded")
	}
	h, err = NewBlockHandler(cfg, filepath.Join(dir, "config.yaml"))
	if err == nil {
		t.Fatal("missing custom file accepted")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 403 || w.Body.String() != "Forbidden" {
		t.Fatal("failed open")
	}
}
func TestSniffSpoofAndErrorPolicies(t *testing.T) {
	logger := logrus.New()
	mh := metrics.NewMetricsHandler(logger)
	cfg := &config.PluginConfig{}
	if err := cfg.PostProcess(); err != nil {
		t.Fatal(err)
	}
	cache := decisions.NewCache()
	scope, value, kind, duration := "ip", "192.0.2.1", "ban", "1h"
	cache.Apply(&models.DecisionsStreamResponse{New: []*models.Decision{{ID: 1, Scope: &scope, Value: &value, Type: &kind, Duration: &duration}}})
	for _, req := range []*plugin.DynamicSniffForwardRequest{
		nil, {RemoteAddr: "192.0.2.1:80", Header: map[string][]string{"X-Real-IP": {"invalid"}}}, {ClientIP: "invalid", RemoteAddr: "198.51.100.1"},
	} {
		if SniffHandler(logger, mh, cfg, req, cache) != plugin.SniffResultAccept {
			t.Fatal("failed open")
		}
	}
	if mh.IPResolutionErrors.Load() != 2 {
		t.Fatal("resolution errors not separate")
	}
	if SniffHandler(logger, mh, cfg, &plugin.DynamicSniffForwardRequest{RemoteAddr: "198.51.100.1"}, cache) != plugin.SniffResultSkip {
		t.Fatal("unbanned client rejected")
	}
}
func FuzzBlockRequest(f *testing.F) {
	f.Add("GET", "/path?token=secret")
	h, _ := NewBlockHandler(config.BlockResponseConfig{Page: "evil", StatusCode: 418}, "config.yaml")
	f.Fuzz(func(t *testing.T, method, uri string) {
		r := &http.Request{Method: method, RequestURI: uri}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 418 {
			t.Fatal(w.Code)
		}
	})
}

func TestCustomOversizeAndInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocked.html")
	for _, body := range [][]byte{[]byte(strings.Repeat("x", maxPageBytes+1)), {0xff, 0xfe}} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		h, err := NewBlockHandler(config.BlockResponseConfig{Page: "custom", CustomPage: path}, filepath.Join(dir, "config.yaml"))
		if err == nil {
			t.Fatal("invalid custom page accepted")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 403 || w.Body.String() != "Forbidden" {
			t.Fatal("invalid custom file failed open")
		}
	}
}
