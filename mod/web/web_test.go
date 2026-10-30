package web

import (
	"context"
	"encoding/json"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpdateCacheTTLBackoffAndOrdering(t *testing.T) {
	var calls atomic.Int32
	var failed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential forwarded")
		}
		if failed.Load() {
			w.WriteHeader(502)
			return
		}
		w.Write([]byte(`[{"tag_name":"v1.2.4-2","prerelease":false},{"tag_name":"v9.0.0-rc1","prerelease":true},{"tag_name":"v1.2.3"},{"tag_name":"v1.2.4-10","prerelease":true},{"tag_name":"v99.0.0","draft":true}]`))
	}))
	defer server.Close()
	now := time.Now()
	c := updateChecker{client: server.Client(), endpoint: server.URL, now: func() time.Time { return now }}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.check(context.Background())
			if err != nil || got != "v1.2.4-2" {
				t.Errorf("update: %s %v", got, err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("checks not coalesced")
	}
	now = now.Add(25 * time.Hour)
	failed.Store(true)
	c.check(context.Background())
	c.check(context.Background())
	if calls.Load() != 2 {
		t.Fatal("failure backoff")
	}
	now = now.Add(6 * time.Minute)
	failed.Store(false)
	if _, err := c.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("cache never refreshed")
	}
	if compareVersions("v1.2.4-2", info.VERSION_STRING) <= 0 || compareVersions("v1.2.3", info.VERSION_STRING) >= 0 {
		t.Fatal("fork version ordering")
	}
}
func TestUpdateUnavailableEmptyCanceledAndOversize(t *testing.T) {
	for _, tt := range []struct {
		status int
		body   string
		bad    bool
	}{{404, "", false}, {200, "[]", false}, {200, "{}", true}, {200, "[", true}, {500, "", true}, {200, strings.Repeat("x", (1<<20)+1), true}} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tt.status); w.Write([]byte(tt.body)) }))
		c := updateChecker{client: server.Client(), endpoint: server.URL, now: time.Now}
		_, err := c.check(context.Background())
		server.Close()
		if (err != nil) != tt.bad {
			t.Fatalf("%d %s: %v", tt.status, tt.body, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := updateChecker{client: &http.Client{}, endpoint: "https://example.invalid", now: time.Now}
	if _, err := c.check(ctx); err == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestHeadersRedactionAndStatus(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	for _, key := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-Api-Key", "X-Csrf-Token", "X-Secret"} {
		r.Header.Set(key, "fixture-sensitive")
	}
	r.Header.Set("Accept", "a&b")
	w := httptest.NewRecorder()
	apiHeadersHandler(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cacheable headers")
	}
	var response HeadersResponse
	if json.Unmarshal(w.Body.Bytes(), &response) != nil {
		t.Fatal("invalid JSON")
	}
	for key, values := range response.Headers {
		if key != "Accept" && values[0] != "[redacted]" {
			t.Fatalf("unredacted %s", key)
		}
	}
	statusMu.Lock()
	runtimeConfigStatus = ConfigStatusResponse{State: "syncing"}
	statusMu.Unlock()
	SetSyncResult(true, "")
	SetSyncResult(false, "timeout")
	w = httptest.NewRecorder()
	apiConfigStatusHandler(w, r)
	var state ConfigStatusResponse
	json.Unmarshal(w.Body.Bytes(), &state)
	if state.State != "degraded" || !state.InitialSyncComplete || state.LastSyncSuccess.IsZero() {
		t.Fatalf("bad state: %+v", state)
	}
	SetStopped()
}
func TestMetricsSumAcrossOrigins(t *testing.T) {
	registry := prometheus.NewRegistry()
	previous := prometheus.DefaultGatherer
	prometheus.DefaultGatherer = registry
	defer func() { prometheus.DefaultGatherer = previous }()
	registry.MustRegister(metrics.Map[metrics.DROPPED_REQUESTS].Gauge)
	gauge := metrics.Map[metrics.DROPPED_REQUESTS].Gauge
	gauge.Reset()
	defer gauge.Reset()
	gauge.WithLabelValues("cscli", "example.com").Set(2)
	gauge.WithLabelValues("crowdsec", "example.com").Set(3)
	w := httptest.NewRecorder()
	apiMetricsHandler(w, httptest.NewRequest("GET", "/", nil))
	var response MetricsResponse
	json.Unmarshal(w.Body.Bytes(), &response)
	if response.BlockedRequests["example.com"] != 5 {
		t.Fatal(response)
	}
}

func TestHTTPServerCancellation(t *testing.T) {
	previous := http.DefaultServeMux
	http.DefaultServeMux = http.NewServeMux()
	defer func() { http.DefaultServeMux = previous }()
	ctx, cancel := context.WithCancel(context.Background())
	g, groupCtx := errgroup.WithContext(ctx)
	InitWebServer(logrus.New(), g, groupCtx, 0, ConfigStatusResponse{Onboarding: true})
	cancel()
	done := make(chan error, 1)
	go func() { done <- g.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP goroutines did not stop")
	}
}

func TestVersionSyntax(t *testing.T) {
	for _, tag := range []string{"v1.2.+3", "v01.2.3", "v1.2.4-rc1", "v1.2.4-", "v1.2.4-01", "v1.2.4/evil"} {
		if _, ok := versionParts(tag); ok {
			t.Fatalf("invalid version accepted: %s", tag)
		}
	}
}

func TestUpdateClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	c := updateChecker{client: &http.Client{Timeout: 20 * time.Millisecond}, endpoint: server.URL, now: time.Now}
	if _, err := c.check(context.Background()); err == nil {
		t.Fatal("timeout not reported")
	}
}
