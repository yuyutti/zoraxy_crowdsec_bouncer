package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

//go:embed www/*
var content embed.FS

// API response structures
type VersionInfo struct {
	Version    string `json:"version"`
	Latest     string `json:"latest,omitempty"`
	UpdateLink string `json:"updateLink,omitempty"`
	IsLatest   bool   `json:"isLatest"`
	CheckError string `json:"checkError,omitempty"`
}

type MetricsResponse struct {
	BlockedRequests   map[string]float64 `json:"blockedRequests"`
	ProcessedRequests map[string]float64 `json:"processedRequests"`
	BlockRate         float64            `json:"blockRate"`
	Error             string             `json:"error,omitempty"`
}

type HeadersResponse struct {
	Headers map[string][]string `json:"headers"`
}

type ConfigStatusResponse struct {
	InvalidDecisions    uint64    `json:"invalidDecisions"`
	State               string    `json:"state"`
	InitialSyncComplete bool      `json:"initialSyncComplete"`
	LastSyncSuccess     time.Time `json:"lastSyncSuccess"`
	LastFailure         string    `json:"lastFailure,omitempty"`
	ActiveDecisions     int       `json:"activeDecisions"`
	FailurePolicy       string    `json:"failurePolicy"`
	IPResolutionErrors  uint64    `json:"ipResolutionErrors"`
	Onboarding          bool      `json:"onboarding"`
	BlockingEnabled     bool      `json:"blockingEnabled"`
	Message             string    `json:"message,omitempty"`
	MissingFields       []string  `json:"missingFields,omitempty"`
}

var statusMu sync.RWMutex
var statusCounts func() (int, uint64, uint64)
var runtimeConfigStatus = ConfigStatusResponse{State: "stopped", FailurePolicy: "last-known-good-until-expiry"}

func SetStatusCounts(counts func() (int, uint64, uint64)) {
	statusMu.Lock()
	defer statusMu.Unlock()
	statusCounts = counts
}
func SetSyncResult(success bool, failure string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	if success {
		runtimeConfigStatus.InitialSyncComplete = true
		runtimeConfigStatus.LastSyncSuccess = time.Now().UTC()
		runtimeConfigStatus.LastFailure = ""
		runtimeConfigStatus.State = "ready"
		runtimeConfigStatus.BlockingEnabled = true
	} else {
		runtimeConfigStatus.LastFailure = failure
		if runtimeConfigStatus.InitialSyncComplete {
			runtimeConfigStatus.State = "degraded"
		} else {
			runtimeConfigStatus.State = "syncing"
		}
	}
}
func SetError(category string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	runtimeConfigStatus.State, runtimeConfigStatus.LastFailure = "error", category
	runtimeConfigStatus.BlockingEnabled = false
}

func SetStopped() {
	statusMu.Lock()
	defer statusMu.Unlock()
	runtimeConfigStatus.State = "stopped"
	runtimeConfigStatus.BlockingEnabled = false
}

// API handlers
func apiVersionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	response := VersionInfo{
		Version: info.VERSION_STRING,
	}

	// Check for latest version
	latest, err := updates.check(r.Context())
	if err != nil {
		response.CheckError = err.Error()
		response.IsLatest = false
	} else {
		response.Latest = latest
		response.IsLatest = latest == "" || compareVersions(latest, info.VERSION_STRING) <= 0
		if !response.IsLatest {
			response.UpdateLink = fmt.Sprintf("https://github.com/yuyutti/zoraxy_crowdsec_bouncer/releases/tag/%s", latest)
		}
	}

	json.NewEncoder(w).Encode(response)
}

func apiMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	response := MetricsResponse{
		BlockedRequests:   make(map[string]float64),
		ProcessedRequests: make(map[string]float64),
	}

	// Get metrics from Prometheus
	metricFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		response.Error = fmt.Sprintf("Failed to gather metrics: %s", err.Error())
		json.NewEncoder(w).Encode(response)
		return
	}

	// Process metrics
	for _, mf := range metricFamilies {
		metricName := mf.GetName()

		// Only process our bouncer metrics
		if metricName != string(metrics.DROPPED_REQUESTS) && metricName != string(metrics.PROCESSED_REQUESTS) {
			continue
		}

		for _, metric := range mf.GetMetric() {
			var hostname string = "unknown"

			// Extract hostname label
			for _, label := range metric.GetLabel() {
				if label.GetName() == "hostname" {
					hostname = label.GetValue()
					break
				}
			}

			value := metric.GetGauge().GetValue()

			if metricName == string(metrics.DROPPED_REQUESTS) {
				response.BlockedRequests[hostname] += value
			} else if metricName == string(metrics.PROCESSED_REQUESTS) {
				response.ProcessedRequests[hostname] += value
			}
		}
	}

	// Calculate block rate
	totalBlocked := 0.0
	totalProcessed := 0.0

	for _, count := range response.BlockedRequests {
		totalBlocked += count
	}
	for _, count := range response.ProcessedRequests {
		totalProcessed += count
	}

	if totalProcessed > 0 {
		response.BlockRate = (totalBlocked / totalProcessed) * 100
	} else {
		response.BlockRate = 0.0
	}

	json.NewEncoder(w).Encode(response)
}

func apiHeadersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	response := HeadersResponse{
		Headers: make(map[string][]string),
	}

	// Allow ordinary diagnostic headers; private application headers are redacted.
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		sensitive := true
		switch lower {
		case "accept", "accept-encoding", "accept-language", "content-type", "content-length", "user-agent", "connection", "x-forwarded-for", "x-real-ip", "cf-connecting-ip", "cf-connecting-ipv6":
			sensitive = false
		}
		if sensitive {
			response.Headers[name] = []string{"[redacted]"}
		} else {
			response.Headers[name] = append([]string(nil), values...)
		}
	}

	json.NewEncoder(w).Encode(response)
}

func apiConfigStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	statusMu.RLock()
	response, counts := runtimeConfigStatus, statusCounts
	statusMu.RUnlock()
	if counts != nil {
		response.ActiveDecisions, response.IPResolutionErrors, response.InvalidDecisions = counts()
	}
	json.NewEncoder(w).Encode(response)
}

// InitWebServer initializes the web server and serves the plugin UI.
// Also sets up a shutdown handler for graceful shutdown.
//
// Runs everything on the default serve mux.
func InitWebServer(logger *logrus.Logger, g *errgroup.Group, ctx context.Context, port int, configStatus ConfigStatusResponse) {
	statusMu.Lock()
	runtimeConfigStatus = configStatus
	runtimeConfigStatus.FailurePolicy = "last-known-good-until-expiry"
	if runtimeConfigStatus.State == "" {
		if configStatus.Onboarding {
			runtimeConfigStatus.State = "onboarding"
		} else {
			runtimeConfigStatus.State = "syncing"
		}
	}
	statusMu.Unlock()

	mux := http.DefaultServeMux

	// webui and API
	embedWebRouter := zoraxy_plugin.NewPluginEmbedUIRouter(info.PLUGIN_ID, &content, info.WEB_ROOT, info.UI_PATH)
	embedWebRouter.AttachHandlerToMux(mux)

	// Add API endpoints
	mux.HandleFunc(info.UI_PATH+"api/version", apiVersionHandler)
	mux.HandleFunc(info.UI_PATH+"api/metrics", apiMetricsHandler)
	mux.HandleFunc(info.UI_PATH+"api/headers", apiHeadersHandler)
	mux.HandleFunc(info.UI_PATH+"api/config-status", apiConfigStatusHandler)

	serverAddr := fmt.Sprintf("127.0.0.1:%d", port)
	server := &http.Server{
		Addr:              serverAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	g.Go(func() error {
		fmt.Printf("Zoraxy Crowdsec Bouncer started at http://%s%s\n", serverAddr, info.UI_PATH)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("web server failed: %w", err)
		}
		return nil
	})
	// Start a graceful shutdown handler
	g.Go(func() error {
		<-ctx.Done() // Wait for cancellation signal
		return ShutdownWebServer(server, 30*time.Second)
	})
}

// ShutdownWebServer gracefully shuts down the web server with a timeout
func ShutdownWebServer(server *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logrus.Info("Shutting down web server...")
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("web server shutdown failed: %w", err)
	}
	logrus.Info("Web server shutdown complete")
	return nil
}
