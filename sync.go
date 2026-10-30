package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/sirupsen/logrus"
)

type streamFetch func(context.Context, bool) (*models.DecisionsStreamResponse, error)

func runDecisionSync(ctx context.Context, b *csbouncer.StreamBouncer, cache *decisions.Cache, interval time.Duration) error {
	return syncLoop(ctx, cache, interval, func(ctx context.Context, full bool) (*models.DecisionsStreamResponse, error) {
		opts := b.Opts
		opts.Startup = full
		data, resp, err := b.APIClient.Decisions.GetStream(ctx, opts)
		if resp != nil && resp.Response != nil && resp.Response.Body != nil {
			_ = resp.Response.Body.Close()
		}
		csbouncer.TotalLAPICalls.Inc()
		if err != nil {
			csbouncer.TotalLAPIError.Inc()
		}
		return data, err
	})
}

func syncLoop(ctx context.Context, cache *decisions.Cache, interval time.Duration, fetch streamFetch) error {
	full := true
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		update, err := fetch(callCtx, full)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil || update == nil {
			category := "lapi"
			if errors.Is(err, context.DeadlineExceeded) {
				category = "timeout"
			}
			if update == nil && err == nil {
				category = "invalid-response"
			}
			web.SetSyncResult(false, category)
			full = true
		} else {
			if full {
				cache.Replace(update)
			} else {
				cache.Apply(update)
			}
			web.SetSyncResult(true, "")
			full = false
		}
		timer.Reset(interval)
	}
}

// One pending payload is retried unchanged; new deltas are collected only after
// acknowledgement. An ambiguous network timeout may still duplicate at LAPI:
// that API has no idempotency key. Never block decision sync for usage reporting.
func runMetrics(ctx context.Context, client *apiclient.ApiClient, mh *metrics.MetricsHandler, logger *logrus.Logger, interval time.Duration) {
	runMetricsSender(ctx, mh, interval, func(ctx context.Context, payload *models.AllMetrics) bool {
		_, response, err := client.UsageMetrics.Add(ctx, payload)
		if response != nil && response.Response != nil && response.Response.Body != nil {
			defer response.Response.Body.Close()
		}
		if err != nil || response == nil || response.Response == nil || response.Response.StatusCode != http.StatusCreated {
			logger.Warn("Usage metrics delivery failed; retained for retry")
			return false
		}
		return true
	})
}
func runMetricsSender(ctx context.Context, mh *metrics.MetricsHandler, interval time.Duration, send func(context.Context, *models.AllMetrics) bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	startup, version := time.Now().Unix(), info.VERSION_STRING
	var pending *models.AllMetrics
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// Cancellation and a ready tick may be selected in either order. Do
		// not collect/send another window after shutdown has been requested.
		if ctx.Err() != nil {
			return
		}
		if pending == nil {
			component := &models.RemediationComponentsMetrics{
				Type:        info.BOUNCER_TYPE,
				BaseMetrics: models.BaseMetrics{Version: &version, UtcStartupTimestamp: &startup, FeatureFlags: []string{}},
			}
			mh.MetricsUpdater(component, interval)
			pending = &models.AllMetrics{RemediationComponents: []*models.RemediationComponentsMetrics{component}}
		}
		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		success := send(sendCtx, pending)
		cancel()
		if success {
			pending = nil
		}
	}
}
