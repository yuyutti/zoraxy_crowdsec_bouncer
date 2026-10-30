package main

import (
	"context"
	"errors"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/sirupsen/logrus"
	"testing"
	"time"
)

func TestSyncOutageRequestsFullSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := decisions.NewCache()
	calls := 0
	err := syncLoop(ctx, cache, time.Nanosecond, func(_ context.Context, full bool) (*models.DecisionsStreamResponse, error) {
		calls++
		if full != (calls == 1 || calls == 3) {
			t.Errorf("call %d full=%v", calls, full)
		}
		switch calls {
		case 1:
			scope, value, kind, duration := "ip", "192.0.2.1", "ban", "1h"
			return &models.DecisionsStreamResponse{New: []*models.Decision{{ID: 1, Scope: &scope, Value: &value, Type: &kind, Duration: &duration}}}, nil
		case 2:
			return nil, errors.New("fixture outage")
		case 3:
			if cache.GetBan("192.0.2.1") == nil {
				t.Error("outage discarded last-known-good")
			}
			return &models.DecisionsStreamResponse{}, nil
		default:
			if cache.GetBan("192.0.2.1") != nil {
				t.Error("full snapshot left stale ban")
			}
			cancel()
			return nil, context.Canceled
		}
	})
	if err != nil || calls != 4 {
		t.Fatalf("%d %v", calls, err)
	}
}
func TestSyncCancellationAndMetricsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := syncLoop(ctx, decisions.NewCache(), time.Second, func(ctx context.Context, _ bool) (*models.DecisionsStreamResponse, error) { return nil, ctx.Err() }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	var first *models.AllMetrics
	mh := metrics.NewMetricsHandler(logrus.New())
	runMetricsSender(ctx, mh, time.Nanosecond, func(_ context.Context, payload *models.AllMetrics) bool {
		calls++
		if calls == 1 {
			first = payload
			return false
		}
		if first != payload {
			t.Fatal("failed metrics payload discarded")
		}
		cancel()
		return true
	})
	if calls != 2 {
		t.Fatal(calls)
	}
}
