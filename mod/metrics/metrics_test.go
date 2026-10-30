package metrics

import (
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
	"sync"
	"testing"
	"time"
)

func TestDeltasResetWindowsAndCardinality(t *testing.T) {
	registry := prometheus.NewRegistry()
	previous := prometheus.DefaultGatherer
	prometheus.DefaultGatherer = registry
	defer func() { prometheus.DefaultGatherer = previous }()
	for _, cfg := range Map {
		cfg.Gauge.Reset()
		cfg.LastValueMap = map[string]float64{}
		registry.MustRegister(cfg.Gauge)
	}
	mh := NewMetricsHandler(logrus.New())
	gauge := Map[PROCESSED_REQUESTS].Gauge
	gauge.WithLabelValues("fixture.example").Set(100)
	first := &models.DetailedMetrics{}
	met := &models.RemediationComponentsMetrics{}
	met.Metrics = []*models.DetailedMetrics{first}
	mh.MetricsUpdater(met, time.Second)
	if len(first.Items) != 0 || len(met.Metrics) != 2 {
		t.Fatal("wrong metrics window")
	}
	gauge.WithLabelValues("fixture.example").Set(5)
	met = &models.RemediationComponentsMetrics{}
	mh.MetricsUpdater(met, time.Second)
	if len(met.Metrics[0].Items) != 1 || *met.Metrics[0].Items[0].Value != 5 {
		t.Fatalf("reset delta: %+v", met.Metrics[0].Items)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				mh.MarkRequestDropped("fixture.example", nil)
				mh.MetricsUpdater(&models.RemediationComponentsMetrics{}, time.Second)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 1024; i++ {
		boundedHostname(time.Unix(int64(i), 0).String())
	}
	labelMu.Lock()
	count := len(knownHosts)
	labelMu.Unlock()
	if count > 256 {
		t.Fatal("unbounded host map")
	}
	if boundedOrigin("arbitrary") != "unknown" {
		t.Fatal("unbounded origin")
	}
	pair := func(name, value string) *dto.LabelPair { return &dto.LabelPair{Name: &name, Value: &value} }
	key := Map[DROPPED_REQUESTS].KeyFunc
	if key([]*dto.LabelPair{pair("origin", "ab"), pair("hostname", "c")}) == key([]*dto.LabelPair{pair("origin", "a"), pair("hostname", "bc")}) {
		t.Fatal("delta key collision")
	}
}
