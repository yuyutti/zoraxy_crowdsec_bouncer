package dynamiccapture

import (
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/sirupsen/logrus"
)

// The Sniff handler is what decides whether to accept or skip a request
// It is called for each request
//
// TODO: if/when we support captchas, we should maybe add a header to the request, or something
func SniffHandler(logger *logrus.Logger, metricsHandler *metrics.MetricsHandler, config *config.PluginConfig, dsfr *plugin.DynamicSniffForwardRequest, decisions *decisions.Cache) plugin.SniffResult {
	hostname := "unknown"
	if dsfr != nil {
		hostname = dsfr.Hostname
	}
	defer metricsHandler.MarkRequestProcessed(hostname)

	// Look up the request IP in the local decision cache.
	ip, err := config.Resolver.Resolve(dsfr)
	if err != nil {
		metricsHandler.MarkIPResolutionError()
		return plugin.SniffResultAccept // Explicit fail-closed: capture sends the fixed block response.
	}

	decision, matched := decisions.LookupBan(ip)
	if !matched {
		logger.Debugf("No decision found for IP: %s", ip)
		return plugin.SniffResultSkip // Skip the request if there is no decision
	}

	// This bouncer currently remediates ban decisions by handing the request
	// to the capture handler, which returns a forbidden response.
	logger.Debugf("Decision found for IP: %s", ip)
	metricsHandler.MarkBanMatched(hostname, decision.Origin)
	return plugin.SniffResultAccept // Accept the request to be handled by the Capture handler
}
