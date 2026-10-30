package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/config"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/dynamiccapture"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/metrics"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/web"
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

func startBouncer(g *errgroup.Group, ctx context.Context, cfg *config.PluginConfig, logger *logrus.Logger, cache *decisions.Cache, mh *metrics.MetricsHandler) error {
	bouncer := &csbouncer.StreamBouncer{
		APIKey: cfg.APIKey, APIUrl: cfg.AgentUrl, UserAgent: info.BOUNCER_USER_AGENT,
		TickerInterval: cfg.StreamUpdateFrequency, Scopes: []string{"ip", "range"},
	}
	if err := bouncer.Init(); err != nil {
		return fmt.Errorf("unable to initialize bouncer")
	}
	// Keep one stream consumer/key. The dependency's Run does not reset Startup
	// after an outage; our polling loop explicitly requests a replacement then.
	g.Go(func() error {
		return runDecisionSync(ctx, bouncer, cache, bouncer.TickerIntervalDuration)
	})
	g.Go(func() error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				cache.Expire()
			}
		}
	})
	g.Go(func() error { runMetrics(ctx, bouncer.APIClient, mh, logger, 15*time.Minute); return nil })
	return nil
}

func main() {
	// Serve the plugin introspect
	// This will print the plugin introspect and exit if the -introspect flag is provided
	pluginIntoSpect := &plugin.IntroSpect{
		ID:            info.PLUGIN_ID,
		Name:          info.PLUGIN_NAME,
		Author:        info.PLUGIN_AUTHOR,
		AuthorContact: info.PLUGIN_AUTHOR_CONTACT,
		Description:   info.PLUGIN_DESCRIPTION,
		URL:           info.PLUGIN_URL,
		Type:          plugin.PluginType_Router,
		Version:       info.VERSION_STRING,
		VersionMajor:  info.VERSION_MAJOR,
		VersionMinor:  info.VERSION_MINOR,
		VersionPatch:  info.VERSION_PATCH,

		DynamicCaptureSniff:   info.DYNAMIC_CAPTURE_SNIFF,
		DynamicCaptureIngress: info.DYNAMIC_CAPTURE_INGRESS,

		UIPath: info.UI_PATH,
	}
	runtimeCfg, err := plugin.ServeAndRecvSpec(pluginIntoSpect)
	if err != nil {
		//Terminate or enter standalone mode here
		fmt.Fprintln(os.Stderr, "Plugin initialization failed")
		os.Exit(1)
	}

	// load the configuration
	pluginConfig := &config.PluginConfig{}
	if err := pluginConfig.LoadConfig(); err != nil {
		if errors.Is(err, config.ErrConfigCreated) {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		if !errors.Is(err, config.ErrConfigCreated) {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}
	}

	// initialize the logger
	logger := logrus.StandardLogger()
	logger.Level = pluginConfig.LogLevel

	missingFields := pluginConfig.MissingRequiredFields()
	onboardingMode := len(missingFields) > 0
	configStatus := web.ConfigStatusResponse{
		Onboarding:      onboardingMode,
		BlockingEnabled: false,
	}
	if onboardingMode {
		configStatus.MissingFields = missingFields
		configStatus.Message = fmt.Sprintf(
			"Bouncer onboarding mode: update %s in %s, then restart the plugin.",
			strings.Join(missingFields, ", "),
			info.CONFIGURATION_FILE,
		)
		logger.Warn(configStatus.Message)
	}

	// initialize the path router
	pathRouter := plugin.NewPathRouter()
	pathRouter.SetDebugPrintMode(pluginConfig.LogLevel >= logrus.DebugLevel)

	// errGroup and context for plugin goroutines
	g, ctx := errgroup.WithContext(context.Background())
	decisionCache := decisions.NewCache()

	// initialize metrics and register custom and CrowdSec metrics
	metricsHandler := metrics.NewMetricsHandler(logger)
	metrics.Map.MustRegisterAll()
	prometheus.MustRegister(csbouncer.TotalLAPICalls, csbouncer.TotalLAPIError)

	blockHandler, pageErr := dynamiccapture.NewBlockHandler(pluginConfig.BlockResponse, pluginConfig.ConfigPath)
	if pageErr != nil {
		logger.Error("Custom block page unavailable; using 403 Forbidden fallback")
	}
	web.SetStatusCounts(func() (int, uint64, uint64) {
		return decisionCache.ActiveCount(), metricsHandler.IPResolutionErrors.Load(), decisionCache.InvalidCount()
	})

	/*
		Dynamic Captures

		If there is not a decision matching the requests IP, we will skip the request so
		that it can be handled by the next plugin or Zoraxy itself.
		If there is a decision for the request IP, we will accept the request and handle it in the dynamic capture handler.
		We will also print the request information to the console for debugging purposes.
	*/
	pathRouter.RegisterDynamicSniffHandler("/d_sniff", http.DefaultServeMux, func(dsfr *plugin.DynamicSniffForwardRequest) plugin.SniffResult {
		return dynamiccapture.SniffHandler(logger, metricsHandler, pluginConfig, dsfr, decisionCache)
	})
	pathRouter.RegisterDynamicCaptureHandle(info.DYNAMIC_CAPTURE_INGRESS, http.DefaultServeMux, func(w http.ResponseWriter, r *http.Request) {
		blockHandler.ServeHTTP(w, r)
	})

	web.InitWebServer(logger, g, ctx, runtimeCfg.Port, configStatus)
	if !onboardingMode {
		if err := startBouncer(g, ctx, pluginConfig, logger, decisionCache, metricsHandler); err != nil {
			web.SetError("initialization")
			logger.Error("Bouncer initialization failed")
		}
	}

	// Handle signals
	utils.StartSignalHandler(logger, g, ctx)

	defer web.SetStopped()
	// wait for the goroutines to finish
	if err := g.Wait(); err != nil && !(errors.Is(err, utils.SignalTermError) || errors.Is(err, utils.SignalIntError)) {
		fmt.Printf("Process terminated with error of type %T: %v\n", err, err)
		logrus.Fatalf("process terminated with error: %v", err)
	} else {
		logrus.Info("process terminated gracefully")
	}
}
