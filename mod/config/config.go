package config

import (
	"errors"
	"fmt"
	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/utils"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

const DefaultStreamUpdateFrequency = "10s"
const PlaceholderAPIKey = "<CROWDSEC_BOUNCER_API_KEY>"

var ErrConfigCreated = errors.New("config file created")

const defaultConfigTemplate = `# Crowdsec Bouncer Configuration
# api_key: "YOUR_CROWDSEC_BOUNCER_API_KEY"
agent_url: http://127.0.0.1:8080
# How frequently to request decision deltas from CrowdSec's stream endpoint.
stream_update_frequency: 10s
# Log level for the bouncer, options: trace, debug, info, warning, error
log_level: warning
# Set to true if zoraxy is proxied behind Cloudflare
is_proxied_behind_cloudflare: true
`

type PluginConfig struct {
	APIKey                    string `yaml:"api_key"`
	AgentUrl                  string `yaml:"agent_url"`
	StreamUpdateFrequency     string `yaml:"stream_update_frequency"`
	LogLevelString            string `yaml:"log_level"`
	IsProxiedBehindCloudflare bool   `yaml:"is_proxied_behind_cloudflare"`

	TrustedProxies          []string            `yaml:"trusted_proxies"`
	CloudflareTrustedRelays []string            `yaml:"cloudflare_trusted_relays"`
	BlockResponse           BlockResponseConfig `yaml:"block_response"`
	Resolver                utils.IPResolver    `yaml:"-"`
	ConfigPath              string              `yaml:"-"`
	LogLevel                logrus.Level        `yaml:"-"`
}

func (p *PluginConfig) MissingRequiredFields() []string {
	missing := make([]string, 0, 2)

	trimmedAPIKey := strings.TrimSpace(p.APIKey)
	if trimmedAPIKey == "" || trimmedAPIKey == PlaceholderAPIKey {
		missing = append(missing, "api_key")
	}

	if strings.TrimSpace(p.AgentUrl) == "" {
		missing = append(missing, "agent_url")
	}

	return missing
}

func (p *PluginConfig) PostProcess() error {
	// This function can be used to perform any post-processing on the configuration
	// For now, it populates the LogLevel based on the LogLevelString
	// parse the log level string into a logrus Level
	if p.LogLevelString == "" {
		p.LogLevelString = "warning"
	}

	level, err := logrus.ParseLevel(p.LogLevelString)
	if err != nil {
		return errors.New("invalid log_level")
	}
	p.LogLevel = level

	if p.StreamUpdateFrequency == "" {
		p.StreamUpdateFrequency = DefaultStreamUpdateFrequency
	}
	interval, err := time.ParseDuration(p.StreamUpdateFrequency)
	if err != nil || interval <= 0 || interval > 24*time.Hour {
		return errors.New("stream_update_frequency must be positive and at most 24h")
	}
	if p.AgentUrl != "" {
		u, err := url.Parse(p.AgentUrl)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("agent_url must be an HTTP(S) URL without credentials, query or fragment")
		}
	}
	parse := func(values []string) ([]netip.Prefix, error) {
		out := make([]netip.Prefix, 0, len(values))
		for _, v := range values {
			prefix, err := netip.ParsePrefix(v)
			if err != nil {
				ip, e := utils.ParseIP(v)
				if e != nil {
					return nil, errors.New("invalid trusted proxy IP/CIDR")
				}
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			}
			if prefix.Addr().Is4In6() {
				return nil, errors.New("use IPv4 CIDR for mapped trusted proxies")
			}
			out = append(out, prefix.Masked())
		}
		return out, nil
	}
	trusted, err := parse(p.TrustedProxies)
	if err != nil {
		return err
	}
	relays, err := parse(p.CloudflareTrustedRelays)
	if err != nil {
		return err
	}
	p.Resolver = utils.IPResolver{Trusted: trusted, CloudflareRelays: relays, Cloudflare: p.IsProxiedBehindCloudflare}
	return p.BlockResponse.Validate()
}

func (p *PluginConfig) LoadConfig() error {
	if p.ConfigPath == "" {
		p.ConfigPath = info.CONFIGURATION_FILE
	}
	absolute, err := filepath.Abs(p.ConfigPath)
	if err != nil {
		return err
	}
	p.ConfigPath = absolute
	configFile, err := os.Open(p.ConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if writeErr := createDefault(p.ConfigPath); writeErr != nil {
				return fmt.Errorf("unable to create default config file: %w", writeErr)
			}
			if err := yaml.UnmarshalStrict([]byte(defaultConfigTemplate), p); err != nil {
				return errors.New("invalid default configuration")
			}
			if err := p.PostProcess(); err != nil {
				return err
			}
			return fmt.Errorf("%w: edit api_key and agent_url, then restart", ErrConfigCreated)
		}
		return fmt.Errorf("unable to open config file: %w", err)
	}
	defer configFile.Close()

	content, err := io.ReadAll(io.LimitReader(configFile, 1<<20+1))
	if err != nil {
		return fmt.Errorf("unable to read configuration: %w", err)
	}

	if err := yaml.UnmarshalStrict(content, p); err != nil {
		return errors.New("invalid YAML configuration: check field names, types and duplicates")
	}

	if len(content) > 1<<20 {
		return errors.New("configuration exceeds 1 MiB")
	}
	if err := p.PostProcess(); err != nil {
		return fmt.Errorf("unable to post-process config: %w", err)
	}

	return nil
}

func createDefault(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(defaultConfigTemplate)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}
