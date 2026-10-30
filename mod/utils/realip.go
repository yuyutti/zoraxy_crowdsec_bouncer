package utils

import (
	"errors"
	"net/netip"
	"strings"

	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"github.com/sirupsen/logrus"
)

// Official network snapshot checked 2026-10-30. Update explicitly; no request I/O.
var cloudflarePrefixes = mustPrefixes(strings.Fields(`173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32`))

func mustPrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func ParseIP(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		ap, e := netip.ParseAddrPort(raw)
		if e != nil {
			return netip.Addr{}, errors.New("invalid client address")
		}
		ip = ap.Addr()
	}
	if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, errors.New("unsupported client address")
	}
	return ip.Unmap(), nil
}

type IPResolver struct {
	Trusted          []netip.Prefix
	CloudflareRelays []netip.Prefix
	Cloudflare       bool
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func singleHeader(headers map[string][]string, key string) (string, bool, error) {
	var found bool
	var value string
	for k, values := range headers {
		if !strings.EqualFold(k, key) {
			continue
		}
		if found || len(values) != 1 || strings.TrimSpace(values[0]) == "" {
			return "", true, errors.New("ambiguous forwarding header")
		}
		found, value = true, strings.TrimSpace(values[0])
	}
	return value, found, nil
}

// Resolve requires a private Zoraxy RPC path. Empty lists trust nobody.
func (resolver IPResolver) Resolve(r *plugin.DynamicSniffForwardRequest) (string, error) {
	if r == nil {
		return "", errors.New("missing sniff request")
	}
	if r.ClientIP != "" {
		ip, err := ParseIP(r.ClientIP)
		return ip.String(), err
	}
	peer, err := ParseIP(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	cf := resolver.Cloudflare && (contains(cloudflarePrefixes, peer) || contains(resolver.CloudflareRelays, peer))
	if !cf && !contains(resolver.Trusted, peer) {
		return peer.String(), nil
	}
	if cf {
		value, present, err := singleHeader(r.Header, "CF-Connecting-IP")
		if err != nil {
			return "", err
		}
		if present {
			ip, err := ParseIP(value)
			if err != nil {
				return "", err
			}
			// Cloudflare Pseudo IPv4 overwrite preserves the native IPv6 header.
			if netip.MustParsePrefix("240.0.0.0/4").Contains(ip) {
				v6, ok, e := singleHeader(r.Header, "CF-Connecting-IPv6")
				if e != nil || !ok {
					return "", errors.New("missing pseudo IPv4 original IPv6")
				}
				ip, err = ParseIP(v6)
				if err != nil || !ip.Is6() {
					return "", errors.New("invalid pseudo IPv4 original IPv6")
				}
			}
			return ip.String(), nil
		}
		return "", errors.New("missing Cloudflare client address")
	}
	xff, hasXFF, err := singleHeader(r.Header, "X-Forwarded-For")
	if err != nil {
		return "", err
	}
	real, hasReal, err := singleHeader(r.Header, "X-Real-IP")
	if err != nil {
		return "", err
	}
	resolved := peer
	if hasXFF {
		parts := strings.Split(xff, ",")
		if len(parts) > 32 {
			return "", errors.New("too many proxy hops")
		}
		hops := make([]netip.Addr, len(parts))
		for i, v := range parts {
			hops[i], err = ParseIP(v)
			if err != nil {
				return "", err
			}
		}
		for i := len(hops) - 1; i >= 0; i-- {
			if !contains(resolver.Trusted, resolved) {
				break
			}
			resolved = hops[i]
		}
		if contains(resolver.Trusted, resolved) {
			return "", errors.New("all forwarded hops trusted; client ambiguous")
		}
	}
	if hasReal {
		ip, err := ParseIP(real)
		if err != nil {
			return "", err
		}
		if hasXFF && ip != resolved {
			return "", errors.New("conflicting forwarding headers")
		}
		resolved = ip
	}
	return resolved.String(), nil
}

func GetRealIP(_ *logrus.Logger, r *plugin.DynamicSniffForwardRequest, cloudflare bool) (string, error) {
	return (IPResolver{Cloudflare: cloudflare}).Resolve(r)
}
