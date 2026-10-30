package utils

import (
	plugin "github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/zoraxy_plugin"
	"net/netip"
	"strings"
	"testing"
)

// Old tests trusted arbitrary headers. That premise intentionally changes in
// 1.2.4-1: untrusted peers are identified exclusively by their socket address.
func TestGetRealIP(t *testing.T) {
	for _, cf := range []bool{false, true} {
		for _, key := range []string{"X-Real-IP", "X-Real-Ip", "x-real-ip", "CF-Connecting-IP", "CF-Connecting-IPv6", "X-Forwarded-For"} {
			for _, forged := range []string{"198.51.100.2", "invalid", "", "198.51.100.2, 192.0.2.1"} {
				r := &plugin.DynamicSniffForwardRequest{RemoteAddr: "192.0.2.10:80", Header: map[string][]string{key: {forged}}}
				got, err := GetRealIP(nil, r, cf)
				if err != nil || got != "192.0.2.10" {
					t.Fatalf("untrusted %s: %q %v", key, got, err)
				}
			}
		}
	}
}
func TestParseIP(t *testing.T) {
	tests := map[string]string{
		"192.0.2.1": "192.0.2.1", " 192.0.2.1:80 ": "192.0.2.1",
		"[2001:DB8::1]:443": "2001:db8::1", "::ffff:192.0.2.1": "192.0.2.1",
		"2001:db8::1": "2001:db8::1",
	}
	for raw, want := range tests {
		ip, err := ParseIP(raw)
		if err != nil || ip.String() != want {
			t.Fatalf("%s: %v %v", raw, ip, err)
		}
	}
	for _, raw := range []string{"", "invalid", "fe80::1%eth0", "[fe80::1%eth0]:80", "192.0.2.1,192.0.2.2", "0.0.0.0", "ff02::1"} {
		if _, err := ParseIP(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
func TestClientIPAndNil(t *testing.T) {
	if _, err := GetRealIP(nil, nil, false); err == nil {
		t.Fatal("nil request accepted")
	}
	r := &plugin.DynamicSniffForwardRequest{ClientIP: "::ffff:192.0.2.1", RemoteAddr: "invalid", Header: map[string][]string{"X-Real-Ip": {"198.51.100.1"}}}
	if got, err := GetRealIP(nil, r, false); err != nil || got != "192.0.2.1" {
		t.Fatalf("client_ip overwritten: %s %v", got, err)
	}
	r.ClientIP = "invalid"
	r.RemoteAddr = "192.0.2.1"
	if _, err := GetRealIP(nil, r, false); err == nil {
		t.Fatal("invalid authoritative client_ip silently fell back")
	}
	r.ClientIP = ""
	r.Header = nil
	if _, err := GetRealIP(nil, r, false); err != nil {
		t.Fatal(err)
	}
}
func TestTrustedForwarding(t *testing.T) {
	resolver := IPResolver{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Cloudflare: true}
	tests := []struct {
		header map[string][]string
		want   string
		bad    bool
	}{
		{map[string][]string{"X-Real-Ip": {"192.0.2.1"}}, "192.0.2.1", false},
		{map[string][]string{"x-real-ip": {"[2001:db8::1]:80"}}, "2001:db8::1", false},
		{map[string][]string{"X-Forwarded-For": {"198.51.100.9, 192.0.2.1, 10.0.0.2"}}, "192.0.2.1", false},
		{map[string][]string{"X-Forwarded-For": {"198.51.100.9, 192.0.2.1"}}, "192.0.2.1", false},
		{map[string][]string{"CF-Connecting-IP": {"198.51.100.9"}}, "10.0.0.1", false},
		{map[string][]string{"X-Real-IP": {"192.0.2.1"}, "x-real-ip": {"192.0.2.1"}}, "", true},
		{map[string][]string{"X-Real-IP": {"192.0.2.1", "192.0.2.2"}}, "", true},
		{map[string][]string{"X-Real-IP": {"192.0.2.1, 192.0.2.2"}}, "", true},
		{map[string][]string{"X-Forwarded-For": {"10.0.0.2"}}, "", true},
		{map[string][]string{"X-Forwarded-For": {"invalid, 192.0.2.1"}}, "", true},
		{map[string][]string{"X-Forwarded-For": {strings.Repeat("10.0.0.2,", 32) + "192.0.2.1"}}, "", true},
		{map[string][]string{"X-Forwarded-For": {"192.0.2.1"}, "X-Real-IP": {"192.0.2.2"}}, "", true},
	}
	for _, tt := range tests {
		got, err := resolver.Resolve(&plugin.DynamicSniffForwardRequest{RemoteAddr: "10.0.0.1:80", Header: tt.header})
		if (err != nil) != tt.bad || (!tt.bad && got != tt.want) {
			t.Fatalf("%v: %q %v", tt.header, got, err)
		}
	}
}
func TestCloudflare(t *testing.T) {
	for _, peer := range []string{"173.245.48.1:80", "[2606:4700::1]:80", "10.0.0.1:80"} {
		resolver := IPResolver{Cloudflare: true, CloudflareRelays: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}
		r := &plugin.DynamicSniffForwardRequest{RemoteAddr: peer, Header: map[string][]string{"cf-connecting-ip": {"192.0.2.1"}, "X-Real-IP": {"invalid"}}}
		got, err := resolver.Resolve(r)
		if err != nil || got != "192.0.2.1" {
			t.Fatalf("CF %s: %s %v", peer, got, err)
		}
		r.Header["cf-connecting-ip"] = []string{"240.0.0.1"}
		r.Header["CF-Connecting-IPv6"] = []string{"2001:db8::1"}
		got, err = resolver.Resolve(r)
		if err != nil || got != "2001:db8::1" {
			t.Fatalf("pseudo: %s %v", got, err)
		}
		delete(r.Header, "CF-Connecting-IPv6")
		if _, err = resolver.Resolve(r); err == nil {
			t.Fatal("missing original IPv6 accepted")
		}
	}
}
func FuzzIPResolver(f *testing.F) {
	f.Add("192.0.2.1:80", "invalid")
	f.Fuzz(func(t *testing.T, peer, header string) {
		r := &plugin.DynamicSniffForwardRequest{RemoteAddr: peer, Header: map[string][]string{"X-Real-IP": {header}}}
		_, _ = GetRealIP(nil, r, true)
	})
}
