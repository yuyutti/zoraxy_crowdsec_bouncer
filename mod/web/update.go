package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/info"
)

// Fork revision -N is ordered numerically above the same upstream base.
// Other prerelease syntax is not offered by this fork's update channel.
func versionParts(v string) ([4]int, bool) {
	var out [4]int
	v = strings.TrimPrefix(v, "v")
	base, revision, hasRevision := strings.Cut(v, "-")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return out, false
	}
	if hasRevision {
		parts = append(parts, revision)
	}
	for i, p := range parts {
		if p == "" {
			return out, false
		}
		for _, digit := range p {
			if digit < '0' || digit > '9' {
				return out, false
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
func compareVersions(a, b string) int {
	av, _ := versionParts(a)
	bv, _ := versionParts(b)
	for i := range av {
		if av[i] > bv[i] {
			return 1
		}
		if av[i] < bv[i] {
			return -1
		}
	}
	return 0
}

type updateChecker struct {
	mu       sync.Mutex
	client   *http.Client
	endpoint string
	now      func() time.Time
	checked  time.Time
	latest   string
	err      error
}

var updates = updateChecker{
	client:   &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }},
	endpoint: "https://api.github.com/repos/yuyutti/zoraxy_crowdsec_bouncer/releases?per_page=100",
	now:      time.Now,
}

func (c *updateChecker) check(ctx context.Context) (string, error) {
	// Serializing the bounded fetch coalesces concurrent checks with the same TTL.
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := 24 * time.Hour
	if c.err != nil {
		ttl = 5 * time.Minute
	}
	if !c.checked.IsZero() && c.now().Sub(c.checked) < ttl {
		return c.latest, c.err
	}
	latest, err := c.fetch(ctx)
	c.latest, c.err, c.checked = latest, err, c.now()
	return latest, err
}
func (c *updateChecker) fetch(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return "", errors.New("invalid update endpoint")
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", info.BOUNCER_USER_AGENT)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", errors.New("update check unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("update check HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		return "", errors.New("invalid update response size")
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.Unmarshal(body, &releases) != nil {
		return "", errors.New("invalid update response")
	}
	latest := ""
	for _, release := range releases {
		if release.Draft || release.Prerelease {
			continue
		}
		// Stable channel excludes every draft and prerelease, including numeric fork revisions.
		if _, ok := versionParts(release.Tag); !ok {
			continue
		}
		if latest == "" || compareVersions(release.Tag, latest) > 0 {
			latest = release.Tag
		}
	}
	return latest, nil
}
