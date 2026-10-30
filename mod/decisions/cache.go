// Package decisions maintains the local CrowdSec decision cache used by the
// stream bouncer.
package decisions

import (
	"container/heap"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/gaissmai/bart"
)

// entry is the trie value for one prefix.
type entry struct {
	best *models.Decision
	// others holds the remaining decisions at the prefix, so the next-best one
	// can be promoted when the winner is removed. It is nil in the common case
	// of a single decision.
	others []*models.Decision
}

// Cache applies decision stream updates and offers concurrent-safe IP lookups.
// CrowdSec sends deleted decisions as well as new decisions, so the cache can
// retain its last known-good state while a later stream update temporarily
// fails.
type Cache struct {
	// mu guards decisions and trie. Updates edit the trie in place under the
	// write lock, so lookups block while an update is being applied.
	mu sync.RWMutex
	// decisions maps decision IDs to decisions, so a deleted or replaced ID
	// can be removed from the prefix it was originally indexed under.
	decisions      map[int64]*models.Decision
	trie           *bart.Table[entry]
	expires        map[int64]time.Time
	expiry         expiryQueue
	now            func() time.Time
	invalidEntries uint64
}

func NewCache() *Cache {
	return NewCacheWithClock(time.Now)
}

func prefixFromDecision(decision *models.Decision) (netip.Prefix, bool) {
	if decision == nil || decision.Value == nil || decision.Scope == nil {
		return netip.Prefix{}, false
	}
	scope := strings.ToLower(*decision.Scope)
	if scope != "ip" && scope != "range" {
		return netip.Prefix{}, false
	}
	if ip, err := netip.ParseAddr(*decision.Value); err == nil && scope == "ip" {
		// PrefixFrom drops the zone, which would make a zoned decision ban the
		// unzoned address. decisionMatchSpecificity never matched those.
		// Zoned decisions should never appear in practice
		if ip.Zone() != "" {
			return netip.Prefix{}, false
		}
		ip = ip.Unmap()
		return netip.PrefixFrom(ip, ip.BitLen()), true
	}
	prefix, err := netip.ParsePrefix(*decision.Value)
	if err != nil {
		return netip.Prefix{}, false
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, false
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix.Masked(), true
}

// better reports whether a should win over b at the same prefix: higher
// specificity first, then higher ID.
func better(a, b *models.Decision, addr netip.Addr) bool {
	aSpec, _ := decisionMatchSpecificity(a, addr)
	bSpec, _ := decisionMatchSpecificity(b, addr)
	return aSpec > bSpec || (aSpec == bSpec && a.ID > b.ID)
}

// removeAt removes list[i] in place by swapping in the last element. Order is
// not preserved, which is fine because the winner is chosen by scanning. It is
// safe because the trie is only touched under c.mu, so no reader or older
// snapshot shares the slice.
func removeAt(list []*models.Decision, i int) []*models.Decision {
	last := len(list) - 1
	list[i] = list[last]
	list[last] = nil // don't retain the decision through the backing array
	if last == 0 {
		return nil
	}
	return list[:last]
}

// removeID removes the decision with the given ID from list, if present.
func removeID(list []*models.Decision, id int64) []*models.Decision {
	for i, d := range list {
		if d.ID == id {
			return removeAt(list, i)
		}
	}
	return list
}

// unindex removes the decision from its prefix in the trie.
func (c *Cache) unindex(decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	c.trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
		if !found {
			return entry{}, true
		}
		if old.best.ID != decision.ID {
			return entry{best: old.best, others: removeID(old.others, decision.ID)}, false
		}
		if len(old.others) == 0 {
			return entry{}, true
		}
		bestIdx := 0
		for i, d := range old.others[1:] {
			if better(d, old.others[bestIdx], prefix.Addr()) {
				bestIdx = i + 1
			}
		}
		nextBest := old.others[bestIdx]
		return entry{best: nextBest, others: removeAt(old.others, bestIdx)}, false
	})
}

// index adds the decision to its prefix in the trie.
func (c *Cache) index(decision *models.Decision) {
	prefix, ok := prefixFromDecision(decision)
	if !ok {
		return
	}
	c.trie.Modify(prefix, func(old entry, found bool) (entry, bool) {
		if !found {
			return entry{best: decision}, false
		}
		winner, loser := old.best, decision
		if better(decision, old.best, prefix.Addr()) {
			winner, loser = decision, old.best
		}
		return entry{best: winner, others: append(old.others, loser)}, false
	})
}

// Apply updates the cache with one response from /v1/decisions/stream.
func (c *Cache) Apply(update *models.DecisionsStreamResponse) {
	if update == nil || (len(update.New) == 0 && len(update.Deleted) == 0) {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, decision := range update.Deleted {
		if decision == nil {
			continue
		}
		if existing, ok := c.decisions[decision.ID]; ok {
			c.unindex(existing)
			delete(c.decisions, decision.ID)
			delete(c.expires, decision.ID)
		}
	}

	now := c.now()
	c.expireLocked(now)
	for _, input := range update.New {
		if input == nil {
			continue
		}
		oldExpiry := c.expires[input.ID]
		if existing, ok := c.decisions[input.ID]; ok {
			c.unindex(existing)
			delete(c.decisions, input.ID)
			delete(c.expires, input.ID)
		}
		prefix, valid := prefixFromDecision(input)
		if input.Type == nil || !strings.EqualFold(*input.Type, "ban") {
			continue
		}
		if !valid || input.Duration == nil {
			c.invalidEntries++
			continue
		}
		duration, err := time.ParseDuration(*input.Duration)
		if err != nil || duration <= 0 || duration > 10*365*24*time.Hour {
			c.invalidEntries++
			continue
		}
		until := now.Add(duration)
		// The same ID denotes the same decision, not a renewed ban. Full resync
		// also preserves earlier deadlines. A genuinely renewed decision needs a new ID.
		if !oldExpiry.IsZero() && oldExpiry.Before(until) {
			until = oldExpiry
		}
		if !until.After(now) {
			continue
		}
		d := cloneDecision(input)
		// Normalize the indexed value without modifying the caller's model.
		if prefix.Addr().Is4() {
			value := prefix.String()
			d.Value = &value
		}
		c.decisions[d.ID] = d
		c.expires[d.ID] = until
		heap.Push(&c.expiry, expiryEvent{d.ID, until})
		c.index(d)
	}
	// Repeated stream entries must not accumulate stale expiry events forever.
	if len(c.expiry) > 2*len(c.decisions)+1024 {
		c.rebuildExpiry()
	}

}

// GetBan returns the most specific matching IP or CIDR ban decision, if any.
func (c *Cache) GetBan(rawIP string) *models.Decision {
	ip, err := netip.ParseAddr(strings.TrimSpace(rawIP))
	if err != nil || ip.Zone() != "" {
		return nil
	}
	ip = ip.Unmap()
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneDecision(c.findBan(ip))
}

func (c *Cache) findBan(ip netip.Addr) *models.Decision {
	e, ok := c.trie.Lookup(ip)
	if !ok {
		return nil
	}
	now := c.now()
	if c.expires[e.best.ID].After(now) {
		return e.best
	}
	// Longest prefix lookup stays indexed. Expired winners fall back to other
	// candidates, then a wider matching prefix; never scan the entire cache.
	query := netip.PrefixFrom(ip, ip.BitLen())
	for query.IsValid() {
		prefix, e, ok := c.trie.LookupPrefixLPM(query)
		if !ok {
			return nil
		}
		if c.expires[e.best.ID].After(now) {
			return e.best
		}
		var best *models.Decision
		consider := func(d *models.Decision) {
			if c.expires[d.ID].After(now) && (best == nil || better(d, best, ip)) {
				best = d
			}
		}
		consider(e.best)
		for _, d := range e.others {
			consider(d)
		}
		if best != nil {
			return best
		}
		if prefix.Bits() == 0 {
			return nil
		}
		query = netip.PrefixFrom(ip, prefix.Bits()-1)
	}
	return nil
}

func decisionMatchSpecificity(decision *models.Decision, ip netip.Addr) (int, bool) {
	if decision == nil || decision.Scope == nil || decision.Value == nil {
		return 0, false
	}

	prefix, ok := prefixFromDecision(decision)
	ip = ip.Unmap()
	if !ok || !prefix.Contains(ip) {
		return 0, false
	}
	specificity := prefix.Bits()
	if strings.EqualFold(*decision.Scope, "ip") && prefix.Bits() == ip.BitLen() {
		specificity++
	}
	return specificity, true
}

func NewCacheWithClock(now func() time.Time) *Cache {
	return &Cache{decisions: make(map[int64]*models.Decision), trie: new(bart.Table[entry]), expires: make(map[int64]time.Time), now: now}
}

type expiryEvent struct {
	id    int64
	until time.Time
}
type expiryQueue []expiryEvent

func (q expiryQueue) Len() int           { return len(q) }
func (q expiryQueue) Less(i, j int) bool { return q[i].until.Before(q[j].until) }
func (q expiryQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *expiryQueue) Push(v any)        { *q = append(*q, v.(expiryEvent)) }
func (q *expiryQueue) Pop() any {
	old := *q
	last := old[len(old)-1]
	*q = old[:len(old)-1]
	return last
}
func (c *Cache) rebuildExpiry() {
	c.expiry = make(expiryQueue, 0, len(c.expires))
	for id, until := range c.expires {
		c.expiry = append(c.expiry, expiryEvent{id, until})
	}
	heap.Init(&c.expiry)
}
func (c *Cache) expireLocked(now time.Time) {
	for len(c.expiry) > 0 && !c.expiry[0].until.After(now) {
		e := heap.Pop(&c.expiry).(expiryEvent)
		if c.expires[e.id] != e.until {
			continue
		}
		if d := c.decisions[e.id]; d != nil {
			c.unindex(d)
		}
		delete(c.decisions, e.id)
		delete(c.expires, e.id)
	}
}
func (c *Cache) Expire() { c.mu.Lock(); defer c.mu.Unlock(); c.expireLocked(c.now()) }
func (c *Cache) ActiveCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	count := 0
	now := c.now()
	for _, until := range c.expires {
		if until.After(now) {
			count++
		}
	}
	return count
}

// Replace is invoked only after a complete snapshot was fetched successfully.
func (c *Cache) Replace(snapshot *models.DecisionsStreamResponse) {
	if snapshot == nil {
		return
	}
	next := NewCacheWithClock(c.now)
	next.Apply(snapshot)
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, until := range next.expires {
		if old := c.expires[id]; !old.IsZero() && old.Before(until) {
			next.expires[id] = old
		}
	}
	next.rebuildExpiry()
	c.decisions, c.trie, c.expires, c.expiry = next.decisions, next.trie, next.expires, next.expiry
	c.invalidEntries += next.invalidEntries
}

func cloneDecision(d *models.Decision) *models.Decision {
	if d == nil {
		return nil
	}
	out := *d
	if d.Simulated != nil {
		v := *d.Simulated
		out.Simulated = &v
	}
	clone := func(p *string) *string {
		if p == nil {
			return nil
		}
		v := *p
		return &v
	}
	out.Scope, out.Value, out.Type = clone(d.Scope), clone(d.Value), clone(d.Type)
	out.Duration, out.Origin, out.Scenario = clone(d.Duration), clone(d.Origin), clone(d.Scenario)
	return &out
}

// Ban is an immutable, allocation-free request result; full models are copied
// only by GetBan for callers that need all diagnostic fields.
type Ban struct {
	ID     int64
	Origin string
}

func (c *Cache) LookupBan(raw string) (Ban, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return Ban{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	d := c.findBan(ip.Unmap())
	if d == nil {
		return Ban{}, false
	}
	origin := "unknown"
	if d.Origin != nil {
		origin = *d.Origin
	}
	return Ban{d.ID, origin}, true
}

func (c *Cache) InvalidCount() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.invalidEntries
}
