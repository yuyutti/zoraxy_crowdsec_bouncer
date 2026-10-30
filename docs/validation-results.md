> Historical local Windows snapshot, before hosted CI/publication. This record
> does not describe later GitHub workflow results. See releasing.md for the current
> required GitHub-only verification and publishing process.

# Local validation results (2026-10-30)

Fork version: v1.2.4-1. Go: 1.26.10 windows/amd64. All seven release targets
were built locally with CGO_ENABLED=0 (Linux 386, amd64, arm/v7, arm64, mipsle,
riscv64; Windows amd64). These are compile checks, not runtime checks on those OSes.
Binaries remain in ignored `build/release`; nothing was published.

Final package tests, race tests with MinGW Clang, vet, staticcheck v0.8.2,
govulncheck v1.9.0, introspection comparison and UI tests passed. Recorded
coverage is 64.4 percent overall. GNU make normal and parallel dry-runs passed.
Python syntax, distributed YAML parsing and whitespace diff checks passed.
See security-review.md for command details and platform boundaries.

Final benchmark run, after concurrent cross-builds/scans finished:

```text
goos: windows
goarch: amd64
pkg: github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions
cpu: 11th Gen Intel(R) Core(TM) i9-11900K @ 3.50GHz
BenchmarkRequestLookup-16               	 2027704	        60.01 ns/op	       0 B/op	       0 allocs/op
BenchmarkIPv6Hit-16                     	 2277496	        52.99 ns/op	       0 B/op	       0 allocs/op
BenchmarkExpiredPrefix-16               	 1341972	        89.40 ns/op	       0 B/op	       0 allocs/op
BenchmarkConcurrentLookupUpdate-16      	  341316	       294.9 ns/op	      34 B/op	       0 allocs/op
BenchmarkLargeBlocklistExactIPHit-16    	  687836	       184.0 ns/op	     160 B/op	       5 allocs/op
BenchmarkLargeBlocklistCIDRHit-16       	  855430	       177.0 ns/op	     160 B/op	       5 allocs/op
BenchmarkLargeBlocklistIPv4Miss-16      	 3779706	        31.55 ns/op	       0 B/op	       0 allocs/op
BenchmarkLargeBlocklistIPv6Miss-16      	 2774245	        44.18 ns/op	       0 B/op	       0 allocs/op
BenchmarkUpdateLargeBlocklist-16        	      12	  11659467 ns/op	 5753141 B/op	  120000 allocs/op
BenchmarkUpdateSmallBlocklist-16        	    1436	     81028 ns/op	   48907 B/op	    1200 allocs/op
BenchmarkUpdateSteadyState/batch=1-16   	  128802	       983.5 ns/op	     632 B/op	      12 allocs/op
BenchmarkUpdateSteadyState/batch=10-16  	   10000	     11011 ns/op	    6697 B/op	     136 allocs/op
BenchmarkUpdateSteadyState/batch=100-16 	    1202	    109481 ns/op	   63111 B/op	    1222 allocs/op
BenchmarkUpdateGrowingBlocklist-16      	     154	    785764 ns/op	  738021 B/op	   11057 allocs/op
BenchmarkDeleteManySamePrefix-16        	       6	  18717750 ns/op	  480000 B/op	   10000 allocs/op
PASS
ok  	github.com/AnthonyMichaelTDM/zoraxycrowdsecbouncer/mod/decisions	4.119s
```

Baseline with original Go 1.26.5: exact hit 39.79 ns/op, CIDR hit 32.61 ns/op,
IPv4 miss 28.81 ns/op, IPv6 miss 43.58 ns/op (100 ms benchmark runs).
The hardened request lookup is 60.01 ns/op with no allocation; it includes expiry
and ownership safety. Full-model GetBan copies cost more and are not the sniff
request path. Concurrent benchmark allocation totals include the update writer.
These short local runs establish scale and ownership cost, not production latency.

Not run: actual Docker Zoraxy + CrowdSec E2E, real Cloudflare forwarding/logs,
hosted GitHub workflows, Linux SIGTERM execution and actual other-architecture
runtime checks. Windows could not create the symlink fixture; Linux CI must
exercise it. The isolated E2E runner and both payload variants are supplied,
but their first Docker acceptance run is still required.

No production deployment/restart, firewall edits, real-user decisions, push,
commit or release publication was performed.
