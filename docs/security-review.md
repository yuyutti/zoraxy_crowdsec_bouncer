> The command results below record the initial local Windows snapshot before the
> later fork publication instructions. Hosted CI now also requires both Docker
> E2E variants and all seven binary builds; publication behavior is described in
> [releasing.md](releasing.md). Final hosted run/release URLs are reported separately.

# Security implementation record: yuyutti v1.2.4-1

Scope: local fork `https://github.com/yuyutti/zoraxy_crowdsec_bouncer`, initially clean
HEAD `fdfe883cb5aa59f60cd53aaa165a2d411c106abd`, matching the supplied review baseline.
Origin remote matched the user-specified fork. No finding was assumed fixed solely
from the instruction document. Upstream Issue 56, PRs 50/54/55, Zoraxy's resolved
client-IP SDK and the installed go-cs-bouncer v0.0.21 source were inspected.

“Fixed” below means the local implementation and the named regression passed.
“Conditional” identifies an external or platform acceptance check still outstanding.
There are no IDs classified as already fixed at the initial target HEAD.

| ID | Status | Files / change | Evidence and remaining boundary |
| --- | --- | --- | --- |
| R01 | Fixed / conditional E2E | `mod/utils/realip.go`, `mod/dynamiccapture/sniff.go`: trust payload client_ip first; secure legacy peer rules; identity errors capture | Untrusted forged/broken headers cannot bypass a cached BAN in regression; actual Zoraxy path still needs Docker E2E |
| R02 | Fixed | `mod/zoraxy_plugin/dynamic_router.go`, `mod/utils`: client_ip field, uniform netip normalization, case-independent unique headers | IPv4, IPv6, mapped IPv6, port, whitespace, zone, nil and duplicate/conflicting header regressions |
| R03 | Fixed / conditional E2E | `mod/decisions/cache.go`, `sync.go`: injected clock, deadlines, heap expiry, indexed fallback, full replacement after success, reconnect forces startup=true | Expiry/same-prefix/wider-prefix/reconnect tests; real LAPI stream acceptance outstanding |
| R04 | Fixed | Cache validates entries, removes same-ID old BAN before non-ban/invalid replacement, copies models both directions; request path uses value result | Invalid entries, mutation, same-ID moves and delete/new ordering tests |
| R05 | Fixed | `mod/metrics`, `mod/web`: sum origins, JSON tuple key, reset reports new count | Same-host origin sum, collision, 100-to-5 reset tests |
| R06 | Fixed | Metrics share a process-wide lock for global delta state, nil origin becomes unknown, append items to new window | Nil decision/origin, multiple windows and concurrent updates passed including race |
| R07 | Fixed | `mod/web/update.go`: synchronized TTL/backoff cache, bounded HTTP client/body, fork release ordering and empty release state | Local httptest success/expiry/failure/backoff/concurrency/cancellation/order cases; no live release publication |
| R08 | Fixed / conditional browser | `mod/web/www/index.html`: actual fetch promises, finally cleanup, DOM nodes/attributes, fork-only link validation, plain header text | Node runs actual script for pending requests, failure recovery, text and link safety; full browser visual acceptance not run |
| R09 | Fixed | `mod/web/web.go`, bundled SDK: non-allowlisted request headers redacted, no-store, no raw payload/header/query debug dumps | Sensitive fixture headers never appear in API response; SDK debug output reduced to generic events |
| R10 | Fixed | `mod/dynamiccapture/capture.go`: set headers before status; UTF-8, no-store, nosniff, HEAD | Recorder Result headers and real loopback process response checked |
| R11 | Fixed / conditional E2E | `main.go`, `mod/web`, `sync.go`: readiness state, empty sync success, degraded last-known-good, first-run UI, explicit preview | Empty-config real process onboarding API passed; synthetic outage/recovery passed; real Zoraxy UI acceptance outstanding |
| R12 | Fixed | `mod/config`: strict size-limited YAML, validated duration/URL/proxies/block response, exclusive 0600 creation, sanitized parse errors | Unknown/duplicate fields, invalid status including explicit zero, wrong types and secret-bearing error fixtures |
| R13 | Fixed / conditional Linux | `main.go`, `sync.go`, `mod/utils/shutdown.go`, `mod/web`: errors returned from init, normal signal handling/unregister, bounded clients/server, independent usage retries | HTTP cancellation and sync/metrics cancellation tests passed; real SIGTERM subprocess assertion only runs in Linux CI; Windows cleanup uses Kill |
| R14 | Fixed / conditional E2E | Bundled dynamic/static/embed SDK: 1 MiB payload limit, malformed payload selects 200 capture, URI/query preserved, parse errors handled, nil default is 404 | Malformed/oversize/null, URI and nil-handler regressions; sniff 200 contract verified in Zoraxy source, actual container E2E outstanding |
| R15 | Fixed / conditional symlink | `mod/zoraxy_plugin/dev_webserver.go`: os.Root confinement; relative roots and no directory listing | Root/traversal/CSRF escaping tests passed; Windows could not create test symlink; Linux test path must confirm outside-root symlink denial. This helper is unused in production main |
| R16 | Fixed | `Makefile`: correct jq prerequisite, explicit sequencing under -j, Linux test binary, private generated config/key | GNU make 4.4.1 normal and -j8 dry-runs passed; actual Docker setup not run |
| R17 | Fixed / conditional CI/E2E | Compose loopback ports, no Docker socket; CI race/pinned scans/fuzz/introspection; CD reusable verification dependency and verified draft-to-public promotion | YAML parses and local equivalent checks pass; hosted workflows not dispatched; Docker unavailable locally |
| R18 | Fixed / conditional release | `mod/info`, `.introspect`, `.releaseurl`, UI/README/Make/CD: distinct fork ID, full revision, fork updates, attribution | Executable introspection equals file; migration/rollback documents key/ID/tags and mutually exclusive stream consumers. No release exists from this work |
| R19 | Fixed | `mod/utils/utils_test.go`, decision tests/benchmarks: true nil input, compare values/IDs, nil-safe diagnostics and valid duration fixtures | Regression and race suites pass; insecure former header assumptions explicitly removed |

## Additional changes and boundaries

- A01: Optional preloaded static default/evil/custom responses. Status and page are
  independent; only 403/418/451/503 are supported. Default response is exactly
  `403 + Forbidden`, no newline. Only the explicit example selects `418 + 666 Evil`.
  Evil with omitted status remains 403 and displays HTTP 403. No status 666 exists.
  Custom-page load errors, invalid UTF-8 and oversized files stay blocked with 403; no dynamic template engine or
  request variables exist, so request-based template expansion/XSS is not introduced.
- A02: Host metric admission capped at 256 values plus fixed buckets; origins use
  a fixed allowlist. Unknown origins aggregate into `unknown`. Delta maps are
  correspondingly bounded. Requests are counted once at sniff; capture does not
  increment BAN metrics. Identity errors are a separate atomic diagnostic count.
- A03: Usage delivery retains one pending payload on failure and retries separately
  from blocking. LAPI provides no idempotency key, so ambiguous network failures
  cannot guarantee exactly-once ingestion; this limitation is explicit.
- A04: govulncheck v1.9.0 initially found reachable standard-library issues in Go
  1.26.5 plus affected required dependencies. Updated minimum Go to 1.26.10,
  x/net to 0.62.0, x/text to 0.43.0, x/sys to 0.49.0 and x/sync to 0.24.0.
  Final scan returned `No vulnerabilities found.` This is a tool result for this
  dependency graph/host, not proof of absence of all vulnerabilities. `bart` was
  moved to direct dependencies by go mod tidy.
- A05: go vet found that assigning the BART table by value copies its mutex.
  Replacement now swaps table pointers; no mutex is copied.
- A06: Standalone UI explicitly says preview/no blocking. No extra stream consumer
  or independent detection engine, new DB, WAF, CAPTCHA, tracking or linked-family
  BAN was added. Custom HTML is static and should contain its own CSS/resources.

Decision duration policy: positive Go duration syntax, at most ten 365-day years.
Missing/empty/invalid/nonpositive/excessive durations are rejected, never made
permanent. Duplicate active IDs retain the earlier deadline; renewal should use a
new CrowdSec ID. Successful full replacement preserves earlier local deadlines for
still-held IDs. Expired records are eventually removed; this is a live residual-
duration stream consumer, not an arbitrarily delayed historical-event replay store.
A successful startup snapshot is required before `ready`; onboarding and initial
sync pass through. When the plugin process is unavailable Zoraxy can skip it;
malformed plugin configuration is an explicit startup error, not a universal
fail-closed Zoraxy deployment setting.

Cloudflare ranges are a checked-in official snapshot; no external lookup is made
at startup or on request. Newly allocated ranges are untrusted until explicitly
reviewed and rebuilt. General proxy trust and CF-relay trust are separate. Pseudo
IPv4 normalization requires compatible native-IP logging. These are local header
fixtures only; no Cloudflare real-route acceptance was performed.

## Commands and observed results

Validation date: 2026-10-30, Windows amd64 / Intel Core i9-11900K.

| Command | Result |
| --- | --- |
| Initial HEAD `go test ./...`, `go build ./...` with Go 1.26.5 | Passed in isolated `build/baseline/source` before source changes |
| Initial 100k blocklist hit/miss benchmark (100 ms runs) | exact 39.79 ns/op, CIDR 32.61 ns/op, IPv4 miss 28.81 ns/op, IPv6 miss 43.58 ns/op, all zero allocations |
| Final `go test ./...` | Passed all packages |
| `go test -race ./...` | Passed with llvm-mingw 20261020 Clang; no detected races |
| `go vet ./...` | Passed after table pointer fix |
| `go test ./... -coverprofile=coverage.out` | Passed; overall coverage 64.4 percent in the recorded run |
| `go build ./...` | Passed |
| `go test ./mod/decisions -run '^$' -bench . -benchmem -benchtime=100ms` | Passed; full local output in ignored `build/benchmarks.txt` |
| `go run . -introspect`, `python tools/check_introspection.py` | Passed without config/LAPI; metadata matches `.introspect` |
| `make -n test-env-ready`, `make -n -j8 test-env-ready` | Both exit 0 (GNU make 4.4.1 built from GNU source, Git Bash shell on Windows) |
| `staticcheck ./...` v0.8.2 | Passed |
| `govulncheck ./...` v1.9.0 on Go 1.26.10 | No vulnerabilities found in recorded scan |
| Fuzz IP resolver, sniff JSON and block HTTP, 5 s each / 4 workers | All passed; 174223, 423538 and 146657 executions respectively in the recorded runs |
| `node --test tools/ui.test.cjs` | 2 passed, 0 failed |
| Compose/workflow/example YAML parse, Python syntax, `git diff --check` | Checked locally; see final verification |
| Docker E2E / actual dual-stack Zoraxy + CrowdSec | **Not executed:** Docker/Compose daemon unavailable in this Windows environment; `make e2e` and manual E2E workflow prepared |
| Actual Cloudflare, hosted CI, release installation | **Not executed:** no external deployment/dispatch/publication authorized or performed |

Performance is not identical to upstream: expiry/time checking has a cost, and
`GetBan` now copies full models (5 allocations on the tested hit fixture). The
actual sniff request path uses zero-allocation `LookupBan`, retaining trie lookup
without full-list scans. Compare final timings only on an idle host; cross-build
and race processes can distort simultaneous benchmark runs. Same-prefix expiry
fallback may scan that prefix's candidates. No claim of zero regression is made.

Final local cross-builds and latest benchmark numbers are recorded in
`docs/validation-results.md`. Reproduction commands and Docker/platform acceptance
steps are in `docs/testing.md`; migration and rollback are in `docs/migration.md`.
No production deployment/restart, firewall change, real-user BAN, upstream push was performed in the initial local snapshot. Later fork commits and
release operations are covered by the explicit publication instructions.

## Primary references

- [Upstream bypass report #56](https://github.com/AnthonyMichaelTDM/zoraxy_crowdsec_bouncer/issues/56)
- [Zoraxy resolved client-IP SDK at the reviewed commit](https://github.com/tobychui/zoraxy/blob/cde44510c6e4e22e2b108314cfa1b659eb4f550f/src/mod/plugins/zoraxy_plugin/dynamic_router.go)
- [Zoraxy dynamic forwarder capture status contract](https://github.com/tobychui/zoraxy/blob/cde44510c6e4e22e2b108314cfa1b659eb4f550f/src/mod/plugins/dynamic_forwarder.go)
- [go-cs-bouncer v0.0.21 stream source](https://github.com/crowdsecurity/go-cs-bouncer/blob/v0.0.21/stream_bouncer.go)
- [go-cs-bouncer v0.0.21 usage metrics source](https://github.com/crowdsecurity/go-cs-bouncer/blob/v0.0.21/metrics.go)
- [Cloudflare request header and Pseudo IPv4 documentation](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
- [Official CF IPv4 networks](https://www.cloudflare.com/ips-v4), [IPv6 networks](https://www.cloudflare.com/ips-v6)
