# Local verification and isolated E2E

Run from the repository root with Go 1.26.10+, Node.js, Python 3, GNU make,
Bash and jq. `-race` needs a supported C compiler (GCC/Clang on Linux; a MinGW
compiler on Windows). Go source uses gofmt; sample YAML uses four spaces.

```sh
go test ./...
go test -race ./...
go vet ./...
go test ./... -coverprofile=coverage.out
go build ./...
go test ./mod/decisions -run '^$' -bench . -benchmem
go run . -introspect
python3 tools/check_introspection.py
make -n test-env-ready
make -n -j8 test-env-ready
node --test tools/ui.test.cjs
go install honnef.co/go/tools/cmd/staticcheck@v0.8.2
staticcheck ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
go test ./mod/utils -run '^$' -fuzz FuzzIPResolver -fuzztime 10s
go test ./mod/zoraxy_plugin -run '^$' -fuzz FuzzSniffPayload -fuzztime 10s
go test ./mod/dynamiccapture -run '^$' -fuzz FuzzBlockRequest -fuzztime 10s
```

The package tests use injected clocks, httptest servers, a temporary plugin process
and synthetic stream fetches. They do not contact a real CrowdSec or Cloudflare
service. The UI tests execute the actual script with a small DOM test double;
they do not establish full browser rendering/accessibility behavior.

`GetBan` returns a defensive model copy. The request path uses `LookupBan`, a small
value result with no allocations. Benchmark both APIs separately; the ownership
boundary deliberately makes full-model hit lookups slower than upstream's shared
mutable pointers. Missing-hit and request-value lookup keep the prefix index;
expiry checking does not scan all decisions. Expiry maintenance uses a heap and
coalesces stale events. A prefix with many expired candidates can require scanning
that prefix's candidates until the periodic sweep removes them.

## Docker E2E

Use an isolated Linux runner with Docker Compose, IPv6 bridge support and the
listed tools. All published test ports bind to 127.0.0.1. The default stack does
not mount Docker's socket. An IPv6 failure is an error, not a passed test.

```sh
make e2e
# After review, stop only this test stack:
docker compose --profile e2e down
```

This builds a Linux plugin, creates a test LAPI key without printing it, writes
private local config, applies the fork Plugin ID to `protected`, starts a static
dual-stack client, and runs `tools/e2e.py`. The script uses HTTPS with local test-certificate verification disabled and explicit
localhost SNI via curl --connect-to; it does not follow the global HTTP redirect
and mistake it for an upstream response. It checks curl's actual local
IPv4/IPv6 addresses separately, unbanned upstream access, 403 default, forged
headers, 418 Evil, removal, expiry during an outage, recovery, missing custom page
fallback and public UI/RPC isolation. It restores config and removes only decisions
with its unique run-specific reason/IDs. It never calls `decisions delete --all`.
This is an executable runner, **not a record of an already completed Docker run**.

The default `zoraxydocker/zoraxy:v3.2.9` exercises the legacy payload. For a pinned
resolved-client-ip source build:

```sh
docker build -f tools/Dockerfile.zoraxy-test -t zoraxy-bouncer-e2e:resolved .
ZORAXY_IMAGE=zoraxy-bouncer-e2e:resolved make e2e
```

The Dockerfile pins Zoraxy commit
`cde44510c6e4e22e2b108314cfa1b659eb4f550f` and preserves the upstream container
entrypoint. `.github/workflows/E2E.yml` offers both variants via workflow_dispatch and as a required reusable CI job.
Run it explicitly on a suitable runner; its hosted results are separate from the earlier local Windows snapshot.
The workflow itself and the pinned source container still require their first
Docker acceptance run. Ports must not already belong to other services.

Additional operational acceptance: observe `syncing -> ready -> degraded -> ready`
in the authenticated Zoraxy management UI, verify a normal empty snapshot, check
tags/groups in each Zoraxy version, confirm real Linux SIGTERM and shutdown of all
helper goroutines, and test an actual Cloudflare path and the logging pipeline's
native IP consistency. A unit header fixture does not prove Cloudflare acceptance.
Onboarding pass-through and plugin process-unavailable behavior are different:
Zoraxy may skip an unavailable plugin. Configuration errors are explicit startup
errors; there is no claim that a dead plugin can force Zoraxy to block.

## Distribution builds

The release workflow builds Linux 386, amd64, arm/v7, arm64, mipsle and riscv64,
and Windows amd64, with CGO_ENABLED=0 and matching asset names. It first calls the
same CI workflow used by PRs, checks the release tag, and publishes only after
verification, both Docker E2E variants and every binary build succeed. Assets are
uploaded to a draft, verified, then made public. Normal main pushes do not publish.
Introspection runs before config or external client initialization. No deployment,
production restart, firewall change, upstream push or release publication is part
of this verification.
