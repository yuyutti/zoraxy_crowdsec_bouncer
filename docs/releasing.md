# Publish and operate from a PC without Go

Repository, PR target, Actions and Releases are all
https://github.com/yuyutti/zoraxy_crowdsec_bouncer (`main`). Upstream is read-only
for comparison and MIT attribution. No new fork is needed.

1. Push the work branch and open a PR against this fork's main. A normal branch
   or main push runs CI; it never creates a Release. You do not need Go, Docker,
   make or jq on your PC. Actions installs Go from go.mod and runs tests, race,
   vet, pinned staticcheck/govulncheck, fuzz, UI and SDK metadata checks, both
   isolated Docker E2E variants and all seven distribution builds.
2. Open the CI run for the exact source commit. Require all jobs to succeed.
   Inspect the seven uploaded binary/checksum artifacts. Do not create a version
   tag for a failing or unverified commit.
3. Check this fork's Tags and Releases for an existing version. The current
   source version is v1.2.4-2. Do not overwrite an existing tag or its assets.
4. After verification, create/push the exact version tag at that verified SHA.
   Alternatively, once CD.yml is present on main, use Actions -> Publish fork
   release -> Run workflow, select the source branch/commit, enter the exact
   source version and leave prerelease enabled for an evaluation build. The
   manual workflow must exist on main to appear in GitHub's Run workflow UI.
5. The publication workflow repeats the same CI at the selected SHA. Its release
   job cannot run before metadata, tests, race, scans, E2E and builds all pass.
   It checks binary metadata and checksums, uploads a draft, verifies all uploaded
   assets and only then publishes. Failure leaves the Release unpublished.
6. Confirm the Actions summary's Release link, full tag, source SHA, seven binary
   names, individual SHA256 files, config.yaml, introspect.json, releaseurl.txt, LICENSE,
   SHA256SUMS and release-notes.md. SHA256SUMS covers the distributable files.
   Download the appropriate binary and compare its checksum using the PC's normal
   checksum tool (for example PowerShell Get-FileHash -Algorithm SHA256).

Initial evaluation download base:
https://github.com/yuyutti/zoraxy_crowdsec_bouncer/releases/download/v1.2.4-2

The evaluation .releaseurl uses that exact tag. GitHub prereleases are not stable
latest releases. The UI's stable update channel excludes every prerelease and
unpublished draft; an empty stable channel does not suggest upstream updates.
A later stable publication can use the manual workflow with prerelease disabled;
its tag still must match source and every validation must pass. The full version
is exposed by -introspect and the version API; SDK numeric compatibility fields
remain 1/2/4 for v1.2.4-2.

All distribution builds preserve the upstream asset naming/platform format:
Linux 386, amd64, arm/v7, arm64, mipsle and riscv64; Windows amd64.
Go module imports intentionally retain the original coherent module path; this
is independent of Plugin ID, repository URLs and update distribution identity.

To install, follow [migration.md](migration.md). Preserve the private config/API
key, stop the old stream consumer before starting the new one, use fork ID
com.yuyutti.zoraxycrowdsecbouncer and update plugin_groups.json/route tags. Do not
apply old and new plugins to the same route. Separate routes may use either ID;
use distinct bouncer keys for concurrent consumers. Rollback restores the old
binary/ID/group membership/tags and private config after stopping the fork.
Publishing assets does not deploy or restart a production Zoraxy server.

GitHub may rename assets with leading periods. The portable release asset names
are `introspect.json` and `releaseurl.txt`; when installing these metadata files,
save them as `.introspect` and `.releaseurl`. Their contents exactly match the
source and the tested binary metadata. Binary names and config.yaml remain in
the upstream format.
