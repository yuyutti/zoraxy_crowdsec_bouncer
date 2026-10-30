# Migration to yuyutti v1.2.4-1

The fork keeps base version 1.2.4 and uses revision suffix `-1`. SDK numeric fields
remain 1/2/4; the additional `version` metadata, version API, User-Agent and release
tag use `v1.2.4-1`. The fork update channel orders numeric revisions numerically.
No same-ID compatibility build is provided.

1. Back up the upstream plugin directory, binary, valid config and Zoraxy's plugin
   groups/tags. Keep the backup private; configs contain the LAPI key.
2. Build this checkout with Go 1.26.10+ (`go build -o zoraxycrowdsecbouncer .`).
   Published artifacts, when explicitly released later, belong to
   `yuyutti/zoraxy_crowdsec_bouncer`; publication is gated by CI on the exact same commit.
3. Install it in a separate plugin directory. Copy the valid config and existing
   bouncer key, and restrict access to the service account (Unix mode 0600 or a
   suitable Windows ACL). No key rotation is required merely for this migration.
4. Before enabling the fork, remove the upstream plugin from the protected groups.
   Stop the old consumer before starting the new one: two stream consumers with
   one bouncer key interfere. Do not apply both plugins to one protected route.
5. Register the fork ID `com.yuyutti.zoraxycrowdsecbouncer`, replacing
   `com.anthonyrubick.zoraxycrowdsecbouncer` in plugin groups. Reapply the protected
   route's tags to this group. A binary replacement alone does not migrate IDs.
6. Review trusted proxies in Zoraxy. With a resolved `client_ip` payload, that IP
   is authoritative. With legacy payloads configure exact proxy IPs/CIDRs; empty
   lists now trust nobody. General trusted proxies do not imply Cloudflare relay
   trust. Explicit `cloudflare_trusted_relays` must validate upstream CF peers and
   overwrite CF metadata. Coordinate native IPv6/Pseudo IPv4 logging in CrowdSec.
7. Old config without `block_response` keeps 403 with exactly `Forbidden`. Add the
   evil/custom examples only when desired. Unknown/duplicate YAML fields and invalid
   settings now produce startup errors; read the error and correct the config.
   Missing custom pages instead keep the running bouncer's 403 fallback.
8. Check the management UI reaches `ready`, including for an empty BAN snapshot.
   Test a dedicated short-duration IPv4 and IPv6 decision on isolated routes.
   Confirm the recognized source IP and only remove decisions created for the test.
   Never expose loopback sniff/capture/API paths through a public proxy rule.
9. Check `.releaseurl` and UI links point to the fork. Evaluation releases use the
   exact `releases/download/v1.2.4-1` path because prereleases are excluded from
   GitHub's stable latest endpoint. The update checker ignores all prereleases
   and drafts. Normal pushes run checks/builds only; tag/manual release runs
   repeat CI including both E2E payload variants at the same SHA before upload
   and publication. There is no automatic installer. See docs/releasing.md.


## Rollback

Remove the fork from protected groups and stop its process. Restore the private
upstream backup, config and upstream ID in the original groups, then reapply the
route tags. Start only the upstream consumer and verify its synchronization and
blocking on isolated test decisions. Restore upstream `.releaseurl` with the
upstream binary. Keep this fork's update metadata out of that directory. Rollback
also restores upstream's former trust behavior; reconsider direct-origin exposure
before relying on its header handling. No database schema or permanent decision
migration is needed.

Native IPv4 and IPv6 are independent identifiers. This fork never infers an IPv6
address or /64 from an IPv4 BAN, nor tracks browsers with cookies/User-Agent.
