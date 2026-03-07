# MEMORY

## WordPress.org Plugin Compliance
- This plugin is intended for possible submission to the official WordPress.org plugin repository.
- Before implementing requested plugin features or behavioral changes, check whether the requested behavior aligns with current WordPress.org plugin rules and expectations.
- In particular, review proposed changes against common WordPress.org concerns such as:
  - security and data handling
  - remote service disclosure and consent
  - malware/scanner behavior
  - external calls, telemetry, and tracking
  - admin UX patterns
  - bundled libraries, licensing, and attribution
  - update mechanisms and anything that could conflict with repository distribution rules
- If a requested feature appears risky or potentially non-compliant with WordPress.org expectations, call that out before implementing it.
- Default approach:
  - build features so they are repository-safe by design
  - avoid dark patterns, hidden remote behavior, or anything likely to trigger plugin review rejection

## Workflow
- Primary plugin development repo:
  - `/var/www/firephage-security`
- Remote WordPress install path:
  - `/var/www/nodesfoundry.com/wp-content/plugins/firephage-security`
- After plugin changes are made locally:
  - commit and push the plugin repo
  - pull the latest changes on the remote WordPress server so `nodesfoundry.com` has the updated plugin code

## Current Plugin State
- The plugin now has a first functional admin implementation instead of scaffold-only placeholders.
- Current shipped pieces:
  - single-screen admin UI with client-side tabs
  - local health checks
  - WordPress core checksum verification
  - resumable background malware scanning
  - FirePhage connection flow using a dashboard-generated token
  - automatic report sync after connection plus scheduled report sync when enabled
- Scanner tuning follow-up:
  - excluded FirePhage plugin files from scanner findings
  - trusted WordPress core files that match official checksums
  - replaced naive one-hit regex flagging with a stricter scoring model to reduce false positives
  - scan progress bar now has active motion while running and the scan button stays disabled during active scans
- Current UX/product expectations:
  - do not expose a manual `Send Report to Dashboard` button in the plugin UI
  - auto-sync should be enabled by default for connected sites
  - after plugin changes in this repo, complete the full workflow through remote sync on the WordPress server in the same task
