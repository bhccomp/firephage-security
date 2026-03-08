# FirePhage Security

WordPress plugin for running local security checks inside WP Admin and optionally syncing those reports to FirePhage.

## Current Modules

- tabbed single-screen WP Admin interface
- local WordPress health and hardening checks
- WordPress core checksum verification
- background malware scan for high-risk PHP and JavaScript files
- updates and maintenance exposure summary
- optional FirePhage dashboard connection with automatic report sync once connected
- FirePhage-hosted checksum caching for WordPress.org plugin/theme package verification with WordPress.org fallback

## Local Development

- Repo path: `/var/www/firephage-security`
- Remote WordPress plugin path: `/var/www/nodesfoundry.com/wp-content/plugins/firephage-security`

## Current State

This is the first functional implementation pass. It includes:

- a single-page admin UI with client-side tab switching
- AJAX actions for scan control, health refresh, dashboard connection, and report sync
- a resumable background scanner driven by WP-Cron batches
- a local report builder that can be sent to FirePhage when connected

## External Services

FirePhage Security can contact external services in two cases:

- Public checksum lookups:
  - the scanner may request WordPress.org plugin/theme checksum metadata from FirePhage cache services
  - if FirePhage cache is unavailable, the plugin falls back to WordPress.org directly
  - these requests send only package type, slug, and version
- Optional paid FirePhage connection:
  - when a user explicitly connects the plugin, the plugin sends site connection details and security reports to FirePhage for dashboard sync and alerts
