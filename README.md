# FirePhage Security

WordPress plugin for running local security checks inside WP Admin and optionally syncing those reports to FirePhage.

## Current Modules

- tabbed single-screen WP Admin interface
- local WordPress health and hardening checks
- WordPress core checksum verification
- background malware scan for high-risk PHP and JavaScript files
- updates and maintenance exposure summary
- optional FirePhage dashboard connection with automatic report sync once connected

## Local Development

- Repo path: `/var/www/firephage-security`
- Remote WordPress plugin path: `/var/www/nodesfoundry.com/wp-content/plugins/firephage-security`

## Current State

This is the first functional implementation pass. It includes:

- a single-page admin UI with client-side tab switching
- AJAX actions for scan control, health refresh, dashboard connection, and report sync
- a resumable background scanner driven by WP-Cron batches
- a local report builder that can be sent to FirePhage when connected
