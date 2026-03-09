=== FirePhage Security ===
Contributors: firephage
Tags: security, malware, hardening, scanner
Requires at least: 6.4
Tested up to: 6.8
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

FirePhage Security provides local WordPress health checks, repository integrity verification, and background malware scanning.

== Description ==

FirePhage Security includes:

* local health and hardening checks
* WordPress core checksum verification
* plugin and theme repository integrity verification
* background malware scanning
* optional paid FirePhage dashboard connection for report sync and alerts

== External services ==

This plugin can contact external services in three cases.

1. Public checksum verification
The plugin may request WordPress.org plugin and theme checksum metadata from FirePhage cache services. If that cache is unavailable, the plugin falls back to WordPress.org directly. These requests send only the package type, slug, and version needed for checksum verification.

2. Optional free FirePhage signature token
If the site owner explicitly requests a free FirePhage signature token, the plugin sends the chosen email address, site URL details, plugin version, and optional marketing-consent preference to FirePhage so the token can be emailed and remote signature updates can be enabled.

3. Optional paid FirePhage connection
If the site owner explicitly connects the plugin to FirePhage, the plugin sends site connection details and security reports to FirePhage so dashboard sync and alerting can work.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/` or install it through WordPress.
2. Activate the plugin.
3. Open the FirePhage admin page to run local checks and scans.
