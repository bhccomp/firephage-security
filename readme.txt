=== FirePhage Security ===
Contributors: firephage
Tags: security, malware scanner, malware, file integrity, login security
Requires at least: 5.3
Tested up to: 6.9
Requires PHP: 7.1
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress security plugin with malware scanning, file integrity checks, login protection, update visibility, and optional FirePhage sync.

== Description ==

FirePhage Security helps you monitor WordPress security locally with malware scanning, official checksum verification, login protection, update visibility, and optional FirePhage dashboard connectivity.

FirePhage Security includes:

* local health and hardening checks
* WordPress core checksum verification
* plugin and theme repository integrity verification
* background malware scanning
* optional paid FirePhage dashboard connection for report sync and alerts

== Licensing ==

FirePhage Security is licensed under GPLv2 or later.

All code and assets bundled inside this plugin are either:

* original FirePhage plugin files released under GPLv2 or later
* or GPL-compatible third-party assets documented below

Bundled third-party asset:

* Choices.js
* Source: https://github.com/Choices-js/Choices
* License: MIT
* Purpose: searchable country and continent dropdowns in the WordPress admin UI
* Copyright: Josh Johnson and contributors

Choices.js is distributed under the MIT License, which is GPL-compatible.

== External services ==

This plugin can contact external services in three cases.

1. Public checksum verification
By default, the plugin requests WordPress.org plugin and theme checksum metadata directly from WordPress.org.

If the site owner explicitly enables the optional FirePhage checksum cache in Scanner Settings or during first-run setup, the plugin requests the same checksum metadata from FirePhage first and then falls back to WordPress.org if needed. These requests send only the package type, slug, and version needed for checksum verification.

When you manually choose Compare or Restore for an official WordPress.org checksum mismatch, the plugin may request the matching reference file through FirePhage so it can show a file comparison or restore the official file you selected. This happens only after a user action and is not part of normal background scanning.

FirePhage is used as a retrieval layer for official WordPress.org reference files; the plugin does not execute arbitrary remote code.

Service: https://firephage.com
Privacy policy: https://firephage.com/privacy
Terms: https://firephage.com/terms

2. Optional free FirePhage signature token
If the site owner explicitly requests a free FirePhage signature token, the plugin sends the chosen email address, site URL details, plugin version, and optional marketing-consent preference to FirePhage so the token can be emailed and remote signature updates can be enabled.

Service: https://firephage.com
Privacy policy: https://firephage.com/privacy
Terms: https://firephage.com/terms

3. Optional paid FirePhage connection
If the site owner explicitly connects the plugin to FirePhage, the plugin sends site connection details and security reports to FirePhage so dashboard sync and alerting can work.

Service: https://firephage.com
Privacy policy: https://firephage.com/privacy
Terms: https://firephage.com/terms

== Installation ==

1. Upload the plugin to `/wp-content/plugins/` or install it through WordPress.
2. Activate the plugin.
3. Open the FirePhage admin page to run local checks and scans.
