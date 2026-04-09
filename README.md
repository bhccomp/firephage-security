# FirePhage Security

FirePhage Security is a WordPress plugin focused on practical site health and security visibility inside WP Admin.

It is built to give site owners and operators a clearer view of:

- WordPress health and hardening state
- core integrity and checksum mismatches
- suspicious file findings from local malware scanning
- update exposure across plugins, themes, and WordPress core
- optional connection to the FirePhage platform for synced reporting

## What the plugin does

The plugin currently includes:

- a single-screen admin experience inside WordPress
- local WordPress health and hardening checks
- WordPress core checksum verification
- resumable background malware scanning
- update and maintenance exposure summaries
- optional FirePhage dashboard connectivity for synced reports

## External services

The plugin can contact external services in these cases:

- optional FirePhage dashboard connection initiated by the site owner
- optional FirePhage-hosted checksum cache when enabled
- optional FirePhage signature refresh and report sync workflows
- WordPress.org checksum metadata as fallback where applicable

These integrations are optional and depend on plugin configuration.

## Status

This repository is under active development.

The current focus is on:

- improving scan accuracy
- keeping the admin workflow readable
- aligning the plugin with production FirePhage reporting workflows

## License

FirePhage Security is licensed under GPLv2 or later.

See [LICENSE](LICENSE) for the full GPL text and [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for bundled asset notices.
