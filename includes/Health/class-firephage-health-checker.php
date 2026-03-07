<?php

namespace FirePhage\Security\Health;

if (! defined('ABSPATH')) {
    exit;
}

final class HealthChecker
{
    private const CACHE_KEY = 'firephage_security_health_report';

    /**
     * @return array<string, mixed>
     */
    public function getReport(bool $force = false): array
    {
        if (! $force) {
            $cached = get_transient(self::CACHE_KEY);

            if (is_array($cached)) {
                return $cached;
            }
        }

        $report = [
            'generated_at' => current_time('mysql'),
            'checks' => $this->buildChecks(),
        ];

        $report['summary'] = $this->summarizeChecks($report['checks']);
        $report['updates'] = $this->buildUpdateSummary();
        $report['core_checksum'] = $this->verifyCoreChecksums();

        set_transient(self::CACHE_KEY, $report, 5 * MINUTE_IN_SECONDS);

        return $report;
    }

    /**
     * @return array<int, array<string, string>>
     */
    private function buildChecks(): array
    {
        return [
            $this->makeCheck(
                'https',
                __('HTTPS is enabled', 'firephage-security'),
                str_starts_with(home_url(), 'https://'),
                __('Site URLs use HTTPS.', 'firephage-security'),
                __('WordPress is not configured to use HTTPS for the site URL.', 'firephage-security'),
                'critical'
            ),
            $this->makeCheck(
                'debug_display',
                __('Debug display is disabled', 'firephage-security'),
                ! (defined('WP_DEBUG_DISPLAY') && WP_DEBUG_DISPLAY),
                __('Errors are not exposed to visitors.', 'firephage-security'),
                __('WP_DEBUG_DISPLAY appears to be enabled and may expose PHP errors publicly.', 'firephage-security'),
                'warning'
            ),
            $this->makeCheck(
                'file_editor',
                __('Plugin and theme editor is disabled', 'firephage-security'),
                defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT,
                __('In-dashboard file editing is disabled.', 'firephage-security'),
                __('Enable DISALLOW_FILE_EDIT to reduce the impact of compromised admin accounts.', 'firephage-security'),
                'warning'
            ),
            $this->makeCheck(
                'registration',
                __('Public user registration is disabled', 'firephage-security'),
                ! (bool) get_option('users_can_register'),
                __('Anyone cannot register new accounts automatically.', 'firephage-security'),
                __('Anyone can register accounts on this site. Confirm that this is intentional.', 'firephage-security'),
                'warning'
            ),
            $this->makeCheck(
                'xmlrpc',
                __('XML-RPC is disabled', 'firephage-security'),
                ! apply_filters('xmlrpc_enabled', true),
                __('XML-RPC is disabled.', 'firephage-security'),
                __('XML-RPC is enabled and can increase brute-force or abuse exposure.', 'firephage-security'),
                'warning'
            ),
            $this->makeCheck(
                'default_admin',
                __('Default "admin" username is not present', 'firephage-security'),
                ! username_exists('admin'),
                __('No user account named "admin" was found.', 'firephage-security'),
                __('A user account named "admin" exists. Rename or remove it if possible.', 'firephage-security'),
                'critical'
            ),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function buildUpdateSummary(): array
    {
        $core = get_site_transient('update_core');
        $plugins = get_site_transient('update_plugins');
        $themes = get_site_transient('update_themes');

        $pluginUpdates = isset($plugins->response) && is_array($plugins->response)
            ? count($plugins->response)
            : 0;

        $themeUpdates = isset($themes->response) && is_array($themes->response)
            ? count($themes->response)
            : 0;

        $coreUpdates = 0;

        if (isset($core->updates) && is_array($core->updates)) {
            foreach ($core->updates as $update) {
                if (isset($update->response) && $update->response === 'upgrade') {
                    $coreUpdates++;
                }
            }
        }

        return [
            'core_updates' => $coreUpdates,
            'plugin_updates' => $pluginUpdates,
            'theme_updates' => $themeUpdates,
            'inactive_plugins' => count(get_option('inactive_plugins', [])),
            'severity' => ($coreUpdates + $pluginUpdates + $themeUpdates) > 0 ? 'warning' : 'good',
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function verifyCoreChecksums(): array
    {
        require_once ABSPATH . 'wp-admin/includes/update.php';
        require_once ABSPATH . WPINC . '/version.php';

        global $wp_local_package;
        global $wp_version;

        $locale = is_string($wp_local_package) && $wp_local_package !== '' ? $wp_local_package : 'en_US';
        $checksums = get_core_checksums($wp_version, $locale);

        if (! is_array($checksums) || $checksums === []) {
            return [
                'status' => 'unknown',
                'summary' => __('WordPress.org checksums are not available for this install.', 'firephage-security'),
                'modified' => [],
                'missing' => [],
            ];
        }

        $modified = [];
        $missing = [];

        foreach ($checksums as $relativePath => $checksum) {
            $absolutePath = ABSPATH . ltrim($relativePath, '/');

            if (! file_exists($absolutePath)) {
                $missing[] = $relativePath;
                continue;
            }

            $fileHash = md5_file($absolutePath);

            if (! is_string($fileHash) || strtolower($fileHash) !== strtolower((string) $checksum)) {
                $modified[] = $relativePath;
            }
        }

        if ($modified === [] && $missing === []) {
            return [
                'status' => 'good',
                'summary' => __('WordPress core checksums match the official release.', 'firephage-security'),
                'modified' => [],
                'missing' => [],
            ];
        }

        return [
            'status' => 'warning',
            'summary' => __('Some WordPress core files differ from the official checksums.', 'firephage-security'),
            'modified' => array_slice($modified, 0, 20),
            'missing' => array_slice($missing, 0, 20),
        ];
    }

    /**
     * @return array<string, string>
     */
    private function makeCheck(
        string $key,
        string $label,
        bool $passing,
        string $successMessage,
        string $failureMessage,
        string $failureSeverity
    ): array {
        return [
            'key' => $key,
            'label' => $label,
            'status' => $passing ? 'good' : $failureSeverity,
            'message' => $passing ? $successMessage : $failureMessage,
        ];
    }

    /**
     * @param array<int, array<string, string>> $checks
     * @return array<string, int>
     */
    private function summarizeChecks(array $checks): array
    {
        $summary = [
            'good' => 0,
            'warning' => 0,
            'critical' => 0,
        ];

        foreach ($checks as $check) {
            $status = $check['status'] ?? 'warning';

            if (isset($summary[$status])) {
                $summary[$status]++;
            }
        }

        return $summary;
    }
}
