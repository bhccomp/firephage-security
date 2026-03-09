<?php

namespace FirePhage\Security\Admin;

use FirePhage\Security\FirePhage\Client;
use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Reports\ReportBuilder;
use FirePhage\Security\Scanner\MalwareScanner;
use FirePhage\Security\Settings;

if (! defined('ABSPATH')) {
    exit;
}

final class Admin
{
    private Settings $settings;

    private MalwareScanner $scanner;

    private HealthChecker $healthChecker;

    private ReportBuilder $reportBuilder;

    private Client $client;

    public function __construct(
        Settings $settings,
        MalwareScanner $scanner,
        HealthChecker $healthChecker,
        ReportBuilder $reportBuilder,
        Client $client
    ) {
        $this->settings = $settings;
        $this->scanner = $scanner;
        $this->healthChecker = $healthChecker;
        $this->reportBuilder = $reportBuilder;
        $this->client = $client;

        add_action('wp_ajax_firephage_start_scan', [$this, 'handleStartScan']);
        add_action('wp_ajax_firephage_scan_status', [$this, 'handleScanStatus']);
        add_action('wp_ajax_firephage_clear_findings', [$this, 'handleClearFindings']);
        add_action('wp_ajax_firephage_delete_suspicious_files', [$this, 'handleDeleteSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_selected_suspicious_files', [$this, 'handleDeleteSelectedSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_suspicious_file', [$this, 'handleDeleteSuspiciousFile']);
        add_action('wp_ajax_firephage_refresh_health', [$this, 'handleRefreshHealth']);
        add_action('wp_ajax_firephage_connect_dashboard', [$this, 'handleConnectDashboard']);
        add_action('wp_ajax_firephage_disconnect_dashboard', [$this, 'handleDisconnectDashboard']);
    }

    public function registerMenus(): void
    {
        add_menu_page(
            __('FirePhage Security', 'firephage-security'),
            __('FirePhage', 'firephage-security'),
            'manage_options',
            'firephage-security',
            [$this, 'renderOverviewPage'],
            'dashicons-shield-alt',
            58
        );
    }

    public function enqueueAssets(string $hook): void
    {
        if ($hook !== 'toplevel_page_firephage-security') {
            return;
        }

        $stylePath = FIREPHAGE_SECURITY_PATH . 'assets/css/admin.css';
        $scriptPath = FIREPHAGE_SECURITY_PATH . 'assets/js/admin.js';
        $styleVersion = file_exists($stylePath) ? (string) filemtime($stylePath) : FIREPHAGE_SECURITY_VERSION;
        $scriptVersion = file_exists($scriptPath) ? (string) filemtime($scriptPath) : FIREPHAGE_SECURITY_VERSION;

        wp_enqueue_style(
            'firephage-security-admin',
            FIREPHAGE_SECURITY_URL . 'assets/css/admin.css',
            [],
            $styleVersion
        );

        wp_enqueue_script(
            'firephage-security-admin',
            FIREPHAGE_SECURITY_URL . 'assets/js/admin.js',
            ['jquery'],
            $scriptVersion,
            true
        );

        wp_localize_script(
            'firephage-security-admin',
            'firephageAdmin',
            [
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('firephage_admin'),
                'labels' => [
                    'startScan' => __('Start Background Scan', 'firephage-security'),
                    'scanStarting' => __('Starting scan...', 'firephage-security'),
                    'notConnected' => __('Not connected', 'firephage-security'),
                    'clearFindings' => __('Clear Findings', 'firephage-security'),
                    'deleteSuspiciousFiles' => __('Delete All Suspicious Files', 'firephage-security'),
                    'deleteSelectedFiles' => __('Delete Selected Files', 'firephage-security'),
                    'deleteFile' => __('Delete File', 'firephage-security'),
                    'confirmDeleteTitle' => __('Delete Suspicious File?', 'firephage-security'),
                    'confirmDeleteAllTitle' => __('Delete All Suspicious Files?', 'firephage-security'),
                    'confirmDeleteSelectedTitle' => __('Delete Selected Suspicious Files?', 'firephage-security'),
                    'confirmDeleteBody' => __('This will permanently delete the selected suspicious file from the server. This action cannot be undone.', 'firephage-security'),
                    'confirmDeleteAllBody' => __('This will permanently delete every file currently flagged as suspicious malware. Protected core files will be skipped. This action cannot be undone.', 'firephage-security'),
                    'confirmDeleteSelectedBody' => __('This will permanently delete the selected suspicious malware files. Protected core files will be skipped. This action cannot be undone.', 'firephage-security'),
                    'confirmAction' => __('Delete', 'firephage-security'),
                    'cancelAction' => __('Cancel', 'firephage-security'),
                ],
            ]
        );
    }

    public function renderOverviewPage(): void
    {
        $settings = $this->settings->all();
        $report = $this->reportBuilder->build();
        $scan = $this->scanner->getState();
        $health = $report['health'];
        $updates = $health['updates'];
        $checksum = $health['core_checksum'];

        echo '<div class="wrap firephage-admin">';
        echo '<div class="firephage-shell">';
        echo '<div class="firephage-hero">';
        echo '<div>';
        echo '<p class="firephage-eyebrow">' . esc_html__('Local WordPress Security', 'firephage-security') . '</p>';
        echo '<h1>' . esc_html__('FirePhage Security', 'firephage-security') . '</h1>';
        echo '<p class="firephage-hero-copy">' . esc_html__('Run local health checks, verify repository integrity, scan high-risk code paths in background batches, and optionally sync reports to FirePhage.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-hero-actions">';
        echo '<a class="button button-primary button-hero" href="' . esc_url($settings['dashboard_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Upgrade with FirePhage', 'firephage-security') . '</a>';
        echo '</div>';
        echo '</div>';

        echo '<div class="firephage-stat-grid">';
        echo $this->renderStatCard(__('Checks Passing', 'firephage-security'), (string) ($health['summary']['good'] ?? 0), __('Local hardening checks currently passing.', 'firephage-security'));
        echo $this->renderStatCard(__('Updates Pending', 'firephage-security'), (string) (($updates['core_updates'] ?? 0) + ($updates['plugin_updates'] ?? 0) + ($updates['theme_updates'] ?? 0)), __('Core, plugin, and theme updates waiting.', 'firephage-security'));
        echo $this->renderStatCard(__('Suspicious Files', 'firephage-security'), (string) ($scan['suspicious_files'] ?? 0), __('Latest malware scan findings.', 'firephage-security'), 'firephage-suspicious-files-stat');
        echo $this->renderStatCard(__('Dashboard Status', 'firephage-security'), ucfirst((string) ($settings['connection_status'] ?? 'disconnected')), __('Whether local reports can be synced to FirePhage.', 'firephage-security'));
        echo '</div>';

        echo '<div class="firephage-tabs" role="tablist" aria-label="' . esc_attr__('FirePhage sections', 'firephage-security') . '">';
        foreach ($this->tabs() as $tabId => $label) {
            echo '<button type="button" class="firephage-tab-button" data-tab="' . esc_attr($tabId) . '">' . esc_html($label) . '</button>';
        }
        echo '</div>';

        echo '<div id="firephage-admin-app" data-scan-status="' . esc_attr(wp_json_encode($scan)) . '">';
        echo '<section class="firephage-tab-panel" data-panel="overview">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<h2>' . esc_html__('What this plugin covers', 'firephage-security') . '</h2>';
        echo '<ul class="firephage-list">';
        echo '<li>' . esc_html__('Local WordPress health and hardening checks', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('WordPress core checksum verification against official release hashes', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Background scanning that prioritizes repository integrity checks before heuristic review', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Optional FirePhage dashboard sync for reports and alerts', 'firephage-security') . '</li>';
        echo '</ul>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<h2>' . esc_html__('Latest sync', 'firephage-security') . '</h2>';
        echo '<p><strong>' . esc_html__('Connection:', 'firephage-security') . '</strong> ' . esc_html(ucfirst($settings['connection_status'])) . '</p>';
        echo '<p><strong>' . esc_html__('Last report sync:', 'firephage-security') . '</strong> ' . esc_html($settings['last_sync_at'] !== '' ? $settings['last_sync_at'] : __('Not sent yet', 'firephage-security')) . '</p>';
        echo '<p><strong>' . esc_html__('Last sync error:', 'firephage-security') . '</strong> ' . esc_html($settings['last_sync_error'] !== '' ? $settings['last_sync_error'] : __('None', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="health">';
        echo '<div class="firephage-panel-header">';
        echo '<div><h2>' . esc_html__('Health Checks', 'firephage-security') . '</h2><p>' . esc_html__('Fast local checks focused on common WordPress exposure points.', 'firephage-security') . '</p></div>';
        echo '<button type="button" class="button button-secondary firephage-refresh-health">' . esc_html__('Refresh Checks', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<div class="firephage-grid" id="firephage-health-checks">';
        foreach ($health['checks'] as $check) {
            echo $this->renderCheckCard($check);
        }
        echo '</div>';
        echo '<div class="firephage-card firephage-checksum-card firephage-section-spaced" id="firephage-core-checksum">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('WordPress Core Checksums', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr((string) ($checksum['status'] ?? 'unknown')) . '">' . esc_html(ucfirst((string) ($checksum['status'] ?? 'unknown'))) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html((string) ($checksum['summary'] ?? '')) . '</p>';
        echo $this->renderChecksumList(__('Modified files', 'firephage-security'), $checksum['modified'] ?? []);
        echo $this->renderChecksumList(__('Missing files', 'firephage-security'), $checksum['missing'] ?? []);
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="scanner">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Malware Scanner', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-scan-status-badge">' . esc_html(ucfirst((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Runs in background batches so large sites can finish without locking up the admin screen, using official package checksums and local clean baselines before suspicious-code heuristics.', 'firephage-security') . '</p>';
        echo '<div class="firephage-progress"><div class="firephage-progress-bar" id="firephage-scan-progress-bar" style="width:' . esc_attr((string) $this->scanProgress($scan)) . '%"></div></div>';
        echo '<p id="firephage-scan-progress-label">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<button type="button" class="button button-primary firephage-start-scan">' . esc_html__('Start Background Scan', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<h3>' . esc_html__('Scan scope', 'firephage-security') . '</h3>';
        echo '<ul class="firephage-list">';
        echo '<li>' . esc_html__('Verifies WordPress core, plugin, and theme files against official package checksums where available', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Seeds and reuses a local clean-file baseline for custom code that is not covered by repository checksums', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Skips uploads, cache-like directories, and obvious bundled/minified noise before applying weighted malware heuristics', 'firephage-security') . '</li>';
        echo '</ul>';
        echo '<p class="firephage-note">' . esc_html__('Checksum lookups may use FirePhage\'s public checksum cache and fall back to WordPress.org. Those requests send only package type, slug, and version. FirePhage dashboard connection remains separate and optional.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-findings-card firephage-section-spaced">';
        echo '<h3>' . esc_html__('Latest findings', 'firephage-security') . '</h3>';
        echo '<div id="firephage-scan-findings">' . $this->renderFindings($scan['findings'] ?? []) . '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="updates">';
        echo '<div class="firephage-grid">';
        echo $this->renderUpdateCard(__('Core updates', 'firephage-security'), (int) ($updates['core_updates'] ?? 0), __('Pending WordPress core releases.', 'firephage-security'));
        echo $this->renderUpdateCard(__('Plugin updates', 'firephage-security'), (int) ($updates['plugin_updates'] ?? 0), __('Installed plugins with updates available.', 'firephage-security'));
        echo $this->renderUpdateCard(__('Theme updates', 'firephage-security'), (int) ($updates['theme_updates'] ?? 0), __('Installed themes with updates available.', 'firephage-security'));
        echo $this->renderUpdateCard(__('Inactive plugins', 'firephage-security'), (int) ($updates['inactive_plugins'] ?? 0), __('Inactive plugins increase maintenance surface and should be reviewed.', 'firephage-security'));
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="connect">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<h2>' . esc_html__('Connect to FirePhage', 'firephage-security') . '</h2>';
        echo '<p>' . esc_html__('Generate a connection token in your FirePhage dashboard, paste it here, and the plugin will exchange it for a site-scoped credential and start syncing local reports automatically.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note">' . esc_html__('This paid connection is only for dashboard sync and alerting. Local health checks, scanner features, and public checksum lookups do not require a connected FirePhage account.', 'firephage-security') . '</p>';
        echo '<form id="firephage-connect-form">';
        echo '<label class="firephage-field"><span>' . esc_html__('Dashboard URL', 'firephage-security') . '</span><input type="url" name="dashboard_url" value="' . esc_attr($settings['dashboard_url']) . '" /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Connection token', 'firephage-security') . '</span><input type="password" name="connection_token" value="' . esc_attr($settings['connection_token']) . '" autocomplete="off" /></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="auto_sync_reports" value="1" ' . checked($settings['auto_sync_reports'], '1', false) . ' /><span>' . esc_html__('Automatically send scheduled local reports after connection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary">' . esc_html__('Connect Plugin', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-disconnect">' . esc_html__('Disconnect', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<h3>' . esc_html__('Why this flow is safer', 'firephage-security') . '</h3>';
        echo '<p>' . esc_html__('The dashboard issues a scoped token first. That avoids trusting domain names alone and makes it possible to verify both site ownership and account intent before reports are accepted.', 'firephage-security') . '</p>';
        echo '<p><strong>' . esc_html__('Connected site ID:', 'firephage-security') . '</strong> <span id="firephage-connected-site-id">' . esc_html($settings['site_id'] !== '' ? $settings['site_id'] : __('Not connected', 'firephage-security')) . '</span></p>';
        echo '</div>';
        echo '</div>';
        echo '</section>';
        echo '</div>';
        echo '<div class="firephage-modal" id="firephage-confirm-modal" hidden>';
        echo '<div class="firephage-modal-backdrop" data-modal-close="1"></div>';
        echo '<div class="firephage-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="firephage-confirm-modal-title">';
        echo '<div class="firephage-modal-head">';
        echo '<h3 id="firephage-confirm-modal-title">' . esc_html__('Confirm Action', 'firephage-security') . '</h3>';
        echo '<button type="button" class="button-link firephage-modal-close" data-modal-close="1" aria-label="' . esc_attr__('Close dialog', 'firephage-security') . '">&times;</button>';
        echo '</div>';
        echo '<p id="firephage-confirm-modal-body"></p>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary" data-modal-close="1">' . esc_html__('Cancel', 'firephage-security') . '</button>';
        echo '<button type="button" class="button firephage-button-danger" id="firephage-confirm-modal-submit">' . esc_html__('Delete', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-toast" id="firephage-toast" hidden></div>';
        echo '</div>';
        echo '</div>';
    }

    public function handleStartScan(): void
    {
        $this->assertAjaxPermissions();

        $result = $this->scanner->startScan();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()], 400);
        }

        wp_send_json_success(['state' => $result]);
    }

    public function handleScanStatus(): void
    {
        $this->assertAjaxPermissions();
        wp_send_json_success(['state' => $this->scanner->getState()]);
    }

    public function handleClearFindings(): void
    {
        $this->assertAjaxPermissions();
        wp_send_json_success([
            'message' => __('Latest findings were cleared.', 'firephage-security'),
            'state' => $this->scanner->clearFindings(),
        ]);
    }

    public function handleDeleteSuspiciousFiles(): void
    {
        $this->assertAjaxPermissions();
        $result = $this->scanner->deleteSuspiciousFiles();

        wp_send_json_success([
            'message' => sprintf(
                __('Deleted %1$d suspicious files. Skipped %2$d protected or unavailable files.', 'firephage-security'),
                (int) ($result['deleted_files'] ?? 0),
                (int) ($result['skipped_files'] ?? 0)
            ),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
    }

    public function handleDeleteSuspiciousFile(): void
    {
        $this->assertAjaxPermissions();
        $file = sanitize_text_field((string) ($_POST['file'] ?? ''));
        $result = $this->scanner->deleteSuspiciousFile($file);

        wp_send_json_success([
            'message' => (string) ($result['message'] ?? __('The request has been processed.', 'firephage-security')),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
    }

    public function handleDeleteSelectedSuspiciousFiles(): void
    {
        $this->assertAjaxPermissions();
        $files = isset($_POST['files']) && is_array($_POST['files']) ? array_map('sanitize_text_field', $_POST['files']) : [];
        $result = $this->scanner->deleteSelectedSuspiciousFiles($files);

        wp_send_json_success([
            'message' => sprintf(
                __('Deleted %1$d selected suspicious files. Skipped %2$d protected or unavailable files.', 'firephage-security'),
                (int) ($result['deleted_files'] ?? 0),
                (int) ($result['skipped_files'] ?? 0)
            ),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
    }

    public function handleRefreshHealth(): void
    {
        $this->assertAjaxPermissions();
        wp_send_json_success(['report' => $this->reportBuilder->build(true)]);
    }

    public function handleConnectDashboard(): void
    {
        $this->assertAjaxPermissions();

        $dashboardUrl = esc_url_raw((string) ($_POST['dashboard_url'] ?? ''));
        $connectionToken = sanitize_text_field((string) ($_POST['connection_token'] ?? ''));
        $autoSync = ! empty($_POST['auto_sync_reports']) ? '1' : '0';

        if ($dashboardUrl === '' || $connectionToken === '') {
            wp_send_json_error(['message' => __('Dashboard URL and connection token are required.', 'firephage-security')], 400);
        }

        $response = $this->client->connect($dashboardUrl, $connectionToken);

        if (is_wp_error($response)) {
            $this->settings->update([
                'dashboard_url' => $dashboardUrl,
                'connection_token' => $connectionToken,
                'connection_status' => 'error',
                'last_sync_error' => $response->get_error_message(),
                'auto_sync_reports' => $autoSync,
            ]);

            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        $this->settings->update([
            'dashboard_url' => $dashboardUrl,
            'connection_token' => '',
            'site_id' => sanitize_text_field((string) ($response['site_id'] ?? '')),
            'site_token' => sanitize_text_field((string) ($response['site_token'] ?? '')),
            'connection_status' => 'connected',
            'last_sync_error' => '',
            'auto_sync_reports' => $autoSync,
        ]);

        if ($autoSync === '1') {
            $syncResponse = $this->client->sendReport($this->settings->all(), $this->reportBuilder->build());

            if (is_wp_error($syncResponse)) {
                $this->settings->update([
                    'last_sync_error' => $syncResponse->get_error_message(),
                ]);
            } else {
                $this->settings->update([
                    'last_sync_at' => current_time('mysql'),
                    'last_sync_error' => '',
                ]);
            }
        }

        wp_send_json_success([
            'message' => __('The plugin is now connected to FirePhage.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleDisconnectDashboard(): void
    {
        $this->assertAjaxPermissions();
        $this->settings->disconnect();

        wp_send_json_success([
            'message' => __('The plugin has been disconnected from FirePhage.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    /**
     * @return array<string, string>
     */
    private function tabs(): array
    {
        return [
            'overview' => __('Overview', 'firephage-security'),
            'health' => __('Health Checks', 'firephage-security'),
            'scanner' => __('Malware Scan', 'firephage-security'),
            'updates' => __('Updates', 'firephage-security'),
            'connect' => __('FirePhage Connect', 'firephage-security'),
        ];
    }

    private function renderStatCard(string $label, string $value, string $description, string $extraClass = ''): string
    {
        return sprintf(
            '<div class="firephage-stat-card %4$s"><span class="firephage-stat-label">%1$s</span><strong class="firephage-stat-value">%2$s</strong><span class="firephage-stat-description">%3$s</span></div>',
            esc_html($label),
            esc_html($value),
            esc_html($description),
            esc_attr($extraClass)
        );
    }

    /**
     * @param array<string, string> $check
     */
    private function renderCheckCard(array $check): string
    {
        return sprintf(
            '<div class="firephage-card"><div class="firephage-card-head"><h3>%1$s</h3><span class="firephage-badge firephage-badge--%2$s">%3$s</span></div><p>%4$s</p></div>',
            esc_html((string) $check['label']),
            esc_attr((string) $check['status']),
            esc_html(ucfirst((string) $check['status'])),
            esc_html((string) $check['message'])
        );
    }

    /**
     * @param array<int, string> $items
     */
    private function renderChecksumList(string $title, array $items): string
    {
        if ($items === []) {
            return '';
        }

        $html = '<div class="firephage-checksum-list"><h4>' . esc_html($title) . '</h4><ul class="firephage-list">';

        foreach ($items as $item) {
            $html .= '<li><code>' . esc_html($item) . '</code></li>';
        }

        return $html . '</ul></div>';
    }

    /**
     * @param array<int, array<string, mixed>> $findings
     */
    private function renderFindings(array $findings): string
    {
        if ($findings === []) {
            return '<p class="firephage-empty">' . esc_html__('No integrity mismatches or suspicious files were flagged by the latest scan.', 'firephage-security') . '</p>';
        }

        $pageSizeOptions = $this->pageSizeOptions(count($findings));
        $html = '<div class="firephage-findings-toolbar">';
        $html .= '<label class="firephage-findings-rows"><span>' . esc_html__('Rows', 'firephage-security') . '</span><select class="firephage-findings-page-size">';
        foreach ($pageSizeOptions as $option) {
            $html .= '<option value="' . esc_attr((string) $option) . '"' . selected($option, 25, false) . '>' . esc_html((string) $option) . '</option>';
        }
        $html .= '</select></label>';
        $html .= '<div class="firephage-findings-actions">';
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-selected-suspicious-files" disabled>' . esc_html__('Delete Selected Files', 'firephage-security') . '</button>';
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-suspicious-files">' . esc_html__('Delete All Suspicious Files', 'firephage-security') . '</button>';
        $html .= '<button type="button" class="button button-secondary firephage-clear-findings">' . esc_html__('Clear Findings', 'firephage-security') . '</button>';
        $html .= '</div>';
        $html .= '</div>';
        $html .= '<div class="firephage-finding-table-wrap">';
        $html .= '<table class="firephage-finding-table">';
        $html .= '<thead><tr>';
        $html .= '<th scope="col">' . esc_html__('Select', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('File Path', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Status', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Details', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Action', 'firephage-security') . '</th>';
        $html .= '</tr></thead><tbody>';

        foreach (array_reverse($findings) as $finding) {
            $file = isset($finding['file']) ? (string) $finding['file'] : '';
            $type = isset($finding['type']) ? (string) $finding['type'] : 'review';
            $confidence = isset($finding['confidence']) ? (string) $finding['confidence'] : 'low';
            $source = isset($finding['source']) ? (string) $finding['source'] : '';
            $reasons = isset($finding['reasons']) && is_array($finding['reasons']) ? $finding['reasons'] : [];
            $status = $type === 'malware' ? __('Suspicious', 'firephage-security') : __('Integrity mismatch', 'firephage-security');
            $detailParts = [];

            if ($source !== '') {
                $detailParts[] = sprintf(__('Source: %s', 'firephage-security'), ucwords(str_replace('_', ' ', $source)));
            }

            if ($confidence !== '') {
                $detailParts[] = sprintf(__('Confidence: %s', 'firephage-security'), ucfirst($confidence));
            }

            if ($reasons !== []) {
                $detailParts[] = implode(', ', array_map('strval', $reasons));
            }

            $html .= '<tr>';
            $html .= '<td>';
            if ($type === 'malware') {
                $html .= '<label class="screen-reader-text" for="firephage-select-' . esc_attr(md5($file)) . '">' . esc_html__('Select suspicious file', 'firephage-security') . '</label>';
                $html .= '<input type="checkbox" id="firephage-select-' . esc_attr(md5($file)) . '" class="firephage-findings-select" value="' . esc_attr($file) . '" />';
            } else {
                $html .= '<span class="firephage-empty">' . esc_html__('No', 'firephage-security') . '</span>';
            }
            $html .= '</td>';
            $html .= '<td><code>' . esc_html($file) . '</code></td>';
            $html .= '<td><span class="firephage-badge firephage-badge--' . esc_attr($type === 'malware' ? 'critical' : 'warning') . '">' . esc_html($status) . '</span></td>';
            $html .= '<td>' . esc_html(implode(' | ', $detailParts)) . '</td>';
            $html .= '<td>';
            if ($type === 'malware') {
                $html .= '<button type="button" class="button firephage-button-danger firephage-delete-finding" data-file="' . esc_attr($file) . '">' . esc_html__('Delete File', 'firephage-security') . '</button>';
            } else {
                $html .= '<span class="firephage-empty">' . esc_html__('Protected', 'firephage-security') . '</span>';
            }
            $html .= '</td>';
            $html .= '</tr>';
        }

        $html .= '</tbody></table></div>';
        $html .= '<div class="firephage-findings-pagination" aria-live="polite"></div>';

        return $html;
    }

    /**
     * @return array<int, int>
     */
    private function pageSizeOptions(int $findingsCount): array
    {
        $options = [];

        foreach ([10, 25, 50, 100] as $option) {
            if ($findingsCount >= $option || $options === []) {
                $options[] = $option;
            }
        }

        return $options;
    }

    private function renderUpdateCard(string $title, int $count, string $description): string
    {
        return sprintf(
            '<div class="firephage-card"><div class="firephage-card-head"><h3>%1$s</h3><span class="firephage-badge firephage-badge--%2$s">%3$s</span></div><p>%4$s</p></div>',
            esc_html($title),
            esc_attr($count > 0 ? 'warning' : 'good'),
            esc_html((string) $count),
            esc_html($description)
        );
    }

    /**
     * @param array<string, mixed> $scan
     */
    private function scanProgress(array $scan): int
    {
        $discovered = (int) ($scan['discovered_files'] ?? 0);
        $scanned = (int) ($scan['scanned_files'] ?? 0);

        if ($discovered < 1) {
            return $scan['status'] === 'completed' ? 100 : 5;
        }

        return max(5, min(100, (int) floor(($scanned / $discovered) * 100)));
    }

    /**
     * @param array<string, mixed> $scan
     */
    private function scanProgressLabel(array $scan): string
    {
        $status = (string) ($scan['status'] ?? 'idle');

        if ($status === 'idle') {
            return __('The scanner is idle. Start a background scan to verify repository integrity and review untrusted code paths.', 'firephage-security');
        }

        if ($status === 'discovering') {
            return sprintf(__('Discovering candidate files: %d found so far.', 'firephage-security'), (int) ($scan['discovered_files'] ?? 0));
        }

        if ($status === 'completed') {
            return sprintf(
                __('Scan completed. %1$d files scanned, %2$d trusted, %3$d clean custom files, %4$d skipped, %5$d integrity mismatches, %6$d suspicious.', 'firephage-security'),
                (int) ($scan['scanned_files'] ?? 0),
                (int) ($scan['trusted_files'] ?? 0),
                (int) ($scan['clean_files'] ?? 0),
                (int) ($scan['skipped_files'] ?? 0),
                (int) ($scan['integrity_issues'] ?? 0),
                (int) ($scan['suspicious_files'] ?? 0)
            );
        }

        if ($status === 'failed') {
            return sprintf(__('Scan failed: %s', 'firephage-security'), (string) ($scan['last_error'] ?? __('Unknown error', 'firephage-security')));
        }

        return sprintf(
            __('Scanning %1$d of %2$d discovered files. Trusted: %3$d. Clean custom files: %4$d. Skipped: %5$d. Integrity mismatches: %6$d. Suspicious: %7$d. Current file: %8$s', 'firephage-security'),
            (int) ($scan['scanned_files'] ?? 0),
            (int) ($scan['discovered_files'] ?? 0),
            (int) ($scan['trusted_files'] ?? 0),
            (int) ($scan['clean_files'] ?? 0),
            (int) ($scan['skipped_files'] ?? 0),
            (int) ($scan['integrity_issues'] ?? 0),
            (int) ($scan['suspicious_files'] ?? 0),
            (string) ($scan['current_file'] ?? '')
        );
    }

    private function mapStateBadge(string $status): string
    {
        return match ($status) {
            'completed' => 'good',
            'failed' => 'critical',
            'discovering', 'scanning' => 'warning',
            default => 'neutral',
        };
    }

    private function assertAjaxPermissions(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You are not allowed to manage FirePhage Security.', 'firephage-security')], 403);
        }

        check_ajax_referer('firephage_admin', 'nonce');
    }
}
