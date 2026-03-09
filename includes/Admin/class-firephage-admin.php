<?php

namespace FirePhage\Security\Admin;

use FirePhage\Security\FirePhage\Client;
use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Reports\ReportBuilder;
use FirePhage\Security\Scanner\MalwareScanner;
use FirePhage\Security\Security\BruteForceProtection;
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

    private BruteForceProtection $bruteForceProtection;

    public function __construct(
        Settings $settings,
        MalwareScanner $scanner,
        HealthChecker $healthChecker,
        ReportBuilder $reportBuilder,
        Client $client,
        BruteForceProtection $bruteForceProtection
    ) {
        $this->settings = $settings;
        $this->scanner = $scanner;
        $this->healthChecker = $healthChecker;
        $this->reportBuilder = $reportBuilder;
        $this->client = $client;
        $this->bruteForceProtection = $bruteForceProtection;

        add_action('wp_ajax_firephage_start_scan', [$this, 'handleStartScan']);
        add_action('wp_ajax_firephage_stop_scan', [$this, 'handleStopScan']);
        add_action('wp_ajax_firephage_scan_status', [$this, 'handleScanStatus']);
        add_action('wp_ajax_firephage_preview_file', [$this, 'handlePreviewFile']);
        add_action('wp_ajax_firephage_clear_findings', [$this, 'handleClearFindings']);
        add_action('wp_ajax_firephage_delete_suspicious_files', [$this, 'handleDeleteSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_selected_suspicious_files', [$this, 'handleDeleteSelectedSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_suspicious_file', [$this, 'handleDeleteSuspiciousFile']);
        add_action('wp_ajax_firephage_refresh_health', [$this, 'handleRefreshHealth']);
        add_action('wp_ajax_firephage_save_bruteforce_settings', [$this, 'handleSaveBruteForceSettings']);
        add_action('wp_ajax_firephage_clear_bruteforce_lockouts', [$this, 'handleClearBruteForceLockouts']);
        add_action('wp_ajax_firephage_save_scanner_settings', [$this, 'handleSaveScannerSettings']);
        add_action('wp_ajax_firephage_connect_dashboard', [$this, 'handleConnectDashboard']);
        add_action('wp_ajax_firephage_disconnect_dashboard', [$this, 'handleDisconnectDashboard']);
        add_action('wp_ajax_firephage_fetch_firewall_summary', [$this, 'handleFetchFirewallSummary']);
        add_action('wp_ajax_firephage_fetch_performance_summary', [$this, 'handleFetchPerformanceSummary']);
    }

    public function registerMenus(): void
    {
        add_menu_page(
            __('FirePhage Security', 'firephage-security'),
            __('FirePhage Security', 'firephage-security'),
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
                    'startNewScan' => __('Start New Scan', 'firephage-security'),
                    'resumeScan' => __('Resume Scan', 'firephage-security'),
                    'overviewStartScan' => __('Scan My Website For Malware', 'firephage-security'),
                    'overviewStartNewScan' => __('Start New Malware Scan', 'firephage-security'),
                    'overviewResumeScan' => __('Resume Malware Scan', 'firephage-security'),
                    'scanStarting' => __('Starting scan...', 'firephage-security'),
                    'scanResuming' => __('Resuming scan...', 'firephage-security'),
                    'stopScan' => __('Cancel Current Scan', 'firephage-security'),
                    'notConnected' => __('Not connected', 'firephage-security'),
                    'clearFindings' => __('Clear Findings', 'firephage-security'),
                    'deleteSuspiciousFiles' => __('Delete All Suspicious Files', 'firephage-security'),
                    'deleteSelectedFiles' => __('Delete Selected Files', 'firephage-security'),
                    'deleteFile' => __('Delete File', 'firephage-security'),
                    'previewFile' => __('Preview', 'firephage-security'),
                    'confirmDeleteTitle' => __('Delete Suspicious File?', 'firephage-security'),
                    'confirmDeleteAllTitle' => __('Delete All Suspicious Files?', 'firephage-security'),
                    'confirmDeleteSelectedTitle' => __('Delete Selected Suspicious Files?', 'firephage-security'),
                    'confirmDeleteBody' => __('This will permanently delete the selected suspicious file from the server. This action cannot be undone.', 'firephage-security'),
                    'confirmDeleteAllBody' => __('This will permanently delete every file currently flagged as suspicious malware. Protected core files will be skipped. This action cannot be undone.', 'firephage-security'),
                    'confirmDeleteSelectedBody' => __('This will permanently delete the selected suspicious malware files. Protected core files will be skipped. This action cannot be undone.', 'firephage-security'),
                    'confirmAction' => __('Delete', 'firephage-security'),
                    'cancelAction' => __('Cancel', 'firephage-security'),
                    'connectRequired' => __('Connect the plugin to FirePhage to load live Pro data.', 'firephage-security'),
                    'loadingProData' => __('Loading FirePhage data...', 'firephage-security'),
                    'proInactive' => __('A connected FirePhage site was found, but this site does not currently have an active Pro plan.', 'firephage-security'),
                    'saveProtectionSettings' => __('Save Protection Settings', 'firephage-security'),
                    'savingProtectionSettings' => __('Saving settings...', 'firephage-security'),
                    'saveScannerSettings' => __('Save Scanner Settings', 'firephage-security'),
                    'savingScannerSettings' => __('Saving scanner settings...', 'firephage-security'),
                    'clearActiveLockouts' => __('Clear Active Lockouts', 'firephage-security'),
                    'confirmClearLockoutsTitle' => __('Clear Active Lockouts?', 'firephage-security'),
                    'confirmClearLockoutsBody' => __('This will immediately remove all active local lockouts and attempt counters for the free brute-force protection layer.', 'firephage-security'),
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
        $bruteForce = $this->bruteForceProtection->getSummary();

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
        foreach ($this->tabs() as $tabId => $tab) {
            echo $this->renderTabButton($tabId, $tab);
        }
        echo '</div>';

        echo '<div id="firephage-admin-app" data-scan-status="' . esc_attr(wp_json_encode($scan)) . '">';
        echo '<section class="firephage-tab-panel" data-panel="overview">';
        echo '<div class="firephage-panel-header">';
        echo '<div><h2>' . esc_html__('Overview', 'firephage-security') . '</h2><p>' . esc_html__('A quick view of local health, malware scan state, update exposure, and FirePhage sync status.', 'firephage-security') . '</p></div>';
        echo '<button type="button" class="button button-secondary firephage-refresh-health">' . esc_html__('Refresh Checks', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Health Snapshot', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr(($health['summary']['bad'] ?? 0) > 0 ? 'warning' : 'good') . '">' . esc_html(($health['summary']['bad'] ?? 0) > 0 ? __('Attention', 'firephage-security') : __('Healthy', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html(sprintf(__('%1$d checks passing, %2$d need review.', 'firephage-security'), (int) ($health['summary']['good'] ?? 0), (int) ($health['summary']['bad'] ?? 0))) . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Malware Scanner', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-overview-scan-status-badge">' . esc_html(ucfirst((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p id="firephage-overview-scan-summary">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-primary firephage-overview-start-scan">' . esc_html($scan['status'] === 'stopped' ? __('Resume Malware Scan', 'firephage-security') : __('Scan My Website For Malware', 'firephage-security')) . '</button>';
        echo '<button type="button" class="button button-secondary firephage-overview-new-scan" style="' . esc_attr($scan['status'] === 'stopped' ? '' : 'display:none;') . '">' . esc_html__('Start New Malware Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-overview-view-results" style="' . esc_attr(($scan['status'] === 'discovering' || $scan['status'] === 'scanning') ? '' : 'display:none;') . '">' . esc_html__('View Results', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Updates Status', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr((($updates['core_updates'] ?? 0) + ($updates['plugin_updates'] ?? 0) + ($updates['theme_updates'] ?? 0)) > 0 ? 'warning' : 'good') . '">' . esc_html((($updates['core_updates'] ?? 0) + ($updates['plugin_updates'] ?? 0) + ($updates['theme_updates'] ?? 0)) > 0 ? __('Updates Pending', 'firephage-security') : __('Current', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html(sprintf(__('%1$d core, %2$d plugin, and %3$d theme updates are waiting. %4$d inactive plugins should be reviewed.', 'firephage-security'), (int) ($updates['core_updates'] ?? 0), (int) ($updates['plugin_updates'] ?? 0), (int) ($updates['theme_updates'] ?? 0), (int) ($updates['inactive_plugins'] ?? 0))) . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Brute Force Protection', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr((string) ($bruteForce['status'] ?? 'neutral')) . '" id="firephage-bruteforce-overview-badge">' . esc_html(($bruteForce['enabled'] ?? false) ? (($bruteForce['active_lockouts_count'] ?? 0) > 0 ? __('Active Lockouts', 'firephage-security') : __('Enabled', 'firephage-security')) : __('Disabled', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p id="firephage-bruteforce-overview-summary">' . esc_html((string) ($bruteForce['summary'] ?? '')) . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Latest Sync', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr(($settings['connection_status'] ?? 'disconnected') === 'connected' ? 'good' : 'neutral') . '">' . esc_html(ucfirst((string) ($settings['connection_status'] ?? 'disconnected'))) . '</span>';
        echo '</div>';
        echo '<p><strong>' . esc_html__('Last report sync:', 'firephage-security') . '</strong> ' . esc_html($settings['last_sync_at'] !== '' ? $settings['last_sync_at'] : __('Not sent yet', 'firephage-security')) . '</p>';
        echo '<p><strong>' . esc_html__('Last sync error:', 'firephage-security') . '</strong> ' . esc_html($settings['last_sync_error'] !== '' ? $settings['last_sync_error'] : __('None', 'firephage-security')) . '</p>';
        echo '</div>';
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
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-primary firephage-start-scan">' . esc_html($scan['status'] === 'stopped' ? __('Resume Scan', 'firephage-security') : __('Start Background Scan', 'firephage-security')) . '</button>';
        echo '<button type="button" class="button button-secondary firephage-start-new-scan" style="' . esc_attr($scan['status'] === 'stopped' ? '' : 'display:none;') . '">' . esc_html__('Start New Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-stop-scan" ' . (($scan['status'] === 'discovering' || $scan['status'] === 'scanning') ? '' : 'style="display:none;"') . '>' . esc_html__('Cancel Current Scan', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Scanner Settings', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Local', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<form id="firephage-scanner-settings-form">';
        echo '<label class="firephage-toggle"><input type="checkbox" name="malware_auto_scans_enabled" value="1" ' . checked($settings['malware_auto_scans_enabled'], '1', false) . ' /><span>' . esc_html__('Enable automatic malware scans', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Scan frequency', 'firephage-security') . '</span><select name="malware_auto_scan_interval">';
        echo '<option value="daily"' . selected($settings['malware_auto_scan_interval'], 'daily', false) . '>' . esc_html__('Once per day', 'firephage-security') . '</option>';
        echo '<option value="twice_daily"' . selected($settings['malware_auto_scan_interval'], 'twice_daily', false) . '>' . esc_html__('Twice per day', 'firephage-security') . '</option>';
        echo '<option value="four_times_daily"' . selected($settings['malware_auto_scan_interval'], 'four_times_daily', false) . '>' . esc_html__('Four times per day', 'firephage-security') . '</option>';
        echo '</select></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Excluded paths or filenames', 'firephage-security') . '</span><textarea name="malware_scan_exclusions" rows="5" placeholder="/wp-content/cache/*&#10;/wp-content/backups/*&#10;*.log">' . esc_textarea($settings['malware_scan_exclusions']) . '</textarea></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary firephage-save-scanner-settings">' . esc_html__('Save Scanner Settings', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '<p class="firephage-note">' . esc_html__('Checksum lookups may use FirePhage\'s public checksum cache and fall back to WordPress.org. Those requests send only package type, slug, and version. FirePhage dashboard connection remains separate and optional.', 'firephage-security') . '</p>';
        echo '<ul class="firephage-list">';
        echo '<li>' . esc_html__('Verifies WordPress core, plugin, and theme files against official package checksums where available', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Seeds and reuses a local clean-file baseline for custom code that is not covered by repository checksums', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Supports wildcard exclusions such as /wp-content/cache/* or *.log for paths you never want scanned', 'firephage-security') . '</li>';
        echo '</ul>';
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

        echo '<section class="firephage-tab-panel" data-panel="bruteforce">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Brute Force Protection', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr((string) ($bruteForce['status'] ?? 'neutral')) . '" id="firephage-bruteforce-status-badge">' . esc_html(($bruteForce['enabled'] ?? false) ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p id="firephage-bruteforce-summary-text">' . esc_html((string) ($bruteForce['summary'] ?? '')) . '</p>';
        echo '<form id="firephage-bruteforce-form">';
        echo '<label class="firephage-toggle"><input type="checkbox" name="bruteforce_enabled" value="1" ' . checked($settings['bruteforce_enabled'], '1', false) . ' /><span>' . esc_html__('Enable local login protection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-grid firephage-grid--3 firephage-grid--compact">';
        echo '<label class="firephage-field"><span>' . esc_html__('Failed attempts', 'firephage-security') . '</span><input type="number" min="3" max="20" step="1" name="bruteforce_threshold" value="' . esc_attr($settings['bruteforce_threshold']) . '" /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Detection window (minutes)', 'firephage-security') . '</span><input type="number" min="5" max="120" step="1" name="bruteforce_window_minutes" value="' . esc_attr($settings['bruteforce_window_minutes']) . '" /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Lockout duration (minutes)', 'firephage-security') . '</span><input type="number" min="5" max="1440" step="1" name="bruteforce_lockout_minutes" value="' . esc_attr($settings['bruteforce_lockout_minutes']) . '" /></label>';
        echo '</div>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="bruteforce_protect_xmlrpc" value="1" ' . checked($settings['bruteforce_protect_xmlrpc'], '1', false) . ' /><span>' . esc_html__('Apply the same protection rules to XML-RPC authentication', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary firephage-save-bruteforce">' . esc_html__('Save Protection Settings', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-clear-bruteforce-lockouts">' . esc_html__('Clear Active Lockouts', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '<p class="firephage-note">' . esc_html__('This is a lightweight local protection layer for the free plugin. Once FirePhage Pro firewall controls are connected, that edge layer should become the primary brute-force defense and this local layer can stay conservative.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Protection Snapshot', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Local', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid" id="firephage-bruteforce-metrics">';
        echo $this->renderLockedMetricCard(__('Threshold', 'firephage-security'), 'firephage-bruteforce-threshold');
        echo $this->renderLockedMetricCard(__('Window', 'firephage-security'), 'firephage-bruteforce-window');
        echo $this->renderLockedMetricCard(__('Active Lockouts', 'firephage-security'), 'firephage-bruteforce-active-count');
        echo '</div>';
        echo '<p class="firephage-note" id="firephage-bruteforce-xmlrpc-note">' . esc_html(($bruteForce['protect_xmlrpc'] ?? false) ? __('XML-RPC authentication is currently covered by the same rate-limit rules.', 'firephage-security') : __('XML-RPC authentication is currently excluded from local brute-force protection.', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2 firephage-section-spaced">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Active Lockouts', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--warning" id="firephage-bruteforce-active-lockouts-badge">' . esc_html(sprintf(__('%d active', 'firephage-security'), (int) ($bruteForce['active_lockouts_count'] ?? 0))) . '</span>';
        echo '</div>';
        echo '<div id="firephage-bruteforce-active-lockouts">' . $this->renderBruteForceRows($bruteForce['active_lockouts'] ?? [], true) . '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Recent Lockout Events', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('History', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div id="firephage-bruteforce-recent-events">' . $this->renderBruteForceRows($bruteForce['recent_events'] ?? [], false) . '</div>';
        echo '</div>';
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

        echo '<section class="firephage-tab-panel" data-panel="firewall">';
        echo '<div class="firephage-pro-shell">';
        echo '<div class="firephage-pro-shell__hero">';
        echo '<div>';
        echo '<p class="firephage-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p>';
        echo '<h2>' . esc_html__('Firewall Control', 'firephage-security') . '</h2>';
        echo '<p>' . esc_html__('Review live protection status, inspect recent firewall activity, and manage paid WAF controls from WordPress once this site is connected to FirePhage.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<span class="firephage-pro-badge">' . esc_html__('Pro', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Firewall Status', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-firewall-status-badge">' . esc_html__('Pro Preview', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p id="firephage-firewall-summary-text">' . esc_html__('Surface protection mode, current zone health, recent attack counts, and shield status here after dashboard wiring is ready.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note" id="firephage-firewall-connection-note">' . esc_html__('Connect this site to FirePhage to load live firewall status and activity into this tab.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-metric-grid">';
        echo $this->renderLockedMetricCard(__('Requests Blocked', 'firephage-security'), 'firephage-firewall-requests-blocked');
        echo $this->renderLockedMetricCard(__('Challenge Rate', 'firephage-security'), 'firephage-firewall-challenge-rate');
        echo $this->renderLockedMetricCard(__('Bot Pressure', 'firephage-security'), 'firephage-firewall-bot-pressure');
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Recent Firewall Activity', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head"><span>' . esc_html__('Time', 'firephage-security') . '</span><span>' . esc_html__('Action', 'firephage-security') . '</span><span>' . esc_html__('Path', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-firewall-activity-body">';
        echo '<div class="firephage-pro-table__row"><span>--</span><span>' . esc_html__('Blocked', 'firephage-security') . '</span><span>/wp-login.php</span></div>';
        echo '<div class="firephage-pro-table__row"><span>--</span><span>' . esc_html__('Challenge', 'firephage-security') . '</span><span>/xmlrpc.php</span></div>';
        echo '<div class="firephage-pro-table__row"><span>--</span><span>' . esc_html__('Allowed', 'firephage-security') . '</span><span>/checkout</span></div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2 firephage-section-spaced">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Protected Controls', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--warning">' . esc_html__('Upgrade Required', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-fieldset">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Protection mode', 'firephage-security') . '</span><select id="firephage-firewall-protection-mode" disabled><option>' . esc_html__('Adaptive WAF', 'firephage-security') . '</option></select></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Trusted IP list', 'firephage-security') . '</span><input type="text" id="firephage-firewall-trusted-ips" value="203.0.113.10" disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Country blocks', 'firephage-security') . '</span><input type="text" id="firephage-firewall-country-blocks" value="RU, CN" disabled /></label>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-upgrade" id="firephage-firewall-upgrade-card">';
        echo '<h3>' . esc_html__('Unlock Firewall Management', 'firephage-security') . '</h3>';
        echo '<p>' . esc_html__('Connect this site to FirePhage Pro to review firewall logs, manage protection modes, and jump into the full dashboard without leaving WordPress.', 'firephage-security') . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<a class="button button-primary" href="' . esc_url($settings['dashboard_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Purchase Pro Plan', 'firephage-security') . '</a>';
        echo '<button type="button" class="button button-secondary" data-tab-target="connect">' . esc_html__('Connect to FirePhage', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="performance">';
        echo '<div class="firephage-pro-shell">';
        echo '<div class="firephage-pro-shell__hero">';
        echo '<div>';
        echo '<p class="firephage-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p>';
        echo '<h2>' . esc_html__('Performance', 'firephage-security') . '</h2>';
        echo '<p>' . esc_html__('Put CDN and cache controls in one place so paid users can manage acceleration, purge flows, and edge behavior directly from the plugin.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<span class="firephage-pro-badge">' . esc_html__('Pro', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('CDN', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-performance-status-badge">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p id="firephage-performance-summary-text">' . esc_html__('This area can show edge status, cached asset ratio, active hostname routing, and quick links to purge or inspect delivery behavior.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note" id="firephage-performance-connection-note">' . esc_html__('Connect this site to FirePhage to load live CDN and cache data into this tab.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-fieldset">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Zone hostname', 'firephage-security') . '</span><input type="text" id="firephage-performance-hostname" value="cdn.example.com" disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Smart image optimization', 'firephage-security') . '</span><input type="checkbox" id="firephage-performance-image-optimization" checked disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Edge compression', 'firephage-security') . '</span><input type="checkbox" id="firephage-performance-edge-compression" checked disabled /></label>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Cache', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Use this panel for purge actions, bypass rules, cache TTL presets, and page-specific exclusions once the FirePhage API is wired.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head"><span>' . esc_html__('Rule', 'firephage-security') . '</span><span>' . esc_html__('Behavior', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-performance-cache-rules">';
        echo '<div class="firephage-pro-table__row"><span>/cart</span><span>' . esc_html__('Bypass cache', 'firephage-security') . '</span><span>' . esc_html__('Enabled', 'firephage-security') . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>/checkout</span><span>' . esc_html__('Bypass cache', 'firephage-security') . '</span><span>' . esc_html__('Enabled', 'firephage-security') . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>/blog/*</span><span>' . esc_html__('TTL 1 hour', 'firephage-security') . '</span><span>' . esc_html__('Enabled', 'firephage-security') . '</span></div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-upgrade firephage-section-spaced" id="firephage-performance-upgrade-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Unlock FirePhage Performance', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--warning">' . esc_html__('Pro Required', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Upgrade to manage CDN delivery and cache behavior from WordPress, then use the plugin as a lightweight control surface for your connected FirePhage site.', 'firephage-security') . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<a class="button button-primary" href="' . esc_url($settings['dashboard_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Purchase Pro Plan', 'firephage-security') . '</a>';
        echo '<button type="button" class="button button-secondary" data-tab-target="connect">' . esc_html__('Connect to FirePhage', 'firephage-security') . '</button>';
        echo '</div>';
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
        echo '<div class="firephage-modal" id="firephage-preview-modal" hidden>';
        echo '<div class="firephage-modal-backdrop" data-preview-close="1"></div>';
        echo '<div class="firephage-modal-dialog firephage-modal-dialog--wide" role="dialog" aria-modal="true" aria-labelledby="firephage-preview-modal-title">';
        echo '<div class="firephage-modal-head">';
        echo '<h3 id="firephage-preview-modal-title">' . esc_html__('File Preview', 'firephage-security') . '</h3>';
        echo '<button type="button" class="button-link firephage-modal-close" data-preview-close="1" aria-label="' . esc_attr__('Close preview dialog', 'firephage-security') . '">&times;</button>';
        echo '</div>';
        echo '<p class="firephage-note" id="firephage-preview-modal-meta"></p>';
        echo '<pre class="firephage-preview-content" id="firephage-preview-modal-content"></pre>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary" data-preview-close="1">' . esc_html__('Close', 'firephage-security') . '</button>';
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

        $forceNew = isset($_POST['force_new']) && sanitize_text_field((string) $_POST['force_new']) === '1';
        $result = $this->scanner->startScan($forceNew);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()], 400);
        }

        wp_send_json_success(['state' => $result]);
    }

    public function handleStopScan(): void
    {
        $this->assertAjaxPermissions();

        $result = $this->scanner->stopScan();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()], 400);
        }

        wp_send_json_success([
            'message' => __('The malware scan has been cancelled. You can resume it later.', 'firephage-security'),
            'state' => $result,
        ]);
    }

    public function handleScanStatus(): void
    {
        $this->assertAjaxPermissions();
        wp_send_json_success(['state' => $this->scanner->getState()]);
    }

    public function handlePreviewFile(): void
    {
        $this->assertAjaxPermissions();
        $file = sanitize_text_field((string) ($_POST['file'] ?? ''));
        $result = $this->scanner->previewFile($file);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()], 400);
        }

        wp_send_json_success($result);
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

    public function handleSaveBruteForceSettings(): void
    {
        $this->assertAjaxPermissions();
        $summary = $this->bruteForceProtection->saveSettings(isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : []);

        wp_send_json_success([
            'message' => __('Brute-force protection settings were saved.', 'firephage-security'),
            'summary' => $summary,
        ]);
    }

    public function handleClearBruteForceLockouts(): void
    {
        $this->assertAjaxPermissions();
        $summary = $this->bruteForceProtection->clearActiveLockouts();

        wp_send_json_success([
            'message' => __('Active local lockouts were cleared.', 'firephage-security'),
            'summary' => $summary,
        ]);
    }

    public function handleSaveScannerSettings(): void
    {
        $this->assertAjaxPermissions();
        $current = $this->settings->all();
        $settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];

        $this->settings->update([
            'malware_auto_scans_enabled' => ! empty($settings['malware_auto_scans_enabled']) ? '1' : '0',
            'malware_auto_scan_interval' => in_array((string) ($settings['malware_auto_scan_interval'] ?? $current['malware_auto_scan_interval']), ['daily', 'twice_daily', 'four_times_daily'], true)
                ? (string) ($settings['malware_auto_scan_interval'] ?? $current['malware_auto_scan_interval'])
                : 'twice_daily',
            'malware_scan_exclusions' => sanitize_textarea_field((string) ($settings['malware_scan_exclusions'] ?? $current['malware_scan_exclusions'])),
        ]);
        do_action('firephage_security_settings_changed');

        wp_send_json_success([
            'message' => __('Scanner settings were saved.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
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

    public function handleFetchFirewallSummary(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        if ($settings['site_token'] === '' || $settings['site_id'] === '' || $settings['connection_status'] !== 'connected') {
            wp_send_json_success([
                'connected' => false,
                'message' => __('Connect the plugin to FirePhage to load firewall data.', 'firephage-security'),
            ]);
        }

        $response = $this->client->fetchFirewallSummary($settings);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        wp_send_json_success($response);
    }

    public function handleFetchPerformanceSummary(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        if ($settings['site_token'] === '' || $settings['site_id'] === '' || $settings['connection_status'] !== 'connected') {
            wp_send_json_success([
                'connected' => false,
                'message' => __('Connect the plugin to FirePhage to load performance data.', 'firephage-security'),
            ]);
        }

        $response = $this->client->fetchPerformanceSummary($settings);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        wp_send_json_success($response);
    }

    /**
     * @return array<string, string>
     */
    private function tabs(): array
    {
        return [
            'overview' => ['label' => __('Overview', 'firephage-security')],
            'scanner' => ['label' => __('Malware Scan', 'firephage-security')],
            'bruteforce' => ['label' => __('Brute Force Protection', 'firephage-security')],
            'updates' => ['label' => __('Updates', 'firephage-security')],
            'firewall' => ['label' => __('Firewall', 'firephage-security'), 'pro' => true],
            'performance' => ['label' => __('Performance', 'firephage-security'), 'pro' => true],
            'connect' => ['label' => __('FirePhage Connect', 'firephage-security')],
        ];
    }

    /**
     * @param array{label: string, pro?: bool} $tab
     */
    private function renderTabButton(string $tabId, array $tab): string
    {
        $html = '<button type="button" class="firephage-tab-button" data-tab="' . esc_attr($tabId) . '">';
        $html .= '<span>' . esc_html($tab['label']) . '</span>';

        if (! empty($tab['pro'])) {
            $html .= '<span class="firephage-tab-pill">' . esc_html__('Pro', 'firephage-security') . '</span>';
        }

        $html .= '</button>';

        return $html;
    }

    private function renderLockedMetricCard(string $label, string $valueId = ''): string
    {
        $id = $valueId !== '' ? ' id="' . esc_attr($valueId) . '"' : '';

        return '<div class="firephage-pro-metric"><span class="firephage-pro-metric__label">' . esc_html($label) . '</span><strong class="firephage-pro-metric__value"' . $id . '>--</strong></div>';
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
            $html .= '<button type="button" class="button button-secondary firephage-preview-file" data-file="' . esc_attr($file) . '">' . esc_html__('Preview', 'firephage-security') . '</button> ';
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
     * @param array<int, array<string, mixed>> $rows
     */
    private function renderBruteForceRows(array $rows, bool $showRemaining): string
    {
        if ($rows === []) {
            return '<p class="firephage-empty">' . esc_html__('No entries to show right now.', 'firephage-security') . '</p>';
        }

        $html = '<div class="firephage-finding-table-wrap firephage-finding-table-wrap--compact"><table class="firephage-finding-table firephage-finding-table--auto">';
        $html .= '<thead><tr>';
        $html .= '<th scope="col">' . esc_html__('Username', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('IP', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Surface', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Attempts', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Started', 'firephage-security') . '</th>';
        $html .= '<th scope="col">' . esc_html__('Expires', 'firephage-security') . '</th>';
        if ($showRemaining) {
            $html .= '<th scope="col">' . esc_html__('Remaining', 'firephage-security') . '</th>';
        }
        $html .= '</tr></thead><tbody>';

        foreach ($rows as $row) {
            $html .= '<tr>';
            $html .= '<td>' . esc_html((string) ($row['username'] !== '' ? $row['username'] : __('Any username', 'firephage-security'))) . '</td>';
            $html .= '<td><code>' . esc_html((string) ($row['ip'] ?? 'unknown')) . '</code></td>';
            $html .= '<td>' . esc_html(strtoupper((string) ($row['surface'] ?? 'login'))) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['failed_attempts'] ?? 0)) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['started_at'] ?? '')) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['expires_at'] ?? '')) . '</td>';
            if ($showRemaining) {
                $html .= '<td>' . esc_html(sprintf(__('%d min', 'firephage-security'), (int) ($row['remaining'] ?? 0))) . '</td>';
            }
            $html .= '</tr>';
        }

        $html .= '</tbody></table></div>';

        return $html;
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

        if ($status === 'stopped') {
            return sprintf(
                __('Scan cancelled at %1$d of %2$d discovered files. Trusted: %3$d. Clean custom files: %4$d. Skipped: %5$d. Integrity mismatches: %6$d. Suspicious: %7$d. Use Resume Scan to continue from the saved position.', 'firephage-security'),
                (int) ($scan['scanned_files'] ?? 0),
                (int) ($scan['discovered_files'] ?? 0),
                (int) ($scan['trusted_files'] ?? 0),
                (int) ($scan['clean_files'] ?? 0),
                (int) ($scan['skipped_files'] ?? 0),
                (int) ($scan['integrity_issues'] ?? 0),
                (int) ($scan['suspicious_files'] ?? 0)
            );
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
