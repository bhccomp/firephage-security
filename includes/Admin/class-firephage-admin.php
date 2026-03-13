<?php

namespace FirePhage\Security\Admin;

use FirePhage\Security\FirePhage\Client;
use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Notifications;
use FirePhage\Security\Reports\ReportBuilder;
use FirePhage\Security\Scanner\MalwareScanner;
use FirePhage\Security\Security\BruteForceProtection;
use FirePhage\Security\Settings;

if (! defined('ABSPATH')) {
    exit;
}

final class Admin
{
    /**
     * @var Settings
     */
    private $settings;

    /**
     * @var MalwareScanner
     */
    private $scanner;

    /**
     * @var HealthChecker
     */
    private $healthChecker;

    /**
     * @var ReportBuilder
     */
    private $reportBuilder;

    /**
     * @var Client
     */
    private $client;

    /**
     * @var BruteForceProtection
     */
    private $bruteForceProtection;

    /**
     * @var Notifications
     */
    private $notifications;

    public function __construct(
        Settings $settings,
        MalwareScanner $scanner,
        HealthChecker $healthChecker,
        ReportBuilder $reportBuilder,
        Client $client,
        BruteForceProtection $bruteForceProtection,
        Notifications $notifications
    ) {
        $this->settings = $settings;
        $this->scanner = $scanner;
        $this->healthChecker = $healthChecker;
        $this->reportBuilder = $reportBuilder;
        $this->client = $client;
        $this->bruteForceProtection = $bruteForceProtection;
        $this->notifications = $notifications;

        add_action('wp_ajax_firephage_start_scan', [$this, 'handleStartScan']);
        add_action('wp_ajax_firephage_stop_scan', [$this, 'handleStopScan']);
        add_action('wp_ajax_firephage_scan_status', [$this, 'handleScanStatus']);
        add_action('wp_ajax_firephage_preview_file', [$this, 'handlePreviewFile']);
        add_action('wp_ajax_firephage_clear_findings', [$this, 'handleClearFindings']);
        add_action('wp_ajax_firephage_delete_suspicious_files', [$this, 'handleDeleteSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_selected_suspicious_files', [$this, 'handleDeleteSelectedSuspiciousFiles']);
        add_action('wp_ajax_firephage_delete_suspicious_file', [$this, 'handleDeleteSuspiciousFile']);
        add_action('wp_ajax_firephage_refresh_health', [$this, 'handleRefreshHealth']);
        add_action('wp_ajax_firephage_refresh_signatures', [$this, 'handleRefreshSignatures']);
        add_action('wp_ajax_firephage_save_bruteforce_settings', [$this, 'handleSaveBruteForceSettings']);
        add_action('wp_ajax_firephage_clear_bruteforce_lockouts', [$this, 'handleClearBruteForceLockouts']);
        add_action('wp_ajax_firephage_save_scanner_settings', [$this, 'handleSaveScannerSettings']);
        add_action('wp_ajax_firephage_save_notification_settings', [$this, 'handleSaveNotificationSettings']);
        add_action('wp_ajax_firephage_register_free_token', [$this, 'handleRegisterFreeToken']);
        add_action('wp_ajax_firephage_check_free_token_status', [$this, 'handleCheckFreeTokenStatus']);
        add_action('wp_ajax_firephage_verify_free_token', [$this, 'handleVerifyFreeToken']);
        add_action('wp_ajax_firephage_decline_free_token', [$this, 'handleDeclineFreeToken']);
        add_action('wp_ajax_firephage_dismiss_free_token_prompt', [$this, 'handleDismissFreeTokenPrompt']);
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
            $this->menuIcon(),
            58
        );
    }

    public function enqueueAssets(string $hook): void
    {
        if ($hook !== 'toplevel_page_firephage-security') {
            return;
        }

        $settings = $this->settings->all();

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
                    'startScan' => __('Start Deep Scan', 'firephage-security'),
                    'startNewScan' => __('Start New Deep Scan', 'firephage-security'),
                    'resumeScan' => __('Resume Scan', 'firephage-security'),
                    'startQuickScan' => __('Start Quick Scan', 'firephage-security'),
                    'startDeepScan' => __('Start Deep Scan', 'firephage-security'),
                    'startNewDeepScan' => __('Start New Deep Scan', 'firephage-security'),
                    'scanStartingQuick' => __('Starting Quick Scan…', 'firephage-security'),
                    'scanStartingDeep' => __('Starting Deep Scan…', 'firephage-security'),
                    'quickScanTitle' => __('Start Quick Scan?', 'firephage-security'),
                    'quickScanBody' => __('Quick Scan is faster, but it is less effective than Deep Scan because it skips broader malware-signature, malicious-domain, and heuristic analysis. If you suspect malware, Deep Scan is strongly recommended.', 'firephage-security'),
                    'quickScanAction' => __('Start Quick Scan', 'firephage-security'),
                    'overviewStartScan' => __('Scan My Website For Malware', 'firephage-security'),
                    'overviewStartNewScan' => __('Start New Malware Scan', 'firephage-security'),
                    'overviewResumeScan' => __('Resume Malware Scan', 'firephage-security'),
                    'scanStarting' => __('Starting scan...', 'firephage-security'),
                    'scanResuming' => __('Resuming scan...', 'firephage-security'),
                    'stopScan' => __('Cancel Current Scan', 'firephage-security'),
                    'notConnected' => __('Not connected', 'firephage-security'),
                    'clearFindings' => __('Clear Findings', 'firephage-security'),
                    'findingsSearchPlaceholder' => __('Search findings...', 'firephage-security'),
                    'findingsSearchLabel' => __('Search findings', 'firephage-security'),
                    'deleteSuspiciousFiles' => __('Delete All Malicious Files', 'firephage-security'),
                    'deleteSelectedFiles' => __('Delete Selected Files', 'firephage-security'),
                    'deleteFile' => __('Delete File', 'firephage-security'),
                    'previewFile' => __('Preview', 'firephage-security'),
                    'confirmDeleteTitle' => __('Delete Malicious File?', 'firephage-security'),
                    'confirmDeleteAllTitle' => __('Delete All Malicious Files?', 'firephage-security'),
                    'confirmDeleteSelectedTitle' => __('Delete Selected Malicious Files?', 'firephage-security'),
                    'confirmDeleteBody' => __('Deleting a malicious file can affect site functionality, so create a backup first and review the file path before continuing.', 'firephage-security'),
                    'confirmDeleteAllBody' => __('Deleting all malicious files can affect site functionality, so create a backup first and review the files before continuing. Protected core files will still be skipped.', 'firephage-security'),
                    'confirmDeleteSelectedBody' => __('Deleting selected malicious files can affect site functionality, so create a backup first and review the files before continuing. Protected core files will still be skipped.', 'firephage-security'),
                    'confirmAction' => __('Delete', 'firephage-security'),
                    'cancelAction' => __('Cancel', 'firephage-security'),
                    'connectRequired' => __('Connect the plugin to FirePhage to load live Pro data.', 'firephage-security'),
                    'loadingProData' => __('Loading FirePhage data...', 'firephage-security'),
                    'proInactive' => __('A connected FirePhage site was found, but this site does not currently have an active Pro plan.', 'firephage-security'),
                    'saveProtectionSettings' => __('Save Protection Settings', 'firephage-security'),
                    'savingProtectionSettings' => __('Saving settings...', 'firephage-security'),
                    'saveScannerSettings' => __('Save Scanner Settings', 'firephage-security'),
                    'savingScannerSettings' => __('Saving scanner settings...', 'firephage-security'),
                    'saveNotificationSettings' => __('Save Notification Settings', 'firephage-security'),
                    'savingNotificationSettings' => __('Saving notification settings...', 'firephage-security'),
                    'registerFreeToken' => __('Email My Free Token', 'firephage-security'),
                    'registeringFreeToken' => __('Sending token...', 'firephage-security'),
                    'checkFreeTokenStatus' => __('Check Verification Status', 'firephage-security'),
                    'checkingFreeTokenStatus' => __('Checking verification...', 'firephage-security'),
                    'declineFreeToken' => __('No Thanks', 'firephage-security'),
                    'dismissFreeToken' => __('Do not bother me again', 'firephage-security'),
                    'refreshSignatures' => __('Refresh Signatures', 'firephage-security'),
                    'refreshingSignatures' => __('Refreshing signatures...', 'firephage-security'),
                    'clearActiveLockouts' => __('Clear Active Lockouts', 'firephage-security'),
                    'confirmClearLockoutsTitle' => __('Clear Active Lockouts?', 'firephage-security'),
                    'confirmClearLockoutsBody' => __('This will immediately remove all active local lockouts and attempt counters for the free brute-force protection layer.', 'firephage-security'),
                    'deleteModalWarning' => __('This action can affect site functionality. Review the file paths carefully before continuing.', 'firephage-security'),
                    'deleteModalBackup' => __('Create a backup before deleting files.', 'firephage-security'),
                    'deleteModalCountLabel' => __('Files marked as malicious', 'firephage-security'),
                    'deleteModalFileLabel' => __('File', 'firephage-security'),
                    'deleteModalFilesLabel' => __('Files', 'firephage-security'),
                    'refreshHealthDone' => __('Health checks refreshed.', 'firephage-security'),
                    'refreshSignaturesDone' => __('FirePhage signatures refreshed.', 'firephage-security'),
                ],
                'freeToken' => [
                    'status' => (string) ($settings['free_signature_token_status'] ?? 'pending'),
                    'email' => (string) (($settings['free_signature_token_email'] ?? '') !== '' ? $settings['free_signature_token_email'] : get_option('admin_email', '')),
                    'marketingOptIn' => (($settings['free_signature_token_marketing_opt_in'] ?? '0') === '1'),
                    'requiresDecision' => (($settings['free_signature_token_status'] ?? 'pending') === 'pending'),
                    'verificationToken' => isset($_GET['firephage_verify']) ? sanitize_text_field((string) wp_unslash($_GET['firephage_verify'])) : '',
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
        $bruteForce = $this->bruteForceProtection->getSummary();
        $notificationState = $this->notifications->state();
        $securityScore = $this->buildSecurityScore($health, $scan, $bruteForce, $settings);
        $lastScanFreshness = $this->humanizeTimestamp((string) ($scan['finished_at'] ?? ''));
        $lastSyncFreshness = $this->humanizeTimestamp((string) ($settings['last_sync_at'] ?? ''));

        echo '<div class="wrap firephage-admin">';
        echo '<div class="firephage-shell">';
        echo '<div class="firephage-hero">';
        echo '<div>';
        echo '<p class="firephage-eyebrow">' . esc_html__('Local WordPress Security', 'firephage-security') . '</p>';
        echo '<h1>' . esc_html__('FirePhage Security', 'firephage-security') . '</h1>';
        echo '<p class="firephage-hero-copy">' . esc_html__('Secure WordPress with malware scanning, brute-force protection, health checks, update visibility, and an optional FirePhage connection for advanced firewall protection plus CDN and cache services that deliver major performance gains.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-hero-actions">';
        echo '<a class="button button-primary button-hero" href="' . esc_url($settings['dashboard_url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Upgrade with FirePhage', 'firephage-security') . '</a>';
        echo '</div>';
        echo '</div>';

        echo '<div class="firephage-tabs" role="tablist" aria-label="' . esc_attr__('FirePhage sections', 'firephage-security') . '">';
        foreach ($this->tabs() as $tabId => $tab) {
            echo $this->renderTabButton($tabId, $tab);
        }
        echo '</div>';

        echo '<div id="firephage-admin-app" data-scan-status="' . esc_attr(wp_json_encode($scan)) . '">';
        echo '<section class="firephage-tab-panel" data-panel="overview">';
        echo '<div class="firephage-panel-header">';
        echo '<div><p>' . esc_html__('A quick view of local health, malware scan state, update exposure, and FirePhage sync status.', 'firephage-security') . '</p></div>';
        echo '<button type="button" class="button button-secondary firephage-refresh-health">' . esc_html__('Refresh Checks', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-score-card" id="firephage-security-score-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Security Score', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($securityScore['tone']) . '" id="firephage-security-score-badge">' . esc_html($securityScore['label']) . '</span>';
        echo '</div>';
        echo '<div class="firephage-score-value"><strong id="firephage-security-score-value">' . esc_html((string) $securityScore['score']) . '</strong><span>/ 100</span></div>';
        echo '<p id="firephage-security-score-summary">' . esc_html($securityScore['summary']) . '</p>';
        echo '<div class="firephage-score-hints" id="firephage-security-score-hints">';
        foreach ($securityScore['hints'] as $hint) {
            echo '<span class="firephage-score-hint">' . esc_html($hint) . '</span>';
        }
        echo '</div>';
        echo '</div>';
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
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-overview-scan-status-badge">' . esc_html($this->scanStatusLabel((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p id="firephage-overview-scan-summary">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<p class="firephage-meta-line"><strong>' . esc_html__('Last scan:', 'firephage-security') . '</strong> <span id="firephage-overview-last-scan">' . esc_html($lastScanFreshness) . '</span></p>';
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
        echo '<span class="firephage-badge firephage-badge--' . esc_attr(($settings['connection_status'] ?? 'disconnected') === 'connected' ? 'good' : 'neutral') . '">' . esc_html($this->connectionStatusLabel((string) ($settings['connection_status'] ?? 'disconnected'))) . '</span>';
        echo '</div>';
        echo '<p><strong>' . esc_html__('Last report sync:', 'firephage-security') . '</strong> <span id="firephage-last-sync-freshness">' . esc_html($lastSyncFreshness) . '</span></p>';
        echo '<p><strong>' . esc_html__('Last sync error:', 'firephage-security') . '</strong> ' . esc_html($settings['last_sync_error'] !== '' ? $settings['last_sync_error'] : __('None', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-grid" id="firephage-health-checks">';
        foreach ($health['checks'] as $check) {
            echo $this->renderCheckCard($check);
        }
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="scanner">';
        echo '<div class="firephage-grid firephage-grid--scanner">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Malware Scanner', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-scan-status-badge">' . esc_html($this->scanStatusLabel((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Runs in background batches so large sites can finish without locking up the admin screen, using official package checksums and local clean baselines before suspicious-code heuristics.', 'firephage-security') . '</p>';
        echo '<div class="firephage-progress"><div class="firephage-progress-bar" id="firephage-scan-progress-bar" style="width:' . esc_attr((string) $this->scanProgress($scan)) . '%"></div></div>';
        echo '<p id="firephage-scan-progress-label">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<div class="firephage-inline-summary firephage-inline-summary--stacked">';
        echo '<span><strong>' . esc_html__('Last scan:', 'firephage-security') . '</strong> <span id="firephage-scanner-last-scan">' . esc_html($lastScanFreshness) . '</span></span>';
        echo '<span><strong>' . esc_html__('Auto scan:', 'firephage-security') . '</strong> <span id="firephage-scanner-auto-scan">' . esc_html(($settings['malware_auto_scans_enabled'] ?? '0') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span></span>';
        echo '</div>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-primary firephage-start-scan">' . esc_html($scan['status'] === 'stopped' ? __('Resume Scan', 'firephage-security') : __('Start Deep Scan', 'firephage-security')) . '</button>';
        echo '<button type="button" class="button button-secondary firephage-start-quick-scan" ' . (($scan['status'] === 'discovering' || $scan['status'] === 'scanning') ? 'style="display:none;"' : '') . '>' . esc_html__('Start Quick Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-start-new-scan" style="' . esc_attr($scan['status'] === 'stopped' ? '' : 'display:none;') . '">' . esc_html__('Start New Deep Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-stop-scan" ' . (($scan['status'] === 'discovering' || $scan['status'] === 'scanning') ? '' : 'style="display:none;"') . '>' . esc_html__('Cancel Current Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-open-scanner-settings">' . esc_html__('Settings', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<ul class="firephage-list firephage-list-spaced">';
        echo '<li>' . esc_html__('Verifies WordPress core, plugin, and theme files against official package checksums where available', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Seeds and reuses a local clean-file baseline for custom code that is not covered by repository checksums', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Supports wildcard exclusions such as /wp-content/cache/* or *.log for paths you never want scanned', 'firephage-security') . '</li>';
        echo '</ul>';
        echo '<p class="firephage-note">' . esc_html__('Checksum lookups may use FirePhage\'s public checksum cache and fall back to WordPress.org. Those requests send only package type, slug, and version. FirePhage dashboard connection remains separate and optional.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card firephage-findings-card">';
        echo '<h3>' . esc_html__('Latest findings', 'firephage-security') . '</h3>';
        echo '<div id="firephage-scan-findings">' . $this->renderFindings($scan['findings'] ?? []) . '</div>';
        echo '</div>';
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

        echo '<section class="firephage-tab-panel" data-panel="notifications">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Notifications', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr(($settings['notifications_enabled'] ?? '1') === '1' ? 'good' : 'neutral') . '">' . esc_html(($settings['notifications_enabled'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Send branded FirePhage Security emails to your preferred admin inbox, including weekly summaries and immediate alerts for malware findings or unexpected WordPress core edits.', 'firephage-security') . '</p>';
        echo '<form id="firephage-notification-settings-form">';
        echo '<label class="firephage-toggle"><input type="checkbox" name="notifications_enabled" value="1" ' . checked($settings['notifications_enabled'] ?? '1', '1', false) . ' /><span>' . esc_html__('Enable email notifications', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Notification email', 'firephage-security') . '</span><input type="email" name="notification_email" value="' . esc_attr($settings['notification_email'] !== '' ? $settings['notification_email'] : get_option('admin_email', '')) . '" /></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="notifications_weekly_report" value="1" ' . checked($settings['notifications_weekly_report'] ?? '1', '1', false) . ' /><span>' . esc_html__('Send weekly security report', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="notifications_alert_malware" value="1" ' . checked($settings['notifications_alert_malware'] ?? '1', '1', false) . ' /><span>' . esc_html__('Alert when malware is detected', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="notifications_alert_core_edits" value="1" ' . checked($settings['notifications_alert_core_edits'] ?? '1', '1', false) . ' /><span>' . esc_html__('Alert when WordPress core files are edited', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary firephage-save-notification-settings">' . esc_html__('Save Notification Settings', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '<p class="firephage-note">' . esc_html__('Weekly reports summarize malware scans, brute-force lockouts, and outdated core, plugin, or theme versions. Immediate alerts are deduplicated per scan so the same result does not spam the inbox repeatedly.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Notification Snapshot', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Email', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid">';
        echo $this->renderLockedMetricCard(__('Recipient', 'firephage-security'), 'firephage-notification-recipient');
        echo $this->renderLockedMetricCard(__('Weekly Report', 'firephage-security'), 'firephage-notification-weekly');
        echo $this->renderLockedMetricCard(__('Malware Alerts', 'firephage-security'), 'firephage-notification-malware');
        echo '</div>';
        echo '<p class="firephage-note"><strong>' . esc_html__('Last weekly report:', 'firephage-security') . '</strong> <span id="firephage-notification-last-weekly">' . esc_html($notificationState['last_weekly_report_at'] !== '' ? $notificationState['last_weekly_report_at'] : __('Not sent yet', 'firephage-security')) . '</span></p>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head"><span>' . esc_html__('Alert Type', 'firephage-security') . '</span><span>' . esc_html__('Latest Trigger', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-notification-alert-summary">';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Malware', 'firephage-security') . '</span><span>' . esc_html($notificationState['last_malware_alert_scan_id'] !== '' ? $notificationState['last_malware_alert_scan_id'] : __('No alert yet', 'firephage-security')) . '</span><span>' . esc_html(($settings['notifications_alert_malware'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Core edits', 'firephage-security') . '</span><span>' . esc_html($notificationState['last_core_alert_scan_id'] !== '' ? $notificationState['last_core_alert_scan_id'] : __('No alert yet', 'firephage-security')) . '</span><span>' . esc_html(($settings['notifications_alert_core_edits'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span></div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-note firephage-pro-note">';
        echo '<strong>' . esc_html__('FirePhage Pro channels', 'firephage-security') . '</strong> ';
        echo esc_html__('Webhook, Slack, and Phone notifications are part of FirePhage Pro together with WAF, CDN, and Cache controls.', 'firephage-security');
        echo '</div>';
        echo '<div class="firephage-pro-fieldset firephage-pro-fieldset--disabled">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Webhook', 'firephage-security') . ' <span class="firephage-inline-pro-pill">' . esc_html__('Pro', 'firephage-security') . '</span></span><input type="url" value="https://hooks.example.com/firephage" disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Slack', 'firephage-security') . ' <span class="firephage-inline-pro-pill">' . esc_html__('Pro', 'firephage-security') . '</span></span><input type="text" value="' . esc_attr__('#security-alerts', 'firephage-security') . '" disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Phone', 'firephage-security') . ' <span class="firephage-inline-pro-pill">' . esc_html__('Pro', 'firephage-security') . '</span></span><input type="tel" value="+1 555 010 7788" disabled /></label>';
        echo '</div>';
        echo '<div class="firephage-inline-actions firephage-section-spaced">';
        echo '<button type="button" class="button button-secondary" data-tab-target="firewall">' . esc_html__('View Pro Protection', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary" data-tab-target="performance">' . esc_html__('View Pro Performance', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="connect">';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<h2>' . esc_html__('Connect to FirePhage', 'firephage-security') . '</h2>';
        echo '<p>' . esc_html__('Generate a connection token in your FirePhage dashboard, paste it here, and the plugin will exchange it for a site-scoped credential and start syncing local reports automatically.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note">' . esc_html__('This paid connection is only for dashboard sync and alerting. Local health checks and checksum lookups do not require a connected FirePhage account. FirePhage signature updates use a separate free token flow.', 'firephage-security') . '</p>';
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
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Free Signature Token', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->freeTokenStatusTone($settings)) . '" id="firephage-free-token-status-badge">' . esc_html($this->freeTokenStatusLabel($settings)) . '</span>';
        echo '</div>';
        echo '<p id="firephage-free-token-summary">' . esc_html($this->freeTokenSummary($settings)) . '</p>';
        echo '<p class="firephage-note">' . esc_html__('The free token enables fresher FirePhage signature updates for local malware detection. It is separate from the paid dashboard connection and can include an optional promo opt-in checkbox.', 'firephage-security') . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-secondary firephage-open-free-token-modal">' . esc_html__('Manage Free Token', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-check-free-token-status" style="' . esc_attr(($settings['free_signature_token_status'] ?? 'pending') === 'awaiting_verification' ? '' : 'display:none;') . '">' . esc_html__('Check Verification Status', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<p><strong>' . esc_html__('Connected site ID:', 'firephage-security') . '</strong> <span id="firephage-connected-site-id">' . esc_html($settings['site_id'] !== '' ? $settings['site_id'] : __('Not connected', 'firephage-security')) . '</span></p>';
        echo '<p class="firephage-note">' . esc_html__('The dashboard issues a scoped token first. That avoids trusting domain names alone and makes it possible to verify both site ownership and account intent before reports are accepted.', 'firephage-security') . '</p>';
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
        echo '<p class="firephage-note" id="firephage-firewall-connection-note">' . esc_html__('Connect FirePhage to view live firewall analytics, then upgrade if you want to manage WAF controls from WordPress.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-metric-grid">';
        echo $this->renderLockedMetricCard(__('Requests Blocked', 'firephage-security'), 'firephage-firewall-requests-blocked', __('Connect to load live counts', 'firephage-security'));
        echo $this->renderLockedMetricCard(__('Challenge Rate', 'firephage-security'), 'firephage-firewall-challenge-rate', __('Connect to load live challenge data', 'firephage-security'));
        echo $this->renderLockedMetricCard(__('Bot Pressure', 'firephage-security'), 'firephage-firewall-bot-pressure', __('Upgrade required for live bot analytics', 'firephage-security'));
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
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Waiting for connection', 'firephage-security') . '</span><span>' . esc_html__('Connect to view live firewall analytics', 'firephage-security') . '</span><span>/wp-login.php</span></div>';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Upgrade required', 'firephage-security') . '</span><span>' . esc_html__('Manage WAF controls from Pro', 'firephage-security') . '</span><span>/xmlrpc.php</span></div>';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('After connection', 'firephage-security') . '</span><span>' . esc_html__('Review recent firewall decisions here', 'firephage-security') . '</span><span>/checkout</span></div>';
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
        echo '<p class="firephage-note" id="firephage-performance-connection-note">' . esc_html__('Connect FirePhage to load performance data, then upgrade if you want to manage CDN and cache settings from WordPress.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-fieldset">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Zone hostname', 'firephage-security') . '</span><input type="text" id="firephage-performance-hostname" value="' . esc_attr__('Connect to load edge hostname', 'firephage-security') . '" disabled /></label>';
        echo '<label class="firephage-pro-field firephage-toggle"><input type="checkbox" id="firephage-performance-image-optimization" checked disabled /><span>' . esc_html__('Smart image optimization', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-pro-field firephage-toggle"><input type="checkbox" id="firephage-performance-edge-compression" checked disabled /><span>' . esc_html__('Edge compression', 'firephage-security') . '</span></label>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Cache', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Use this panel for purge actions, bypass rules, cache TTL presets, and page-specific exclusions once this site is connected to FirePhage Pro.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head"><span>' . esc_html__('Rule', 'firephage-security') . '</span><span>' . esc_html__('Behavior', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-performance-cache-rules">';
        echo '<div class="firephage-pro-table__row"><span>/cart</span><span>' . esc_html__('Bypass cache', 'firephage-security') . '</span><span>' . esc_html__('Upgrade required to manage', 'firephage-security') . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>/checkout</span><span>' . esc_html__('Bypass cache', 'firephage-security') . '</span><span>' . esc_html__('Connect to load live rules', 'firephage-security') . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>/blog/*</span><span>' . esc_html__('TTL 1 hour', 'firephage-security') . '</span><span>' . esc_html__('Pro cache controls only', 'firephage-security') . '</span></div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-estimate-card firephage-section-spaced">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Estimated Speed Improvement', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--warning">' . esc_html__('Estimate', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Estimated improvement: 20-40% faster cached delivery for anonymous traffic once FirePhage CDN and cache are enabled.', 'firephage-security') . '</p>';
        echo '<ul class="firephage-list">';
        echo '<li>' . esc_html__('Better cache hit rates for repeat page views', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Lower origin load during traffic spikes', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Faster static asset delivery from the edge', 'firephage-security') . '</li>';
        echo '</ul>';
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
        echo '<div id="firephage-confirm-modal-body"></div>';
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
        echo '<div class="firephage-modal" id="firephage-scanner-settings-modal" hidden>';
        echo '<div class="firephage-modal-backdrop" data-scanner-settings-close="1"></div>';
        echo '<div class="firephage-modal-dialog firephage-modal-dialog--wide" role="dialog" aria-modal="true" aria-labelledby="firephage-scanner-settings-title">';
        echo '<div class="firephage-modal-head">';
        echo '<h3 id="firephage-scanner-settings-title">' . esc_html__('Scanner Settings', 'firephage-security') . '</h3>';
        echo '<button type="button" class="button-link firephage-modal-close" data-scanner-settings-close="1" aria-label="' . esc_attr__('Close scanner settings', 'firephage-security') . '">&times;</button>';
        echo '</div>';
        echo '<form id="firephage-scanner-settings-form">';
        echo '<label class="firephage-toggle"><input type="checkbox" name="malware_auto_scans_enabled" value="1" ' . checked($settings['malware_auto_scans_enabled'], '1', false) . ' /><span>' . esc_html__('Enable automatic malware scans', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="use_firephage_signature_feed" value="1" ' . checked($settings['use_firephage_signature_feed'] ?? '1', '1', false) . ' /><span>' . esc_html__('Use FirePhage signature updates for local malware detection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-summary">';
        echo '<span class="firephage-inline-summary__label">' . esc_html__('Token status', 'firephage-security') . '</span>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->freeTokenStatusTone($settings)) . '" id="firephage-free-token-settings-badge">' . esc_html($this->freeTokenStatusLabel($settings)) . '</span>';
        echo '</div>';
        echo '<p class="firephage-note" id="firephage-free-token-settings-summary">' . esc_html($this->freeTokenSummary($settings)) . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-secondary firephage-open-free-token-modal">' . esc_html__('Get or Manage Free Token', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-check-free-token-status" style="' . esc_attr(($settings['free_signature_token_status'] ?? 'pending') === 'awaiting_verification' ? '' : 'display:none;') . '">' . esc_html__('Check Verification Status', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-refresh-signatures">' . esc_html__('Refresh Signatures', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<label class="firephage-field"><span>' . esc_html__('Scan frequency', 'firephage-security') . '</span><select name="malware_auto_scan_interval">';
        echo '<option value="daily"' . selected($settings['malware_auto_scan_interval'], 'daily', false) . '>' . esc_html__('Once per day', 'firephage-security') . '</option>';
        echo '<option value="twice_daily"' . selected($settings['malware_auto_scan_interval'], 'twice_daily', false) . '>' . esc_html__('Twice per day', 'firephage-security') . '</option>';
        echo '<option value="four_times_daily"' . selected($settings['malware_auto_scan_interval'], 'four_times_daily', false) . '>' . esc_html__('Four times per day', 'firephage-security') . '</option>';
        echo '</select></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Excluded paths or filenames', 'firephage-security') . '</span><textarea name="malware_scan_exclusions" rows="5" placeholder="/wp-content/cache/*&#10;/wp-content/backups/*&#10;*.log">' . esc_textarea($settings['malware_scan_exclusions']) . '</textarea></label>';
        echo '<p class="firephage-note">' . esc_html__('Use one exclusion per line. Wildcards are supported, so paths like /wp-content/cache/* or filenames like *.log can be skipped during scan discovery. FirePhage signature updates require a free token, are fetched as data only, cached locally, and the bundled fallback signatures remain available if FirePhage is unreachable.', 'firephage-security') . '</p>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary" data-scanner-settings-close="1">' . esc_html__('Cancel', 'firephage-security') . '</button>';
        echo '<button type="submit" class="button button-primary firephage-save-scanner-settings">' . esc_html__('Save Scanner Settings', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-modal" id="firephage-free-token-modal" hidden>';
        echo '<div class="firephage-modal-backdrop" data-free-token-close="1"></div>';
        echo '<div class="firephage-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="firephage-free-token-title">';
        echo '<div class="firephage-modal-head">';
        echo '<h3 id="firephage-free-token-title">' . esc_html__('Free FirePhage Signature Token', 'firephage-security') . '</h3>';
        echo '<button type="button" class="button-link firephage-modal-close" data-free-token-close="1" aria-label="' . esc_attr__('Close free token dialog', 'firephage-security') . '">&times;</button>';
        echo '</div>';
        echo '<p>' . esc_html__('Enter the email address to receive the free FirePhage token for signature updates. This keeps malware-signature delivery opt-in and separate from paid dashboard features. If you decline this, you can still use the Malware Scanner, but with limited malware signatures and without receiving signature updates created from the newest malware samples our team collects 24/7.', 'firephage-security') . '</p>';
        echo '<form id="firephage-free-token-form">';
        echo '<label class="firephage-field"><span>' . esc_html__('Email address', 'firephage-security') . '</span><input type="email" name="email" value="' . esc_attr(($settings['free_signature_token_email'] ?? '') !== '' ? $settings['free_signature_token_email'] : get_option('admin_email', '')) . '" required /></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="marketing_opt_in" value="1" ' . checked($settings['free_signature_token_marketing_opt_in'] ?? '0', '1', false) . ' /><span>' . esc_html__('I want to receive occasional FirePhage promo codes, Pro offers, and product updates', 'firephage-security') . '</span></label>';
        echo '<p class="firephage-note">' . esc_html__('This marketing checkbox is optional and not required for the free token. After you submit this form, verify the email link we send before FirePhage activates remote signature updates.', 'firephage-security') . '</p>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary firephage-dismiss-free-token">' . esc_html__('Do not bother me again', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-decline-free-token">' . esc_html__('No Thanks', 'firephage-security') . '</button>';
        echo '<button type="submit" class="button button-primary firephage-register-free-token">' . esc_html__('Email My Free Token', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
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
        $scanMode = sanitize_text_field((string) ($_POST['scan_mode'] ?? 'deep'));
        $result = $this->scanner->startScan($forceNew, $scanMode);

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
                __('Deleted %1$d malicious files. Skipped %2$d protected or unavailable files.', 'firephage-security'),
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
                __('Deleted %1$d selected malicious files. Skipped %2$d protected or unavailable files.', 'firephage-security'),
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

    public function handleRefreshSignatures(): void
    {
        $this->assertAjaxPermissions();
        $result = $this->scanner->refreshSignatureFeed();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()], 400);
        }

        wp_send_json_success([
            'message' => __('FirePhage signatures were refreshed.', 'firephage-security'),
        ]);
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
            'use_firephage_signature_feed' => ! empty($settings['use_firephage_signature_feed']) ? '1' : '0',
            'malware_auto_scan_interval' => in_array((string) ($settings['malware_auto_scan_interval'] ?? $current['malware_auto_scan_interval']), ['daily', 'twice_daily', 'four_times_daily'], true)
                ? (string) ($settings['malware_auto_scan_interval'] ?? $current['malware_auto_scan_interval'])
                : 'daily',
            'malware_scan_exclusions' => sanitize_textarea_field((string) ($settings['malware_scan_exclusions'] ?? $current['malware_scan_exclusions'])),
        ]);
        do_action('firephage_security_settings_changed');

        wp_send_json_success([
            'message' => __('Scanner settings were saved.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleRegisterFreeToken(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();
        $serviceUrl = esc_url_raw((string) ($settings['checksum_service_url'] ?? ''));
        $email = sanitize_email((string) ($_POST['email'] ?? ''));
        $marketingOptIn = ! empty($_POST['marketing_opt_in']);

        if ($serviceUrl === '' || $email === '') {
            wp_send_json_error(['message' => __('A valid FirePhage service URL and email address are required.', 'firephage-security')], 400);
        }

        $response = $this->client->registerFreeToken($serviceUrl, $email, $marketingOptIn);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        $this->settings->update([
            'free_signature_token' => '',
            'free_signature_status_token' => sanitize_text_field((string) ($response['status_token'] ?? '')),
            'free_signature_token_email' => sanitize_email((string) ($response['email'] ?? $email)),
            'free_signature_token_status' => 'awaiting_verification',
            'free_signature_token_last_requested_at' => current_time('mysql'),
            'free_signature_token_marketing_opt_in' => $marketingOptIn ? '1' : '0',
            'use_firephage_signature_feed' => '1',
        ]);

        wp_send_json_success([
            'message' => __('Check your inbox and verify your email address. FirePhage will activate remote signature updates after verification.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleCheckFreeTokenStatus(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();
        $serviceUrl = esc_url_raw((string) ($settings['checksum_service_url'] ?? ''));
        $statusToken = sanitize_text_field((string) ($settings['free_signature_status_token'] ?? ''));

        if ($serviceUrl === '' || $statusToken === '') {
            wp_send_json_error(['message' => __('There is no pending FirePhage email verification request for this site.', 'firephage-security')], 400);
        }

        $response = $this->client->fetchFreeTokenStatus($serviceUrl, $statusToken);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        if (($response['status'] ?? '') === 'verified') {
            $this->settings->update([
                'free_signature_token' => sanitize_text_field((string) ($response['token'] ?? '')),
                'free_signature_token_status' => 'registered',
            ]);

            wp_send_json_success([
                'message' => __('Email verified. FirePhage signature updates are now active.', 'firephage-security'),
                'settings' => $this->settings->all(),
            ]);
        }

        $this->settings->update([
            'free_signature_token_status' => 'awaiting_verification',
        ]);

        wp_send_json_success([
            'message' => __('Verification is still pending. Open the email from FirePhage and click the verification link first.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleVerifyFreeToken(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();
        $serviceUrl = esc_url_raw((string) ($settings['checksum_service_url'] ?? ''));
        $verificationToken = sanitize_text_field((string) ($_POST['verification_token'] ?? ''));

        if ($serviceUrl === '' || $verificationToken === '') {
            wp_send_json_error(['message' => __('A valid verification request is required.', 'firephage-security')], 400);
        }

        $response = $this->client->verifyFreeToken($serviceUrl, $verificationToken);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 400);
        }

        $this->settings->update([
            'free_signature_token' => sanitize_text_field((string) ($response['token'] ?? '')),
            'free_signature_token_status' => 'registered',
        ]);

        wp_send_json_success([
            'message' => __('Email verified on this WordPress site. FirePhage signature updates are now active.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleDeclineFreeToken(): void
    {
        $this->assertAjaxPermissions();

        $this->settings->update([
            'free_signature_token' => '',
            'free_signature_status_token' => '',
            'free_signature_token_status' => 'declined',
            'free_signature_token_marketing_opt_in' => '0',
            'use_firephage_signature_feed' => '0',
        ]);

        wp_send_json_success([
            'message' => __('FirePhage signature updates remain optional. The plugin will keep using bundled fallback signatures only.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleDismissFreeTokenPrompt(): void
    {
        $this->assertAjaxPermissions();

        $this->settings->update([
            'free_signature_token_status' => 'dismissed',
        ]);

        wp_send_json_success([
            'message' => __('The free-token prompt will stay hidden unless you open it again manually.', 'firephage-security'),
            'settings' => $this->settings->all(),
        ]);
    }

    public function handleSaveNotificationSettings(): void
    {
        $this->assertAjaxPermissions();
        $current = $this->settings->all();
        $settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];

        $this->settings->update([
            'notifications_enabled' => ! empty($settings['notifications_enabled']) ? '1' : '0',
            'notification_email' => sanitize_email((string) ($settings['notification_email'] ?? $current['notification_email'])),
            'notifications_weekly_report' => ! empty($settings['notifications_weekly_report']) ? '1' : '0',
            'notifications_alert_malware' => ! empty($settings['notifications_alert_malware']) ? '1' : '0',
            'notifications_alert_core_edits' => ! empty($settings['notifications_alert_core_edits']) ? '1' : '0',
        ]);
        do_action('firephage_security_settings_changed');

        wp_send_json_success([
            'message' => __('Notification settings were saved.', 'firephage-security'),
            'settings' => $this->settings->all(),
            'state' => $this->notifications->state(),
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
            'scanner' => ['label' => __('Malware Scanner', 'firephage-security')],
            'bruteforce' => ['label' => __('Brute Force Protection', 'firephage-security')],
            'updates' => ['label' => __('Updates', 'firephage-security')],
            'notifications' => ['label' => __('Notifications', 'firephage-security')],
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

    /**
     * @param array<string, string> $settings
     */
    private function freeTokenStatusLabel(array $settings): string
    {
        switch ((string) ($settings['free_signature_token_status'] ?? 'pending')) {
            case 'registered':
                return __('Active', 'firephage-security');

            case 'awaiting_verification':
                return __('Verify Email', 'firephage-security');

            case 'declined':
                return __('Declined', 'firephage-security');

            case 'dismissed':
                return __('Hidden', 'firephage-security');

            default:
                return __('Pending', 'firephage-security');
        }
    }

    /**
     * @param array<string, string> $settings
     */
    private function freeTokenStatusTone(array $settings): string
    {
        switch ((string) ($settings['free_signature_token_status'] ?? 'pending')) {
            case 'registered':
                return 'good';

            case 'awaiting_verification':
                return 'warning';

            case 'declined':
            case 'dismissed':
                return 'neutral';

            default:
                return 'warning';
        }
    }

    /**
     * @param array<string, string> $settings
     */
    private function freeTokenSummary(array $settings): string
    {
        $status = (string) ($settings['free_signature_token_status'] ?? 'pending');
        $email = (string) ($settings['free_signature_token_email'] ?? '');

        if ($status === 'registered' && $email !== '') {
            return sprintf(__('Signature updates are active with the free FirePhage token sent to %s.', 'firephage-security'), $email);
        }

        if ($status === 'declined') {
            return __('Remote FirePhage signature updates are turned off. You can request a free token later at any time.', 'firephage-security');
        }

        if ($status === 'dismissed') {
            return __('The free-token prompt is hidden. You can still request a free token later from the plugin whenever you want fresher FirePhage signature updates.', 'firephage-security');
        }

        if ($status === 'awaiting_verification') {
            return __('Verification email sent. Open your inbox, click the FirePhage verification link, then return here and check verification status to activate remote signature updates.', 'firephage-security');
        }

        return __('Choose whether you want a free FirePhage token for fresher malware-signature updates. Until you confirm yes or no, the plugin will ask again when you open this screen.', 'firephage-security');
    }

    private function renderLockedMetricCard(string $label, string $valueId = '', string $value = '--'): string
    {
        $id = $valueId !== '' ? ' id="' . esc_attr($valueId) . '"' : '';

        return '<div class="firephage-pro-metric"><span class="firephage-pro-metric__label">' . esc_html($label) . '</span><strong class="firephage-pro-metric__value"' . $id . '>' . esc_html($value) . '</strong></div>';
    }

    private function menuIcon(): string
    {
        $svg = <<<'SVG'
<svg width="128" height="128" viewBox="0 0 128 128" fill="none" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldPhageGradient" x1="20" y1="14" x2="104" y2="110" gradientUnits="userSpaceOnUse">
      <stop stop-color="#38BDF8"/>
      <stop offset="1" stop-color="#0EA5E9"/>
    </linearGradient>
  </defs>
  <path d="M64 10L108 30V68C108 95 88 115 64 124C40 115 20 95 20 68V30L64 10Z" stroke="url(#shieldPhageGradient)" stroke-width="8"/>
  <path d="M64 40L79 49V65L64 74L49 65V49L64 40Z" stroke="#7DD3FC" stroke-width="5"/>
  <path d="M64 74V91" stroke="#7DD3FC" stroke-width="5" stroke-linecap="round"/>
  <path d="M64 91L51 105" stroke="#7DD3FC" stroke-width="4" stroke-linecap="round"/>
  <path d="M64 91L77 105" stroke="#7DD3FC" stroke-width="4" stroke-linecap="round"/>
</svg>
SVG;

        return 'data:image/svg+xml;base64,' . base64_encode($svg);
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
            esc_html($this->humanizeCheckStatus((string) $check['status'])),
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
            return '<p class="firephage-empty">' . esc_html__('No malicious files detected in the latest scan.', 'firephage-security') . '</p>';
        }

        $pageSizeOptions = $this->pageSizeOptions(count($findings));
        $html = '<div class="firephage-findings-toolbar">';
        $html .= '<label class="firephage-findings-search"><span class="screen-reader-text">' . esc_html__('Search findings', 'firephage-security') . '</span><input type="search" class="firephage-findings-search-input" placeholder="' . esc_attr__('Search findings...', 'firephage-security') . '" /></label>';
        $html .= '<label class="firephage-findings-rows"><span>' . esc_html__('Rows', 'firephage-security') . '</span><select class="firephage-findings-page-size">';
        foreach ($pageSizeOptions as $option) {
            $html .= '<option value="' . esc_attr((string) $option) . '"' . selected($option, 25, false) . '>' . esc_html((string) $option) . '</option>';
        }
        $html .= '</select></label>';
        $html .= '<div class="firephage-findings-actions">';
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-selected-suspicious-files" disabled>' . esc_html__('Delete Selected Files', 'firephage-security') . '</button>';
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-suspicious-files">' . esc_html__('Delete All Malicious Files', 'firephage-security') . '</button>';
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
            $status = $type === 'malware' ? __('Malicious', 'firephage-security') : __('Integrity mismatch', 'firephage-security');
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
                $html .= '<label class="screen-reader-text" for="firephage-select-' . esc_attr(md5($file)) . '">' . esc_html__('Select malicious file', 'firephage-security') . '</label>';
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
            return '<p class="firephage-empty">' . esc_html($showRemaining ? __('No active lockouts right now.', 'firephage-security') : __('No recent lockout events right now.', 'firephage-security')) . '</p>';
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
                __('Scan cancelled at %1$d of %2$d discovered files. Trusted: %3$d. Clean custom files: %4$d. Skipped: %5$d. Integrity mismatches: %6$d. Malicious: %7$d. Use Resume Scan to continue from the saved position.', 'firephage-security'),
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
                __('Scan completed. %1$d files scanned, %2$d trusted, %3$d clean custom files, %4$d skipped, %5$d integrity mismatches, %6$d malicious.', 'firephage-security'),
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
            __('Scanning %1$d of %2$d discovered files. Trusted: %3$d. Clean custom files: %4$d. Skipped: %5$d. Integrity mismatches: %6$d. Malicious: %7$d. Current file: %8$s', 'firephage-security'),
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
        switch ($status) {
            case 'completed':
                return 'good';

            case 'failed':
                return 'critical';

            case 'discovering':
            case 'scanning':
                return 'warning';

            default:
                return 'neutral';
        }
    }

    private function scanStatusLabel(string $status): string
    {
        switch ($status) {
            case 'completed':
                return __('Completed', 'firephage-security');

            case 'failed':
                return __('Needs Review', 'firephage-security');

            case 'discovering':
                return __('Preparing Scan', 'firephage-security');

            case 'scanning':
                return __('Scanning', 'firephage-security');

            case 'stopped':
                return __('Cancelled', 'firephage-security');

            default:
                return __('Idle', 'firephage-security');
        }
    }

    private function connectionStatusLabel(string $status): string
    {
        switch ($status) {
            case 'connected':
                return __('Connected', 'firephage-security');

            case 'error':
                return __('Needs Attention', 'firephage-security');

            default:
                return __('Not Connected', 'firephage-security');
        }
    }

    private function humanizeCheckStatus(string $status): string
    {
        switch ($status) {
            case 'good':
                return __('Healthy', 'firephage-security');

            case 'warning':
                return __('Needs Review', 'firephage-security');

            case 'critical':
                return __('Action Needed', 'firephage-security');

            default:
                return ucfirst($status);
        }
    }

    private function humanizeTimestamp(string $timestamp): string
    {
        if ($timestamp === '') {
            return __('Never', 'firephage-security');
        }

        $unix = strtotime($timestamp);

        if ($unix === false) {
            return $timestamp;
        }

        $delta = time() - $unix;

        if ($delta < 60) {
            return __('Just now', 'firephage-security');
        }

        if ($delta < HOUR_IN_SECONDS) {
            $minutes = max(1, (int) floor($delta / MINUTE_IN_SECONDS));
            return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'firephage-security'), $minutes);
        }

        if ($delta < DAY_IN_SECONDS) {
            $hours = max(1, (int) floor($delta / HOUR_IN_SECONDS));
            return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'firephage-security'), $hours);
        }

        $days = max(1, (int) floor($delta / DAY_IN_SECONDS));

        return sprintf(_n('%d day ago', '%d days ago', $days, 'firephage-security'), $days);
    }

    /**
     * @param array<string, mixed> $health
     * @param array<string, mixed> $scan
     * @param array<string, mixed> $bruteForce
     * @param array<string, string> $settings
     * @return array{score: int, tone: string, label: string, summary: string, hints: array<int, string>}
     */
    private function buildSecurityScore(array $health, array $scan, array $bruteForce, array $settings): array
    {
        $score = 40;
        $hints = [];
        $checks = [];

        foreach (($health['checks'] ?? []) as $check) {
            if (! is_array($check) || ! isset($check['key'])) {
                continue;
            }

            $checks[(string) $check['key']] = (string) ($check['status'] ?? 'warning');
        }

        $addHint = static function (array &$items, string $hint): void {
            if (count($items) < 4 && ! in_array($hint, $items, true)) {
                $items[] = $hint;
            }
        };

        $score += ($checks['https'] ?? '') === 'good' ? 10 : 0;
        if (($checks['https'] ?? '') !== 'good') {
            $addHint($hints, __('+10 enable HTTPS across the site', 'firephage-security'));
        }

        $score += ($checks['debug_display'] ?? '') === 'good' ? 6 : 0;
        if (($checks['debug_display'] ?? '') !== 'good') {
            $addHint($hints, __('+3 disable debug display', 'firephage-security'));
        }

        $score += ($checks['file_editor'] ?? '') === 'good' ? 6 : 0;
        $score += ($checks['registration'] ?? '') === 'good' ? 4 : 0;
        $score += ($checks['default_admin'] ?? '') === 'good' ? 6 : 0;
        $score += ($checks['xmlrpc'] ?? '') === 'good' ? 5 : (($settings['bruteforce_protect_xmlrpc'] ?? '0') === '1' ? 3 : 0);

        if (($settings['bruteforce_enabled'] ?? '0') === '1') {
            $score += 8;
        } else {
            $addHint($hints, __('+5 enable brute force protection', 'firephage-security'));
        }

        $pendingUpdates = (int) (($health['updates']['core_updates'] ?? 0) + ($health['updates']['plugin_updates'] ?? 0) + ($health['updates']['theme_updates'] ?? 0));
        if ($pendingUpdates === 0) {
            $score += 10;
        } elseif ($pendingUpdates <= 3) {
            $score += 4;
            $addHint($hints, __('+4 apply pending updates', 'firephage-security'));
        } else {
            $addHint($hints, __('+8 reduce update exposure', 'firephage-security'));
        }

        $suspicious = (int) ($scan['suspicious_files'] ?? 0);
        $integrity = (int) ($scan['integrity_issues'] ?? 0);
        if ($suspicious === 0 && $integrity === 0 && in_array((string) ($scan['status'] ?? 'idle'), ['completed', 'idle'], true)) {
            $score += 10;
        } else {
            if ($suspicious > 0) {
                $score -= min(18, $suspicious * 3);
                $addHint($hints, __('+5 resolve malicious file findings', 'firephage-security'));
            }

            if ($integrity > 0) {
                $score -= min(10, $integrity * 2);
            }
        }

        if (($settings['connection_status'] ?? 'disconnected') === 'connected') {
            $score += 5;
        } else {
            $addHint($hints, __('+10 connect FirePhage Pro firewall', 'firephage-security'));
        }

        $score = max(0, min(100, $score));

        $tone = $score >= 85 ? 'good' : ($score >= 65 ? 'warning' : 'critical');
        $label = $score >= 85 ? __('Strong', 'firephage-security') : ($score >= 65 ? __('Good', 'firephage-security') : __('Needs Work', 'firephage-security'));
        $summary = $score >= 85
            ? __('Core security controls look healthy. Keep scans and updates consistent.', 'firephage-security')
            : ($score >= 65
                ? __('The site is in a decent state, but a few improvements would raise protection quickly.', 'firephage-security')
                : __('Several security signals need attention. Start with the highest-impact issues below.', 'firephage-security'));

        if ($hints === []) {
            $hints[] = __('Keep updates current and review each completed scan.', 'firephage-security');
        }

        return [
            'score' => $score,
            'tone' => $tone,
            'label' => $label,
            'summary' => $summary,
            'hints' => array_slice($hints, 0, 4),
        ];
    }

    private function assertAjaxPermissions(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You are not allowed to manage FirePhage Security.', 'firephage-security')], 403);
        }

        check_ajax_referer('firephage_admin', 'nonce');
    }
}
