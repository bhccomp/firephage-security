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
        add_action('wp_ajax_firephage_process_scan_batch', [$this, 'handleProcessScanBatch']);
        add_action('wp_ajax_firephage_preview_file', [$this, 'handlePreviewFile']);
        add_action('wp_ajax_firephage_compare_file', [$this, 'handleCompareFile']);
        add_action('wp_ajax_firephage_restore_file', [$this, 'handleRestoreFile']);
        add_action('wp_ajax_firephage_restore_all_integrity_files', [$this, 'handleRestoreAllIntegrityFiles']);
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
        add_action('wp_ajax_firephage_dismiss_setup_wizard', [$this, 'handleDismissSetupWizard']);
        add_action('wp_ajax_firephage_complete_setup_wizard', [$this, 'handleCompleteSetupWizard']);
        add_action('wp_ajax_firephage_connect_dashboard', [$this, 'handleConnectDashboard']);
        add_action('wp_ajax_firephage_disconnect_dashboard', [$this, 'handleDisconnectDashboard']);
        add_action('wp_ajax_firephage_fetch_plugin_status', [$this, 'handleFetchPluginStatus']);
        add_action('wp_ajax_firephage_fetch_firewall_summary', [$this, 'handleFetchFirewallSummary']);
        add_action('wp_ajax_firephage_fetch_performance_summary', [$this, 'handleFetchPerformanceSummary']);
        add_action('wp_ajax_firephage_create_firewall_rule', [$this, 'handleCreateFirewallRule']);
        add_action('wp_ajax_firephage_delete_firewall_rule', [$this, 'handleDeleteFirewallRule']);
        add_action('wp_ajax_firephage_toggle_firewall_rule', [$this, 'handleToggleFirewallRule']);
        add_action('wp_ajax_firephage_purge_edge_cache', [$this, 'handlePurgeEdgeCache']);
        add_action('wp_ajax_firephage_toggle_troubleshooting_mode', [$this, 'handleToggleTroubleshootingMode']);
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
        $choicesStylePath = FIREPHAGE_SECURITY_PATH . 'assets/vendor/choices/choices.min.css';
        $choicesScriptPath = FIREPHAGE_SECURITY_PATH . 'assets/vendor/choices/choices.min.js';
        $styleVersion = file_exists($stylePath) ? (string) filemtime($stylePath) : FIREPHAGE_SECURITY_VERSION;
        $scriptVersion = file_exists($scriptPath) ? (string) filemtime($scriptPath) : FIREPHAGE_SECURITY_VERSION;
        $choicesStyleVersion = file_exists($choicesStylePath) ? (string) filemtime($choicesStylePath) : FIREPHAGE_SECURITY_VERSION;
        $choicesScriptVersion = file_exists($choicesScriptPath) ? (string) filemtime($choicesScriptPath) : FIREPHAGE_SECURITY_VERSION;

        wp_enqueue_style(
            'firephage-security-choices',
            FIREPHAGE_SECURITY_URL . 'assets/vendor/choices/choices.min.css',
            [],
            $choicesStyleVersion
        );

        wp_enqueue_style(
            'firephage-security-admin',
            FIREPHAGE_SECURITY_URL . 'assets/css/admin.css',
            ['firephage-security-choices'],
            $styleVersion
        );

        wp_enqueue_script(
            'firephage-security-choices',
            FIREPHAGE_SECURITY_URL . 'assets/vendor/choices/choices.min.js',
            [],
            $choicesScriptVersion,
            true
        );

        wp_enqueue_script(
            'firephage-security-admin',
            FIREPHAGE_SECURITY_URL . 'assets/js/admin.js',
            ['jquery', 'firephage-security-choices'],
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
                    'quickScanBody' => __('Quick Scan is faster, but it checks less than a Deep Scan. If you already suspect malware, Deep Scan is the safer choice.', 'firephage-security'),
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
                    'compareFile' => __('Compare', 'firephage-security'),
                    'restoreFile' => __('Restore', 'firephage-security'),
                    'restoreAllFiles' => __('Restore All Modified Files', 'firephage-security'),
                    'compareTitle' => __('Compare Files', 'firephage-security'),
                    'localFile' => __('Local file', 'firephage-security'),
                    'officialReference' => __('Official reference', 'firephage-security'),
                    'previewTruncated' => __('Preview truncated to keep the browser responsive.', 'firephage-security'),
                    'confirmRestoreTitle' => __('Restore Official File?', 'firephage-security'),
                    'confirmRestoreAllTitle' => __('Restore All Modified Files?', 'firephage-security'),
                    'confirmRestoreBody' => __('This will overwrite the local file with the official WordPress.org version for the installed package release.', 'firephage-security'),
                    'confirmRestoreAllBody' => __('This will overwrite every checksum-based modified file in the current findings list with the official WordPress.org package version.', 'firephage-security'),
                    'confirmRestoreBackup' => __('Create a backup before restoring files.', 'firephage-security'),
                    'confirmRestoreWarning' => __('Restoring official files will overwrite local edits.', 'firephage-security'),
                    'confirmRestoreAcknowledge' => __('I understand this will overwrite local changes. Do not show this warning again until the next scan.', 'firephage-security'),
                    'confirmRestoreAcknowledgeRequired' => __('Please check the confirmation box before restoring files.', 'firephage-security'),
                    'confirmRestoreCountLabel' => __('Files ready to restore', 'firephage-security'),
                    'confirmDeleteTitle' => __('Delete Malicious File?', 'firephage-security'),
                    'confirmDeleteAllTitle' => __('Delete All Malicious Files?', 'firephage-security'),
                    'confirmDeleteSelectedTitle' => __('Delete Selected Malicious Files?', 'firephage-security'),
                    'confirmDeleteBody' => __('Deleting a malicious file can affect site functionality, so create a backup first and review the file path before continuing.', 'firephage-security'),
                    'confirmDeleteAllBody' => __('Deleting all malicious files can affect site functionality, so create a backup first and review the files before continuing. Protected core files will still be skipped.', 'firephage-security'),
                    'confirmDeleteSelectedBody' => __('Deleting selected malicious files can affect site functionality, so create a backup first and review the files before continuing. Protected core files will still be skipped.', 'firephage-security'),
                    'confirmDeleteFirewallRuleTitle' => __('Delete Firewall Rule?', 'firephage-security'),
                    'confirmDeleteFirewallRuleBody' => __('This will remove the selected access rule from FirePhage and WordPress.', 'firephage-security'),
                    'confirmDeleteFirewallRuleTargetLabel' => __('Rule target', 'firephage-security'),
                    'confirmDeleteFirewallRuleAction' => __('Delete Rule', 'firephage-security'),
                    'confirmAction' => __('Delete', 'firephage-security'),
                    'cancelAction' => __('Cancel', 'firephage-security'),
                    'connectRequired' => __('Connect the plugin to FirePhage to load live Pro data.', 'firephage-security'),
                    'loadingProData' => __('Loading FirePhage data...', 'firephage-security'),
                    'proInactive' => __('This site is connected, but it does not currently have an active Pro plan.', 'firephage-security'),
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
                    'confirmClearLockoutsBody' => __('This will immediately clear all active local lockouts and failed-login counters for the plugin’s local protection layer.', 'firephage-security'),
                    'deleteModalWarning' => __('This action can affect site functionality. Review the file paths carefully before continuing.', 'firephage-security'),
                    'deleteModalBackup' => __('Create a backup before deleting files.', 'firephage-security'),
                    'deleteModalCountLabel' => __('Files marked as malicious', 'firephage-security'),
                    'deleteModalFileLabel' => __('File', 'firephage-security'),
                    'deleteModalFilesLabel' => __('Files', 'firephage-security'),
                    'refreshHealthDone' => __('Health checks refreshed.', 'firephage-security'),
                    'refreshSignaturesDone' => __('FirePhage signatures refreshed.', 'firephage-security'),
                    'applyRecommendedSetup' => __('Applying recommended settings...', 'firephage-security'),
                    'saveSetupWizard' => __('Saving setup and starting your first scan...', 'firephage-security'),
                ],
                'freeToken' => [
                    'status' => (string) ($settings['free_signature_token_status'] ?? 'pending'),
                    'email' => (string) (($settings['free_signature_token_email'] ?? '') !== '' ? $settings['free_signature_token_email'] : get_option('admin_email', '')),
                    'marketingOptIn' => (($settings['free_signature_token_marketing_opt_in'] ?? '0') === '1'),
                    'requiresDecision' => (($settings['free_signature_token_status'] ?? 'pending') === 'pending'),
                    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only email verification token passed to JavaScript; sanitized before use.
                    'verificationToken' => isset($_GET['firephage_verify']) ? sanitize_text_field((string) wp_unslash($_GET['firephage_verify'])) : '',
                ],
                'setupWizard' => [
                    'shouldOpen' => get_option('firephage_security_show_setup_wizard', '') === '1',
                ],
            ]
        );
    }

    public function renderOverviewPage(): void
    {
        if (! headers_sent()) {
            nocache_headers();
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: Wed, 11 Jan 1984 05:00:00 GMT');
        }

        $settings = $this->settings->all();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only admin tab selector; sanitized and allowlisted below.
        $requestedTab = isset($_GET['tab']) ? sanitize_key((string) wp_unslash($_GET['tab'])) : 'overview';
        $availableTabs = array_keys($this->tabs());
        $activeTab = in_array($requestedTab, $availableTabs, true) ? $requestedTab : 'overview';
        $report = $this->reportBuilder->build();
        $scan = $this->scanner->getState();
        $health = $report['health'];
        $updates = $health['updates'];
        $bruteForce = $this->bruteForceProtection->getSummary();
        $notificationState = $this->notifications->state();
        $securityScore = $this->buildSecurityScore($health, $scan, $bruteForce, $settings);
        $overviewStatus = $this->buildOverviewStatus($health, $scan, $bruteForce, $settings, $securityScore);
        $lastScanFreshness = $this->humanizeTimestamp((string) ($scan['finished_at'] ?? ''));
        $lastSyncFreshness = $this->humanizeTimestamp((string) ($settings['last_sync_at'] ?? ''));
        $pendingUpdates = (int) (($updates['core_updates'] ?? 0) + ($updates['plugin_updates'] ?? 0) + ($updates['theme_updates'] ?? 0));
        $scannerFindings = (int) ($scan['suspicious_files'] ?? 0);
        $officialChecksumMismatches = $this->officialChecksumMismatches($scan);
        $baselineChanges = $this->baselineChanges($scan);
        $bruteforceWafManaged = ! empty($bruteForce['waf_managed']);
        $dashboardFirewallUrl = $this->dashboardFirewallUrl($settings);
        $remoteProEnabled = ($settings['remote_pro_enabled'] ?? '0') === '1';
        $isConnected = ($settings['connection_status'] ?? 'disconnected') === 'connected' && ($settings['site_token'] ?? '') !== '' && ($settings['site_id'] ?? '') !== '';

        if ($isConnected && ! $remoteProEnabled) {
            $status = $this->client->fetchStatus($settings);

            if (! is_wp_error($status)) {
                $this->cacheRemotePlanState($status);
                $settings = $this->settings->all();
                $dashboardFirewallUrl = $this->dashboardFirewallUrl($settings);
                $remoteProEnabled = ($settings['remote_pro_enabled'] ?? '0') === '1';
            }
        }

        echo '<div class="wrap firephage-admin">';
        echo '<h1 class="wp-heading-inline screen-reader-text">' . esc_html__('FirePhage Security', 'firephage-security') . '</h1>';
        echo '<hr class="wp-header-end">';
        echo '<div class="firephage-shell">';
        echo '<div class="firephage-hero">';
        echo '<div>';
        echo '<p class="firephage-eyebrow">' . esc_html__('Local WordPress Security', 'firephage-security') . '</p>';
        echo '<h1>' . esc_html__('FirePhage Security', 'firephage-security') . '</h1>';
        echo '<p class="firephage-hero-copy">' . esc_html__('Secure WordPress with malware scanning, brute-force protection, health checks, update visibility, and an optional FirePhage connection for advanced firewall protection plus CDN and cache services that deliver major performance gains.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-hero-actions">';
        if (! $remoteProEnabled) {
            echo '<a class="button button-primary button-hero" id="firephage-hero-upgrade-button" href="' . esc_url($this->firephageTrackedUrl($settings, 'overview', 'hero_upgrade')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Upgrade with FirePhage', 'firephage-security') . '</a>';
        }
        echo '</div>';
        echo '</div>';

        echo '<div class="firephage-tabs" role="tablist" aria-label="' . esc_attr__('FirePhage sections', 'firephage-security') . '">';
        foreach ($this->tabs() as $tabId => $tab) {
            echo wp_kses($this->renderTabButton($tabId, $tab, $activeTab === $tabId), $this->adminAllowedHtml());
        }
        echo '</div>';

        echo '<div id="firephage-admin-app" data-active-tab="' . esc_attr($activeTab) . '" data-scan-status="' . esc_attr(wp_json_encode($scan)) . '" data-site-connected="' . esc_attr($isConnected ? '1' : '0') . '" data-remote-pro-enabled="' . esc_attr($remoteProEnabled ? '1' : '0') . '">';
        echo '<section class="firephage-tab-panel" data-panel="overview"' . ($activeTab === 'overview' ? '' : ' hidden') . '>';
        echo '<div class="firephage-panel-header">';
        echo '<div><h2>' . esc_html__('Overview', 'firephage-security') . '</h2><p>' . esc_html__('Start here to see whether the site looks healthy, what needs attention, and which fix to tackle next.', 'firephage-security') . '</p></div>';
        echo '<button type="button" class="button button-secondary firephage-refresh-health">' . esc_html__('Refresh Site Checks', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-score-card" id="firephage-security-score-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Security Score', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($securityScore['tone']) . '" id="firephage-security-score-badge">' . esc_html($securityScore['label']) . '</span>';
        echo '</div>';
        echo '<div class="firephage-score-value"><strong id="firephage-security-score-value">' . esc_html((string) $securityScore['score']) . '</strong><span>/ 100</span></div>';
        echo '<p id="firephage-security-score-summary">' . esc_html($securityScore['summary']) . '</p>';
        echo '<div class="firephage-recommendation-box">';
        echo '<p class="firephage-section-kicker">' . esc_html__('Recommended next steps', 'firephage-security') . '</p>';
        echo '<div class="firephage-score-hints" id="firephage-security-score-hints">';
        foreach ($securityScore['hints'] as $hint) {
            echo '<span class="firephage-score-hint">' . esc_html($hint) . '</span>';
        }
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Site Status', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($overviewStatus['tone']) . '" id="firephage-overview-status-badge">' . esc_html($overviewStatus['label']) . '</span>';
        echo '</div>';
        echo '<p id="firephage-overview-status-summary">' . esc_html($overviewStatus['summary']) . '</p>';
        echo '<div class="firephage-mini-grid">';
        echo wp_kses($this->renderStatCard(
            __('Security checks', 'firephage-security'),
            $overviewStatus['checks_value'],
            $overviewStatus['checks_summary'],
            'firephage-stat-card--compact firephage-overview-checks-stat'
        ), $this->adminAllowedHtml());
        echo wp_kses($this->renderStatCard(
            __('Local login protection', 'firephage-security'),
            $overviewStatus['protection_value'],
            $overviewStatus['protection_summary'],
            'firephage-stat-card--compact firephage-overview-protection-stat'
        ), $this->adminAllowedHtml());
        echo wp_kses($this->renderStatCard(
            __('Last sync', 'firephage-security'),
            $overviewStatus['sync_value'],
            $overviewStatus['sync_summary'],
            'firephage-stat-card--compact firephage-overview-sync-stat'
        ), $this->adminAllowedHtml());
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Malware Scanner', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-overview-scan-status-badge">' . esc_html($this->scanStatusLabel((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p id="firephage-overview-scan-summary">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<p class="firephage-meta-line"><strong>' . esc_html__('Last scan:', 'firephage-security') . '</strong> <span id="firephage-overview-last-scan">' . esc_html($lastScanFreshness) . '</span></p>';
        echo '<div class="firephage-mini-grid">';
        echo wp_kses($this->renderStatCard(__('Flagged files', 'firephage-security'), (string) $scannerFindings, $scannerFindings > 0 ? __('Review these files carefully before deleting anything.', 'firephage-security') : __('No malicious files were found in the latest scan.', 'firephage-security'), 'firephage-stat-card--compact firephage-overview-flagged-stat'), $this->adminAllowedHtml());
        echo wp_kses($this->renderStatCard(__('Official checksum mismatches', 'firephage-security'), (string) $officialChecksumMismatches, $officialChecksumMismatches > 0 ? __('These files do not match official WordPress.org package checksums and should be reviewed first.', 'firephage-security') : ($baselineChanges > 0 ? __('No official checksum mismatches were found. Some unverifiable package files changed against the local baseline.', 'firephage-security') : __('No official checksum mismatches were found.', 'firephage-security')), 'firephage-stat-card--compact firephage-overview-modified-stat'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-primary firephage-overview-start-scan">' . esc_html($scan['status'] === 'stopped' ? __('Resume Malware Scan', 'firephage-security') : __('Scan My Website For Malware', 'firephage-security')) . '</button>';
        echo '<button type="button" class="button button-secondary firephage-overview-new-scan" style="' . esc_attr($scan['status'] === 'stopped' ? '' : 'display:none;') . '">' . esc_html__('Start New Malware Scan', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-overview-view-results" style="' . esc_attr(($scan['status'] === 'discovering' || $scan['status'] === 'scanning') ? '' : 'display:none;') . '">' . esc_html__('View Results', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Updates Status', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($pendingUpdates > 0 ? 'warning' : 'good') . '">' . esc_html($pendingUpdates > 0 ? __('Updates waiting', 'firephage-security') : __('All clear', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html($pendingUpdates > 0
            /* translators: 1: Number of pending updates. 2: Number of inactive plugins. */
            ? sprintf(__('%1$d updates are waiting across WordPress core, plugins, and themes. %2$d inactive plugins should also be reviewed.', 'firephage-security'), $pendingUpdates, (int) ($updates['inactive_plugins'] ?? 0))
            : __('WordPress core, plugins, and themes are up to date right now.', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-panel-header firephage-panel-header--subsection">';
        echo '<div><h3>' . esc_html__('Detailed checks', 'firephage-security') . '</h3><p>' . esc_html__('These checks help explain why the score looks the way it does.', 'firephage-security') . '</p></div>';
        echo '</div>';
        echo '<div class="firephage-grid" id="firephage-health-checks">';
        foreach ($health['checks'] as $check) {
            echo wp_kses($this->renderCheckCard($check), $this->adminAllowedHtml());
        }
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="scanner"' . ($activeTab === 'scanner' ? '' : ' hidden') . '>';
        echo '<div class="firephage-grid firephage-grid--scanner">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Malware Scanner', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->mapStateBadge((string) $scan['status'])) . '" id="firephage-scan-status-badge">' . esc_html($this->scanStatusLabel((string) $scan['status'])) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Runs safely in the background so larger sites can finish scanning without locking up wp-admin. FirePhage checks trusted WordPress packages, local clean-file history, and malware signatures when available.', 'firephage-security') . '</p>';
        echo '<div class="firephage-progress"><div class="firephage-progress-bar" id="firephage-scan-progress-bar" style="width:' . esc_attr((string) $this->scanProgress($scan)) . '%"></div></div>';
        echo '<p id="firephage-scan-progress-label">' . esc_html($this->scanProgressLabel($scan)) . '</p>';
        echo '<div class="firephage-mini-grid">';
        echo wp_kses($this->renderStatCard(__('Files checked', 'firephage-security'), (string) ((int) ($scan['scanned_files'] ?? 0)), __('Files reviewed in the current scan.', 'firephage-security'), 'firephage-stat-card--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderStatCard(__('Flagged files', 'firephage-security'), (string) $scannerFindings, $scannerFindings > 0 ? __('Review these files before deciding whether to delete them.', 'firephage-security') : __('No malicious files were flagged in the latest scan.', 'firephage-security'), 'firephage-stat-card--compact firephage-scanner-flagged-stat'), $this->adminAllowedHtml());
        echo wp_kses($this->renderStatCard(__('Official checksum mismatches', 'firephage-security'), (string) $officialChecksumMismatches, $officialChecksumMismatches > 0 ? __('These files do not match official WordPress.org package checksums and should be checked first.', 'firephage-security') : ($baselineChanges > 0 ? __('No official checksum mismatches were found. Some unverifiable package files changed against the local baseline.', 'firephage-security') : __('No official checksum mismatches were reported.', 'firephage-security')), 'firephage-stat-card--compact firephage-scanner-modified-stat'), $this->adminAllowedHtml());
        echo '</div>';
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
        echo '<li>' . esc_html__('Checks WordPress core, plugins, and themes against official package checksums when available.', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Keeps a local clean-file baseline for custom code that WordPress.org cannot verify.', 'firephage-security') . '</li>';
        echo '<li>' . esc_html__('Lets you exclude paths such as /wp-content/cache/* or *.log if you never want them scanned.', 'firephage-security') . '</li>';
        echo '</ul>';
        echo '<p class="firephage-note">' . esc_html__('Checksum verification can use FirePhage\'s checksum cache first when you enable it, with WordPress.org remaining available as fallback. Your paid dashboard connection is separate and optional.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card firephage-findings-card">';
        echo '<h3>' . esc_html__('Latest findings', 'firephage-security') . '</h3>';
        echo '<p class="firephage-findings-intro">' . esc_html__('Review flagged files carefully. Nothing is deleted automatically, and WordPress core files marked as protected will stay untouched.', 'firephage-security') . '</p>';
        if ($scannerFindings > 0) {
            $helperCopy = __('Need help reviewing these files? FirePhage offers deeper analysis, cleanup options, and a free consultation.', 'firephage-security');
            echo '<div class="firephage-context-bar">';
            echo '<p>' . esc_html($helperCopy) . '</p>';
            echo '<a class="firephage-context-bar__link" href="' . esc_url($this->firephageTrackedUrl($settings, 'malware-scanner', 'review_cleanup_options')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Review Cleanup Options', 'firephage-security') . '</a>';
            echo '</div>';
        }
        echo '<div id="firephage-scan-findings">' . wp_kses($this->renderFindings($scan['findings'] ?? []), $this->adminAllowedHtml()) . '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="updates"' . ($activeTab === 'updates' ? '' : ' hidden') . '>';
        echo wp_kses($this->renderUpdatesSummary($updates), $this->adminAllowedHtml());
        echo '<div class="firephage-grid">';
        echo wp_kses($this->renderUpdateCard(
            __('Core updates', 'firephage-security'),
            (int) ($updates['core_updates'] ?? 0),
            __('New WordPress core releases are ready to review.', 'firephage-security'),
            __('WordPress core is up to date.', 'firephage-security'),
            __('Open WordPress updates', 'firephage-security'),
            admin_url('update-core.php')
        ), $this->adminAllowedHtml());
        echo wp_kses($this->renderUpdateCard(
            __('Plugin updates', 'firephage-security'),
            (int) ($updates['plugin_updates'] ?? 0),
            __('Installed plugins with updates ready to review.', 'firephage-security'),
            __('No plugin updates are needed right now.', 'firephage-security'),
            __('View plugins', 'firephage-security'),
            admin_url('plugins.php')
        ), $this->adminAllowedHtml());
        echo wp_kses($this->renderUpdateCard(
            __('Theme updates', 'firephage-security'),
            (int) ($updates['theme_updates'] ?? 0),
            __('Installed themes with updates ready to review.', 'firephage-security'),
            __('No theme updates are needed right now.', 'firephage-security'),
            __('View themes', 'firephage-security'),
            admin_url('themes.php')
        ), $this->adminAllowedHtml());
        echo wp_kses($this->renderUpdateCard(
            __('Inactive plugins', 'firephage-security'),
            (int) ($updates['inactive_plugins'] ?? 0),
            __('Inactive plugins should still be reviewed as part of routine site maintenance.', 'firephage-security'),
            __('No inactive plugins need review right now.', 'firephage-security'),
            __('Review plugins', 'firephage-security'),
            admin_url('plugins.php?plugin_status=inactive')
        ), $this->adminAllowedHtml());
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="bruteforce"' . ($activeTab === 'bruteforce' ? '' : ' hidden') . '>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Brute Force Protection', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr((string) ($bruteForce['status'] ?? 'neutral')) . '" id="firephage-bruteforce-status-badge">' . esc_html($bruteforceWafManaged ? __('WAF Managed', 'firephage-security') : (($bruteForce['enabled'] ?? false) ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security'))) . '</span>';
        echo '</div>';
        echo '<p id="firephage-bruteforce-summary-text">' . esc_html((string) ($bruteForce['summary'] ?? '')) . '</p>';
        echo '<div id="firephage-bruteforce-local-panel"' . ($bruteforceWafManaged ? ' hidden' : '') . '>';
        echo '<form id="firephage-bruteforce-form">';
        echo '<label class="firephage-toggle"><input type="checkbox" name="bruteforce_enabled" value="1" ' . checked($settings['bruteforce_enabled'], '1', false) . ' /><span>' . esc_html__('Enable local login protection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-grid firephage-grid--3 firephage-grid--compact">';
        echo '<label class="firephage-field"><span>' . esc_html__('Failed logins before lockout', 'firephage-security') . '</span><input type="number" min="3" max="20" step="1" name="bruteforce_threshold" value="' . esc_attr($settings['bruteforce_threshold']) . '" /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('How long to watch failed logins (minutes)', 'firephage-security') . '</span><input type="number" min="5" max="120" step="1" name="bruteforce_window_minutes" value="' . esc_attr($settings['bruteforce_window_minutes']) . '" /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('How long to block logins (minutes)', 'firephage-security') . '</span><input type="number" min="5" max="1440" step="1" name="bruteforce_lockout_minutes" value="' . esc_attr($settings['bruteforce_lockout_minutes']) . '" /></label>';
        echo '</div>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="bruteforce_protect_xmlrpc" value="1" ' . checked($settings['bruteforce_protect_xmlrpc'], '1', false) . ' /><span>' . esc_html__('Apply the same rules to XML-RPC logins', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary firephage-save-bruteforce">' . esc_html__('Save Protection Settings', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-clear-bruteforce-lockouts">' . esc_html__('Clear Active Lockouts', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</form>';
        echo '<p class="firephage-note">' . esc_html__('This is the plugin’s local login protection. If you later connect FirePhage Pro, the edge firewall becomes your main login shield and this local layer can stay conservative.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div id="firephage-bruteforce-managed-panel"' . ($bruteforceWafManaged ? '' : ' hidden') . '>';
        echo '<div class="firephage-context-bar firephage-context-bar--bruteforce">';
        echo '<p>' . esc_html__('This site is on a paid FirePhage plan, so login and XML-RPC brute-force protection is enforced at the edge. The local PHP lockout layer is automatically disabled to avoid duplicate rate limiting and conflicting lockouts.', 'firephage-security') . '</p>';
        if ($dashboardFirewallUrl !== '') {
            echo '<a class="firephage-context-bar__link" href="' . esc_url($dashboardFirewallUrl) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Open FirePhage Firewall', 'firephage-security') . '</a>';
        }
        echo '</div>';
        echo '<p class="firephage-note firephage-note--subtle">' . esc_html__('Adjust WAF login throttling and XML-RPC protection from the FirePhage dashboard. This WordPress tab becomes a live status view while your plan is active.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Protection Snapshot', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-bruteforce-snapshot-badge">' . esc_html($bruteforceWafManaged ? __('Edge', 'firephage-security') : __('Local', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid" id="firephage-bruteforce-metrics">';
        echo wp_kses($this->renderLockedMetricCard($bruteforceWafManaged ? __('Login endpoint', 'firephage-security') : __('Threshold', 'firephage-security'), 'firephage-bruteforce-threshold', $bruteforceWafManaged ? __('WAF managed', 'firephage-security') : '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard($bruteforceWafManaged ? __('XML-RPC', 'firephage-security') : __('Window', 'firephage-security'), 'firephage-bruteforce-window', $bruteforceWafManaged ? __('Protected at edge', 'firephage-security') : '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard($bruteforceWafManaged ? __('Local PHP lockouts', 'firephage-security') : __('Active Lockouts', 'firephage-security'), 'firephage-bruteforce-active-count', $bruteforceWafManaged ? __('Disabled while WAF is active', 'firephage-security') : '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<p class="firephage-note" id="firephage-bruteforce-xmlrpc-note">' . esc_html(($bruteForce['protect_xmlrpc'] ?? false) ? __('XML-RPC authentication is currently covered by the same rate-limit rules.', 'firephage-security') : __('XML-RPC authentication is currently excluded from local brute-force protection.', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-section-spaced" id="firephage-bruteforce-local-history">';
        echo '<div class="firephage-card-head firephage-card-head--bruteforce-history">';
        echo '<div><h3>' . esc_html__('Lockout History', 'firephage-security') . '</h3><p>' . esc_html__('Switch between current local lockouts and recent lockout history without squeezing the tables into narrow columns.', 'firephage-security') . '</p></div>';
        echo '<div class="firephage-subtabs" role="tablist" aria-label="' . esc_attr__('Brute force history views', 'firephage-security') . '">';
        echo '<button type="button" class="firephage-subtab-button is-active" data-bruteforce-view="active" aria-pressed="true">' . esc_html__('Active Lockouts', 'firephage-security') . '</button>';
        echo '<button type="button" class="firephage-subtab-button" data-bruteforce-view="recent" aria-pressed="false">' . esc_html__('Recent Lockout Events', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-bruteforce-view" data-bruteforce-panel="active">';
        echo '<div class="firephage-card-head firephage-card-head--subsection">';
        echo '<h4>' . esc_html__('Active Lockouts', 'firephage-security') . '</h4>';
        /* translators: %d: Number of active brute-force lockouts. */
        echo '<span class="firephage-badge firephage-badge--warning" id="firephage-bruteforce-active-lockouts-badge">' . esc_html(sprintf(__('%d active', 'firephage-security'), (int) ($bruteForce['active_lockouts_count'] ?? 0))) . '</span>';
        echo '</div>';
        echo '<div id="firephage-bruteforce-active-lockouts">' . wp_kses($this->renderBruteForceRows($bruteForce['active_lockouts'] ?? [], true), $this->adminAllowedHtml()) . '</div>';
        echo '</div>';
        echo '<div class="firephage-bruteforce-view" data-bruteforce-panel="recent" hidden>';
        echo '<div class="firephage-card-head firephage-card-head--subsection">';
        echo '<h4>' . esc_html__('Recent Lockout Events', 'firephage-security') . '</h4>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('History', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div id="firephage-bruteforce-recent-events">' . wp_kses($this->renderBruteForceRows($bruteForce['recent_events'] ?? [], false), $this->adminAllowedHtml()) . '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="notifications"' . ($activeTab === 'notifications' ? '' : ' hidden') . '>';
        $notificationChannelAccess = $this->notificationChannelAccess($settings);
        $notificationsPaid = ! empty($notificationChannelAccess['paid']);
        $notificationBadgeClass = $notificationsPaid ? 'good' : 'warning';
        $notificationBadgeLabel = $notificationsPaid ? __('Included', 'firephage-security') : __('Plan Required', 'firephage-security');
        $notificationExtraChannelsNote = $notificationsPaid
            ? __('Slack and webhook routing are managed in FirePhage. The status below reflects your current dashboard setup.', 'firephage-security')
            : __('Webhook and Slack alerts are available after connecting a paid FirePhage plan.', 'firephage-security');
        $notificationChannels = is_array($notificationChannelAccess['alert_channels'] ?? null) ? $notificationChannelAccess['alert_channels'] : [];
        $slackStatus = ! $notificationsPaid
            ? __('Locked', 'firephage-security')
            : (! empty($notificationChannels['slack']['enabled']) && ! empty($notificationChannels['slack']['configured'])
                ? __('Enabled', 'firephage-security')
                : __('Not configured', 'firephage-security'));
        $webhookStatus = ! $notificationsPaid
            ? __('Locked', 'firephage-security')
            : (! empty($notificationChannels['webhook']['enabled']) && ! empty($notificationChannels['webhook']['configured'])
                ? __('Enabled', 'firephage-security')
                : __('Not configured', 'firephage-security'));
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h2>' . esc_html__('Notifications', 'firephage-security') . '</h2>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr(($settings['notifications_enabled'] ?? '1') === '1' ? 'good' : 'neutral') . '">' . esc_html(($settings['notifications_enabled'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Send FirePhage Security emails to the inbox you want to watch, including weekly summaries and immediate scan alerts for malware findings and unexpected WordPress core edits. When both are detected in the same scan, FirePhage sends one combined email instead of two separate alerts.', 'firephage-security') . '</p>';
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
        echo '<p class="firephage-note">' . esc_html__('Weekly reports summarize scans, lockouts, and pending updates. Immediate scan alerts are deduplicated so the same scan does not flood your inbox, and combined malware plus core-edit findings are sent in one email.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Notification Snapshot', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Email', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid firephage-pro-metric-grid--notification">';
        echo wp_kses($this->renderLockedMetricCard(__('Recipient', 'firephage-security'), 'firephage-notification-recipient', '--', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Weekly Report', 'firephage-security'), 'firephage-notification-weekly', '--', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Malware Alerts', 'firephage-security'), 'firephage-notification-malware', '--', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<p class="firephage-note"><strong>' . esc_html__('Last weekly report:', 'firephage-security') . '</strong> <span id="firephage-notification-last-weekly">' . esc_html($notificationState['last_weekly_report_at'] !== '' ? $notificationState['last_weekly_report_at'] : __('Not sent yet', 'firephage-security')) . '</span></p>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head"><span>' . esc_html__('Alert Type', 'firephage-security') . '</span><span>' . esc_html__('Latest Trigger', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-notification-alert-summary">';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Malware', 'firephage-security') . '</span><span>' . esc_html($notificationState['last_malware_alert_scan_id'] !== '' ? $notificationState['last_malware_alert_scan_id'] : __('No alert yet', 'firephage-security')) . '</span><span>' . esc_html(($settings['notifications_alert_malware'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span></div>';
        echo '<div class="firephage-pro-table__row"><span>' . esc_html__('Core edits', 'firephage-security') . '</span><span>' . esc_html($notificationState['last_core_alert_scan_id'] !== '' ? $notificationState['last_core_alert_scan_id'] : __('No alert yet', 'firephage-security')) . '</span><span>' . esc_html(($settings['notifications_alert_core_edits'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security')) . '</span></div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-note firephage-pro-note" id="firephage-notification-pro-note">';
        echo '<strong>' . esc_html__('Extra notification channels', 'firephage-security') . '</strong> ';
        echo esc_html($notificationExtraChannelsNote);
        echo '</div>';
        echo '<div class="firephage-card-head firephage-section-spaced-sm">';
        echo '<h4>' . esc_html__('Extra Alert Channels', 'firephage-security') . '</h4>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($notificationBadgeClass) . '" id="firephage-notification-pro-badge">' . esc_html($notificationBadgeLabel) . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid firephage-pro-metric-grid--notification-channels" id="firephage-notification-pro-fields">';
        echo wp_kses($this->renderLockedMetricCard(__('Webhook', 'firephage-security'), 'firephage-notification-webhook-status', $webhookStatus, 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Slack', 'firephage-security'), 'firephage-notification-slack-status', $slackStatus, 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<div class="firephage-inline-actions firephage-inline-actions--quiet firephage-section-spaced">';
        echo '<button type="button" class="button-link firephage-link-button" data-tab-target="firewall">' . esc_html__('View Pro protection', 'firephage-security') . '</button>';
        echo '<button type="button" class="button-link firephage-link-button" data-tab-target="performance">' . esc_html__('View Pro performance', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="connect"' . ($activeTab === 'connect' ? '' : ' hidden') . '>';
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card">';
        echo '<h2>' . esc_html__('Connect to FirePhage', 'firephage-security') . '</h2>';
        echo '<p>' . esc_html__('Generate a connection token in your FirePhage dashboard, paste it here, and the plugin will exchange it for a site-specific credential for dashboard sync.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note">' . esc_html__('This paid connection is optional. Local scans, local protection, and checksum lookups work without it. The free signature token is a separate option for fresher malware signatures.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note firephage-note--subtle">' . sprintf(
            /* translators: %s: FirePhage link */
            wp_kses_post(__('Need to finish setup in FirePhage first? <a href="%s" target="_blank" rel="noopener noreferrer">Open the dashboard</a>.', 'firephage-security')),
            esc_url($this->firephageTrackedUrl($settings, 'connect', 'open_dashboard'))
        ) . '</p>';
        echo '<form id="firephage-connect-form" data-connected="' . esc_attr($isConnected ? '1' : '0') . '">';
        echo '<label class="firephage-field"><span>' . esc_html__('Dashboard URL', 'firephage-security') . '</span><input type="url" name="dashboard_url" value="' . esc_attr($settings['dashboard_url']) . '" ' . disabled($isConnected, true, false) . ' /></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Connection token', 'firephage-security') . '</span><input type="password" name="connection_token" value="' . esc_attr($settings['connection_token']) . '" autocomplete="off" ' . disabled($isConnected, true, false) . ' /></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="auto_sync_reports" value="1" ' . checked($settings['auto_sync_reports'], '1', false) . ' /><span>' . esc_html__('Automatically send scheduled local reports after connection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="submit" class="button button-primary firephage-connect-submit" ' . disabled($isConnected, true, false) . '>' . esc_html__('Connect Plugin', 'firephage-security') . '</button>';
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
        echo '<p class="firephage-note">' . esc_html__('The free token enables fresher FirePhage signature updates for local malware detection. It is separate from the paid dashboard connection, and the marketing opt-in remains optional.', 'firephage-security') . '</p>';
        echo '<div class="firephage-inline-actions">';
        echo '<button type="button" class="button button-secondary firephage-open-free-token-modal">' . esc_html__('Manage Free Token', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-check-free-token-status" style="' . esc_attr(($settings['free_signature_token_status'] ?? 'pending') === 'awaiting_verification' ? '' : 'display:none;') . '">' . esc_html__('Check Verification Status', 'firephage-security') . '</button>';
        echo '</div>';
        echo '<p><strong>' . esc_html__('Connected site ID:', 'firephage-security') . '</strong> <span id="firephage-connected-site-id">' . esc_html($settings['site_id'] !== '' ? $settings['site_id'] : __('Not connected', 'firephage-security')) . '</span></p>';
        echo '<p class="firephage-note">' . esc_html__('FirePhage issues a site-specific token after you connect so reports can be matched to the correct dashboard site without relying on the domain name alone.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="firewall"' . ($activeTab === 'firewall' ? '' : ' hidden') . '>';
        echo '<div class="firephage-pro-shell">';
        if (! $remoteProEnabled) {
            echo '<div class="firephage-pro-shell__hero">';
            echo '<div>';
            echo '<p class="firephage-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p>';
            echo '<h2>' . esc_html__('Firewall Control', 'firephage-security') . '</h2>';
            echo '<p>' . esc_html__('The plugin handles local login safeguards and scan-driven protection checks. Connect FirePhage when you want live traffic filtering, edge protection, and real firewall visibility from the network layer.', 'firephage-security') . '</p>';
            echo '</div>';
            echo '<span class="firephage-pro-badge">' . esc_html__('Pro', 'firephage-security') . '</span>';
            echo '</div>';
        }
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<div><h3>' . esc_html__('Firewall Status', 'firephage-security') . '</h3></div>';
        echo '<div class="firephage-card-head__actions">';
        echo '<label class="firephage-compact-select"><span class="screen-reader-text">' . esc_html__('Firewall time range', 'firephage-security') . '</span><select id="firephage-firewall-range"><option value="24h">' . esc_html__('24 hours', 'firephage-security') . '</option><option value="7d">' . esc_html__('7 days', 'firephage-security') . '</option></select></label>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-firewall-status-badge">' . esc_html__('Waiting', 'firephage-security') . '</span>';
        echo '</div>';
        echo '</div>';
        echo '<p id="firephage-firewall-summary-text">' . esc_html__('FirePhage will load current zone health, recent attack counts, and recent firewall decisions here for paid connected sites.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note" id="firephage-firewall-connection-note">' . esc_html($remoteProEnabled
            ? __('Local plugin safeguards still protect login attempts and XML-RPC traffic on this WordPress site. FirePhage WAF adds the edge-side layer before traffic reaches WordPress.', 'firephage-security')
            : __('This site is currently using local WordPress protection only. Connect a paid FirePhage site to add edge filtering and live firewall analytics before traffic reaches WordPress.', 'firephage-security')) . '</p>';
        echo '<div class="firephage-pro-metric-grid">';
        echo wp_kses($this->renderLockedMetricCard(__('Total Requests', 'firephage-security'), 'firephage-firewall-total-requests', '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Requests Blocked', 'firephage-security'), 'firephage-firewall-requests-blocked', '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Challenge Rate', 'firephage-security'), 'firephage-firewall-challenge-rate', '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Bot Pressure', 'firephage-security'), 'firephage-firewall-bot-pressure', '', 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<div class="firephage-context-bar firephage-context-bar--rules firephage-section-spaced">';
        echo '<p>' . esc_html($remoteProEnabled
            ? __('Local plugin safeguards still protect login attempts and XML-RPC traffic on this WordPress site. FirePhage WAF adds the edge-side layer before traffic reaches WordPress.', 'firephage-security')
            : __('Firewall metrics and configured access rules are available only on connected paid FirePhage sites. Local login protection and XML-RPC safeguards continue to run in WordPress.', 'firephage-security')) . '</p>';
        echo '</div>';
        echo '<div class="firephage-pro-metric-grid firephage-pro-metric-grid--local firephage-section-spaced">';
        echo wp_kses($this->renderLockedMetricCard(__('Login protection', 'firephage-security'), '', ($settings['bruteforce_enabled'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security'), 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('XML-RPC rules', 'firephage-security'), '', ($settings['bruteforce_protect_xmlrpc'] ?? '1') === '1' ? __('Enabled', 'firephage-security') : __('Disabled', 'firephage-security'), 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo wp_kses($this->renderLockedMetricCard(__('Local scanner', 'firephage-security'), '', __('Available', 'firephage-security'), 'firephage-pro-metric__value--compact'), $this->adminAllowedHtml());
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Recent Firewall Activity', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-firewall-activity-badge">' . esc_html__('Waiting', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<div class="firephage-pro-table">';
        echo '<div class="firephage-pro-table__row firephage-pro-table__row--head firephage-pro-table__row--activity"><span>' . esc_html__('Time', 'firephage-security') . '</span><span>' . esc_html__('Action', 'firephage-security') . '</span><span>' . esc_html__('Path', 'firephage-security') . '</span><span>' . esc_html__('Source', 'firephage-security') . '</span></div>';
        echo '<div id="firephage-firewall-activity-body"></div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-section-spaced">';
        echo '<div class="firephage-card firephage-pro-card firephage-preview-card" id="firephage-firewall-preview-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Traffic Insights', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-firewall-insights-badge">' . esc_html__('Preview', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p id="firephage-firewall-insights-summary">' . esc_html__('Live traffic insights become available after connecting FirePhage. This preview shows the kinds of patterns you can review once edge analytics are enabled.', 'firephage-security') . '</p>';
        echo '<div class="firephage-preview-split">';
        echo '<div class="firephage-preview-panel" id="firephage-firewall-countries-panel">';
        echo '<h4>' . esc_html__('Traffic by country', 'firephage-security') . '</h4>';
        echo wp_kses($this->renderFirewallPreviewBar(__('United States', 'firephage-security'), '72%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('Germany', 'firephage-security'), '41%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('United Kingdom', 'firephage-security'), '33%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('Japan', 'firephage-security'), '19%'), $this->adminAllowedHtml());
        echo '</div>';
        echo '<div class="firephage-preview-panel" id="firephage-firewall-ips-panel">';
        echo '<h4>' . esc_html__('Top IPs', 'firephage-security') . '</h4>';
        echo wp_kses($this->renderFirewallPreviewBar(__('Allowed requests', 'firephage-security'), '88%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('Blocked requests', 'firephage-security'), '24%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('Challenge rate', 'firephage-security'), '17%'), $this->adminAllowedHtml());
        echo wp_kses($this->renderFirewallPreviewBar(__('Bot activity', 'firephage-security'), '29%'), $this->adminAllowedHtml());
        echo '</div>';
        echo '</div>';
        echo '<p class="firephage-note firephage-note--subtle firephage-preview-note" id="firephage-firewall-insights-note">' . esc_html__('Preview values are illustrative only. Connect FirePhage to load real firewall events and live traffic patterns for this site.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-section-spaced">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Protected Controls', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--warning" id="firephage-firewall-controls-badge">' . esc_html__('Waiting', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p id="firephage-firewall-controls-note">' . esc_html__('Managed live at the FirePhage edge. Add new rules below and review every blocked or allowlisted entry in one configured access rules table.', 'firephage-security') . '</p>';
        echo '<div class="firephage-firewall-mode-card firephage-section-spaced"><span class="firephage-firewall-mode-card__label">' . esc_html__('Protection mode', 'firephage-security') . '</span><strong id="firephage-firewall-protection-mode">' . esc_html__('Adaptive WAF', 'firephage-security') . '</strong><small>' . esc_html__('Protection adapts at the edge before traffic reaches WordPress.', 'firephage-security') . '</small></div>';
        echo '<div class="firephage-pro-fieldset firephage-pro-fieldset--actions firephage-section-spaced">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Block IP', 'firephage-security') . '</span><div class="firephage-inline-actions"><input type="text" id="firephage-firewall-block-ip" placeholder="' . esc_attr__('203.0.113.10', 'firephage-security') . '" ' . disabled($remoteProEnabled, false, false) . ' /><button type="button" class="button button-secondary" id="firephage-firewall-block-ip-button" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Block', 'firephage-security') . '</button></div></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Allowlist IP', 'firephage-security') . '</span><div class="firephage-inline-actions"><input type="text" id="firephage-firewall-allow-ip" placeholder="' . esc_attr__('198.51.100.20', 'firephage-security') . '" ' . disabled($remoteProEnabled, false, false) . ' /><button type="button" class="button button-secondary" id="firephage-firewall-allow-ip-button" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Allow', 'firephage-security') . '</button></div></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Block country', 'firephage-security') . '</span><div class="firephage-inline-actions"><select id="firephage-firewall-block-country" ' . disabled($remoteProEnabled, false, false) . '><option value="">' . esc_html__('Search and choose a country...', 'firephage-security') . '</option></select><button type="button" class="button button-secondary" id="firephage-firewall-block-country-button" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Block', 'firephage-security') . '</button></div></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Block continent', 'firephage-security') . '</span><div class="firephage-inline-actions"><select id="firephage-firewall-block-continent" ' . disabled($remoteProEnabled, false, false) . '><option value="">' . esc_html__('Search and choose a continent...', 'firephage-security') . '</option></select><button type="button" class="button button-secondary" id="firephage-firewall-block-continent-button" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Block', 'firephage-security') . '</button></div></label>';
        echo '</div>';
        echo '<div class="firephage-context-bar firephage-section-spaced">';
        echo '<p>' . esc_html__('Configured Access Rules mirrors the FirePhage dashboard. Switch between IP, country, and continent rules here, then enable, disable, or remove each entry directly from WordPress.', 'firephage-security') . '</p>';
        echo '</div>';
        echo '<div class="firephage-card-head firephage-card-head--subsection firephage-section-spaced">';
        echo '<div><h4>' . esc_html__('Configured Access Rules', 'firephage-security') . '</h4><p>' . esc_html__('Review active and disabled rules by target type.', 'firephage-security') . '</p></div>';
        echo '<div class="firephage-subtabs" id="firephage-firewall-rule-tabs">';
        echo '<button type="button" class="firephage-subtab-button is-active" data-firewall-rule-tab="ip">' . esc_html__('IPs', 'firephage-security') . '</button>';
        echo '<button type="button" class="firephage-subtab-button" data-firewall-rule-tab="country">' . esc_html__('Countries', 'firephage-security') . '</button>';
        echo '<button type="button" class="firephage-subtab-button" data-firewall-rule-tab="continent">' . esc_html__('Continents', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-pro-table firephage-section-spaced" data-firewall-rule-panel="ip"><div class="firephage-pro-table__row firephage-pro-table__row--head firephage-pro-table__row--rules"><span>' . esc_html__('Target', 'firephage-security') . '</span><span>' . esc_html__('Action', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span><span>' . esc_html__('Source', 'firephage-security') . '</span><span>' . esc_html__('Manage', 'firephage-security') . '</span></div><div id="firephage-firewall-rules-ip"></div></div>';
        echo '<div class="firephage-pro-table firephage-section-spaced" data-firewall-rule-panel="country" hidden><div class="firephage-pro-table__row firephage-pro-table__row--head firephage-pro-table__row--rules"><span>' . esc_html__('Target', 'firephage-security') . '</span><span>' . esc_html__('Action', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span><span>' . esc_html__('Source', 'firephage-security') . '</span><span>' . esc_html__('Manage', 'firephage-security') . '</span></div><div id="firephage-firewall-rules-country"></div></div>';
        echo '<div class="firephage-pro-table firephage-section-spaced" data-firewall-rule-panel="continent" hidden><div class="firephage-pro-table__row firephage-pro-table__row--head firephage-pro-table__row--rules"><span>' . esc_html__('Target', 'firephage-security') . '</span><span>' . esc_html__('Action', 'firephage-security') . '</span><span>' . esc_html__('State', 'firephage-security') . '</span><span>' . esc_html__('Source', 'firephage-security') . '</span><span>' . esc_html__('Manage', 'firephage-security') . '</span></div><div id="firephage-firewall-rules-continent"></div></div>';
        echo '</div>';
        if (! $remoteProEnabled) {
            echo '<div class="firephage-card firephage-pro-upgrade" id="firephage-firewall-upgrade-card">';
            echo '<h3>' . esc_html__('Unlock Firewall Management', 'firephage-security') . '</h3>';
            echo '<p>' . esc_html__('Connect this site to FirePhage Pro to review live firewall events, inspect edge protection decisions, and manage WAF controls from WordPress.', 'firephage-security') . '</p>';
            echo '<div class="firephage-inline-actions">';
            echo '<a class="button button-primary" href="' . esc_url($this->firephageTrackedUrl($settings, 'firewall', 'connect_live_data')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Purchase Pro Plan', 'firephage-security') . '</a>';
            echo '<button type="button" class="button-link firephage-link-button" data-tab-target="connect">' . esc_html__('Open connection settings', 'firephage-security') . '</button>';
            echo '</div>';
            echo '</div>';
        }
        echo '</div>';
        echo '</section>';

        echo '<section class="firephage-tab-panel" data-panel="performance"' . ($activeTab === 'performance' ? '' : ' hidden') . '>';
        echo '<div class="firephage-pro-shell">';
        if (! $remoteProEnabled) {
            echo '<div class="firephage-pro-shell__hero">';
            echo '<div>';
            echo '<p class="firephage-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p>';
            echo '<h2>' . esc_html__('Performance', 'firephage-security') . '</h2>';
            echo '<p>' . esc_html__('Put CDN and cache controls in one place so connected paid sites can review acceleration, purge flows, and edge behavior directly from the plugin.', 'firephage-security') . '</p>';
            echo '</div>';
            echo '<span class="firephage-pro-badge">' . esc_html__('Pro', 'firephage-security') . '</span>';
            echo '</div>';
        }
        echo '<div class="firephage-grid firephage-grid--2">';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('CDN', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral" id="firephage-performance-status-badge">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p id="firephage-performance-summary-text">' . esc_html__('FirePhage will load edge status, cache efficiency, traffic routing, and delivery behavior here for paid connected sites.', 'firephage-security') . '</p>';
        echo '<p class="firephage-note" id="firephage-performance-connection-note">' . esc_html__('Connect FirePhage to load performance data. An active paid plan unlocks the live CDN and cache telemetry shown here.', 'firephage-security') . '</p>';
        echo '<div class="firephage-pro-fieldset">';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Traffic routing', 'firephage-security') . '</span><input type="text" id="firephage-performance-routing" value="' . esc_attr__('Connect to load edge routing status', 'firephage-security') . '" disabled /></label>';
        echo '<label class="firephage-pro-field"><span>' . esc_html__('Troubleshooting mode', 'firephage-security') . '</span><input type="text" id="firephage-performance-troubleshooting" value="' . esc_attr__('Disabled', 'firephage-security') . '" disabled /></label>';
        echo '<label class="firephage-pro-field firephage-toggle"><input type="checkbox" id="firephage-performance-image-optimization" checked disabled /><span>' . esc_html__('Smart image optimization', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-pro-field firephage-toggle"><input type="checkbox" id="firephage-performance-edge-compression" checked disabled /><span>' . esc_html__('Edge compression', 'firephage-security') . '</span></label>';
        echo '</div>';
        echo '<div class="firephage-inline-actions firephage-section-spaced">';
        echo '<button type="button" class="button button-secondary" id="firephage-performance-purge-cache" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Purge Edge Cache', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary" id="firephage-performance-toggle-troubleshooting" ' . disabled($remoteProEnabled, false, false) . '>' . esc_html__('Enable Troubleshooting Mode', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-card firephage-pro-card">';
        echo '<div class="firephage-card-head">';
        echo '<h3>' . esc_html__('Cache', 'firephage-security') . '</h3>';
        echo '<span class="firephage-badge firephage-badge--neutral">' . esc_html__('Locked', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<p>' . esc_html__('Use this panel for purge actions, bypass rules, cache TTL presets, and page-specific exclusions once this site is connected.', 'firephage-security') . '</p>';
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
        if (! $remoteProEnabled) {
            echo '<div class="firephage-card firephage-pro-upgrade firephage-section-spaced" id="firephage-performance-upgrade-card">';
            echo '<div class="firephage-card-head">';
            echo '<h3>' . esc_html__('Unlock FirePhage Performance', 'firephage-security') . '</h3>';
            echo '<span class="firephage-badge firephage-badge--warning">' . esc_html__('Pro Required', 'firephage-security') . '</span>';
            echo '</div>';
            echo '<p>' . esc_html__('Upgrade to manage CDN delivery and cache behavior from WordPress, then use the plugin as a lightweight control surface for your connected FirePhage site.', 'firephage-security') . '</p>';
            echo '<div class="firephage-inline-actions">';
            echo '<a class="button button-primary" href="' . esc_url($this->firephageTrackedUrl($settings, 'performance', 'connect_live_data')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Purchase Pro Plan', 'firephage-security') . '</a>';
            echo '<button type="button" class="button-link firephage-link-button" data-tab-target="connect">' . esc_html__('Open connection settings', 'firephage-security') . '</button>';
            echo '</div>';
            echo '</div>';
        }
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
        echo '<div id="firephage-preview-modal-content"></div>';
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
        echo '<label class="firephage-toggle"><input type="checkbox" name="use_firephage_checksum_cache" value="1" ' . checked($settings['use_firephage_checksum_cache'] ?? '0', '1', false) . ' /><span>' . esc_html__('Use FirePhage checksum cache first for package verification', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="use_firephage_signature_feed" value="1" ' . checked($settings['use_firephage_signature_feed'] ?? '1', '1', false) . ' /><span>' . esc_html__('Use FirePhage signature updates for local malware detection', 'firephage-security') . '</span></label>';
        echo '<div class="firephage-inline-summary">';
        echo '<span class="firephage-inline-summary__label">' . esc_html__('Token status', 'firephage-security') . '</span>';
        echo '<span class="firephage-badge firephage-badge--' . esc_attr($this->freeTokenStatusTone($settings)) . '" id="firephage-free-token-settings-badge">' . esc_html($this->freeTokenStatusLabel($settings)) . '</span>';
        echo '</div>';
        echo '<div class="firephage-inline-summary">';
        echo '<span class="firephage-inline-summary__label">' . esc_html__('Last signature update', 'firephage-security') . '</span>';
        echo '<span class="firephage-inline-summary__value" id="firephage-signature-last-refreshed">' . esc_html($this->formatRecordedTimeLabel((string) ($settings['signature_feed_last_refreshed_at'] ?? ''))) . '</span>';
        echo '</div>';
        echo '<p class="firephage-note" id="firephage-free-token-settings-summary">' . esc_html($this->freeTokenSummary($settings)) . '</p>';
        echo '<div class="firephage-modal-feedback" id="firephage-scanner-settings-feedback" hidden aria-live="polite"></div>';
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
        echo '<p class="firephage-note">' . esc_html__('Use one exclusion per line. Wildcards are supported, so paths like /wp-content/cache/* or filenames like *.log can be skipped during scan discovery. When enabled, FirePhage checksum cache is used first and WordPress.org remains fallback. This sends only package type, slug, and version. FirePhage signature updates require a free token, are fetched as data only, cached locally, and the bundled fallback signatures remain available if FirePhage is unreachable.', 'firephage-security') . '</p>';
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
        echo '<div class="firephage-modal-feedback" id="firephage-free-token-feedback" hidden aria-live="polite"></div>';
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
        echo '<div class="firephage-modal" id="firephage-setup-wizard-modal" hidden>';
        echo '<div class="firephage-modal-backdrop" data-setup-wizard-close="1"></div>';
        echo '<div class="firephage-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="firephage-setup-wizard-title">';
        echo '<div class="firephage-modal-head">';
        echo '<h3 id="firephage-setup-wizard-title">' . esc_html__('Recommended First-Time Setup', 'firephage-security') . '</h3>';
        echo '<button type="button" class="button-link firephage-modal-close" data-setup-wizard-close="1" aria-label="' . esc_attr__('Close setup wizard', 'firephage-security') . '">&times;</button>';
        echo '</div>';
        echo '<div class="firephage-setup-steps">';
        echo '<span class="firephage-setup-step-indicator is-active" data-step-indicator="token">' . esc_html__('1. Free Token', 'firephage-security') . '</span>';
        echo '<span class="firephage-setup-step-indicator" data-step-indicator="settings">' . esc_html__('2. Recommended Settings', 'firephage-security') . '</span>';
        echo '</div>';
        echo '<form id="firephage-setup-wizard-form">';
        echo '<div class="firephage-modal-feedback" id="firephage-setup-wizard-feedback" hidden aria-live="polite"></div>';
        echo '<div class="firephage-setup-step" data-setup-step="token">';
        echo '<p>' . esc_html__('Start with the optional free FirePhage token for fresher malware signatures. It is separate from the paid dashboard connection, and the promo checkbox stays optional.', 'firephage-security') . '</p>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="request_free_token" value="1" checked /><span>' . esc_html__('Email me a free FirePhage token for fresher signature updates', 'firephage-security') . '</span></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Email address', 'firephage-security') . '</span><input type="email" name="setup_token_email" value="' . esc_attr(($settings['free_signature_token_email'] ?? '') !== '' ? $settings['free_signature_token_email'] : get_option('admin_email', '')) . '" /></label>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="setup_marketing_opt_in" value="1" ' . checked($settings['free_signature_token_marketing_opt_in'] ?? '0', '1', false) . ' /><span>' . esc_html__('I want to receive occasional FirePhage promo codes, Pro offers, and product updates', 'firephage-security') . '</span></label>';
        echo '<p class="firephage-note firephage-note--subtle">' . esc_html__('You can skip this and keep using the bundled local signatures. If you request the free token, verify the email link later to activate remote signature updates.', 'firephage-security') . '</p>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary" data-setup-wizard-close="1">' . esc_html__('Not now', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-primary firephage-setup-wizard-next">' . esc_html__('Next', 'firephage-security') . '</button>';
        echo '</div>';
        echo '</div>';
        echo '<div class="firephage-setup-step" data-setup-step="settings" hidden>';
        echo '<p>' . esc_html__('Choose how often FirePhage should scan this site and how strict local login protection should be. When you finish, FirePhage will start the first deep scan automatically.', 'firephage-security') . '</p>';
        echo '<label class="firephage-toggle"><input type="checkbox" name="use_firephage_checksum_cache" value="1" checked /><span>' . esc_html__('Use FirePhage checksum cache first for package verification', 'firephage-security') . '</span></label>';
        echo '<p class="firephage-note firephage-note--subtle">' . esc_html__('This first-run choice is optional. If you leave this enabled, FirePhage is used as the main checksum source and WordPress.org remains available as fallback when needed. This sends only package type, slug, and version. You can turn this off later at any time from Scanner Settings if you change your mind.', 'firephage-security') . '</p>';
        echo '<label class="firephage-field"><span>' . esc_html__('Automatic malware scans', 'firephage-security') . '</span><select name="malware_auto_scan_interval">';
        echo '<option value="daily">' . esc_html__('Once per day', 'firephage-security') . '</option>';
        echo '<option value="twice_daily" selected>' . esc_html__('Twice per day (recommended)', 'firephage-security') . '</option>';
        echo '<option value="four_times_daily">' . esc_html__('Four times per day', 'firephage-security') . '</option>';
        echo '</select></label>';
        echo '<label class="firephage-field"><span>' . esc_html__('Local login protection', 'firephage-security') . '</span><select name="bruteforce_profile">';
        echo '<option value="basic">' . esc_html__('Basic', 'firephage-security') . '</option>';
        echo '<option value="recommended" selected>' . esc_html__('Recommended', 'firephage-security') . '</option>';
        echo '<option value="strict">' . esc_html__('Stricter', 'firephage-security') . '</option>';
        echo '</select></label>';
        echo '<p class="firephage-note firephage-note--subtle">' . esc_html__('Recommended settings enable automatic scans twice per day, a balanced local login-protection profile with XML-RPC protection turned on, and FirePhage checksum cache as the primary verification source.', 'firephage-security') . '</p>';
        echo '<div class="firephage-modal-actions">';
        echo '<button type="button" class="button button-secondary firephage-setup-wizard-back">' . esc_html__('Back', 'firephage-security') . '</button>';
        echo '<button type="button" class="button button-secondary firephage-apply-recommended-setup">' . esc_html__('Apply Recommended Settings', 'firephage-security') . '</button>';
        echo '<button type="submit" class="button button-primary firephage-save-setup-wizard">' . esc_html__('Save and Start First Scan', 'firephage-security') . '</button>';
        echo '</div>';
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

        // Nonce and capability checks are handled centrally in assertAjaxPermissions().
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $forceNew = isset($_POST['force_new']) && sanitize_text_field((string) wp_unslash($_POST['force_new'])) === '1';
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $scanMode = sanitize_text_field((string) wp_unslash($_POST['scan_mode'] ?? 'deep'));
        $result = $this->scanner->startScan($forceNew, $scanMode);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => sanitize_text_field($result->get_error_message())], 400);
        }

        wp_send_json_success(['state' => $result]);
    }

    public function handleStopScan(): void
    {
        $this->assertAjaxPermissions();

        $result = $this->scanner->stopScan();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => sanitize_text_field($result->get_error_message())], 400);
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

    public function handleProcessScanBatch(): void
    {
        $this->assertAjaxPermissions();
        $this->scanner->processBatch();
        wp_send_json_success(['state' => $this->scanner->getState()]);
    }

    public function handlePreviewFile(): void
    {
        $this->assertAjaxPermissions();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $file = sanitize_text_field((string) wp_unslash($_POST['file'] ?? ''));
        $result = $this->scanner->previewFile($file);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => sanitize_text_field($result->get_error_message())], 400);
        }

        wp_send_json_success($result);
    }

    public function handleCompareFile(): void
    {
        $this->assertAjaxPermissions();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $file = sanitize_text_field((string) wp_unslash($_POST['file'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $source = sanitize_text_field((string) wp_unslash($_POST['source'] ?? ''));
        $result = $this->scanner->compareFile($file, $source);

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => sanitize_text_field($result->get_error_message())], 400);
        }

        wp_send_json_success($result);
    }

    public function handleRestoreFile(): void
    {
        $this->assertAjaxPermissions();
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $file = sanitize_text_field((string) wp_unslash($_POST['file'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $source = sanitize_text_field((string) wp_unslash($_POST['source'] ?? ''));
        $result = $this->scanner->restoreIntegrityFile($file, $source);

        wp_send_json_success([
            'message' => sanitize_text_field((string) ($result['message'] ?? __('The file restore request has been processed.', 'firephage-security'))),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
    }

    public function handleRestoreAllIntegrityFiles(): void
    {
        $this->assertAjaxPermissions();
        $result = $this->scanner->restoreAllIntegrityFiles();

        wp_send_json_success([
            'message' => sprintf(
                /* translators: 1: Number of restored files. 2: Number of skipped files. */
                __('Restored %1$d modified files. Skipped %2$d files that could not be restored.', 'firephage-security'),
                (int) ($result['restored_files'] ?? 0),
                (int) ($result['skipped_files'] ?? 0)
            ),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
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
                /* translators: 1: Number of deleted files. 2: Number of skipped files. */
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
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $file = sanitize_text_field((string) wp_unslash($_POST['file'] ?? ''));
        $result = $this->scanner->deleteSuspiciousFile($file);

        wp_send_json_success([
            'message' => sanitize_text_field((string) ($result['message'] ?? __('The request has been processed.', 'firephage-security'))),
            'state' => $result['state'] ?? $this->scanner->getState(),
        ]);
    }

    public function handleDeleteSelectedSuspiciousFiles(): void
    {
        $this->assertAjaxPermissions();
        // phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Verified in assertAjaxPermissions(); entries are unslashed and sanitized immediately below.
        $rawFiles = isset($_POST['files']) && is_array($_POST['files']) ? $_POST['files'] : [];
        // phpcs:enable
        $files = array_map('sanitize_text_field', array_map('wp_unslash', $rawFiles));
        $result = $this->scanner->deleteSelectedSuspiciousFiles($files);

        wp_send_json_success([
            'message' => sprintf(
                /* translators: 1: Number of deleted files. 2: Number of skipped files. */
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
        $report = $this->reportBuilder->build(true);
        $settings = $this->settings->all();
        $health = is_array($report['health'] ?? null) ? $report['health'] : [];
        $scan = is_array($report['malware_scan'] ?? null) ? $report['malware_scan'] : [];
        $bruteForce = is_array($report['brute_force'] ?? null) ? $report['brute_force'] : [];
        $securityScore = $this->buildSecurityScore($health, $scan, $bruteForce, $settings);

        wp_send_json_success([
            'report' => $report,
            'security_score' => $securityScore,
            'overview_status' => $this->buildOverviewStatus($health, $scan, $bruteForce, $settings, $securityScore),
        ]);
    }

    public function handleRefreshSignatures(): void
    {
        $this->assertAjaxPermissions();
        $result = $this->scanner->refreshSignatureFeed();

        if (is_wp_error($result)) {
            wp_send_json_error(['message' => sanitize_text_field($result->get_error_message())], 400);
        }

        $refreshedAt = current_time('mysql');
        $this->settings->update([
            'signature_feed_last_refreshed_at' => $refreshedAt,
        ]);

        wp_send_json_success([
            'message' => __('FirePhage signatures were refreshed.', 'firephage-security'),
            'last_refreshed_at' => $refreshedAt,
            'last_refreshed_label' => $this->formatRecordedTimeLabel($refreshedAt),
        ]);
    }

    public function handleSaveBruteForceSettings(): void
    {
        $this->assertAjaxPermissions();
        // Settings values are sanitized in BruteForceProtection::saveSettings().
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Verified in assertAjaxPermissions(); values sanitized in saveSettings().
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
        // Individual values are normalized before saving below.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Verified in assertAjaxPermissions(); values sanitized below.
        $settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];

        $this->settings->update([
            'malware_auto_scans_enabled' => ! empty($settings['malware_auto_scans_enabled']) ? '1' : '0',
            'use_firephage_checksum_cache' => ! empty($settings['use_firephage_checksum_cache']) ? '1' : '0',
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
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $email = sanitize_email((string) wp_unslash($_POST['email'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $marketingOptIn = ! empty($_POST['marketing_opt_in']);

        if ($serviceUrl === '' || $email === '') {
            wp_send_json_error(['message' => __('A valid FirePhage service URL and email address are required.', 'firephage-security')], 400);
        }

        $response = $this->client->registerFreeToken($serviceUrl, $email, $marketingOptIn);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
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
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
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
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $verificationToken = sanitize_text_field((string) wp_unslash($_POST['verification_token'] ?? ''));

        if ($serviceUrl === '' || $verificationToken === '') {
            wp_send_json_error(['message' => __('A valid verification request is required.', 'firephage-security')], 400);
        }

        $response = $this->client->verifyFreeToken($serviceUrl, $verificationToken);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
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

    public function handleDismissSetupWizard(): void
    {
        $this->assertAjaxPermissions();

        update_option('firephage_security_setup_wizard_seen', '1', false);
        delete_option('firephage_security_show_setup_wizard');

        wp_send_json_success([
            'message' => __('You can finish setup later from the plugin settings whenever you are ready.', 'firephage-security'),
        ]);
    }

    public function handleCompleteSetupWizard(): void
    {
        $this->assertAjaxPermissions();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $mode = sanitize_text_field((string) wp_unslash($_POST['mode'] ?? 'custom'));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $interval = sanitize_text_field((string) wp_unslash($_POST['malware_auto_scan_interval'] ?? 'twice_daily'));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $profile = sanitize_text_field((string) wp_unslash($_POST['bruteforce_profile'] ?? 'recommended'));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $useChecksumCache = sanitize_text_field((string) wp_unslash($_POST['use_firephage_checksum_cache'] ?? '1')) === '1' ? '1' : '0';

        if ($mode === 'recommended') {
            $interval = 'twice_daily';
            $profile = 'recommended';
            $useChecksumCache = '1';
        }

        if (! in_array($interval, ['daily', 'twice_daily', 'four_times_daily'], true)) {
            $interval = 'twice_daily';
        }

        $profiles = [
            'basic' => [
                'bruteforce_enabled' => '1',
                'bruteforce_threshold' => '6',
                'bruteforce_window_minutes' => '15',
                'bruteforce_lockout_minutes' => '20',
                'bruteforce_protect_xmlrpc' => '0',
            ],
            'recommended' => [
                'bruteforce_enabled' => '1',
                'bruteforce_threshold' => '5',
                'bruteforce_window_minutes' => '15',
                'bruteforce_lockout_minutes' => '30',
                'bruteforce_protect_xmlrpc' => '1',
            ],
            'strict' => [
                'bruteforce_enabled' => '1',
                'bruteforce_threshold' => '4',
                'bruteforce_window_minutes' => '15',
                'bruteforce_lockout_minutes' => '45',
                'bruteforce_protect_xmlrpc' => '1',
            ],
        ];

        $selectedProfile = $profiles[$profile] ?? $profiles['recommended'];

        $this->settings->update(array_merge($selectedProfile, [
            'malware_auto_scans_enabled' => '1',
            'malware_auto_scan_interval' => $interval,
            'use_firephage_checksum_cache' => $useChecksumCache,
        ]));

        update_option('firephage_security_setup_wizard_seen', '1', false);
        delete_option('firephage_security_show_setup_wizard');
        do_action('firephage_security_settings_changed');

        $scanResult = $this->scanner->startScan(true, 'deep');
        $message = __('Setup saved. Your first deep scan has started.', 'firephage-security');
        $scanStarted = ! is_wp_error($scanResult);

        if (! $scanStarted) {
            $message = __('Setup saved. FirePhage could not start the first scan automatically, so you can start it from the Malware Scanner tab.', 'firephage-security');
        }

        wp_send_json_success([
            'message' => $message,
            'settings' => $this->settings->all(),
            'bruteforce_summary' => $this->bruteForceProtection->getSummary(),
            'scan_started' => $scanStarted,
            'scan_state' => $scanStarted && is_array($scanResult) ? $scanResult : $this->scanner->getState(),
        ]);
    }

    public function handleSaveNotificationSettings(): void
    {
        $this->assertAjaxPermissions();
        $current = $this->settings->all();
        // Individual values are normalized before saving below.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Verified in assertAjaxPermissions(); values sanitized below.
        $settings = isset($_POST['settings']) && is_array($_POST['settings']) ? wp_unslash($_POST['settings']) : [];

        $updatedSettings = [
            'notifications_enabled' => ! empty($settings['notifications_enabled']) ? '1' : '0',
            'notification_email' => sanitize_email((string) ($settings['notification_email'] ?? $current['notification_email'])),
            'notifications_weekly_report' => ! empty($settings['notifications_weekly_report']) ? '1' : '0',
            'notifications_alert_malware' => ! empty($settings['notifications_alert_malware']) ? '1' : '0',
            'notifications_alert_core_edits' => ! empty($settings['notifications_alert_core_edits']) ? '1' : '0',
            'notifications_webhook_url' => esc_url_raw((string) ($settings['notifications_webhook_url'] ?? $current['notifications_webhook_url'])),
            'notifications_slack_channel' => esc_url_raw((string) ($settings['notifications_slack_channel'] ?? $current['notifications_slack_channel'])),
            'notifications_phone' => sanitize_text_field((string) ($settings['notifications_phone'] ?? $current['notifications_phone'])),
        ];

        $this->settings->update($updatedSettings);
        do_action('firephage_security_settings_changed');

        $savedSettings = $this->settings->all();
        $message = __('Notification settings were saved.', 'firephage-security');

        if (($savedSettings['connection_status'] ?? '') === 'connected' && ($savedSettings['site_token'] ?? '') !== '' && ($savedSettings['site_id'] ?? '') !== '') {
            $syncResponse = $this->client->syncAlertChannels($savedSettings, $updatedSettings);

            if (is_wp_error($syncResponse)) {
                $message = __('Notification settings were saved locally, but FirePhage could not update Slack and webhook alert routing yet.', 'firephage-security');
            }
        }

        wp_send_json_success([
            'message' => $message,
            'settings' => $savedSettings,
            'state' => $this->notifications->state(),
        ]);
    }

    public function handleConnectDashboard(): void
    {
        $this->assertAjaxPermissions();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $dashboardUrl = esc_url_raw((string) wp_unslash($_POST['dashboard_url'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $connectionToken = sanitize_text_field((string) wp_unslash($_POST['connection_token'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
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
                'last_sync_error' => sanitize_text_field($response->get_error_message()),
                'auto_sync_reports' => $autoSync,
            ]);

            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
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
                    'last_sync_error' => sanitize_text_field($syncResponse->get_error_message()),
                ]);
            } else {
                $this->settings->update([
                    'last_sync_at' => current_time('mysql'),
                    'last_sync_error' => '',
                ]);
            }
        }

        $savedSettings = $this->settings->all();
        $this->client->syncAlertChannels($savedSettings, [
            'notifications_enabled' => ($savedSettings['notifications_enabled'] ?? '0') === '1',
            'notification_email' => $savedSettings['notification_email'] ?? '',
            'notifications_alert_malware' => ($savedSettings['notifications_alert_malware'] ?? '0') === '1',
            'notifications_alert_core_edits' => ($savedSettings['notifications_alert_core_edits'] ?? '0') === '1',
            'notifications_webhook_url' => $savedSettings['notifications_webhook_url'] ?? '',
            'notifications_slack_channel' => $savedSettings['notifications_slack_channel'] ?? '',
        ]);

        wp_send_json_success([
            'message' => __('The plugin is now connected to FirePhage.', 'firephage-security'),
            'settings' => $savedSettings,
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

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $range = sanitize_text_field((string) wp_unslash($_POST['range'] ?? '24h'));
        if (! in_array($range, ['24h', '7d'], true)) {
            $range = '24h';
        }

        $response = $this->client->fetchFirewallSummary($settings, $range);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $this->cacheRemotePlanState($response);
        wp_send_json_success($response);
    }

    public function handleFetchPluginStatus(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        if ($settings['site_token'] === '' || $settings['site_id'] === '' || $settings['connection_status'] !== 'connected') {
            wp_send_json_success([
                'connected' => false,
                'message' => __('Connect the plugin to FirePhage to load site plan details.', 'firephage-security'),
            ]);
        }

        $response = $this->client->fetchStatus($settings);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $this->cacheRemotePlanState($response);
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
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $this->cacheRemotePlanState($response);
        wp_send_json_success($response);
    }

    public function handleCreateFirewallRule(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $ruleType = sanitize_key((string) wp_unslash($_POST['rule_type'] ?? ''));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $action = sanitize_key((string) wp_unslash($_POST['action'] ?? 'block'));
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $target = sanitize_text_field((string) wp_unslash($_POST['target'] ?? ''));

        $response = $this->client->createFirewallRule($settings, [
            'rule_type' => $ruleType,
            'action' => $action,
            'target' => $target,
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $summary = $this->client->fetchFirewallSummary($settings);
        if (is_wp_error($summary)) {
            wp_send_json_success([
                'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule created.', 'firephage-security'))),
            ]);
        }

        $this->cacheRemotePlanState($summary);
        wp_send_json_success([
            'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule created.', 'firephage-security'))),
            'summary' => $summary,
        ]);
    }

    public function handleDeleteFirewallRule(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $ruleId = absint($_POST['rule_id'] ?? 0);
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $target = sanitize_text_field((string) wp_unslash($_POST['target'] ?? ''));

        if ($ruleId <= 0) {
            wp_send_json_error(['message' => __('A valid firewall rule id is required.', 'firephage-security')], 400);
        }

        $response = $this->client->deleteFirewallRule($settings, [
            'rule_id' => $ruleId,
            'target' => $target,
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $summary = $this->client->fetchFirewallSummary($settings);
        if (is_wp_error($summary)) {
            wp_send_json_success([
                'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule removed.', 'firephage-security'))),
            ]);
        }

        $this->cacheRemotePlanState($summary);
        wp_send_json_success([
            'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule removed.', 'firephage-security'))),
            'summary' => $summary,
        ]);
    }

    public function handleToggleFirewallRule(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $ruleId = absint($_POST['rule_id'] ?? 0);
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $enabled = sanitize_text_field((string) wp_unslash($_POST['enabled'] ?? '')) === '1';

        if ($ruleId <= 0) {
            wp_send_json_error(['message' => __('A valid firewall rule id is required.', 'firephage-security')], 400);
        }

        $response = $this->client->toggleFirewallRule($settings, [
            'rule_id' => $ruleId,
            'enabled' => $enabled,
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $summary = $this->client->fetchFirewallSummary($settings);
        if (is_wp_error($summary)) {
            wp_send_json_success([
                'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule updated.', 'firephage-security'))),
            ]);
        }

        $this->cacheRemotePlanState($summary);
        wp_send_json_success([
            'message' => sanitize_text_field((string) ($response['message'] ?? __('Firewall rule updated.', 'firephage-security'))),
            'summary' => $summary,
        ]);
    }

    public function handlePurgeEdgeCache(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        $response = $this->client->purgeCache($settings, [
            'paths' => ['/*'],
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        wp_send_json_success([
            'message' => sanitize_text_field((string) ($response['message'] ?? __('Edge cache purge requested.', 'firephage-security'))),
        ]);
    }

    public function handleToggleTroubleshootingMode(): void
    {
        $this->assertAjaxPermissions();
        $settings = $this->settings->all();

        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified in assertAjaxPermissions().
        $enabled = ! empty($_POST['enabled']);

        $response = $this->client->toggleTroubleshootingMode($settings, $enabled);

        if (is_wp_error($response)) {
            wp_send_json_error(['message' => sanitize_text_field($response->get_error_message())], 400);
        }

        $summary = $this->client->fetchPerformanceSummary($settings);
        if (is_wp_error($summary)) {
            wp_send_json_success([
                'message' => sanitize_text_field((string) ($response['message'] ?? __('Troubleshooting mode updated.', 'firephage-security'))),
            ]);
        }

        wp_send_json_success([
            'message' => sanitize_text_field((string) ($response['message'] ?? __('Troubleshooting mode updated.', 'firephage-security'))),
            'summary' => $summary,
        ]);
    }

    /**
     * Allowed markup for FirePhage admin UI fragments rendered by helper methods.
     *
     * @return array<string, array<string, true>>
     */
    private function adminAllowedHtml(): array
    {
        $global = [
            'id' => true,
            'class' => true,
            'style' => true,
            'title' => true,
            'role' => true,
            'hidden' => true,
            'aria-hidden' => true,
            'aria-label' => true,
            'aria-live' => true,
            'aria-pressed' => true,
            'aria-expanded' => true,
            'aria-controls' => true,
            'data-tab' => true,
            'data-tab-target' => true,
            'data-file' => true,
            'data-source' => true,
            'data-bruteforce-view' => true,
            'data-bruteforce-panel' => true,
            'data-firewall-rule-tab' => true,
            'data-firewall-rule-panel' => true,
        ];

        return [
            'a' => $global + ['href' => true, 'target' => true, 'rel' => true],
            'button' => $global + ['type' => true, 'disabled' => true, 'name' => true, 'value' => true],
            'code' => $global,
            'details' => $global + ['open' => true],
            'div' => $global,
            'h2' => $global,
            'h3' => $global,
            'h4' => $global,
            'input' => $global + ['type' => true, 'name' => true, 'value' => true, 'placeholder' => true, 'checked' => true, 'disabled' => true, 'readonly' => true, 'min' => true, 'max' => true, 'step' => true, 'autocomplete' => true],
            'label' => $global + ['for' => true],
            'li' => $global,
            'option' => $global + ['value' => true, 'selected' => true],
            'p' => $global,
            'select' => $global + ['name' => true, 'disabled' => true],
            'small' => $global,
            'span' => $global,
            'strong' => $global,
            'summary' => $global,
            'table' => $global,
            'tbody' => $global,
            'td' => $global + ['colspan' => true],
            'th' => $global + ['scope' => true, 'colspan' => true],
            'thead' => $global,
            'tr' => $global,
            'ul' => $global,
        ];
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
    private function renderTabButton(string $tabId, array $tab, bool $isActive = false): string
    {
        $html = '<button type="button" class="firephage-tab-button' . ($isActive ? ' is-active' : '') . '" data-tab="' . esc_attr($tabId) . '">';
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
            /* translators: %s: Email address that received the free token. */
            return sprintf(__('Signature updates are active with the free FirePhage token sent to %s.', 'firephage-security'), $email);
        }

        if ($status === 'declined') {
            return __('Free FirePhage signature updates are turned off. You can request a token later at any time.', 'firephage-security');
        }

        if ($status === 'dismissed') {
            return __('The free-token prompt is hidden. You can still request a free token later whenever you want fresher FirePhage signatures.', 'firephage-security');
        }

        if ($status === 'awaiting_verification') {
            return __('Verification email sent. Open it, confirm the link, then return here and check the status to activate remote signature updates.', 'firephage-security');
        }

        return __('Choose whether you want a free FirePhage token for fresher malware signatures. Until you decide, the plugin will remind you when you return here.', 'firephage-security');
    }

    private function formatRecordedTimeLabel(string $timestamp): string
    {
        if ($timestamp === '') {
            return __('Never', 'firephage-security');
        }

        $epoch = strtotime($timestamp);

        if ($epoch === false) {
            return $timestamp;
        }

        return sprintf(
            /* translators: 1: Formatted date and time. 2: Human readable elapsed time. */
            __('%1$s (%2$s ago)', 'firephage-security'),
            wp_date(get_option('date_format') . ' ' . get_option('time_format'), $epoch),
            human_time_diff($epoch, time())
        );
    }

    /**
     * @param array<string, string> $settings
     */
    private function firephageTrackedUrl(array $settings, string $screen, string $cta, string $path = ''): string
    {
        $baseUrl = (string) ($settings['dashboard_url'] ?? 'https://firephage.com');
        $target = $path !== '' ? trailingslashit(untrailingslashit($baseUrl)) . ltrim($path, '/') : $baseUrl;
        $query = wp_parse_url($target, PHP_URL_QUERY);
        $params = [];

        if (is_string($query) && $query !== '') {
            parse_str($query, $params);
        }

        $params['source'] = 'wp-plugin';
        $params['screen'] = $screen;
        $params['cta'] = $cta;
        $params['v'] = FIREPHAGE_SECURITY_VERSION;
        $params['site'] = substr(hash('sha256', (string) wp_parse_url(home_url('/'), PHP_URL_HOST)), 0, 12);

        return add_query_arg($params, remove_query_arg(array_keys($params), $target));
    }

    private function renderFirewallPreviewBar(string $label, string $width): string
    {
        return '<div class="firephage-preview-bar"><div class="firephage-preview-bar__meta"><span>' . esc_html($label) . '</span><span>' . esc_html($width) . '</span></div><div class="firephage-preview-bar__track"><span style="width:' . esc_attr($width) . ';"></span></div></div>';
    }

    /**
     * @param array<string, mixed>|null $summary
     */
    private function renderInitialFirewallRulesRows(?array $summary): string
    {
        return '';
    }

    /**
     * @param array<string, mixed>|null $summary
     */
    private function renderInitialFirewallActivityRows(?array $summary): string
    {
        return '';
    }

    private function renderLockedMetricCard(string $label, string $valueId = '', string $value = '--', string $valueClass = ''): string
    {
        $id = $valueId !== '' ? ' id="' . esc_attr($valueId) . '"' : '';
        $class = 'firephage-pro-metric__value' . ($valueClass !== '' ? ' ' . $valueClass : '');
        $style = $valueClass === 'firephage-pro-metric__value--compact'
            ? ' style="font-size:12px;line-height:1.25;word-break:break-word;"'
            : '';

        return '<div class="firephage-pro-metric"><span class="firephage-pro-metric__label">' . esc_html($label) . '</span><strong class="' . esc_attr($class) . '"' . $id . $style . '>' . esc_html($value) . '</strong></div>';
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
            return '<p class="firephage-empty">' . esc_html__('No flagged files were found in the latest scan.', 'firephage-security') . '</p>';
        }

        $pageSizeOptions = $this->pageSizeOptions(count($findings));
        $restorableCount = 0;

        foreach ($findings as $finding) {
            if (is_array($finding) && (($finding['type'] ?? '') !== 'malware') && in_array((string) ($finding['source'] ?? ''), ['core_checksum', 'plugin_checksum', 'theme_checksum'], true)) {
                $restorableCount++;
            }
        }

        $html = '<div class="firephage-findings-toolbar">';
        $html .= '<label class="firephage-findings-search"><span class="screen-reader-text">' . esc_html__('Search findings', 'firephage-security') . '</span><input type="search" class="firephage-findings-search-input" placeholder="' . esc_attr__('Search findings...', 'firephage-security') . '" /></label>';
        $html .= '<label class="firephage-findings-rows"><span>' . esc_html__('Rows', 'firephage-security') . '</span><select class="firephage-findings-page-size">';
        foreach ($pageSizeOptions as $option) {
            $html .= '<option value="' . esc_attr((string) $option) . '"' . selected($option, 25, false) . '>' . esc_html((string) $option) . '</option>';
        }
        $html .= '</select></label>';
        $html .= '<div class="firephage-findings-actions">';
        if ($restorableCount > 0) {
            $html .= '<button type="button" class="button button-secondary firephage-restore-integrity-files">' . esc_html__('Restore All Modified Files', 'firephage-security') . '</button>';
        }
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-selected-suspicious-files" disabled>' . esc_html__('Delete Selected Flagged Files', 'firephage-security') . '</button>';
        $html .= '<button type="button" class="button firephage-button-danger firephage-delete-suspicious-files">' . esc_html__('Delete All Flagged Files', 'firephage-security') . '</button>';
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
            $status = $type === 'malware' ? __('Flagged', 'firephage-security') : __('Modified file', 'firephage-security');
            $detailParts = [];

            if ($source !== '') {
                /* translators: %s: Malware finding source. */
                $detailParts[] = sprintf(__('Source: %s', 'firephage-security'), ucwords(str_replace('_', ' ', $source)));
            }

            if ($confidence !== '') {
                /* translators: %s: Malware finding confidence level. */
                $detailParts[] = sprintf(__('Confidence: %s', 'firephage-security'), ucfirst($confidence));
            }

            if ($reasons !== []) {
                $detailParts[] = implode(', ', array_map('strval', $reasons));
            }

            $html .= '<tr>';
            $html .= '<td>';
            $html .= '<label class="screen-reader-text" for="firephage-select-' . esc_attr(md5($file)) . '">' . esc_html__('Select file', 'firephage-security') . '</label>';
            $html .= '<input type="checkbox" id="firephage-select-' . esc_attr(md5($file)) . '" class="firephage-findings-select" value="' . esc_attr($file) . '" />';
            $html .= '</td>';
            $html .= '<td><code>' . esc_html($file) . '</code></td>';
            $html .= '<td><span class="firephage-badge firephage-badge--' . esc_attr($type === 'malware' ? 'critical' : 'warning') . '">' . esc_html($status) . '</span></td>';
            $html .= '<td>' . esc_html(implode(' | ', $detailParts)) . '</td>';
            $html .= '<td>';
            if ($type === 'malware') {
                $html .= '<button type="button" class="button button-secondary firephage-preview-file" data-file="' . esc_attr($file) . '">' . esc_html__('Review File', 'firephage-security') . '</button> ';
                $html .= '<button type="button" class="button firephage-button-danger firephage-delete-finding" data-file="' . esc_attr($file) . '">' . esc_html__('Delete Flagged File', 'firephage-security') . '</button>';
            } else {
                $html .= '<div class="firephage-row-actions">';
                $html .= '<button type="button" class="button button-secondary firephage-preview-file" data-file="' . esc_attr($file) . '">' . esc_html__('Review File', 'firephage-security') . '</button>';
                if (in_array($source, ['core_checksum', 'plugin_checksum', 'theme_checksum'], true)) {
                    $html .= '<details class="firephage-action-menu">';
                    $html .= '<summary class="button button-secondary">' . esc_html__('Actions', 'firephage-security') . ' <span class="firephage-action-menu__chevron" aria-hidden="true">▾</span></summary>';
                    $html .= '<div class="firephage-action-menu__panel">';
                    $html .= '<button type="button" class="button button-secondary firephage-compare-file" data-file="' . esc_attr($file) . '" data-source="' . esc_attr($source) . '">' . esc_html__('Compare', 'firephage-security') . '</button>';
                    $html .= '<button type="button" class="button button-secondary firephage-restore-file" data-file="' . esc_attr($file) . '" data-source="' . esc_attr($source) . '">' . esc_html__('Restore', 'firephage-security') . '</button>';
                    $html .= '</div>';
                    $html .= '</details>';
                }
                $html .= '</div>';
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

    private function renderUpdateCard(string $title, int $count, string $description, string $clearMessage, string $actionLabel, string $actionUrl): string
    {
        return sprintf(
            '<div class="firephage-card"><div class="firephage-card-head"><h3>%1$s</h3><span class="firephage-badge firephage-badge--%2$s">%3$s</span></div><p>%4$s</p><a class="firephage-card-action" href="%5$s">%6$s</a></div>',
            esc_html($title),
            esc_attr($count > 0 ? 'warning' : 'good'),
            esc_html($count > 0 ? (string) $count : __('All clear', 'firephage-security')),
            esc_html($count > 0 ? $description : $clearMessage),
            esc_url($actionUrl),
            esc_html($actionLabel)
        );
    }

    private function renderUpdatesSummary(array $updates): string
    {
        $coreUpdates = (int) ($updates['core_updates'] ?? 0);
        $pluginUpdates = (int) ($updates['plugin_updates'] ?? 0);
        $themeUpdates = (int) ($updates['theme_updates'] ?? 0);
        $inactivePlugins = (int) ($updates['inactive_plugins'] ?? 0);
        $pendingUpdates = $coreUpdates + $pluginUpdates + $themeUpdates;
        $lastChecked = $this->getUpdatesLastCheckedLabel();

        $items = [
            [
                'label' => __('Pending updates', 'firephage-security'),
                'value' => (string) $pendingUpdates,
                'tone' => $pendingUpdates > 0 ? 'warning' : 'good',
                'description' => $pendingUpdates > 0
                    ? __('Across WordPress core, plugins, and themes.', 'firephage-security')
                    : __('Everything looks up to date.', 'firephage-security'),
            ],
            [
                'label' => __('WordPress core', 'firephage-security'),
                /* translators: %d: Number of WordPress core updates. */
                'value' => $coreUpdates > 0 ? sprintf(_n('%d update', '%d updates', $coreUpdates, 'firephage-security'), $coreUpdates) : __('Up to date', 'firephage-security'),
                'tone' => $coreUpdates > 0 ? 'warning' : 'good',
                'description' => $coreUpdates > 0 ? __('A core update is ready to review.', 'firephage-security') : __('No core update is waiting.', 'firephage-security'),
            ],
            [
                'label' => __('Plugins & themes', 'firephage-security'),
                'value' => ($pluginUpdates + $themeUpdates) > 0
                    /* translators: %d: Number of plugin and theme updates. */
                    ? sprintf(_n('%d update', '%d updates', $pluginUpdates + $themeUpdates, 'firephage-security'), $pluginUpdates + $themeUpdates)
                    : __('Up to date', 'firephage-security'),
                'tone' => ($pluginUpdates + $themeUpdates) > 0 ? 'warning' : 'good',
                'description' => ($pluginUpdates + $themeUpdates) > 0
                    ? __('Some installed items are ready to update.', 'firephage-security')
                    : __('Plugins and themes are current.', 'firephage-security'),
            ],
            [
                'label' => __('Inactive plugins', 'firephage-security'),
                'value' => $inactivePlugins > 0
                    /* translators: %d: Number of inactive plugins. */
                    ? sprintf(_n('%d plugin', '%d plugins', $inactivePlugins, 'firephage-security'), $inactivePlugins)
                    : __('Reviewed', 'firephage-security'),
                'tone' => $inactivePlugins > 0 ? 'neutral' : 'good',
                'description' => $inactivePlugins > 0
                    ? __('Inactive plugins should still be reviewed from time to time.', 'firephage-security')
                    : __('No inactive plugins are waiting for review.', 'firephage-security'),
            ],
        ];

        $html = '<div class="firephage-updates-summary">';
        $html .= '<div class="firephage-updates-summary__header">';
        $html .= '<p class="firephage-updates-summary__intro">' . esc_html__('Keeping WordPress, plugins, and themes updated helps reduce risk and avoids avoidable site issues.', 'firephage-security') . '</p>';
        if ($lastChecked !== '') {
            /* translators: %s: Human readable last checked time. */
            $html .= '<p class="firephage-updates-summary__meta">' . esc_html(sprintf(__('Last checked %s', 'firephage-security'), $lastChecked)) . '</p>';
        }
        $html .= '</div>';
        $html .= '<div class="firephage-mini-grid firephage-mini-grid--updates">';

        foreach ($items as $item) {
            $html .= sprintf(
                '<div class="firephage-stat-card firephage-stat-card--compact firephage-stat-card--summary"><span class="firephage-badge firephage-badge--%1$s">%2$s</span><span class="firephage-stat-value">%3$s</span><p class="firephage-stat-label">%4$s</p><p class="firephage-stat-description">%5$s</p></div>',
                esc_attr((string) $item['tone']),
                esc_html((string) $item['label']),
                esc_html((string) $item['value']),
                esc_html((string) $item['label']),
                esc_html((string) $item['description'])
            );
        }

        $html .= '</div>';
        $html .= '</div>';

        return $html;
    }

    private function getUpdatesLastCheckedLabel(): string
    {
        $timestamps = [];

        foreach (['update_core', 'update_plugins', 'update_themes'] as $transient) {
            $data = get_site_transient($transient);

            if (is_object($data) && isset($data->last_checked) && is_numeric($data->last_checked)) {
                $timestamps[] = (int) $data->last_checked;
            }
        }

        if ($timestamps === []) {
            return '';
        }

        $lastChecked = max($timestamps);

        if ($lastChecked <= 0) {
            return '';
        }

        return sprintf(
            '%1$s (%2$s)',
            wp_date(get_option('date_format') . ' ' . get_option('time_format'), $lastChecked),
            human_time_diff($lastChecked, time()) . ' ' . __('ago', 'firephage-security')
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

        $html = '<div class="firephage-finding-table-wrap firephage-finding-table-wrap--compact"><table class="firephage-finding-table firephage-finding-table--auto firephage-bruteforce-table">';
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
            $html .= '<td class="firephage-bruteforce-table__ip"><code class="firephage-cell-code firephage-cell-code--ip">' . esc_html((string) ($row['ip'] ?? 'unknown')) . '</code></td>';
            $html .= '<td>' . esc_html(strtoupper((string) ($row['surface'] ?? 'login'))) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['failed_attempts'] ?? 0)) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['started_at'] ?? '')) . '</td>';
            $html .= '<td>' . esc_html((string) ($row['expires_at'] ?? '')) . '</td>';
            if ($showRemaining) {
                /* translators: %d: Minutes remaining in the lockout. */
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
            return __('No scan is running. Start a scan to check WordPress files and review anything unusual.', 'firephage-security');
        }

        if ($status === 'discovering') {
            /* translators: %d: Number of files discovered so far. */
            return sprintf(__('Getting ready to scan. %d files have been queued so far.', 'firephage-security'), (int) ($scan['discovered_files'] ?? 0));
        }

        if ($status === 'stopped') {
            return sprintf(
                /* translators: 1: Scanned files. 2: Discovered files. 3: Trusted files. 4: Clean custom files. 5: Skipped files. 6: Integrity summary. 7: Flagged files. */
                __('The scan was paused after %1$d of %2$d files. Trusted files: %3$d. Clean custom files: %4$d. Skipped: %5$d. %6$s. Flagged files: %7$d. Use Resume Scan to continue.', 'firephage-security'),
                (int) ($scan['scanned_files'] ?? 0),
                (int) ($scan['discovered_files'] ?? 0),
                (int) ($scan['trusted_files'] ?? 0),
                (int) ($scan['clean_files'] ?? 0),
                (int) ($scan['skipped_files'] ?? 0),
                $this->scanIntegritySummary($scan),
                (int) ($scan['suspicious_files'] ?? 0)
            );
        }

        if ($status === 'completed') {
            return sprintf(
                /* translators: 1: Scanned files. 2: Trusted files. 3: Clean custom files. 4: Skipped files. 5: Integrity summary. 6: Flagged files. */
                __('Latest scan finished. %1$d files were checked, %2$d trusted, %3$d clean custom files, %4$d skipped, %5$s, and %6$d flagged files.', 'firephage-security'),
                (int) ($scan['scanned_files'] ?? 0),
                (int) ($scan['trusted_files'] ?? 0),
                (int) ($scan['clean_files'] ?? 0),
                (int) ($scan['skipped_files'] ?? 0),
                $this->scanIntegritySummary($scan),
                (int) ($scan['suspicious_files'] ?? 0)
            );
        }

        if ($status === 'failed') {
            /* translators: %s: Scan failure message. */
            return sprintf(__('Scan failed: %s', 'firephage-security'), (string) ($scan['last_error'] ?? __('Unknown error', 'firephage-security')));
        }

        return sprintf(
            /* translators: 1: Scanned files. 2: Discovered files. 3: Trusted files. 4: Clean custom files. 5: Skipped files. 6: Integrity summary. 7: Flagged files. 8: Current file path. */
            __('Scanning %1$d of %2$d files. Trusted: %3$d. Clean custom files: %4$d. Skipped: %5$d. %6$s. Flagged files: %7$d. Current file: %8$s', 'firephage-security'),
            (int) ($scan['scanned_files'] ?? 0),
            (int) ($scan['discovered_files'] ?? 0),
            (int) ($scan['trusted_files'] ?? 0),
            (int) ($scan['clean_files'] ?? 0),
            (int) ($scan['skipped_files'] ?? 0),
            $this->scanIntegritySummary($scan),
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
                return __('Attention Needed', 'firephage-security');

            case 'discovering':
                return __('Preparing Scan', 'firephage-security');

            case 'scanning':
                return __('Scanning', 'firephage-security');

            case 'stopped':
                return __('Paused', 'firephage-security');

            default:
                return __('Idle', 'firephage-security');
        }
    }

    /**
     * @param array<string, mixed> $scan
     */
    private function officialChecksumMismatches(array $scan): int
    {
        return max(0, (int) ($scan['official_checksum_mismatches'] ?? 0));
    }

    /**
     * @param array<string, mixed> $scan
     */
    private function baselineChanges(array $scan): int
    {
        return max(0, (int) ($scan['baseline_changes'] ?? 0));
    }

    /**
     * @param array<string, mixed> $scan
     */
    private function scanIntegritySummary(array $scan): string
    {
        $official = $this->officialChecksumMismatches($scan);
        $baseline = $this->baselineChanges($scan);

        if ($baseline < 1) {
            /* translators: %d: Number of official checksum mismatches. */
            return sprintf(__('Official checksum mismatches: %d', 'firephage-security'), $official);
        }

        return sprintf(
            /* translators: 1: Number of official checksum mismatches. 2: Number of local baseline changes. */
            __('Official checksum mismatches: %1$d. Local baseline changes: %2$d', 'firephage-security'),
            $official,
            $baseline
        );
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
                return __('Review', 'firephage-security');

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
            /* translators: %d: Number of minutes elapsed. */
            return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'firephage-security'), $minutes);
        }

        if ($delta < DAY_IN_SECONDS) {
            $hours = max(1, (int) floor($delta / HOUR_IN_SECONDS));
            /* translators: %d: Number of hours elapsed. */
            return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'firephage-security'), $hours);
        }

        $days = max(1, (int) floor($delta / DAY_IN_SECONDS));

        /* translators: %d: Number of days elapsed. */
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
        $score = 28;
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

        $score += ($checks['https'] ?? '') === 'good' ? 8 : 0;
        if (($checks['https'] ?? '') !== 'good') {
            $addHint($hints, __('Turn on HTTPS across the site.', 'firephage-security'));
        }

        $score += ($checks['debug_display'] ?? '') === 'good' ? 4 : 0;
        if (($checks['debug_display'] ?? '') !== 'good') {
            $addHint($hints, __('Hide debug messages from visitors.', 'firephage-security'));
        }

        $score += ($checks['file_editor'] ?? '') === 'good' ? 4 : 0;
        $score += ($checks['registration'] ?? '') === 'good' ? 3 : 0;
        $score += ($checks['default_admin'] ?? '') === 'good' ? 5 : 0;
        $wafManaged = ($settings['connection_status'] ?? 'disconnected') === 'connected'
            && ($settings['remote_pro_enabled'] ?? '0') === '1';

        $score += ($checks['xmlrpc'] ?? '') === 'good' ? 3 : (($settings['bruteforce_protect_xmlrpc'] ?? '0') === '1' || $wafManaged ? 1 : 0);

        if ($wafManaged) {
            $score += 8;
        } elseif (($settings['bruteforce_enabled'] ?? '0') === '1') {
            $score += 8;
        } else {
            $addHint($hints, __('Enable local login protection.', 'firephage-security'));
        }

        $pendingUpdates = (int) (($health['updates']['core_updates'] ?? 0) + ($health['updates']['plugin_updates'] ?? 0) + ($health['updates']['theme_updates'] ?? 0));
        if ($pendingUpdates === 0) {
            $score += 12;
        } elseif ($pendingUpdates <= 2) {
            $score += 3;
            $addHint($hints, __('Apply the pending updates.', 'firephage-security'));
        } elseif ($pendingUpdates <= 6) {
            $score -= 6;
            $addHint($hints, __('Bring WordPress, plugins, and themes up to date.', 'firephage-security'));
        } else {
            $score -= 14;
            $addHint($hints, __('Updates need attention first.', 'firephage-security'));
        }

        $suspicious = (int) ($scan['suspicious_files'] ?? 0);
        $officialChecksumMismatches = $this->officialChecksumMismatches($scan);
        $baselineChanges = $this->baselineChanges($scan);
        $scanStatus = (string) ($scan['status'] ?? 'idle');
        $scannedFiles = (int) ($scan['scanned_files'] ?? 0);

        if ($suspicious === 0 && $officialChecksumMismatches === 0 && $baselineChanges === 0 && $scanStatus === 'completed') {
            $score += 14;
        } elseif ($scanStatus === 'running') {
            $score += 3;
        } elseif ($scannedFiles === 0 || in_array($scanStatus, ['idle', 'pending'], true)) {
            $score -= 16;
            $addHint($hints, __('Run a malware scan so this score reflects the site state.', 'firephage-security'));
        } else {
            if ($suspicious > 0) {
                $score -= min(36, $suspicious * 6);
                $addHint($hints, __('Review the flagged files first.', 'firephage-security'));
            }

            if ($officialChecksumMismatches > 0) {
                $score -= min(28, $officialChecksumMismatches * 4);
                $addHint($hints, __('Review official checksum mismatches first.', 'firephage-security'));
            }

            if ($baselineChanges > 0) {
                $score -= min(12, $baselineChanges * 1);
                $addHint($hints, __('Review unverifiable plugin or theme file changes after updates.', 'firephage-security'));
            }
        }

        if (($settings['connection_status'] ?? 'disconnected') === 'connected') {
            $score += 4;
        } else {
            $score -= 6;
            $addHint($hints, __('Connect FirePhage if you want dashboard sync and edge protection.', 'firephage-security'));
        }

        $score = max(0, min(100, $score));

        $tone = $score >= 90 ? 'good' : ($score >= 72 ? 'warning' : 'critical');
        $label = $score >= 90 ? __('Strong', 'firephage-security') : ($score >= 72 ? __('Good', 'firephage-security') : __('Needs attention', 'firephage-security'));
        $summary = $score >= 90
            ? __('Your site looks well covered. Keep scans current and stay on top of updates.', 'firephage-security')
            : ($score >= 72
                ? __('Your site is in a reasonable place, but a few important fixes still need attention.', 'firephage-security')
                : __('Important security steps are still missing or unresolved. Start with the items below.', 'firephage-security'));

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

    /**
     * @param array<string, mixed> $health
     * @param array<string, mixed> $scan
     * @param array<string, mixed> $bruteForce
     * @param array<string, string> $settings
     * @param array{score?: int}|null $securityScore
     * @return array{tone: string, label: string, summary: string, checks_value: string, checks_summary: string, protection_value: string, protection_summary: string, sync_value: string, sync_summary: string}
     */
    private function buildOverviewStatus(array $health, array $scan, array $bruteForce, array $settings, ?array $securityScore = null): array
    {
        $goodChecks = (int) ($health['summary']['good'] ?? 0);
        $badChecks = (int) ($health['summary']['bad'] ?? 0);
        $totalChecks = max(0, $goodChecks + $badChecks);
        $pendingUpdates = (int) (($health['updates']['core_updates'] ?? 0) + ($health['updates']['plugin_updates'] ?? 0) + ($health['updates']['theme_updates'] ?? 0));
        $suspicious = (int) ($scan['suspicious_files'] ?? 0);
        $officialChecksumMismatches = $this->officialChecksumMismatches($scan);
        $baselineChanges = $this->baselineChanges($scan);
        $scanStatus = (string) ($scan['status'] ?? 'idle');
        $scannedFiles = (int) ($scan['scanned_files'] ?? 0);
        $score = (int) ($securityScore['score'] ?? $this->buildSecurityScore($health, $scan, $bruteForce, $settings)['score']);
        $wafManaged = ($settings['connection_status'] ?? 'disconnected') === 'connected'
            && ($settings['remote_pro_enabled'] ?? '0') === '1';
        $protectionValue = $wafManaged
            ? __('WAF managed', 'firephage-security')
            : (($settings['bruteforce_enabled'] ?? '0') === '1' ? __('On', 'firephage-security') : __('Off', 'firephage-security'));
        $protectionSummary = (string) ($bruteForce['summary'] ?? __('Login protection is not enabled yet.', 'firephage-security'));
        $syncValue = $this->humanizeTimestamp((string) ($settings['last_sync_at'] ?? ''));
        $syncSummary = $settings['last_sync_error'] !== '' ? __('The last dashboard sync reported an issue.', 'firephage-security') : __('The latest dashboard report was sent successfully.', 'firephage-security');

        $tone = 'good';
        $label = __('Looking good', 'firephage-security');
        $summary = __('A quick summary of local protection, site checks, and the latest dashboard sync.', 'firephage-security');

        if ($suspicious > 0) {
            $tone = 'critical';
            $label = __('Action needed', 'firephage-security');
            $summary = __('Malware findings were detected. Review the flagged files before treating the site as healthy.', 'firephage-security');
        } elseif ($officialChecksumMismatches > 0) {
            $tone = 'critical';
            $label = __('Action needed', 'firephage-security');
            $summary = __('Official WordPress.org checksum mismatches were detected. Review those files before trusting the current site status.', 'firephage-security');
        } elseif ($baselineChanges > 0) {
            $tone = 'warning';
            $label = __('Needs review', 'firephage-security');
            $summary = __('Some plugin or theme package files changed against the local baseline. This is common right after a premium package update, but it should still be reviewed.', 'firephage-security');
        } elseif ($scanStatus === 'failed') {
            $tone = 'critical';
            $label = __('Action needed', 'firephage-security');
            $summary = __('The last malware scan failed, so the current status is incomplete until a new scan finishes.', 'firephage-security');
        } elseif (in_array($scanStatus, ['discovering', 'scanning', 'running'], true)) {
            $tone = 'warning';
            $label = __('Scan in progress', 'firephage-security');
            $summary = __('The first scan is still running, so the current status is provisional until it finishes.', 'firephage-security');
        } elseif ($scannedFiles === 0 || in_array($scanStatus, ['idle', 'pending', 'stopped'], true)) {
            $tone = 'warning';
            $label = __('Scan needed', 'firephage-security');
            $summary = __('Run and complete a malware scan before treating this status as a reliable baseline.', 'firephage-security');
        } elseif ($score < 40 || $pendingUpdates > 6 || $badChecks > 2) {
            $tone = 'critical';
            $label = __('Needs attention', 'firephage-security');
            $summary = __('Important issues are still unresolved. Start with updates, failed checks, and scanner findings.', 'firephage-security');
        } elseif ($score < 72 || $pendingUpdates > 0 || $badChecks > 0 || $settings['last_sync_error'] !== '') {
            $tone = 'warning';
            $label = __('Needs review', 'firephage-security');
            $summary = __('The site has a usable baseline, but some issues still need review before it can be considered fully healthy.', 'firephage-security');
        }

        return [
            'tone' => $tone,
            'label' => $label,
            'summary' => $summary,
            /* translators: 1: Number of passing checks. 2: Total number of checks. */
            'checks_value' => sprintf(__('%1$d / %2$d', 'firephage-security'), $goodChecks, $totalChecks),
            'checks_summary' => $badChecks > 0 ? __('Some checks still need review.', 'firephage-security') : __('Core settings look good.', 'firephage-security'),
            'protection_value' => $protectionValue,
            'protection_summary' => $protectionSummary,
            'sync_value' => $syncValue,
            'sync_summary' => $syncSummary,
        ];
    }

    private function assertAjaxPermissions(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('You are not allowed to manage FirePhage Security.', 'firephage-security')], 403);
        }

        check_ajax_referer('firephage_admin', 'nonce');
    }

    /**
     * @param array<string, string> $settings
     * @return array<string, mixed>
     */
    private function notificationChannelAccess(array $settings): array
    {
        if (($settings['site_token'] ?? '') === '' || ($settings['site_id'] ?? '') === '' || ($settings['connection_status'] ?? '') !== 'connected') {
            return [
                'paid' => false,
                'connected' => false,
                'alert_channels' => [],
            ];
        }

        $response = $this->client->fetchStatus($settings);

        if (is_wp_error($response)) {
            return [
                'paid' => false,
                'connected' => true,
                'alert_channels' => [],
            ];
        }

        $this->cacheRemotePlanState($response);

        return [
            'paid' => ! empty($response['billing']['pro_enabled']),
            'connected' => ! empty($response['connected']),
            'alert_channels' => is_array($response['alert_channels'] ?? null) ? $response['alert_channels'] : [],
        ];
    }

    /**
     * @param array<string, mixed> $response
     */
    private function cacheRemotePlanState(array $response): void
    {
        $billing = is_array($response['billing'] ?? null) ? $response['billing'] : [];

        $this->settings->update([
            'remote_pro_enabled' => ! empty($billing['pro_enabled']) ? '1' : '0',
            'remote_plan_name' => sanitize_text_field((string) ($billing['plan_name'] ?? '')),
        ]);
    }

    /**
     * @param array<string, string> $settings
     * @return array<string, string>
     */
    private function dashboardFirewallUrl(array $settings): string
    {
        if (($settings['dashboard_url'] ?? '') === '' || ($settings['site_id'] ?? '') === '') {
            return '';
        }

        return add_query_arg(
            ['site_id' => $settings['site_id']],
            untrailingslashit((string) $settings['dashboard_url']) . '/app/firewall'
        );
    }
}
