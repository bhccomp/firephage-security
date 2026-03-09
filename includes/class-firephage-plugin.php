<?php

namespace FirePhage\Security;

use FirePhage\Security\Admin\Admin;
use FirePhage\Security\FirePhage\Client;
use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Reports\ReportBuilder;
use FirePhage\Security\Scanner\MalwareScanner;
use FirePhage\Security\Security\BruteForceProtection;

if (! defined('ABSPATH')) {
    exit;
}

require_once FIREPHAGE_SECURITY_PATH . 'includes/Health/class-firephage-health-checker.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Scanner/class-firephage-malware-scanner.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Security/class-firephage-brute-force-protection.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Reports/class-firephage-report-builder.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/FirePhage/class-firephage-client.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/class-firephage-settings.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Admin/class-firephage-admin.php';

final class Plugin
{
    private const REPORT_CRON_HOOK = 'firephage_security_sync_report';
    private const AUTO_SCAN_CRON_HOOK = 'firephage_security_auto_scan';

    private static ?self $instance = null;

    private Settings $settings;

    private MalwareScanner $scanner;

    private HealthChecker $healthChecker;

    private BruteForceProtection $bruteForceProtection;

    private ReportBuilder $reportBuilder;

    private Client $client;

    private Admin $admin;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->settings = new Settings();
        $this->scanner = new MalwareScanner();
        $this->healthChecker = new HealthChecker();
        $this->bruteForceProtection = new BruteForceProtection($this->settings);
        $this->reportBuilder = new ReportBuilder($this->healthChecker, $this->scanner, $this->bruteForceProtection);
        $this->client = new Client();
        $this->admin = new Admin($this->settings, $this->scanner, $this->healthChecker, $this->reportBuilder, $this->client, $this->bruteForceProtection);
    }

    public function boot(): void
    {
        add_action('plugins_loaded', [$this, 'loadTextdomain']);
        add_action('init', [$this, 'syncSchedules']);
        add_action('firephage_security_settings_changed', [$this, 'syncSchedules']);
        add_filter('cron_schedules', [$this, 'registerSchedules']);
        add_action('admin_init', [$this, 'registerPrivacyPolicyContent']);
        add_action('admin_init', [$this->settings, 'register']);
        add_action('admin_menu', [$this->admin, 'registerMenus']);
        add_action('admin_enqueue_scripts', [$this->admin, 'enqueueAssets']);
        add_action(self::REPORT_CRON_HOOK, [$this, 'sendScheduledReport']);
        add_action(self::AUTO_SCAN_CRON_HOOK, [$this, 'runScheduledMalwareScan']);

        $this->scanner->registerHooks();
        $this->bruteForceProtection->registerHooks();
    }

    public static function activate(): void
    {
        if (get_option(Settings::OPTION_KEY, null) === null) {
            update_option(Settings::OPTION_KEY, (new Settings())->all(), false);
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook(MalwareScanner::CRON_HOOK);
        wp_clear_scheduled_hook(MalwareScanner::MONITOR_CRON_HOOK);
        wp_clear_scheduled_hook(self::REPORT_CRON_HOOK);
        wp_clear_scheduled_hook(self::AUTO_SCAN_CRON_HOOK);
    }

    public function loadTextdomain(): void
    {
        load_plugin_textdomain('firephage-security', false, dirname(plugin_basename(FIREPHAGE_SECURITY_FILE)) . '/languages');
    }

    public function syncSchedules(): void
    {
        $settings = $this->settings->all();
        $shouldSchedule = $settings['auto_sync_reports'] === '1' && $settings['site_token'] !== '';
        $scanSchedule = $this->malwareScanSchedule((string) ($settings['malware_auto_scan_interval'] ?? 'daily'));
        $shouldScheduleScans = ($settings['malware_auto_scans_enabled'] ?? '0') === '1';

        if ($shouldSchedule && ! wp_next_scheduled(self::REPORT_CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::REPORT_CRON_HOOK);
        }

        if (! $shouldSchedule) {
            wp_clear_scheduled_hook(self::REPORT_CRON_HOOK);
        }

        $autoScanEvent = function_exists('wp_get_scheduled_event') ? wp_get_scheduled_event(self::AUTO_SCAN_CRON_HOOK) : false;

        if ($shouldScheduleScans && $autoScanEvent === false) {
            wp_schedule_event(time() + MINUTE_IN_SECONDS, $scanSchedule, self::AUTO_SCAN_CRON_HOOK);
        }

        if ($shouldScheduleScans && $autoScanEvent !== false && isset($autoScanEvent->schedule) && $autoScanEvent->schedule !== $scanSchedule) {
            wp_clear_scheduled_hook(self::AUTO_SCAN_CRON_HOOK);
            wp_schedule_event(time() + MINUTE_IN_SECONDS, $scanSchedule, self::AUTO_SCAN_CRON_HOOK);
        }

        if (! $shouldScheduleScans) {
            wp_clear_scheduled_hook(self::AUTO_SCAN_CRON_HOOK);
        }
    }

    /**
     * @param array<string, array<string, mixed>> $schedules
     * @return array<string, array<string, mixed>>
     */
    public function registerSchedules(array $schedules): array
    {
        $schedules['firephage_twice_daily'] = [
            'interval' => 12 * HOUR_IN_SECONDS,
            'display' => __('FirePhage Twice Daily', 'firephage-security'),
        ];
        $schedules['firephage_four_times_daily'] = [
            'interval' => 6 * HOUR_IN_SECONDS,
            'display' => __('FirePhage Four Times Daily', 'firephage-security'),
        ];

        return $schedules;
    }

    public function registerPrivacyPolicyContent(): void
    {
        if (! function_exists('wp_add_privacy_policy_content')) {
            return;
        }

        wp_add_privacy_policy_content(
            __('FirePhage Security', 'firephage-security'),
            wp_kses_post(
                '<p>' . esc_html__('FirePhage Security can contact external services in two cases.', 'firephage-security') . '</p>' .
                '<p>' . esc_html__('For checksum verification, the plugin may request public package checksum metadata from FirePhage cache services and WordPress.org. Those requests include only the package type, slug, and version needed to verify repository files.', 'firephage-security') . '</p>' .
                '<p>' . esc_html__('If you choose to connect the plugin to a paid FirePhage account, the plugin will also send site connection details and security reports to FirePhage so dashboard sync and alerting can work.', 'firephage-security') . '</p>'
            )
        );
    }

    public function sendScheduledReport(): void
    {
        $settings = $this->settings->all();

        if ($settings['site_token'] === '' || $settings['dashboard_url'] === '' || $settings['auto_sync_reports'] !== '1') {
            return;
        }

        $response = $this->client->sendReport($settings, $this->reportBuilder->build());

        if (is_wp_error($response)) {
            $this->settings->update([
                'last_sync_error' => $response->get_error_message(),
            ]);

            return;
        }

        $this->settings->update([
            'last_sync_at' => current_time('mysql'),
            'last_sync_error' => '',
        ]);
    }

    public function runScheduledMalwareScan(): void
    {
        $state = $this->scanner->getState();

        if (in_array((string) ($state['status'] ?? 'idle'), ['discovering', 'scanning'], true)) {
            return;
        }

        $this->scanner->startScan(true);
    }

    private function malwareScanSchedule(string $value): string
    {
        return match ($value) {
            'daily' => 'daily',
            'four_times_daily' => 'firephage_four_times_daily',
            default => 'firephage_twice_daily',
        };
    }
}
