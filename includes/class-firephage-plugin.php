<?php

namespace FirePhage\Security;

use FirePhage\Security\Admin\Admin;
use FirePhage\Security\FirePhage\Client;
use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Reports\ReportBuilder;
use FirePhage\Security\Scanner\MalwareScanner;

if (! defined('ABSPATH')) {
    exit;
}

require_once FIREPHAGE_SECURITY_PATH . 'includes/Health/class-firephage-health-checker.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Scanner/class-firephage-malware-scanner.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Reports/class-firephage-report-builder.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/FirePhage/class-firephage-client.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/class-firephage-settings.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Admin/class-firephage-admin.php';

final class Plugin
{
    private const REPORT_CRON_HOOK = 'firephage_security_sync_report';

    private static ?self $instance = null;

    private Settings $settings;

    private MalwareScanner $scanner;

    private HealthChecker $healthChecker;

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
        $this->reportBuilder = new ReportBuilder($this->healthChecker, $this->scanner);
        $this->client = new Client();
        $this->admin = new Admin($this->settings, $this->scanner, $this->healthChecker, $this->reportBuilder, $this->client);
    }

    public function boot(): void
    {
        add_action('plugins_loaded', [$this, 'loadTextdomain']);
        add_action('init', [$this, 'syncSchedules']);
        add_action('admin_init', [$this->settings, 'register']);
        add_action('admin_menu', [$this->admin, 'registerMenus']);
        add_action('admin_enqueue_scripts', [$this->admin, 'enqueueAssets']);
        add_action(self::REPORT_CRON_HOOK, [$this, 'sendScheduledReport']);

        $this->scanner->registerHooks();
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
        wp_clear_scheduled_hook(self::REPORT_CRON_HOOK);
    }

    public function loadTextdomain(): void
    {
        load_plugin_textdomain('firephage-security', false, dirname(plugin_basename(FIREPHAGE_SECURITY_FILE)) . '/languages');
    }

    public function syncSchedules(): void
    {
        $settings = $this->settings->all();
        $shouldSchedule = $settings['auto_sync_reports'] === '1' && $settings['site_token'] !== '';

        if ($shouldSchedule && ! wp_next_scheduled(self::REPORT_CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::REPORT_CRON_HOOK);
        }

        if (! $shouldSchedule) {
            wp_clear_scheduled_hook(self::REPORT_CRON_HOOK);
        }
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
}
