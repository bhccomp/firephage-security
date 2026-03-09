<?php

namespace FirePhage\Security;

if (! defined('ABSPATH')) {
    exit;
}

final class Settings
{
    public const OPTION_KEY = 'firephage_security_settings';

    /**
     * @return array<string, string>
     */
    public function all(): array
    {
        $defaults = [
            'dashboard_url' => 'https://waf-saas.firephage.com',
            'checksum_service_url' => 'https://waf-saas.firephage.com',
            'connection_token' => '',
            'site_token' => '',
            'site_id' => '',
            'connection_status' => 'disconnected',
            'last_sync_at' => '',
            'last_sync_error' => '',
            'auto_sync_reports' => '1',
            'use_firephage_checksum_cache' => '1',
            'free_signature_token' => '',
            'free_signature_status_token' => '',
            'free_signature_token_email' => '',
            'free_signature_token_status' => 'pending',
            'free_signature_token_last_requested_at' => '',
            'free_signature_token_marketing_opt_in' => '0',
            'bruteforce_enabled' => '1',
            'bruteforce_threshold' => '5',
            'bruteforce_window_minutes' => '15',
            'bruteforce_lockout_minutes' => '30',
            'bruteforce_protect_xmlrpc' => '1',
            'malware_auto_scans_enabled' => '0',
            'malware_auto_scan_interval' => 'daily',
            'malware_scan_exclusions' => '',
            'use_firephage_signature_feed' => '1',
            'notifications_enabled' => '1',
            'notification_email' => '',
            'notifications_weekly_report' => '1',
            'notifications_alert_malware' => '1',
            'notifications_alert_core_edits' => '1',
        ];

        $value = get_option(self::OPTION_KEY, []);

        if (! is_array($value)) {
            return $defaults;
        }

        return array_merge($defaults, array_intersect_key($value, $defaults));
    }

    public function register(): void
    {
        register_setting('firephage_security', self::OPTION_KEY, [$this, 'sanitize']);
    }

    /**
     * @param mixed $input
     * @return array<string, string>
     */
    public function sanitize($input): array
    {
        $input = is_array($input) ? $input : [];
        $settings = $this->all();

        return [
            'dashboard_url' => esc_url_raw((string) ($input['dashboard_url'] ?? $settings['dashboard_url'])),
            'checksum_service_url' => esc_url_raw((string) ($input['checksum_service_url'] ?? $settings['checksum_service_url'])),
            'connection_token' => sanitize_text_field((string) ($input['connection_token'] ?? $settings['connection_token'])),
            'site_id' => sanitize_text_field((string) ($input['site_id'] ?? $settings['site_id'])),
            'site_token' => sanitize_text_field((string) ($input['site_token'] ?? $settings['site_token'])),
            'connection_status' => sanitize_text_field((string) ($input['connection_status'] ?? $settings['connection_status'])),
            'last_sync_at' => sanitize_text_field((string) ($input['last_sync_at'] ?? $settings['last_sync_at'])),
            'last_sync_error' => sanitize_text_field((string) ($input['last_sync_error'] ?? $settings['last_sync_error'])),
            'auto_sync_reports' => ! empty($input['auto_sync_reports']) ? '1' : '0',
            'use_firephage_checksum_cache' => ! empty($input['use_firephage_checksum_cache']) ? '1' : '0',
            'free_signature_token' => sanitize_text_field((string) ($input['free_signature_token'] ?? $settings['free_signature_token'])),
            'free_signature_status_token' => sanitize_text_field((string) ($input['free_signature_status_token'] ?? $settings['free_signature_status_token'])),
            'free_signature_token_email' => sanitize_email((string) ($input['free_signature_token_email'] ?? $settings['free_signature_token_email'])),
            'free_signature_token_status' => in_array((string) ($input['free_signature_token_status'] ?? $settings['free_signature_token_status']), ['pending', 'awaiting_verification', 'registered', 'declined', 'dismissed'], true)
                ? (string) ($input['free_signature_token_status'] ?? $settings['free_signature_token_status'])
                : 'pending',
            'free_signature_token_last_requested_at' => sanitize_text_field((string) ($input['free_signature_token_last_requested_at'] ?? $settings['free_signature_token_last_requested_at'])),
            'free_signature_token_marketing_opt_in' => ! empty($input['free_signature_token_marketing_opt_in']) ? '1' : '0',
            'bruteforce_enabled' => ! empty($input['bruteforce_enabled']) ? '1' : '0',
            'bruteforce_threshold' => (string) max(3, min(20, absint($input['bruteforce_threshold'] ?? $settings['bruteforce_threshold']))),
            'bruteforce_window_minutes' => (string) max(5, min(120, absint($input['bruteforce_window_minutes'] ?? $settings['bruteforce_window_minutes']))),
            'bruteforce_lockout_minutes' => (string) max(5, min(1440, absint($input['bruteforce_lockout_minutes'] ?? $settings['bruteforce_lockout_minutes']))),
            'bruteforce_protect_xmlrpc' => ! empty($input['bruteforce_protect_xmlrpc']) ? '1' : '0',
            'malware_auto_scans_enabled' => ! empty($input['malware_auto_scans_enabled']) ? '1' : '0',
            'malware_auto_scan_interval' => in_array((string) ($input['malware_auto_scan_interval'] ?? $settings['malware_auto_scan_interval']), ['daily', 'twice_daily', 'four_times_daily'], true)
                ? (string) ($input['malware_auto_scan_interval'] ?? $settings['malware_auto_scan_interval'])
                : 'daily',
            'malware_scan_exclusions' => sanitize_textarea_field((string) ($input['malware_scan_exclusions'] ?? $settings['malware_scan_exclusions'])),
            'use_firephage_signature_feed' => ! empty($input['use_firephage_signature_feed']) ? '1' : '0',
            'notifications_enabled' => ! empty($input['notifications_enabled']) ? '1' : '0',
            'notification_email' => sanitize_email((string) ($input['notification_email'] ?? $settings['notification_email'])),
            'notifications_weekly_report' => ! empty($input['notifications_weekly_report']) ? '1' : '0',
            'notifications_alert_malware' => ! empty($input['notifications_alert_malware']) ? '1' : '0',
            'notifications_alert_core_edits' => ! empty($input['notifications_alert_core_edits']) ? '1' : '0',
        ];
    }

    /**
     * @param array<string, string> $values
     */
    public function update(array $values): void
    {
        update_option(self::OPTION_KEY, array_merge($this->all(), $values), false);
    }

    public function disconnect(): void
    {
        $this->update([
            'connection_token' => '',
            'site_id' => '',
            'site_token' => '',
            'connection_status' => 'disconnected',
            'last_sync_at' => '',
            'last_sync_error' => '',
        ]);
    }
}
