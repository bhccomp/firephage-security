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
            'connection_token' => '',
            'site_token' => '',
            'site_id' => '',
            'connection_status' => 'disconnected',
            'last_sync_at' => '',
            'last_sync_error' => '',
            'auto_sync_reports' => '1',
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
            'connection_token' => sanitize_text_field((string) ($input['connection_token'] ?? $settings['connection_token'])),
            'site_id' => sanitize_text_field((string) ($input['site_id'] ?? $settings['site_id'])),
            'site_token' => sanitize_text_field((string) ($input['site_token'] ?? $settings['site_token'])),
            'connection_status' => sanitize_text_field((string) ($input['connection_status'] ?? $settings['connection_status'])),
            'last_sync_at' => sanitize_text_field((string) ($input['last_sync_at'] ?? $settings['last_sync_at'])),
            'last_sync_error' => sanitize_text_field((string) ($input['last_sync_error'] ?? $settings['last_sync_error'])),
            'auto_sync_reports' => ! empty($input['auto_sync_reports']) ? '1' : '0',
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
