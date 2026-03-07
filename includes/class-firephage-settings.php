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
            'api_base_url' => '',
            'site_token' => '',
            'site_id' => '',
        ];

        $value = get_option(self::OPTION_KEY, []);

        if (! is_array($value)) {
            return $defaults;
        }

        return array_merge($defaults, array_intersect_key($value, $defaults));
    }

    public function register(): void
    {
        register_setting(
            'firephage_security',
            self::OPTION_KEY,
            [$this, 'sanitize']
        );

        add_settings_section(
            'firephage_security_connection',
            __('FirePhage Connection', 'firephage-security'),
            function (): void {
                echo '<p>' . esc_html__('Connect this WordPress site to your FirePhage dashboard.', 'firephage-security') . '</p>';
            },
            'firephage_security'
        );

        add_settings_field(
            'api_base_url',
            __('API Base URL', 'firephage-security'),
            [$this, 'renderApiBaseUrlField'],
            'firephage_security',
            'firephage_security_connection'
        );

        add_settings_field(
            'site_id',
            __('FirePhage Site ID', 'firephage-security'),
            [$this, 'renderSiteIdField'],
            'firephage_security',
            'firephage_security_connection'
        );

        add_settings_field(
            'site_token',
            __('Site Token', 'firephage-security'),
            [$this, 'renderSiteTokenField'],
            'firephage_security',
            'firephage_security_connection'
        );
    }

    /**
     * @param mixed $input
     * @return array<string, string>
     */
    public function sanitize($input): array
    {
        $input = is_array($input) ? $input : [];

        return [
            'api_base_url' => esc_url_raw((string) ($input['api_base_url'] ?? '')),
            'site_id' => sanitize_text_field((string) ($input['site_id'] ?? '')),
            'site_token' => sanitize_text_field((string) ($input['site_token'] ?? '')),
        ];
    }

    public function renderApiBaseUrlField(): void
    {
        $settings = $this->all();

        printf(
            '<input type="url" name="%1$s[api_base_url]" value="%2$s" class="regular-text" placeholder="https://waf-saas.firephage.com" />',
            esc_attr(self::OPTION_KEY),
            esc_attr($settings['api_base_url'])
        );
    }

    public function renderSiteIdField(): void
    {
        $settings = $this->all();

        printf(
            '<input type="text" name="%1$s[site_id]" value="%2$s" class="regular-text" />',
            esc_attr(self::OPTION_KEY),
            esc_attr($settings['site_id'])
        );
    }

    public function renderSiteTokenField(): void
    {
        $settings = $this->all();

        printf(
            '<input type="password" name="%1$s[site_token]" value="%2$s" class="regular-text" autocomplete="off" />',
            esc_attr(self::OPTION_KEY),
            esc_attr($settings['site_token'])
        );
    }
}
