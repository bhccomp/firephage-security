<?php

namespace FirePhage\Security\Admin;

use FirePhage\Security\Settings;

if (! defined('ABSPATH')) {
    exit;
}

final class Admin
{
    private Settings $settings;

    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
    }

    public function registerMenus(): void
    {
        $capability = 'manage_options';

        add_menu_page(
            __('FirePhage Security', 'firephage-security'),
            __('FirePhage', 'firephage-security'),
            $capability,
            'firephage-security',
            [$this, 'renderOverviewPage'],
            'dashicons-shield-alt',
            58
        );

        add_submenu_page('firephage-security', __('Overview', 'firephage-security'), __('Overview', 'firephage-security'), $capability, 'firephage-security', [$this, 'renderOverviewPage']);
        add_submenu_page('firephage-security', __('Malware Scanner', 'firephage-security'), __('Malware Scanner', 'firephage-security'), $capability, 'firephage-security-malware', [$this, 'renderMalwarePage']);
        add_submenu_page('firephage-security', __('Vulnerabilities', 'firephage-security'), __('Vulnerabilities', 'firephage-security'), $capability, 'firephage-security-vulnerabilities', [$this, 'renderVulnerabilitiesPage']);
        add_submenu_page('firephage-security', __('Login Protection', 'firephage-security'), __('Login Protection', 'firephage-security'), $capability, 'firephage-security-login', [$this, 'renderLoginProtectionPage']);
        add_submenu_page('firephage-security', __('Security Headers', 'firephage-security'), __('Security Headers', 'firephage-security'), $capability, 'firephage-security-headers', [$this, 'renderHeadersPage']);
        add_submenu_page('firephage-security', __('Security Report', 'firephage-security'), __('Security Report', 'firephage-security'), $capability, 'firephage-security-report', [$this, 'renderReportPage']);
        add_submenu_page('firephage-security', __('Settings', 'firephage-security'), __('Settings', 'firephage-security'), $capability, 'firephage-security-settings', [$this, 'renderSettingsPage']);
    }

    public function renderOverviewPage(): void
    {
        $settings = $this->settings->all();

        $cards = [
            [
                'title' => __('Firewall', 'firephage-security'),
                'description' => __('Blocked traffic, top attack sources, and current protection posture from FirePhage.', 'firephage-security'),
                'status' => __('Coming soon', 'firephage-security'),
            ],
            [
                'title' => __('CDN & Cache', 'firephage-security'),
                'description' => __('Traffic and caching insights connected to the FirePhage dashboard.', 'firephage-security'),
                'status' => __('Coming soon', 'firephage-security'),
            ],
            [
                'title' => __('Site Security', 'firephage-security'),
                'description' => __('WordPress-focused checks including malware scanning, plugin vulnerabilities, and login protection.', 'firephage-security'),
                'status' => __('Scaffolded', 'firephage-security'),
            ],
        ];

        $this->renderPageStart(__('FirePhage Security Overview', 'firephage-security'), __('Basic visibility into FirePhage and WordPress security status.', 'firephage-security'));

        if ($settings['api_base_url'] === '' || $settings['site_token'] === '') {
            echo '<div class="notice notice-warning"><p>' .
                esc_html__('FirePhage is not connected yet. Open Settings and add the API details to enable remote insights.', 'firephage-security') .
                '</p></div>';
        }

        echo '<div class="firephage-grid">';

        foreach ($cards as $card) {
            echo '<div class="firephage-card">';
            echo '<h2>' . esc_html($card['title']) . '</h2>';
            echo '<p>' . esc_html($card['description']) . '</p>';
            echo '<p><strong>' . esc_html__('Status:', 'firephage-security') . '</strong> ' . esc_html($card['status']) . '</p>';
            echo '</div>';
        }

        echo '</div>';

        $this->renderPageEnd();
    }

    public function renderMalwarePage(): void
    {
        $this->renderPlaceholderPage(
            __('Malware Scanner', 'firephage-security'),
            __('This module will scan WordPress files against a basic malware signature set and report suspicious matches.', 'firephage-security')
        );
    }

    public function renderVulnerabilitiesPage(): void
    {
        $this->renderPlaceholderPage(
            __('Plugin Vulnerabilities', 'firephage-security'),
            __('This module will monitor installed plugins and themes for known security issues.', 'firephage-security')
        );
    }

    public function renderLoginProtectionPage(): void
    {
        $this->renderPlaceholderPage(
            __('WP Login Protection', 'firephage-security'),
            __('This module will add brute force protection and login hardening for wp-login and XML-RPC entry points.', 'firephage-security')
        );
    }

    public function renderHeadersPage(): void
    {
        $this->renderPlaceholderPage(
            __('Security Headers', 'firephage-security'),
            __('This module will audit security headers and report gaps that affect browser-side hardening.', 'firephage-security')
        );
    }

    public function renderReportPage(): void
    {
        $this->renderPlaceholderPage(
            __('Security Report', 'firephage-security'),
            __('This module will combine FirePhage insights with WordPress checks into a single security report.', 'firephage-security')
        );
    }

    public function renderSettingsPage(): void
    {
        $this->renderPageStart(__('FirePhage Settings', 'firephage-security'), __('Configure the connection between this WordPress site and FirePhage.', 'firephage-security'));

        echo '<form method="post" action="options.php">';
        settings_fields('firephage_security');
        do_settings_sections('firephage_security');
        submit_button(__('Save Settings', 'firephage-security'));
        echo '</form>';

        $this->renderPageEnd();
    }

    private function renderPlaceholderPage(string $title, string $description): void
    {
        $this->renderPageStart($title, $description);

        echo '<div class="firephage-card">';
        echo '<p>' . esc_html__('Scaffolded and ready for implementation.', 'firephage-security') . '</p>';
        echo '</div>';

        $this->renderPageEnd();
    }

    private function renderPageStart(string $title, string $description): void
    {
        echo '<div class="wrap firephage-admin">';
        echo '<h1>' . esc_html($title) . '</h1>';
        echo '<p>' . esc_html($description) . '</p>';
        echo '<style>
            .firephage-admin .firephage-grid {
                display: grid;
                gap: 16px;
                grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                margin-top: 20px;
            }
            .firephage-admin .firephage-card {
                background: #ffffff;
                border: 1px solid #dcdcde;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
            }
            .firephage-admin .firephage-card h2 {
                margin-top: 0;
            }
        </style>';
    }

    private function renderPageEnd(): void
    {
        echo '</div>';
    }
}
