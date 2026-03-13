<?php

namespace FirePhage\Security;

use FirePhage\Security\Reports\ReportBuilder;

if (! defined('ABSPATH')) {
    exit;
}

final class Notifications
{
    public const STATE_OPTION_KEY = 'firephage_security_notification_state';

    /**
     * @var Settings
     */
    private $settings;

    /**
     * @var ReportBuilder
     */
    private $reportBuilder;

    public function __construct(Settings $settings, ReportBuilder $reportBuilder)
    {
        $this->settings = $settings;
        $this->reportBuilder = $reportBuilder;
    }

    public function handleScanCompleted(array $state): void
    {
        $settings = $this->settings->all();

        if (($settings['notifications_enabled'] ?? '1') !== '1') {
            return;
        }

        $recipient = $this->recipient($settings);
        $scanId = (string) ($state['scan_id'] ?? '');

        if ($recipient === '' || $scanId === '') {
            return;
        }

        $notificationState = $this->state();

        if (($settings['notifications_alert_malware'] ?? '1') === '1'
            && (int) ($state['suspicious_files'] ?? 0) > 0
            && ($notificationState['last_malware_alert_scan_id'] ?? '') !== $scanId) {
            $this->sendEmail(
                $recipient,
                __('Malware detected on your WordPress site', 'firephage-security'),
                $this->buildMalwareAlert($state, $settings)
            );

            $notificationState['last_malware_alert_scan_id'] = $scanId;
        }

        if (($settings['notifications_alert_core_edits'] ?? '1') === '1'
            && $this->hasCoreIntegrityFinding($state)
            && ($notificationState['last_core_alert_scan_id'] ?? '') !== $scanId) {
            $this->sendEmail(
                $recipient,
                __('WordPress core checksum changes detected', 'firephage-security'),
                $this->buildCoreIntegrityAlert($state, $settings)
            );

            $notificationState['last_core_alert_scan_id'] = $scanId;
        }

        $this->writeState($notificationState);
    }

    public function sendWeeklySummary(): void
    {
        $settings = $this->settings->all();

        if (($settings['notifications_enabled'] ?? '1') !== '1' || ($settings['notifications_weekly_report'] ?? '1') !== '1') {
            return;
        }

        $recipient = $this->recipient($settings);

        if ($recipient === '') {
            return;
        }

        $report = $this->reportBuilder->build(true);

        if (! $this->sendEmail(
            $recipient,
            __('Your weekly FirePhage Security report', 'firephage-security'),
            $this->buildWeeklyReport($report, $settings)
        )) {
            return;
        }

        $state = $this->state();
        $state['last_weekly_report_at'] = current_time('mysql');
        $this->writeState($state);
    }

    /**
     * @return array<string, string>
     */
    public function state(): array
    {
        $defaults = [
            'last_malware_alert_scan_id' => '',
            'last_core_alert_scan_id' => '',
            'last_weekly_report_at' => '',
        ];

        $value = get_option(self::STATE_OPTION_KEY, []);

        return is_array($value) ? array_merge($defaults, array_intersect_key($value, $defaults)) : $defaults;
    }

    /**
     * @param array<string, string> $state
     */
    private function writeState(array $state): void
    {
        update_option(self::STATE_OPTION_KEY, $state, false);
    }

    /**
     * @param array<string, string> $settings
     */
    private function recipient(array $settings): string
    {
        $email = sanitize_email((string) ($settings['notification_email'] ?? ''));

        if ($email !== '') {
            return $email;
        }

        return sanitize_email((string) get_option('admin_email', ''));
    }

    /**
     * @param array<string, mixed> $state
     */
    private function hasCoreIntegrityFinding(array $state): bool
    {
        $findings = isset($state['findings']) && is_array($state['findings']) ? $state['findings'] : [];

        foreach ($findings as $finding) {
            if (is_array($finding) && ($finding['type'] ?? '') === 'integrity' && ($finding['source'] ?? '') === 'core_checksum') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $state
     * @param array<string, string> $settings
     */
    private function buildMalwareAlert(array $state, array $settings): string
    {
        $items = '';
        $findings = isset($state['findings']) && is_array($state['findings']) ? array_slice($state['findings'], -6) : [];

        foreach ($findings as $finding) {
            if (! is_array($finding) || ($finding['type'] ?? '') !== 'malware') {
                continue;
            }

            $items .= '<li><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></li>';
        }

        if ($items === '') {
            $items = '<li>' . esc_html__('Suspicious files were detected, but the current alert does not include individual rows.', 'firephage-security') . '</li>';
        }

        $content = '<p>' . esc_html__('FirePhage Security detected suspicious files during the latest malware scan.', 'firephage-security') . '</p>';
        $content .= '<div class="metric-row"><div class="metric-card"><span>Suspicious Files</span><strong>' . (int) ($state['suspicious_files'] ?? 0) . '</strong></div><div class="metric-card"><span>Integrity Issues</span><strong>' . (int) ($state['integrity_issues'] ?? 0) . '</strong></div></div>';
        $content .= '<h3>' . esc_html__('Recent suspicious paths', 'firephage-security') . '</h3><ul>' . $items . '</ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Open FirePhage Security', 'firephage-security') . '</a></p>';
        $content .= $this->upsellPanel($settings);

        return $this->wrapEmail(
            __('Malware Alert', 'firephage-security'),
            __('Immediate action recommended', 'firephage-security'),
            $content
        );
    }

    /**
     * @param array<string, mixed> $state
     * @param array<string, string> $settings
     */
    private function buildCoreIntegrityAlert(array $state, array $settings): string
    {
        $items = '';
        $findings = isset($state['findings']) && is_array($state['findings']) ? array_slice($state['findings'], -10) : [];

        foreach ($findings as $finding) {
            if (! is_array($finding) || ($finding['type'] ?? '') !== 'integrity' || ($finding['source'] ?? '') !== 'core_checksum') {
                continue;
            }

            $items .= '<li><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></li>';
        }

        if ($items === '') {
            $items = '<li>' . esc_html__('Core checksum mismatches were detected, but no file list is available in this alert.', 'firephage-security') . '</li>';
        }

        $content = '<p>' . esc_html__('Some WordPress core files do not match official checksums. Review these changes carefully, especially if they were unexpected.', 'firephage-security') . '</p>';
        $content .= '<ul>' . $items . '</ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Review Scanner Findings', 'firephage-security') . '</a></p>';
        $content .= $this->upsellPanel($settings);

        return $this->wrapEmail(
            __('Core Integrity Alert', 'firephage-security'),
            __('WordPress core edits detected', 'firephage-security'),
            $content
        );
    }

    /**
     * @param array<string, mixed> $report
     * @param array<string, string> $settings
     */
    private function buildWeeklyReport(array $report, array $settings): string
    {
        $health = $report['health'];
        $scan = $report['malware_scan'];
        $bruteForce = $report['brute_force'];
        $updates = $health['updates'];
        $pendingUpdates = (int) ($updates['core_updates'] ?? 0) + (int) ($updates['plugin_updates'] ?? 0) + (int) ($updates['theme_updates'] ?? 0);

        $content = '<p>' . esc_html__('Here is your weekly FirePhage Security summary for this WordPress site.', 'firephage-security') . '</p>';
        $content .= '<div class="metric-row"><div class="metric-card"><span>Suspicious Files</span><strong>' . (int) ($scan['suspicious_files'] ?? 0) . '</strong></div><div class="metric-card"><span>Active Lockouts</span><strong>' . (int) ($bruteForce['active_lockouts_count'] ?? 0) . '</strong></div><div class="metric-card"><span>Pending Updates</span><strong>' . $pendingUpdates . '</strong></div></div>';
        $content .= '<h3>' . esc_html__('Update reminders', 'firephage-security') . '</h3><ul><li>' . sprintf(esc_html__('%d WordPress core updates pending', 'firephage-security'), (int) ($updates['core_updates'] ?? 0)) . '</li><li>' . sprintf(esc_html__('%d plugin updates pending', 'firephage-security'), (int) ($updates['plugin_updates'] ?? 0)) . '</li><li>' . sprintf(esc_html__('%d theme updates pending', 'firephage-security'), (int) ($updates['theme_updates'] ?? 0)) . '</li></ul>';
        $content .= '<h3>' . esc_html__('Scanner and login protection', 'firephage-security') . '</h3><ul><li>' . sprintf(esc_html__('Last scan status: %s', 'firephage-security'), esc_html(ucfirst((string) ($scan['status'] ?? 'idle')))) . '</li><li>' . sprintf(esc_html__('Files scanned: %d', 'firephage-security'), (int) ($scan['scanned_files'] ?? 0)) . '</li><li>' . sprintf(esc_html__('Active brute-force lockouts: %d', 'firephage-security'), (int) ($bruteForce['active_lockouts_count'] ?? 0)) . '</li></ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Open FirePhage Security', 'firephage-security') . '</a></p>';
        $content .= $this->upsellPanel($settings);

        return $this->wrapEmail(
            __('Weekly Security Report', 'firephage-security'),
            __('Your WordPress security summary', 'firephage-security'),
            $content
        );
    }

    /**
     * @param array<string, string> $settings
     */
    private function upsellPanel(array $settings): string
    {
        return '<div class="upsell-panel"><p class="upsell-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p><h3>' . esc_html__('Upgrade to WAF, CDN, and Cache', 'firephage-security') . '</h3><p>' . esc_html__('Add advanced firewall protection, global CDN delivery, and cache controls built for major WordPress performance gains.', 'firephage-security') . '</p><p><a class="button button-alt" href="' . esc_url((string) ($settings['dashboard_url'] ?? 'https://waf-saas.firephage.com')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Explore FirePhage', 'firephage-security') . '</a></p></div>';
    }

    private function wrapEmail(string $eyebrow, string $title, string $content): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0;background:#e6f4fb;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:linear-gradient(180deg,#e6f4fb 0%,#f8fbfd 100%);padding:32px 16px;"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:720px;background:#ffffff;border-radius:28px;overflow:hidden;box-shadow:0 24px 60px rgba(15,23,42,.14);"><tr><td style="padding:36px 36px 28px;background:linear-gradient(135deg,#082f49 0%,#0f172a 100%);color:#f8fafc;"><p style="margin:0 0 10px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#bae6fd;">' . esc_html($eyebrow) . '</p><h1 style="margin:0;font-size:30px;line-height:1.15;color:#fff;">' . esc_html($title) . '</h1><p style="margin:14px 0 0;font-size:15px;line-height:1.6;color:rgba(241,245,249,.9);">' . esc_html(get_bloginfo('name')) . ' · ' . esc_html(home_url('/')) . '</p></td></tr><tr><td style="padding:32px 36px;"><style>.metric-row{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.metric-card{flex:1 1 180px;padding:16px 18px;border:1px solid #dbeafe;border-radius:18px;background:#f8fbfd}.metric-card span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#64748b;margin-bottom:8px}.metric-card strong{font-size:28px;color:#0f172a}.upsell-panel{margin-top:28px;padding:24px;border-radius:24px;background:linear-gradient(135deg,#fff7ed 0%,#ffffff 100%);border:1px solid #fed7aa}.upsell-eyebrow{margin:0 0 10px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#c2410c}.button,.button-alt{display:inline-block;padding:12px 18px;border-radius:999px;background:#0ea5e9;color:#fff !important;text-decoration:none;font-weight:600}.button-alt{background:#ea580c}h3{margin:24px 0 10px;color:#0f172a}p,li{font-size:15px;line-height:1.65;color:#334155}ul{padding-left:18px}code{background:#eff6ff;padding:2px 6px;border-radius:8px;color:#0f172a}</style>' . $content . '</td></tr></table></td></tr></table></body></html>';
    }

    private function sendEmail(string $recipient, string $subject, string $body): bool
    {
        add_filter('wp_mail_content_type', [$this, 'htmlContentType']);
        $sent = wp_mail($recipient, $subject, $body);
        remove_filter('wp_mail_content_type', [$this, 'htmlContentType']);

        return (bool) $sent;
    }

    public function htmlContentType(): string
    {
        return 'text/html';
    }
}
