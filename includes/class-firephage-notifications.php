<?php

namespace FirePhage\Security;

use FirePhage\Security\Reports\ReportBuilder;

if (! defined('ABSPATH')) {
    exit;
}

final class Notifications
{
    public const STATE_OPTION_KEY = 'firephage_security_notification_state';
    private const EMAIL_ACTION_QUERY = 'firephage_notification_action';

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

    public function maybeHandleEmailPreferenceAction(): void
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Signed public email links are validated below.
        $action = isset($_GET[self::EMAIL_ACTION_QUERY]) ? sanitize_key((string) wp_unslash($_GET[self::EMAIL_ACTION_QUERY])) : '';

        if ($action !== 'mute-alert') {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Signed public email links are validated below.
        $alertType = isset($_GET['alert_type']) ? sanitize_key((string) wp_unslash($_GET['alert_type'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Signed public email links are validated below.
        $email = isset($_GET['email']) ? sanitize_email((string) wp_unslash($_GET['email'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Signed public email links are validated below.
        $token = isset($_GET['token']) ? sanitize_text_field((string) wp_unslash($_GET['token'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Signed public email links are validated below.
        $confirmed = isset($_GET['confirm']) ? sanitize_key((string) wp_unslash($_GET['confirm'])) === '1' : false;

        if (! $this->isValidAlertType($alertType) || $email === '' || $token === '' || ! hash_equals($this->emailActionToken($alertType, $email), $token)) {
            wp_die(esc_html__('This notification link is invalid or has expired.', 'firephage-security'), esc_html__('FirePhage Security', 'firephage-security'), ['response' => 403]);
        }

        if ($email !== $this->recipient($this->settings->all())) {
            wp_die(esc_html__('This notification link no longer matches the current alert email address for this site.', 'firephage-security'), esc_html__('FirePhage Security', 'firephage-security'), ['response' => 403]);
        }

        if (! $confirmed) {
            $this->renderMuteAlertConfirmation($alertType, $email, $token);
        }

        $this->muteAlertType($alertType);
        $this->renderMuteAlertResult($alertType);
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
        $hasMalware = (int) ($state['suspicious_files'] ?? 0) > 0;
        $hasCoreIntegrity = $this->hasCoreIntegrityFinding($state);
        $canSendMalware = ($settings['notifications_alert_malware'] ?? '1') === '1'
            && $hasMalware
            && ($notificationState['last_malware_alert_scan_id'] ?? '') !== $scanId;
        $canSendCore = ($settings['notifications_alert_core_edits'] ?? '1') === '1'
            && $hasCoreIntegrity
            && ($notificationState['last_core_alert_scan_id'] ?? '') !== $scanId;

        if ($canSendMalware && $canSendCore) {
            $this->sendEmail(
                $recipient,
                __('Security issues detected on your WordPress site', 'firephage-security'),
                $this->buildCombinedAlert($state, $settings)
            );

            $notificationState['last_malware_alert_scan_id'] = $scanId;
            $notificationState['last_core_alert_scan_id'] = $scanId;
        } elseif ($canSendMalware) {
            $this->sendEmail(
                $recipient,
                __('Malware detected on your WordPress site', 'firephage-security'),
                $this->buildMalwareAlert($state, $settings)
            );

            $notificationState['last_malware_alert_scan_id'] = $scanId;
        } elseif ($canSendCore) {
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
        $items = $this->buildMalwareFindingItems($state);
        $officialChecksumMismatches = (int) ($state['official_checksum_mismatches'] ?? 0);
        $baselineChanges = (int) ($state['baseline_changes'] ?? 0);
        if ($items === '') {
            $items = '<li>' . esc_html__('Malicious files were detected, but the current alert does not include individual rows.', 'firephage-security') . '</li>';
        }

        $content = '<p>' . esc_html__('FirePhage Security detected malicious files during the latest malware scan.', 'firephage-security') . '</p>';
        $content .= '<div class="metric-row"><div class="metric-card"><span>Malicious Files</span><strong>' . (int) ($state['suspicious_files'] ?? 0) . '</strong></div><div class="metric-card"><span>Official Checksum Mismatches</span><strong>' . $officialChecksumMismatches . '</strong></div><div class="metric-card"><span>Local Baseline Changes</span><strong>' . $baselineChanges . '</strong></div></div>';
        $content .= '<h3>' . esc_html__('Recent malicious paths', 'firephage-security') . '</h3><ul>' . $items . '</ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Open FirePhage Security', 'firephage-security') . '</a></p>';
        $content .= $this->muteAlertPanel('malware', $settings);
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
        $items = $this->buildCoreIntegrityItems($state);
        if ($items === '') {
            $items = '<li>' . esc_html__('Core checksum mismatches were detected, but no file list is available in this alert.', 'firephage-security') . '</li>';
        }

        $content = '<p>' . esc_html__('Some WordPress core files do not match official checksums. Review these changes carefully, especially if they were unexpected.', 'firephage-security') . '</p>';
        $content .= '<ul>' . $items . '</ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Review Scanner Findings', 'firephage-security') . '</a></p>';
        $content .= $this->muteAlertPanel('core', $settings);
        $content .= $this->upsellPanel($settings);

        return $this->wrapEmail(
            __('Core Integrity Alert', 'firephage-security'),
            __('WordPress core edits detected', 'firephage-security'),
            $content
        );
    }

    /**
     * @param array<string, mixed> $state
     * @param array<string, string> $settings
     */
    private function buildCombinedAlert(array $state, array $settings): string
    {
        $malwareItems = $this->buildMalwareFindingItems($state);
        $coreItems = $this->buildCoreIntegrityItems($state);
        $officialChecksumMismatches = (int) ($state['official_checksum_mismatches'] ?? 0);
        $baselineChanges = (int) ($state['baseline_changes'] ?? 0);

        if ($malwareItems === '') {
            $malwareItems = '<li>' . esc_html__('Malicious files were detected, but the current alert does not include individual rows.', 'firephage-security') . '</li>';
        }

        if ($coreItems === '') {
            $coreItems = '<li>' . esc_html__('Core checksum mismatches were detected, but no file list is available in this alert.', 'firephage-security') . '</li>';
        }

        $content = '<p>' . esc_html__('FirePhage Security detected both malicious files and unexpected WordPress core file changes during the latest scan.', 'firephage-security') . '</p>';
        $content .= '<div class="metric-row"><div class="metric-card"><span>Malicious Files</span><strong>' . (int) ($state['suspicious_files'] ?? 0) . '</strong></div><div class="metric-card"><span>Official Checksum Mismatches</span><strong>' . $officialChecksumMismatches . '</strong></div><div class="metric-card"><span>Local Baseline Changes</span><strong>' . $baselineChanges . '</strong></div></div>';
        $content .= '<h3>' . esc_html__('Recent malicious paths', 'firephage-security') . '</h3><ul>' . $malwareItems . '</ul>';
        $content .= '<h3>' . esc_html__('Modified core files', 'firephage-security') . '</h3><ul>' . $coreItems . '</ul>';
        $content .= '<p><a class="button" href="' . esc_url(admin_url('admin.php?page=firephage-security')) . '">' . esc_html__('Open FirePhage Security', 'firephage-security') . '</a></p>';
        $content .= $this->muteAlertPanel('malware', $settings);
        $content .= $this->muteAlertPanel('core', $settings);
        $content .= $this->upsellPanel($settings);

        return $this->wrapEmail(
            __('Security Alert', 'firephage-security'),
            __('Malware and core file changes detected', 'firephage-security'),
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

        /* translators: %d: Number of WordPress core updates pending. */
        $coreUpdatesText = sprintf(esc_html__('%d WordPress core updates pending', 'firephage-security'), (int) ($updates['core_updates'] ?? 0));
        /* translators: %d: Number of plugin updates pending. */
        $pluginUpdatesText = sprintf(esc_html__('%d plugin updates pending', 'firephage-security'), (int) ($updates['plugin_updates'] ?? 0));
        /* translators: %d: Number of theme updates pending. */
        $themeUpdatesText = sprintf(esc_html__('%d theme updates pending', 'firephage-security'), (int) ($updates['theme_updates'] ?? 0));
        /* translators: %s: Latest malware scan status. */
        $scanStatusText = sprintf(esc_html__('Last scan status: %s', 'firephage-security'), esc_html(ucfirst((string) ($scan['status'] ?? 'idle'))));
        /* translators: %d: Number of files scanned. */
        $filesScannedText = sprintf(esc_html__('Files scanned: %d', 'firephage-security'), (int) ($scan['scanned_files'] ?? 0));
        /* translators: %d: Number of active brute-force lockouts. */
        $activeLockoutsText = sprintf(esc_html__('Active brute-force lockouts: %d', 'firephage-security'), (int) ($bruteForce['active_lockouts_count'] ?? 0));

        $content = '<p>' . esc_html__('Here is your weekly FirePhage Security summary for this WordPress site.', 'firephage-security') . '</p>';
        $content .= '<div class="metric-row"><div class="metric-card"><span>Malicious Files</span><strong>' . (int) ($scan['suspicious_files'] ?? 0) . '</strong></div><div class="metric-card"><span>Active Lockouts</span><strong>' . (int) ($bruteForce['active_lockouts_count'] ?? 0) . '</strong></div><div class="metric-card"><span>Pending Updates</span><strong>' . $pendingUpdates . '</strong></div></div>';
        $content .= '<h3>' . esc_html__('Update reminders', 'firephage-security') . '</h3><ul><li>' . $coreUpdatesText . '</li><li>' . $pluginUpdatesText . '</li><li>' . $themeUpdatesText . '</li></ul>';
        $content .= '<h3>' . esc_html__('Scanner and login protection', 'firephage-security') . '</h3><ul><li>' . $scanStatusText . '</li><li>' . $filesScannedText . '</li><li>' . $activeLockoutsText . '</li></ul>';
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
        return '<div class="upsell-panel"><p class="upsell-eyebrow">' . esc_html__('FirePhage Pro', 'firephage-security') . '</p><h3>' . esc_html__('Upgrade to WAF, CDN, and Cache', 'firephage-security') . '</h3><p>' . esc_html__('Add advanced firewall protection, global CDN delivery, and cache controls built for major WordPress performance gains.', 'firephage-security') . '</p><p><a class="button button-alt" href="' . esc_url((string) ($settings['dashboard_url'] ?? 'https://firephage.com')) . '" target="_blank" rel="noopener noreferrer">' . esc_html__('Explore FirePhage', 'firephage-security') . '</a></p></div>';
    }

    private function wrapEmail(string $eyebrow, string $title, string $content): string
    {
        return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0;background:#e6f4fb;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:linear-gradient(180deg,#e6f4fb 0%,#f8fbfd 100%);padding:32px 16px;"><tr><td align="center"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:720px;background:#ffffff;border-radius:28px;overflow:hidden;box-shadow:0 24px 60px rgba(15,23,42,.14);"><tr><td style="padding:36px 36px 28px;background:linear-gradient(135deg,#082f49 0%,#0f172a 100%);color:#f8fafc;"><p style="margin:0 0 10px;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:#bae6fd;">' . esc_html($eyebrow) . '</p><h1 style="margin:0;font-size:30px;line-height:1.15;color:#fff;">' . esc_html($title) . '</h1><p style="margin:14px 0 0;font-size:15px;line-height:1.6;color:rgba(241,245,249,.9);">' . esc_html(get_bloginfo('name')) . ' · ' . esc_html(home_url('/')) . '</p></td></tr><tr><td style="padding:32px 36px;">' . $content . '</td></tr></table></td></tr></table></body></html>';
    }

    /**
     * @param array<string, mixed> $state
     */
    private function buildMalwareFindingItems(array $state): string
    {
        $items = '';
        $findings = isset($state['findings']) && is_array($state['findings']) ? array_slice($state['findings'], -6) : [];

        foreach ($findings as $finding) {
            if (! is_array($finding) || ($finding['type'] ?? '') !== 'malware') {
                continue;
            }

            $items .= '<li><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></li>';
        }

        return $items;
    }

    /**
     * @param array<string, mixed> $state
     */
    private function buildCoreIntegrityItems(array $state): string
    {
        $items = '';
        $findings = isset($state['findings']) && is_array($state['findings']) ? array_slice($state['findings'], -10) : [];

        foreach ($findings as $finding) {
            if (! is_array($finding) || ($finding['type'] ?? '') !== 'integrity' || ($finding['source'] ?? '') !== 'core_checksum') {
                continue;
            }

            $items .= '<li><code>' . esc_html((string) ($finding['file'] ?? '')) . '</code></li>';
        }

        return $items;
    }

    /**
     * @param array<string, string> $settings
     */
    private function muteAlertPanel(string $alertType, array $settings): string
    {
        $recipient = $this->recipient($settings);

        if ($recipient === '') {
            return '';
        }

        return '<div style="margin-top:24px;padding-top:18px;border-top:1px solid #e2e8f0;"><p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#64748b;">' . esc_html__('Need fewer alerts? You can stop this specific email type, but it is not recommended until the issue has been reviewed and resolved.', 'firephage-security') . '</p><p style="margin:0;"><a href="' . esc_url($this->emailActionUrl($alertType, $recipient)) . '" style="font-size:13px;color:#0f766e;text-decoration:underline;">' . esc_html($alertType === 'malware' ? __('Don’t email me again about malware findings', 'firephage-security') : __('Don’t email me again about modified core files', 'firephage-security')) . '</a></p></div>';
    }

    private function emailActionUrl(string $alertType, string $email): string
    {
        return add_query_arg([
            self::EMAIL_ACTION_QUERY => 'mute-alert',
            'alert_type' => $alertType,
            'email' => $email,
            'token' => $this->emailActionToken($alertType, $email),
        ], home_url('/'));
    }

    private function emailActionToken(string $alertType, string $email): string
    {
        return hash_hmac('sha256', $alertType . '|' . strtolower($email) . '|' . home_url('/'), wp_salt('auth'));
    }

    private function isValidAlertType(string $alertType): bool
    {
        return in_array($alertType, ['malware', 'core'], true);
    }

    private function muteAlertType(string $alertType): void
    {
        if ($alertType === 'malware') {
            $this->settings->update(['notifications_alert_malware' => '0']);
            return;
        }

        $this->settings->update(['notifications_alert_core_edits' => '0']);
    }

    private function renderMuteAlertConfirmation(string $alertType, string $email, string $token): void
    {
        $title = $alertType === 'malware'
            ? __('Stop malware alert emails?', 'firephage-security')
            : __('Stop modified core file emails?', 'firephage-security');
        $body = $alertType === 'malware'
            ? __('This is not recommended. Malware findings should be reviewed as soon as possible. If you continue, FirePhage Security will stop sending this malware alert email to the selected address for this site.', 'firephage-security')
            : __('This is not recommended. Modified WordPress core files should be reviewed as soon as possible. If you continue, FirePhage Security will stop sending this modified core file alert email to the selected address for this site.', 'firephage-security');
        $confirmUrl = add_query_arg([
            self::EMAIL_ACTION_QUERY => 'mute-alert',
            'alert_type' => $alertType,
            'email' => $email,
            'token' => $token,
            'confirm' => '1',
        ], home_url('/'));

        /* translators: %s: Alert email address. */
        $alertEmailText = sprintf(__('Alert email: %s', 'firephage-security'), $email);

        wp_die(
            '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0;background:#eef5f9;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;"><div style="max-width:560px;margin:48px auto;padding:0 16px;"><div style="background:#fff;border:1px solid #dbe7ef;border-radius:24px;box-shadow:0 20px 40px rgba(15,23,42,.08);padding:32px;"><p style="margin:0 0 10px;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#0ea5e9;">' . esc_html__('FirePhage Security', 'firephage-security') . '</p><h1 style="margin:0 0 14px;font-size:28px;line-height:1.2;">' . esc_html($title) . '</h1><p style="margin:0 0 18px;font-size:15px;line-height:1.7;color:#334155;">' . esc_html($body) . '</p><p style="margin:0 0 22px;font-size:14px;color:#64748b;">' . esc_html($alertEmailText) . '</p><p style="margin:0 0 12px;"><a href="' . esc_url($confirmUrl) . '" style="display:inline-block;padding:12px 18px;border-radius:999px;background:#0f766e;color:#fff;text-decoration:none;font-weight:600;">' . esc_html__('Yes, stop this alert', 'firephage-security') . '</a></p><p style="margin:0;"><a href="' . esc_url(admin_url('admin.php?page=firephage-security&tab=notifications')) . '" style="color:#475569;text-decoration:underline;">' . esc_html__('Keep alerts enabled', 'firephage-security') . '</a></p></div></div></body></html>',
            esc_html__('FirePhage Security', 'firephage-security'),
            ['response' => 200]
        );
    }

    private function renderMuteAlertResult(string $alertType): void
    {
        $message = $alertType === 'malware'
            ? __('Malware alert emails are now turned off for this site. You can turn them back on later in FirePhage Security > Notifications.', 'firephage-security')
            : __('Modified core file alert emails are now turned off for this site. You can turn them back on later in FirePhage Security > Notifications.', 'firephage-security');

        wp_die(
            '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head><body style="margin:0;background:#eef5f9;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;color:#0f172a;"><div style="max-width:560px;margin:48px auto;padding:0 16px;"><div style="background:#fff;border:1px solid #dbe7ef;border-radius:24px;box-shadow:0 20px 40px rgba(15,23,42,.08);padding:32px;"><p style="margin:0 0 10px;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#0ea5e9;">' . esc_html__('FirePhage Security', 'firephage-security') . '</p><h1 style="margin:0 0 14px;font-size:28px;line-height:1.2;">' . esc_html__('Preference updated', 'firephage-security') . '</h1><p style="margin:0 0 18px;font-size:15px;line-height:1.7;color:#334155;">' . esc_html($message) . '</p><p style="margin:0;"><a href="' . esc_url(admin_url('admin.php?page=firephage-security&tab=notifications')) . '" style="color:#0f766e;text-decoration:underline;">' . esc_html__('Open notification settings', 'firephage-security') . '</a></p></div></div></body></html>',
            esc_html__('FirePhage Security', 'firephage-security'),
            ['response' => 200]
        );
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
