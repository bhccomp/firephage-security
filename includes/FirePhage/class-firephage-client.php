<?php

namespace FirePhage\Security\FirePhage;

use WP_Error;

if (! defined('ABSPATH')) {
    exit;
}

final class Client
{
    /**
     * @return array<string, mixed>|WP_Error
     */
    public function connect(string $dashboardUrl, string $connectionToken)
    {
        $response = wp_remote_post(
            untrailingslashit($dashboardUrl) . '/api/plugin/connect',
            [
                'timeout' => 15,
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                ],
                'body' => wp_json_encode([
                    'connection_token' => $connectionToken,
                    'home_url' => home_url('/'),
                    'site_url' => site_url('/'),
                    'admin_email' => get_option('admin_email'),
                    'plugin_version' => FIREPHAGE_SECURITY_VERSION,
                ]),
            ]
        );

        return $this->normalizeResponse($response, 'connect');
    }

    /**
     * @param array<string, string> $settings
     * @param array<string, mixed> $report
     * @return array<string, mixed>|WP_Error
     */
    public function sendReport(array $settings, array $report)
    {
        if (($settings['site_token'] ?? '') === '') {
            return new WP_Error('missing_site_token', __('Connect the plugin before sending reports.', 'firephage-security'));
        }

        $response = wp_remote_post(
            untrailingslashit($settings['dashboard_url']) . '/api/plugin/report',
            [
                'timeout' => 20,
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => 'Bearer ' . $settings['site_token'],
                ],
                'body' => wp_json_encode([
                    'site_id' => $settings['site_id'],
                    'report' => $report,
                ]),
            ]
        );

        return $this->normalizeResponse($response, 'report');
    }

    /**
     * @return array<string, mixed>|WP_Error
     */
    public function fetchPublicChecksums(string $serviceUrl, string $type, string $slug, string $version)
    {
        $response = wp_remote_get(
            add_query_arg(
                [
                    'type' => $type,
                    'slug' => $slug,
                    'version' => $version,
                ],
                untrailingslashit($serviceUrl) . '/api/plugin/checksums'
            ),
            [
                'timeout' => 12,
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]
        );

        return $this->normalizeResponse($response, 'checksums');
    }

    /**
     * @return array<string, mixed>|WP_Error
     */
    public function fetchPublicSignatures(string $serviceUrl)
    {
        return new WP_Error('missing_signature_token', __('A free FirePhage signature token is required.', 'firephage-security'));
    }

    /**
     * @return array<string, mixed>|WP_Error
     */
    public function registerFreeToken(string $serviceUrl, string $email, bool $marketingOptIn)
    {
        $response = wp_remote_post(
            untrailingslashit($serviceUrl) . '/api/plugin/free-token/register',
            [
                'timeout' => 15,
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                ],
                'body' => wp_json_encode([
                    'email' => $email,
                    'home_url' => home_url('/'),
                    'site_url' => site_url('/'),
                    'admin_email' => get_option('admin_email'),
                    'plugin_version' => FIREPHAGE_SECURITY_VERSION,
                    'marketing_opt_in' => $marketingOptIn,
                ]),
            ]
        );

        return $this->normalizeResponse($response, 'free token registration');
    }

    /**
     * @return array<string, mixed>|WP_Error
     */
    public function fetchProtectedSignatures(string $serviceUrl, string $freeToken)
    {
        $response = wp_remote_get(
            untrailingslashit($serviceUrl) . '/api/plugin/signatures',
            [
                'timeout' => 12,
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $freeToken,
                ],
            ]
        );

        return $this->normalizeResponse($response, 'signatures');
    }

    /**
     * @param array<string, string> $settings
     * @return array<string, mixed>|WP_Error
     */
    public function fetchFirewallSummary(array $settings)
    {
        return $this->fetchProtectedSummary($settings, '/api/plugin/firewall-summary', 'firewall summary');
    }

    /**
     * @param array<string, string> $settings
     * @return array<string, mixed>|WP_Error
     */
    public function fetchPerformanceSummary(array $settings)
    {
        return $this->fetchProtectedSummary($settings, '/api/plugin/performance-summary', 'performance summary');
    }

    /**
     * @param array<string, string> $settings
     * @return array<string, mixed>|WP_Error
     */
    private function fetchProtectedSummary(array $settings, string $path, string $context)
    {
        if (($settings['site_token'] ?? '') === '' || ($settings['site_id'] ?? '') === '' || ($settings['dashboard_url'] ?? '') === '') {
            return new WP_Error('missing_site_token', __('Connect the plugin before loading FirePhage Pro data.', 'firephage-security'));
        }

        $response = wp_remote_get(
            add_query_arg(
                [
                    'site_id' => $settings['site_id'],
                ],
                untrailingslashit($settings['dashboard_url']) . $path
            ),
            [
                'timeout' => 15,
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $settings['site_token'],
                ],
            ]
        );

        return $this->normalizeResponse($response, $context);
    }

    /**
     * @param array<string, mixed>|WP_Error $response
     * @return array<string, mixed>|WP_Error
     */
    private function normalizeResponse($response, string $context)
    {
        if (is_wp_error($response)) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $payload = json_decode($body, true);

        if ($code < 200 || $code >= 300) {
            $message = is_array($payload) && isset($payload['message']) && is_string($payload['message'])
                ? $payload['message']
                : sprintf(__('FirePhage %s request failed.', 'firephage-security'), $context);

            return new WP_Error('firephage_request_failed', $message, ['status' => $code]);
        }

        if (! is_array($payload)) {
            return new WP_Error('invalid_response', __('FirePhage returned an invalid response.', 'firephage-security'));
        }

        return $payload;
    }
}
