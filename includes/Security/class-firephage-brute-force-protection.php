<?php

namespace FirePhage\Security\Security;

use FirePhage\Security\Settings;
use WP_Error;
use WP_User;

if (! defined('ABSPATH')) {
    exit;
}

final class BruteForceProtection
{
    private const STATE_OPTION_KEY = 'firephage_security_bruteforce_state';

    private const MAX_EVENT_LOG = 50;

    /**
     * @var Settings
     */
    private $settings;

    /**
     * @var array<string, string>
     */
    private $currentContext = [];

    public function __construct(?Settings $settings = null)
    {
        $this->settings = $settings ?? new Settings();
    }

    public function registerHooks(): void
    {
        add_filter('authenticate', [$this, 'enforceProtection'], 5, 3);
        add_action('wp_login_failed', [$this, 'recordFailedLogin'], 10, 2);
        add_action('wp_login', [$this, 'recordSuccessfulLogin'], 10, 2);
    }

    /**
     * @param WP_User|WP_Error|null $user
     * @return WP_User|WP_Error|null
     */
    public function enforceProtection($user, string $username, string $password)
    {
        $settings = $this->settings->all();

        if (! $this->isEnabled($settings)) {
            $this->currentContext = [];

            return $user;
        }

        $surface = $this->currentSurface();

        if ($surface === 'xmlrpc' && ($settings['bruteforce_protect_xmlrpc'] ?? '1') !== '1') {
            $this->currentContext = [];

            return $user;
        }

        if ($username === '' && $password === '') {
            $this->currentContext = [];

            return $user;
        }

        $context = $this->buildContext($username, $surface);
        $this->currentContext = $context;

        $lockout = $this->findActiveLockout($context);

        if ($lockout === null) {
            return $user;
        }

        $minutes = max(1, (int) ceil(((int) $lockout['expires_at'] - time()) / MINUTE_IN_SECONDS));

        return new WP_Error(
            'firephage_bruteforce_locked',
            sprintf(
                __('Too many login attempts. Try again in %d minute(s).', 'firephage-security'),
                $minutes
            )
        );
    }

    public function recordFailedLogin(string $username, ?WP_Error $error = null): void
    {
        unset($error);

        $settings = $this->settings->all();

        if (! $this->isEnabled($settings)) {
            return;
        }

        $surface = $this->currentContext['surface'] ?? $this->currentSurface();

        if ($surface === 'xmlrpc' && ($settings['bruteforce_protect_xmlrpc'] ?? '1') !== '1') {
            return;
        }

        $context = $this->currentContext !== []
            ? $this->currentContext
            : $this->buildContext($username, $surface);

        $state = $this->readState(true);
        $threshold = max(3, (int) ($settings['bruteforce_threshold'] ?? 5));
        $windowSeconds = max(5, (int) ($settings['bruteforce_window_minutes'] ?? 15)) * MINUTE_IN_SECONDS;
        $lockoutSeconds = max(5, (int) ($settings['bruteforce_lockout_minutes'] ?? 30)) * MINUTE_IN_SECONDS;
        $now = time();

        foreach ($this->counterKeys($context) as $scope => $key) {
            $attempt = $state['attempts'][$key] ?? [
                'count' => 0,
                'first_attempt' => $now,
                'last_attempt' => $now,
                'ip' => $context['ip'],
                'username' => $context['username'],
                'surface' => $context['surface'],
                'scope' => $scope,
            ];

            if (($now - (int) $attempt['first_attempt']) > $windowSeconds) {
                $attempt['count'] = 0;
                $attempt['first_attempt'] = $now;
            }

            $attempt['count'] = (int) $attempt['count'] + 1;
            $attempt['last_attempt'] = $now;
            $attempt['username'] = $context['username'];
            $state['attempts'][$key] = $attempt;

            if ((int) $attempt['count'] < $threshold) {
                continue;
            }

            $lockout = [
                'ip' => $context['ip'],
                'username' => $scope === 'ip' ? '' : $context['username'],
                'surface' => $context['surface'],
                'scope' => $scope,
                'reason' => $scope === 'ip' ? 'ip_threshold' : 'credential_threshold',
                'failed_attempts' => (int) $attempt['count'],
                'started_at' => $now,
                'expires_at' => $now + $lockoutSeconds,
            ];

            $state['lockouts'][$key] = $lockout;
            unset($state['attempts'][$key]);
            $this->appendEvent($state, $lockout);
        }

        $this->writeState($state);
    }

    public function recordSuccessfulLogin(string $userLogin, WP_User $user): void
    {
        unset($user);

        $context = $this->currentContext !== []
            ? $this->currentContext
            : $this->buildContext($userLogin, $this->currentSurface());

        $state = $this->readState(true);

        foreach ($this->counterKeys($context) as $key) {
            unset($state['attempts'][$key], $state['lockouts'][$key]);
        }

        $this->writeState($state);
        $this->currentContext = [];
    }

    /**
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        $settings = $this->settings->all();
        $state = $this->readState(true);
        $lockouts = array_values($state['lockouts']);
        usort($lockouts, static function (array $left, array $right): int {
            return ((int) $right['expires_at']) <=> ((int) $left['expires_at']);
        });
        $events = array_values($state['events']);
        usort($events, static function (array $left, array $right): int {
            return ((int) $right['started_at']) <=> ((int) $left['started_at']);
        });

        return [
            'enabled' => $this->isEnabled($settings),
            'protect_xmlrpc' => ($settings['bruteforce_protect_xmlrpc'] ?? '1') === '1',
            'threshold' => (int) ($settings['bruteforce_threshold'] ?? 5),
            'window_minutes' => (int) ($settings['bruteforce_window_minutes'] ?? 15),
            'lockout_minutes' => (int) ($settings['bruteforce_lockout_minutes'] ?? 30),
            'status' => ! $this->isEnabled($settings) ? 'neutral' : ($lockouts === [] ? 'good' : 'warning'),
            'summary' => ! $this->isEnabled($settings)
                ? __('Local brute-force protection is currently disabled.', 'firephage-security')
                : sprintf(
                    __('Lock out repeated login attempts after %1$d failures inside %2$d minutes. Current active lockouts: %3$d.', 'firephage-security'),
                    (int) ($settings['bruteforce_threshold'] ?? 5),
                    (int) ($settings['bruteforce_window_minutes'] ?? 15),
                    count($lockouts)
                ),
            'active_lockouts_count' => count($lockouts),
            'active_lockouts' => array_slice(array_map([$this, 'formatLockout'], $lockouts), 0, 10),
            'recent_events' => array_slice(array_map([$this, 'formatEvent'], $events), 0, 10),
        ];
    }

    /**
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    public function saveSettings(array $input): array
    {
        $current = $this->settings->all();

        $this->settings->update([
            'bruteforce_enabled' => ! empty($input['bruteforce_enabled']) ? '1' : '0',
            'bruteforce_threshold' => (string) max(3, min(20, absint($input['bruteforce_threshold'] ?? $current['bruteforce_threshold'] ?? 5))),
            'bruteforce_window_minutes' => (string) max(5, min(120, absint($input['bruteforce_window_minutes'] ?? $current['bruteforce_window_minutes'] ?? 15))),
            'bruteforce_lockout_minutes' => (string) max(5, min(1440, absint($input['bruteforce_lockout_minutes'] ?? $current['bruteforce_lockout_minutes'] ?? 30))),
            'bruteforce_protect_xmlrpc' => ! empty($input['bruteforce_protect_xmlrpc']) ? '1' : '0',
        ]);

        return $this->getSummary();
    }

    /**
     * @return array<string, mixed>
     */
    public function clearActiveLockouts(): array
    {
        $state = $this->readState(true);
        $state['attempts'] = [];
        $state['lockouts'] = [];
        $this->writeState($state);

        return $this->getSummary();
    }

    /**
     * @param array<string, string> $settings
     */
    private function isEnabled(array $settings): bool
    {
        return ($settings['bruteforce_enabled'] ?? '1') === '1';
    }

    private function currentSurface(): string
    {
        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            return 'xmlrpc';
        }

        return 'login';
    }

    /**
     * @return array<string, string>
     */
    private function buildContext(string $username, string $surface): array
    {
        $normalizedUsername = sanitize_user(wp_unslash($username), true);

        return [
            'ip' => $this->clientIp(),
            'username' => strtolower($normalizedUsername),
            'surface' => $surface,
        ];
    }

    private function clientIp(): string
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field((string) wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

        return $ip !== '' ? $ip : 'unknown';
    }

    /**
     * @param array<string, string> $context
     * @return array<string, string>
     */
    private function counterKeys(array $context): array
    {
        $keys = [
            'ip' => 'ip:' . md5($context['ip'] . '|' . $context['surface']),
        ];

        if ($context['username'] !== '') {
            $keys['account'] = 'account:' . md5($context['ip'] . '|' . $context['username'] . '|' . $context['surface']);
        }

        return $keys;
    }

    /**
     * @param array<string, string> $context
     * @return array<string, mixed>|null
     */
    private function findActiveLockout(array $context): ?array
    {
        $state = $this->readState(true);

        foreach ($this->counterKeys($context) as $key) {
            if (! isset($state['lockouts'][$key])) {
                continue;
            }

            return $state['lockouts'][$key];
        }

        return null;
    }

    /**
     * @return array{attempts: array<string, array<string, mixed>>, lockouts: array<string, array<string, mixed>>, events: array<int, array<string, mixed>>}
     */
    private function readState(bool $prune = false): array
    {
        $state = get_option(self::STATE_OPTION_KEY, []);
        $state = is_array($state) ? $state : [];
        $state = [
            'attempts' => isset($state['attempts']) && is_array($state['attempts']) ? $state['attempts'] : [],
            'lockouts' => isset($state['lockouts']) && is_array($state['lockouts']) ? $state['lockouts'] : [],
            'events' => isset($state['events']) && is_array($state['events']) ? $state['events'] : [],
        ];

        if (! $prune) {
            return $state;
        }

        $now = time();
        $changed = false;

        foreach ($state['attempts'] as $key => $attempt) {
            if (($now - (int) ($attempt['last_attempt'] ?? 0)) <= DAY_IN_SECONDS) {
                continue;
            }

            unset($state['attempts'][$key]);
            $changed = true;
        }

        foreach ($state['lockouts'] as $key => $lockout) {
            if ((int) ($lockout['expires_at'] ?? 0) > $now) {
                continue;
            }

            unset($state['lockouts'][$key]);
            $changed = true;
        }

        $state['events'] = array_values(array_filter(
            $state['events'],
            static function (array $event) use ($now): bool {
                return ((int) ($event['expires_at'] ?? 0)) > ($now - WEEK_IN_SECONDS);
            }
        ));

        if (count($state['events']) > self::MAX_EVENT_LOG) {
            $state['events'] = array_slice($state['events'], -self::MAX_EVENT_LOG);
            $changed = true;
        }

        if ($changed) {
            $this->writeState($state);
        }

        return $state;
    }

    /**
     * @param array{attempts: array<string, array<string, mixed>>, lockouts: array<string, array<string, mixed>>, events: array<int, array<string, mixed>>} $state
     */
    private function writeState(array $state): void
    {
        update_option(self::STATE_OPTION_KEY, $state, false);
    }

    /**
     * @param array{attempts: array<string, array<string, mixed>>, lockouts: array<string, array<string, mixed>>, events: array<int, array<string, mixed>>} $state
     * @param array<string, mixed> $lockout
     */
    private function appendEvent(array &$state, array $lockout): void
    {
        $state['events'][] = $lockout;

        if (count($state['events']) > self::MAX_EVENT_LOG) {
            $state['events'] = array_slice($state['events'], -self::MAX_EVENT_LOG);
        }
    }

    /**
     * @param array<string, mixed> $lockout
     * @return array<string, mixed>
     */
    private function formatLockout(array $lockout): array
    {
        $expiresAt = (int) ($lockout['expires_at'] ?? time());

        return [
            'username' => (string) ($lockout['username'] ?? ''),
            'ip' => (string) ($lockout['ip'] ?? 'unknown'),
            'surface' => (string) ($lockout['surface'] ?? 'login'),
            'scope' => (string) ($lockout['scope'] ?? 'account'),
            'failed_attempts' => (int) ($lockout['failed_attempts'] ?? 0),
            'started_at' => $this->formatTimestamp((int) ($lockout['started_at'] ?? time())),
            'expires_at' => $this->formatTimestamp($expiresAt),
            'remaining' => max(1, (int) ceil(($expiresAt - time()) / MINUTE_IN_SECONDS)),
        ];
    }

    /**
     * @param array<string, mixed> $event
     * @return array<string, mixed>
     */
    private function formatEvent(array $event): array
    {
        return [
            'username' => (string) ($event['username'] ?? ''),
            'ip' => (string) ($event['ip'] ?? 'unknown'),
            'surface' => (string) ($event['surface'] ?? 'login'),
            'scope' => (string) ($event['scope'] ?? 'account'),
            'failed_attempts' => (int) ($event['failed_attempts'] ?? 0),
            'started_at' => $this->formatTimestamp((int) ($event['started_at'] ?? time())),
            'expires_at' => $this->formatTimestamp((int) ($event['expires_at'] ?? time())),
        ];
    }

    private function formatTimestamp(int $timestamp): string
    {
        return wp_date(get_option('date_format') . ' ' . get_option('time_format'), $timestamp);
    }
}
