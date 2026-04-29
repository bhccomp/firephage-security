<?php

namespace FirePhage\Security\Security;

use FirePhage\Security\Settings;
use WP_Error;
use WP_User;
use wpdb;

if (! defined('ABSPATH')) {
    exit;
}

final class BruteForceProtection
{
    private const STATE_OPTION_KEY = 'firephage_security_bruteforce_state';
    private const ENTRIES_TABLE_SUFFIX = 'firephage_security_bruteforce_entries';
    private const EVENTS_TABLE_SUFFIX = 'firephage_security_bruteforce_events';
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

    public static function installStorage(): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $charsetCollate = $wpdb->get_charset_collate();
        $entriesTable = self::entriesTableName();
        $eventsTable = self::eventsTableName();

        dbDelta(
            "CREATE TABLE {$entriesTable} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                entry_type varchar(20) NOT NULL,
                counter_key varchar(64) NOT NULL,
                ip varchar(100) NOT NULL DEFAULT '',
                username varchar(191) NOT NULL DEFAULT '',
                surface varchar(20) NOT NULL DEFAULT 'login',
                scope varchar(20) NOT NULL DEFAULT 'account',
                reason varchar(50) NOT NULL DEFAULT '',
                failed_attempts int(10) unsigned NOT NULL DEFAULT 0,
                first_attempt_at bigint(20) unsigned NOT NULL DEFAULT 0,
                last_attempt_at bigint(20) unsigned NOT NULL DEFAULT 0,
                started_at bigint(20) unsigned NOT NULL DEFAULT 0,
                expires_at bigint(20) unsigned NOT NULL DEFAULT 0,
                created_at datetime NOT NULL,
                updated_at datetime NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY entry_type_key (entry_type, counter_key),
                KEY entry_type_expires (entry_type, expires_at),
                KEY last_attempt_at (last_attempt_at)
            ) {$charsetCollate};"
        );

        dbDelta(
            "CREATE TABLE {$eventsTable} (
                id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                counter_key varchar(64) NOT NULL,
                ip varchar(100) NOT NULL DEFAULT '',
                username varchar(191) NOT NULL DEFAULT '',
                surface varchar(20) NOT NULL DEFAULT 'login',
                scope varchar(20) NOT NULL DEFAULT 'account',
                reason varchar(50) NOT NULL DEFAULT '',
                failed_attempts int(10) unsigned NOT NULL DEFAULT 0,
                started_at bigint(20) unsigned NOT NULL DEFAULT 0,
                expires_at bigint(20) unsigned NOT NULL DEFAULT 0,
                created_at datetime NOT NULL,
                PRIMARY KEY  (id),
                KEY started_at (started_at),
                KEY expires_at (expires_at)
            ) {$charsetCollate};"
        );

        (new self())->migrateLegacyStateIfNeeded();
    }

    public static function storageTablesExist(): bool
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return false;
        }

        $entriesTable = self::entriesTableName();
        $eventsTable = self::eventsTableName();

        $entriesExists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $entriesTable));
        $eventsExists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $eventsTable));

        return $entriesExists === $entriesTable && $eventsExists === $eventsTable;
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
                /* translators: %d: Minutes until the login lockout expires. */
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

        $threshold = max(3, (int) ($settings['bruteforce_threshold'] ?? 5));
        $windowSeconds = max(5, (int) ($settings['bruteforce_window_minutes'] ?? 15)) * MINUTE_IN_SECONDS;
        $lockoutSeconds = max(5, (int) ($settings['bruteforce_lockout_minutes'] ?? 30)) * MINUTE_IN_SECONDS;
        $now = time();

        $this->pruneStorage();

        foreach ($this->counterKeys($context) as $scope => $counterKey) {
            $attempt = $this->getAttemptEntry($counterKey);

            if ($attempt === null) {
                $attempt = [
                    'counter_key' => $counterKey,
                    'ip' => $context['ip'],
                    'username' => $context['username'],
                    'surface' => $context['surface'],
                    'scope' => $scope,
                    'reason' => '',
                    'failed_attempts' => 0,
                    'first_attempt_at' => $now,
                    'last_attempt_at' => $now,
                    'started_at' => 0,
                    'expires_at' => 0,
                ];
            }

            if (($now - (int) ($attempt['first_attempt_at'] ?? 0)) > $windowSeconds) {
                $attempt['failed_attempts'] = 0;
                $attempt['first_attempt_at'] = $now;
            }

            $attempt['failed_attempts'] = (int) ($attempt['failed_attempts'] ?? 0) + 1;
            $attempt['last_attempt_at'] = $now;
            $attempt['username'] = $context['username'];
            $attempt['ip'] = $context['ip'];
            $attempt['surface'] = $context['surface'];
            $attempt['scope'] = $scope;

            if ((int) $attempt['failed_attempts'] < $threshold) {
                $this->replaceEntry('attempt', $attempt);
                continue;
            }

            $lockout = [
                'counter_key' => $counterKey,
                'ip' => $context['ip'],
                'username' => $scope === 'ip' ? '' : $context['username'],
                'surface' => $context['surface'],
                'scope' => $scope,
                'reason' => $scope === 'ip' ? 'ip_threshold' : 'credential_threshold',
                'failed_attempts' => (int) $attempt['failed_attempts'],
                'first_attempt_at' => 0,
                'last_attempt_at' => 0,
                'started_at' => $now,
                'expires_at' => $now + $lockoutSeconds,
            ];

            $this->replaceEntry('lockout', $lockout);
            $this->deleteEntry('attempt', $counterKey);
            $this->insertEvent($lockout);
        }
    }

    public function recordSuccessfulLogin(string $userLogin, WP_User $user): void
    {
        unset($user);

        $context = $this->currentContext !== []
            ? $this->currentContext
            : $this->buildContext($userLogin, $this->currentSurface());

        foreach ($this->counterKeys($context) as $counterKey) {
            $this->deleteEntry('attempt', $counterKey);
            $this->deleteEntry('lockout', $counterKey);
        }

        $this->currentContext = [];
    }

    /**
     * @return array<string, mixed>
     */
    public function getSummary(): array
    {
        $settings = $this->settings->all();
        $wafManaged = $this->isWafManaged($settings);
        $localConfigured = ($settings['bruteforce_enabled'] ?? '1') === '1';
        $effectiveEnabled = $localConfigured && ! $wafManaged;

        $this->pruneStorage();

        $lockouts = $this->getActiveLockouts();
        $events = $this->getRecentEvents();

        return [
            'enabled' => $effectiveEnabled,
            'configured' => $localConfigured,
            'waf_managed' => $wafManaged,
            'protect_xmlrpc' => $wafManaged ? true : (($settings['bruteforce_protect_xmlrpc'] ?? '1') === '1'),
            'threshold' => (int) ($settings['bruteforce_threshold'] ?? 5),
            'window_minutes' => (int) ($settings['bruteforce_window_minutes'] ?? 15),
            'lockout_minutes' => (int) ($settings['bruteforce_lockout_minutes'] ?? 30),
            'status' => $wafManaged ? 'good' : (! $effectiveEnabled ? 'neutral' : ($lockouts === [] ? 'good' : 'warning')),
            'summary' => $wafManaged
                ? __('FirePhage WAF is now protecting WordPress logins and XML-RPC at the edge. The local PHP lockout layer is standing down to avoid duplicate enforcement.', 'firephage-security')
                : (! $effectiveEnabled
                    ? __('Local brute-force protection is currently disabled.', 'firephage-security')
                    : sprintf(
                        /* translators: 1: Failed login threshold. 2: Lockout window in minutes. 3: Current active lockout count. */
                        __('Lock out repeated login attempts after %1$d failures inside %2$d minutes. Current active lockouts: %3$d.', 'firephage-security'),
                        (int) ($settings['bruteforce_threshold'] ?? 5),
                        (int) ($settings['bruteforce_window_minutes'] ?? 15),
                        count($lockouts)
                    )),
            'active_lockouts_count' => $wafManaged ? 0 : count($lockouts),
            'active_lockouts' => $wafManaged ? [] : array_slice(array_map([$this, 'formatLockout'], $lockouts), 0, 10),
            'recent_events' => $wafManaged ? [] : array_slice(array_map([$this, 'formatEvent'], $events), 0, 10),
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
        $this->deleteEntriesByType('attempt');
        $this->deleteEntriesByType('lockout');

        return $this->getSummary();
    }

    /**
     * @param array<string, string> $settings
     */
    private function isEnabled(array $settings): bool
    {
        return ($settings['bruteforce_enabled'] ?? '1') === '1' && ! $this->isWafManaged($settings);
    }

    /**
     * @param array<string, string> $settings
     */
    private function isWafManaged(array $settings): bool
    {
        return ($settings['connection_status'] ?? 'disconnected') === 'connected'
            && ($settings['remote_pro_enabled'] ?? '0') === '1';
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
        $now = time();

        foreach ($this->counterKeys($context) as $counterKey) {
            $lockout = $this->getLockoutEntry($counterKey, $now);

            if ($lockout !== null) {
                return $lockout;
            }
        }

        return null;
    }

    private function pruneStorage(): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $entriesTable = self::entriesTableName();
        $eventsTable = self::eventsTableName();
        $now = time();

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$entriesTable} WHERE entry_type = %s AND last_attempt_at > 0 AND last_attempt_at <= %d",
                'attempt',
                $now - DAY_IN_SECONDS
            )
        );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$entriesTable} WHERE entry_type = %s AND expires_at > 0 AND expires_at <= %d",
                'lockout',
                $now
            )
        );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$eventsTable} WHERE expires_at > 0 AND expires_at <= %d",
                $now - WEEK_IN_SECONDS
            )
        );

        $overflowIds = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT id FROM {$eventsTable} ORDER BY started_at DESC, id DESC LIMIT %d, %d",
                self::MAX_EVENT_LOG,
                1000
            )
        );

        if ($overflowIds !== []) {
            $this->deleteEventsByIds($overflowIds);
        }
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getActiveLockouts(): array
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return [];
        }

        $entriesTable = self::entriesTableName();
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT counter_key, ip, username, surface, scope, reason, failed_attempts, started_at, expires_at
                 FROM {$entriesTable}
                 WHERE entry_type = %s AND expires_at > %d
                 ORDER BY expires_at DESC",
                'lockout',
                time()
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function getRecentEvents(): array
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return [];
        }

        $eventsTable = self::eventsTableName();
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT counter_key, ip, username, surface, scope, reason, failed_attempts, started_at, expires_at
                 FROM {$eventsTable}
                 WHERE expires_at > %d
                 ORDER BY started_at DESC, id DESC
                 LIMIT %d",
                time() - WEEK_IN_SECONDS,
                self::MAX_EVENT_LOG
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function getAttemptEntry(string $counterKey): ?array
    {
        return $this->getEntry('attempt', $counterKey);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function getLockoutEntry(string $counterKey, int $now): ?array
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return null;
        }

        $entriesTable = self::entriesTableName();
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT counter_key, ip, username, surface, scope, reason, failed_attempts, started_at, expires_at
                 FROM {$entriesTable}
                 WHERE entry_type = %s AND counter_key = %s AND expires_at > %d
                 LIMIT 1",
                'lockout',
                $counterKey,
                $now
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function getEntry(string $entryType, string $counterKey): ?array
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return null;
        }

        $entriesTable = self::entriesTableName();
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT counter_key, ip, username, surface, scope, reason, failed_attempts, first_attempt_at, last_attempt_at, started_at, expires_at
                 FROM {$entriesTable}
                 WHERE entry_type = %s AND counter_key = %s
                 LIMIT 1",
                $entryType,
                $counterKey
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private function replaceEntry(string $entryType, array $entry): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $timestamp = current_time('mysql', true);

        $wpdb->replace(
            self::entriesTableName(),
            [
                'entry_type' => $entryType,
                'counter_key' => (string) ($entry['counter_key'] ?? ''),
                'ip' => (string) ($entry['ip'] ?? ''),
                'username' => (string) ($entry['username'] ?? ''),
                'surface' => (string) ($entry['surface'] ?? 'login'),
                'scope' => (string) ($entry['scope'] ?? 'account'),
                'reason' => (string) ($entry['reason'] ?? ''),
                'failed_attempts' => (int) ($entry['failed_attempts'] ?? 0),
                'first_attempt_at' => (int) ($entry['first_attempt_at'] ?? 0),
                'last_attempt_at' => (int) ($entry['last_attempt_at'] ?? 0),
                'started_at' => (int) ($entry['started_at'] ?? 0),
                'expires_at' => (int) ($entry['expires_at'] ?? 0),
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ],
            [
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%d',
                '%d',
                '%d',
                '%d',
                '%d',
                '%s',
                '%s',
            ]
        );
    }

    private function deleteEntry(string $entryType, string $counterKey): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $wpdb->delete(
            self::entriesTableName(),
            [
                'entry_type' => $entryType,
                'counter_key' => $counterKey,
            ],
            [
                '%s',
                '%s',
            ]
        );
    }

    private function deleteEntriesByType(string $entryType): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $wpdb->delete(
            self::entriesTableName(),
            [
                'entry_type' => $entryType,
            ],
            ['%s']
        );
    }

    /**
     * @param array<string, mixed> $lockout
     */
    private function insertEvent(array $lockout): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $wpdb->insert(
            self::eventsTableName(),
            [
                'counter_key' => (string) ($lockout['counter_key'] ?? ''),
                'ip' => (string) ($lockout['ip'] ?? ''),
                'username' => (string) ($lockout['username'] ?? ''),
                'surface' => (string) ($lockout['surface'] ?? 'login'),
                'scope' => (string) ($lockout['scope'] ?? 'account'),
                'reason' => (string) ($lockout['reason'] ?? ''),
                'failed_attempts' => (int) ($lockout['failed_attempts'] ?? 0),
                'started_at' => (int) ($lockout['started_at'] ?? 0),
                'expires_at' => (int) ($lockout['expires_at'] ?? 0),
                'created_at' => current_time('mysql', true),
            ],
            [
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%s',
                '%d',
                '%d',
                '%d',
                '%s',
            ]
        );
    }

    /**
     * @param list<int|string> $ids
     */
    private function deleteEventsByIds(array $ids): void
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return;
        }

        $ids = array_values(array_filter(array_map('absint', $ids)));

        if ($ids === []) {
            return;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '%d'));
        $wpdb->query($wpdb->prepare(
            'DELETE FROM ' . self::eventsTableName() . " WHERE id IN ({$placeholders})",
            $ids
        ));
    }

    private function migrateLegacyStateIfNeeded(): void
    {
        $state = get_option(self::STATE_OPTION_KEY, null);

        if (! is_array($state)) {
            return;
        }

        if ($this->storageHasData()) {
            delete_option(self::STATE_OPTION_KEY);

            return;
        }

        $normalizedState = [
            'attempts' => isset($state['attempts']) && is_array($state['attempts']) ? $state['attempts'] : [],
            'lockouts' => isset($state['lockouts']) && is_array($state['lockouts']) ? $state['lockouts'] : [],
            'events' => isset($state['events']) && is_array($state['events']) ? $state['events'] : [],
        ];

        foreach ($normalizedState['attempts'] as $counterKey => $attempt) {
            if (! is_array($attempt)) {
                continue;
            }

            $this->replaceEntry('attempt', [
                'counter_key' => (string) $counterKey,
                'ip' => (string) ($attempt['ip'] ?? ''),
                'username' => (string) ($attempt['username'] ?? ''),
                'surface' => (string) ($attempt['surface'] ?? 'login'),
                'scope' => (string) ($attempt['scope'] ?? 'account'),
                'reason' => '',
                'failed_attempts' => (int) ($attempt['count'] ?? 0),
                'first_attempt_at' => (int) ($attempt['first_attempt'] ?? 0),
                'last_attempt_at' => (int) ($attempt['last_attempt'] ?? 0),
                'started_at' => 0,
                'expires_at' => 0,
            ]);
        }

        foreach ($normalizedState['lockouts'] as $counterKey => $lockout) {
            if (! is_array($lockout)) {
                continue;
            }

            $this->replaceEntry('lockout', [
                'counter_key' => (string) $counterKey,
                'ip' => (string) ($lockout['ip'] ?? ''),
                'username' => (string) ($lockout['username'] ?? ''),
                'surface' => (string) ($lockout['surface'] ?? 'login'),
                'scope' => (string) ($lockout['scope'] ?? 'account'),
                'reason' => (string) ($lockout['reason'] ?? ''),
                'failed_attempts' => (int) ($lockout['failed_attempts'] ?? 0),
                'first_attempt_at' => 0,
                'last_attempt_at' => 0,
                'started_at' => (int) ($lockout['started_at'] ?? 0),
                'expires_at' => (int) ($lockout['expires_at'] ?? 0),
            ]);
        }

        foreach (array_slice($normalizedState['events'], -self::MAX_EVENT_LOG) as $event) {
            if (! is_array($event)) {
                continue;
            }

            $this->insertEvent([
                'counter_key' => isset($event['scope'], $event['ip'], $event['surface'])
                    ? (string) $event['scope'] . ':' . md5((string) ($event['ip'] ?? '') . '|' . (string) ($event['username'] ?? '') . '|' . (string) ($event['surface'] ?? 'login'))
                    : '',
                'ip' => (string) ($event['ip'] ?? ''),
                'username' => (string) ($event['username'] ?? ''),
                'surface' => (string) ($event['surface'] ?? 'login'),
                'scope' => (string) ($event['scope'] ?? 'account'),
                'reason' => (string) ($event['reason'] ?? ''),
                'failed_attempts' => (int) ($event['failed_attempts'] ?? 0),
                'started_at' => (int) ($event['started_at'] ?? 0),
                'expires_at' => (int) ($event['expires_at'] ?? 0),
            ]);
        }

        delete_option(self::STATE_OPTION_KEY);
        $this->pruneStorage();
    }

    private function storageHasData(): bool
    {
        global $wpdb;

        if (! ($wpdb instanceof wpdb)) {
            return false;
        }

        $entriesCount = (int) $wpdb->get_var('SELECT COUNT(*) FROM ' . self::entriesTableName());
        $eventsCount = (int) $wpdb->get_var('SELECT COUNT(*) FROM ' . self::eventsTableName());

        return $entriesCount > 0 || $eventsCount > 0;
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

    private static function entriesTableName(): string
    {
        global $wpdb;

        return $wpdb->prefix . self::ENTRIES_TABLE_SUFFIX;
    }

    private static function eventsTableName(): string
    {
        global $wpdb;

        return $wpdb->prefix . self::EVENTS_TABLE_SUFFIX;
    }
}
