<?php

namespace FirePhage\Security\Reports;

use FirePhage\Security\Health\HealthChecker;
use FirePhage\Security\Scanner\MalwareScanner;
use FirePhage\Security\Security\BruteForceProtection;

if (! defined('ABSPATH')) {
    exit;
}

final class ReportBuilder
{
    /**
     * @var HealthChecker
     */
    private $healthChecker;

    /**
     * @var MalwareScanner
     */
    private $scanner;

    /**
     * @var BruteForceProtection
     */
    private $bruteForceProtection;

    public function __construct(HealthChecker $healthChecker, MalwareScanner $scanner, BruteForceProtection $bruteForceProtection)
    {
        $this->healthChecker = $healthChecker;
        $this->scanner = $scanner;
        $this->bruteForceProtection = $bruteForceProtection;
    }

    /**
     * @return array<string, mixed>
     */
    public function build(bool $forceHealthRefresh = false): array
    {
        $health = $this->healthChecker->getReport($forceHealthRefresh);
        $scan = $this->scanner->getState();

        return [
            'generated_at' => current_time('mysql'),
            'site' => [
                'home_url' => home_url('/'),
                'site_url' => site_url('/'),
                'wp_version' => get_bloginfo('version'),
                'php_version' => PHP_VERSION,
                'plugin_version' => FIREPHAGE_SECURITY_VERSION,
            ],
            'health' => $health,
            'malware_scan' => [
                'status' => $scan['status'],
                'started_at' => $scan['started_at'],
                'updated_at' => $scan['updated_at'],
                'finished_at' => $scan['finished_at'],
                'discovered_files' => (int) $scan['discovered_files'],
                'scanned_files' => (int) $scan['scanned_files'],
                'suspicious_files' => (int) $scan['suspicious_files'],
                'skipped_files' => (int) $scan['skipped_files'],
                'findings' => array_slice(is_array($scan['findings']) ? $scan['findings'] : [], -20),
            ],
            'brute_force' => $this->bruteForceProtection->getSummary(),
        ];
    }
}
