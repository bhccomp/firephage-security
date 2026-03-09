<?php

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('firephage_security_settings');
delete_option('firephage_security_scan_state');
delete_option('firephage_security_scan_baseline');
delete_option('firephage_security_bruteforce_state');
delete_option('firephage_security_notification_state');
delete_transient('firephage_security_health_report');
