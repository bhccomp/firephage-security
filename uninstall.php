<?php

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('firephage_security_settings');
delete_option('firephage_security_scan_state');
delete_option('firephage_security_scan_baseline');
delete_option('firephage_security_bruteforce_state');
delete_option('firephage_security_notification_state');
delete_option('firephage_security_activation_redirect');
delete_option('firephage_security_show_setup_wizard');
delete_option('firephage_security_setup_wizard_seen');
delete_option('firephage_security_storage_schema_version');
delete_transient('firephage_security_health_report');

global $wpdb;

if (isset($wpdb->prefix)) {
    $wpdb->query('DROP TABLE IF EXISTS `' . $wpdb->prefix . 'firephage_security_bruteforce_entries`');
    $wpdb->query('DROP TABLE IF EXISTS `' . $wpdb->prefix . 'firephage_security_bruteforce_events`');
}
