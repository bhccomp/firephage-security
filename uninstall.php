<?php

if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('firephage_security_settings');
