<?php
/**
 * Plugin Name: FirePhage Security
 * Plugin URI: https://firephage.com
 * Description: WordPress security toolkit with local health checks, malware scanning, and optional FirePhage dashboard sync.
 * Version: 0.1.0
 * Author: FirePhage
 * Author URI: https://firephage.com
 * Text Domain: firephage-security
 */

if (! defined('ABSPATH')) {
    exit;
}

define('FIREPHAGE_SECURITY_VERSION', '0.1.0');
define('FIREPHAGE_SECURITY_FILE', __FILE__);
define('FIREPHAGE_SECURITY_PATH', plugin_dir_path(__FILE__));
define('FIREPHAGE_SECURITY_URL', plugin_dir_url(__FILE__));

require_once FIREPHAGE_SECURITY_PATH . 'includes/class-firephage-plugin.php';

function firephage_security(): FirePhage\Security\Plugin
{
    return FirePhage\Security\Plugin::instance();
}

register_activation_hook(FIREPHAGE_SECURITY_FILE, [FirePhage\Security\Plugin::class, 'activate']);
register_deactivation_hook(FIREPHAGE_SECURITY_FILE, [FirePhage\Security\Plugin::class, 'deactivate']);

firephage_security()->boot();
