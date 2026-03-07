<?php

namespace FirePhage\Security;

if (! defined('ABSPATH')) {
    exit;
}

require_once FIREPHAGE_SECURITY_PATH . 'includes/class-firephage-settings.php';
require_once FIREPHAGE_SECURITY_PATH . 'includes/Admin/class-firephage-admin.php';

final class Plugin
{
    private static ?self $instance = null;

    private Settings $settings;

    private Admin\Admin $admin;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->settings = new Settings();
        $this->admin = new Admin\Admin($this->settings);
    }

    public function boot(): void
    {
        add_action('plugins_loaded', [$this, 'loadTextdomain']);
        add_action('admin_init', [$this->settings, 'register']);
        add_action('admin_menu', [$this->admin, 'registerMenus']);
    }

    public function loadTextdomain(): void
    {
        load_plugin_textdomain('firephage-security', false, dirname(plugin_basename(FIREPHAGE_SECURITY_FILE)) . '/languages');
    }
}
