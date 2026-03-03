<?php
/**
 * Plugin Name: Blue Collar Crypto – Trust Engine
 * Description: Core reputation and trust system for Blue Collar Crypto. Handles votes, scoring, and reputation infrastructure.
 * Version: 2.0.0
 * Author: Blue Collar Labs LLC
 * Text Domain: bcc-trust
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * CONSTANTS
 * ======================================================
 */

define('BCC_TRUST_VERSION', '2.0.0');
define('BCC_TRUST_PATH', plugin_dir_path(__FILE__));
define('BCC_TRUST_URL', plugin_dir_url(__FILE__));
define('BCC_TRUST_FILE', __FILE__);

/**
 * ======================================================
 * AUTOLOADER
 * ======================================================
 */

// First try Composer autoloader
if (file_exists(BCC_TRUST_PATH . 'vendor/autoload.php')) {
    require_once BCC_TRUST_PATH . 'vendor/autoload.php';
} else {
    // Fallback manual autoloader if Composer not used
    spl_autoload_register(function ($class) {
        // Project-specific namespace prefix
        $prefix = 'BCCTrust\\';
        $base_dir = BCC_TRUST_PATH . 'app/';

        // Does the class use the namespace prefix?
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            return;
        }

        // Get the relative class name
        $relative_class = substr($class, $len);

        // Replace namespace separators with directory separators
        $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';

        // If the file exists, require it
        if (file_exists($file)) {
            require $file;
        }
    });
}

/**
 * ======================================================
 * BOOTSTRAP
 * ======================================================
 */

require_once BCC_TRUST_PATH . 'bootstrap.php';

/**
 * ======================================================
 * ACTIVATION / DEACTIVATION / UNINSTALL
 * ======================================================
 */

register_activation_hook(__FILE__, 'bcc_trust_activate');

function bcc_trust_activate() {
    // Load tables.php
    require_once BCC_TRUST_PATH . 'includes/database/tables.php';
    
    error_log('BCC Trust: Activation started');
    
    // Create tables - this will succeed even without PeepSo
    if (function_exists('bcc_trust_create_tables')) {
        $result = bcc_trust_create_tables();
        error_log('BCC Trust: Table creation result: ' . ($result ? 'success' : 'failed'));
    } else {
        error_log('BCC Trust: bcc_trust_create_tables function not found');
    }
    
    // Set initial database version
    update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
    
    // Clear any existing cron jobs first
    wp_clear_scheduled_hook('bcc_trust_daily_cleanup');
    wp_clear_scheduled_hook('bcc_trust_hourly_recalc');
    wp_clear_scheduled_hook('bcc_trust_daily_ml_update');
    wp_clear_scheduled_hook('bcc_trust_hourly_graph_update');
    
    // Schedule cron jobs
    if (!wp_next_scheduled('bcc_trust_daily_cleanup')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_cleanup');
        error_log('BCC Trust: Scheduled daily cleanup');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_recalc')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_recalc');
        error_log('BCC Trust: Scheduled hourly recalculation');
    }
    
    if (!wp_next_scheduled('bcc_trust_daily_ml_update')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_ml_update');
        error_log('BCC Trust: Scheduled daily ML update');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_graph_update')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_graph_update');
        error_log('BCC Trust: Scheduled hourly graph update');
    }
    
    // Flush rewrite rules for REST API endpoints
    flush_rewrite_rules();
    
    error_log('BCC Trust: Activation completed');
}

register_deactivation_hook(__FILE__, 'bcc_trust_deactivate');

function bcc_trust_deactivate() {
    // Clear scheduled cron jobs
    wp_clear_scheduled_hook('bcc_trust_daily_cleanup');
    wp_clear_scheduled_hook('bcc_trust_hourly_recalc');
    wp_clear_scheduled_hook('bcc_trust_daily_ml_update');
    wp_clear_scheduled_hook('bcc_trust_hourly_graph_update');
    
    // Flush rewrite rules
    flush_rewrite_rules();
    
    error_log('BCC Trust: Deactivation completed');
}

/**
 * ======================================================
 * CHECK DATABASE VERSION ON UPGRADE
 * ======================================================
 */

add_action('plugins_loaded', 'bcc_trust_check_db_version');

function bcc_trust_check_db_version() {
    $current_version = get_option('bcc_trust_db_version', '1.0.0');
    
    if (version_compare($current_version, BCC_TRUST_VERSION, '<')) {
        require_once BCC_TRUST_PATH . 'includes/database/tables.php';
        
        if (function_exists('bcc_trust_create_tables')) {
            bcc_trust_create_tables();
            update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
            error_log('BCC Trust: Database upgraded to version ' . BCC_TRUST_VERSION);
        }
    }
}

/**
 * ======================================================
 * INITIALIZATION
 * ======================================================
 */

add_action('plugins_loaded', 'bcc_trust_init');

function bcc_trust_init() {
    // Load text domain for translations
    load_plugin_textdomain('bcc-trust', false, dirname(plugin_basename(__FILE__)) . '/languages');
}

/**
 * ======================================================
 * HELPER FUNCTIONS
 * ======================================================
 */

/**
 * Render trust widget for a PeepSo page
 * 
 * @param array $args Widget arguments
 */
function bcc_trust_render_widget($args = []) {
    if (file_exists(BCC_TRUST_PATH . 'templates/trust-widget.php')) {
        include BCC_TRUST_PATH . 'templates/trust-widget.php';
    }
}

// Alias for backward compatibility
if (!function_exists('bcc_trust_display_widget')) {
    function bcc_trust_display_widget($page_id, $show_actions = true) {
        bcc_trust_render_widget([
            'page_id' => $page_id,
            'show_actions' => $show_actions
        ]);
    }
}


/**
 * ======================================================
 * ADMIN NOTICES
 * ======================================================
 */
add_action('admin_notices', 'bcc_trust_admin_notices');

function bcc_trust_admin_notices() {
    // Only show to admins
    if (!current_user_can('manage_options')) {
        return;
    }
    
    // Check if PeepSo is active by looking for its main class
    if (!class_exists('PeepSo')) {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p><strong>BCC Trust Engine:</strong> PeepSo is not active. Some features may be limited.</p>
        </div>
        <?php
    }
    
    // Check database version
    $db_version = get_option('bcc_trust_db_version', '1.0.0');
    if (version_compare($db_version, BCC_TRUST_VERSION, '<')) {
        ?>
        <div class="notice notice-info is-dismissible">
            <p><strong>BCC Trust Engine:</strong> Database update available. <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=update_db'); ?>">Update now</a>.</p>
        </div>
        <?php
    }
}

/**
 * ======================================================
 * ACTION LINKS
 * ======================================================
 */

add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'bcc_trust_action_links');

function bcc_trust_action_links($links) {
    $links[] = '<a href="' . admin_url('admin.php?page=bcc-trust-dashboard') . '">Dashboard</a>';
    $links[] = '<a href="' . admin_url('admin.php?page=bcc-trust-moderation') . '">Moderation</a>';
    $links[] = '<a href="' . admin_url('admin.php?page=bcc-trust-settings') . '">Settings</a>';
    return $links;
}