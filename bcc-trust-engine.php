<?php
/**
 * Plugin Name: Blue Collar Crypto – Trust Engine
 * Description: Core reputation and trust system for Blue Collar Crypto. Handles votes, scoring, fraud detection, and reputation infrastructure.
 * Version: 2.3.0
 * Author: Blue Collar Labs LLC
 * Text Domain: bcc-trust
 * Domain Path: /languages
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * CONSTANTS
 * ======================================================
 */

define('BCC_TRUST_VERSION', '2.3.0');
define('BCC_TRUST_PATH', plugin_dir_path(__FILE__));
define('BCC_TRUST_URL', plugin_dir_url(__FILE__));
define('BCC_TRUST_FILE', __FILE__);
define('BCC_TRUST_DB_VERSION', '2.3.0');


/**
 * ======================================================
 * AUTOLOADER
 * ======================================================
 */

// First try Composer autoloader
if (file_exists(BCC_TRUST_PATH . 'vendor/autoload.php')) {
    require_once BCC_TRUST_PATH . 'vendor/autoload.php';
}

// PSR-4 style autoloader for BCC Trust classes
spl_autoload_register(function ($class) {
    // Base directory for our namespace
    $base_dir = BCC_TRUST_PATH . 'app/';
    
    // Handle legacy classes
    $legacy_map = [
        'BCC_Page_Score_Calculator' => 'includes/services/class-page-score-calculator.php'
    ];
    
    if (isset($legacy_map[$class])) {
        $file = BCC_TRUST_PATH . $legacy_map[$class];
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    
    // Handle BCCTrust namespace
    if (strpos($class, 'BCCTrust\\') === 0) {
        // Remove namespace prefix
        $class_path = str_replace('BCCTrust\\', '', $class);
        
        // Convert namespace separators to directory separators
        $class_path = str_replace('\\', '/', $class_path);
        
        // Build file path
        $file = $base_dir . $class_path . '.php';
        
        if (defined('WP_DEBUG') && WP_DEBUG) {
            if (!file_exists($file)) {
                error_log("BCC Trust Autoloader: File not found for class {$class} at {$file}");
            }
        }
        
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    
    return false;
});

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
    // Load database schema
    require_once BCC_TRUST_PATH . 'includes/database/tables.php';
    
    // Create ALL tables
    if (function_exists('bcc_trust_create_tables')) {
        $result = bcc_trust_create_tables();
        
        // Verify tables were created
        $missing = bcc_trust_verify_all_tables();
        update_option('bcc_trust_activation_issues', $missing);
        
        if (empty($missing)) {
            update_option('bcc_trust_db_version', BCC_TRUST_DB_VERSION);
        }
    }
    
    // Schedule cron jobs - use function from hooks.php
    if (function_exists('bcc_trust_schedule_cron_jobs')) {
        bcc_trust_schedule_cron_jobs();
    }
    
    // Initial sync of users
    if (function_exists('bcc_trust_sync_user_info')) {
        $synced = bcc_trust_sync_user_info();
        update_option('bcc_trust_initial_sync', $synced);
    }
    
    // Flush rewrite rules for REST API endpoints
    flush_rewrite_rules();
    
    // Set activation flag
    update_option('bcc_trust_activated', time());
}

register_deactivation_hook(__FILE__, 'bcc_trust_deactivate');

function bcc_trust_deactivate() {
    // Clear scheduled cron jobs
    $cron_hooks = [
        'bcc_trust_daily_cleanup',
        'bcc_trust_hourly_recalc',
        'bcc_trust_daily_ml_update',
        'bcc_trust_hourly_graph_update'
    ];
    
    foreach ($cron_hooks as $hook) {
        wp_clear_scheduled_hook($hook);
    }
    
    // Flush rewrite rules
    flush_rewrite_rules();
}

/**
 * ======================================================
 * CHECK DATABASE VERSION ON UPGRADE
 * ======================================================
 */

add_action('plugins_loaded', 'bcc_trust_check_db_version');

function bcc_trust_check_db_version() {
    $current_version = get_option('bcc_trust_db_version', '1.0.0');
    
    if (version_compare($current_version, BCC_TRUST_DB_VERSION, '<')) {
        require_once BCC_TRUST_PATH . 'includes/database/tables.php';
        
        if (function_exists('bcc_trust_create_tables')) {
            bcc_trust_create_tables();
            update_option('bcc_trust_db_version', BCC_TRUST_DB_VERSION);
            
            // Reschedule cron jobs
            if (function_exists('bcc_trust_schedule_cron_jobs')) {
                bcc_trust_schedule_cron_jobs();
            }
        }
    }
}

/**
 * ======================================================
 * INITIALIZATION
 * ======================================================
 */

add_action('init', 'bcc_trust_init'); // Changed from plugins_loaded to fix translation notice

function bcc_trust_init() {
    // Load text domain for translations
    load_plugin_textdomain('bcc-trust', false, dirname(plugin_basename(__FILE__)) . '/languages');
    
    // Register post types if needed
    // register_post_type('bcc_trust_log', ...);
}

/**
 * Alias for backward compatibility
 */
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
    
    // Check if PeepSo is active
    if (!class_exists('PeepSo')) {
        ?>
        <div class="notice notice-warning is-dismissible">
            <p>
                <strong>⚠️ BCC Trust Engine:</strong> 
                PeepSo is not active. The plugin will work but PeepSo integration features will be limited.
                <a href="<?php echo admin_url('plugin-install.php?tab=search&s=peepso'); ?>">Install PeepSo</a>
            </p>
        </div>
        <?php
    }
    
    // Check for missing tables
    $missing_tables = get_option('bcc_trust_activation_issues', []);
    if (!empty($missing_tables)) {
        ?>
        <div class="notice notice-error">
            <p><strong>⚠️ BCC Trust Engine: Database tables missing!</strong></p>
            <p>Missing tables: <?php echo implode(', ', array_map('esc_html', $missing_tables)); ?></p>
            <p>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'); ?>" class="button button-primary">
                    Go to Repair Tools
                </a>
            </p>
        </div>
        <?php
    }
    
    // Check database version
    $db_version = get_option('bcc_trust_db_version', '1.0.0');
    if (version_compare($db_version, BCC_TRUST_DB_VERSION, '<')) {
        ?>
        <div class="notice notice-info is-dismissible">
            <p>
                <strong>BCC Trust Engine:</strong> 
                Database update available. <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'); ?>">Run update now</a>.
                (Current: <?php echo $db_version; ?> → New: <?php echo BCC_TRUST_DB_VERSION; ?>)
            </p>
        </div>
        <?php
    }
    
    // Show performance notice if lots of data
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $vote_count = $wpdb->get_var("SELECT COUNT(*) FROM {$votes_table}");
    
    if ($vote_count > 10000) {
        ?>
        <div class="notice notice-info is-dismissible">
            <p>
                <strong>📊 BCC Trust Engine:</strong> 
                You have <?php echo number_format($vote_count); ?> votes in the system. 
                Consider running <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'); ?>">database optimization</a>.
            </p>
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
add_filter('plugin_row_meta', 'bcc_trust_plugin_row_meta', 10, 2);

function bcc_trust_action_links($links) {
    $plugin_links = [
        '<a href="' . admin_url('admin.php?page=bcc-trust-dashboard') . '">📊 Dashboard</a>',
        '<a href="' . admin_url('admin.php?page=bcc-trust-moderation') . '">🛡️ Moderation</a>',
        '<a href="' . admin_url('admin.php?page=bcc-trust-dashboard&tab=repair') . '">🔧 Repair</a>'
    ];
    
    return array_merge($plugin_links, $links);
}

function bcc_trust_plugin_row_meta($links, $file) {
    if (plugin_basename(__FILE__) === $file) {
        $row_meta = [
            'docs' => '<a href="https://docs.bluecollarcrypto.com/trust-engine" target="_blank">📚 Documentation</a>',
            'support' => '<a href="https://bluecollarcrypto.com/support" target="_blank">💬 Support</a>'
        ];
        
        $links = array_merge($links, $row_meta);
    }
    
    return $links;
}