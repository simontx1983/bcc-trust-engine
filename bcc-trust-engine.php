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

if (file_exists(BCC_TRUST_PATH . 'vendor/autoload.php')) {
    require_once BCC_TRUST_PATH . 'vendor/autoload.php';
}

spl_autoload_register(function ($class) {

    $base_dir = BCC_TRUST_PATH . 'app/';

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

    if (strpos($class, 'BCCTrust\\') === 0) {

        $class_path = str_replace('BCCTrust\\', '', $class);
        $class_path = str_replace('\\', '/', $class_path);
        $file = $base_dir . $class_path . '.php';

        if (defined('WP_DEBUG') && WP_DEBUG && !file_exists($file)) {
            error_log("BCC Trust Autoloader: Missing {$file} for class {$class}");
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
 * ACTIVATION
 * ======================================================
 */

register_activation_hook(__FILE__, 'bcc_trust_activate');

function bcc_trust_activate() {

    require_once BCC_TRUST_PATH . 'includes/database/tables.php';

    if (function_exists('bcc_trust_create_tables')) {

        bcc_trust_create_tables();

        if (function_exists('bcc_trust_verify_all_tables')) {

            $missing = bcc_trust_verify_all_tables();
            update_option('bcc_trust_activation_issues', $missing);

            if (empty($missing)) {
                update_option('bcc_trust_db_version', BCC_TRUST_DB_VERSION);
            }
        }
    }

    if (function_exists('bcc_trust_schedule_cron_jobs')) {
        bcc_trust_schedule_cron_jobs();
    }

    /**
     * Schedule initial user sync instead of running during activation
     */
    if (!wp_next_scheduled('bcc_trust_initial_user_sync')) {
        wp_schedule_single_event(time() + 60, 'bcc_trust_initial_user_sync');
    }

    flush_rewrite_rules();

    update_option('bcc_trust_activated', time());
}


/**
 * ======================================================
 * DEACTIVATION
 * ======================================================
 */

register_deactivation_hook(__FILE__, 'bcc_trust_deactivate');

function bcc_trust_deactivate() {

    $cron_hooks = [
        'bcc_trust_daily_cleanup',
        'bcc_trust_hourly_recalc',
        'bcc_trust_daily_ml_update',
        'bcc_trust_hourly_graph_update',
        'bcc_trust_initial_user_sync'
    ];

    foreach ($cron_hooks as $hook) {
        wp_clear_scheduled_hook($hook);
    }

    flush_rewrite_rules();
}


/**
 * ======================================================
 * USER SYNC SCHEDULER
 * ======================================================
 */

add_action('bcc_trust_initial_user_sync', 'bcc_trust_sync_user_info');


/**
 * ======================================================
 * DATABASE VERSION CHECK
 * ======================================================
 */

add_action('init', 'bcc_trust_check_db_version');

function bcc_trust_check_db_version() {

    $current_version = get_option('bcc_trust_db_version', '1.0.0');

    if (version_compare($current_version, BCC_TRUST_DB_VERSION, '<')) {

        require_once BCC_TRUST_PATH . 'includes/database/tables.php';

        if (function_exists('bcc_trust_create_tables')) {

            bcc_trust_create_tables();

            update_option('bcc_trust_db_version', BCC_TRUST_DB_VERSION);

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

add_action('init', 'bcc_trust_init');

function bcc_trust_init() {

    load_plugin_textdomain(
        'bcc-trust',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages'
    );
}


/**
 * ======================================================
 * BACKWARD COMPATIBILITY
 * ======================================================
 */

if (!function_exists('bcc_trust_display_widget')) {
    function bcc_trust_display_widget($page_id, $show_actions = true) {

        if (function_exists('bcc_trust_render_widget')) {
            bcc_trust_render_widget([
                'page_id' => $page_id,
                'show_actions' => $show_actions
            ]);
        }
    }
}


/**
 * ======================================================
 * ADMIN NOTICES
 * ======================================================
 */

add_action('admin_notices', 'bcc_trust_admin_notices');

function bcc_trust_admin_notices() {

    if (!current_user_can('manage_options')) {
        return;
    }

    if (!class_exists('PeepSo')) {
        echo '<div class="notice notice-warning is-dismissible">
        <p><strong>⚠️ BCC Trust Engine:</strong> PeepSo is not active. Some features will be limited.</p>
        </div>';
    }

    $missing_tables = get_option('bcc_trust_activation_issues', []);

    if (!empty($missing_tables)) {

        echo '<div class="notice notice-error">
        <p><strong>⚠️ BCC Trust Engine: Missing database tables</strong></p>
        <p>' . esc_html(implode(', ', $missing_tables)) . '</p>
        </div>';
    }

    $db_version = get_option('bcc_trust_db_version', '1.0.0');

    if (version_compare($db_version, BCC_TRUST_DB_VERSION, '<')) {

        echo '<div class="notice notice-info is-dismissible">
        <p><strong>BCC Trust Engine:</strong> Database update available.</p>
        </div>';
    }

    global $wpdb;

    if (function_exists('bcc_trust_votes_table')) {

        $votes_table = bcc_trust_votes_table();

        if ($wpdb->get_var("SHOW TABLES LIKE '{$votes_table}'") == $votes_table) {

            $vote_count = $wpdb->get_var("SELECT COUNT(*) FROM {$votes_table}");

            if ($vote_count > 10000) {

                echo '<div class="notice notice-info is-dismissible">
                <p><strong>📊 BCC Trust Engine:</strong> ' .
                number_format($vote_count) .
                ' votes recorded.</p>
                </div>';
            }
        }
    }
}


/**
 * ======================================================
 * PLUGIN ACTION LINKS
 * ======================================================
 */

add_filter('plugin_action_links_' . plugin_basename(__FILE__), 'bcc_trust_action_links');

function bcc_trust_action_links($links) {

    $plugin_links = [
        '<a href="' . admin_url('admin.php?page=bcc-trust-dashboard') . '">Dashboard</a>',
        '<a href="' . admin_url('admin.php?page=bcc-trust-moderation') . '">Moderation</a>'
    ];

    return array_merge($plugin_links, $links);
}