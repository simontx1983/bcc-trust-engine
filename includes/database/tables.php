<?php
/**
 * Main Database Loader
 *
 * @package BCC_Trust_Engine
 * @subpackage Database
 * @version 2.3.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
|--------------------------------------------------------------------------
| Load Database Components
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/schema-core.php';
require_once __DIR__ . '/schema-user-info.php';
require_once __DIR__ . '/sync-functions.php';
require_once __DIR__ . '/hooks.php';


/**
 * Create all tables during plugin activation
 */
function bcc_trust_create_tables() {

    global $wpdb;

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    error_log('BCC Trust: Starting database installation');

    /*
    |--------------------------------------------------------------------------
    | Check if PeepSo exists (optional)
    |--------------------------------------------------------------------------
    */

    $peepso_pages_table = $wpdb->prefix . 'peepso_pages';
    $peepso_pages_exists = $wpdb->get_var("SHOW TABLES LIKE '$peepso_pages_table'") === $peepso_pages_table;

    if (!$peepso_pages_exists) {
        error_log('BCC Trust: PeepSo Pages table not found. Trust tables will still be created.');
    }

    /*
    |--------------------------------------------------------------------------
    | Create Tables
    |--------------------------------------------------------------------------
    */

    // User info table (source of truth)
    if (function_exists('bcc_trust_create_user_info_table')) {
        bcc_trust_create_user_info_table();
        error_log('BCC Trust: User info table created');
    } else {
        error_log('BCC Trust ERROR: bcc_trust_create_user_info_table function missing');
    }

    // Core trust engine tables
    if (function_exists('bcc_trust_create_core_tables')) {
        bcc_trust_create_core_tables();
        error_log('BCC Trust: Core tables created');
    } else {
        error_log('BCC Trust ERROR: bcc_trust_create_core_tables function missing');
    }

    /*
    |--------------------------------------------------------------------------
    | Verify All Tables Were Created
    |--------------------------------------------------------------------------
    */

    $missing_tables = bcc_trust_verify_all_tables();

    if (empty($missing_tables)) {
        error_log('BCC Trust: All database tables verified successfully');
        update_option('bcc_trust_tables_verified', true);
        delete_option('bcc_trust_missing_tables');
    } else {
        error_log('BCC Trust ERROR: Missing tables: ' . implode(', ', $missing_tables));
        update_option('bcc_trust_tables_verified', false);
        update_option('bcc_trust_missing_tables', $missing_tables);
    }

    /*
    |--------------------------------------------------------------------------
    | Store Schema Version
    |--------------------------------------------------------------------------
    */

    update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
    update_option('bcc_trust_schema_version', '2.3.0');

    error_log('BCC Trust: Database installation completed');

    return true;
}


/**
 * Verify all required tables exist
 *
 * @return array
 */
function bcc_trust_verify_all_tables() {

    global $wpdb;

    $required_tables = [
        'bcc_trust_votes',
        'bcc_trust_page_scores',
        'bcc_trust_endorsements',
        'bcc_trust_verifications',
        'bcc_trust_eligibility',
        'bcc_trust_activity',
        'bcc_trust_activity_archive',
        'bcc_trust_flags',
        'bcc_trust_reputation',
        'bcc_trust_device_fingerprints',
        'bcc_trust_patterns',
        'bcc_trust_user_info',
        'bcc_trust_fraud_analysis',
        'bcc_trust_suspensions'
    ];

    $missing = [];

    foreach ($required_tables as $table) {

        $full_name = $wpdb->prefix . $table;

        $exists = $wpdb->get_var(
            $wpdb->prepare("SHOW TABLES LIKE %s", $full_name)
        );

        if ($exists !== $full_name) {
            $missing[] = $table;
        }
    }

    return $missing;
}


/**
 * Get page owner ID from PeepSo tables
 *
 * @param int $page_id
 * @return int
 */
function bcc_trust_get_page_owner($page_id) {

    global $wpdb;

    static $members_table_exists = null;
    static $page_users_table_exists = null;
    static $pages_users_table_exists = null;

    /*
    |--------------------------------------------------------------------------
    | Detect PeepSo tables once
    |--------------------------------------------------------------------------
    */

    if ($members_table_exists === null) {
        $members_table = $wpdb->prefix . 'peepso_page_members';
        $members_table_exists = $wpdb->get_var("SHOW TABLES LIKE '$members_table'") === $members_table;
    }

    if ($page_users_table_exists === null) {
        $table = $wpdb->prefix . 'peepso_page_users';
        $page_users_table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;
    }

    if ($pages_users_table_exists === null) {
        $table = $wpdb->prefix . 'peepso_pages_users';
        $pages_users_table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;
    }

    /*
    |--------------------------------------------------------------------------
    | Primary Method — peepso_page_members
    |--------------------------------------------------------------------------
    */

    if ($members_table_exists) {

        $table = $wpdb->prefix . 'peepso_page_members';

        $owner = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT pm_user_id
                 FROM {$table}
                 WHERE pm_page_id = %d
                 AND pm_user_status = 'member_owner'
                 LIMIT 1",
                $page_id
            )
        );

        if ($owner) {
            return (int) $owner;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Alternative Method — peepso_page_users
    |--------------------------------------------------------------------------
    */

    if ($page_users_table_exists) {

        $table = $wpdb->prefix . 'peepso_page_users';

        $owner = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT user_id
                 FROM {$table}
                 WHERE page_id = %d
                 AND (role = 'owner' OR role = 'admin')
                 LIMIT 1",
                $page_id
            )
        );

        if ($owner) {
            return (int) $owner;
        }

        $owner = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT user_id
                 FROM {$table}
                 WHERE pm_page_id = %d
                 AND (role = 'owner' OR role = 'admin')
                 LIMIT 1",
                $page_id
            )
        );

        if ($owner) {
            return (int) $owner;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Alternative Method — peepso_pages_users
    |--------------------------------------------------------------------------
    */

    if ($pages_users_table_exists) {

        $table = $wpdb->prefix . 'peepso_pages_users';

        $owner = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT user_id
                 FROM {$table}
                 WHERE page_id = %d
                 AND (role = 'owner' OR role = 'admin')
                 LIMIT 1",
                $page_id
            )
        );

        if ($owner) {
            return (int) $owner;
        }
    }

    /*
    |--------------------------------------------------------------------------
    | Final fallback — WordPress post author
    |--------------------------------------------------------------------------
    */

    $post = get_post($page_id);

    if ($post && $post->post_author) {
        return (int) $post->post_author;
    }

    return 0;
}