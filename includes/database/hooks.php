<?php
/**
 * Database-Related WordPress Hooks
 *
 * @package BCC_Trust_Engine
 * @subpackage Database
 * @version 2.1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * USER SYNC HOOKS
 * ======================================================
 */

/**
 * Sync user when they register
 */
add_action('user_register', 'bcc_trust_sync_user_on_register');
function bcc_trust_sync_user_on_register($user_id) {
    bcc_trust_sync_user_info($user_id);
}

/**
 * Sync user when profile is updated
 */
add_action('profile_update', 'bcc_trust_sync_user_on_update');
function bcc_trust_sync_user_on_update($user_id) {
    bcc_trust_sync_user_info($user_id);
}

/**
 * Track user login
 */
add_action('wp_login', 'bcc_trust_track_login', 10, 2);
function bcc_trust_track_login($user_login, $user) {

    $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field($_SERVER['REMOTE_ADDR']) : '';

    update_user_meta($user->ID, 'bcc_trust_last_login', current_time('mysql'));
    update_user_meta($user->ID, 'bcc_trust_last_ip', $ip);

    bcc_trust_sync_user_info($user->ID);
}

/**
 * Admin action for manual sync all users
 */
add_action('admin_action_bcc_trust_sync_all_users', 'bcc_trust_handle_sync_all_users');
function bcc_trust_handle_sync_all_users() {

    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }

    $count = bcc_trust_sync_user_info();

    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=users&synced=' . $count));
    exit;
}


/**
 * ======================================================
 * AJAX HANDLERS
 * ======================================================
 */


/**
 * AJAX handler for syncing a single user
 */
add_action('wp_ajax_bcc_trust_sync_user', 'bcc_trust_ajax_sync_user');
function bcc_trust_ajax_sync_user() {

    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'bcc_trust_admin')) {
        wp_send_json_error('Invalid nonce');
    }

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;

    if (!$user_id) {
        wp_send_json_error('No user ID provided');
    }

    $result = bcc_trust_sync_user_info($user_id);

    if ($result > 0) {
        wp_send_json_success(['message' => 'User synced successfully']);
    } else {
        wp_send_json_error('Sync failed');
    }
}


/**
 * AJAX handler for bulk syncing users
 */
add_action('wp_ajax_bcc_trust_bulk_sync_users', 'bcc_trust_ajax_bulk_sync_users');
function bcc_trust_ajax_bulk_sync_users() {

    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'bcc_trust_admin')) {
        wp_send_json_error('Invalid nonce');
    }

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $user_ids = isset($_POST['user_ids']) ? array_map('intval', $_POST['user_ids']) : [];

    if (empty($user_ids)) {
        wp_send_json_error('No users selected');
    }

    $synced = 0;

    foreach ($user_ids as $user_id) {
        if (bcc_trust_sync_user_info($user_id)) {
            $synced++;
        }
    }

    wp_send_json_success([
        'message' => "Synced {$synced} of " . count($user_ids) . " users",
        'synced' => $synced
    ]);
}


/**
 * ======================================================
 * PAGE SCORE INITIALIZATION
 * ======================================================
 */


/**
 * AJAX handler for initializing page score manually
 */
add_action('wp_ajax_bcc_trust_init_page_score', 'bcc_trust_ajax_init_page_score');
function bcc_trust_ajax_init_page_score() {

    global $wpdb;

    if (!isset($_POST['nonce']) || !wp_verify_nonce($_POST['nonce'], 'bcc_trust_admin')) {
        wp_send_json_error('Invalid nonce');
    }

    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }

    $page_id = isset($_POST['page_id']) ? intval($_POST['page_id']) : 0;

    if (!$page_id) {
        wp_send_json_error('No page ID provided');
    }

    $scoresTable = bcc_trust_scores_table();

    $post = get_post($page_id);
    if (!$post) {
        wp_send_json_error('Page not found');
    }

    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM {$scoresTable} WHERE page_id = %d",
        $page_id
    ));

    if (!$exists) {

        $owner_id = bcc_trust_get_page_owner($page_id);
        if (!$owner_id) {
            $owner_id = $post->post_author;
        }

        $result = $wpdb->insert(
            $scoresTable,
            [
                'page_id' => $page_id,
                'page_owner_id' => $owner_id,
                'total_score' => 50.00,
                'positive_score' => 0,
                'negative_score' => 0,
                'vote_count' => 0,
                'unique_voters' => 0,
                'confidence_score' => 0,
                'reputation_tier' => 'neutral',
                'endorsement_count' => 0,
                'last_calculated_at' => current_time('mysql')
            ],
            ['%d', '%d', '%f', '%f', '%f', '%d', '%d', '%f', '%s', '%d', '%s']
        );

        if ($result) {
            wp_send_json_success('Score initialized successfully');
        } else {
            wp_send_json_error('Failed to initialize score');
        }

    } else {
        wp_send_json_error('Score already exists for this page');
    }
}


/**
 * ======================================================
 * AUTO INITIALIZE PAGE SCORE WHEN PAGE IS CREATED
 * ======================================================
 */

add_action('peepso_page_created', 'bcc_trust_auto_init_page_score');

function bcc_trust_auto_init_page_score($page_id) {

    global $wpdb;

    $scoresTable = bcc_trust_scores_table();

    $exists = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT id FROM $scoresTable WHERE page_id = %d",
            $page_id
        )
    );

    if (!$exists) {

        $owner_id = bcc_trust_get_page_owner($page_id);

        $wpdb->insert(
            $scoresTable,
            [
                'page_id' => $page_id,
                'page_owner_id' => $owner_id,
                'total_score' => 50.00,
                'positive_score' => 0,
                'negative_score' => 0,
                'vote_count' => 0,
                'unique_voters' => 0,
                'confidence_score' => 0,
                'reputation_tier' => 'neutral',
                'endorsement_count' => 0,
                'last_calculated_at' => current_time('mysql')
            ]
        );
    }
}