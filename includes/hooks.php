<?php
/**
 * BCC Trust Engine - Action and Filter Hooks
 * 
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * CRON JOB HOOKS
 * ======================================================
 */

// Daily cleanup job
add_action('bcc_trust_daily_cleanup', 'bcc_trust_run_daily_cleanup');
function bcc_trust_run_daily_cleanup() {
    global $wpdb;
    
    // Clean verifications table
    $verifications_table = bcc_trust_verifications_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$verifications_table'") == $verifications_table;
    if ($table_exists) {
        $wpdb->query(
            "DELETE FROM {$verifications_table} WHERE expires_at < UTC_TIMESTAMP()"
        );
    }
    
    // Clean old activity logs
    if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
        $activity_table = bcc_trust_activity_table();
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$activity_table'") == $activity_table;
        if ($table_exists) {
            \BCCTrust\Security\AuditLogger::cleanOldLogs(90);
        }
    }
    
    // Clean old fingerprint records
    if (class_exists('\\BCCTrust\\Security\\DeviceFingerprinter')) {
        \BCCTrust\Security\DeviceFingerprinter::cleanOldRecords(90);
    }
    
    // Clean old eligibility cache
    $eligibility_table = bcc_trust_eligibility_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$eligibility_table'") == $eligibility_table;
    if ($table_exists) {
        $wpdb->query(
            "DELETE FROM {$eligibility_table} WHERE expires_at < NOW()"
        );
    }
}

// Hourly recalculation job
add_action('bcc_trust_hourly_recalc', 'bcc_trust_run_hourly_recalc');
function bcc_trust_run_hourly_recalc() {
    global $wpdb;
    
    $scores_table = bcc_trust_scores_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$scores_table'") == $scores_table;
    
    if (!$table_exists) {
        return;
    }
    
    if (class_exists('BCC_Page_Score_Calculator')) {
        $calculator = new BCC_Page_Score_Calculator();
        
        $pages = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT page_id FROM {$scores_table} 
                 WHERE last_calculated_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
                 LIMIT %d",
                100
            )
        );
        
        foreach ($pages as $page_id) {
            if (method_exists($calculator, 'recalculate_page_score')) {
                $calculator->recalculate_page_score($page_id);
            }
        }
    }
}

// Daily ML model update
add_action('bcc_trust_daily_ml_update', 'bcc_trust_run_daily_ml_update');
function bcc_trust_run_daily_ml_update() {
    if (!class_exists('\\BCCTrust\\Security\\MLFraudDetector')) {
        return;
    }
    
    $mlDetector = new \BCCTrust\Security\MLFraudDetector();
    
    global $wpdb;
    $audit_table = bcc_trust_activity_table();
    
    $active_users = $wpdb->get_col("
        SELECT DISTINCT user_id FROM {$audit_table}
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        LIMIT 1000
    ");
    
    foreach ($active_users as $user_id) {
        $prediction = $mlDetector->predictFraudProbability($user_id);
        
        update_user_meta($user_id, 'bcc_trust_ml_prediction', $prediction['probability']);
        update_user_meta($user_id, 'bcc_trust_ml_risk_level', $prediction['risk_level']);
        update_user_meta($user_id, 'bcc_trust_ml_features', $prediction['features']);
        update_user_meta($user_id, 'bcc_trust_ml_updated', time());
        
        if ($prediction['risk_level'] === 'critical' || $prediction['risk_level'] === 'high') {
            if (!get_user_meta($user_id, 'bcc_trust_suspended', true)) {
                update_user_meta($user_id, 'bcc_trust_needs_review', true);
                update_user_meta($user_id, 'bcc_trust_review_reason', 'ml_high_risk');
                
                \BCCTrust\Security\AuditLogger::log('ml_high_risk_detected', $user_id, [
                    'risk_level' => $prediction['risk_level'],
                    'probability' => $prediction['probability']
                ], 'user');
            }
        }
    }
}

// Hourly trust graph update
add_action('bcc_trust_hourly_graph_update', 'bcc_trust_run_hourly_graph_update');
function bcc_trust_run_hourly_graph_update() {
    if (!class_exists('\\BCCTrust\\Security\\TrustGraph')) {
        return;
    }
    
    $graph = new \BCCTrust\Security\TrustGraph();
    
    global $wpdb;
    $audit_table = bcc_trust_activity_table();
    
    $activeUsers = $wpdb->get_col("
        SELECT DISTINCT user_id FROM {$audit_table}
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
        LIMIT 1000
    ");
    
    foreach ($activeUsers as $userId) {
        $graph->calculateTrustRank($userId);
    }
}

/**
 * ======================================================
 * CRON SCHEDULING
 * ======================================================
 */

add_action('wp_loaded', 'bcc_trust_schedule_cron_jobs');
function bcc_trust_schedule_cron_jobs() {
    if (!wp_next_scheduled('bcc_trust_daily_cleanup')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_cleanup');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_recalc')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_recalc');
    }
    
    if (!wp_next_scheduled('bcc_trust_daily_ml_update')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_ml_update');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_graph_update')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_graph_update');
    }
}

/**
 * ======================================================
 * DATABASE VERSION CHECK
 * ======================================================
 */

add_action('init', 'bcc_trust_check_db_version_on_init');
function bcc_trust_check_db_version_on_init() {
    $current_version = get_option('bcc_trust_db_version', '0.0.0');
    if (version_compare($current_version, BCC_TRUST_VERSION, '<')) {
        require_once BCC_TRUST_PATH . 'includes/database/tables.php';
        if (function_exists('bcc_trust_create_tables')) {
            bcc_trust_create_tables();
            update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
        }
    }
}

/**
 * ======================================================
 * ADMIN NOTICES
 * ======================================================
 */

if (is_admin()) {
    add_action('admin_notices', 'bcc_trust_system_requirements_notice');
    function bcc_trust_system_requirements_notice() {
        // Check PHP version
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            echo '<div class="notice notice-error"><p>';
            echo 'BCC Trust Engine requires PHP 7.4 or higher. You are running PHP ' . PHP_VERSION;
            echo '</p></div>';
        }
        
        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, '5.8', '<')) {
            echo '<div class="notice notice-warning"><p>';
            echo 'BCC Trust Engine recommends WordPress 5.8 or higher for optimal performance.';
            echo '</p></div>';
        }
        
        // Check if tables were created successfully
        global $wpdb;
        $scores_table = bcc_trust_scores_table();
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$scores_table'") == $scores_table;
        
        if (!$table_exists) {
            echo '<div class="notice notice-error"><p>';
            echo 'BCC Trust Engine database tables were not created. Please deactivate and reactivate the plugin.';
            echo '</p></div>';
        }
    }
}

/**
 * ======================================================
 * REST API INIT
 * ======================================================
 */

add_action('rest_api_init', 'bcc_trust_register_rest_routes');
function bcc_trust_register_rest_routes() {
    if (class_exists('\\BCCTrust\\Controllers\\TrustRestController')) {
        \BCCTrust\Controllers\TrustRestController::register_routes();
    }
}

/**
 * ======================================================
 * TEXT DOMAIN INIT
 * ======================================================
 */

add_action('init', 'bcc_trust_load_textdomain');
function bcc_trust_load_textdomain() {
    load_plugin_textdomain(
        'bcc-trust',
        false,
        dirname(plugin_basename(BCC_TRUST_FILE)) . '/languages'
    );
}

/**
 * ======================================================
 * EXTENSIBILITY HOOKS (for other plugins)
 * ======================================================
 */

// Vote hooks
add_action('bcc_trust_before_vote', 'bcc_trust_do_before_vote', 10, 3);
add_action('bcc_trust_after_vote', 'bcc_trust_do_after_vote', 10, 4);
add_action('bcc_trust_vote_removed', 'bcc_trust_do_vote_removed', 10, 3);

// Endorsement hooks
add_action('bcc_trust_before_endorse', 'bcc_trust_do_before_endorse', 10, 2);
add_action('bcc_trust_after_endorse', 'bcc_trust_do_after_endorse', 10, 3);
add_action('bcc_trust_endorse_revoked', 'bcc_trust_do_endorse_revoked', 10, 2);

// Fraud detection hooks
add_action('bcc_trust_fraud_detected', 'bcc_trust_do_fraud_detected', 10, 3);
add_action('bcc_trust_high_risk_detected', 'bcc_trust_do_high_risk_detected', 10, 2);

// User status hooks
add_action('bcc_trust_user_suspended', 'bcc_trust_do_user_suspended', 10, 3);
add_action('bcc_trust_user_unsuspended', 'bcc_trust_do_user_unsuspended', 10, 2);
add_action('bcc_trust_user_verified', 'bcc_trust_do_user_verified', 10, 1);

// System hooks
add_action('bcc_trust_cleanup_completed', 'bcc_trust_do_cleanup_completed', 10, 1);
add_action('bcc_trust_ring_detected', 'bcc_trust_do_ring_detected', 10, 2);

// Filter hooks
add_filter('bcc_trust_vote_weight', 'bcc_trust_filter_vote_weight', 10, 3);
add_filter('bcc_trust_base_vote_weight', 'bcc_trust_filter_base_vote_weight', 10, 2);
add_filter('bcc_trust_endorse_weight', 'bcc_trust_filter_endorse_weight', 10, 3);
add_filter('bcc_trust_base_endorse_weight', 'bcc_trust_filter_base_endorse_weight', 10, 2);
add_filter('bcc_trust_fraud_score', 'bcc_trust_filter_fraud_score', 10, 2);
add_filter('bcc_trust_risk_thresholds', 'bcc_trust_filter_risk_thresholds', 10, 1);
add_filter('bcc_trust_fraud_triggers', 'bcc_trust_filter_fraud_triggers', 10, 2);
add_filter('bcc_trust_show_widget', 'bcc_trust_filter_show_widget', 10, 2);
add_filter('bcc_trust_widget_classes', 'bcc_trust_filter_widget_classes', 10, 2);
add_filter('bcc_trust_score_display', 'bcc_trust_filter_score_display', 10, 3);
add_filter('bcc_trust_page_score_data', 'bcc_trust_filter_page_score_data', 10, 2);
add_filter('bcc_trust_user_info_data', 'bcc_trust_filter_user_info_data', 10, 2);

// Hook implementations (empty by default - for extensibility)
function bcc_trust_do_before_vote($page_id, $voter_id, $vote_type) {
    do_action('bcc_trust_before_vote', $page_id, $voter_id, $vote_type);
}

function bcc_trust_do_after_vote($page_id, $voter_id, $vote_type, $new_score) {
    do_action('bcc_trust_after_vote', $page_id, $voter_id, $vote_type, $new_score);
}

function bcc_trust_do_vote_removed($page_id, $voter_id, $old_vote) {
    do_action('bcc_trust_vote_removed', $page_id, $voter_id, $old_vote);
}

function bcc_trust_do_before_endorse($page_id, $endorser_id) {
    do_action('bcc_trust_before_endorse', $page_id, $endorser_id);
}

function bcc_trust_do_after_endorse($page_id, $endorser_id, $weight) {
    do_action('bcc_trust_after_endorse', $page_id, $endorser_id, $weight);
}

function bcc_trust_do_endorse_revoked($page_id, $endorser_id) {
    do_action('bcc_trust_endorse_revoked', $page_id, $endorser_id);
}

function bcc_trust_do_fraud_detected($user_id, $fraud_score, $triggers) {
    do_action('bcc_trust_fraud_detected', $user_id, $fraud_score, $triggers);
}

function bcc_trust_do_high_risk_detected($user_id, $risk_level) {
    do_action('bcc_trust_high_risk_detected', $user_id, $risk_level);
}

function bcc_trust_do_user_suspended($user_id, $reason, $suspended_by) {
    do_action('bcc_trust_user_suspended', $user_id, $reason, $suspended_by);
}

function bcc_trust_do_user_unsuspended($user_id, $unsuspended_by) {
    do_action('bcc_trust_user_unsuspended', $user_id, $unsuspended_by);
}

function bcc_trust_do_user_verified($user_id) {
    do_action('bcc_trust_user_verified', $user_id);
}

function bcc_trust_do_cleanup_completed($stats) {
    do_action('bcc_trust_cleanup_completed', $stats);
}

function bcc_trust_do_ring_detected($ring, $strength) {
    do_action('bcc_trust_ring_detected', $ring, $strength);
}

// Filter implementations
function bcc_trust_filter_vote_weight($weight, $voter_id, $page_id) {
    return apply_filters('bcc_trust_vote_weight', $weight, $voter_id, $page_id);
}

function bcc_trust_filter_base_vote_weight($weight, $voter_id) {
    return apply_filters('bcc_trust_base_vote_weight', $weight, $voter_id);
}

function bcc_trust_filter_endorse_weight($weight, $endorser_id, $page_id) {
    return apply_filters('bcc_trust_endorse_weight', $weight, $endorser_id, $page_id);
}

function bcc_trust_filter_base_endorse_weight($weight, $endorser_id) {
    return apply_filters('bcc_trust_base_endorse_weight', $weight, $endorser_id);
}

function bcc_trust_filter_fraud_score($score, $user_id) {
    return apply_filters('bcc_trust_fraud_score', $score, $user_id);
}

function bcc_trust_filter_risk_thresholds($thresholds) {
    $defaults = [
        'critical' => BCC_TRUST_FRAUD_CRITICAL,
        'high' => BCC_TRUST_FRAUD_HIGH,
        'medium' => BCC_TRUST_FRAUD_MEDIUM,
        'low' => BCC_TRUST_FRAUD_LOW
    ];
    return apply_filters('bcc_trust_risk_thresholds', $defaults);
}

function bcc_trust_filter_fraud_triggers($triggers, $user_id) {
    return apply_filters('bcc_trust_fraud_triggers', $triggers, $user_id);
}

function bcc_trust_filter_show_widget($show, $page_id) {
    return apply_filters('bcc_trust_show_widget', $show, $page_id);
}

function bcc_trust_filter_widget_classes($classes, $page_id) {
    return apply_filters('bcc_trust_widget_classes', $classes, $page_id);
}

function bcc_trust_filter_score_display($display, $score, $context) {
    return apply_filters('bcc_trust_score_display', $display, $score, $context);
}

function bcc_trust_filter_page_score_data($data, $page_id) {
    return apply_filters('bcc_trust_page_score_data', $data, $page_id);
}

function bcc_trust_filter_user_info_data($data, $user_id) {
    return apply_filters('bcc_trust_user_info_data', $data, $user_id);
}