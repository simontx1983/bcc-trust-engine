<?php
/**
 * Blue Collar Crypto - Trust Engine Database Queries
 *
 * Optimized query functions for the trust engine
 * Enhanced with fraud detection, fingerprinting, and behavioral analysis
 *
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * VOTE QUERIES (Enhanced)
 * ======================================================
 */

/**
 * Get user's vote on a page with fraud context
 *
 * @param int $page_id
 * @param int $voter_user_id
 * @return object|null
 */
function bcc_trust_get_user_vote($page_id, $voter_user_id) {
    global $wpdb;
    $table = bcc_trust_votes_table();

    return $wpdb->get_row(
        $wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE page_id = %d AND voter_user_id = %d
             LIMIT 1",
            $page_id,
            $voter_user_id
        )
    );
}

/**
 * Get user's active vote with fraud score
 *
 * @param int $page_id
 * @param int $user_id
 * @return object|null
 */
function bcc_trust_db_get_user_vote_enhanced($page_id, $user_id) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    return $wpdb->get_row($wpdb->prepare(
        "SELECT v.*, 
                COALESCE(uf.meta_value, 0) as fraud_score,
                f.automation_score,
                f.risk_level as device_risk
         FROM {$votes_table} v
         LEFT JOIN {$wpdb->usermeta} uf 
            ON v.voter_user_id = uf.user_id 
            AND uf.meta_key = 'bcc_trust_fraud_score'
         LEFT JOIN {$fingerprint_table} f
            ON v.voter_user_id = f.user_id
            AND f.id = (
                SELECT id FROM {$fingerprint_table} 
                WHERE user_id = v.voter_user_id 
                ORDER BY last_seen DESC 
                LIMIT 1
            )
         WHERE v.page_id = %d
         AND v.voter_user_id = %d
         AND v.status = 1
         LIMIT 1",
        $page_id,
        $user_id
    ));
}

/**
 * Get votes with fraud data for a page
 *
 * @param int $page_id
 * @param bool $include_suspicious_only
 * @return array
 */
function bcc_trust_db_get_page_votes_with_fraud($page_id, $include_suspicious_only = false) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    $suspicious_clause = $include_suspicious_only ? 
        "AND (uf.meta_value > 50 OR f.automation_score > 50)" : "";

    return $wpdb->get_results($wpdb->prepare(
        "SELECT v.*, 
                u.display_name as voter_name,
                COALESCE(uf.meta_value, 0) as fraud_score,
                f.automation_score,
                f.risk_level,
                f.fingerprint
         FROM {$votes_table} v
         LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
         LEFT JOIN {$wpdb->usermeta} uf 
            ON v.voter_user_id = uf.user_id 
            AND uf.meta_key = 'bcc_trust_fraud_score'
         LEFT JOIN {$fingerprint_table} f
            ON v.voter_user_id = f.user_id
            AND f.id = (
                SELECT id FROM {$fingerprint_table} 
                WHERE user_id = v.voter_user_id 
                ORDER BY last_seen DESC 
                LIMIT 1
            )
         WHERE v.page_id = %d 
         AND v.status = 1
         {$suspicious_clause}
         ORDER BY v.created_at DESC",
        $page_id
    ));
}

/**
 * Get suspicious votes for moderation
 *
 * @param int $fraud_threshold
 * @param int $automation_threshold
 * @param int $limit
 * @return array
 */
function bcc_trust_db_get_suspicious_votes($fraud_threshold = 50, $automation_threshold = 50, $limit = 100) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $scores_table = bcc_trust_scores_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT v.*, 
                u.display_name as voter_name,
                s.page_owner_id,
                p.post_title as page_title,
                COALESCE(uf.meta_value, 0) as fraud_score,
                f.automation_score,
                f.risk_level,
                f.fingerprint
         FROM {$votes_table} v
         JOIN {$scores_table} s ON v.page_id = s.page_id
         LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
         LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
         LEFT JOIN {$wpdb->usermeta} uf 
            ON v.voter_user_id = uf.user_id 
            AND uf.meta_key = 'bcc_trust_fraud_score'
         LEFT JOIN {$fingerprint_table} f
            ON v.voter_user_id = f.user_id
            AND f.id = (
                SELECT id FROM {$fingerprint_table} 
                WHERE user_id = v.voter_user_id 
                ORDER BY last_seen DESC 
                LIMIT 1
            )
         WHERE v.status = 1
         AND (uf.meta_value > %d OR f.automation_score > %d)
         ORDER BY GREATEST(uf.meta_value, f.automation_score) DESC
         LIMIT %d",
        $fraud_threshold,
        $automation_threshold,
        $limit
    ));
}

/**
 * ======================================================
 * FINGERPRINT QUERIES (NEW)
 * ======================================================
 */

/**
 * Get fingerprints for a user
 *
 * @param int $user_id
 * @return array
 */
function bcc_trust_db_get_user_fingerprints($user_id) {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT * FROM {$table}
         WHERE user_id = %d
         ORDER BY last_seen DESC",
        $user_id
    ));
}

/**
 * Get users sharing a fingerprint
 *
 * @param string $fingerprint
 * @return array
 */
function bcc_trust_db_get_fingerprint_users($fingerprint) {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT f.*, u.display_name, u.user_email,
                COALESCE(uf.meta_value, 0) as fraud_score
         FROM {$table} f
         JOIN {$wpdb->users} u ON f.user_id = u.ID
         LEFT JOIN {$wpdb->usermeta} uf 
            ON f.user_id = uf.user_id 
            AND uf.meta_key = 'bcc_trust_fraud_score'
         WHERE f.fingerprint = %s
         ORDER BY f.last_seen DESC",
        $fingerprint
    ));
}

/**
 * Get suspicious fingerprints (high automation or shared)
 *
 * @param int $min_users Minimum users sharing fingerprint
 * @param int $automation_threshold
 * @return array
 */
function bcc_trust_db_get_suspicious_fingerprints($min_users = 2, $automation_threshold = 50) {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT fingerprint, 
                COUNT(DISTINCT user_id) as user_count,
                GROUP_CONCAT(DISTINCT user_id) as user_ids,
                MAX(automation_score) as max_automation,
                AVG(automation_score) as avg_automation,
                MAX(risk_level) as max_risk,
                MAX(last_seen) as last_seen
         FROM {$table}
         GROUP BY fingerprint
         HAVING user_count >= %d OR max_automation >= %d
         ORDER BY user_count DESC, max_automation DESC",
        $min_users,
        $automation_threshold
    ));
}

/**
 * Get fingerprint statistics
 *
 * @return object
 */
function bcc_trust_db_get_fingerprint_stats() {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();

    return $wpdb->get_row("
        SELECT 
            COUNT(*) as total_records,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT fingerprint) as unique_fingerprints,
            SUM(CASE WHEN automation_score > 50 THEN 1 ELSE 0 END) as automated_detected,
            SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN risk_level = 'medium' THEN 1 ELSE 0 END) as medium_risk,
            COUNT(DISTINCT CASE 
                WHEN fingerprint IN (
                    SELECT fingerprint FROM {$table} 
                    GROUP BY fingerprint 
                    HAVING COUNT(DISTINCT user_id) > 1
                ) THEN fingerprint 
            END) as shared_fingerprints
        FROM {$table}
    ");
}

/**
 * ======================================================
 * FRAUD DETECTION QUERIES (NEW)
 * ======================================================
 */

/**
 * Get users with high fraud scores
 *
 * @param int $threshold
 * @param int $limit
 * @return array
 */
function bcc_trust_db_get_high_fraud_users($threshold = 50, $limit = 100) {
    global $wpdb;

    return $wpdb->get_results($wpdb->prepare("
        SELECT u.ID, u.display_name, u.user_email, u.user_registered,
               um_fraud.meta_value as fraud_score,
               um_analysis.meta_value as fraud_analysis,
               COUNT(DISTINCT v.id) as total_votes,
               COUNT(DISTINCT e.id) as total_endorsements
        FROM {$wpdb->users} u
        JOIN {$wpdb->usermeta} um_fraud 
            ON u.ID = um_fraud.user_id 
            AND um_fraud.meta_key = 'bcc_trust_fraud_score'
        LEFT JOIN {$wpdb->usermeta} um_analysis
            ON u.ID = um_analysis.user_id 
            AND um_analysis.meta_key = 'bcc_trust_fraud_analysis'
        LEFT JOIN " . bcc_trust_votes_table() . " v 
            ON u.ID = v.voter_user_id AND v.status = 1
        LEFT JOIN " . bcc_trust_endorsements_table() . " e 
            ON u.ID = e.endorser_user_id AND e.status = 1
        WHERE um_fraud.meta_value >= %d
        GROUP BY u.ID
        ORDER BY CAST(um_fraud.meta_value AS UNSIGNED) DESC
        LIMIT %d",
        $threshold,
        $limit
    ));
}

/**
 * Get fraud score history for a user
 *
 * @param int $user_id
 * @param int $days
 * @return array
 */
function bcc_trust_db_get_fraud_history($user_id, $days = 30) {
    global $wpdb;
    $audit_table = bcc_trust_activity_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT created_at, metadata
         FROM {$audit_table}
         WHERE user_id = %d 
         AND action IN ('fraud_score_increased', 'fraud_detected', 'auto_suspended')
         AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
         ORDER BY created_at DESC",
        $user_id,
        $days
    ));
}

/**
 * Get users in vote rings
 *
 * @return array
 */
function bcc_trust_db_get_vote_rings() {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $scores_table = bcc_trust_scores_table();

    return $wpdb->get_results("
        SELECT 
            v1.voter_user_id as user_a, 
            v2.voter_user_id as user_b,
            COUNT(*) as mutual_count,
            SUM(v1.weight + v2.weight) as total_weight,
            u1.display_name as user_a_name,
            u2.display_name as user_b_name
        FROM {$votes_table} v1
        JOIN {$scores_table} s1 ON v1.page_id = s1.page_id
        JOIN {$votes_table} v2 ON v2.voter_user_id = s1.page_owner_id
        JOIN {$scores_table} s2 ON v2.page_id = s2.page_id
        JOIN {$wpdb->users} u1 ON v1.voter_user_id = u1.ID
        JOIN {$wpdb->users} u2 ON v2.voter_user_id = u2.ID
        WHERE v1.status = 1 
          AND v2.status = 1
          AND s2.page_owner_id = v1.voter_user_id
          AND v1.voter_user_id < v2.voter_user_id
        GROUP BY v1.voter_user_id, v2.voter_user_id
        HAVING mutual_count >= 3
        ORDER BY mutual_count DESC
    ");
}

/**
 * ======================================================
 * SCORE QUERIES (Enhanced)
 * ======================================================
 */

/**
 * Get score for page with fraud context
 *
 * @param int $page_id
 * @return object|null
 */
function bcc_trust_db_get_score_enhanced($page_id) {
    global $wpdb;
    $table = bcc_trust_scores_table();

    $score = $wpdb->get_row($wpdb->prepare(
        "SELECT s.*, 
                p.post_title,
                p.post_author,
                u.display_name as owner_name,
                COALESCE(uf.meta_value, 0) as owner_fraud_score
         FROM {$table} s
         LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
         LEFT JOIN {$wpdb->users} u ON s.page_owner_id = u.ID
         LEFT JOIN {$wpdb->usermeta} uf 
            ON s.page_owner_id = uf.user_id 
            AND uf.meta_key = 'bcc_trust_fraud_score'
         WHERE s.page_id = %d",
        $page_id
    ));

    return $score;
}

/**
 * Get pages with suspicious voting patterns
 *
 * @param int $threshold
 * @return array
 */
function bcc_trust_db_get_suspicious_pages($threshold = 30) {
    global $wpdb;
    $scores_table = bcc_trust_scores_table();
    $votes_table = bcc_trust_votes_table();

    return $wpdb->get_results($wpdb->prepare("
        SELECT s.*, 
               p.post_title,
               COUNT(v.id) as total_votes,
               SUM(CASE WHEN um.meta_value > 50 THEN 1 ELSE 0 END) as suspicious_votes,
               AVG(CASE WHEN um.meta_value > 50 THEN v.weight ELSE 0 END) as avg_suspicious_weight
        FROM {$scores_table} s
        JOIN {$wpdb->posts} p ON s.page_id = p.ID
        LEFT JOIN {$votes_table} v ON s.page_id = v.page_id AND v.status = 1
        LEFT JOIN {$wpdb->usermeta} um 
            ON v.voter_user_id = um.user_id 
            AND um.meta_key = 'bcc_trust_fraud_score'
        GROUP BY s.page_id
        HAVING suspicious_votes > %d
        ORDER BY suspicious_votes DESC",
        $threshold
    ));
}

/**
 * ======================================================
 * BEHAVIORAL PATTERN QUERIES (NEW)
 * ======================================================
 */

/**
 * Get behavioral patterns for a user
 *
 * @param int $user_id
 * @param string $pattern_type
 * @return array
 */
function bcc_trust_db_get_user_patterns($user_id, $pattern_type = null) {
    global $wpdb;
    $table = bcc_trust_patterns_table();

    $where = "user_id = %d";
    $params = [$user_id];

    if ($pattern_type) {
        $where .= " AND pattern_type = %s";
        $params[] = $pattern_type;
    }

    return $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE {$where}
             ORDER BY detected_at DESC
             LIMIT 50",
            $params
        )
    );
}

/**
 * Get most common behavior flags
 *
 * @param int $limit
 * @return array
 */
function bcc_trust_db_get_common_behavior_flags($limit = 20) {
    global $wpdb;
    $table = bcc_trust_patterns_table();

    return $wpdb->get_results($wpdb->prepare("
        SELECT pattern_type, 
               COUNT(*) as occurrence_count,
               AVG(confidence) as avg_confidence,
               COUNT(DISTINCT user_id) as unique_users
        FROM {$table}
        WHERE pattern_type LIKE 'behavior_%'
        GROUP BY pattern_type
        ORDER BY occurrence_count DESC
        LIMIT %d",
        $limit
    ));
}

/**
 * ======================================================
 * ENHANCED STATISTICS QUERIES
 * ======================================================
 */

/**
 * Get comprehensive fraud statistics
 *
 * @return object
 */
function bcc_trust_db_get_fraud_stats() {
    global $wpdb;

    $stats = new stdClass();

    // User fraud stats
    $stats->users = $wpdb->get_row("
        SELECT 
            COUNT(DISTINCT user_id) as users_with_scores,
            AVG(CAST(meta_value AS UNSIGNED)) as avg_fraud_score,
            SUM(CASE WHEN CAST(meta_value AS UNSIGNED) >= 80 THEN 1 ELSE 0 END) as critical_risk,
            SUM(CASE WHEN CAST(meta_value AS UNSIGNED) BETWEEN 60 AND 79 THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN CAST(meta_value AS UNSIGNED) BETWEEN 40 AND 59 THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN CAST(meta_value AS UNSIGNED) BETWEEN 20 AND 39 THEN 1 ELSE 0 END) as low_risk,
            SUM(CASE WHEN CAST(meta_value AS UNSIGNED) < 20 THEN 1 ELSE 0 END) as minimal_risk
        FROM {$wpdb->usermeta}
        WHERE meta_key = 'bcc_trust_fraud_score'
    ");

    // Suspension stats
    $stats->suspensions = $wpdb->get_row("
        SELECT 
            COUNT(*) as total_suspended,
            SUM(CASE WHEN meta_value = 'auto_suspension' THEN 1 ELSE 0 END) as auto_suspended,
            SUM(CASE WHEN meta_value != 'auto_suspension' THEN 1 ELSE 0 END) as manually_suspended
        FROM {$wpdb->usermeta}
        WHERE meta_key = 'bcc_trust_suspended_reason'
    ");

    // Device stats
    $fingerprint_table = bcc_trust_fingerprints_table();
    $stats->devices = $wpdb->get_row("
        SELECT 
            COUNT(DISTINCT fingerprint) as unique_devices,
            SUM(CASE WHEN automation_score > 70 THEN 1 ELSE 0 END) as high_automation,
            SUM(CASE WHEN automation_score BETWEEN 40 AND 70 THEN 1 ELSE 0 END) as medium_automation,
            COUNT(DISTINCT CASE 
                WHEN fingerprint IN (
                    SELECT fingerprint FROM {$fingerprint_table} 
                    GROUP BY fingerprint 
                    HAVING COUNT(DISTINCT user_id) > 1
                ) THEN fingerprint 
            END) as shared_devices
        FROM {$fingerprint_table}
    ");

    // Vote ring stats
    $votes_table = bcc_trust_votes_table();
    $scores_table = bcc_trust_scores_table();
    $stats->vote_rings = $wpdb->get_var("
        SELECT COUNT(DISTINCT CONCAT(v1.voter_user_id, '-', v2.voter_user_id))
        FROM {$votes_table} v1
        JOIN {$scores_table} s1 ON v1.page_id = s1.page_id
        JOIN {$votes_table} v2 ON v2.voter_user_id = s1.page_owner_id
        JOIN {$scores_table} s2 ON v2.page_id = s2.page_id
        WHERE v1.status = 1 
          AND v2.status = 1
          AND s2.page_owner_id = v1.voter_user_id
          AND v1.voter_user_id != v2.voter_user_id
        GROUP BY v1.voter_user_id, v2.voter_user_id
        HAVING COUNT(*) >= 3
    ");

    return $stats;
}

/**
 * Get activity summary for dashboard
 *
 * @param int $hours
 * @return object
 */
function bcc_trust_db_get_activity_summary($hours = 24) {
    global $wpdb;
    $audit_table = bcc_trust_activity_table();

    return $wpdb->get_row($wpdb->prepare("
        SELECT 
            COUNT(*) as total_actions,
            COUNT(DISTINCT user_id) as active_users,
            SUM(CASE WHEN action LIKE 'vote_%' THEN 1 ELSE 0 END) as votes_cast,
            SUM(CASE WHEN action LIKE 'endorse%' THEN 1 ELSE 0 END) as endorsements_made,
            SUM(CASE WHEN action LIKE '%fraud%' OR action LIKE '%suspicious%' THEN 1 ELSE 0 END) as fraud_alerts,
            COUNT(DISTINCT target_id) as unique_pages_affected
        FROM {$audit_table}
        WHERE created_at > DATE_SUB(NOW(), INTERVAL %d HOUR)",
        $hours
    ));
}

/**
 * ======================================================
 * CLEANUP QUERIES
 * ======================================================
 */

/**
 * Clean up old fingerprint records
 *
 * @param int $days
 * @return int
 */
function bcc_trust_db_clean_old_fingerprints($days = 90) {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();

    return $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$table} WHERE last_seen < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days
        )
    );
}

/**
 * Clean up old pattern records
 *
 * @param int $days
 * @return int
 */
function bcc_trust_db_clean_old_patterns($days = 30) {
    global $wpdb;
    $table = bcc_trust_patterns_table();

    return $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$table} 
             WHERE expires_at < NOW() 
             OR (expires_at IS NULL AND detected_at < DATE_SUB(NOW(), INTERVAL %d DAY))",
            $days
        )
    );
}

/**
 * Archive old activity logs
 *
 * @param int $days
 * @return bool
 */
function bcc_trust_db_archive_old_activity($days = 90) {
    global $wpdb;
    $table = bcc_trust_activity_table();
    $archive_table = $table . '_archive';

    // Create archive table if not exists
    $wpdb->query("CREATE TABLE IF NOT EXISTS {$archive_table} LIKE {$table}");

    // Move old records
    $moved = $wpdb->query(
        $wpdb->prepare(
            "INSERT INTO {$archive_table} 
             SELECT * FROM {$table} 
             WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days
        )
    );

    // Delete from main table
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$table} 
             WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days
        )
    );

    return $moved !== false;
}
// Add to queries.php or create a new admin-ajax.php

/**
 * AJAX handler for syncing a single user
 */
add_action('wp_ajax_bcc_trust_sync_user', 'bcc_trust_ajax_sync_user');
function bcc_trust_ajax_sync_user() {
    check_ajax_referer('bcc_trust_admin', 'nonce');
    
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
    check_ajax_referer('bcc_trust_admin', 'nonce');
    
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