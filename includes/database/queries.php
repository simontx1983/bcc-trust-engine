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
             WHERE page_id = %d AND voter_user_id = %d AND status = 1
             LIMIT 1",
            $page_id,
            $voter_user_id
        )
    );
}

/**
 * Get user's active vote with fraud context
 *
 * @param int $page_id
 * @param int $user_id
 * @return object|null
 */
function bcc_trust_get_user_vote_enhanced($page_id, $user_id) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $user_info_table = bcc_trust_user_info_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    return $wpdb->get_row($wpdb->prepare(
        "SELECT v.*, 
                ui.fraud_score,
                ui.automation_score,
                ui.risk_level,
                f.automation_score as device_automation,
                f.risk_level as device_risk
         FROM {$votes_table} v
         LEFT JOIN {$user_info_table} ui ON v.voter_user_id = ui.user_id
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
function bcc_trust_get_page_votes_with_fraud($page_id, $include_suspicious_only = false) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $user_info_table = bcc_trust_user_info_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    $suspicious_clause = $include_suspicious_only ? 
        "AND (ui.fraud_score > 50 OR ui.automation_score > 50)" : "";

    return $wpdb->get_results($wpdb->prepare(
        "SELECT v.*, 
                u.display_name as voter_name,
                ui.fraud_score,
                ui.automation_score,
                ui.risk_level,
                f.fingerprint,
                f.automation_score as device_automation
         FROM {$votes_table} v
         LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
         LEFT JOIN {$user_info_table} ui ON v.voter_user_id = ui.user_id
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
function bcc_trust_get_suspicious_votes($fraud_threshold = 50, $automation_threshold = 50, $limit = 100) {
    global $wpdb;
    $votes_table = bcc_trust_votes_table();
    $scores_table = bcc_trust_scores_table();
    $user_info_table = bcc_trust_user_info_table();
    $fingerprint_table = bcc_trust_fingerprints_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT v.*, 
                u.display_name as voter_name,
                s.page_owner_id,
                p.post_title as page_title,
                ui.fraud_score,
                ui.automation_score,
                ui.risk_level,
                f.fingerprint
         FROM {$votes_table} v
         JOIN {$scores_table} s ON v.page_id = s.page_id
         LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
         LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
         LEFT JOIN {$user_info_table} ui ON v.voter_user_id = ui.user_id
         LEFT JOIN {$fingerprint_table} f
            ON v.voter_user_id = f.user_id
            AND f.id = (
                SELECT id FROM {$fingerprint_table} 
                WHERE user_id = v.voter_user_id 
                ORDER BY last_seen DESC 
                LIMIT 1
            )
         WHERE v.status = 1
         AND (ui.fraud_score > %d OR ui.automation_score > %d)
         ORDER BY GREATEST(ui.fraud_score, ui.automation_score) DESC
         LIMIT %d",
        $fraud_threshold,
        $automation_threshold,
        $limit
    ));
}

/**
 * ======================================================
 * USER INFO QUERIES (NEW)
 * ======================================================
 */

/**
 * Get user info with fraud data
 *
 * @param int $user_id
 * @return object|null
 */
function bcc_trust_get_user_info_enhanced($user_id) {
    global $wpdb;
    $table = bcc_trust_user_info_table();
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT ui.*, 
                u.display_name,
                u.user_email,
                u.user_registered
         FROM {$table} ui
         JOIN {$wpdb->users} u ON ui.user_id = u.ID
         WHERE ui.user_id = %d",
        $user_id
    ));
}

/**
 * Get users with high fraud scores from user_info table
 *
 * @param int $threshold
 * @param int $limit
 * @return array
 */
function bcc_trust_get_high_risk_users($threshold = 50, $limit = 100) {
    global $wpdb;
    $table = bcc_trust_user_info_table();

    return $wpdb->get_results($wpdb->prepare("
        SELECT ui.*, u.display_name, u.user_email
        FROM {$table} ui
        JOIN {$wpdb->users} u ON ui.user_id = u.ID
        WHERE ui.fraud_score >= %d
        ORDER BY ui.fraud_score DESC
        LIMIT %d",
        $threshold,
        $limit
    ));
}

/**
 * Get users by risk level
 *
 * @param string $risk_level
 * @param int $limit
 * @return array
 */
function bcc_trust_get_users_by_risk($risk_level, $limit = 100) {
    global $wpdb;
    $table = bcc_trust_user_info_table();

    return $wpdb->get_results($wpdb->prepare("
        SELECT ui.*, u.display_name, u.user_email
        FROM {$table} ui
        JOIN {$wpdb->users} u ON ui.user_id = u.ID
        WHERE ui.risk_level = %s
        ORDER BY ui.fraud_score DESC
        LIMIT %d",
        $risk_level,
        $limit
    ));
}

/**
 * ======================================================
 * FINGERPRINT QUERIES
 * ======================================================
 */

/**
 * Get fingerprints for a user
 *
 * @param int $user_id
 * @return array
 */
function bcc_trust_get_user_fingerprints($user_id) {
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
function bcc_trust_get_fingerprint_users($fingerprint) {
    global $wpdb;
    $table = bcc_trust_fingerprints_table();
    $user_info_table = bcc_trust_user_info_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT f.*, 
                u.display_name, 
                u.user_email,
                ui.fraud_score,
                ui.risk_level
         FROM {$table} f
         JOIN {$wpdb->users} u ON f.user_id = u.ID
         LEFT JOIN {$user_info_table} ui ON f.user_id = ui.user_id
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
function bcc_trust_get_suspicious_fingerprints($min_users = 2, $automation_threshold = 50) {
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
function bcc_trust_get_fingerprint_stats() {
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
 * FRAUD DETECTION QUERIES
 * ======================================================
 */

/**
 * Get fraud score history for a user from activity log
 *
 * @param int $user_id
 * @param int $days
 * @return array
 */
function bcc_trust_get_fraud_history($user_id, $days = 30) {
    global $wpdb;
    $audit_table = bcc_trust_activity_table();

    return $wpdb->get_results($wpdb->prepare(
        "SELECT created_at, action, target_type, target_id
         FROM {$audit_table}
         WHERE user_id = %d 
         AND action IN ('fraud_score_increased', 'fraud_detected', 'user_suspended')
         AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
         ORDER BY created_at DESC",
        $user_id,
        $days
    ));
}

/**
 * Get potential vote rings
 *
 * @return array
 */
function bcc_trust_get_vote_rings() {
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
function bcc_trust_get_page_score_enhanced($page_id) {
    global $wpdb;
    $table = bcc_trust_scores_table();
    $user_info_table = bcc_trust_user_info_table();

    $score = $wpdb->get_row($wpdb->prepare(
        "SELECT s.*, 
                p.post_title,
                p.post_author,
                u.display_name as owner_name,
                ui.fraud_score as owner_fraud_score,
                ui.risk_level as owner_risk_level
         FROM {$table} s
         LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
         LEFT JOIN {$wpdb->users} u ON s.page_owner_id = u.ID
         LEFT JOIN {$user_info_table} ui ON s.page_owner_id = ui.user_id
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
function bcc_trust_get_suspicious_pages($threshold = 30) {
    global $wpdb;
    $scores_table = bcc_trust_scores_table();
    $votes_table = bcc_trust_votes_table();
    $user_info_table = bcc_trust_user_info_table();

    return $wpdb->get_results($wpdb->prepare("
        SELECT s.*, 
               p.post_title,
               COUNT(v.id) as total_votes,
               SUM(CASE WHEN ui.fraud_score > 50 THEN 1 ELSE 0 END) as suspicious_votes,
               AVG(CASE WHEN ui.fraud_score > 50 THEN v.weight ELSE 0 END) as avg_suspicious_weight,
               s.fraud_metadata
        FROM {$scores_table} s
        JOIN {$wpdb->posts} p ON s.page_id = p.ID
        LEFT JOIN {$votes_table} v ON s.page_id = v.page_id AND v.status = 1
        LEFT JOIN {$user_info_table} ui ON v.voter_user_id = ui.user_id
        GROUP BY s.page_id
        HAVING suspicious_votes > %d
        ORDER BY suspicious_votes DESC",
        $threshold
    ));
}

/**
 * ======================================================
 * BEHAVIORAL PATTERN QUERIES
 * ======================================================
 */

/**
 * Get behavioral patterns for a user
 *
 * @param int $user_id
 * @param string $pattern_type
 * @return array
 */
function bcc_trust_get_user_patterns($user_id, $pattern_type = null) {
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
function bcc_trust_get_common_behavior_flags($limit = 20) {
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
function bcc_trust_get_fraud_stats() {
    global $wpdb;
    $user_info_table = bcc_trust_user_info_table();
    $fingerprint_table = bcc_trust_fingerprints_table();
    $votes_table = bcc_trust_votes_table();
    $scores_table = bcc_trust_scores_table();

    $stats = new stdClass();

    // User fraud stats from user_info table
    $stats->users = $wpdb->get_row("
        SELECT 
            COUNT(*) as total_users,
            AVG(fraud_score) as avg_fraud_score,
            SUM(CASE WHEN fraud_score >= 80 THEN 1 ELSE 0 END) as critical_risk,
            SUM(CASE WHEN fraud_score BETWEEN 60 AND 79 THEN 1 ELSE 0 END) as high_risk,
            SUM(CASE WHEN fraud_score BETWEEN 40 AND 59 THEN 1 ELSE 0 END) as medium_risk,
            SUM(CASE WHEN fraud_score BETWEEN 20 AND 39 THEN 1 ELSE 0 END) as low_risk,
            SUM(CASE WHEN fraud_score < 20 THEN 1 ELSE 0 END) as minimal_risk,
            SUM(CASE WHEN is_suspended = 1 THEN 1 ELSE 0 END) as suspended_users,
            SUM(CASE WHEN is_verified = 1 THEN 1 ELSE 0 END) as verified_users
        FROM {$user_info_table}
    ");

    // Device stats
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
function bcc_trust_get_activity_summary($hours = 24) {
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
function bcc_trust_clean_old_fingerprints($days = 90) {
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
function bcc_trust_clean_old_patterns($days = 30) {
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
function bcc_trust_archive_old_activity($days = 90) {
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
