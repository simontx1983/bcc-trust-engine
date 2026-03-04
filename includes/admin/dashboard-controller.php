<?php
/**
 * Trust Engine Admin Dashboard Controller
 *
 * Handles data loading for the admin dashboard.
 *
 * @package BCC_Trust_Engine
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * DATA LOADER FUNCTIONS
 * ======================================================
 */

function bcc_trust_get_overview_data() {
    global $wpdb;

    $votesTable   = bcc_trust_votes_table();
    $scoresTable  = bcc_trust_scores_table();
    $endorseTable = bcc_trust_endorsements_table();
    $userInfoTable = bcc_trust_user_info_table();

    return [
        'total_votes' =>
            (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM {$votesTable} WHERE status = 1"
            ),
        'total_endorsements' =>
            (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM {$endorseTable} WHERE status = 1"
            ),
        'total_pages' =>
            (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM {$scoresTable}"
            ),
        'total_users' =>
            (int) $wpdb->get_var(
                "SELECT COUNT(*) FROM {$userInfoTable}"
            )
    ];
}

function bcc_trust_get_pages_data() {
    global $wpdb;
    $scoresTable = bcc_trust_scores_table();
    
    $pages = $wpdb->get_results(
        "SELECT * FROM {$scoresTable}
         ORDER BY total_score DESC
         LIMIT 100"
    );
    
    return ['pages' => $pages];
}

function bcc_trust_get_all_pages_data() {
    global $wpdb;
    $scoresTable = bcc_trust_scores_table();
    
    $pages = $wpdb->get_results(
        "SELECT *
        FROM {$wpdb->posts} p
        LEFT JOIN {$scoresTable} s
        ON p.ID = s.page_id
        WHERE p.post_type = 'peepso-page'
        ORDER BY p.ID DESC
        LIMIT 200"
    );
    
    return ['pages' => $pages];
}

function bcc_trust_get_users_data() {
    global $wpdb;
    $userInfoTable = bcc_trust_user_info_table();
    
    $users = $wpdb->get_results(
        "SELECT * FROM {$userInfoTable}
         ORDER BY fraud_score DESC
         LIMIT 200"
    );
    
    return ['users' => $users];
}

function bcc_trust_get_activity_data() {
    global $wpdb;
    $auditTable = bcc_trust_activity_table();
    
    $activity = $wpdb->get_results(
        "SELECT * FROM {$auditTable}
         ORDER BY created_at DESC
         LIMIT 100"
    );
    
    return ['activity' => $activity];
}

function bcc_trust_get_fraud_data() {
    global $wpdb;
    $userInfoTable = bcc_trust_user_info_table();
    
    $users = $wpdb->get_results(
        "SELECT * FROM {$userInfoTable}
         WHERE fraud_score > 50
         ORDER BY fraud_score DESC
         LIMIT 100"
    );
    
    return ['fraud_users' => $users];
}

function bcc_trust_get_devices_data() {
    global $wpdb;
    $fingerprintTable = bcc_trust_fingerprints_table();
    
    $devices = $wpdb->get_results(
        "SELECT * FROM {$fingerprintTable}
         ORDER BY last_seen DESC
         LIMIT 100"
    );
    
    return ['devices' => $devices];
}

function bcc_trust_get_rings_data() {
    $rings = [];
    if (class_exists('BCCTrust\\Security\\TrustGraph')) {
        $trustGraph = new \BCCTrust\Security\TrustGraph();
        $rings = $trustGraph->getSuspiciousClusters(3);
    }
    return ['rings' => $rings];
}

function bcc_trust_get_ml_data() {
    global $wpdb;
    $patternsTable = bcc_trust_patterns_table();
    
    $patterns = $wpdb->get_results(
        "SELECT * FROM {$patternsTable}
         ORDER BY detected_at DESC
         LIMIT 100"
    );
    
    return ['patterns' => $patterns];
}

function bcc_trust_get_repair_data() {
    return ['repair_tools' => true];
}