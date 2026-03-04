<?php
/**
 * Database Table Name Functions
 * 
 * @package BCC_Trust_Engine
 * @subpackage Database
 * @version 2.2.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Votes table
 */
function bcc_trust_votes_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_votes';
}

/**
 * Page scores table
 */
function bcc_trust_scores_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_page_scores';
}

/**
 * Endorsements table
 */
function bcc_trust_endorsements_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_endorsements';
}

/**
 * Email verifications table
 */
function bcc_trust_verifications_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_verifications';
}

/**
 * Vote eligibility cache table
 */
function bcc_trust_eligibility_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_eligibility';
}

/**
 * Activity log table
 */
function bcc_trust_activity_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_activity';
}

/**
 * Activity log archive table
 */
function bcc_trust_activity_archive_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_activity_archive';
}

/**
 * Flags table for reported votes
 */
function bcc_trust_flags_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_flags';
}

/**
 * User reputation table
 */
function bcc_trust_reputation_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_reputation';
}

/**
 * Device fingerprints table
 */
function bcc_trust_fingerprints_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_device_fingerprints';
}

/**
 * Behavioral patterns table for ML
 */
function bcc_trust_patterns_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_patterns';
}

/**
 * User info table (unified user data)
 */
function bcc_trust_user_info_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_user_info';
}

/**
 * Fraud analysis results table
 */
function bcc_trust_fraud_analysis_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_fraud_analysis';
}

/**
 * User suspensions table
 */
function bcc_trust_suspensions_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_suspensions';
}

/**
 * Get all table names as an array
 * 
 * @return array
 */
function bcc_trust_get_all_tables() {
    return [
        'votes' => bcc_trust_votes_table(),
        'scores' => bcc_trust_scores_table(),
        'endorsements' => bcc_trust_endorsements_table(),
        'verifications' => bcc_trust_verifications_table(),
        'eligibility' => bcc_trust_eligibility_table(),
        'activity' => bcc_trust_activity_table(),
        'activity_archive' => bcc_trust_activity_archive_table(),
        'flags' => bcc_trust_flags_table(),
        'reputation' => bcc_trust_reputation_table(),
        'fingerprints' => bcc_trust_fingerprints_table(),
        'patterns' => bcc_trust_patterns_table(),
        'user_info' => bcc_trust_user_info_table(),
        'fraud_analysis' => bcc_trust_fraud_analysis_table(),
        'suspensions' => bcc_trust_suspensions_table()
    ];
}