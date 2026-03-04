<?php
/**
 * Core Database Schema
 *
 * @package BCC_Trust_Engine
 * @subpackage Database
 * @version 2.2.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Create all core database tables
 */
function bcc_trust_create_core_tables() {

    global $wpdb;

    $charset_collate = $wpdb->get_charset_collate();

    /*
    ======================================================
    VOTES TABLE
    ======================================================
    */

    $votes_table = bcc_trust_votes_table();

    $sql = "CREATE TABLE $votes_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        voter_user_id BIGINT UNSIGNED NOT NULL,
        page_id BIGINT UNSIGNED NOT NULL,
        vote_type TINYINT NOT NULL,
        weight DECIMAL(5,2) NOT NULL DEFAULT 1.0,
        reason VARCHAR(100) NULL,
        explanation TEXT NULL,
        status TINYINT NOT NULL DEFAULT 1,
        ip_address VARBINARY(16) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY unique_vote (voter_user_id, page_id, status),
        KEY idx_page_votes (page_id, vote_type, status),
        KEY idx_voter_history (voter_user_id, created_at),
        KEY idx_created (created_at),
        KEY idx_ip_lookup (ip_address, created_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    PAGE TRUST SCORES
    ======================================================
    */

    $scores_table = bcc_trust_scores_table();

    $sql = "CREATE TABLE $scores_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        page_id BIGINT UNSIGNED NOT NULL,
        page_owner_id BIGINT UNSIGNED NOT NULL,
        total_score DECIMAL(5,2) NOT NULL DEFAULT 50.00,
        positive_score DECIMAL(5,2) NOT NULL DEFAULT 0,
        negative_score DECIMAL(5,2) NOT NULL DEFAULT 0,
        vote_count INT UNSIGNED NOT NULL DEFAULT 0,
        unique_voters INT UNSIGNED NOT NULL DEFAULT 0,
        confidence_score DECIMAL(3,2) NOT NULL DEFAULT 0,
        reputation_tier VARCHAR(20) NOT NULL DEFAULT 'neutral',
        endorsement_count INT UNSIGNED NOT NULL DEFAULT 0,
        last_vote_at DATETIME NULL,
        last_calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        fraud_metadata TEXT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY unique_page_score (page_id),
        KEY idx_owner_scores (page_owner_id, total_score),
        KEY idx_tier_lookup (reputation_tier, total_score),
        KEY idx_confidence (confidence_score),
        KEY idx_page_lookup (page_id, total_score, confidence_score)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    ENDORSEMENTS
    ======================================================
    */

    $endorsements_table = bcc_trust_endorsements_table();

    $sql = "CREATE TABLE $endorsements_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        endorser_user_id BIGINT UNSIGNED NOT NULL,
        page_id BIGINT UNSIGNED NOT NULL,
        context VARCHAR(50) NOT NULL DEFAULT 'general',
        weight DECIMAL(5,2) NOT NULL DEFAULT 3.0,
        reason TEXT NULL,
        status TINYINT NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY unique_endorsement (endorser_user_id, page_id, context, status),
        KEY idx_page_endorsements (page_id, status, created_at),
        KEY idx_endorser_history (endorser_user_id, created_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    EMAIL VERIFICATIONS
    ======================================================
    */

    $verifications_table = bcc_trust_verifications_table();

    $sql = "CREATE TABLE $verifications_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        verification_code VARCHAR(64) NOT NULL,
        verified_at DATETIME NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY unique_user (user_id),
        KEY idx_code (verification_code),
        KEY idx_expires (expires_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    ELIGIBILITY CACHE
    ======================================================
    */

    $eligibility_table = bcc_trust_eligibility_table();

    $sql = "CREATE TABLE $eligibility_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        is_eligible TINYINT(1) NOT NULL DEFAULT 1,
        reason VARCHAR(100) NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_expires (expires_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    ACTIVITY LOG
    ======================================================
    */

    $activity_table = bcc_trust_activity_table();

    $sql = "CREATE TABLE $activity_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        action VARCHAR(50) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
        ip_address VARBINARY(16) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_action (action),
        KEY idx_target (target_type, target_id),
        KEY idx_created (created_at),
        KEY idx_ip_lookup (ip_address, created_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    ACTIVITY ARCHIVE TABLE
    ======================================================
    */

    $activity_archive_table = $activity_table . '_archive';
    
    // Create archive table with same structure as main table
    $wpdb->query("CREATE TABLE IF NOT EXISTS $activity_archive_table LIKE $activity_table");
    
    // Add archive-specific index for better performance
    $wpdb->query("ALTER TABLE $activity_archive_table ADD INDEX IF NOT EXISTS idx_archive_created (created_at)");

    /*
    ======================================================
    FLAGS
    ======================================================
    */

    $flags_table = bcc_trust_flags_table();

    $sql = "CREATE TABLE $flags_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        vote_id BIGINT UNSIGNED NOT NULL,
        flagger_user_id BIGINT UNSIGNED NOT NULL,
        reason VARCHAR(100) NOT NULL,
        status TINYINT NOT NULL DEFAULT 0,
        resolved_by BIGINT UNSIGNED NULL,
        resolved_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_vote (vote_id),
        KEY idx_status (status),
        KEY idx_flagger (flagger_user_id)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    REPUTATION
    ======================================================
    */

    $reputation_table = bcc_trust_reputation_table();

    $sql = "CREATE TABLE $reputation_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        reputation_score DECIMAL(5,2) NOT NULL DEFAULT 50.00,
        reputation_tier VARCHAR(20) NOT NULL DEFAULT 'neutral',
        total_votes_cast INT UNSIGNED NOT NULL DEFAULT 0,
        total_votes_received INT UNSIGNED NOT NULL DEFAULT 0,
        flag_count INT UNSIGNED NOT NULL DEFAULT 0,
        vote_weight DECIMAL(5,2) NOT NULL DEFAULT 1.0,
        last_calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY unique_user (user_id),
        KEY idx_score (reputation_score),
        KEY idx_tier (reputation_tier)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    DEVICE FINGERPRINTS
    ======================================================
    */

    $fingerprints_table = bcc_trust_fingerprints_table();

    $sql = "CREATE TABLE $fingerprints_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        fingerprint VARCHAR(64) NOT NULL,
        automation_score TINYINT UNSIGNED DEFAULT 0,
        automation_signals TEXT NULL,
        first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip_address VARBINARY(16) NULL,
        user_agent TEXT NULL,
        risk_level VARCHAR(20) DEFAULT 'low',
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_fingerprint (fingerprint),
        KEY idx_automation (automation_score),
        KEY idx_user_fingerprint (user_id, fingerprint),
        KEY idx_user_fingerprint_lastseen (user_id, fingerprint, last_seen),
        KEY idx_automation_risk (automation_score, risk_level),
        KEY idx_ip_fingerprint (ip_address, fingerprint)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    BEHAVIOR PATTERNS
    ======================================================
    */

    $patterns_table = bcc_trust_patterns_table();

    $sql = "CREATE TABLE $patterns_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        pattern_type VARCHAR(50) NOT NULL,
        pattern_data TEXT NOT NULL,
        confidence DECIMAL(3,2) DEFAULT 0,
        detected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_type (pattern_type),
        KEY idx_expires (expires_at),
        KEY idx_user_type (user_id, pattern_type),
        KEY idx_detected (detected_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    FRAUD ANALYSIS
    ======================================================
    */

    $fraud_analysis_table = bcc_trust_fraud_analysis_table();

    $sql = "CREATE TABLE $fraud_analysis_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        fraud_score TINYINT UNSIGNED NOT NULL,
        risk_level VARCHAR(20) NOT NULL,
        confidence DECIMAL(3,2) NOT NULL,
        triggers TEXT NOT NULL,
        details TEXT NULL,
        analyzed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_score (fraud_score),
        KEY idx_risk (risk_level),
        KEY idx_expires (expires_at),
        KEY idx_user_recent (user_id, analyzed_at)
    ) $charset_collate;";

    dbDelta($sql);

    /*
    ======================================================
    SUSPENSIONS
    ======================================================
    */

    $suspensions_table = bcc_trust_suspensions_table();

    $sql = "CREATE TABLE $suspensions_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        suspended_by BIGINT UNSIGNED NOT NULL,
        reason VARCHAR(100) NOT NULL,
        fraud_score_at_time TINYINT UNSIGNED NULL,
        notes TEXT NULL,
        suspended_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NULL,
        unsuspended_at DATETIME NULL,
        unsuspended_by BIGINT UNSIGNED NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_status (suspended_at, unsuspended_at),
        KEY idx_expires (expires_at),
        KEY idx_active (unsuspended_at, expires_at)
    ) $charset_collate;";

    dbDelta($sql);
}