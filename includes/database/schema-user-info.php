<?php
/**
 * User Info Table Schema - CLEAN VERSION
 *
 * @package BCC_Trust_Engine
 */

if (!defined('ABSPATH')) {
    exit;
}

function bcc_trust_create_user_info_table() {

    global $wpdb;

    $table = $wpdb->prefix . 'bcc_trust_user_info';
    $charset = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table (

        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,

        /* WordPress identity */
        user_login VARCHAR(60) NOT NULL,
        user_email VARCHAR(100) NOT NULL,
        display_name VARCHAR(250) NOT NULL,
        registered DATETIME DEFAULT NULL,

        /* PeepSo signals */
        usr_last_activity DATETIME DEFAULT NULL,
        usr_views INT DEFAULT 0,
        usr_likes INT DEFAULT 0,
        usr_role VARCHAR(50) DEFAULT NULL,

        /* Trust system */
        fraud_score INT DEFAULT 0,
        trust_rank FLOAT DEFAULT 0,
        risk_level VARCHAR(20) DEFAULT 'unknown',
        is_suspended TINYINT(1) DEFAULT 0,
        is_verified TINYINT(1) DEFAULT 0,

        votes_cast INT DEFAULT 0,
        endorsements_given INT DEFAULT 0,

        automation_score INT DEFAULT 0,
        behavior_score INT DEFAULT 0,

        pages_owned INT DEFAULT 0,
        groups_owned INT DEFAULT 0,

        posts_created INT DEFAULT 0,
        comments_made INT DEFAULT 0,

        last_login DATETIME DEFAULT NULL,
        last_ip_address VARCHAR(45) DEFAULT NULL,
        device_fingerprint VARCHAR(255) DEFAULT NULL,

        /* =============================
           GITHUB VERIFICATION SIGNALS
           ============================= */

        github_id BIGINT DEFAULT NULL,
        github_username VARCHAR(100) DEFAULT NULL,
        github_avatar VARCHAR(255) DEFAULT NULL,

        github_followers INT DEFAULT 0,
        github_public_repos INT DEFAULT 0,
        github_org_count INT DEFAULT 0,

        github_account_created DATETIME DEFAULT NULL,
        github_account_age_days INT DEFAULT 0,

        github_has_verified_email TINYINT(1) DEFAULT 0,

        github_verified_at DATETIME DEFAULT NULL,
        github_last_synced DATETIME DEFAULT NULL,

        github_access_token TEXT DEFAULT NULL,

        github_trust_boost FLOAT DEFAULT 0,
        github_fraud_reduction INT DEFAULT 0,

        /* timestamps */

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

        PRIMARY KEY (id),
        UNIQUE KEY user_id (user_id),

        /* indexes */

        KEY fraud_score (fraud_score),
        KEY risk_level (risk_level),
        KEY usr_last_activity (usr_last_activity),

        KEY github_id (github_id),
        KEY github_username (github_username),
        KEY github_followers (github_followers),
        KEY github_account_age (github_account_age_days),

        KEY idx_fraud_risk (fraud_score, risk_level),
        KEY idx_verification (is_verified, fraud_score)

    ) $charset;";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);

    error_log('BCC Trust: User info table installed');
}