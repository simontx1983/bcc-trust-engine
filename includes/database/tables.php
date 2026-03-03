<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Create Trust Engine Database Tables for PeepSo Pages
 */
function bcc_trust_create_tables() {
    global $wpdb;
    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    
    $charset_collate = $wpdb->get_charset_collate();
    
    // Check if PeepSo Pages table exists - but don't fail if it doesn't
    $peepso_pages_table = $wpdb->prefix . 'peepso_pages';
    $peepso_pages_exists = ($wpdb->get_var("SHOW TABLES LIKE '$peepso_pages_table'") == $peepso_pages_table);
    
    if (!$peepso_pages_exists) {
        // Log warning but continue creating our tables
        error_log('BCC Trust: PeepSo Pages table not found. Will create trust tables anyway.');
    }

    /*
    ============================================================
    USER INFO TABLE - New unified user data table
    ============================================================
    */
    bcc_trust_create_user_info_table();
    
    /*
    ============================================================
    VOTES - Users voting on PeepSo Pages
    ============================================================
    */
    $votes_table = bcc_trust_votes_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $votes_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        voter_user_id BIGINT UNSIGNED NOT NULL COMMENT 'User ID doing the voting',
        page_id BIGINT UNSIGNED NOT NULL COMMENT 'PeepSo Page ID',
        vote_type TINYINT NOT NULL COMMENT '1 = upvote, -1 = downvote',
        weight DECIMAL(5,2) NOT NULL DEFAULT 1.0 COMMENT 'Vote weight based on voter reputation',
        reason VARCHAR(100) NULL COMMENT 'Reason code for downvote',
        explanation TEXT NULL COMMENT 'Optional explanation',
        status TINYINT NOT NULL DEFAULT 1 COMMENT '1=active, 0=removed, -1=flagged',
        ip_address VARBINARY(16) NULL COMMENT 'Binary IP for privacy/GDPR',
        created_at DATETIME NOT NULL,
        updated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY unique_vote (voter_user_id, page_id, status),
        KEY idx_page_votes (page_id, vote_type, status),
        KEY idx_voter_history (voter_user_id, created_at),
        KEY idx_created (created_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    PAGE TRUST SCORES - One per PeepSo Page
    ============================================================
    */
    $scores_table = bcc_trust_scores_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $scores_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        page_id BIGINT UNSIGNED NOT NULL COMMENT 'PeepSo Page ID',
        page_owner_id BIGINT UNSIGNED NOT NULL COMMENT 'Page owner user ID',
        total_score DECIMAL(5,2) NOT NULL DEFAULT 50.00 COMMENT '0-100 score',
        positive_score DECIMAL(5,2) NOT NULL DEFAULT 0 COMMENT 'Weighted upvotes',
        negative_score DECIMAL(5,2) NOT NULL DEFAULT 0 COMMENT 'Weighted downvotes',
        vote_count INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Total active votes',
        unique_voters INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Distinct voters',
        confidence_score DECIMAL(3,2) NOT NULL DEFAULT 0 COMMENT '0-1 confidence level',
        reputation_tier VARCHAR(20) NOT NULL DEFAULT 'neutral',
        endorsement_count INT UNSIGNED NOT NULL DEFAULT 0,
        last_vote_at DATETIME NULL,
        last_calculated_at DATETIME NOT NULL,
        fraud_metadata TEXT NULL COMMENT 'JSON data about fraud detection',
        PRIMARY KEY (id),
        UNIQUE KEY unique_page_score (page_id),
        KEY idx_owner_scores (page_owner_id, total_score),
        KEY idx_tier_lookup (reputation_tier, total_score),
        KEY idx_confidence (confidence_score),
        INDEX idx_page_lookup (page_id, total_score, confidence_score)
    ) $charset_collate;";
    
    dbDelta($sql);   
    
    /*
    ============================================================
    PAGE ENDORSEMENTS - Users endorsing PeepSo Pages
    ============================================================
    */
    $endorsements_table = bcc_trust_endorsements_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $endorsements_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        endorser_user_id BIGINT UNSIGNED NOT NULL COMMENT 'User doing the endorsing',
        page_id BIGINT UNSIGNED NOT NULL COMMENT 'PeepSo Page being endorsed',
        context VARCHAR(50) NOT NULL DEFAULT 'general' COMMENT 'e.g., general, business, service',
        weight DECIMAL(5,2) NOT NULL DEFAULT 3.0 COMMENT 'Endorsement weight',
        reason TEXT NULL,
        status TINYINT NOT NULL DEFAULT 1 COMMENT '1=active, 0=revoked',
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY unique_endorsement (endorser_user_id, page_id, context, status),
        KEY idx_page_endorsements (page_id, status, created_at),
        KEY idx_endorser_history (endorser_user_id, created_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    EMAIL VERIFICATIONS
    ============================================================
    */
    $verifications_table = bcc_trust_verifications_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $verifications_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        verification_code VARCHAR(64) NOT NULL,
        verified_at DATETIME NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY unique_user (user_id),
        KEY idx_code (verification_code),
        KEY idx_expires (expires_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    VOTE ELIGIBILITY CACHE
    ============================================================
    */
    $eligibility_table = bcc_trust_eligibility_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $eligibility_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        is_eligible TINYINT(1) NOT NULL DEFAULT 1,
        reason VARCHAR(100) NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_expires (expires_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    ACTIVITY LOG
    ============================================================
    */
    $activity_table = bcc_trust_activity_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $activity_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        action VARCHAR(50) NOT NULL,
        target_type VARCHAR(50) NOT NULL,
        target_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
        ip_address VARBINARY(16) NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_action (action),
        KEY idx_target (target_type, target_id),
        KEY idx_created (created_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    FLAGS TABLE
    ============================================================
    */
    $flags_table = bcc_trust_flags_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $flags_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        vote_id BIGINT UNSIGNED NOT NULL,
        flagger_user_id BIGINT UNSIGNED NOT NULL,
        reason VARCHAR(100) NOT NULL,
        status TINYINT NOT NULL DEFAULT 0 COMMENT '0=pending, 1=resolved, 2=dismissed',
        resolved_by BIGINT UNSIGNED NULL,
        resolved_at DATETIME NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY idx_vote (vote_id),
        KEY idx_status (status),
        KEY idx_flagger (flagger_user_id)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    REPUTATION TABLE
    ============================================================
    */
    $reputation_table = bcc_trust_reputation_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $reputation_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        reputation_score DECIMAL(5,2) NOT NULL DEFAULT 50.00,
        reputation_tier VARCHAR(20) NOT NULL DEFAULT 'neutral',
        total_votes_cast INT UNSIGNED NOT NULL DEFAULT 0,
        total_votes_received INT UNSIGNED NOT NULL DEFAULT 0,
        flag_count INT UNSIGNED NOT NULL DEFAULT 0,
        vote_weight DECIMAL(5,2) NOT NULL DEFAULT 1.0,
        last_calculated_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY unique_user (user_id),
        KEY idx_score (reputation_score),
        KEY idx_tier (reputation_tier)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    DEVICE FINGERPRINTS TABLE
    ============================================================
    */
    $fingerprints_table = bcc_trust_fingerprints_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $fingerprints_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        fingerprint VARCHAR(64) NOT NULL,
        automation_score TINYINT UNSIGNED DEFAULT 0,
        automation_signals TEXT NULL,
        first_seen DATETIME NOT NULL,
        last_seen DATETIME NOT NULL,
        ip_address VARBINARY(16) NULL,
        user_agent TEXT NULL,
        risk_level VARCHAR(20) DEFAULT 'low',
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_fingerprint (fingerprint),
        KEY idx_automation (automation_score),
        INDEX idx_user_fingerprint (user_id, fingerprint)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    BEHAVIORAL PATTERNS TABLE - For ML training
    ============================================================
    */
    $patterns_table = bcc_trust_patterns_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $patterns_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        pattern_type VARCHAR(50) NOT NULL,
        pattern_data TEXT NOT NULL,
        confidence DECIMAL(3,2) DEFAULT 0,
        detected_at DATETIME NOT NULL,
        expires_at DATETIME NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_type (pattern_type),
        KEY idx_expires (expires_at),
        INDEX idx_user_type (user_id, pattern_type)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    FRAUD ANALYSIS RESULTS - Store comprehensive fraud analysis
    ============================================================
    */
    $fraud_analysis_table = bcc_trust_fraud_analysis_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $fraud_analysis_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        fraud_score TINYINT UNSIGNED NOT NULL,
        risk_level VARCHAR(20) NOT NULL,
        confidence DECIMAL(3,2) NOT NULL,
        triggers TEXT NOT NULL COMMENT 'JSON array of trigger reasons',
        details TEXT NULL COMMENT 'JSON details of analysis',
        analyzed_at DATETIME NOT NULL,
        expires_at DATETIME NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_score (fraud_score),
        KEY idx_risk (risk_level),
        KEY idx_expires (expires_at),
        INDEX idx_user_recent (user_id, analyzed_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    /*
    ============================================================
    SUSPENSIONS - Track user suspension history
    ============================================================
    */
    $suspensions_table = bcc_trust_suspensions_table();
    
    $sql = "CREATE TABLE IF NOT EXISTS $suspensions_table (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NOT NULL,
        suspended_by BIGINT UNSIGNED NOT NULL COMMENT '0 = system, otherwise admin user ID',
        reason VARCHAR(100) NOT NULL,
        fraud_score_at_time TINYINT UNSIGNED NULL,
        notes TEXT NULL,
        suspended_at DATETIME NOT NULL,
        expires_at DATETIME NULL,
        unsuspended_at DATETIME NULL,
        unsuspended_by BIGINT UNSIGNED NULL,
        PRIMARY KEY (id),
        KEY idx_user (user_id),
        KEY idx_status (suspended_at, unsuspended_at),
        KEY idx_expires (expires_at)
    ) $charset_collate;";
    
    dbDelta($sql);
    
    // Store schema version - increment version to trigger rebuild on existing sites
    update_option('bcc_trust_db_version', '1.2.0'); // Incremented for new tables
    
    return true;
}

/**
 * Create User Info Table - Fixed version with no usr_id and no FULLTEXT indexes
 */
function bcc_trust_create_user_info_table() {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'bcc_trust_user_info';
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        user_login varchar(60) NOT NULL,
        user_email varchar(100) NOT NULL,
        display_name varchar(250) NOT NULL,
        registered datetime DEFAULT NULL,
        
        -- PeepSo specific data
        usr_last_activity datetime DEFAULT NULL,
        usr_views int(11) DEFAULT 0,
        usr_likes int(11) DEFAULT 0,
        usr_role varchar(50) DEFAULT NULL,
        
        -- Trust & Fraud scores
        fraud_score int(3) DEFAULT 0,
        trust_rank float DEFAULT 0,
        risk_level varchar(20) DEFAULT 'unknown',
        is_suspended tinyint(1) DEFAULT 0,
        is_verified tinyint(1) DEFAULT 0,
        votes_cast int(11) DEFAULT 0,
        endorsements_given int(11) DEFAULT 0,
        automation_score int(3) DEFAULT 0,
        behavior_score int(3) DEFAULT 0,
        
        -- Page statistics
        pages_owned int(11) DEFAULT 0,
        pages_joined int(11) DEFAULT 0,
        pages_moderated int(11) DEFAULT 0,
        pages_pending int(11) DEFAULT 0,
        page_ids_owned longtext,
        page_ids_joined longtext,
        
        -- Group statistics
        groups_owned int(11) DEFAULT 0,
        groups_joined int(11) DEFAULT 0,
        groups_moderated int(11) DEFAULT 0,
        groups_pending int(11) DEFAULT 0,
        group_ids_owned longtext,
        group_ids_joined longtext,
        
        -- Post/Comment statistics
        posts_created int(11) DEFAULT 0,
        comments_made int(11) DEFAULT 0,
        post_ids_created longtext,
        last_post_date datetime DEFAULT NULL,
        last_comment_date datetime DEFAULT NULL,
        
        -- Activity tracking
        last_login datetime DEFAULT NULL,
        last_ip_address varchar(45) DEFAULT NULL,
        device_fingerprint varchar(255) DEFAULT NULL,
        
        -- Fraud detection data
        fraud_triggers longtext,
        trust_graph_data longtext,
       
        PRIMARY KEY (id),
        UNIQUE KEY user_id (user_id),
        KEY fraud_score (fraud_score),
        KEY risk_level (risk_level),
        KEY pages_owned (pages_owned),
        KEY groups_owned (groups_owned),
        KEY usr_last_activity (usr_last_activity)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

/**
 * Sync User Info - Separate function that can be called manually or via hooks
 */
function bcc_trust_sync_user_info($user_id = null) {
    global $wpdb;
    
    $table_name = $wpdb->prefix . 'bcc_trust_user_info';
    
    if ($user_id) {
        $users = [get_userdata($user_id)];
    } else {
        $users = get_users(['number' => -1]);
    }
    
    $synced_count = 0;
    
    foreach ($users as $user) {
        if (!$user) continue;
        
        // Get PeepSo user data
        $peepso_user = $wpdb->get_row($wpdb->prepare("
            SELECT * FROM {$wpdb->prefix}peepso_users 
            WHERE usr_id = %d
        ", $user->ID));
        
        // Get pages owned (where user is owner)
        $pages_owned = $wpdb->get_results($wpdb->prepare("
            SELECT pm_page_id 
            FROM {$wpdb->prefix}peepso_page_members 
            WHERE pm_user_id = %d 
            AND pm_user_status = 'member_owner'
        ", $user->ID));
        
        $page_ids_owned = wp_list_pluck($pages_owned, 'pm_page_id');
        $pages_owned_count = count($page_ids_owned);
        
        // Get pages joined (where user is member)
        $pages_joined = $wpdb->get_results($wpdb->prepare("
            SELECT pm_page_id 
            FROM {$wpdb->prefix}peepso_page_members 
            WHERE pm_user_id = %d 
            AND pm_user_status = 'member'
        ", $user->ID));
        
        $page_ids_joined = wp_list_pluck($pages_joined, 'pm_page_id');
        $pages_joined_count = count($page_ids_joined);
        
        // Get pages where user is moderator
        $pages_moderated = $wpdb->get_results($wpdb->prepare("
            SELECT pm_page_id 
            FROM {$wpdb->prefix}peepso_page_members 
            WHERE pm_user_id = %d 
            AND pm_user_status = 'moderator'
        ", $user->ID));
        
        $pages_moderated_count = count($pages_moderated);
        
        // Get pages pending approval
        $pages_pending = $wpdb->get_results($wpdb->prepare("
            SELECT pm_page_id 
            FROM {$wpdb->prefix}peepso_page_members 
            WHERE pm_user_id = %d 
            AND pm_user_status = 'pending'
        ", $user->ID));
        
        $pages_pending_count = count($pages_pending);
        
        // Get groups owned
        $groups_owned = $wpdb->get_results($wpdb->prepare("
            SELECT gm_group_id 
            FROM {$wpdb->prefix}peepso_group_members 
            WHERE gm_user_id = %d 
            AND gm_user_status = 'member_owner'
        ", $user->ID));
        
        $group_ids_owned = wp_list_pluck($groups_owned, 'gm_group_id');
        $groups_owned_count = count($group_ids_owned);
        
        // Get groups joined
        $groups_joined = $wpdb->get_results($wpdb->prepare("
            SELECT gm_group_id 
            FROM {$wpdb->prefix}peepso_group_members 
            WHERE gm_user_id = %d 
            AND gm_user_status = 'member'
        ", $user->ID));
        
        $group_ids_joined = wp_list_pluck($groups_joined, 'gm_group_id');
        $groups_joined_count = count($group_ids_joined);
        
        // Get groups moderated
        $groups_moderated = $wpdb->get_results($wpdb->prepare("
            SELECT gm_group_id 
            FROM {$wpdb->prefix}peepso_group_members 
            WHERE gm_user_id = %d 
            AND gm_user_status = 'moderator'
        ", $user->ID));
        
        $groups_moderated_count = count($groups_moderated);
        
        // Get groups pending
        $groups_pending = $wpdb->get_results($wpdb->prepare("
            SELECT gm_group_id 
            FROM {$wpdb->prefix}peepso_group_members 
            WHERE gm_user_id = %d 
            AND gm_user_status = 'pending'
        ", $user->ID));
        
        $groups_pending_count = count($groups_pending);
        
        // Get posts created by user
        $posts = $wpdb->get_results($wpdb->prepare("
            SELECT ID, post_date 
            FROM {$wpdb->posts} 
            WHERE post_author = %d 
            AND post_type IN ('post', 'peepso-page', 'peepso-group')
            ORDER BY post_date DESC
        ", $user->ID));
        
        $post_ids_created = wp_list_pluck($posts, 'ID');
        $posts_created_count = count($post_ids_created);
        $last_post_date = !empty($posts) ? $posts[0]->post_date : null;
        
        // Get comments made by user
        $comments = $wpdb->get_results($wpdb->prepare("
            SELECT comment_ID, comment_date 
            FROM {$wpdb->comments} 
            WHERE comment_author = %s 
            OR user_id = %d
            ORDER BY comment_date DESC
        ", $user->user_email, $user->ID));
        
        $comments_made_count = count($comments);
        $last_comment_date = !empty($comments) ? $comments[0]->comment_date : null;
        
        // Get trust/fraud data
        $trust_data = get_user_meta($user->ID, 'bcc_trust_fraud_analysis', true);
        $fraud_score = (int) get_user_meta($user->ID, 'bcc_trust_fraud_score', true);
        $trust_rank = (float) get_user_meta($user->ID, 'bcc_trust_graph_rank', true);
        $votes_cast = (int) get_user_meta($user->ID, 'bcc_trust_votes_cast', true);
        $endorsements_given = (int) get_user_meta($user->ID, 'bcc_trust_endorsements_given', true);
        $fraud_triggers = get_user_meta($user->ID, 'bcc_trust_fraud_triggers', true);
        
        // Prepare data for insert/update
        $data = [
            'user_id' => $user->ID,
            'user_login' => $user->user_login,
            'user_email' => $user->user_email,
            'display_name' => $user->display_name ?: $user->user_login,
            'registered' => $user->user_registered,
            
            // PeepSo data
            'usr_last_activity' => $peepso_user ? $peepso_user->usr_last_activity : null,
            'usr_views' => $peepso_user ? (int)$peepso_user->usr_views : 0,
            'usr_likes' => $peepso_user ? (int)$peepso_user->usr_likes : 0,
            'usr_role' => $peepso_user ? $peepso_user->usr_role : null,
            
            // Trust scores
            'fraud_score' => $fraud_score,
            'trust_rank' => $trust_rank,
            'risk_level' => is_array($trust_data) ? ($trust_data['risk_level'] ?? 'unknown') : 'unknown',
            'is_suspended' => (int) get_user_meta($user->ID, 'bcc_trust_suspended', true),
            'is_verified' => (int) get_user_meta($user->ID, 'bcc_trust_email_verified', true),
            'votes_cast' => $votes_cast,
            'endorsements_given' => $endorsements_given,
            
            // Page stats
            'pages_owned' => $pages_owned_count,
            'pages_joined' => $pages_joined_count,
            'pages_moderated' => $pages_moderated_count,
            'pages_pending' => $pages_pending_count,
            'page_ids_owned' => !empty($page_ids_owned) ? json_encode($page_ids_owned) : null,
            'page_ids_joined' => !empty($page_ids_joined) ? json_encode($page_ids_joined) : null,
            
            // Group stats
            'groups_owned' => $groups_owned_count,
            'groups_joined' => $groups_joined_count,
            'groups_moderated' => $groups_moderated_count,
            'groups_pending' => $groups_pending_count,
            'group_ids_owned' => !empty($group_ids_owned) ? json_encode($group_ids_owned) : null,
            'group_ids_joined' => !empty($group_ids_joined) ? json_encode($group_ids_joined) : null,
            
            // Post/Comment stats
            'posts_created' => $posts_created_count,
            'comments_made' => $comments_made_count,
            'post_ids_created' => !empty($post_ids_created) ? json_encode($post_ids_created) : null,
            'last_post_date' => $last_post_date,
            'last_comment_date' => $last_comment_date,
            
            // Fraud data
            'fraud_triggers' => is_array($fraud_triggers) ? json_encode($fraud_triggers) : null,
            'last_ip_address' => get_user_meta($user->ID, 'bcc_trust_last_ip', true),
            'device_fingerprint' => get_user_meta($user->ID, 'bcc_trust_device_fingerprint', true),
            'automation_score' => (int) get_user_meta($user->ID, 'bcc_trust_automation_score', true),
            'trust_graph_data' => null,
        ];
        
        // Check if record exists
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name WHERE user_id = %d",
            $user->ID
        ));
        
        // Create format specifiers array
        $formats = [];
        foreach ($data as $key => $value) {
            // Determine format based on field name
            if (in_array($key, ['fraud_score', 'automation_score', 'behavior_score', 'votes_cast', 'endorsements_given', 
                                 'pages_owned', 'pages_joined', 'pages_moderated', 'pages_pending', 
                                 'groups_owned', 'groups_joined', 'groups_moderated', 'groups_pending',
                                 'posts_created', 'comments_made', 'usr_views', 'usr_likes'])) {
                $formats[] = '%d'; // Integer
            } elseif (in_array($key, ['trust_rank'])) {
                $formats[] = '%f'; // Float
            } elseif (in_array($key, ['last_post_date', 'last_comment_date', 'usr_last_activity', 'last_login', 'registered', 'page_ids_owned', 
                                       'page_ids_joined', 'group_ids_owned', 'group_ids_joined', 'post_ids_created', 'fraud_triggers'])) {
                $formats[] = '%s'; // String (including JSON and dates)
            } else {
                $formats[] = '%s'; // Default to string
            }
        }
        
        if ($exists) {
            $wpdb->update(
                $table_name, 
                $data, 
                ['user_id' => $user->ID],
                $formats,
                ['%d'] // user_id is integer
            );
        } else {
            $wpdb->insert(
                $table_name, 
                $data,
                $formats
            );
        }
        
        $synced_count++;
    }
    
    return $synced_count;
}

/**
 * Helper functions for table names - ALL TABLES CONSISTENTLY PREFIXED
 */
function bcc_trust_votes_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_votes';
}

function bcc_trust_scores_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_page_scores';
}

function bcc_trust_endorsements_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_endorsements';
}

function bcc_trust_verifications_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_verifications';
}

function bcc_trust_eligibility_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_eligibility';
}

function bcc_trust_activity_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_activity';
}

function bcc_trust_flags_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_flags';
}

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
 * User info table
 */
function bcc_trust_user_info_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_user_info';
}

/**
 * NEW: Fraud analysis table
 */
function bcc_trust_fraud_analysis_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_fraud_analysis';
}

/**
 * NEW: Suspensions table
 */
function bcc_trust_suspensions_table() {
    global $wpdb;
    return $wpdb->prefix . 'bcc_trust_suspensions';
}

function bcc_trust_get_page_owner($page_id) {
    global $wpdb;
    
    // Try PeepSo page members table first (most common - uses pm_user_id)
    $members_table = $wpdb->prefix . 'peepso_page_members';
    if ($wpdb->get_var("SHOW TABLES LIKE '$members_table'") == $members_table) {
        $owner = $wpdb->get_var($wpdb->prepare(
            "SELECT pm_user_id FROM {$members_table} 
             WHERE pm_page_id = %d 
             AND pm_user_status = 'member_owner' 
             LIMIT 1",
            $page_id
        ));
        
        if ($owner && $owner > 0) {
            return (int) $owner;
        }
    }
    
    // Try alternative tables that might use 'user_id'
    $possible_tables = [
        $wpdb->prefix . 'peepso_page_users',
        $wpdb->prefix . 'peepso_pages_users'
    ];
    
    foreach ($possible_tables as $table) {
        if ($wpdb->get_var("SHOW TABLES LIKE '$table'") == $table) {
            $owner = $wpdb->get_var($wpdb->prepare(
                "SELECT user_id FROM {$table} 
                 WHERE page_id = %d AND (role = 'owner' OR role = 'admin') 
                 LIMIT 1",
                $page_id
            ));
            
            if ($owner && $owner > 0) {
                return (int) $owner;
            }
        }
    }
    
    // Fallback to post author
    $post = get_post($page_id);
    return $post ? (int) $post->post_author : 0;
}

/**
 * Log audit event helper
 */
if (!function_exists('bcc_trust_log_audit')) {
    function bcc_trust_log_audit($action, $data = []) {
        if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
            \BCCTrust\Security\AuditLogger::log($action, null, $data);
        }
    }
}

/**
 * Schedule cleanup for old fingerprint records
 */
add_action('bcc_trust_daily_cleanup', function() {
    global $wpdb;
    
    // Clean old fingerprints (older than 90 days)
    $fingerprints_table = bcc_trust_fingerprints_table();
    $cutoff = date('Y-m-d H:i:s', strtotime('-90 days'));
    
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$fingerprints_table} WHERE last_seen < %s",
            $cutoff
        )
    );
    
    // Clean old patterns (older than 30 days)
    $patterns_table = bcc_trust_patterns_table();
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$patterns_table} WHERE expires_at < %s OR (expires_at IS NULL AND detected_at < %s)",
            current_time('mysql'),
            date('Y-m-d H:i:s', strtotime('-30 days'))
        )
    );
    
    // Clean old fraud analysis (older than 90 days)
    $fraud_analysis_table = bcc_trust_fraud_analysis_table();
    $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$fraud_analysis_table} WHERE expires_at < %s OR (expires_at IS NULL AND analyzed_at < %s)",
            current_time('mysql'),
            date('Y-m-d H:i:s', strtotime('-90 days'))
        )
    );
});

/**
 * Hook into user actions to keep sync table updated
 */
add_action('user_register', 'bcc_trust_sync_user_on_register');
function bcc_trust_sync_user_on_register($user_id) {
    bcc_trust_sync_user_info($user_id);
}

add_action('profile_update', 'bcc_trust_sync_user_on_update');
function bcc_trust_sync_user_on_update($user_id) {
    bcc_trust_sync_user_info($user_id);
}

add_action('wp_login', 'bcc_trust_track_login', 10, 2);
function bcc_trust_track_login($user_login, $user) {
    update_user_meta($user->ID, 'bcc_trust_last_login', current_time('mysql'));
    update_user_meta($user->ID, 'bcc_trust_last_ip', $_SERVER['REMOTE_ADDR']);
    bcc_trust_sync_user_info($user->ID);
}

// Add admin action for manual sync
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
 * Get user data from user_info table
 */
function bcc_trust_get_user_info($user_id) {
    global $wpdb;
    
    $table = bcc_trust_user_info_table();
    
    return $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$table} WHERE user_id = %d",
        $user_id
    ));
}

/**
 * Get multiple users from user_info table with filters
 */
function bcc_trust_get_users_info($args = []) {
    global $wpdb;
    
    $table = bcc_trust_user_info_table();
    
    $defaults = [
        'orderby' => 'fraud_score',
        'order' => 'DESC',
        'limit' => 50,
        'offset' => 0,
        'risk_level' => '',
        'search' => ''
    ];
    
    $args = wp_parse_args($args, $defaults);
    
    $where = ['1=1'];
    $params = [];
    
    if (!empty($args['risk_level'])) {
        $where[] = "risk_level = %s";
        $params[] = $args['risk_level'];
    }
    
    if (!empty($args['search'])) {
        $where[] = "(display_name LIKE %s OR user_email LIKE %s OR user_login LIKE %s)";
        $search_term = '%' . $wpdb->esc_like($args['search']) . '%';
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
    }
    
    $where_clause = implode(' AND ', $where);
    
    // Validate orderby
    $valid_orderby = ['fraud_score', 'trust_rank', 'votes_cast', 'endorsements_given', 'pages_owned', 'groups_owned', 'usr_last_activity', 'registered'];
    if (!in_array($args['orderby'], $valid_orderby)) {
        $args['orderby'] = 'fraud_score';
    }
    
    $sql = "SELECT * FROM {$table} 
            WHERE {$where_clause} 
            ORDER BY {$args['orderby']} {$args['order']} 
            LIMIT %d OFFSET %d";
    
    $params[] = $args['limit'];
    $params[] = $args['offset'];
    
    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }
    
    return $wpdb->get_results($sql);
}

/**
 * Sync user pages - update user_info table with page ownership data
 */
function bcc_trust_sync_user_pages($user_id = null) {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();
    $scoresTable = bcc_trust_scores_table();
    
    if ($user_id) {
        // Get all pages owned by this user
        $pages = $wpdb->get_results($wpdb->prepare(
            "SELECT page_id FROM {$scoresTable} WHERE page_owner_id = %d",
            $user_id
        ));
        
        $page_ids = wp_list_pluck($pages, 'page_id');
        $count = count($page_ids);
        
        $wpdb->update(
            $userInfoTable,
            [
                'pages_owned' => $count,
                'page_ids_owned' => !empty($page_ids) ? json_encode($page_ids) : null
            ],
            ['user_id' => $user_id],
            ['%d', '%s'],
            ['%d']
        );
    } else {
        // Update all users
        $users = $wpdb->get_col("SELECT user_id FROM {$userInfoTable}");
        foreach ($users as $uid) {
            bcc_trust_sync_user_pages($uid);
        }
    }
}

/**
 * AJAX handler for initializing page score
 */
add_action('wp_ajax_bcc_trust_init_page_score', 'bcc_trust_ajax_init_page_score');
function bcc_trust_ajax_init_page_score() {
    check_ajax_referer('bcc_trust_admin', 'nonce');
    
    if (!current_user_can('manage_options')) {
        wp_send_json_error('Unauthorized');
    }
    
    $page_id = isset($_POST['page_id']) ? intval($_POST['page_id']) : 0;
    
    if (!$page_id) {
        wp_send_json_error('No page ID provided');
    }
    
    global $wpdb;
    $scoresTable = bcc_trust_scores_table();
    
    // Check if page exists
    $post = get_post($page_id);
    if (!$post) {
        wp_send_json_error('Page not found');
    }
    
    // Check if already exists
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
 * Database repair function - Fix page owner mismatches
 */
function bcc_trust_repair_page_owners() {
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $membersTable = $wpdb->prefix . 'peepso_page_members';
    
    // Check if members table exists
    if ($wpdb->get_var("SHOW TABLES LIKE '$membersTable'") != $membersTable) {
        return 0;
    }
    
    // Update page_owner_id based on peepso_page_members
    $updated = $wpdb->query("
        UPDATE {$scoresTable} s
        JOIN {$membersTable} pm ON s.page_id = pm.pm_page_id
        SET s.page_owner_id = pm.pm_user_id
        WHERE pm.pm_user_status = 'member_owner'
        AND s.page_owner_id != pm.pm_user_id
    ");
    
    return $updated;
}