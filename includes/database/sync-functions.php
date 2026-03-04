<?php
/**
 * Database Sync Functions
 * 
 * @package BCC_Trust_Engine
 * @subpackage Database
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Sync User Info - Sync WordPress user data to user_info table
 * 
 * @param int|null $user_id Specific user ID or null for all users
 * @return int Number of users synced
 */
function bcc_trust_sync_user_info($user_id = null) {
    global $wpdb;
    
    $table_name = bcc_trust_user_info_table();
    
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
        
        $pages_owned_count = count($pages_owned);
        
        // Get groups owned
        $groups_owned = $wpdb->get_results($wpdb->prepare("
            SELECT gm_group_id 
            FROM {$wpdb->prefix}peepso_group_members 
            WHERE gm_user_id = %d 
            AND gm_user_status = 'member_owner'
        ", $user->ID));
        
        $groups_owned_count = count($groups_owned);
        
        // Get posts created by user
        $posts = $wpdb->get_results($wpdb->prepare("
            SELECT ID 
            FROM {$wpdb->posts} 
            WHERE post_author = %d 
            AND post_type IN ('post', 'peepso-page', 'peepso-group')
        ", $user->ID));
        
        $posts_created_count = count($posts);
        
        // Get comments made by user
        $comments = $wpdb->get_results($wpdb->prepare("
            SELECT comment_ID 
            FROM {$wpdb->comments} 
            WHERE comment_author = %s 
            OR user_id = %d
        ", $user->user_email, $user->ID));
        
        $comments_made_count = count($comments);
        
        // Get trust/fraud data
        $trust_data = get_user_meta($user->ID, 'bcc_trust_fraud_analysis', true);
        $fraud_score = (int) get_user_meta($user->ID, 'bcc_trust_fraud_score', true);
        $trust_rank = (float) get_user_meta($user->ID, 'bcc_trust_graph_rank', true);
        $votes_cast = (int) get_user_meta($user->ID, 'bcc_trust_votes_cast', true);
        $endorsements_given = (int) get_user_meta($user->ID, 'bcc_trust_endorsements_given', true);
        
        // Prepare data for insert/update - ONLY columns that exist in schema
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
            
            // Count stats (these exist in schema)
            'pages_owned' => $pages_owned_count,
            'groups_owned' => $groups_owned_count,
            'posts_created' => $posts_created_count,
            'comments_made' => $comments_made_count,
            
            // Fraud data
            'last_ip_address' => get_user_meta($user->ID, 'bcc_trust_last_ip', true),
            'device_fingerprint' => get_user_meta($user->ID, 'bcc_trust_device_fingerprint', true),
            'automation_score' => (int) get_user_meta($user->ID, 'bcc_trust_automation_score', true),
            
            // GitHub fields
            'github_id' => null,
            'github_username' => null,
            'github_avatar' => null,
            'github_followers' => 0,
            'github_public_repos' => 0,
            'github_org_count' => 0,
            'github_account_created' => null,
            'github_account_age_days' => 0,
            'github_has_verified_email' => 0,
            'github_verified_at' => null,
            'github_last_synced' => null,
            'github_access_token' => null,
            'github_trust_boost' => 0,
            'github_fraud_reduction' => 0,
        ];
        
        // Check if record exists
        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table_name WHERE user_id = %d",
            $user->ID
        ));
        
        // Create format specifiers array
        $formats = [];
        foreach ($data as $key => $value) {
            if (in_array($key, [
                'fraud_score', 'automation_score', 'behavior_score', 'votes_cast', 'endorsements_given',
                'pages_owned', 'groups_owned', 'posts_created', 'comments_made', 
                'usr_views', 'usr_likes', 'is_suspended', 'is_verified',
                'github_id', 'github_followers', 'github_public_repos', 'github_org_count',
                'github_account_age_days', 'github_has_verified_email', 'github_fraud_reduction'
            ])) {
                $formats[] = '%d';
            } elseif (in_array($key, ['trust_rank', 'github_trust_boost'])) {
                $formats[] = '%f';
            } else {
                $formats[] = '%s';
            }
        }
        
        if ($exists) {
            $wpdb->update(
                $table_name, 
                $data, 
                ['user_id' => $user->ID],
                $formats,
                ['%d']
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