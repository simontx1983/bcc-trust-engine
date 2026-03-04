<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Trust Engine Moderation Tools
 * Enhanced with fraud detection, behavioral analysis, and device fingerprinting
 * 
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

add_action('admin_menu', function () {
    add_submenu_page(
        'bcc-trust-dashboard',
        'Moderation',
        'Moderation',
        'manage_options',
        'bcc-trust-moderation',
        'bcc_trust_render_moderation'
    );
});

function bcc_trust_render_moderation() {
    if (!current_user_can('manage_options')) {
        return;
    }

    global $wpdb;

    // Handle actions
    if (isset($_POST['suspend_user']) && check_admin_referer('bcc_trust_moderation')) {
        $userId = intval($_POST['user_id']);
        $reason = isset($_POST['suspend_reason']) ? sanitize_text_field($_POST['suspend_reason']) : 'manual_suspension';
        
        // Get current fraud score
        $userInfoTable = bcc_trust_user_info_table();
        $userInfo = $wpdb->get_row($wpdb->prepare(
            "SELECT fraud_score FROM {$userInfoTable} WHERE user_id = %d",
            $userId
        ));
        
        // Insert into suspensions table
        $suspensionsTable = bcc_trust_suspensions_table();
        $wpdb->insert(
            $suspensionsTable,
            [
                'user_id' => $userId,
                'suspended_by' => get_current_user_id(),
                'reason' => $reason,
                'fraud_score_at_time' => $userInfo ? $userInfo->fraud_score : null,
                'suspended_at' => current_time('mysql')
            ],
            ['%d', '%d', '%s', '%d', '%s']
        );
        
        // Update user_info table
        $wpdb->update(
            $userInfoTable,
            ['is_suspended' => 1],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        );
        
        // Log the action
        if (class_exists('BCCTrust\Security\AuditLogger')) {
            BCCTrust\Security\AuditLogger::log('admin_suspend', $userId, [
                'admin_id' => get_current_user_id(),
                'reason' => $reason
            ], 'user');
        }
        
        echo '<div class="notice notice-success"><p>User suspended. Reason: ' . esc_html($reason) . '</p></div>';
    }

    if (isset($_POST['unsuspend_user']) && check_admin_referer('bcc_trust_moderation')) {
        $userId = intval($_POST['user_id']);
        
        // Update suspensions table
        $suspensionsTable = bcc_trust_suspensions_table();
        $wpdb->update(
            $suspensionsTable,
            [
                'unsuspended_at' => current_time('mysql'),
                'unsuspended_by' => get_current_user_id()
            ],
            [
                'user_id' => $userId,
                'unsuspended_at' => null
            ],
            ['%s', '%d'],
            ['%d', '%s']
        );
        
        // Update user_info table
        $userInfoTable = bcc_trust_user_info_table();
        $wpdb->update(
            $userInfoTable,
            ['is_suspended' => 0],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        );
        
        // Log the action
        if (class_exists('BCCTrust\Security\AuditLogger')) {
            BCCTrust\Security\AuditLogger::log('admin_unsuspend', $userId, [
                'admin_id' => get_current_user_id()
            ], 'user');
        }
        
        echo '<div class="notice notice-success"><p>User unsuspended.</p></div>';
    }

    if (isset($_POST['clear_votes']) && check_admin_referer('bcc_trust_moderation')) {
        $userId = intval($_POST['user_id']);
        
        $votesTable = bcc_trust_votes_table();
        
        // Get affected pages before clearing
        $affectedPages = $wpdb->get_col($wpdb->prepare(
            "SELECT DISTINCT page_id FROM {$votesTable} WHERE voter_user_id = %d AND status = 1",
            $userId
        ));

        // Soft delete all votes by this user
        $wpdb->update(
            $votesTable,
            ['status' => 0, 'updated_at' => current_time('mysql')],
            ['voter_user_id' => $userId],
            ['%d', '%s'],
            ['%d']
        );

        // Update user's vote count in user_info table
        $userInfoTable = bcc_trust_user_info_table();
        $wpdb->update(
            $userInfoTable,
            ['votes_cast' => 0],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        );

        // Recalculate scores for affected pages
        if (function_exists('bcc_trust_recalculate_page_score')) {
            foreach ($affectedPages as $pageId) {
                bcc_trust_recalculate_page_score($pageId);
            }
        }

        // Log the action
        if (class_exists('BCCTrust\Security\AuditLogger')) {
            BCCTrust\Security\AuditLogger::log('admin_clear_votes', $userId, [
                'admin_id' => get_current_user_id(),
                'pages_affected' => count($affectedPages)
            ], 'user');
        }

        echo '<div class="notice notice-success"><p>Votes cleared and scores recalculated for ' . count($affectedPages) . ' pages.</p></div>';
    }

    if (isset($_POST['clear_fingerprints']) && check_admin_referer('bcc_trust_moderation')) {
        $userId = intval($_POST['user_id']);
        
        $fingerprintTable = bcc_trust_fingerprints_table();
        
        $wpdb->delete(
            $fingerprintTable,
            ['user_id' => $userId],
            ['%d']
        );
        
        // Update user_info table
        $userInfoTable = bcc_trust_user_info_table();
        $wpdb->update(
            $userInfoTable,
            [
                'device_fingerprint' => null,
                'automation_score' => 0
            ],
            ['user_id' => $userId],
            ['%s', '%d'],
            ['%d']
        );
        
        echo '<div class="notice notice-success"><p>Device fingerprints cleared for user.</p></div>';
    }

    if (isset($_POST['reanalyze_user']) && check_admin_referer('bcc_trust_moderation')) {
        $userId = intval($_POST['user_id']);
        
        // Clear caches
        if (class_exists('BCCTrust\Security\FraudDetector')) {
            BCCTrust\Security\FraudDetector::clearCache($userId);
        }
        
        if (class_exists('BCCTrust\Security\BehavioralAnalyzer')) {
            $analyzer = new BCCTrust\Security\BehavioralAnalyzer();
            $analyzer->clearCache($userId);
        }
        
        // Force new analysis
        if (class_exists('BCCTrust\Security\FraudDetector')) {
            $newScore = BCCTrust\Security\FraudDetector::getEnhancedFraudScore($userId);
            
            // Get updated analysis
            $analysis = BCCTrust\Security\FraudDetector::analyzeFraud($userId);
            
            // Update user_info table with new fraud data
            $userInfoTable = bcc_trust_user_info_table();
            $wpdb->update(
                $userInfoTable,
                [
                    'fraud_score' => $newScore,
                    'risk_level' => $analysis['risk_level'] ?? 'unknown',
                    'fraud_triggers' => isset($analysis['triggers']) ? json_encode($analysis['triggers']) : null,
                    'behavior_score' => $analysis['details']['behavior_score'] ?? 0
                ],
                ['user_id' => $userId],
                ['%d', '%s', '%s', '%d'],
                ['%d']
            );
            
            echo '<div class="notice notice-success"><p>User reanalyzed. New fraud score: ' . $newScore . '</p></div>';
        }
    }

    // Get user if specified
    $userId = isset($_GET['user_id']) ? intval($_GET['user_id']) : 0;
    $ip = isset($_GET['ip']) ? sanitize_text_field($_GET['ip']) : '';
    $fingerprint = isset($_GET['fingerprint']) ? sanitize_text_field($_GET['fingerprint']) : '';

    if ($userId) {
        bcc_trust_render_user_moderation($userId);
    } elseif ($ip) {
        bcc_trust_render_ip_moderation($ip);
    } elseif ($fingerprint) {
        bcc_trust_render_fingerprint_moderation($fingerprint);
    } else {
        bcc_trust_render_user_list();
    }
}

/**
 * Render user list with enhanced filters - UPDATED to use user_info table
 */
function bcc_trust_render_user_list() {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();
    $suspensionsTable = bcc_trust_suspensions_table();
    
    $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
    $filter = isset($_GET['filter']) ? sanitize_key($_GET['filter']) : 'all';
    $risk_level = isset($_GET['risk_level']) ? sanitize_key($_GET['risk_level']) : '';
    
    // Pagination
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $per_page = 50;
    $offset = ($current_page - 1) * $per_page;

    // Build WHERE clause
    $where = ['1=1'];
    $params = [];

    if ($search) {
        $where[] = "(display_name LIKE %s OR user_email LIKE %s OR user_login LIKE %s)";
        $search_term = '%' . $wpdb->esc_like($search) . '%';
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
    }

    if ($risk_level) {
        $where[] = "risk_level = %s";
        $params[] = $risk_level;
    }

    if ($filter === 'suspended') {
        $where[] = "is_suspended = 1";
    } elseif ($filter === 'verified') {
        $where[] = "is_verified = 1";
    } elseif ($filter === 'high_fraud') {
        $where[] = "fraud_score >= 70";
    }

    $where_clause = implode(' AND ', $where);

    // Get total count
    $count_sql = "SELECT COUNT(*) FROM {$userInfoTable} WHERE {$where_clause}";
    if (!empty($params)) {
        $count_sql = $wpdb->prepare($count_sql, $params);
    }
    $total_items = $wpdb->get_var($count_sql);

    // Get users from user_info table
    $sql = "SELECT ui.*, 
                   (SELECT COUNT(*) FROM {$suspensionsTable} s WHERE s.user_id = ui.user_id AND s.unsuspended_at IS NULL) as active_suspensions
            FROM {$userInfoTable} ui 
            WHERE {$where_clause} 
            ORDER BY ui.fraud_score DESC 
            LIMIT %d OFFSET %d";
    $params[] = $per_page;
    $params[] = $offset;
    
    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }

    $users = $wpdb->get_results($sql);
    ?>

    <div class="wrap">
        <h1>Trust Moderation</h1>

        <!-- Sync button -->
        <div style="margin: 10px 0;">
            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&sync=1'); ?>" class="button button-primary">Sync All Users</a>
            <?php if (isset($_GET['synced'])): ?>
                <span style="margin-left: 10px; color: green;">Synced <?php echo intval($_GET['synced']); ?> users!</span>
            <?php endif; ?>
        </div>

        <form method="get">
            <input type="hidden" name="page" value="bcc-trust-moderation">
            <div class="tablenav top">
                <div class="alignleft actions">
                    <select name="filter">
                        <option value="all" <?php selected($filter, 'all'); ?>>All Users</option>
                        <option value="suspended" <?php selected($filter, 'suspended'); ?>>Suspended Only</option>
                        <option value="verified" <?php selected($filter, 'verified'); ?>>Verified Only</option>
                        <option value="high_fraud" <?php selected($filter, 'high_fraud'); ?>>High Fraud Risk</option>
                    </select>
                    
                    <select name="risk_level">
                        <option value="">All Risk Levels</option>
                        <option value="critical" <?php selected($risk_level, 'critical'); ?>>Critical Risk</option>
                        <option value="high" <?php selected($risk_level, 'high'); ?>>High Risk</option>
                        <option value="medium" <?php selected($risk_level, 'medium'); ?>>Medium Risk</option>
                        <option value="low" <?php selected($risk_level, 'low'); ?>>Low Risk</option>
                        <option value="minimal" <?php selected($risk_level, 'minimal'); ?>>Minimal Risk</option>
                    </select>
                    
                    <input type="submit" class="button" value="Filter">
                    
                    <?php if ($search): ?>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation'); ?>" class="button">Clear Filters</a>
                    <?php endif; ?>
                </div>
                <div class="alignright">
                    <input type="search" name="s" value="<?php echo esc_attr($search); ?>" placeholder="Search users...">
                    <input type="submit" class="button" value="Search">
                </div>
            </div>
        </form>

        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>User</th>
                    <th>Email</th>
                    <th>Status</th>
                    <th>Fraud Score</th>
                    <th>Risk Level</th>
                    <th>Triggers</th>
                    <th>Last Active</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($users)): ?>
                    <tr>
                        <td colspan="8" style="text-align:center; padding:20px;">
                            <strong>No users found matching your criteria.</strong>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($users as $user): 
                        $triggers = [];
                        if ($user->fraud_triggers) {
                            $triggers = json_decode($user->fraud_triggers, true);
                            if (!is_array($triggers)) $triggers = [];
                        }
                    ?>
                        <tr>
                            <td>
                                <strong><?php echo esc_html($user->display_name); ?></strong>
                                <br><small>ID: <?php echo $user->user_id; ?></small>
                            </td>
                            <td><?php echo esc_html($user->user_email); ?></td>
                            <td>
                                <?php if ($user->is_suspended || $user->active_suspensions > 0): ?>
                                    <span class="status-badge suspended" style="background:#f44336; color:#fff; padding:3px 8px; border-radius:3px;">Suspended</span>
                                <?php else: ?>
                                    <span class="status-badge active" style="background:#4caf50; color:#fff; padding:3px 8px; border-radius:3px;">Active</span>
                                <?php endif; ?>
                                <?php if ($user->is_verified): ?>
                                    <br><small style="color:#4caf50;">✓ Verified</small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div style="display:flex; align-items:center;">
                                    <div style="width:60px; height:20px; background:#eee; border-radius:10px; position:relative; overflow:hidden; margin-right:8px;">
                                        <div style="position:absolute; top:0; left:0; height:100%; width:<?php echo $user->fraud_score; ?>%; background:<?php echo bcc_trust_get_score_color($user->fraud_score); ?>;"></div>
                                    </div>
                                    <?php echo $user->fraud_score; ?>/100
                                </div>
                            </td>
                            <td>
                                <span style="padding:3px 8px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($user->risk_level); ?>; color:#fff;">
                                    <?php echo esc_html(ucfirst($user->risk_level)); ?>
                                </span>
                            </td>
                            <td>
                                <?php 
                                $triggers = array_slice($triggers, 0, 2);
                                echo esc_html(implode(', ', $triggers));
                                if (count($triggers) > 2) echo '...';
                                ?>
                            </td>
                            <td>
                                <?php 
                                if ($user->usr_last_activity) {
                                    echo date('Y-m-d H:i', strtotime($user->usr_last_activity));
                                } else {
                                    echo '—';
                                }
                                ?>
                            </td>
                            <td>
                                <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $user->user_id); ?>" class="button button-small">Manage</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <!-- Pagination -->
        <?php
        $total_pages = ceil($total_items / $per_page);
        if ($total_pages > 1):
        ?>
        <div class="tablenav bottom">
            <div class="tablenav-pages">
                <span class="displaying-num"><?php echo number_format($total_items); ?> items</span>
                <?php
                echo paginate_links([
                    'base' => add_query_arg('paged', '%#%'),
                    'format' => '',
                    'prev_text' => '&laquo;',
                    'next_text' => '&raquo;',
                    'total' => $total_pages,
                    'current' => $current_page
                ]);
                ?>
            </div>
        </div>
        <?php 
        endif;
        
        // Handle sync request
        if (isset($_GET['sync']) && $_GET['sync'] == '1') {
            $synced = bcc_trust_sync_user_info();
            echo '<script>window.location.href = "' . admin_url('admin.php?page=bcc-trust-moderation&synced=' . $synced) . '";</script>';
        }
        ?>
    </div>
    <?php
}

/**
 * Render detailed user moderation view - UPDATED to use new tables
 */
function bcc_trust_render_user_moderation($userId) {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();
    $votesTable = bcc_trust_votes_table();
    $endorseTable = bcc_trust_endorsements_table();
    $auditTable = bcc_trust_activity_table();
    $scoresTable = bcc_trust_scores_table();
    $fingerprintTable = bcc_trust_fingerprints_table();
    $fraudAnalysisTable = bcc_trust_fraud_analysis_table();
    $suspensionsTable = bcc_trust_suspensions_table();

    // Get user data from user_info table
    $userInfo = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM {$userInfoTable} WHERE user_id = %d",
        $userId
    ));

    $user = get_userdata($userId);
    if (!$user || !$userInfo) {
        echo '<div class="notice notice-error"><p>User not found.</p></div>';
        return;
    }

    // Parse fraud triggers
    $fraudTriggers = $userInfo->fraud_triggers ? json_decode($userInfo->fraud_triggers, true) : [];

    // Get suspension history
    $suspensionHistory = $wpdb->get_results($wpdb->prepare("
        SELECT * FROM {$suspensionsTable}
        WHERE user_id = %d
        ORDER BY suspended_at DESC
    ", $userId));

    // Get fraud analysis history
    $fraudAnalysisHistory = $wpdb->get_results($wpdb->prepare("
        SELECT * FROM {$fraudAnalysisTable}
        WHERE user_id = %d
        ORDER BY analyzed_at DESC
        LIMIT 20
    ", $userId));

    // Get user's pages and their scores
    $userPages = $wpdb->get_results($wpdb->prepare("
        SELECT s.*, p.post_title
        FROM {$scoresTable} s
        JOIN {$wpdb->posts} p ON s.page_id = p.ID
        WHERE s.page_owner_id = %d
        ORDER BY s.total_score DESC
    ", $userId));

    // Get recent votes by this user
    $recentVotes = $wpdb->get_results($wpdb->prepare("
        SELECT v.*, p.post_title as page_title
        FROM {$votesTable} v
        LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
        WHERE v.voter_user_id = %d
        AND v.status = 1
        ORDER BY v.created_at DESC
        LIMIT 20
    ", $userId));

    // Get recent activity
    $recentActivity = $wpdb->get_results($wpdb->prepare("
        SELECT * FROM {$auditTable}
        WHERE user_id = %d
        ORDER BY created_at DESC
        LIMIT 20
    ", $userId));

    // Get user's IPs
    $userIPs = $wpdb->get_results($wpdb->prepare("
        SELECT DISTINCT ip_address, COUNT(*) as count, MAX(created_at) as last_seen
        FROM {$auditTable}
        WHERE user_id = %d
        AND ip_address IS NOT NULL
        GROUP BY ip_address
        ORDER BY last_seen DESC
    ", $userId));

    // Get user's device fingerprints
    $fingerprints = $wpdb->get_results($wpdb->prepare("
        SELECT * FROM {$fingerprintTable}
        WHERE user_id = %d
        ORDER BY last_seen DESC
    ", $userId));
    ?>

    <div class="wrap">
        <h1>Moderate User: <?php echo esc_html($user->display_name ?: $user->user_login); ?></h1>
        
        <p>
            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation'); ?>" class="button">&larr; Back to list</a>
            <a href="<?php echo get_edit_user_link($userId); ?>" class="button" target="_blank">Edit User Profile</a>
        </p>

        <!-- User Information -->
        <div class="user-info-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>User Information</h2>
            <table class="form-table">
                <tr>
                    <th>ID</th>
                    <td><?php echo $userId; ?></td>
                </tr>
                <tr>
                    <th>Username</th>
                    <td><?php echo esc_html($user->user_login); ?></td>
                </tr>
                <tr>
                    <th>Display Name</th>
                    <td><?php echo esc_html($user->display_name); ?></td>
                </tr>
                <tr>
                    <th>Email</th>
                    <td><?php echo esc_html($user->user_email); ?></td>
                </tr>
                <tr>
                    <th>Registered</th>
                    <td><?php echo esc_html($user->user_registered); ?></td>
                </tr>
                <tr>
                    <th>Roles</th>
                    <td><?php echo implode(', ', array_map('esc_html', $user->roles)); ?></td>
                </tr>
                <tr>
                    <th>PeepSo User ID</th>
                    <td><?php echo $userInfo->usr_id ?: '—'; ?></td>
                </tr>
                <tr>
                    <th>Last Activity</th>
                    <td><?php echo $userInfo->usr_last_activity ? esc_html($userInfo->usr_last_activity) : '—'; ?></td>
                </tr>
                <tr>
                    <th>Verified</th>
                    <td><?php echo $userInfo->is_verified ? '✓ Yes' : '✗ No'; ?></td>
                </tr>
                <tr>
                    <th>Status</th>
                    <td>
                        <span class="status-badge <?php echo $userInfo->is_suspended ? 'suspended' : 'active'; ?>" style="background:<?php echo $userInfo->is_suspended ? '#f44336' : '#4caf50'; ?>; color:#fff; padding:3px 8px; border-radius:3px;">
                            <?php echo $userInfo->is_suspended ? 'Suspended' : 'Active'; ?>
                        </span>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Fraud Analysis Summary -->
        <div class="fraud-summary" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4; border-left:5px solid <?php echo bcc_trust_get_risk_color($userInfo->risk_level); ?>;">
            <h2>Fraud Analysis Summary</h2>
            
            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom:20px;">
                <div class="stat-card">
                    <h3 style="margin:0 0 5px 0; font-size:14px; color:#555;">Fraud Score</h3>
                    <div style="display:flex; align-items:center;">
                        <div style="width:100px; height:20px; background:#eee; border-radius:10px; position:relative; overflow:hidden; margin-right:10px;">
                            <div style="position:absolute; top:0; left:0; height:100%; width:<?php echo $userInfo->fraud_score; ?>%; background:<?php echo bcc_trust_get_score_color($userInfo->fraud_score); ?>;"></div>
                        </div>
                        <span style="font-size:24px; font-weight:bold;"><?php echo $userInfo->fraud_score; ?></span>
                    </div>
                </div>
                
                <div class="stat-card">
                    <h3 style="margin:0 0 5px 0; font-size:14px; color:#555;">Risk Level</h3>
                    <span style="font-size:24px; font-weight:bold; padding:5px 15px; border-radius:5px; background:<?php echo bcc_trust_get_risk_color($userInfo->risk_level); ?>; color:#fff;">
                        <?php echo esc_html(ucfirst($userInfo->risk_level)); ?>
                    </span>
                </div>
                
                <div class="stat-card">
                    <h3 style="margin:0 0 5px 0; font-size:14px; color:#555;">Trust Rank</h3>
                    <div style="display:flex; align-items:center;">
                        <div style="width:100px; height:6px; background:#eee; border-radius:3px; margin-right:10px;">
                            <div style="width:<?php echo $userInfo->trust_rank * 100; ?>%; height:6px; background:#4caf50; border-radius:3px;"></div>
                        </div>
                        <span style="font-size:24px; font-weight:bold;"><?php echo number_format($userInfo->trust_rank, 2); ?></span>
                    </div>
                </div>
                
                <div class="stat-card">
                    <h3 style="margin:0 0 5px 0; font-size:14px; color:#555;">Behavior Score</h3>
                    <span style="font-size:24px; font-weight:bold;"><?php echo $userInfo->behavior_score ?: 'N/A'; ?></span>
                </div>
                
                <div class="stat-card">
                    <h3 style="margin:0 0 5px 0; font-size:14px; color:#555;">Automation Score</h3>
                    <span style="font-size:24px; font-weight:bold;"><?php echo $userInfo->automation_score ?: '0'; ?>%</span>
                </div>
            </div>
            
            <?php if (!empty($fraudTriggers)): ?>
                <h3>Detection Triggers</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                    <?php foreach ($fraudTriggers as $trigger): ?>
                        <span style="background:#f0f0f1; padding:5px 10px; border-radius:3px; font-size:12px;">
                            <?php echo esc_html($trigger); ?>
                        </span>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>

        <!-- Action Buttons -->
        <div class="action-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>Moderation Actions</h2>
            
            <form method="post" style="display: inline-block; margin-right: 10px;">
                <?php wp_nonce_field('bcc_trust_moderation'); ?>
                <input type="hidden" name="user_id" value="<?php echo $userId; ?>">
                
                <?php if ($userInfo->is_suspended): ?>
                    <button type="submit" name="unsuspend_user" class="button button-primary">Unsuspend User</button>
                <?php else: ?>
                    <select name="suspend_reason" style="vertical-align: top; margin-right:5px;">
                        <option value="manual_suspension">Manual Suspension</option>
                        <option value="fraud_detected">Fraud Detected</option>
                        <option value="vote_ring">Vote Ring</option>
                        <option value="automation">Automation/Bot</option>
                        <option value="abusive">Abusive Behavior</option>
                        <option value="spam">Spam</option>
                    </select>
                    <button type="submit" name="suspend_user" class="button" style="background:#f44336; border-color:#d32f2f; color:#fff;" onclick="return confirm('Are you sure you want to suspend this user?');">Suspend User</button>
                <?php endif; ?>
            </form>

            <form method="post" style="display: inline-block; margin-right: 10px;">
                <?php wp_nonce_field('bcc_trust_moderation'); ?>
                <input type="hidden" name="user_id" value="<?php echo $userId; ?>">
                <button type="submit" name="clear_votes" class="button" onclick="return confirm('Clear all votes by this user? This cannot be undone.');">Clear All Votes</button>
            </form>

            <form method="post" style="display: inline-block; margin-right: 10px;">
                <?php wp_nonce_field('bcc_trust_moderation'); ?>
                <input type="hidden" name="user_id" value="<?php echo $userId; ?>">
                <button type="submit" name="clear_fingerprints" class="button" onclick="return confirm('Clear device fingerprints for this user?');">Clear Fingerprints</button>
            </form>

            <form method="post" style="display: inline-block;">
                <?php wp_nonce_field('bcc_trust_moderation'); ?>
                <input type="hidden" name="user_id" value="<?php echo $userId; ?>">
                <button type="submit" name="reanalyze_user" class="button">Reanalyze User</button>
            </form>
        </div>

        <!-- Statistics -->
        <div class="stats-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>Activity Statistics</h2>
            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px;">
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Votes Cast</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo number_format($userInfo->votes_cast); ?></div>
                </div>
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Endorsements Given</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo number_format($userInfo->endorsements_given); ?></div>
                </div>
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Pages Owned</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo number_format($userInfo->pages_owned); ?></div>
                </div>
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Groups Owned</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo number_format($userInfo->groups_owned); ?></div>
                </div>
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Posts Created</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo number_format($userInfo->posts_created); ?></div>
                </div>
                <div class="stat-card" style="background:#f8f9f9; padding:15px; text-align:center; border-radius:4px;">
                    <h3 style="margin:0 0 10px 0; font-size:14px; color:#555;">Devices Used</h3>
                    <div class="stat-value" style="font-size:24px; font-weight:bold; color:#0073aa;"><?php echo count($fingerprints); ?></div>
                </div>
            </div>
        </div>

        <!-- Suspension History -->
        <?php if (!empty($suspensionHistory)): ?>
            <div class="suspension-history" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Suspension History</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Suspended</th>
                            <th>By</th>
                            <th>Reason</th>
                            <th>Fraud Score</th>
                            <th>Unsuspended</th>
                            <th>Notes</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($suspensionHistory as $sus): 
                            $suspender = $sus->suspended_by ? get_userdata($sus->suspended_by) : null;
                            $unsuspender = $sus->unsuspended_by ? get_userdata($sus->unsuspended_by) : null;
                        ?>
                            <tr>
                                <td><?php echo esc_html($sus->suspended_at); ?></td>
                                <td><?php echo $suspender ? esc_html($suspender->display_name) : 'System'; ?></td>
                                <td><?php echo esc_html($sus->reason); ?></td>
                                <td><?php echo $sus->fraud_score_at_time ?: '—'; ?></td>
                                <td>
                                    <?php if ($sus->unsuspended_at): ?>
                                        <?php echo esc_html($sus->unsuspended_at); ?><br>
                                        <small>by <?php echo $unsuspender ? esc_html($unsuspender->display_name) : 'System'; ?></small>
                                    <?php else: ?>
                                        <strong style="color:#f44336;">Active</strong>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo esc_html($sus->notes ?: '—'); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Fraud Analysis History -->
        <?php if (!empty($fraudAnalysisHistory)): ?>
            <div class="fraud-analysis-history" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Fraud Analysis History</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Analyzed</th>
                            <th>Score</th>
                            <th>Risk Level</th>
                            <th>Confidence</th>
                            <th>Triggers</th>
                            <th>Expires</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fraudAnalysisHistory as $analysis): 
                            $triggers = json_decode($analysis->triggers, true);
                        ?>
                            <tr>
                                <td><?php echo esc_html($analysis->analyzed_at); ?></td>
                                <td><strong><?php echo $analysis->fraud_score; ?></strong></td>
                                <td>
                                    <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($analysis->risk_level); ?>; color:#fff;">
                                        <?php echo esc_html(ucfirst($analysis->risk_level)); ?>
                                    </span>
                                </td>
                                <td><?php echo round($analysis->confidence * 100); ?>%</td>
                                <td>
                                    <?php 
                                    if (!empty($triggers)) {
                                        echo esc_html(implode(', ', array_slice($triggers, 0, 3)));
                                        if (count($triggers) > 3) echo '...';
                                    } else {
                                        echo '—';
                                    }
                                    ?>
                                </td>
                                <td><?php echo $analysis->expires_at ? esc_html($analysis->expires_at) : 'Never'; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Device Fingerprints -->
        <?php if ($fingerprints): ?>
            <div class="fingerprints-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Device Fingerprints</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Fingerprint</th>
                            <th>Automation Score</th>
                            <th>Risk Level</th>
                            <th>First Seen</th>
                            <th>Last Seen</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fingerprints as $fp): ?>
                            <tr>
                                <td><code><?php echo substr($fp->fingerprint, 0, 16); ?>...</code></td>
                                <td>
                                    <div style="display:flex; align-items:center;">
                                        <div style="width:50px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                            <div style="width:<?php echo $fp->automation_score; ?>%; height:6px; background:#f44336; border-radius:3px;"></div>
                                        </div>
                                        <?php echo $fp->automation_score; ?>%
                                    </div>
                                </td>
                                <td>
                                    <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($fp->risk_level); ?>; color:#fff;">
                                        <?php echo esc_html($fp->risk_level ?: 'unknown'); ?>
                                    </span>
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($fp->first_seen)); ?></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($fp->last_seen)); ?></td>
                                <td>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&fingerprint=' . urlencode($fp->fingerprint)); ?>" class="button button-small">Investigate</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Owned Pages -->
        <?php if ($userPages): ?>
            <div class="pages-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Owned Pages</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Page</th>
                            <th>Score</th>
                            <th>Tier</th>
                            <th>Votes</th>
                            <th>Endorsements</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($userPages as $page): ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html($page->post_title ?: 'Page #' . $page->page_id); ?></strong>
                                    <br><small>ID: <?php echo $page->page_id; ?></small>
                                </td>
                                <td><strong><?php echo number_format($page->total_score, 1); ?></strong></td>
                                <td><span style="padding:3px 8px; border-radius:3px; background:<?php echo bcc_trust_get_tier_color($page->reputation_tier); ?>; color:#fff;"><?php echo esc_html($page->reputation_tier); ?></span></td>
                                <td><?php echo number_format($page->vote_count); ?></td>
                                <td><?php echo number_format($page->endorsement_count); ?></td>
                                <td>
                                    <a href="<?php echo get_permalink($page->page_id); ?>" class="button button-small" target="_blank">View</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Recent Votes -->
        <?php if ($recentVotes): ?>
            <div class="votes-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Recent Votes</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Page</th>
                            <th>Type</th>
                            <th>Weight</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentVotes as $vote): ?>
                            <tr>
                                <td>
                                    <?php if ($vote->page_title): ?>
                                        <a href="<?php echo get_permalink($vote->page_id); ?>" target="_blank">
                                            <?php echo esc_html($vote->page_title); ?>
                                        </a>
                                    <?php else: ?>
                                        Page #<?php echo $vote->page_id; ?>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $vote->vote_type > 0 ? '⬆ Upvote' : '⬇ Downvote'; ?></td>
                                <td><?php echo $vote->weight; ?></td>
                                <td><?php echo esc_html($vote->created_at); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

 <!-- IP Addresses -->
<?php if ($userIPs): ?>
    <div class="ips-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
        <h2>IP Addresses Used</h2>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Activity Count</th>
                    <th>Last Seen</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($userIPs as $ip):
                    $ipAddress = '';
                    if (!empty($ip->ip_address)) {
                        $converted = @inet_ntop($ip->ip_address);
                        $ipAddress = $converted !== false ? $converted : 'Invalid IP';
                    }
                ?>
                    <tr>
                        <td><code><?php echo esc_html($ipAddress); ?></code></td>
                        <td><?php echo $ip->count; ?></td>
                        <td><?php echo esc_html($ip->last_seen); ?></td>
                        <td>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&ip=' . urlencode($ipAddress)); ?>" class="button button-small">Investigate</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>       


        <!-- Recent Activity -->
        <?php if ($recentActivity): ?>
            <div class="activity-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Recent Activity</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Action</th>
                            <th>Target</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentActivity as $act): ?>
                            <tr>
                                <td><?php echo esc_html($act->created_at); ?></td>
                                <td><?php echo esc_html($act->action); ?></td>
                                <td>
                                    <?php if ($act->target_id): ?>
                                        <?php if ($act->target_type === 'page'): ?>
                                            <a href="<?php echo get_permalink($act->target_id); ?>" target="_blank">
                                                <?php echo get_the_title($act->target_id) ?: 'Page #' . $act->target_id; ?>
                                            </a>
                                        <?php else: ?>
                                            <?php echo esc_html($act->target_id); ?>
                                        <?php endif; ?>
                                        (<?php echo esc_html($act->target_type ?: '—'); ?>)
                                    <?php else: ?>
                                        —
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
    <?php
}

/**
 * Render IP moderation view - UPDATED to remove metadata
 */
function bcc_trust_render_ip_moderation($ip) {
    global $wpdb;

    $auditTable = bcc_trust_activity_table();
    $votesTable = bcc_trust_votes_table();
    $fingerprintTable = bcc_trust_fingerprints_table();
    $userInfoTable = bcc_trust_user_info_table();

    // Convert IP to binary for database lookup
    $ipBinary = inet_pton($ip);

    // Get activities from this IP
    $activities = $wpdb->get_results($wpdb->prepare("
        SELECT a.*, u.user_login, u.display_name
        FROM {$auditTable} a
        LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
        WHERE a.ip_address = %s
        ORDER BY a.created_at DESC
        LIMIT 200
    ", $ipBinary));

    // Get unique users from this IP with data from user_info table
    $users = $wpdb->get_results($wpdb->prepare("
        SELECT DISTINCT a.user_id, u.user_login, u.display_name,
               ui.fraud_score, ui.risk_level, ui.is_suspended,
               COUNT(*) as activity_count,
               MAX(a.created_at) as last_seen
        FROM {$auditTable} a
        LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
        LEFT JOIN {$userInfoTable} ui ON a.user_id = ui.user_id
        WHERE a.ip_address = %s AND a.user_id IS NOT NULL
        GROUP BY a.user_id
        ORDER BY last_seen DESC
    ", $ipBinary));

    // Get recent votes from this IP
    $recentVotes = $wpdb->get_results($wpdb->prepare("
        SELECT v.*, p.post_title as page_title, u.display_name as voter_name
        FROM {$votesTable} v
        LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
        LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
        WHERE v.ip_address = %s
        AND v.status = 1
        ORDER BY v.created_at DESC
        LIMIT 50
    ", $ipBinary));

    // Get fingerprints from this IP
    $fingerprints = $wpdb->get_results($wpdb->prepare("
        SELECT DISTINCT fingerprint, COUNT(*) as device_count,
               MAX(automation_score) as max_automation,
               MAX(risk_level) as risk_level,
               MAX(last_seen) as last_seen
        FROM {$fingerprintTable}
        WHERE ip_address = %s
        GROUP BY fingerprint
        ORDER BY last_seen DESC
    ", $ipBinary));
    ?>

    <div class="wrap">
        <h1>IP Investigation: <code><?php echo esc_html($ip); ?></code></h1>
        
        <p><a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation'); ?>" class="button">&larr; Back to list</a></p>

        <!-- IP Information -->
        <div class="ip-info-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>IP Information</h2>
            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                <div>
                    <strong>IP Address:</strong><br>
                    <code><?php echo esc_html($ip); ?></code>
                </div>
                <div>
                    <strong>Total Activities:</strong><br>
                    <span style="font-size:24px; font-weight:bold;"><?php echo count($activities); ?></span>
                </div>
                <div>
                    <strong>Unique Users:</strong><br>
                    <span style="font-size:24px; font-weight:bold;"><?php echo count($users); ?></span>
                </div>
                <div>
                    <strong>Unique Devices:</strong><br>
                    <span style="font-size:24px; font-weight:bold;"><?php echo count($fingerprints); ?></span>
                </div>
            </div>
        </div>

        <!-- Users from this IP -->
        <?php if ($users): ?>
            <div class="users-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Users from this IP</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Activity Count</th>
                            <th>Fraud Score</th>
                            <th>Risk Level</th>
                            <th>Suspended</th>
                            <th>Last Seen</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html($user->display_name ?: $user->user_login); ?></strong>
                                    <br><small>ID: <?php echo $user->user_id; ?></small>
                                </td>
                                <td><?php echo $user->activity_count; ?></td>
                                <td>
                                    <span style="color:<?php echo bcc_trust_get_score_color($user->fraud_score ?: 0); ?>; font-weight:bold;">
                                        <?php echo $user->fraud_score ?: 0; ?>/100
                                    </span>
                                </td>
                                <td>
                                    <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($user->risk_level ?: 'unknown'); ?>; color:#fff;">
                                        <?php echo esc_html(ucfirst($user->risk_level ?: 'Unknown')); ?>
                                    </span>
                                </td>
                                <td><?php echo $user->is_suspended ? '✓' : '✗'; ?></td>
                                <td><?php echo date('Y-m-d H:i', strtotime($user->last_seen)); ?></td>
                                <td>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $user->user_id); ?>" class="button button-small">View</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Devices from this IP -->
        <?php if ($fingerprints): ?>
            <div class="devices-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Devices from this IP</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Fingerprint</th>
                            <th>Device Count</th>
                            <th>Max Automation</th>
                            <th>Risk Level</th>
                            <th>Last Seen</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($fingerprints as $fp): ?>
                            <tr>
                                <td><code><?php echo substr($fp->fingerprint, 0, 16); ?>...</code></td>
                                <td><?php echo $fp->device_count; ?></td>
                                <td><?php echo $fp->max_automation; ?>%</td>
                                <td>
                                    <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($fp->risk_level); ?>; color:#fff;">
                                        <?php echo esc_html($fp->risk_level ?: 'unknown'); ?>
                                    </span>
                                </td>
                                <td><?php echo date('Y-m-d H:i', strtotime($fp->last_seen)); ?></td>
                                <td>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&fingerprint=' . urlencode($fp->fingerprint)); ?>" class="button button-small">Investigate</a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Recent Votes -->
        <?php if ($recentVotes): ?>
            <div class="votes-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
                <h2>Recent Votes from this IP</h2>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Voter</th>
                            <th>Page</th>
                            <th>Type</th>
                            <th>Weight</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($recentVotes as $vote): ?>
                            <tr>
                                <td><?php echo esc_html($vote->created_at); ?></td>
                                <td>
                                    <?php if ($vote->voter_name): ?>
                                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $vote->voter_user_id); ?>">
                                            <?php echo esc_html($vote->voter_name); ?>
                                        </a>
                                    <?php else: ?>
                                        User #<?php echo $vote->voter_user_id; ?>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($vote->page_title): ?>
                                        <a href="<?php echo get_permalink($vote->page_id); ?>" target="_blank">
                                            <?php echo esc_html($vote->page_title); ?>
                                        </a>
                                    <?php else: ?>
                                        Page #<?php echo $vote->page_id; ?>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $vote->vote_type > 0 ? '⬆ Upvote' : '⬇ Downvote'; ?></td>
                                <td><?php echo $vote->weight; ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>

        <!-- Recent Activity -->
        <div class="activities-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>Recent Activity from this IP</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>User</th>
                        <th>Target</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($activities as $act): ?>
                        <tr>
                            <td><?php echo esc_html($act->created_at); ?></td>
                            <td><?php echo esc_html($act->action); ?></td>
                            <td>
                                <?php if ($act->user_id): ?>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $act->user_id); ?>">
                                        <?php echo esc_html($act->display_name ?: $act->user_login ?: 'User #' . $act->user_id); ?>
                                    </a>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($act->target_id): ?>
                                    <?php if ($act->target_type === 'page'): ?>
                                        <a href="<?php echo get_permalink($act->target_id); ?>" target="_blank">
                                            <?php echo get_the_title($act->target_id) ?: 'Page #' . $act->target_id; ?>
                                        </a>
                                    <?php else: ?>
                                        <?php echo esc_html($act->target_id); ?>
                                    <?php endif; ?>
                                    (<?php echo esc_html($act->target_type ?: '—'); ?>)
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php
}

/**
 * Render fingerprint moderation view - UPDATED
 */
function bcc_trust_render_fingerprint_moderation($fingerprint) {
    global $wpdb;

    $fingerprintTable = bcc_trust_fingerprints_table();
    $auditTable = bcc_trust_activity_table();
    $userInfoTable = bcc_trust_user_info_table();

    // Get all records with this fingerprint with user_info data
    $records = $wpdb->get_results($wpdb->prepare("
        SELECT f.*, u.display_name as user_name, ui.fraud_score, ui.risk_level
        FROM {$fingerprintTable} f
        LEFT JOIN {$wpdb->users} u ON f.user_id = u.ID
        LEFT JOIN {$userInfoTable} ui ON f.user_id = ui.user_id
        WHERE f.fingerprint = %s
        ORDER BY f.last_seen DESC
    ", $fingerprint));

    if (empty($records)) {
        echo '<div class="notice notice-error"><p>Fingerprint not found.</p></div>';
        return;
    }

    // Get users associated with this fingerprint
    $userIds = array_unique(array_column($records, 'user_id'));
    $userCount = count($userIds);

    // Get automation data
    $automationScores = array_column($records, 'automation_score');
    $maxAutomation = max($automationScores);
    ?>

    <div class="wrap">
        <h1>Device Fingerprint Investigation</h1>
        
        <p>
            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation'); ?>" class="button">&larr; Back to list</a>
        </p>

        <!-- Fingerprint Information -->
        <div class="fingerprint-info" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>Fingerprint Information</h2>
            <table class="form-table">
                <tr>
                    <th>Fingerprint</th>
                    <td><code><?php echo esc_html($fingerprint); ?></code></td>
                </tr>
                <tr>
                    <th>Associated Users</th>
                    <td><strong><?php echo $userCount; ?></strong> users</td>
                </tr>
                <tr>
                    <th>Total Records</th>
                    <td><?php echo count($records); ?></td>
                </tr>
                <tr>
                    <th>Max Automation Score</th>
                    <td>
                        <div style="display:flex; align-items:center;">
                            <div style="width:100px; height:20px; background:#eee; border-radius:10px; position:relative; overflow:hidden; margin-right:10px;">
                                <div style="position:absolute; top:0; left:0; height:100%; width:<?php echo $maxAutomation; ?>%; background:#f44336;"></div>
                            </div>
                            <?php echo $maxAutomation; ?>%
                        </div>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Users Table -->
        <div class="users-box" style="background:#fff; padding:20px; margin-top:20px; border:1px solid #ccd0d4;">
            <h2>Users on this Device</h2>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>User</th>
                        <th>Fraud Score</th>
                        <th>Risk Level</th>
                        <th>Automation Score</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>IP Address</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($records as $record): ?>
                        <tr>
                            <td>
                                <?php if ($record->user_id): ?>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $record->user_id); ?>">
                                        <?php echo esc_html($record->user_name ?: 'User #' . $record->user_id); ?>
                                    </a>
                                <?php else: ?>
                                    Unknown User
                                <?php endif; ?>
                            </td>
                            <td>
                                <span style="color:<?php echo bcc_trust_get_score_color($record->fraud_score ?: 0); ?>; font-weight:bold;">
                                    <?php echo $record->fraud_score ?: 0; ?>
                                </span>
                            </td>
                            <td>
                                <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($record->risk_level ?: 'unknown'); ?>; color:#fff;">
                                    <?php echo esc_html(ucfirst($record->risk_level ?: 'Unknown')); ?>
                                </span>
                            </td>
                            <td>
                                <div style="display:flex; align-items:center;">
                                    <div style="width:50px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                        <div style="width:<?php echo $record->automation_score; ?>%; height:6px; background:#f44336; border-radius:3px;"></div>
                                    </div>
                                    <?php echo $record->automation_score; ?>%
                                </div>
                            </td>
                            <td><?php echo date('Y-m-d H:i', strtotime($record->first_seen)); ?></td>
                            <td><?php echo date('Y-m-d H:i', strtotime($record->last_seen)); ?></td>
                            <td>
                                <?php if ($record->ip_address): ?>
                                    <?php $ip = inet_ntop($record->ip_address); ?>
                                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&ip=' . urlencode($ip)); ?>">
                                        <?php echo esc_html($ip); ?>
                                    </a>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                            <td>
                                <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $record->user_id); ?>" class="button button-small">View User</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php
}

/**
 * Handle bulk suspend action
 */
add_action('admin_action_bcc_trust_bulk_suspend', 'bcc_trust_handle_bulk_suspend');
function bcc_trust_handle_bulk_suspend() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized');
    }
    
    check_admin_referer('bulk-users');
    
    $user_ids = isset($_GET['users']) ? array_map('intval', $_GET['users']) : [];
    $action = isset($_GET['action2']) ? $_GET['action2'] : $_GET['action'];
    
    if (empty($user_ids)) {
        wp_redirect(add_query_arg('bulk', 'no_users', wp_get_referer()));
        exit;
    }
    
    $processed = 0;
    foreach ($user_ids as $user_id) {
        if ($action === 'suspend') {
            // Handle suspend
            global $wpdb;
            $userInfoTable = bcc_trust_user_info_table();
            $wpdb->update(
                $userInfoTable,
                ['is_suspended' => 1],
                ['user_id' => $user_id],
                ['%d'],
                ['%d']
            );
            $processed++;
        } elseif ($action === 'unsuspend') {
            // Handle unsuspend
            global $wpdb;
            $userInfoTable = bcc_trust_user_info_table();
            $wpdb->update(
                $userInfoTable,
                ['is_suspended' => 0],
                ['user_id' => $user_id],
                ['%d'],
                ['%d']
            );
            $processed++;
        } elseif ($action === 'clear_votes') {
            // Handle clear votes
            // Implementation here
            $processed++;
        } elseif ($action === 'reanalyze') {
            // Handle reanalyze
            // Implementation here
            $processed++;
        }
    }
    
    wp_redirect(add_query_arg('bulk', $processed, wp_get_referer()));
    exit;
}

