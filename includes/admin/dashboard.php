<?php
if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('bcc_trust_votes_table')) {
    function bcc_trust_votes_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_votes';
    }
}

if (!function_exists('bcc_trust_scores_table')) {
    function bcc_trust_scores_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_page_scores';
    }
}

if (!function_exists('bcc_trust_endorsements_table')) {
    function bcc_trust_endorsements_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_endorsements';
    }
}

if (!function_exists('bcc_trust_activity_table')) {
    function bcc_trust_activity_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_activity';
    }
}

if (!function_exists('bcc_trust_fingerprints_table')) {
    function bcc_trust_fingerprints_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_device_fingerprints';
    }
}

if (!function_exists('bcc_trust_patterns_table')) {
    function bcc_trust_patterns_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_patterns';
    }
}

if (!function_exists('bcc_trust_user_info_table')) {
    function bcc_trust_user_info_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_user_info';
    }
}

if (!function_exists('bcc_trust_flags_table')) {
    function bcc_trust_flags_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_flags';
    }
}

if (!function_exists('bcc_trust_reputation_table')) {
    function bcc_trust_reputation_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_reputation';
    }
}

if (!function_exists('bcc_trust_eligibility_table')) {
    function bcc_trust_eligibility_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_eligibility';
    }
}

if (!function_exists('bcc_trust_verifications_table')) {
    function bcc_trust_verifications_table() {
        global $wpdb;
        return $wpdb->prefix . 'bcc_trust_verifications';
    }
}

if (!function_exists('bcc_trust_get_page_owner')) {
    function bcc_trust_get_page_owner($page_id) {
        global $wpdb;
        
        
        $possible_tables = [
            $wpdb->prefix . 'peepso_page_users',
            $wpdb->prefix . 'peepso_pages_users', 
            $wpdb->prefix . 'peepso_page_members'
        ];
        
        foreach ($possible_tables as $table) {
            if ($wpdb->get_var("SHOW TABLES LIKE '$table'") == $table) {
                $owner = $wpdb->get_var($wpdb->prepare(
                    "SELECT user_id FROM {$table} 
                     WHERE page_id = %d AND (role = 'owner' OR role = 'admin' OR is_owner = 1) 
                     LIMIT 1",
                    $page_id
                ));
                
                if ($owner) {
                    return $owner;
                }
            }
        }
        
        // Fallback to post author
        $post = get_post($page_id);
        return $post ? $post->post_author : 0;
    }
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

if (!function_exists('bcc_trust_add_repair_button')) {
    function bcc_trust_add_repair_button() {
        global $wpdb;
        
        $scoresTable = bcc_trust_scores_table();
        $postsTable = $wpdb->posts;
        
        $mismatches = $wpdb->get_var("
            SELECT COUNT(*) 
            FROM {$scoresTable} s
            LEFT JOIN {$postsTable} p ON s.page_id = p.ID
            WHERE s.page_owner_id != p.post_author OR p.ID IS NULL
        ");
        
        if ($mismatches > 0) {
            ?>
            <div class="notice notice-warning" style="margin: 20px 0 10px;">
                <p>
                    <strong>⚠️ Page-Owner Mismatch Detected:</strong> 
                    <?php echo $mismatches; ?> page(s) have incorrect owner assignments.
                    <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=repair_owners'); ?>" 
                       class="button button-small" 
                       onclick="return confirm('Run page-owner repair? This will fix mismatched page owners.');">
                        🔧 Repair Now
                    </a>
                </p>
            </div>
            <?php
        }
    }
}



if (!function_exists('bcc_trust_sync_user_info')) {
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
            
            // Get pages owned
            $pages_owned = $wpdb->get_results($wpdb->prepare("
                SELECT pm_page_id 
                FROM {$wpdb->prefix}peepso_page_members 
                WHERE pm_user_id = %d 
                AND pm_user_status = 'member_owner'
            ", $user->ID));
            
            $page_ids_owned = wp_list_pluck($pages_owned, 'pm_page_id');
            $pages_owned_count = count($page_ids_owned);
            
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
                'usr_id' => $peepso_user ? $peepso_user->usr_id : null,
                'usr_last_activity' => $peepso_user ? $peepso_user->usr_last_activity : null,
                
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
                'page_ids_owned' => !empty($page_ids_owned) ? json_encode($page_ids_owned) : null,
                
                // Fraud data
                'fraud_triggers' => is_array($fraud_triggers) ? json_encode($fraud_triggers) : null,
                
                'metadata' => json_encode([
                    'roles' => implode(', ', $user->roles)
                ])
            ];
            
            // Check if record exists
            $exists = $wpdb->get_var($wpdb->prepare(
                "SELECT id FROM $table_name WHERE user_id = %d",
                $user->ID
            ));
            
            if ($exists) {
                $wpdb->update($table_name, $data, ['user_id' => $user->ID]);
            } else {
                $wpdb->insert($table_name, $data);
            }
            
            $synced_count++;
        }
        
        return $synced_count;
    }
}


// ======================================================
// ADMIN MENU AND DASHBOARD FUNCTIONS
// ======================================================

add_action('admin_menu', function () {
    add_menu_page(
        'Trust Engine Dashboard',
        'Trust Engine',
        'manage_options',
        'bcc-trust-dashboard',
        'bcc_trust_render_dashboard',
        'dashicons-shield',
        26
    );
});

function bcc_trust_render_dashboard() {
    if (!current_user_can('manage_options')) {
        return;
    }

    global $wpdb;

    // Get current tab
    $current_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'overview';
    ?>
    <div class="wrap bcc-trust-dashboard">
        <h1>Trust Engine Dashboard</h1>
        <nav class="nav-tab-wrapper">
            <a href="?page=bcc-trust-dashboard&tab=overview" class="nav-tab <?php echo $current_tab === 'overview' ? 'nav-tab-active' : ''; ?>">Overview</a>
            <a href="?page=bcc-trust-dashboard&tab=pages" class="nav-tab <?php echo $current_tab === 'pages' ? 'nav-tab-active' : ''; ?>">Top Pages</a>
            <a href="?page=bcc-trust-dashboard&tab=all-pages" class="nav-tab <?php echo $current_tab === 'all-pages' ? 'nav-tab-active' : ''; ?>">All Pages</a>
            <a href="?page=bcc-trust-dashboard&tab=users" class="nav-tab <?php echo $current_tab === 'users' ? 'nav-tab-active' : ''; ?>">User Trust</a>
            <a href="?page=bcc-trust-dashboard&tab=activity" class="nav-tab <?php echo $current_tab === 'activity' ? 'nav-tab-active' : ''; ?>">Activity Log</a>
            <a href="?page=bcc-trust-dashboard&tab=fraud" class="nav-tab <?php echo $current_tab === 'fraud' ? 'nav-tab-active' : ''; ?>">Fraud Detection</a>
            <a href="?page=bcc-trust-dashboard&tab=devices" class="nav-tab <?php echo $current_tab === 'devices' ? 'nav-tab-active' : ''; ?>">Devices</a>
            <a href="?page=bcc-trust-dashboard&tab=rings" class="nav-tab <?php echo $current_tab === 'rings' ? 'nav-tab-active' : ''; ?>">Vote Rings</a>
            <a href="?page=bcc-trust-dashboard&tab=ml" class="nav-tab <?php echo $current_tab === 'ml' ? 'nav-tab-active' : ''; ?>">ML Insights</a>
            <a href="?page=bcc-trust-dashboard&tab=repair" class="nav-tab <?php echo $current_tab === 'repair' ? 'nav-tab-active' : ''; ?>" style="background: #f0f8ff; border-color: #46b450;">🔧 Repair</a>
        </nav>

        <div class="tab-content">
            <?php
            switch ($current_tab) {
                case 'pages':
                    bcc_trust_render_pages_tab();
                    break;
                case 'all-pages':
                    bcc_trust_render_all_pages_tab();
                    break;
                case 'users':
                    bcc_trust_render_users_tab();
                    break;
                case 'activity':
                    bcc_trust_render_activity_tab();
                    break;
                case 'fraud':
                    bcc_trust_render_fraud_tab();
                    break;
                case 'devices':
                    bcc_trust_render_devices_tab();
                    break;
                case 'rings':
                    bcc_trust_render_rings_tab();
                    break;
                case 'ml':
                    bcc_trust_render_ml_tab();
                    break;
                case 'repair':
                    bcc_trust_render_repair_tab();
                    break;
                default:
                    bcc_trust_render_overview_tab();
                    break;
            }
            ?>
        </div>
    </div>
    <?php
}

function bcc_trust_render_overview_tab() {
    global $wpdb;

    bcc_trust_add_repair_button();

    $votesTable   = bcc_trust_votes_table();
    $scoresTable  = bcc_trust_scores_table();
    $endorseTable = bcc_trust_endorsements_table();
    $auditTable   = bcc_trust_activity_table();
    $fingerprintTable = bcc_trust_fingerprints_table();
    $patternsTable = bcc_trust_patterns_table();
    $userInfoTable = bcc_trust_user_info_table();

    // System stats
    $totalVotes = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$votesTable} WHERE status = 1");
    $totalEndorsements = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$endorseTable} WHERE status = 1");
    $totalPages = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$scoresTable}");
    
    // Get user stats from user_info table
    $totalUsers = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$userInfoTable}");
    
    $verifiedUsers = (int) $wpdb->get_var("
        SELECT COUNT(*) FROM {$userInfoTable}
        WHERE is_verified = 1
    ");

    $suspendedUsers = (int) $wpdb->get_var("
        SELECT COUNT(*) FROM {$userInfoTable}
        WHERE is_suspended = 1
    ");

    // Fraud stats from user_info table
    $highFraudUsers = (int) $wpdb->get_var("
        SELECT COUNT(*) FROM {$userInfoTable}
        WHERE fraud_score > 70
    ");

    // Risk level distribution
    $riskDistribution = $wpdb->get_results("
        SELECT risk_level, COUNT(*) as count
        FROM {$userInfoTable}
        GROUP BY risk_level
    ");

    // Fraud stats from fingerprints
    $totalFingerprints = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$fingerprintTable}");
    $uniqueDevices = (int) $wpdb->get_var("SELECT COUNT(DISTINCT fingerprint) FROM {$fingerprintTable}");
    $automatedDetected = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$fingerprintTable} WHERE automation_score > 50");
    $sharedDevices = (int) $wpdb->get_var("
        SELECT COUNT(*) FROM (
            SELECT fingerprint, COUNT(DISTINCT user_id) as user_count
            FROM {$fingerprintTable}
            GROUP BY fingerprint
            HAVING user_count > 1
        ) as shared
    ");

    // Behavioral patterns
    $totalPatterns = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$patternsTable}");
    $suspiciousPatterns = (int) $wpdb->get_var("
        SELECT COUNT(*) FROM {$patternsTable} 
        WHERE pattern_type = 'suspicious_behavior'
    ");

    // Vote stats
    $voteStats = $wpdb->get_row("
        SELECT 
            SUM(CASE WHEN vote_type > 0 THEN 1 ELSE 0 END) as positive_count,
            SUM(CASE WHEN vote_type < 0 THEN 1 ELSE 0 END) as negative_count,
            SUM(CASE WHEN vote_type > 0 THEN weight ELSE 0 END) as positive_weight,
            SUM(CASE WHEN vote_type < 0 THEN weight ELSE 0 END) as negative_weight,
            AVG(weight) as avg_weight
        FROM {$votesTable}
        WHERE status = 1
    ");

    // Recent activity
    $recentActivity = $wpdb->get_results("
        SELECT action, user_id, target_id, target_type, created_at, metadata
        FROM {$auditTable}
        ORDER BY created_at DESC
        LIMIT 10
    ");

    // Get trust graph stats
    $trustGraphStats = [];
    if (class_exists('BCCTrust\\Security\\TrustGraph')) {
        $trustGraph = new \BCCTrust\Security\TrustGraph();
        $trustGraphStats = $trustGraph->getStats();
    }

    // Get average trust rank from user_info
    $avgTrustRank = $wpdb->get_var("SELECT AVG(trust_rank) FROM {$userInfoTable}");
    ?>

    <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0;">
        <!-- Voting Stats -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Voting Activity</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalVotes); ?></div>
            <div class="stat-detail">
                ⬆ <?php echo number_format($voteStats->positive_count ?? 0); ?> 
                (<?php echo number_format($voteStats->positive_weight ?? 0, 1); ?> weight)
                <br>
                ⬇ <?php echo number_format($voteStats->negative_count ?? 0); ?> 
                (<?php echo number_format($voteStats->negative_weight ?? 0, 1); ?> weight)
                <br>
                <small>Avg weight: <?php echo number_format($voteStats->avg_weight ?? 0, 2); ?></small>
            </div>
        </div>

        <!-- Endorsements -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Endorsements</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalEndorsements); ?></div>
        </div>

        <!-- Users -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Users</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalUsers); ?></div>
            <div class="stat-detail">
                ✓ <?php echo number_format($verifiedUsers); ?> verified<br>
                ⚠ <?php echo number_format($suspendedUsers); ?> suspended<br>
                🚫 <?php echo number_format($highFraudUsers); ?> high fraud
            </div>
        </div>

        <!-- Pages -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Pages</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalPages); ?></div>
        </div>

        <!-- Device Fingerprints -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Device Fingerprints</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalFingerprints); ?></div>
            <div class="stat-detail">
                📱 <?php echo number_format($uniqueDevices); ?> unique devices<br>
                🤖 <?php echo number_format($automatedDetected); ?> automated<br>
                🔗 <?php echo number_format($sharedDevices); ?> shared devices
            </div>
        </div>

        <!-- Behavioral Patterns -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Behavioral Analysis</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($totalPatterns); ?></div>
            <div class="stat-detail">
                ⚠ <?php echo number_format($suspiciousPatterns); ?> suspicious<br>
                📊 ML training data
            </div>
        </div>

        <!-- Trust Network -->
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
            <h3>Trust Network</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($trustGraphStats['total_users_tracked'] ?? $totalUsers); ?></div>
            <div class="stat-detail">
                ⭐ Avg trust: <?php echo number_format($avgTrustRank ?: 0, 2); ?><br>
                🔍 <?php echo number_format($trustGraphStats['vote_rings_detected'] ?? 0); ?> vote rings
            </div>
        </div>
    </div>

    <!-- Risk Distribution -->
    <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
        <h3>Risk Level Distribution</h3>
        <div style="display: flex; height: 30px; margin: 15px 0; border-radius: 5px; overflow: hidden;">
            <?php
            $total = array_sum(wp_list_pluck($riskDistribution, 'count'));
            if ($total > 0):
                $colors = [
                    'critical' => '#9c27b0',
                    'high' => '#f44336',
                    'medium' => '#ff9800',
                    'low' => '#2196f3',
                    'minimal' => '#4caf50',
                    'unknown' => '#999'
                ];
                foreach ($riskDistribution as $level):
                    $width = ($level->count / $total) * 100;
                    if ($width > 0):
            ?>
                        <div style="width: <?php echo $width; ?>%; background: <?php echo $colors[$level->risk_level] ?? '#999'; ?>; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: bold;">
                            <?php echo $level->risk_level; ?> (<?php echo $level->count; ?>)
                        </div>
            <?php
                    endif;
                endforeach;
            endif;
            ?>
        </div>
    </div>

    <h2>Recent Activity</h2>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>Action</th>
                <th>User</th>
                <th>Target</th>
                <th>Type</th>
                <th>Time</th>
                <th>Metadata</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($recentActivity as $row): ?>
                <tr>
                    <td>
                        <?php echo esc_html($row->action); ?>
                        <?php if (strpos($row->action, 'fraud') !== false || strpos($row->action, 'suspicious') !== false): ?>
                            <span style="color: #f44336;">⚠️</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->user_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $row->user_id); ?>">
                                User #<?php echo $row->user_id; ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->target_id): ?>
                            <?php if ($row->target_type === 'page'): ?>
                                <a href="<?php echo get_permalink($row->target_id); ?>" target="_blank">
                                    <?php echo get_the_title($row->target_id) ?: 'Page #' . $row->target_id; ?>
                                </a>
                            <?php else: ?>
                                <?php echo esc_html($row->target_id); ?>
                            <?php endif; ?>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($row->target_type ?: '—'); ?></td>
                    <td><?php echo esc_html($row->created_at); ?></td>
                    <td>
                        <?php if ($row->metadata): ?>
                            <pre style="margin:0; font-size:10px; max-height:60px; overflow:auto;"><?php echo esc_html(substr($row->metadata, 0, 100)); ?>...</pre>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * Pages Tab - Top Trusted Pages
 */
function bcc_trust_render_pages_tab() {
    global $wpdb;

    $scoresTable = bcc_trust_scores_table();

    $filter = isset($_GET['tier']) ? sanitize_key($_GET['tier']) : 'all';
    $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';

    $where = "p.post_status = 'publish' OR p.post_status IS NULL";
    $params = [];

    if ($filter !== 'all') {
        $where .= " AND s.reputation_tier = %s";
        $params[] = $filter;
    }

    if ($search) {
        $where .= " AND (p.post_title LIKE %s OR s.page_id LIKE %s)";
        $params[] = '%' . $wpdb->esc_like($search) . '%';
        $params[] = '%' . $wpdb->esc_like($search) . '%';
    }

    $sql = "SELECT s.*, p.post_title, p.post_author, u.display_name as owner_name
            FROM {$scoresTable} s
            LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
            LEFT JOIN {$wpdb->users} u ON s.page_owner_id = u.ID
            WHERE {$where}
            ORDER BY s.total_score DESC
            LIMIT 100";

    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }

    $topPages = $wpdb->get_results($sql);

    // Get tier distribution
    $tierCounts = $wpdb->get_results("
        SELECT reputation_tier, COUNT(*) as count
        FROM {$scoresTable}
        GROUP BY reputation_tier
    ");

    $tierCountsAssoc = [];
    foreach ($tierCounts as $tc) {
        $tierCountsAssoc[$tc->reputation_tier] = $tc->count;
    }
    ?>

    <h2>Page Trust Scores</h2>

    <div class="tablenav top">
        <form method="get" style="display: inline-block;">
            <input type="hidden" name="page" value="bcc-trust-dashboard">
            <input type="hidden" name="tab" value="pages">
            
            <div class="alignleft actions">
                <select name="tier">
                    <option value="all" <?php selected($filter, 'all'); ?>>All Tiers</option>
                    <option value="elite" <?php selected($filter, 'elite'); ?>>Elite (<?php echo $tierCountsAssoc['elite'] ?? 0; ?>)</option>
                    <option value="trusted" <?php selected($filter, 'trusted'); ?>>Trusted (<?php echo $tierCountsAssoc['trusted'] ?? 0; ?>)</option>
                    <option value="neutral" <?php selected($filter, 'neutral'); ?>>Neutral (<?php echo $tierCountsAssoc['neutral'] ?? 0; ?>)</option>
                    <option value="caution" <?php selected($filter, 'caution'); ?>>Caution (<?php echo $tierCountsAssoc['caution'] ?? 0; ?>)</option>
                    <option value="risky" <?php selected($filter, 'risky'); ?>>Risky (<?php echo $tierCountsAssoc['risky'] ?? 0; ?>)</option>
                </select>
                <input type="submit" class="button" value="Filter">
            </div>

            <div class="alignright">
                <input type="search" name="s" value="<?php echo esc_attr($search); ?>" placeholder="Search pages...">
                <input type="submit" class="button" value="Search">
            </div>
        </form>
    </div>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>Page</th>
                <th>Owner</th>
                <th>Score</th>
                <th>Tier</th>
                <th>Votes</th>
                <th>Endorsements</th>
                <th>Confidence</th>
                <th>Last Vote</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($topPages as $page): ?>
                <tr>
                    <td>
                        <strong><?php echo esc_html($page->post_title ?: 'Page #' . $page->page_id); ?></strong>
                        <br><small>ID: <?php echo $page->page_id; ?></small>
                    </td>
                    <td>
                        <?php if ($page->page_owner_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $page->page_owner_id); ?>">
                                <?php echo esc_html($page->owner_name ?: 'User #' . $page->page_owner_id); ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td><strong><?php echo number_format($page->total_score, 1); ?></strong></td>
                    <td>
                        <span class="tier-badge" style="padding:3px 8px; border-radius:3px; background:<?php echo bcc_trust_get_tier_color($page->reputation_tier); ?>; color:#fff; display:inline-block;">
                            <?php echo esc_html($page->reputation_tier); ?>
                        </span>
                    </td>
                    <td><?php echo number_format($page->vote_count); ?></td>
                    <td><?php echo number_format($page->endorsement_count); ?></td>
                    <td>
                        <div style="display:flex; align-items:center;">
                            <div style="width:60px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                <div style="width:<?php echo $page->confidence_score * 100; ?>%; height:6px; background:#2196f3; border-radius:3px;"></div>
                            </div>
                            <?php echo round($page->confidence_score * 100); ?>%
                        </div>
                    </td>
                    <td><?php echo $page->last_vote_at ? date('Y-m-d H:i', strtotime($page->last_vote_at)) : 'Never'; ?></td>
                    <td>
                        <a href="<?php echo get_permalink($page->page_id); ?>" class="button button-small" target="_blank">View</a>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $page->page_owner_id); ?>" class="button button-small">Owner</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * Users Tab - User Trust Scores (UPDATED to use user_info table)
 */
function bcc_trust_render_users_tab() {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();

    $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
    $filter = isset($_GET['filter']) ? sanitize_key($_GET['filter']) : 'all';
    $orderby = isset($_GET['orderby']) ? sanitize_key($_GET['orderby']) : 'fraud_score';
    $order = isset($_GET['order']) ? sanitize_key($_GET['order']) : 'DESC';
    
    // Pagination
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $per_page = 50;
    $offset = ($current_page - 1) * $per_page;

    // Build WHERE clause
    $where = ['1=1'];
    $params = [];

    if ($search) {
        $where[] = "(user_login LIKE %s OR user_email LIKE %s OR display_name LIKE %s)";
        $search_term = '%' . $wpdb->esc_like($search) . '%';
        $params[] = $search_term;
        $params[] = $search_term;
        $params[] = $search_term;
    }

    if ($filter !== 'all') {
        $where[] = "risk_level = %s";
        $params[] = $filter;
    }

    $where_clause = implode(' AND ', $where);

    // Get total count
    $count_sql = "SELECT COUNT(*) FROM {$userInfoTable} WHERE {$where_clause}";
    if (!empty($params)) {
        $count_sql = $wpdb->prepare($count_sql, $params);
    }
    $total_items = $wpdb->get_var($count_sql);

    // Validate orderby
    $valid_orderby = ['fraud_score', 'trust_rank', 'votes_cast', 'endorsements_given', 'pages_owned', 'groups_owned', 'usr_last_activity', 'registered'];
    if (!in_array($orderby, $valid_orderby)) {
        $orderby = 'fraud_score';
    }

    // Get users from user_info table
    $sql = "SELECT * FROM {$userInfoTable} WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";
    $params[] = $per_page;
    $params[] = $offset;
    
    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }

    $users = $wpdb->get_results($sql);
    ?>

    <h2>User Trust Analysis</h2>

    <!-- Sync button -->
    <div style="margin: 10px 0;">
        <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=users&sync=1'); ?>" class="button button-primary">Sync All Users</a>
        <?php if (isset($_GET['synced'])): ?>
            <span style="margin-left: 10px; color: green;">Synced <?php echo intval($_GET['synced']); ?> users!</span>
        <?php endif; ?>
    </div>

    <div class="tablenav top">
        <form method="get" style="display: inline-block;">
            <input type="hidden" name="page" value="bcc-trust-dashboard">
            <input type="hidden" name="tab" value="users">
            
            <div class="alignleft actions">
                <select name="filter">
                    <option value="all" <?php selected($filter, 'all'); ?>>All Users</option>
                    <option value="critical" <?php selected($filter, 'critical'); ?>>Critical Risk</option>
                    <option value="high" <?php selected($filter, 'high'); ?>>High Risk</option>
                    <option value="medium" <?php selected($filter, 'medium'); ?>>Medium Risk</option>
                    <option value="low" <?php selected($filter, 'low'); ?>>Low Risk</option>
                    <option value="minimal" <?php selected($filter, 'minimal'); ?>>Minimal Risk</option>
                </select>
                
                <select name="orderby">
                    <option value="fraud_score" <?php selected($orderby, 'fraud_score'); ?>>Sort by Fraud Score</option>
                    <option value="trust_rank" <?php selected($orderby, 'trust_rank'); ?>>Sort by Trust Rank</option>
                    <option value="votes_cast" <?php selected($orderby, 'votes_cast'); ?>>Sort by Votes</option>
                    <option value="endorsements_given" <?php selected($orderby, 'endorsements_given'); ?>>Sort by Endorsements</option>
                    <option value="pages_owned" <?php selected($orderby, 'pages_owned'); ?>>Sort by Pages Owned</option>
                    <option value="groups_owned" <?php selected($orderby, 'groups_owned'); ?>>Sort by Groups Owned</option>
                    <option value="registered" <?php selected($orderby, 'registered'); ?>>Sort by Registration</option>
                </select>
                
                <select name="order">
                    <option value="DESC" <?php selected($order, 'DESC'); ?>>Descending</option>
                    <option value="ASC" <?php selected($order, 'ASC'); ?>>Ascending</option>
                </select>
                
                <input type="submit" class="button" value="Apply">
            </div>

            <div class="alignright">
                <input type="search" name="s" value="<?php echo esc_attr($search); ?>" placeholder="Search users...">
                <input type="submit" class="button" value="Search">
            </div>
        </form>
    </div>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>User</th>
                <th>Fraud Score</th>
                <th>Risk Level</th>
                <th>Trust Rank</th>
                <th>Activity</th>
                <th>Content</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $user): ?>
                <tr>
                    <td>
                        <strong><?php echo esc_html($user->display_name); ?></strong>
                        <br><small>ID: <?php echo $user->user_id; ?></small>
                        <br><small><?php echo esc_html($user->user_email); ?></small>
                        <?php if ($user->usr_last_activity): ?>
                            <br><small>Last active: <?php echo date('Y-m-d H:i', strtotime($user->usr_last_activity)); ?></small>
                        <?php endif; ?>
                    </td>
                    <td>
                        <div style="display:flex; align-items:center;">
                            <div style="width:60px; height:20px; background:#eee; border-radius:10px; position:relative; overflow:hidden; margin-right:8px;">
                                <div style="position:absolute; top:0; left:0; height:100%; width:<?php echo $user->fraud_score; ?>%; background:<?php echo bcc_trust_get_score_color($user->fraud_score); ?>;"></div>
                            </div>
                            <?php echo $user->fraud_score; ?>
                        </div>
                    </td>
                    <td>
                        <span class="risk-badge" style="padding:3px 8px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($user->risk_level); ?>; color:#fff; display:inline-block;">
                            <?php echo esc_html(ucfirst($user->risk_level)); ?>
                        </span>
                    </td>
                    <td>
                        <div style="display:flex; align-items:center;">
                            <div style="width:60px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                <div style="width:<?php echo $user->trust_rank * 100; ?>%; height:6px; background:#4caf50; border-radius:3px;"></div>
                            </div>
                            <?php echo number_format($user->trust_rank, 2); ?>
                        </div>
                    </td>
                    <td>
                        Votes: <?php echo $user->votes_cast; ?><br>
                        Endorsements: <?php echo $user->endorsements_given; ?>
                    </td>
                    <td>
                        Pages: <?php echo $user->pages_owned; ?><br>
                        Groups: <?php echo $user->groups_owned; ?><br>
                        Posts: <?php echo $user->posts_created; ?>
                    </td>
                    <td>
                        <?php if ($user->is_suspended): ?>
                            <span style="background:#f44336; color:#fff; padding:2px 5px; border-radius:3px;">Suspended</span>
                        <?php endif; ?>
                        <?php if ($user->is_verified): ?>
                            <span style="background:#4caf50; color:#fff; padding:2px 5px; border-radius:3px;">✓ Verified</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $user->user_id); ?>" class="button button-small">Investigate</a>
                    </td>
                </tr>
            <?php endforeach; ?>
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
    <?php endif;

    // Handle sync request
    if (isset($_GET['sync']) && $_GET['sync'] == '1') {
        $synced = bcc_trust_sync_user_info();
        echo '<script>window.location.href = "' . admin_url('admin.php?page=bcc-trust-dashboard&tab=users&synced=' . $synced) . '";</script>';
    }
}

/**
 * Activity Tab - Complete Audit Log
 */
function bcc_trust_render_activity_tab() {
    global $wpdb;

    $auditTable = bcc_trust_activity_table();

    $page = isset($_GET['paged']) ? max(1, (int) $_GET['paged']) : 1;
    $per_page = 50;
    $offset = ($page - 1) * $per_page;

    $action_filter = isset($_GET['action']) ? sanitize_text_field($_GET['action']) : '';
    $user_filter = isset($_GET['user_id']) ? (int) $_GET['user_id'] : 0;

    $where = ['1=1'];
    $params = [];

    if ($action_filter) {
        $where[] = "action LIKE %s";
        $params[] = '%' . $wpdb->esc_like($action_filter) . '%';
    }

    if ($user_filter) {
        $where[] = "user_id = %d";
        $params[] = $user_filter;
    }

    $where_clause = implode(' AND ', $where);

    $total_sql = "SELECT COUNT(*) FROM {$auditTable} WHERE {$where_clause}";
    if (!empty($params)) {
        $total_sql = $wpdb->prepare($total_sql, $params);
    }
    $total = (int) $wpdb->get_var($total_sql);

    $sql = "SELECT a.*, u.user_login, u.display_name
            FROM {$auditTable} a
            LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
            WHERE {$where_clause}
            ORDER BY a.created_at DESC
            LIMIT %d OFFSET %d";
    
    $params[] = $per_page;
    $params[] = $offset;
    
    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }

    $activity = $wpdb->get_results($sql);

    // Get unique actions for filter
    $actions = $wpdb->get_col("SELECT DISTINCT action FROM {$auditTable} ORDER BY action LIMIT 50");
    ?>

    <h2>Complete Audit Log</h2>
    
    <div class="tablenav top">
        <form method="get" style="display: inline-block;">
            <input type="hidden" name="page" value="bcc-trust-dashboard">
            <input type="hidden" name="tab" value="activity">
            
            <div class="alignleft actions">
                <select name="action">
                    <option value="">All Actions</option>
                    <?php foreach ($actions as $action): ?>
                        <option value="<?php echo esc_attr($action); ?>" <?php selected($action_filter, $action); ?>>
                            <?php echo esc_html($action); ?>
                        </option>
                    <?php endforeach; ?>
                </select>
                
                <input type="number" name="user_id" placeholder="User ID" value="<?php echo $user_filter; ?>" style="width:100px;">
                
                <input type="submit" class="button" value="Filter">
                <a href="?page=bcc-trust-dashboard&tab=activity" class="button">Clear</a>
            </div>
        </form>
    </div>

    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>ID</th>
                <th>Time</th>
                <th>Action</th>
                <th>User</th>
                <th>Target</th>
                <th>IP Address</th>
                <th>Metadata</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($activity as $row): ?>
                <tr>
                    <td><?php echo $row->id; ?></td>
                    <td><?php echo esc_html($row->created_at); ?></td>
                    <td>
                        <?php echo esc_html($row->action); ?>
                        <?php if (strpos($row->action, 'fraud') !== false || strpos($row->action, 'suspicious') !== false): ?>
                            <span style="color: #f44336;">⚠️</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->user_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $row->user_id); ?>">
                                <?php echo esc_html($row->display_name ?: $row->user_login ?: 'User #' . $row->user_id); ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->target_id): ?>
                            <?php if ($row->target_type === 'page'): ?>
                                <a href="<?php echo get_permalink($row->target_id); ?>" target="_blank">
                                    <?php echo get_the_title($row->target_id) ?: 'Page #' . $row->target_id; ?>
                                </a>
                            <?php else: ?>
                                <?php echo esc_html($row->target_id); ?>
                            <?php endif; ?>
                            <br><small>(<?php echo esc_html($row->target_type ?: '—'); ?>)</small>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->ip_address): ?>
                            <?php $ip = inet_ntop($row->ip_address); ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&ip=' . urlencode($ip)); ?>">
                                <?php echo esc_html($ip); ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($row->metadata): ?>
                            <?php $metadata = json_decode($row->metadata, true); ?>
                            <pre style="margin:0; font-size:10px; max-height:60px; overflow:auto;"><?php echo esc_html(json_encode($metadata, JSON_PRETTY_PRINT)); ?></pre>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <?php
    $total_pages = ceil($total / $per_page);
    if ($total_pages > 1):
    ?>
        <div class="tablenav">
            <div class="tablenav-pages">
                <?php
                echo paginate_links([
                    'base' => add_query_arg('paged', '%#%'),
                    'format' => '',
                    'prev_text' => '&laquo;',
                    'next_text' => '&raquo;',
                    'total' => $total_pages,
                    'current' => $page
                ]);
                ?>
            </div>
        </div>
    <?php endif;
}

/**
 * Fraud Tab - Fraud Detection Dashboard (UPDATED to use user_info table)
 */
function bcc_trust_render_fraud_tab() {
    global $wpdb;

    $auditTable = bcc_trust_activity_table();
    $votesTable = bcc_trust_votes_table();
    $fingerprintTable = bcc_trust_fingerprints_table();
    $userInfoTable = bcc_trust_user_info_table();

    // Get fraud statistics from user_info table
    $fraudStats = [];
    
    $fraudStats['average_fraud_score'] = (float) $wpdb->get_var("SELECT AVG(fraud_score) FROM {$userInfoTable}");
    $fraudStats['suspended_users'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$userInfoTable} WHERE is_suspended = 1");
    
    // Risk distribution
    $riskDistribution = $wpdb->get_results("
        SELECT risk_level, COUNT(*) as count
        FROM {$userInfoTable}
        GROUP BY risk_level
    ");
    
    $fraudStats['risk_distribution'] = [];
    foreach ($riskDistribution as $rd) {
        $fraudStats['risk_distribution'][$rd->risk_level] = $rd->count;
    }

    // Get high fraud users
    $highFraudUsers = $wpdb->get_results("
        SELECT user_id, display_name, user_email, fraud_score, risk_level, 
               is_suspended, fraud_triggers, votes_cast, pages_owned, groups_owned
        FROM {$userInfoTable}
        WHERE fraud_score > 50
        ORDER BY fraud_score DESC
        LIMIT 50
    ");

    // Format high fraud users for display
    $formattedUsers = [];
    foreach ($highFraudUsers as $user) {
        $triggers = [];
        if ($user->fraud_triggers) {
            $triggersData = json_decode($user->fraud_triggers, true);
            $triggers = is_array($triggersData) ? $triggersData : [];
        }
        
        $formattedUsers[] = [
            'id' => $user->user_id,
            'name' => $user->display_name,
            'email' => $user->user_email,
            'fraud_score' => $user->fraud_score,
            'risk_level' => $user->risk_level,
            'suspended' => $user->is_suspended,
            'confidence' => $user->fraud_score, // Use fraud score as confidence
            'triggers' => $triggers
        ];
    }

    // Get recent fraud alerts
    $recentFraud = $wpdb->get_results("
        SELECT * FROM {$auditTable}
        WHERE action LIKE '%fraud%' OR action LIKE '%suspicious%'
        ORDER BY created_at DESC
        LIMIT 20
    ");
    ?>

    <h2>Fraud Detection Dashboard</h2>

    <!-- Fraud Stats Overview -->
    <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Average Fraud Score</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($fraudStats['average_fraud_score'] ?? 0, 1); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Suspended Users</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($fraudStats['suspended_users'] ?? 0); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>High Risk Users</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($fraudStats['risk_distribution']['high'] ?? 0); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Critical Risk</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($fraudStats['risk_distribution']['critical'] ?? 0); ?></div>
        </div>
    </div>

    <!-- Risk Distribution Chart -->
    <div class="risk-distribution" style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
        <h3>Risk Level Distribution</h3>
        <div style="display: flex; height: 30px; margin: 15px 0; border-radius: 5px; overflow: hidden;">
            <?php
            $total = array_sum($fraudStats['risk_distribution'] ?? []);
            if ($total > 0):
                $colors = [
                    'critical' => '#9c27b0',
                    'high' => '#f44336',
                    'medium' => '#ff9800',
                    'low' => '#2196f3',
                    'minimal' => '#4caf50',
                    'unknown' => '#999'
                ];
                foreach ($fraudStats['risk_distribution'] as $level => $count):
                    $width = ($count / $total) * 100;
                    if ($width > 0):
            ?>
                        <div style="width: <?php echo $width; ?>%; background: <?php echo $colors[$level] ?? '#999'; ?>; display: flex; align-items: center; justify-content: center; color: white; font-size: 12px; font-weight: bold;">
                            <?php echo $level; ?> (<?php echo $count; ?>)
                        </div>
            <?php
                    endif;
                endforeach;
            endif;
            ?>
        </div>
    </div>

    <!-- High Risk Users Table -->
    <h3>High Risk Users (Fraud Score > 50)</h3>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>User</th>
                <th>Fraud Score</th>
                <th>Risk Level</th>
                <th>Confidence</th>
                <th>Triggers</th>
                <th>Suspended</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($formattedUsers as $user): ?>
                <tr>
                    <td>
                        <strong><?php echo esc_html($user['name']); ?></strong>
                        <br><small>ID: <?php echo $user['id']; ?></small>
                        <br><small><?php echo esc_html($user['email']); ?></small>
                    </td>
                    <td>
                        <div style="display:flex; align-items:center;">
                            <div style="width:60px; height:20px; background:#eee; border-radius:10px; position:relative; overflow:hidden; margin-right:8px;">
                                <div style="position:absolute; top:0; left:0; height:100%; width:<?php echo $user['fraud_score']; ?>%; background:<?php echo bcc_trust_get_score_color($user['fraud_score']); ?>;"></div>
                            </div>
                            <?php echo $user['fraud_score']; ?>
                        </div>
                    </td>
                    <td>
                        <span style="padding:3px 8px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($user['risk_level']); ?>; color:#fff;">
                            <?php echo esc_html(ucfirst($user['risk_level'])); ?>
                        </span>
                    </td>
                    <td><?php echo $user['confidence']; ?>%</td>
                    <td>
                        <?php 
                        $triggers = array_slice($user['triggers'], 0, 3);
                        echo esc_html(implode(', ', $triggers));
                        if (count($user['triggers']) > 3) echo '...';
                        ?>
                    </td>
                    <td><?php echo $user['suspended'] ? '✓' : '✗'; ?></td>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $user['id']); ?>" class="button button-small">Investigate</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <!-- Recent Fraud Alerts -->
    <h3 style="margin-top: 30px;">Recent Fraud Alerts</h3>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>Time</th>
                <th>Action</th>
                <th>User</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($recentFraud as $alert): ?>
                <tr>
                    <td><?php echo esc_html($alert->created_at); ?></td>
                    <td><?php echo esc_html($alert->action); ?></td>
                    <td>
                        <?php if ($alert->user_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $alert->user_id); ?>">
                                User #<?php echo $alert->user_id; ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php if ($alert->metadata): ?>
                            <pre style="margin:0; font-size:10px; max-height:60px; overflow:auto;"><?php echo esc_html(substr($alert->metadata, 0, 200)); ?></pre>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * Devices Tab - Device Fingerprint Analysis
 */
function bcc_trust_render_devices_tab() {
    global $wpdb;

    $fingerprintTable = bcc_trust_fingerprints_table();
    $userInfoTable = bcc_trust_user_info_table();

    // Get device statistics
    $stats = [];
    
    $stats['total_records'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$fingerprintTable}");
    $stats['unique_fingerprints'] = (int) $wpdb->get_var("SELECT COUNT(DISTINCT fingerprint) FROM {$fingerprintTable}");
    $stats['automated_detected'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$fingerprintTable} WHERE automation_score > 50");
    
    $sharedDevices = $wpdb->get_var("
        SELECT COUNT(*) FROM (
            SELECT fingerprint, COUNT(DISTINCT user_id) as user_count
            FROM {$fingerprintTable}
            GROUP BY fingerprint
            HAVING user_count > 1
        ) as shared
    ");
    $stats['shared_devices'] = (int) $sharedDevices;
    
    $totalUsers = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$userInfoTable}");
    $stats['sharing_ratio'] = $totalUsers > 0 ? round(($stats['shared_devices'] / $totalUsers) * 100, 1) . '%' : '0%';

    // Get shared devices (multiple users)
    $sharedDevices = $wpdb->get_results("
        SELECT fingerprint, COUNT(DISTINCT user_id) as user_count, 
               GROUP_CONCAT(DISTINCT user_id) as user_ids,
               MAX(automation_score) as max_automation,
               MAX(risk_level) as risk_level,
               MAX(last_seen) as last_seen
        FROM {$fingerprintTable}
        GROUP BY fingerprint
        HAVING user_count > 1
        ORDER BY user_count DESC
        LIMIT 50
    ");

    // Get high automation devices
    $automatedDevices = $wpdb->get_results("
        SELECT f.*, u.display_name as user_name
        FROM {$fingerprintTable} f
        LEFT JOIN {$userInfoTable} u ON f.user_id = u.user_id
        WHERE f.automation_score > 50
        ORDER BY f.automation_score DESC
        LIMIT 50
    ");

    // Get recent fingerprints
    $recentFingerprints = $wpdb->get_results("
        SELECT f.*, u.display_name as user_name
        FROM {$fingerprintTable} f
        LEFT JOIN {$userInfoTable} u ON f.user_id = u.user_id
        ORDER BY f.last_seen DESC
        LIMIT 100
    ");
    ?>

    <h2>Device Fingerprint Analysis</h2>

    <!-- Device Stats Overview -->
    <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0;">
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Total Records</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($stats['total_records'] ?? 0); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Unique Devices</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($stats['unique_fingerprints'] ?? 0); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Automated Detected</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($stats['automated_detected'] ?? 0); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Shared Devices</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($stats['shared_devices'] ?? 0); ?></div>
            <div class="stat-detail"><?php echo $stats['sharing_ratio'] ?? '0%'; ?> of users</div>
        </div>
    </div>

    <!-- Shared Devices -->
    <h3>Devices Shared by Multiple Users</h3>
    <?php if ($sharedDevices): ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>Fingerprint</th>
                    <th>Users</th>
                    <th>User IDs</th>
                    <th>Automation Score</th>
                    <th>Risk Level</th>
                    <th>Last Seen</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($sharedDevices as $device): ?>
                    <tr>
                        <td><code><?php echo substr($device->fingerprint, 0, 16); ?>...</code></td>
                        <td><strong><?php echo $device->user_count; ?></strong> users</td>
                        <td>
                            <?php 
                            $userIds = explode(',', $device->user_ids);
                            foreach ($userIds as $uid):
                            ?>
                                <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $uid); ?>">#<?php echo $uid; ?></a>
                            <?php endforeach; ?>
                        </td>
                        <td><?php echo $device->max_automation; ?></td>
                        <td>
                            <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($device->risk_level); ?>; color:#fff;">
                                <?php echo esc_html($device->risk_level ?: 'unknown'); ?>
                            </span>
                        </td>
                        <td><?php echo date('Y-m-d H:i', strtotime($device->last_seen)); ?></td>
                        <td>
                            <button class="button button-small" onclick="alert('Investigation feature coming soon')">Investigate</button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No shared devices detected.</p>
    <?php endif; ?>

    <!-- Automated/Bot Devices -->
    <h3 style="margin-top: 30px;">Automated/Bot Devices</h3>
    <?php if ($automatedDevices): ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>User</th>
                    <th>Fingerprint</th>
                    <th>Automation Score</th>
                    <th>Signals</th>
                    <th>Risk Level</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($automatedDevices as $device): ?>
                    <tr>
                        <td>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $device->user_id); ?>">
                                <?php echo esc_html($device->user_name ?: 'User #' . $device->user_id); ?>
                            </a>
                        </td>
                        <td><code><?php echo substr($device->fingerprint, 0, 16); ?>...</code></td>
                        <td>
                            <div style="display:flex; align-items:center;">
                                <div style="width:50px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                    <div style="width:<?php echo $device->automation_score; ?>%; height:6px; background:#f44336; border-radius:3px;"></div>
                                </div>
                                <?php echo $device->automation_score; ?>%
                            </div>
                        </td>
                        <td>
                            <?php 
                            if ($device->automation_signals) {
                                $signals = json_decode($device->automation_signals, true);
                                echo esc_html(implode(', ', array_slice($signals, 0, 3)));
                            } else {
                                echo '—';
                            }
                            ?>
                        </td>
                        <td>
                            <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($device->risk_level); ?>; color:#fff;">
                                <?php echo esc_html($device->risk_level ?: 'unknown'); ?>
                            </span>
                        </td>
                        <td><?php echo date('Y-m-d H:i', strtotime($device->first_seen)); ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($device->last_seen)); ?></td>
                        <td>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $device->user_id); ?>" class="button button-small">View User</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No automated devices detected.</p>
    <?php endif; ?>

    <!-- Recent Fingerprints -->
    <h3 style="margin-top: 30px;">Recent Device Fingerprints</h3>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>User</th>
                <th>Fingerprint</th>
                <th>Automation</th>
                <th>Risk Level</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($recentFingerprints as $fp): ?>
                <tr>
                    <td>
                        <?php if ($fp->user_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $fp->user_id); ?>">
                                <?php echo esc_html($fp->user_name ?: 'User #' . $fp->user_id); ?>
                            </a>
                        <?php else: ?>
                            —
                        <?php endif; ?>
                    </td>
                    <td><code><?php echo substr($fp->fingerprint, 0, 16); ?>...</code></td>
                    <td><?php echo $fp->automation_score; ?>%</td>
                    <td>
                        <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($fp->risk_level); ?>; color:#fff;">
                            <?php echo esc_html($fp->risk_level ?: 'unknown'); ?>
                        </span>
                    </td>
                    <td><?php echo date('Y-m-d H:i', strtotime($fp->first_seen)); ?></td>
                    <td><?php echo date('Y-m-d H:i', strtotime($fp->last_seen)); ?></td>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $fp->user_id); ?>" class="button button-small">View</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * Vote Rings Tab - Vote Ring Detection
 */
function bcc_trust_render_rings_tab() {
    global $wpdb;

    $rings = [];
    $trustGraph = null;

    if (class_exists('BCCTrust\\Security\\TrustGraph')) {
        $trustGraph = new \BCCTrust\Security\TrustGraph();
        $rings = $trustGraph->getSuspiciousClusters(3);
    }

    // Get vote statistics for ring analysis
    $votesTable = bcc_trust_votes_table();
    $scoresTable = bcc_trust_scores_table();
    $userInfoTable = bcc_trust_user_info_table();

    $mutualVotes = $wpdb->get_results("
        SELECT 
            v1.voter_user_id as user_a, 
            v2.voter_user_id as user_b,
            COUNT(*) as mutual_count,
            SUM(v1.weight + v2.weight) as total_weight
        FROM {$votesTable} v1
        JOIN {$scoresTable} s1 ON v1.page_id = s1.page_id
        JOIN {$votesTable} v2 ON v2.voter_user_id = s1.page_owner_id
        JOIN {$scoresTable} s2 ON v2.page_id = s2.page_id
        WHERE v1.status = 1 
          AND v2.status = 1
          AND s2.page_owner_id = v1.voter_user_id
          AND v1.voter_user_id != v2.voter_user_id
        GROUP BY v1.voter_user_id, v2.voter_user_id
        HAVING mutual_count >= 3
        ORDER BY mutual_count DESC
        LIMIT 100
    ");
    ?>

    <h2>Vote Ring Detection</h2>

    <?php if (empty($rings)): ?>
        <div class="notice notice-success">
            <p>No vote rings detected. Your community looks healthy!</p>
        </div>
    <?php else: ?>
        <div class="notice notice-warning">
            <p><strong><?php echo count($rings); ?></strong> potential vote rings detected. Review below.</p>
        </div>
    <?php endif; ?>

    <!-- Vote Rings -->
    <?php foreach ($rings as $index => $ring): ?>
        <div class="ring-box" style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4; border-left: 5px solid <?php echo $ring['risk_level'] === 'high' ? '#f44336' : ($ring['risk_level'] === 'medium' ? '#ff9800' : '#2196f3'); ?>;">
            <h3>Ring #<?php echo $index + 1; ?> 
                <small style="font-weight:normal; margin-left:10px;">
                    Size: <?php echo $ring['size']; ?> users | 
                    Strength: <?php echo number_format($ring['strength'], 1); ?> | 
                    Risk Level: <span style="padding:2px 5px; border-radius:3px; background:<?php echo bcc_trust_get_risk_color($ring['risk_level']); ?>; color:#fff;"><?php echo esc_html(ucfirst($ring['risk_level'])); ?></span>
                </small>
            </h3>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Username</th>
                        <th>Fraud Score</th>
                        <th>Trust Rank</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($ring['users'] as $userId): 
                        $userInfo = $wpdb->get_row($wpdb->prepare(
                            "SELECT display_name, fraud_score, trust_rank FROM {$userInfoTable} WHERE user_id = %d",
                            $userId
                        ));
                    ?>
                        <tr>
                            <td><?php echo $userId; ?></td>
                            <td>
                                <?php echo esc_html($userInfo->display_name ?? 'Unknown User'); ?>
                            </td>
                            <td>
                                <span style="color:<?php echo ($userInfo->fraud_score ?? 0) > 70 ? '#f44336' : (($userInfo->fraud_score ?? 0) > 40 ? '#ff9800' : '#4caf50'); ?>;">
                                    <?php echo $userInfo->fraud_score ?? 0; ?>
                                </span>
                            </td>
                            <td><?php echo number_format($userInfo->trust_rank ?? 0, 2); ?></td>
                            <td>
                                <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $userId); ?>" class="button button-small">Investigate</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

            <p style="margin-top:10px;">
                <em>Detected: <?php echo $ring['detected_at']; ?></em>
            </p>
        </div>
    <?php endforeach; ?>

    <!-- Mutual Voting Patterns -->
    <h3 style="margin-top: 30px;">Mutual Voting Patterns</h3>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>User A</th>
                <th>User B</th>
                <th>Mutual Votes</th>
                <th>Total Weight</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($mutualVotes as $mv): ?>
                <tr>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $mv->user_a); ?>">
                            User #<?php echo $mv->user_a; ?>
                        </a>
                    </td>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $mv->user_b); ?>">
                            User #<?php echo $mv->user_b; ?>
                        </a>
                    </td>
                    <td><strong><?php echo $mv->mutual_count; ?></strong></td>
                    <td><?php echo number_format($mv->total_weight, 1); ?></td>
                    <td>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $mv->user_a); ?>" class="button button-small">View A</a>
                        <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $mv->user_b); ?>" class="button button-small">View B</a>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * ML Insights Tab - Machine Learning Data (UPDATED to use user_info table)
 */
function bcc_trust_render_ml_tab() {
    global $wpdb;

    $patternsTable = bcc_trust_patterns_table();
    $userInfoTable = bcc_trust_user_info_table();

    // Get pattern statistics
    $patternStats = $wpdb->get_results("
        SELECT pattern_type, COUNT(*) as count, AVG(confidence) as avg_confidence
        FROM {$patternsTable}
        GROUP BY pattern_type
        ORDER BY count DESC
    ");

    // Get recent patterns
    $recentPatterns = $wpdb->get_results("
        SELECT p.*, u.display_name as user_name
        FROM {$patternsTable} p
        LEFT JOIN {$userInfoTable} u ON p.user_id = u.user_id
        ORDER BY p.detected_at DESC
        LIMIT 100
    ");

    // Get behavior statistics from user_info
    $behaviorStats = [];
    $behaviorStats['average_behavior_score'] = (float) $wpdb->get_var("SELECT AVG(automation_score) FROM {$userInfoTable}");
    $behaviorStats['high_risk_users'] = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$userInfoTable} WHERE risk_level IN ('high', 'critical')");
    
    // Get top behavior flags from patterns table
    $behaviorStats['top_behavior_flags'] = [];
    $topFlags = $wpdb->get_results("
        SELECT pattern_type, COUNT(*) as count
        FROM {$patternsTable}
        GROUP BY pattern_type
        ORDER BY count DESC
        LIMIT 10
    ");
    foreach ($topFlags as $flag) {
        $behaviorStats['top_behavior_flags'][$flag->pattern_type] = $flag->count;
    }
    ?>

    <h2>Machine Learning Insights</h2>

    <!-- Pattern Statistics -->
    <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0;">
        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Total Patterns</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo array_sum(array_column($patternStats, 'count')); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Pattern Types</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo count($patternStats); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>Avg Automation Score</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($behaviorStats['average_behavior_score'] ?? 0, 1); ?></div>
        </div>

        <div class="stat-card" style="background: #fff; padding: 20px; border: 1px solid #ccd0d4;">
            <h3>High/Critical Risk</h3>
            <div class="stat-value" style="font-size: 32px; font-weight: bold;"><?php echo number_format($behaviorStats['high_risk_users'] ?? 0); ?></div>
        </div>
    </div>

    <!-- Pattern Type Distribution -->
    <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
        <h3>Pattern Type Distribution</h3>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>Pattern Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                    <th>Avg Confidence</th>
                </tr>
            </thead>
            <tbody>
                <?php 
                $total = array_sum(array_column($patternStats, 'count'));
                foreach ($patternStats as $stat): 
                ?>
                    <tr>
                        <td><strong><?php echo esc_html($stat->pattern_type); ?></strong></td>
                        <td><?php echo number_format($stat->count); ?></td>
                        <td>
                            <div style="display:flex; align-items:center;">
                                <div style="width:100px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                    <div style="width:<?php echo ($stat->count / $total) * 100; ?>%; height:6px; background:#2196f3; border-radius:3px;"></div>
                                </div>
                                <?php echo round(($stat->count / $total) * 100, 1); ?>%
                            </div>
                        </td>
                        <td><?php echo round($stat->avg_confidence * 100, 1); ?>%</td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Top Behavior Flags -->
    <?php if (!empty($behaviorStats['top_behavior_flags'])): ?>
        <div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">
            <h3>Most Common Behavior Flags</h3>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Flag</th>
                        <th>Count</th>
                        <th>Distribution</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $flagTotal = array_sum($behaviorStats['top_behavior_flags']);
                    foreach ($behaviorStats['top_behavior_flags'] as $flag => $count): 
                    ?>
                        <tr>
                            <td><code><?php echo esc_html($flag); ?></code></td>
                            <td><?php echo number_format($count); ?></td>
                            <td>
                                <div style="display:flex; align-items:center;">
                                    <div style="width:100px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                        <div style="width:<?php echo ($count / $flagTotal) * 100; ?>%; height:6px; background:#ff9800; border-radius:3px;"></div>
                                    </div>
                                    <?php echo round(($count / $flagTotal) * 100, 1); ?>%
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>

    <!-- Recent Patterns -->
    <h3>Recent Detected Patterns</h3>
    <table class="wp-list-table widefat fixed striped">
        <thead>
            <tr>
                <th>User</th>
                <th>Pattern Type</th>
                <th>Confidence</th>
                <th>Data</th>
                <th>Detected</th>
                <th>Expires</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($recentPatterns as $pattern): ?>
                <tr>
                    <td>
                        <?php if ($pattern->user_id): ?>
                            <a href="<?php echo admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $pattern->user_id); ?>">
                                <?php echo esc_html($pattern->user_name ?: 'User #' . $pattern->user_id); ?>
                            </a>
                        <?php else: ?>
                            System
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($pattern->pattern_type); ?></td>
                    <td><?php echo round($pattern->confidence * 100, 1); ?>%</td>
                    <td>
                        <?php 
                        $data = json_decode($pattern->pattern_data, true);
                        if (is_array($data)) {
                            echo '<pre style="margin:0; font-size:10px; max-height:60px; overflow:auto;">' . esc_html(json_encode($data, JSON_PRETTY_PRINT)) . '</pre>';
                        } else {
                            echo '—';
                        }
                        ?>
                    </td>
                    <td><?php echo date('Y-m-d H:i', strtotime($pattern->detected_at)); ?></td>
                    <td><?php echo $pattern->expires_at ? date('Y-m-d H:i', strtotime($pattern->expires_at)) : 'Never'; ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
    <?php
}

/**
 * All Pages Tab - Shows EVERY page with trust scores
 */
function bcc_trust_render_all_pages_tab() {
    global $wpdb;
    
    // Get current page for pagination
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $per_page = 20;
    $offset = ($current_page - 1) * $per_page;
    
    // Get filter/sort parameters
    $search = isset($_GET['s']) ? sanitize_text_field($_GET['s']) : '';
    $tier_filter = isset($_GET['tier']) ? sanitize_key($_GET['tier']) : '';
    $status_filter = isset($_GET['status']) ? sanitize_key($_GET['status']) : '';
    $orderby = isset($_GET['orderby']) ? sanitize_key($_GET['orderby']) : 'total_score';
    $order = isset($_GET['order']) && strtoupper($_GET['order']) === 'ASC' ? 'ASC' : 'DESC';
    
    // Build WHERE clause
    $where = "1=1";
    $params = [];
    
    if ($search) {
        $where .= " AND (p.post_title LIKE %s OR p.ID LIKE %s)";
        $params[] = '%' . $wpdb->esc_like($search) . '%';
        $params[] = '%' . $wpdb->esc_like($search) . '%';
    }
    
    if ($tier_filter) {
        $where .= " AND s.reputation_tier = %s";
        $params[] = $tier_filter;
    }
    
    if ($status_filter === 'with_scores') {
        $where .= " AND s.id IS NOT NULL";
    } elseif ($status_filter === 'without_scores') {
        $where .= " AND s.id IS NULL";
    } elseif ($status_filter === 'published') {
        $where .= " AND p.post_status = 'publish'";
    } elseif ($status_filter === 'draft') {
        $where .= " AND p.post_status = 'draft'";
    } elseif ($status_filter === 'private') {
        $where .= " AND p.post_status = 'private'";
    } elseif ($status_filter === 'trash') {
        $where .= " AND p.post_status = 'trash'";
    }
    
    // Get ALL PeepSo pages with their trust scores (if any)
    $sql = "SELECT 
                p.ID as page_id,
                p.post_title as page_title,
                p.post_author as page_owner_id,
                p.post_status as page_status,
                p.post_date as page_created,
                s.*,
                u.display_name as owner_name,
                u.user_email as owner_email,
                u.user_login as owner_login
            FROM {$wpdb->posts} p
            LEFT JOIN " . bcc_trust_scores_table() . " s ON p.ID = s.page_id
            LEFT JOIN {$wpdb->users} u ON p.post_author = u.ID
            WHERE p.post_type = 'peepso-page'
            AND {$where}
            ORDER BY ";
    
    // Validate orderby to prevent SQL injection
    $valid_orderby = ['total_score', 'vote_count', 'confidence_score', 'page_id', 'post_title', 'post_date'];
    if (in_array($orderby, $valid_orderby)) {
        if ($orderby === 'post_title' || $orderby === 'post_date') {
            $sql .= "p.{$orderby} {$order}";
        } elseif ($orderby === 'page_id') {
            $sql .= "p.ID {$order}";
        } else {
            $sql .= "COALESCE(s.{$orderby}, 0) {$order}";
        }
    } else {
        $sql .= "COALESCE(s.total_score, 0) DESC, p.ID DESC";
    }
    
    // Get total count for pagination
    $count_sql = "SELECT COUNT(*) FROM {$wpdb->posts} p 
                  WHERE p.post_type = 'peepso-page' AND {$where}";
    if (!empty($params)) {
        $count_sql = $wpdb->prepare($count_sql, $params);
    }
    $total_items = $wpdb->get_var($count_sql);
    
    // Add limit for current page
    $sql .= " LIMIT %d OFFSET %d";
    $params[] = $per_page;
    $params[] = $offset;
    
    if (!empty($params)) {
        $sql = $wpdb->prepare($sql, $params);
    }
    
    $pages = $wpdb->get_results($sql);
    
    // Get tier counts for filter dropdown
    $tier_counts = $wpdb->get_results("
        SELECT reputation_tier, COUNT(*) as count 
        FROM " . bcc_trust_scores_table() . " 
        GROUP BY reputation_tier
    ");
    $tier_counts_assoc = [];
    foreach ($tier_counts as $tc) {
        $tier_counts_assoc[$tc->reputation_tier] = $tc->count;
    }
    
    // Get status counts
    $status_counts = $wpdb->get_results("
        SELECT post_status, COUNT(*) as count 
        FROM {$wpdb->posts} 
        WHERE post_type = 'peepso-page'
        GROUP BY post_status
    ");
    $status_counts_assoc = [];
    foreach ($status_counts as $sc) {
        $status_counts_assoc[$sc->post_status] = $sc->count;
    }
    
    $scores_count = $wpdb->get_var("SELECT COUNT(*) FROM " . bcc_trust_scores_table());
   ?>
    
    <div class="wrap">
        <h2>All PeepSo Pages</h2>
        
        <!-- Filter Bar -->
        <div class="tablenav top">
            <form method="get" style="display: inline-block; width: 100%;">
                <input type="hidden" name="page" value="bcc-trust-dashboard">
                <input type="hidden" name="tab" value="all-pages">
                
                <div class="alignleft actions">
                    <select name="tier">
                        <option value="">All Tiers</option>
                        <option value="elite" <?php selected($tier_filter, 'elite'); ?>>Elite (<?php echo $tier_counts_assoc['elite'] ?? 0; ?>)</option>
                        <option value="trusted" <?php selected($tier_filter, 'trusted'); ?>>Trusted (<?php echo $tier_counts_assoc['trusted'] ?? 0; ?>)</option>
                        <option value="neutral" <?php selected($tier_filter, 'neutral'); ?>>Neutral (<?php echo $tier_counts_assoc['neutral'] ?? 0; ?>)</option>
                        <option value="caution" <?php selected($tier_filter, 'caution'); ?>>Caution (<?php echo $tier_counts_assoc['caution'] ?? 0; ?>)</option>
                        <option value="risky" <?php selected($tier_filter, 'risky'); ?>>Risky (<?php echo $tier_counts_assoc['risky'] ?? 0; ?>)</option>
                    </select>
                    
                    <select name="status">
                        <option value="">All Statuses</option>
                        <option value="published" <?php selected($status_filter, 'published'); ?>>Published (<?php echo $status_counts_assoc['publish'] ?? 0; ?>)</option>
                        <option value="private" <?php selected($status_filter, 'private'); ?>>Private (<?php echo $status_counts_assoc['private'] ?? 0; ?>)</option>
                        <option value="draft" <?php selected($status_filter, 'draft'); ?>>Draft (<?php echo $status_counts_assoc['draft'] ?? 0; ?>)</option>
                        <option value="trash" <?php selected($status_filter, 'trash'); ?>>Trash (<?php echo $status_counts_assoc['trash'] ?? 0; ?>)</option>
                        <option value="with_scores" <?php selected($status_filter, 'with_scores'); ?>>With Trust Scores (<?php echo $scores_count; ?>)</option>
                        <option value="without_scores" <?php selected($status_filter, 'without_scores'); ?>>Without Scores (<?php echo $total_items - $scores_count; ?>)</option>
                    </select>
                    
                    <select name="orderby">
                        <option value="total_score" <?php selected($orderby, 'total_score'); ?>>Sort by Trust Score</option>
                        <option value="vote_count" <?php selected($orderby, 'vote_count'); ?>>Sort by Vote Count</option>
                        <option value="confidence_score" <?php selected($orderby, 'confidence_score'); ?>>Sort by Confidence</option>
                        <option value="post_date" <?php selected($orderby, 'post_date'); ?>>Sort by Creation Date</option>
                        <option value="post_title" <?php selected($orderby, 'post_title'); ?>>Sort by Title</option>
                        <option value="page_id" <?php selected($orderby, 'page_id'); ?>>Sort by Page ID</option>
                    </select>
                    
                    <select name="order">
                        <option value="DESC" <?php selected($order, 'DESC'); ?>>Descending</option>
                        <option value="ASC" <?php selected($order, 'ASC'); ?>>Ascending</option>
                    </select>
                    
                    <input type="submit" class="button" value="Apply Filters">
                </div>
                
                <div class="alignright">
                    <input type="search" name="s" value="<?php echo esc_attr($search); ?>" placeholder="Search pages...">
                    <input type="submit" class="button" value="Search">
                </div>
            </form>
        </div>
        
        <!-- Pages Table -->
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Page</th>
                    <th>Owner</th>
                    <th>Status</th>
                    <th>Trust Score</th>
                    <th>Tier</th>
                    <th>Votes</th>
                    <th>Endorsements</th>
                    <th>Confidence</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($pages)): ?>
                    <tr>
                        <td colspan="11" style="text-align:center; padding:20px;">
                            <strong>No pages found matching your criteria.</strong>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($pages as $page): 
                        $has_score = !empty($page->total_score);
                        $tier_info = $has_score ? bcc_trust_get_tier_info($page->reputation_tier) : ['color' => '#999', 'icon' => '❓'];
                        
                        // Determine status color
                        $status_color = '#999';
                        $status_label = $page->page_status;
                        switch ($page->page_status) {
                            case 'publish':
                                $status_color = '#4caf50';
                                $status_label = 'Published';
                                break;
                            case 'private':
                                $status_color = '#ff9800';
                                $status_label = 'Private';
                                break;
                            case 'draft':
                                $status_color = '#f44336';
                                $status_label = 'Draft';
                                break;
                            case 'trash':
                                $status_color = '#9e9e9e';
                                $status_label = 'Trash';
                                break;
                            default:
                                $status_color = '#999';
                                $status_label = ucfirst($page->page_status);
                        }
                        
                        // Handle owner information - post_author = 0 is common for system pages
                        $has_owner = !empty($page->page_owner_id) && $page->page_owner_id > 0;
                        $owner_display = 'System';
                        $owner_link = '#';
                        
                        if ($has_owner) {
                            if (!empty($page->owner_name)) {
                                $owner_display = $page->owner_name;
                            } elseif (!empty($page->owner_login)) {
                                $owner_display = $page->owner_login;
                            } else {
                                // Try to get user directly
                                $user = get_userdata($page->page_owner_id);
                                if ($user) {
                                    $owner_display = $user->display_name ?: $user->user_login;
                                } else {
                                    $owner_display = 'User #' . $page->page_owner_id . ' (deleted)';
                                }
                            }
                            $owner_link = admin_url('admin.php?page=bcc-trust-moderation&user_id=' . $page->page_owner_id);
                        }
                    ?>
                        <tr>
                            <td><strong>#<?php echo $page->page_id; ?></strong></td>
                            <td>
                                <strong><?php echo esc_html($page->page_title ?: 'Untitled'); ?></strong>
                                <?php if (empty($page->page_title)): ?>
                                    <br><small style="color: #999;">(no title)</small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($has_owner): ?>
                                    <a href="<?php echo esc_url($owner_link); ?>" title="User ID: <?php echo $page->page_owner_id; ?>">
                                        <?php echo esc_html($owner_display); ?>
                                    </a>
                                <?php else: ?>
                                    <span style="color: #999;"><?php echo $owner_display; ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span style="background: <?php echo $status_color; ?>; color: #fff; padding: 3px 8px; border-radius: 3px; display: inline-block; font-size: 11px;">
                                    <?php echo esc_html($status_label); ?>
                                </span>
                            </td>
                            <td>
                                <?php if ($has_score): ?>
                                    <strong><?php echo number_format($page->total_score, 1); ?></strong>
                                <?php else: ?>
                                    <em style="color: #999;">No score yet</em>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($has_score): ?>
                                    <span style="padding: 3px 8px; border-radius: 3px; background: <?php echo $tier_info['color']; ?>; color: #fff; display: inline-block; font-size: 11px;">
                                        <?php echo $tier_info['icon']; ?> <?php echo esc_html(ucfirst($page->reputation_tier)); ?>
                                    </span>
                                <?php else: ?>
                                    <span style="color: #999;">—</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo $has_score ? number_format($page->vote_count) : '0'; ?></td>
                            <td><?php echo $has_score ? number_format($page->endorsement_count) : '0'; ?></td>
                            <td>
                                <?php if ($has_score && $page->confidence_score > 0): ?>
                                    <div style="display:flex; align-items:center;">
                                        <div style="width:50px; height:6px; background:#eee; border-radius:3px; margin-right:8px;">
                                            <div style="width:<?php echo $page->confidence_score * 100; ?>%; height:6px; background:#2196f3; border-radius:3px;"></div>
                                        </div>
                                        <?php echo round($page->confidence_score * 100); ?>%
                                    </div>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                            <td><?php echo date('Y-m-d', strtotime($page->page_created)); ?></td>
                            <td>
                                <a href="<?php echo get_permalink($page->page_id); ?>" class="button button-small" target="_blank">View</a>
                                <?php if ($has_owner): ?>
                                    <a href="<?php echo esc_url($owner_link); ?>" class="button button-small">Owner</a>
                                <?php endif; ?>
                                <?php if (!$has_score): ?>
                                    <button class="button button-small" onclick="initializePageScore(<?php echo $page->page_id; ?>)">Init</button>
                                <?php endif; ?>
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
        <?php endif; ?>
    </div>
    
    <script>
    function initializePageScore(pageId) {
        if (confirm('Initialize trust score for this page? This will create a default score of 50.')) {
            jQuery.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'bcc_trust_init_page_score',
                    page_id: pageId,
                    nonce: '<?php echo wp_create_nonce('bcc_trust_admin'); ?>'
                },
                success: function(response) {
                    if (response.success) {
                        alert('Score initialized successfully!');
                        location.reload();
                    } else {
                        alert('Error: ' + response.data);
                    }
                }
            });
        }
    }
    </script>
    <?php
}

/**
 * Repair Tab - Dedicated repair tools
 */
function bcc_trust_render_repair_tab() {
    ?>
    <div class="wrap">
        <h2>🔧 Repair & Sync Tools</h2>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px;">
        
        <?php 
            
function bcc_trust_show_repair_diagnostics() {
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $postsTable = $wpdb->posts;
    
    // Pages with mismatched owners
    $mismatches = $wpdb->get_results("
        SELECT s.page_id, p.post_title, s.page_owner_id as score_owner, p.post_author as post_author
        FROM {$scoresTable} s
        JOIN {$postsTable} p ON s.page_id = p.ID
        WHERE s.page_owner_id != p.post_author
    ");
    
    // Pages missing from scores table
    $missing = $wpdb->get_results("
        SELECT p.ID, p.post_title, p.post_author
        FROM {$postsTable} p
        LEFT JOIN {$scoresTable} s ON p.ID = s.page_id
        WHERE p.post_type = 'peepso-page'
        AND s.page_id IS NULL
    ");
    
    echo '<div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">';
    echo '<h3>🔍 Repair Diagnostics</h3>';
    
    if (empty($mismatches) && empty($missing)) {
        echo '<p style="color: #4caf50;">✅ All pages have correct owner assignments and score entries!</p>';
    } else {
        if (!empty($mismatches)) {
            echo '<p style="color: #f44336;">⚠️ ' . count($mismatches) . ' pages have mismatched owners:</p>';
            echo '<ul>';
            foreach ($mismatches as $page) {
                echo '<li>Page #' . $page->page_id . ' "' . esc_html($page->post_title) . '" - Score owner: ' . $page->score_owner . ', Post author: ' . $page->post_author . '</li>';
            }
            echo '</ul>';
        }
        
        if (!empty($missing)) {
            echo '<p style="color: #ff9800;">⚠️ ' . count($missing) . ' pages missing score entries:</p>';
            echo '<ul>';
            foreach ($missing as $page) {
                echo '<li>Page #' . $page->ID . ' "' . esc_html($page->post_title) . '" (Author: ' . $page->post_author . ')</li>';
            }
            echo '</ul>';
        }
    }
    
    echo '</div>';
}
?>
        
        <!-- Page-Owner Repair Card -->

            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #23282d;">📄 Page-Owner Repair</h3>
                <p>Fix relationships between pages and their owners. This will:</p>
                <ul style="margin-bottom: 20px;">
                    <li>✓ Find correct owners for all pages</li>
                    <li>✓ Update page scores table</li>
                    <li>✓ Fix user page ownership counts</li>
                    <li>✓ Create missing score entries</li>
                </ul>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=repair_owners'); ?>" 
                   class="button button-primary" 
                   onclick="return confirm('Run page-owner repair? This may take a moment.');">
                    🔄 Run Page-Owner Repair
                </a>
            </div>
            
            <!-- User Info Sync Card -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #23282d;">👥 User Info Sync</h3>
                <p>Synchronize all user data with the user_info table:</p>
                <ul style="margin-bottom: 20px;">
                    <li>✓ Update PeepSo user data</li>
                    <li>✓ Refresh page/group counts</li>
                    <li>✓ Update post/comment stats</li>
                    <li>✓ Sync fraud detection data</li>
                </ul>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=users&sync=1'); ?>" 
                   class="button button-primary">
                    👥 Sync All Users
                </a>
            </div>
            
            <!-- Database Check Card -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #23282d;">🗄️ Database Check</h3>
                <p>Verify database integrity and fix common issues:</p>
                <ul style="margin-bottom: 20px;">
                    <li>✓ Check for missing tables</li>
                    <li>✓ Verify table structures</li>
                    <li>✓ Fix orphaned records</li>
                    <li>✓ Optimize tables</li>
                </ul>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=check_db'); ?>" 
                   class="button button-primary" 
                   onclick="return confirm('Run database check?');">
                    🔍 Run Database Check
                </a>
            </div>
            
            <!-- Trust Score Recalculation Card -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #23282d;">📊 Trust Score Recalculation</h3>
                <p>Recalculate all trust scores from scratch:</p>
                <ul style="margin-bottom: 20px;">
                    <li>✓ Recalculate page scores</li>
                    <li>✓ Update user trust ranks</li>
                    <li>✓ Rebuild confidence scores</li>
                    <li>✓ Refresh reputation tiers</li>
                </ul>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=recalc_scores'); ?>" 
                   class="button button-primary" 
                   onclick="return confirm('Recalculate all trust scores? This may take a while.');">
                    📊 Recalculate All Scores
                </a>
            </div>
            
            <!-- Device Fingerprint Cleanup Card -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
                <h3 style="margin-top: 0; color: #23282d;">📱 Device Cleanup</h3>
                <p>Clean up old device fingerprints:</p>
                <ul style="margin-bottom: 20px;">
                    <li>✓ Remove old fingerprints (>90 days)</li>
                    <li>✓ Clean expired patterns</li>
                    <li>✓ Optimize fingerprint table</li>
                </ul>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=clean_devices'); ?>" 
                   class="button button-primary" 
                   onclick="return confirm('Run device cleanup?');">
                    🧹 Run Device Cleanup
                </a>
            </div>
            
            <!-- Full System Repair Card -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px; border-left: 4px solid #46b450;">
                <h3 style="margin-top: 0; color: #23282d;">🔄 Complete System Repair</h3>
                <p>Run all repair tools in sequence:</p>
                <ol style="margin-bottom: 20px;">
                    <li>1. Page-Owner Repair</li>
                    <li>2. User Info Sync</li>
                    <li>3. Database Check</li>
                    <li>4. Score Recalculation</li>
                </ol>
                <a href="<?php echo admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&action=complete_repair'); ?>" 
                   class="button button-primary button-hero" 
                   onclick="return confirm('Run COMPLETE system repair? This may take several minutes.');">
                    🚀 Run Complete Repair
                </a>
            </div>
        </div>
        
        <?php
        // Handle repair actions
        if (isset($_GET['action'])) {
            $action = sanitize_key($_GET['action']);
            
            switch ($action) {
                case 'repair_owners':
                    bcc_trust_run_owner_repair();
                    break;
                case 'check_db':
                    bcc_trust_run_db_check();
                    break;
                case 'recalc_scores':
                    bcc_trust_run_score_recalc();
                    break;
                case 'clean_devices':
                    bcc_trust_run_device_cleanup();
                    break;
                case 'complete_repair':
                    bcc_trust_run_complete_repair();
                    break;
            }
        }
        
        // Display results if any
        $repair_results = get_transient('bcc_trust_repair_results');
        if ($repair_results) {
            echo '<div style="margin-top: 30px; padding: 20px; background: #f0f8ff; border: 1px solid #46b450; border-radius: 5px;">';
            echo '<h3 style="margin-top: 0; color: #46b450;">✅ Repair Results</h3>';
            echo '<pre style="background: #fff; padding: 15px; border-radius: 4px; overflow: auto;">';
            print_r($repair_results);
            echo '</pre>';
            echo '</div>';
            delete_transient('bcc_trust_repair_results');
        }
        ?>
    </div>
    <?php
}
/**
 * Run Owner Repair - FIXED VERSION
 */
function bcc_trust_run_owner_repair() {
    global $wpdb;
    
    $results = [
        'action' => 'owner_repair',
        'pages_fixed' => 0,
        'owners_reassigned' => 0,
        'missing_created' => 0,
        'users_updated' => 0,
        'details' => []
    ];
    
    $scoresTable = bcc_trust_scores_table();
    $userInfoTable = bcc_trust_user_info_table();
    
    // ======================================================
    // STEP 1: Get ALL PeepSo pages (not just those in scores table)
    // ======================================================
    $all_pages = $wpdb->get_results("
        SELECT ID, post_author, post_title, post_status 
        FROM {$wpdb->posts} 
        WHERE post_type = 'peepso-page'
    ");
    
    $results['details'][] = "Found " . count($all_pages) . " total PeepSo pages";
    
    // ======================================================
    // STEP 2: Process each page to find correct owner
    // ======================================================
    foreach ($all_pages as $page) {
        $page_id = $page->ID;
        $correct_owner = 0;
        $owner_source = '';
        
        // Method 1: Try PeepSo page members table (most accurate)
        $owner = $wpdb->get_var($wpdb->prepare(
            "SELECT pm_user_id FROM {$wpdb->prefix}peepso_page_members 
             WHERE pm_page_id = %d AND pm_user_status = 'member_owner' LIMIT 1",
            $page_id
        ));
        
        if ($owner && $owner > 0) {
            $correct_owner = $owner;
            $owner_source = 'peepso_page_members';
        }
        
        // Method 2: Try alternative PeepSo page users table
        if (!$correct_owner) {
            $owner = $wpdb->get_var($wpdb->prepare(
                "SELECT user_id FROM {$wpdb->prefix}peepso_page_users 
                 WHERE page_id = %d AND (role = 'owner' OR role = 'admin') LIMIT 1",
                $page_id
            ));
            
            if ($owner && $owner > 0) {
                $correct_owner = $owner;
                $owner_source = 'peepso_page_users';
            }
        }
        
        // Method 3: Fallback to post author
        if (!$correct_owner && $page->post_author > 0) {
            $correct_owner = $page->post_author;
            $owner_source = 'post_author';
        }
        
        if (!$correct_owner) {
            $results['details'][] = "Page {$page_id} ('{$page->post_title}') - No owner found";
            continue;
        }
        
        // ======================================================
        // STEP 3: Check if page exists in scores table
        // ======================================================
        $existing_score = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$scoresTable} WHERE page_id = %d",
            $page_id
        ));
        
        if (!$existing_score) {
            // Create new score entry
            $wpdb->insert(
                $scoresTable,
                [
                    'page_id' => $page_id,
                    'page_owner_id' => $correct_owner,
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
            $results['missing_created']++;
            $results['details'][] = "Page {$page_id} - Created new score entry with owner {$correct_owner} (from {$owner_source})";
        } 
        else if ($existing_score->page_owner_id != $correct_owner) {
            // Update existing score with correct owner
            $wpdb->update(
                $scoresTable,
                ['page_owner_id' => $correct_owner],
                ['page_id' => $page_id],
                ['%d'],
                ['%d']
            );
            $results['owners_reassigned']++;
            $results['details'][] = "Page {$page_id} - Updated owner from {$existing_score->page_owner_id} to {$correct_owner} (from {$owner_source})";
        }
        
        $results['pages_fixed']++;
    }
    
    // ======================================================
    // STEP 4: Update user info table with page counts
    // ======================================================
    $all_owners = $wpdb->get_results("
        SELECT DISTINCT page_owner_id 
        FROM {$scoresTable} 
        WHERE page_owner_id > 0
    ");
    
    foreach ($all_owners as $owner) {
        $user_id = $owner->page_owner_id;
        
        // Get all pages owned by this user
        $user_pages = $wpdb->get_results($wpdb->prepare(
            "SELECT page_id FROM {$scoresTable} WHERE page_owner_id = %d",
            $user_id
        ));
        
        $page_ids = wp_list_pluck($user_pages, 'page_id');
        $page_count = count($page_ids);
        
        // Check if user exists in user_info table
        $user_exists = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$userInfoTable} WHERE user_id = %d",
            $user_id
        ));
        
        if ($user_exists) {
            $wpdb->update(
                $userInfoTable,
                [
                    'pages_owned' => $page_count,
                    'page_ids_owned' => !empty($page_ids) ? json_encode($page_ids) : null
                ],
                ['user_id' => $user_id],
                ['%d', '%s'],
                ['%d']
            );
        } else {
            // Get user data
            $user = get_userdata($user_id);
            if ($user) {
                $wpdb->insert(
                    $userInfoTable,
                    [
                        'user_id' => $user_id,
                        'user_login' => $user->user_login,
                        'user_email' => $user->user_email,
                        'display_name' => $user->display_name ?: $user->user_login,
                        'registered' => $user->user_registered,
                        'pages_owned' => $page_count,
                        'page_ids_owned' => !empty($page_ids) ? json_encode($page_ids) : null
                    ],
                    ['%d', '%s', '%s', '%s', '%s', '%d', '%s']
                );
            }
        }
        
        $results['users_updated']++;
    }
    
    // ======================================================
    // STEP 5: Clean up orphaned score entries (pages that no longer exist)
    // ======================================================
    $orphaned = $wpdb->query("
        DELETE s FROM {$scoresTable} s
        LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
        WHERE p.ID IS NULL
    ");
    
    if ($orphaned > 0) {
        $results['details'][] = "Removed {$orphaned} orphaned score entries for deleted pages";
    }
    
    // Store results
    set_transient('bcc_trust_repair_results', $results, 60);
    
    // Redirect back to repair tab
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}
/**
 * Run Database Check
 */
function bcc_trust_run_db_check() {
    global $wpdb;
    
    $results = [
        'action' => 'db_check',
        'tables_checked' => [],
        'issues_found' => [],
        'issues_fixed' => 0
    ];
    
    $tables = [
        'votes' => bcc_trust_votes_table(),
        'scores' => bcc_trust_scores_table(),
        'endorsements' => bcc_trust_endorsements_table(),
        'user_info' => bcc_trust_user_info_table(),
        'fingerprints' => bcc_trust_fingerprints_table(),
        'patterns' => bcc_trust_patterns_table(),
        'activity' => bcc_trust_activity_table()
    ];
    
    foreach ($tables as $name => $table) {
        $exists = $wpdb->get_var("SHOW TABLES LIKE '$table'") == $table;
        $results['tables_checked'][$name] = $exists ? 'OK' : 'MISSING';
        
        if (!$exists) {
            $results['issues_found'][] = "Table {$name} is missing";
        } else {
            // Check for orphaned records
            if ($name == 'scores') {
                $orphaned = $wpdb->get_var("
                    SELECT COUNT(*) FROM {$table} s
                    LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                    WHERE p.ID IS NULL
                ");
                if ($orphaned > 0) {
                    $results['issues_found'][] = "Found {$orphaned} orphaned score records";
                    // Fix orphaned records
                    $wpdb->query("
                        DELETE s FROM {$table} s
                        LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                        WHERE p.ID IS NULL
                    ");
                    $results['issues_fixed'] += $orphaned;
                }
            }
            
            if ($name == 'user_info') {
                $orphaned = $wpdb->get_var("
                    SELECT COUNT(*) FROM {$table} u
                    LEFT JOIN {$wpdb->users} w ON u.user_id = w.ID
                    WHERE w.ID IS NULL
                ");
                if ($orphaned > 0) {
                    $results['issues_found'][] = "Found {$orphaned} orphaned user records";
                    $wpdb->query("
                        DELETE u FROM {$table} u
                        LEFT JOIN {$wpdb->users} w ON u.user_id = w.ID
                        WHERE w.ID IS NULL
                    ");
                    $results['issues_fixed'] += $orphaned;
                }
            }
        }
    }
    
    set_transient('bcc_trust_repair_results', $results, 60);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}

/**
 * Run Score Recalculation
 */
function bcc_trust_run_score_recalc() {
    global $wpdb;
    
    $results = [
        'action' => 'score_recalc',
        'pages_recalculated' => 0,
        'users_updated' => 0
    ];
    
    $scoresTable = bcc_trust_scores_table();
    $votesTable = bcc_trust_votes_table();
    
    // Recalculate each page score
    $pages = $wpdb->get_results("SELECT page_id FROM {$scoresTable}");
    
    foreach ($pages as $page) {
        // Get vote stats
        $vote_stats = $wpdb->get_row($wpdb->prepare("
            SELECT 
                COUNT(*) as vote_count,
                SUM(CASE WHEN vote_type > 0 THEN weight ELSE 0 END) as positive_score,
                SUM(CASE WHEN vote_type < 0 THEN weight ELSE 0 END) as negative_score,
                COUNT(DISTINCT voter_user_id) as unique_voters
            FROM {$votesTable}
            WHERE page_id = %d AND status = 1
        ", $page->page_id));
        
        if ($vote_stats) {
            $total_score = 50; // Base score
            
            if ($vote_stats->vote_count > 0) {
                $net_score = ($vote_stats->positive_score - $vote_stats->negative_score);
                $total_score = 50 + ($net_score * 5);
                $total_score = max(0, min(100, $total_score));
            }
            
            $confidence = min(1, ($vote_stats->vote_count / 100) * 0.8 + 0.2);
            
            // Determine tier
            $tier = 'neutral';
            if ($total_score >= 80) $tier = 'elite';
            elseif ($total_score >= 60) $tier = 'trusted';
            elseif ($total_score >= 40) $tier = 'neutral';
            elseif ($total_score >= 20) $tier = 'caution';
            else $tier = 'risky';
            
            $wpdb->update(
                $scoresTable,
                [
                    'total_score' => $total_score,
                    'positive_score' => $vote_stats->positive_score,
                    'negative_score' => $vote_stats->negative_score,
                    'vote_count' => $vote_stats->vote_count,
                    'unique_voters' => $vote_stats->unique_voters,
                    'confidence_score' => $confidence,
                    'reputation_tier' => $tier,
                    'last_calculated_at' => current_time('mysql')
                ],
                ['page_id' => $page->page_id],
                ['%f', '%f', '%f', '%d', '%d', '%f', '%s', '%s'],
                ['%d']
            );
            
            $results['pages_recalculated']++;
        }
    }
    
    set_transient('bcc_trust_repair_results', $results, 60);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}

/**
 * Run Device Cleanup
 */
function bcc_trust_run_device_cleanup() {
    global $wpdb;
    
    $results = [
        'action' => 'device_cleanup',
        'fingerprints_removed' => 0,
        'patterns_removed' => 0
    ];
    
    $fingerprintTable = bcc_trust_fingerprints_table();
    $patternsTable = bcc_trust_patterns_table();
    
    // Remove old fingerprints
    $cutoff = date('Y-m-d H:i:s', strtotime('-90 days'));
    $results['fingerprints_removed'] = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$fingerprintTable} WHERE last_seen < %s",
            $cutoff
        )
    );
    
    // Remove expired patterns
    $results['patterns_removed'] = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$patternsTable} WHERE expires_at < %s OR (expires_at IS NULL AND detected_at < %s)",
            current_time('mysql'),
            date('Y-m-d H:i:s', strtotime('-30 days'))
        )
    );
    
    set_transient('bcc_trust_repair_results', $results, 60);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}

/**
 * Run Complete Repair
 */
function bcc_trust_run_complete_repair() {
    $results = [
        'action' => 'complete_repair',
        'steps' => []
    ];
    
    // Step 1: Owner Repair
    ob_start();
    bcc_trust_run_owner_repair();
    $results['steps']['owner_repair'] = get_transient('bcc_trust_repair_results');
    delete_transient('bcc_trust_repair_results');
    
    // Step 2: User Sync (via direct function call)
    global $wpdb;
    $sync_count = bcc_trust_sync_user_info();
    $results['steps']['user_sync'] = ['users_synced' => $sync_count];
    
    // Step 3: Database Check
    ob_start();
    bcc_trust_run_db_check();
    $results['steps']['db_check'] = get_transient('bcc_trust_repair_results');
    delete_transient('bcc_trust_repair_results');
    
    // Step 4: Score Recalculation
    ob_start();
    bcc_trust_run_score_recalc();
    $results['steps']['score_recalc'] = get_transient('bcc_trust_repair_results');
    delete_transient('bcc_trust_repair_results');
    
    set_transient('bcc_trust_repair_results', $results, 120);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}