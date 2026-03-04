<?php
/**
 * Trust Engine Admin Actions
 *
 * Handles repair and maintenance tools triggered from the admin dashboard.
 *
 * @package BCC_Trust_Engine
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
|--------------------------------------------------------------------------
| REGISTER ADMIN ACTION HANDLERS
|--------------------------------------------------------------------------
*/

add_action('admin_post_bcc_trust_repair_owners', 'bcc_trust_repair_page_owners');
add_action('admin_post_bcc_trust_recalc_scores', 'bcc_trust_recalculate_scores');
add_action('admin_post_bcc_trust_clean_devices', 'bcc_trust_clean_devices');

/*
|--------------------------------------------------------------------------
| SECURITY CHECK
|--------------------------------------------------------------------------
*/

function bcc_trust_admin_security_check() {
    if (!current_user_can('manage_options')) {
        wp_die('Unauthorized access.');
    }
    if (!isset($_REQUEST['_wpnonce']) || !wp_verify_nonce($_REQUEST['_wpnonce'], 'bcc_trust_admin_action')) {
        wp_die('Security check failed.');
    }
}

/**
 * Show repair diagnostics (used in repair tab)
 */
function bcc_trust_show_repair_diagnostics() {
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $postsTable = $wpdb->posts;
    $userInfoTable = bcc_trust_user_info_table();
    $fraudAnalysisTable = bcc_trust_fraud_analysis_table();
    $suspensionsTable = bcc_trust_suspensions_table();
    
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
    
    // Users missing from user_info table
    $missing_users = $wpdb->get_results("
        SELECT u.ID, u.user_login, u.user_email
        FROM {$wpdb->users} u
        LEFT JOIN {$userInfoTable} ui ON u.ID = ui.user_id
        WHERE ui.user_id IS NULL
        LIMIT 10
    ");
    
    // Fraud analysis orphaned
    $orphaned_fraud = $wpdb->get_var("
        SELECT COUNT(*) FROM {$fraudAnalysisTable} fa
        LEFT JOIN {$wpdb->users} u ON fa.user_id = u.ID
        WHERE u.ID IS NULL
    ");
    
    // Suspensions orphaned
    $orphaned_suspensions = $wpdb->get_var("
        SELECT COUNT(*) FROM {$suspensionsTable} s
        LEFT JOIN {$wpdb->users} u ON s.user_id = u.ID
        WHERE u.ID IS NULL
    ");
    
    echo '<div style="background: #fff; padding: 20px; margin: 20px 0; border: 1px solid #ccd0d4;">';
    echo '<h3>🔍 Repair Diagnostics</h3>';
    
    $issues_found = false;
    
    if (!empty($mismatches)) {
        echo '<p style="color: #f44336;">⚠️ ' . count($mismatches) . ' pages have mismatched owners:</p>';
        echo '<ul>';
        foreach ($mismatches as $page) {
            echo '<li>Page #' . $page->page_id . ' "' . esc_html($page->post_title) . '" - Score owner: ' . $page->score_owner . ', Post author: ' . $page->post_author . '</li>';
        }
        echo '</ul>';
        $issues_found = true;
    }
    
    if (!empty($missing)) {
        echo '<p style="color: #ff9800;">⚠️ ' . count($missing) . ' pages missing score entries:</p>';
        echo '<ul>';
        foreach ($missing as $page) {
            echo '<li>Page #' . $page->ID . ' "' . esc_html($page->post_title) . '" (Author: ' . $page->post_author . ')</li>';
        }
        echo '</ul>';
        $issues_found = true;
    }
    
    if (!empty($missing_users)) {
        echo '<p style="color: #ff9800;">⚠️ ' . count($missing_users) . ' users missing from user_info table (showing first 10):</p>';
        echo '<ul>';
        foreach ($missing_users as $user) {
            echo '<li>User #' . $user->ID . ' ' . esc_html($user->user_login) . ' (' . esc_html($user->user_email) . ')</li>';
        }
        echo '</ul>';
        $issues_found = true;
    }
    
    if ($orphaned_fraud) {
        echo '<p style="color: #ff9800;">⚠️ ' . $orphaned_fraud . ' orphaned fraud analysis records found.</p>';
        $issues_found = true;
    }
    
    if ($orphaned_suspensions) {
        echo '<p style="color: #ff9800;">⚠️ ' . $orphaned_suspensions . ' orphaned suspension records found.</p>';
        $issues_found = true;
    }
    
    if (!$issues_found) {
        echo '<p style="color: #4caf50;">✅ All systems are healthy! No issues detected.</p>';
    }
    
    echo '</div>';
}

/*
|--------------------------------------------------------------------------
| REPAIR PAGE OWNERS
|--------------------------------------------------------------------------
*/

function bcc_trust_repair_page_owners() {
    bcc_trust_admin_security_check();
    global $wpdb;

    $scoresTable = bcc_trust_scores_table();
    $pagesTable  = $wpdb->prefix . 'peepso_pages';

    if (!$wpdb->get_var("SHOW TABLES LIKE '{$scoresTable}'")) {
        wp_die('Trust scores table not found.');
    }

    if (!$wpdb->get_var("SHOW TABLES LIKE '{$pagesTable}'")) {
        wp_die('PeepSo pages table not found.');
    }

    $rows = $wpdb->get_results("
        SELECT p.id AS page_id, p.user_id
        FROM {$pagesTable} p
        LEFT JOIN {$scoresTable} s
        ON p.id = s.page_id
    ");

    $fixed = 0;

    foreach ($rows as $row) {
        $updated = $wpdb->update(
            $scoresTable,
            ['owner_user_id' => intval($row->user_id)],
            ['page_id' => intval($row->page_id)],
            ['%d'],
            ['%d']
        );

        if ($updated !== false) {
            $fixed++;
        }
    }

    wp_safe_redirect(
        admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&repaired=' . intval($fixed))
    );
    exit;
}

/**
 * Run Owner Repair (enhanced version)
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
    
    // Get ALL PeepSo pages
    $all_pages = $wpdb->get_results("
        SELECT ID, post_author, post_title, post_status 
        FROM {$wpdb->posts} 
        WHERE post_type = 'peepso-page'
    ");
    
    $results['details'][] = "Found " . count($all_pages) . " total PeepSo pages";
    
    foreach ($all_pages as $page) {
        $page_id = $page->ID;
        $correct_owner = 0;
        $owner_source = '';
        
        // Try PeepSo page members table
        $owner = $wpdb->get_var($wpdb->prepare(
            "SELECT pm_user_id FROM {$wpdb->prefix}peepso_page_members 
             WHERE pm_page_id = %d AND pm_user_status = 'member_owner' LIMIT 1",
            $page_id
        ));
        
        if ($owner && $owner > 0) {
            $correct_owner = $owner;
            $owner_source = 'peepso_page_members';
        }
        
        // Fallback to post author
        if (!$correct_owner && $page->post_author > 0) {
            $correct_owner = $page->post_author;
            $owner_source = 'post_author';
        }
        
        if (!$correct_owner) {
            $results['details'][] = "Page {$page_id} - No owner found";
            continue;
        }
        
        // Check if page exists in scores table
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
        } 
        else if ($existing_score->page_owner_id != $correct_owner) {
            // Update existing score
            $wpdb->update(
                $scoresTable,
                ['page_owner_id' => $correct_owner],
                ['page_id' => $page_id],
                ['%d'],
                ['%d']
            );
            $results['owners_reassigned']++;
        }
        
        $results['pages_fixed']++;
    }
    
    // Clean up orphaned score entries
    $orphaned = $wpdb->query("
        DELETE s FROM {$scoresTable} s
        LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
        WHERE p.ID IS NULL
    ");
    
    if ($orphaned > 0) {
        $results['details'][] = "Removed {$orphaned} orphaned score entries";
    }
    
    set_transient('bcc_trust_repair_results', $results, 60);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}

/*
|--------------------------------------------------------------------------
| RECALCULATE TRUST SCORES
|--------------------------------------------------------------------------
*/

function bcc_trust_recalculate_scores() {
    bcc_trust_admin_security_check();
    global $wpdb;

    $scoresTable  = bcc_trust_scores_table();
    $votesTable   = bcc_trust_votes_table();
    $endorseTable = bcc_trust_endorsements_table();

    if (!$wpdb->get_var("SHOW TABLES LIKE '{$scoresTable}'")) {
        wp_die('Trust scores table missing.');
    }

    $pages = $wpdb->get_results("SELECT page_id FROM {$scoresTable}");

    if (!$pages) {
        wp_safe_redirect(
            admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&recalculated=0')
        );
        exit;
    }

    foreach ($pages as $page) {
        $page_id = intval($page->page_id);

        $votes = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT SUM(vote_value)
                FROM {$votesTable}
                WHERE page_id = %d AND status = 1",
                $page_id
            )
        );

        $endorse = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT SUM(weight)
                FROM {$endorseTable}
                WHERE page_id = %d AND status = 1",
                $page_id
            )
        );

        $votes   = floatval($votes);
        $endorse = floatval($endorse);

        $score = ($votes * 1.0) + ($endorse * 3.0);

        $wpdb->update(
            $scoresTable,
            [
                'total_score' => $score,
                'updated_at'  => current_time('mysql')
            ],
            ['page_id' => $page_id],
            ['%f', '%s'],
            ['%d']
        );
    }

    wp_safe_redirect(
        admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&recalculated=1')
    );
    exit;
}

/**
 * Run Score Recalculation (enhanced)
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
    
    $pages = $wpdb->get_results("SELECT page_id FROM {$scoresTable}");
    
    foreach ($pages as $page) {
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
            $total_score = 50;
            
            if ($vote_stats->vote_count > 0) {
                $net_score = ($vote_stats->positive_score - $vote_stats->negative_score);
                $total_score = 50 + ($net_score * 5);
                $total_score = max(0, min(100, $total_score));
            }
            
            $confidence = min(1, ($vote_stats->vote_count / 100) * 0.8 + 0.2);
            
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

/*
|--------------------------------------------------------------------------
| CLEAN DEVICE FINGERPRINTS
|--------------------------------------------------------------------------
*/

function bcc_trust_clean_devices() {
    bcc_trust_admin_security_check();
    global $wpdb;

    $fingerprintTable = bcc_trust_fingerprints_table();

    if (!$wpdb->get_var("SHOW TABLES LIKE '{$fingerprintTable}'")) {
        wp_die('Device fingerprint table missing.');
    }

    $deleted = $wpdb->query(
        "DELETE FROM {$fingerprintTable}
         WHERE last_seen < DATE_SUB(NOW(), INTERVAL 90 DAY)"
    );

    wp_safe_redirect(
        admin_url('admin.php?page=bcc-trust-dashboard&tab=repair&cleaned=' . intval($deleted))
    );
    exit;
}

/**
 * Run Device Cleanup (enhanced)
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
    
    $cutoff = date('Y-m-d H:i:s', strtotime('-90 days'));
    $results['fingerprints_removed'] = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$fingerprintTable} WHERE last_seen < %s",
            $cutoff
        )
    );
    
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
        'activity' => bcc_trust_activity_table(),
        'fraud_analysis' => bcc_trust_fraud_analysis_table(),
        'suspensions' => bcc_trust_suspensions_table()
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
 * Run Fraud Analysis Cleanup
 */
function bcc_trust_run_fraud_cleanup() {
    global $wpdb;
    
    $results = [
        'action' => 'fraud_cleanup',
        'fraud_analyses_removed' => 0,
        'suspensions_archived' => 0
    ];
    
    $fraudAnalysisTable = bcc_trust_fraud_analysis_table();
    $suspensionsTable = bcc_trust_suspensions_table();
    
    $cutoff = date('Y-m-d H:i:s', strtotime('-90 days'));
    $results['fraud_analyses_removed'] = $wpdb->query(
        $wpdb->prepare(
            "DELETE FROM {$fraudAnalysisTable} WHERE expires_at < %s OR (expires_at IS NULL AND analyzed_at < %s)",
            current_time('mysql'),
            $cutoff
        )
    );
    
    $results['suspensions_archived'] = $wpdb->query(
        $wpdb->prepare(
            "UPDATE {$suspensionsTable} SET notes = CONCAT(notes, ' [ARCHIVED]') 
             WHERE unsuspended_at IS NOT NULL 
             AND unsuspended_at < %s",
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
    
    // Step 2: User Sync
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
    
    // Step 5: Device Cleanup
    ob_start();
    bcc_trust_run_device_cleanup();
    $results['steps']['device_cleanup'] = get_transient('bcc_trust_repair_results');
    delete_transient('bcc_trust_repair_results');
    
    // Step 6: Fraud Cleanup
    ob_start();
    bcc_trust_run_fraud_cleanup();
    $results['steps']['fraud_cleanup'] = get_transient('bcc_trust_repair_results');
    delete_transient('bcc_trust_repair_results');
    
    set_transient('bcc_trust_repair_results', $results, 120);
    wp_redirect(admin_url('admin.php?page=bcc-trust-dashboard&tab=repair'));
    exit;
}