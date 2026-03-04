<?php
/**
 * Advanced Trust Widget Template
 * 
 * This file should be included via bcc_trust_render_widget() function,
 * not loaded directly.
 * 
 * @package BCC_Trust_Engine
 * @subpackage Frontend
 * @version 2.0.0
 */

// Prevent direct access - MUST BE FIRST
if (!defined('ABSPATH')) {
    exit;
}

// CRITICAL: This file must ONLY be included by bcc_trust_render_widget()
// Check if we're being included correctly
$bcc_valid_call = false;
$bcc_debug_backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5);

foreach ($bcc_debug_backtrace as $trace) {
    if (isset($trace['function']) && $trace['function'] === 'bcc_trust_render_widget') {
        $bcc_valid_call = true;
        break;
    }
}

// If not called from bcc_trust_render_widget(), show error and return
if (!$bcc_valid_call) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('BCC Trust Error: trust-widget.php accessed directly or from invalid function');
    }
    
    // In admin, show helpful message
    if (is_admin()) {
        echo '<div class="notice notice-error"><p><strong>BCC Trust Engine:</strong> Widget template loaded incorrectly. This file should only be included via bcc_trust_render_widget().</p></div>';
    }
    return;
}

// Now safely process the widget
$page_id = isset($args['page_id']) ? intval($args['page_id']) : 0;
if (!$page_id) {
    echo '<div class="bcc-trust-error">Invalid page ID</div>';
    return;
}

// Set default args
$default_args = [
    'show_detailed' => true,
    'show_actions' => true,
    'show_fraud_alerts' => true,
    'show_github' => true
];

// Merge with provided args
$args = wp_parse_args($args, $default_args);

$viewer_id = get_current_user_id();

// Check if required classes exist
if (!class_exists('\\BCCTrust\\Repositories\\ScoreRepository') || 
    !class_exists('\\BCCTrust\\Services\\VoteService') ||
    !class_exists('\\BCCTrust\\Repositories\\UserInfoRepository')) {
    echo '<div class="bcc-trust-error">Trust system not available</div>';
    return;
}

/* ======================================================
 PAGE OWNER CHECK - This determines what to show
====================================================== */
$page_owner_id = 0;
if (function_exists('bcc_trust_get_page_owner')) {
    $page_owner_id = (int) bcc_trust_get_page_owner($page_id);
}
$is_owner = ($viewer_id && $viewer_id == $page_owner_id);
$is_visitor = ($viewer_id && !$is_owner);
$is_logged_out = !$viewer_id;

/* ======================================================
 TRUST SCORE DATA using PageScore value object
====================================================== */
try {
    $scoreRepo = new \BCCTrust\Repositories\ScoreRepository();
    $score = $scoreRepo->getByPageId($page_id);
} catch (Exception $e) {
    error_log('BCC Trust: Error getting score - ' . $e->getMessage());
    $score = null;
}

// Use getter methods from PageScore value object
$total_score = $score ? $score->getTotalScore() : 50;
$positive_score = $score ? $score->getPositiveScore() : 0;
$negative_score = $score ? $score->getNegativeScore() : 0;
$vote_count = $score ? $score->getVoteCount() : 0;
$confidence = $score ? $score->getConfidenceScore() : 0;
$tier = $score ? $score->getReputationTier() : 'neutral';
$endorsement_count = $score ? $score->getEndorsementCount() : 0;
$has_fraud_alerts = $score ? $score->hasFraudAlerts() : false;
$fraud_alert_count = $score ? $score->getFraudAlertCount() : 0;

$confidence_percent = intval($confidence * 100);

if ($confidence_percent >= 80) {
    $confidence_label = "Very high reliability";
} elseif ($confidence_percent >= 50) {
    $confidence_label = "Moderate reliability";
} else {
    $confidence_label = "Limited voting data";
}

/* ======================================================
 USER DATA from user_info table
====================================================== */
$user_fraud_score = 0;
$user_risk_level = 'unknown';
if ($viewer_id) {
    try {
        $userInfoRepo = new \BCCTrust\Repositories\UserInfoRepository();
        $userInfo = $userInfoRepo->getByUserId($viewer_id);
        if ($userInfo) {
            $user_fraud_score = $userInfo->fraud_score;
            $user_risk_level = $userInfo->risk_level;
        }
    } catch (Exception $e) {
        error_log('BCC Trust: Error getting user info - ' . $e->getMessage());
    }
}

/* ======================================================
 GITHUB CONNECTION STATUS - Get ALL GitHub data
====================================================== */
$github_username = null;
$github_connected = false;
$github_verified_at = null;
$github_id = null;
$github_followers = 0;
$github_public_repos = 0;
$github_org_count = 0;
$github_trust_boost = 0;
$github_fraud_reduction = 0;
$total_github_boost = 0;

if ($viewer_id) {
    try {
        global $wpdb;
        $userInfoTable = bcc_trust_user_info_table();
        
        $githubInfo = $wpdb->get_row($wpdb->prepare(
            "SELECT 
                github_id,
                github_username,
                github_followers,
                github_public_repos,
                github_org_count,
                github_verified_at,
                github_trust_boost,
                github_fraud_reduction
            FROM {$userInfoTable}
            WHERE user_id = %d",
            $viewer_id
        ));
        
        if ($githubInfo && $githubInfo->github_username) {
            $github_username = $githubInfo->github_username;
            $github_verified_at = $githubInfo->github_verified_at;
            $github_connected = true;
            $github_id = $githubInfo->github_id;
            $github_followers = (int)$githubInfo->github_followers;
            $github_public_repos = (int)$githubInfo->github_public_repos;
            $github_org_count = (int)$githubInfo->github_org_count;
            $github_trust_boost = (float)$githubInfo->github_trust_boost;
            $github_fraud_reduction = (int)$githubInfo->github_fraud_reduction;
            $total_github_boost = $github_trust_boost + $github_fraud_reduction;
        }
    } catch (Exception $e) {
        error_log('BCC Trust: Error getting GitHub data - ' . $e->getMessage());
    }
}

/* ======================================================
 VOTE STATUS
====================================================== */
$my_vote_type = 0;
try {
    $voteService = new \BCCTrust\Services\VoteService();
    $my_vote = $voteService->getUserPageVote($page_id, $viewer_id);
    $my_vote_type = $my_vote ? intval($my_vote->vote_type) : 0;
} catch (Exception $e) {
    error_log('BCC Trust: Error getting user vote - ' . $e->getMessage());
}

/* ======================================================
 ENDORSEMENT STATUS
====================================================== */
$has_endorsed = false;
if ($viewer_id) {
    try {
        $endorseService = new \BCCTrust\Services\EndorsementService();
        $has_endorsed = $endorseService->hasEndorsedPage($page_id, $viewer_id);
    } catch (Exception $e) {
        error_log('BCC Trust: Error getting endorsement - ' . $e->getMessage());
    }
}

// Determine if user can vote (not high-risk)
$can_vote = $is_visitor && $user_fraud_score < 70;
?>

<div class="bcc-trust-wrapper" 
     data-page-id="<?php echo esc_attr($page_id); ?>"
     data-target="<?php echo esc_attr($page_id); ?>"
     data-nonce="<?php echo wp_create_nonce('wp_rest'); ?>">

    <!-- ================= TRUST SCORE - SHOWN TO EVERYONE ================= -->
    <div class="bcc-trust-header">
        <strong>Trust Score:</strong>
        <span class="bcc-score-value"><?php echo number_format($total_score, 1); ?></span>
        <span class="bcc-tier-label">(<?php echo esc_html(ucfirst($tier)); ?>)</span>
        
        <?php if ($args['show_fraud_alerts'] && $has_fraud_alerts): ?>
            <span class="bcc-fraud-alert" title="Suspicious activity detected">
                ⚠️ <?php echo $fraud_alert_count; ?>
            </span>
        <?php endif; ?>
    </div>

    <!-- ================= DETAILS - SHOWN TO EVERYONE ================= -->
    <div class="bcc-trust-details">
        <span class="bcc-confidence-level" title="<?php echo esc_attr($confidence_label); ?>">
            <?php echo $confidence_percent; ?>% confidence
        </span>
        <span class="bcc-vote-total">
            <?php echo intval($vote_count); ?> votes
        </span>
        <span class="bcc-endorsement-total">
            <?php echo intval($endorsement_count); ?> endorsements
        </span>
    </div>

    <?php if ($args['show_detailed']): ?>
        <!-- ================= DETAILED SCORES - SHOWN TO EVERYONE ================= -->
        <div class="bcc-detailed-scores">
            <div class="bcc-positive-score">
                <span>👍 Positive:</span>
                <span class="value"><?php echo number_format($positive_score, 1); ?></span>
            </div>
            <div class="bcc-negative-score">
                <span>👎 Negative:</span>
                <span class="value"><?php echo number_format($negative_score, 1); ?></span>
            </div>
        </div>
    <?php endif; ?>

    <!-- ================= ACTIONS SECTION - DIFFERENT FOR OWNERS VS VISITORS ================= -->
    <?php if ($args['show_actions']): ?>
        
        <?php if ($is_owner): ?>
            <!-- ================= PAGE OWNER VIEW - Only stats, no voting ================= -->
            <div class="bcc-owner-view">
                <p class="bcc-owner-title">
                    <span class="dashicons dashicons-admin-users"></span> 
                    You are the owner of this page
                </p>
                <div class="bcc-owner-stats">
                    <strong>Page Statistics:</strong>
                    <ul>
                        <li>Total Votes: <?php echo intval($vote_count); ?></li>
                        <li>Unique Voters: <?php echo $score ? $score->getUniqueVoters() : 0; ?></li>
                        <li>Endorsements: <?php echo intval($endorsement_count); ?></li>
                        <li>Confidence: <?php echo $confidence_percent; ?>%</li>
                    </ul>
                </div>
                <p class="bcc-owner-note">
                    As the page owner, you cannot vote on your own page.
                </p>
            </div>
            
        <?php elseif ($is_visitor): ?>
            <!-- ================= VISITOR VIEW - Full voting and endorsement actions ================= -->
            <?php if ($user_fraud_score >= 70): ?>
                <!-- ================= USER IS HIGH-RISK ================= -->
                <div class="bcc-user-warning">
                    <strong>Account Restricted</strong>
                    <p>Your account is under review. Voting is temporarily disabled.</p>
                </div>
            <?php else: ?>
                <!-- ================= VOTING ACTIONS ================= -->
                <div class="bcc-vote-actions">
                    <button class="bcc-vote-button button button-small <?php echo $my_vote_type === 1 ? 'active' : ''; ?>"
                            data-type="1"
                            <?php echo $my_vote_type !== 0 ? 'disabled' : ''; ?>>
                        ⬆ Upvote
                    </button>

                    <button class="bcc-vote-button button button-small <?php echo $my_vote_type === -1 ? 'active' : ''; ?>"
                            data-type="-1"
                            <?php echo $my_vote_type !== 0 ? 'disabled' : ''; ?>>
                        ⬇ Downvote
                    </button>

                    <?php if ($my_vote_type !== 0): ?>
                        <button class="bcc-remove-vote-button button button-small button-link">
                            Remove Vote
                        </button>
                    <?php endif; ?>
                </div>

                <!-- ================= ENDORSEMENT ACTIONS ================= -->
                <div class="bcc-endorse-actions">
                    <button class="bcc-endorse-button button button-small <?php echo $has_endorsed ? 'active' : ''; ?>"
                            <?php echo $has_endorsed ? 'disabled' : ''; ?>>
                        ⭐ <?php echo $has_endorsed ? 'Endorsed' : 'Endorse'; ?>
                    </button>
                    
                    <?php if ($has_endorsed): ?>
                        <button class="bcc-revoke-endorse-button button button-small button-link">
                            Revoke
                        </button>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
            
        <?php elseif ($is_logged_out): ?>
            <!-- ================= LOGGED OUT VIEW - Login prompt ================= -->
            <div class="bcc-logged-out-view">
                <p>
                    <span class="dashicons dashicons-lock"></span>
                    <a href="<?php echo esc_url(wp_login_url(get_permalink($page_id))); ?>">Log in</a> to vote or endorse this page
                </p>
                <p class="bcc-logged-out-score">
                    Trust score: <?php echo number_format($total_score, 1); ?> (<?php echo esc_html(ucfirst($tier)); ?>)
                </p>
            </div>
        <?php endif; ?>
        
    <?php endif; ?>

    <!-- ================= GITHUB VERIFICATION SECTION ================= -->
    <?php if ($args['show_github'] && $viewer_id): ?>
        <div class="bcc-github-section">
            <h4 class="bcc-github-title">🔗 GitHub Verification</h4>
            
            <?php if ($github_connected): ?>
                <!-- ================= GITHUB CONNECTED - SHOW DATA ================= -->
                <div class="bcc-github-connected">
                    <div class="bcc-github-header">
                        <svg class="bcc-github-icon" height="20" width="20" viewBox="0 0 16 16">
                            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                        </svg>
                        <strong class="bcc-github-username">
                            <a href="https://github.com/<?php echo esc_attr($github_username); ?>" target="_blank">
                                @<?php echo esc_html($github_username); ?>
                            </a>
                        </strong>
                        <?php if ($github_verified_at): ?>
                            <span class="bcc-github-verified">
                                (verified <?php echo human_time_diff(strtotime($github_verified_at), current_time('timestamp')); ?> ago)
                            </span>
                        <?php endif; ?>
                    </div>
                    
                    <!-- ================= GITHUB STATS GRID ================= -->
                    <div class="bcc-github-stats-grid">
                        <?php if ($github_id): ?>
                            <div class="bcc-github-stat-card">
                                <div class="bcc-github-stat-label">GitHub ID</div>1
                                <div class="bcc-github-stat-value">#<?php echo esc_html($github_id); ?></div>
                                
                            </div>
                        <?php endif; ?>
                        
                        <div class="bcc-github-stat-card">
                            <div class="bcc-github-stat-label">Followers</div>
                            <div class="bcc-github-stat-value"><?php echo number_format($github_followers); ?></div>
                            
                        </div>
                        
                        <div class="bcc-github-stat-card">
                            <div class="bcc-github-stat-value"><?php echo number_format($github_public_repos); ?></div>
                            <div class="bcc-github-stat-label">Public Repos</div>
                        </div>
                        
                        <?php if ($github_org_count > 0): ?>
                            <div class="bcc-github-stat-card">
                                <div class="bcc-github-stat-value"><?php echo number_format($github_org_count); ?></div>
                                <div class="bcc-github-stat-label">Organizations</div>
                            </div>
                        <?php endif; ?>
                    </div>
                    
                    <!-- ================= TRUST BOOST METER ================= -->
                    <div class="bcc-trust-impact">
                        <div class="bcc-trust-impact-header">
                            <span class="bcc-trust-impact-label">Trust Impact</span>
                            <span class="bcc-trust-impact-value">
                                +<?php echo number_format($total_github_boost, 1); ?> points
                            </span>
                        </div>
                        
                        <?php if ($github_trust_boost > 0): ?>
                            <div class="bcc-trust-breakdown">
                                <span>Trust Boost</span>
                                <span>+<?php echo number_format($github_trust_boost, 1); ?></span>
                            </div>
                        <?php endif; ?>
                        
                        <?php if ($github_fraud_reduction > 0): ?>
                            <div class="bcc-trust-breakdown">
                                <span>Fraud Reduction</span>
                                <span>-<?php echo $github_fraud_reduction; ?></span>
                            </div>
                        <?php endif; ?>
                        
                        <div class="bcc-progress-bar">
                            <div class="bcc-progress-fill" style="width: <?php echo min(100, $total_github_boost); ?>%;"></div>
                        </div>
                    </div>
                    
                    <!-- ================= DISCONNECT BUTTON - ONLY FOR PAGE OWNER ================= -->
                    <?php if ($is_owner): ?>
                        <button class="button button-small bcc-github-disconnect">
                            Disconnect GitHub Account
                        </button>
                    <?php endif; ?>
                </div>
                
            <?php elseif ($is_owner): ?>
                <!-- ================= GITHUB NOT CONNECTED - SHOW BUTTON ONLY TO PAGE OWNER ================= -->
                <button class="button button-small bcc-github-connect">
                    <svg class="bcc-github-button-icon" height="16" width="16" viewBox="0 0 16 16">
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                    </svg>
                    Connect GitHub Account
                </button>
                <p class="bcc-github-note">
                    <small>Verify your GitHub to increase trust score and reduce fraud score</small>
                </p>
                
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- ================= ADMIN ALERTS - ONLY SHOW TO ADMINS ================= -->
    <?php if ($args['show_fraud_alerts'] && $has_fraud_alerts && current_user_can('manage_options')): ?>
        <div class="bcc-admin-alert">
            <strong>⚠️ Admin Notice:</strong> This page has <?php echo $fraud_alert_count; ?> fraud alert(s).
            <a href="<?php echo esc_url(admin_url('admin.php?page=bcc-trust-dashboard&tab=fraud')); ?>">Review in dashboard →</a>
        </div>
    <?php endif; ?>

    <!-- ================= STATUS MESSAGE AREA ================= -->
    <div class="bcc-status-message"></div>
</div>