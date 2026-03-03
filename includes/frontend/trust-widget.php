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

if (!defined('ABSPATH')) {
    exit;
}

// This file should only be used when included by bcc_trust_render_widget()
// If accessed directly, do nothing
if (!isset($args) || !is_array($args)) {
    return;
}

// Default args
$args = wp_parse_args($args, [
    'page_id'          => 0,
    'show_detailed'    => true,
    'show_actions'     => true,
    'show_fraud_alerts' => true
]);

$page_id = intval($args['page_id']);
if (!$page_id) {
    echo '<div class="bcc-trust-error">Invalid page ID</div>';
    return;
}

$viewer_id = get_current_user_id();

// Check if required classes exist
if (!class_exists('\\BCCTrust\\Repositories\\ScoreRepository') || 
    !class_exists('\\BCCTrust\\Services\\VoteService') ||
    !class_exists('\\BCCTrust\\Repositories\\UserInfoRepository')) {
    echo '<div class="bcc-trust-error">Trust system not available</div>';
    return;
}

/* ======================================================
 PAGE OWNER CHECK
====================================================== */
$page_owner_id = 0;
if (function_exists('bcc_trust_get_page_owner')) {
    $page_owner_id = (int) bcc_trust_get_page_owner($page_id);
}
$is_owner = ($viewer_id && $viewer_id == $page_owner_id);

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
$can_vote = $viewer_id && !$is_owner && $user_fraud_score < 70;
?>

<div class="bcc-trust-wrapper" 
     data-page-id="<?php echo esc_attr($page_id); ?>"
     data-target="<?php echo esc_attr($page_id); ?>"
     data-nonce="<?php echo wp_create_nonce('wp_rest'); ?>">

    <!-- ================= TRUST SCORE ================= -->
    <div class="bcc-trust-header">
        <strong>Trust Score:</strong>
        <span class="bcc-score-value"><?php echo number_format($total_score, 1); ?></span>
        <span class="bcc-tier-label">(<?php echo esc_html(ucfirst($tier)); ?>)</span>
        
        <?php if ($args['show_fraud_alerts'] && $has_fraud_alerts): ?>
            <span class="bcc-fraud-alert" title="Suspicious activity detected" style="margin-left: 8px; color: #d63638; display: inline-block; animation: pulse 2s infinite;">
                ⚠️ <?php echo $fraud_alert_count; ?>
            </span>
        <?php endif; ?>
    </div>

    <!-- ================= DETAILS ================= -->
    <div class="bcc-trust-details" style="font-size:0.9em; color:#666; margin:5px 0;">
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
        <!-- ================= DETAILED SCORES ================= -->
        <div class="bcc-detailed-scores" style="display:flex; gap:15px; margin:10px 0; font-size:0.9em;">
            <div class="bcc-positive-score">
                <span style="color:#4caf50;">👍 Positive:</span>
                <span class="value"><?php echo number_format($positive_score, 1); ?></span>
            </div>
            <div class="bcc-negative-score">
                <span style="color:#f44336;">👎 Negative:</span>
                <span class="value"><?php echo number_format($negative_score, 1); ?></span>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($args['show_actions']): ?>
        <?php if ($viewer_id && !$is_owner): ?>
            <?php if ($user_fraud_score >= 70): ?>
                <!-- ================= USER IS HIGH-RISK ================= -->
                <div class="bcc-user-warning" style="margin-top:10px; padding:8px; background:#f8d7da; border-radius:4px; color:#721c24;">
                    <strong>Account Restricted</strong>
                    <p style="margin:5px 0 0; font-size:0.9em;">Your account is under review. Voting is temporarily disabled.</p>
                </div>
            <?php else: ?>
                <!-- ================= VOTING ACTIONS ================= -->
                <div class="bcc-trust-actions" style="margin-top:10px;">
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
                        <button class="bcc-remove-vote-button button button-small button-link" style="margin-left:5px;">
                            Remove Vote
                        </button>
                    <?php endif; ?>
                </div>

                <!-- ================= ENDORSEMENT ACTIONS ================= -->
                <div class="bcc-endorse-actions" style="margin-top:8px;">
                    <button class="bcc-endorse-button button button-small <?php echo $has_endorsed ? 'active' : ''; ?>"
                            <?php echo $has_endorsed ? 'disabled' : ''; ?>>
                        ⭐ <?php echo $has_endorsed ? 'Endorsed' : 'Endorse'; ?>
                    </button>
                    
                    <?php if ($has_endorsed): ?>
                        <button class="bcc-revoke-endorse-button button button-small button-link" style="margin-left:5px;">
                            Revoke
                        </button>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php elseif ($is_owner): ?>
            <p class="bcc-owner-notice" style="font-style:italic; color:#999; margin-top:10px; font-size:0.9em;">
                You cannot vote on your own page
            </p>
        <?php else: ?>
            <p class="bcc-login-notice" style="margin-top:10px; font-size:0.9em;">
                <a href="<?php echo esc_url(wp_login_url(get_permalink($page_id))); ?>">Log in</a> to vote
            </p>
        <?php endif; ?>
    <?php endif; ?>

    <!-- ================= ADMIN ALERTS ================= -->
    <?php if ($args['show_fraud_alerts'] && $has_fraud_alerts && current_user_can('manage_options')): ?>
        <div class="bcc-admin-alert" style="margin-top:10px; padding:8px; background:#fff3cd; border-left:4px solid #ffb900; font-size:0.9em;">
            <strong>⚠️ Admin Notice:</strong> This page has <?php echo $fraud_alert_count; ?> fraud alert(s).
            <a href="<?php echo esc_url(admin_url('admin.php?page=bcc-trust-dashboard&tab=fraud')); ?>" style="display:block; margin-top:4px;">Review in dashboard →</a>
        </div>
    <?php endif; ?>

    <!-- ================= STATUS MESSAGE AREA ================= -->
    <div class="bcc-status-message" style="margin-top:8px; min-height:20px; font-size:0.9em;"></div>
</div>

<style>
.bcc-vote-button.active,
.bcc-endorse-button.active {
    background: #2271b1;
    color: white;
    border-color: #2271b1;
}
.bcc-vote-button.active:hover,
.bcc-endorse-button.active:hover {
    background: #135e96;
}
.bcc-vote-button:disabled,
.bcc-endorse-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}
.bcc-fraud-alert {
    display: inline-block;
    font-weight: bold;
}
@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.6; }
    100% { opacity: 1; }
}
.bcc-status-message.success { color: #00a32a; }
.bcc-status-message.error { color: #d63638; }
.bcc-status-message.info { color: #2271b1; }
</style>