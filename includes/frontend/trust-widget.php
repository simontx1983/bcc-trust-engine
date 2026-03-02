<?php
/**
 * Advanced Trust Widget Template
 * 
 * This file should be included via bcc_trust_render_widget() function,
 * not loaded directly.
 * 
 * @package BCC_Trust_Engine
 * @subpackage Frontend
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
    'page_id'       => 0,
    'show_detailed' => true,
    'show_actions'  => true
]);

$page_id = intval($args['page_id']);
if (!$page_id) {
    echo '<div class="bcc-trust-error">Invalid page ID</div>';
    return;
}

$viewer_id = get_current_user_id();

// Check if required classes exist
if (!class_exists('\\BCCTrust\\Repositories\\ScoreRepository') || 
    !class_exists('\\BCCTrust\\Services\\VoteService')) {
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
 TRUST SCORE DATA
====================================================== */
try {
    $scoreRepo = new \BCCTrust\Repositories\ScoreRepository();
    $score = $scoreRepo->getByPageId($page_id);
} catch (Exception $e) {
    error_log('BCC Trust: Error getting score - ' . $e->getMessage());
    $score = null;
}

$total_score = $score ? floatval($score->total_score) : 50;
$positive_score = $score ? floatval($score->positive_score) : 0;
$negative_score = $score ? floatval($score->negative_score) : 0;
$vote_count = $score ? intval($score->vote_count) : 0;
$confidence = $score ? floatval($score->confidence_score) : 0;
$tier = $score ? $score->reputation_tier : 'neutral';
$endorsement_count = $score ? intval($score->endorsement_count) : 0;

$confidence_percent = intval($confidence * 100);

if ($confidence_percent >= 80) {
    $confidence_label = "Very high reliability";
} elseif ($confidence_percent >= 50) {
    $confidence_label = "Moderate reliability";
} else {
    $confidence_label = "Limited voting data";
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
            <!-- ================= VOTING ACTIONS ================= -->
            <div class="bcc-trust-actions" style="margin-top:10px;">
                <button class="bcc-vote-button button button-small <?php echo $my_vote_type === 1 ? 'active' : ''; ?>"
                        data-type="1">
                    ⬆ Upvote
                </button>

                <button class="bcc-vote-button button button-small <?php echo $my_vote_type === -1 ? 'active' : ''; ?>"
                        data-type="-1">
                    ⬇ Downvote
                </button>

                <button class="bcc-endorse-button button button-small <?php echo $has_endorsed ? 'revoke' : ''; ?>">
                    <?php echo $has_endorsed ? 'Revoke Endorsement' : '⭐ Endorse'; ?>
                </button>
            </div>
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

    <!-- ================= STATUS MESSAGE AREA ================= -->
    <div class="bcc-status-message" style="margin-top:8px; min-height:20px;"></div>
</div>