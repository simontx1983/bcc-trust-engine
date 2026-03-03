<?php
if (!defined('ABSPATH')) {
    exit;
}

use BCCTrust\Repositories\ScoreRepository;
use BCCTrust\Repositories\UserInfoRepository;
use BCCTrust\Repositories\VoteRepository;
use BCCTrust\Repositories\EndorsementRepository;

/**
 * Shortcode for displaying trust score widget
 * 
 * Usage: [bcc_trust page_id="123" show_actions="true" title="Page Trust Score" show_title="true"]
 */
add_shortcode('bcc_trust', function ($atts) {
    $atts = shortcode_atts([
        'page_id'      => 0,
        'show_actions' => 'true',
        'title'        => 'Page Trust Score',
        'show_title'   => 'true',
        'show_fraud_alerts' => 'true'
    ], $atts);

    $pageId = (int) $atts['page_id'];
    $showActions = filter_var($atts['show_actions'], FILTER_VALIDATE_BOOLEAN);
    $showTitle = filter_var($atts['show_title'], FILTER_VALIDATE_BOOLEAN);
    $showFraudAlerts = filter_var($atts['show_fraud_alerts'], FILTER_VALIDATE_BOOLEAN);

    if (!$pageId) {
        return '<p class="bcc-error">Error: No page ID specified.</p>';
    }

    // Verify page exists and is a PeepSo Page (or at least a post)
    $page = get_post($pageId);
    if (!$page) {
        return '<p class="bcc-error">Error: Page not found.</p>';
    }

    // Initialize repositories
    $scoreRepo = new ScoreRepository();
    $voteRepo = new VoteRepository();
    $endorseRepo = new EndorsementRepository();
    $userInfoRepo = new UserInfoRepository();

    // Get page score using new system
    $score = $scoreRepo->getByPageId($pageId);
    
    // Get page owner
    $pageOwnerId = bcc_trust_get_page_owner($pageId) ?: $page->post_author;
    $is_owner = is_user_logged_in() && get_current_user_id() == $pageOwnerId;

    // Get current user's data if logged in
    $currentUserId = get_current_user_id();
    $currentUserInfo = $currentUserId ? $userInfoRepo->getByUserId($currentUserId) : null;
    $userVote = $currentUserId ? $voteRepo->get($currentUserId, $pageId) : null;
    $userEndorsement = $currentUserId ? $endorseRepo->get($currentUserId, $pageId) : null;

    // Prepare initial score data
    $initial_score = null;
    if ($score) {
        $initial_score = [
            'total_score' => $score->getTotalScore(),
            'reputation_tier' => $score->getReputationTier(),
            'confidence_score' => $score->getConfidenceScore(),
            'vote_count' => $score->getVoteCount(),
            'endorsement_count' => $score->getEndorsementCount(),
            'has_fraud_alerts' => $score->hasFraudAlerts(),
            'fraud_alert_count' => $score->getFraudAlertCount()
        ];
    }

    ob_start();
    ?>
    <div class="bcc-trust-wrapper" 
         data-page-id="<?php echo esc_attr($pageId); ?>"
         data-page-title="<?php echo esc_attr($page->post_title); ?>"
         data-page-owner="<?php echo esc_attr($pageOwnerId); ?>"
         data-initial-score='<?php echo $initial_score ? json_encode($initial_score) : ''; ?>'
         data-nonce="<?php echo esc_attr(wp_create_nonce('bcc_trust_public')); ?>">
        
        <div class="bcc-trust-header">
            <?php if ($showTitle): ?>
                <strong><?php echo esc_html($atts['title']); ?>:</strong>
            <?php endif; ?>
            <span class="bcc-score-value">
                <?php echo $initial_score ? esc_html($initial_score['total_score']) : '—'; ?>
            </span>
            <?php if ($initial_score && $initial_score['reputation_tier']): ?>
                <span class="bcc-tier-label">
                    (<?php echo esc_html(ucfirst($initial_score['reputation_tier'])); ?>)
                </span>
            <?php endif; ?>
            
            <?php if ($showFraudAlerts && $initial_score && $initial_score['has_fraud_alerts']): ?>
                <span class="bcc-fraud-alert" title="Suspicious activity detected" style="margin-left: 8px; color: #d63638;">
                    ⚠️ <?php echo $initial_score['fraud_alert_count']; ?>
                </span>
            <?php endif; ?>
        </div>

        <div class="bcc-trust-details" style="font-size:0.9em; color:#666; margin:5px 0;">
            <?php if ($initial_score): ?>
                <span class="bcc-confidence-level">
                    <?php echo round($initial_score['confidence_score'] * 100); ?>% confidence
                </span>
                <span class="bcc-vote-total">
                    <?php echo esc_html($initial_score['vote_count']); ?> votes
                </span>
                <span class="bcc-endorsement-total">
                    <?php echo esc_html($initial_score['endorsement_count']); ?> endorsements
                </span>
            <?php else: ?>
                <span class="bcc-confidence-level">No votes yet</span>
            <?php endif; ?>
        </div>

        <?php if ($showActions): ?>
            <div class="bcc-trust-actions" style="margin-top: 10px;">
                <?php if (is_user_logged_in()): ?>
                    <?php if (!$is_owner): ?>
                        <?php if ($currentUserInfo && $currentUserInfo->fraud_score > 70): ?>
                            <div class="bcc-user-warning" style="color: #d63638; margin-bottom: 8px; padding: 8px; background: #f8d7da; border-radius: 4px;">
                                Your account is under review. Voting is temporarily disabled.
                            </div>
                        <?php else: ?>
                            <div class="bcc-vote-buttons">
                                <button class="bcc-vote-button button button-small <?php echo $userVote && $userVote->vote_type > 0 ? 'active' : ''; ?>" 
                                        data-type="1" 
                                        <?php echo $userVote && $userVote->vote_type > 0 ? 'disabled' : ''; ?>>
                                    ⬆ Upvote
                                </button>
                                <button class="bcc-vote-button button button-small <?php echo $userVote && $userVote->vote_type < 0 ? 'active' : ''; ?>" 
                                        data-type="-1" 
                                        <?php echo $userVote && $userVote->vote_type < 0 ? 'disabled' : ''; ?>>
                                    ⬇ Downvote
                                </button>
                                <?php if ($userVote): ?>
                                    <button class="bcc-remove-vote-button button button-small button-link" style="margin-left: 5px;">
                                        Remove Vote
                                    </button>
                                <?php endif; ?>
                            </div>
                            
                            <div class="bcc-endorse-section" style="margin-top: 8px;">
                                <button class="bcc-endorse-button button button-small <?php echo $userEndorsement ? 'active' : ''; ?>" 
                                        <?php echo $userEndorsement ? 'disabled' : ''; ?>>
                                    ⭐ <?php echo $userEndorsement ? 'Endorsed' : 'Endorse Page'; ?>
                                </button>
                                <?php if ($userEndorsement): ?>
                                    <button class="bcc-revoke-endorse-button button button-small button-link" style="margin-left: 5px;">
                                        Revoke Endorsement
                                    </button>
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <p class="bcc-owner-note"><em>You cannot vote on your own page</em></p>
                    <?php endif; ?>
                <?php else: ?>
                    <p class="bcc-login-prompt">
                        <a href="<?php echo esc_url(wp_login_url(get_permalink($pageId))); ?>">Log in</a> to vote on this page
                    </p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="bcc-status-message" style="margin-top:8px; min-height: 20px;"></div>
        
        <?php if ($showFraudAlerts && $initial_score && $initial_score['has_fraud_alerts'] && current_user_can('manage_options')): ?>
            <div class="bcc-admin-alert" style="margin-top: 10px; padding: 8px; background: #fff3cd; border-left: 4px solid #ffb900;">
                <strong>Admin Notice:</strong> This page has <?php echo $initial_score['fraud_alert_count']; ?> fraud alert(s). 
                <a href="<?php echo esc_url(admin_url('admin.php?page=bcc-trust-dashboard&tab=fraud')); ?>">Review in dashboard</a>
            </div>
        <?php endif; ?>
    </div>

    <style>
    .bcc-vote-button.active, .bcc-endorse-button.active {
        background: #2271b1;
        color: white;
        border-color: #2271b1;
    }
    .bcc-vote-button.active:hover, .bcc-endorse-button.active:hover {
        background: #135e96;
    }
    .bcc-fraud-alert {
        display: inline-block;
        animation: pulse 2s infinite;
    }
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.6; }
        100% { opacity: 1; }
    }
    .bcc-status-message.success {
        color: #00a32a;
    }
    .bcc-status-message.error {
        color: #d63638;
    }
    .bcc-status-message.info {
        color: #2271b1;
    }
    </style>
    <?php
    return ob_get_clean();
});

/**
 * Helper function to display trust widget in templates
 * 
 * @param int $page_id
 * @param bool $show_actions
 * @param string $title
 * @param bool $show_title
 * @param bool $show_fraud_alerts
 */
function bcc_trust_display($page_id, $show_actions = true, $title = 'Page Trust Score', $show_title = true, $show_fraud_alerts = true) {
    echo do_shortcode(sprintf(
        '[bcc_trust page_id="%d" show_actions="%s" title="%s" show_title="%s" show_fraud_alerts="%s"]',
        (int) $page_id,
        $show_actions ? 'true' : 'false',
        esc_attr($title),
        $show_title ? 'true' : 'false',
        $show_fraud_alerts ? 'true' : 'false'
    ));
}

/**
 * Simplified widget display function for sidebar widgets
 */
function bcc_trust_display_widget($args = []) {
    $defaults = [
        'page_id' => 0,
        'show_actions' => true,
        'title' => 'Page Trust Score',
        'show_title' => true,
        'show_fraud_alerts' => true,
        'before_widget' => '',
        'after_widget' => '',
        'before_title' => '<h3 class="widget-title">',
        'after_title' => '</h3>'
    ];
    
    $args = wp_parse_args($args, $defaults);
    
    if (!$args['page_id']) {
        return;
    }
    
    echo $args['before_widget'];
    
    if ($args['show_title']) {
        echo $args['before_title'] . esc_html($args['title']) . $args['after_title'];
    }
    
    bcc_trust_display(
        $args['page_id'],
        $args['show_actions'],
        '',
        false,
        $args['show_fraud_alerts']
    );
    
    echo $args['after_widget'];
}

/**
 * Enqueue frontend scripts
 */
add_action('wp_enqueue_scripts', function() {
    if (!is_admin()) {
        wp_enqueue_script(
            'bcc-trust-frontend',
            plugins_url('assets/js/frontend.js', dirname(__FILE__)),
            ['jquery'],
            '2.0.0',
            true
        );
        
        wp_localize_script('bcc-trust-frontend', 'bccTrust', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'rest_url' => rest_url('bcc-trust/v1/'),
            'nonce' => wp_create_nonce('wp_rest'),
            'is_logged_in' => is_user_logged_in()
        ]);
        
        wp_enqueue_style(
            'bcc-trust-frontend',
            plugins_url('assets/css/frontend.css', dirname(__FILE__)),
            [],
            '2.0.0'
        );
    }
});

