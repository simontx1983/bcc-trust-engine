<?php
if (!defined('ABSPATH')) {
    exit;
}

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
        'show_title'   => 'true'
    ], $atts);

    $pageId = (int) $atts['page_id'];
    $showActions = filter_var($atts['show_actions'], FILTER_VALIDATE_BOOLEAN);
    $showTitle = filter_var($atts['show_title'], FILTER_VALIDATE_BOOLEAN);

    if (!$pageId) {
        return '<p>Error: No page ID specified.</p>';
    }

    // Verify page exists and is a PeepSo Page (or at least a post)
    $page = get_post($pageId);
    if (!$page) {
        return '<p>Error: Page not found.</p>';
    }

    // Check if current user is the page owner
    $pageOwnerId = bcc_trust_get_page_owner($pageId) ?: $page->post_author;
    $is_owner = is_user_logged_in() && get_current_user_id() == $pageOwnerId;

    // Get initial score data if available (for non-JS fallback)
    $initial_score = null;
    if (class_exists('BCC_Page_Score_Calculator')) {
        $calculator = new BCC_Page_Score_Calculator();
        $score = $calculator->get_page_score($pageId);
        if ($score) {
            $initial_score = [
                'total_score' => $score->total_score,
                'reputation_tier' => $score->reputation_tier,
                'confidence_score' => $score->confidence_score,
                'vote_count' => $score->vote_count,
                'endorsement_count' => $score->endorsement_count
            ];
        }
    }

    ob_start();
    ?>
    <div class="bcc-trust-wrapper" 
         data-page-id="<?php echo esc_attr($pageId); ?>"
         data-page-title="<?php echo esc_attr($page->post_title); ?>"
         data-page-owner="<?php echo esc_attr($pageOwnerId); ?>"
         data-initial-score='<?php echo $initial_score ? json_encode($initial_score) : ''; ?>'>
        
        <div class="bcc-trust-header">
            <?php if ($showTitle): ?>
                <strong><?php echo esc_html($atts['title']); ?>:</strong>
            <?php endif; ?>
            <span class="bcc-score-value">
                <?php echo $initial_score ? esc_html($initial_score['total_score']) : '—'; ?>
            </span>
            <?php if ($initial_score && $initial_score['reputation_tier']): ?>
                <span class="bcc-tier-label">
                    (<?php echo esc_html($initial_score['reputation_tier']); ?>)
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
                <span class="bcc-confidence-level"></span>
                <span class="bcc-vote-total"></span>
                <span class="bcc-endorsement-total"></span>
            <?php endif; ?>
        </div>

        <?php if ($showActions): ?>
            <div class="bcc-trust-actions" style="margin-top: 10px;">
                <?php if (is_user_logged_in()): ?>
                    <?php if (!$is_owner): ?>
                        <button class="bcc-vote-button button button-small" data-type="1">⬆ Upvote</button>
                        <button class="bcc-vote-button button button-small" data-type="-1">⬇ Downvote</button>
                        <button class="bcc-endorse-button button button-small">⭐ Endorse Page</button>
                    <?php else: ?>
                        <p><em>You cannot vote on your own page</em></p>
                    <?php endif; ?>
                <?php else: ?>
                    <p><a href="<?php echo esc_url(wp_login_url(get_permalink($pageId))); ?>">Log in</a> to vote on this page</p>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="bcc-status-message" style="margin-top:8px; min-height: 20px;"></div>
    </div>
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
 */
function bcc_trust_display($page_id, $show_actions = true, $title = 'Page Trust Score', $show_title = true) {
    echo do_shortcode(sprintf(
        '[bcc_trust page_id="%d" show_actions="%s" title="%s" show_title="%s"]',
        (int) $page_id,
        $show_actions ? 'true' : 'false',
        esc_attr($title),
        $show_title ? 'true' : 'false'
    ));
}

