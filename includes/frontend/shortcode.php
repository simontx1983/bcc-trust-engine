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
        'show_fraud_alerts' => 'true',
        'show_github'  => 'true'
    ], $atts);

    $pageId = (int) $atts['page_id'];
    $showActions = filter_var($atts['show_actions'], FILTER_VALIDATE_BOOLEAN);
    $showTitle = filter_var($atts['show_title'], FILTER_VALIDATE_BOOLEAN);
    $showFraudAlerts = filter_var($atts['show_fraud_alerts'], FILTER_VALIDATE_BOOLEAN);
    $showGithub = filter_var($atts['show_github'], FILTER_VALIDATE_BOOLEAN);

    if (!$pageId) {
        return '<p class="bcc-error">Error: No page ID specified.</p>';
    }

    $page = get_post($pageId);
    if (!$page) {
        return '<p class="bcc-error">Error: Page not found.</p>';
    }

    // Initialize repositories
    $scoreRepo = new ScoreRepository();
    $voteRepo = new VoteRepository();
    $endorseRepo = new EndorsementRepository();
    $userInfoRepo = new UserInfoRepository();

    // Get page score
    $score = $scoreRepo->getByPageId($pageId);
    
    // Get page owner
    $pageOwnerId = bcc_trust_get_page_owner($pageId) ?: $page->post_author;
    $is_owner = is_user_logged_in() && get_current_user_id() == $pageOwnerId;

    // Get current user's data if logged in
    $currentUserId = get_current_user_id();
    $currentUserInfo = $currentUserId ? $userInfoRepo->getByUserId($currentUserId) : null;
    $userVote = $currentUserId ? $voteRepo->get($currentUserId, $pageId) : null;
    $userEndorsement = $currentUserId ? $endorseRepo->get($currentUserId, $pageId) : null;

    // Get GitHub connection status for current user - DIRECT FROM DB, NO API CALL
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
    
    if ($currentUserId) {
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
            $currentUserId
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
    }

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
        
        <!-- ================= TRUST SCORE SECTION ================= -->
        <div class="bcc-trust-section">
            <h3 class="bcc-section-title">📊 Trust Score</h3>
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
                    <span class="bcc-fraud-alert" title="Suspicious activity detected">
                        ⚠️ <?php echo $initial_score['fraud_alert_count']; ?>
                    </span>
                <?php endif; ?>
            </div>

            <div class="bcc-trust-details">
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
        </div>

        <!-- ================= VOTING & ENDORSEMENT SECTION ================= -->
        <?php if ($showActions): ?>
            <div class="bcc-trust-section">
                <h3 class="bcc-section-title">🗳️ Voting & Endorsements</h3>
                <div class="bcc-trust-actions">
                    <?php if (is_user_logged_in()): ?>
                        <?php if (!$is_owner): ?>
                            <?php if ($currentUserInfo && $currentUserInfo->fraud_score > 70): ?>
                                <div class="bcc-user-warning">
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
                                        <button class="bcc-remove-vote-button button button-small button-link">
                                            Remove Vote
                                        </button>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="bcc-endorse-section">
                                    <button class="bcc-endorse-button button button-small <?php echo $userEndorsement ? 'active' : ''; ?>" 
                                            <?php echo $userEndorsement ? 'disabled' : ''; ?>>
                                        ⭐ <?php echo $userEndorsement ? 'Endorsed' : 'Endorse Page'; ?>
                                    </button>
                                    <?php if ($userEndorsement): ?>
                                        <button class="bcc-revoke-endorse-button button button-small button-link">
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
            </div>
        <?php endif; ?>

        <!-- ================= GITHUB VERIFICATION SECTION ================= -->
        <?php if ($showGithub): ?>
            <div class="bcc-trust-section">
                <h3 class="bcc-section-title">🔗 GitHub Verification</h3>
                <div class="bcc-github-section">
                    <?php if (is_user_logged_in()): ?>
                        <?php if ($github_connected): ?>
                            <!-- GITHUB CONNECTED - SHOW DATA -->
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
                                </div>
                                
                                <div class="bcc-github-stats-grid">
                                    <?php if ($github_username): ?>
                                        <div class="bcc-github-stat-card">
                                            <div class="bcc-github-stat-value">@<?php echo esc_html($github_username); ?></div>
                                            <div class="bcc-github-stat-label">GitHub Username</div>
                                        </div>
                                    <?php endif; ?>
                                    
                                    <div class="bcc-github-stat-card">
                                        <div class="bcc-github-stat-value"><?php echo number_format($github_followers); ?></div>
                                        <div class="bcc-github-stat-label">Followers</div>
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
                                
                                <!-- TRUST BOOST METER -->
                                <?php if ($total_github_boost > 0): ?>
                                <div class="bcc-trust-impact">
                                    <div class="bcc-trust-impact-header">
                                        <span class="bcc-trust-impact-label">Trust Impact</span>
                                        <span class="bcc-trust-impact-value">+<?php echo number_format($total_github_boost, 1); ?> points</span>
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
                                <?php endif; ?>
                                
                                <!-- DISCONNECT BUTTON - ONLY FOR PAGE OWNER -->
                                <?php if ($is_owner): ?>
                                    <button class="button button-small bcc-github-disconnect">
                                        Disconnect GitHub Account
                                    </button>
                                <?php endif; ?>
                            </div>
                            
                        <?php elseif ($is_owner): ?>
                            <!-- GITHUB NOT CONNECTED - SHOW BUTTON ONLY TO PAGE OWNER -->
                            <button class="button button-small bcc-github-connect">
                                <svg height="16" width="16" viewBox="0 0 16 16" class="bcc-github-button-icon">
                                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
                                </svg>
                                Connect GitHub Account
                            </button>
                            <p class="bcc-github-note">
                                <small>Verify your GitHub to increase trust score and reduce fraud score</small>
                            </p>
                            
                        <?php else: ?>
                            <!-- LOGGED IN BUT NOT OWNER - NO BUTTON SHOWN -->
                            <div class="bcc-github-message">
                                <p>🔐 The page owner can connect GitHub to build trust.</p>
                            </div>
                        <?php endif; ?>
                    <?php else: ?>
                        <!-- NOT LOGGED IN -->
                        <div class="bcc-github-message">
                            <p>🔐 GitHub verification helps build trust in the community.</p>
                            <p class="bcc-github-login-prompt">
                                <a href="<?php echo esc_url(wp_login_url(get_permalink($pageId))); ?>">Log in</a> to connect your GitHub account and increase your trust score.
                            </p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- ================= STATUS MESSAGE AREA ================= -->
        <div class="bcc-status-message"></div>
        
        <!-- ================= ADMIN ALERTS - ONLY SHOW TO ADMINS ================= -->
        <?php if ($showFraudAlerts && $initial_score && $initial_score['has_fraud_alerts'] && current_user_can('manage_options')): ?>
            <div class="bcc-admin-alert">
                <strong>Admin Notice:</strong> This page has <?php echo $initial_score['fraud_alert_count']; ?> fraud alert(s). 
                <a href="<?php echo esc_url(admin_url('admin.php?page=bcc-trust-dashboard&tab=fraud')); ?>">Review in dashboard</a>
            </div>
        <?php endif; ?>
    </div>
    <?php
    return ob_get_clean();
});