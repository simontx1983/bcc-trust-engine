<?php
/**
 * PeepSo Pages Integration for Trust Engine
 * 
 * @package BCC_Trust_Engine
 * @subpackage Frontend
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BCC_PeepSo_Pages_Integration {
    
    /**
     * @var \BCCTrust\Repositories\ScoreRepository
     */
    private static $scoreRepo;
    
    /**
     * @var \BCCTrust\Repositories\UserInfoRepository
     */
    private static $userInfoRepo;
    
    /**
     * Initialize repositories
     */
    private static function init_repositories() {
        if (!self::$scoreRepo) {
            self::$scoreRepo = new \BCCTrust\Repositories\ScoreRepository();
        }
        if (!self::$userInfoRepo) {
            self::$userInfoRepo = new \BCCTrust\Repositories\UserInfoRepository();
        }
    }
    
    /**
     * Get UserInfoRepo instance
     */
    private static function getUserInfoRepo() {
        self::init_repositories();
        return self::$userInfoRepo;
    }
    
    /**
     * Check if PeepSo Pages extension is active
     */
    public static function is_peepso_pages_active() {
        return class_exists('PeepSoPage') || 
               defined('PEEPSO_PAGES_PLUGIN_VERSION') ||
               function_exists('PeepSoPage');
    }
    
    /**
     * Get PeepSo pages table name
     */
    private static function get_pages_table() {
        global $wpdb;
        return $wpdb->prefix . 'peepso_pages';
    }
    
    /**
     * Get page data with trust score
     */
    public static function get_page_with_trust_score($page_id) {
        self::init_repositories();
        global $wpdb;
        
        // Get PeepSo page data
        $pages_table = self::get_pages_table();
        $page = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$pages_table} WHERE ID = %d",
            $page_id
        ));
        
        if (!$page) {
            return null;
        }
        
        // Get trust score using repository
        $score = self::$scoreRepo->getByPageId($page_id);
        
        // Get page owner
        $page_owner = bcc_trust_get_page_owner($page_id);
        
        return (object) array(
            'page' => $page,
            'trust_score' => $score ?: self::get_default_score($page_id, $page_owner),
            'owner_id' => $page_owner,
            'score_api' => $score ? $score->toApiResponse() : null
        );
    }
    
    /**
     * Get default score for new page
     */
    private static function get_default_score($page_id, $owner_id) {
        // Use the value object to create default
        $score = \BCCTrust\ValueObjects\PageScore::createDefault($page_id, $owner_id);
        
        // Convert to legacy object format for compatibility
        return (object) array(
            'page_id' => $score->getPageId(),
            'page_owner_id' => $score->getPageOwnerId(),
            'total_score' => $score->getTotalScore(),
            'positive_score' => $score->getPositiveScore(),
            'negative_score' => $score->getNegativeScore(),
            'vote_count' => $score->getVoteCount(),
            'unique_voters' => $score->getUniqueVoters(),
            'confidence_score' => $score->getConfidenceScore(),
            'reputation_tier' => $score->getReputationTier(),
            'endorsement_count' => $score->getEndorsementCount(),
            'last_calculated_at' => $score->getLastCalculatedAt()->format('Y-m-d H:i:s'),
            'has_fraud_alerts' => $score->hasFraudAlerts()
        );
    }
    
    /**
     * Add trust widget to PeepSo page profile
     */
    public static function add_trust_widget_to_page() {
        add_action('peepso_page_profile_single_after_bio', function($page) {
            if (isset($page->ID) && function_exists('bcc_trust_display_widget')) {
                bcc_trust_display_widget($page->ID, true);
            }
        });
    }
    
    /**
     * Add trust score to page header
     */
    public static function add_trust_score_to_page_header() {
        add_action('peepso_page_profile_single_before_title', function($page) {
            if (isset($page->ID)) {
                $score_data = self::get_page_with_trust_score($page->ID);
                if ($score_data && $score_data->trust_score) {
                    $score = $score_data->trust_score;
                    $tier_info = bcc_trust_get_tier_info($score->reputation_tier);
                    ?>
                    <div class="bcc-page-trust-badge" style="display: inline-block; margin-left: 10px; padding: 3px 8px; border-radius: 3px; background: <?php echo esc_attr($tier_info['color']); ?>; color: #fff; font-size: 12px;">
                        <?php echo $tier_info['icon']; ?> <?php echo number_format($score->total_score, 1); ?> (<?php echo esc_html($tier_info['label']); ?>)
                        <?php if ($score->has_fraud_alerts ?? false): ?>
                            <span style="margin-left: 5px; background: rgba(255,255,255,0.3); padding: 2px 4px; border-radius: 2px;">⚠️</span>
                        <?php endif; ?>
                    </div>
                    <?php
                }
            }
        });
    }
    
    /**
     * Hook into PeepSo page creation
     */
    public static function handle_page_creation($page_id, $user_id) {
        self::init_repositories();
        
        // Use repository to create default score
        try {
            $score = self::$scoreRepo->createDefault($page_id, $user_id);
            
            // Update user's page count in user_info table
            self::$userInfoRepo->incrementPageCount($user_id, $page_id);
            
            // Log the creation
            if (function_exists('bcc_trust_log_audit')) {
                bcc_trust_log_audit('page_created', [
                    'page_id' => $page_id,
                    'user_id' => $user_id,
                    'action' => 'create'
                ]);
            }
            
        } catch (Exception $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('BCC Trust: Failed to initialize page score - ' . $e->getMessage());
            }
        }
    }
    
    /**
     * Add trust tab to page profile
     */
    public static function add_trust_tab_to_page() {
        add_filter('peepso_page_profile_tabs', function($tabs, $page_id) {
            $tabs['trust'] = [
                'href' => '#trust',
                'label' => 'Trust',
                'icon' => 'shield'
            ];
            return $tabs;
        }, 10, 2);
        
        add_action('peepso_page_profile_tab_content', function($tab, $page_id) {
            if ($tab === 'trust' && function_exists('bcc_trust_display')) {
                echo '<div class="peepso-tab-content">';
                bcc_trust_display($page_id, true, 'Page Trust Details', true);
                echo '</div>';
            }
        }, 10, 2);
    }
}

// Alias function for backward compatibility
if (!function_exists('bcc_trust_display_widget')) {
    function bcc_trust_display_widget($page_id, $show_actions = true) {
        if (function_exists('bcc_trust_render_widget')) {
            bcc_trust_render_widget([
                'page_id' => $page_id,
                'show_actions' => $show_actions
            ]);
        }
    }
}

// Initialize integration
add_action('plugins_loaded', function() {
    // Check if PeepSo is active
    if (defined('PEEPSO_VERSION')) {
        // Initialize PeepSo integration
        if (BCC_PeepSo_Pages_Integration::is_peepso_pages_active()) {
            // Add trust widget to page profile
            BCC_PeepSo_Pages_Integration::add_trust_widget_to_page();
            
            // Add trust badge to page header
            BCC_PeepSo_Pages_Integration::add_trust_score_to_page_header();
            
            // Add trust tab
            BCC_PeepSo_Pages_Integration::add_trust_tab_to_page();
        }
    }
});

// Hook into page creation
add_action('peepso_page_after_create', array('BCC_PeepSo_Pages_Integration', 'handle_page_creation'), 10, 2);

// Hook into page deletion
add_action('peepso_page_after_delete', function($page_id) {
    BCC_PeepSo_Pages_Integration::init_repositories();
    global $wpdb;
    
    // Get page owner before deletion
    $scores_table = bcc_trust_scores_table();
    $owner_id = $wpdb->get_var($wpdb->prepare(
        "SELECT page_owner_id FROM {$scores_table} WHERE page_id = %d",
        $page_id
    ));
    
    // Delete from scores table
    $wpdb->delete($scores_table, ['page_id' => $page_id], ['%d']);
    
    // Update user's page count if owner found
    if ($owner_id) {
        BCC_PeepSo_Pages_Integration::getUserInfoRepo()->decrementPageCount($owner_id, $page_id);
    }
});

// Note: bcc_trust_get_userInfoRepo() function removed from here - now in helpers.php

/**
 * Handle page creation from the frontend dialog
 * 
 * @param int $page_id The newly created page ID
 * @param array $data The page data submitted
 */
function bcc_trust_handle_page_creation($page_id, $data) {
    if (!$page_id) {
        return;
    }
    
    $owner_id = get_current_user_id();
    
    // Use the integration class to handle creation
    BCC_PeepSo_Pages_Integration::handle_page_creation($page_id, $owner_id);
}

/**
 * Handle AJAX page creation (catches the actual AJAX request)
 */
function bcc_trust_handle_ajax_page_creation() {
    // Check nonce
    if (!isset($_POST['_wpnonce']) || !wp_verify_nonce($_POST['_wpnonce'], 'peepso_page_create')) {
        return;
    }
    
    // We'll let PeepSo handle the actual creation, but we need to catch the result
    // This requires hooking into PeepSo's response filter
    add_filter('peepso_page_create_response', 'bcc_trust_catch_page_creation_response');
}

/**
 * Catch PeepSo's page creation response
 */
function bcc_trust_catch_page_creation_response($response) {
    if (isset($response['success']) && $response['success'] && isset($response['id'])) {
        $page_id = $response['id'];
        
        // Initialize the trust score
        bcc_trust_handle_page_creation($page_id, []);
        
        // Add trust score to response (optional)
        $response['trust_score'] = 50.0;
        $response['trust_tier'] = 'neutral';
    }
    
    return $response;
}

/**
 * Handle page save in admin
 */
function bcc_trust_handle_page_save($post_id, $post, $update) {
    // Avoid autosaves
    if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
        return;
    }
    
    // Check permissions
    if (!current_user_can('edit_post', $post_id)) {
        return;
    }
    
    // Check if this is a PeepSo page post type
    if ($post->post_type !== 'peepso-page') {
        return;
    }
    
    // Check if this is a new page or update
    if (!$update) {
        // New page created in admin
        bcc_trust_handle_page_creation($post_id, []);
    } else {
        // Existing page updated - check if owner changed
        $old_owner = get_post_meta($post_id, '_peepso_page_owner_id', true);
        $new_owner = $post->post_author;
        
        if ($old_owner && $old_owner != $new_owner) {
            bcc_trust_handle_owner_change($post_id, $new_owner);
        }
    }
}

/**
 * Handle page owner change
 */
function bcc_trust_handle_owner_change($page_id, $new_owner_id) {
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $userInfoRepo = bcc_trust_get_userInfoRepo(); // This now comes from helpers.php
    
    // Get old owner
    $old_owner = $wpdb->get_var($wpdb->prepare(
        "SELECT page_owner_id FROM {$scoresTable} WHERE page_id = %d",
        $page_id
    ));
    
    if ($old_owner && $old_owner != $new_owner_id) {
        // Update page owner in scores table
        $wpdb->update(
            $scoresTable,
            ['page_owner_id' => $new_owner_id],
            ['page_id' => $page_id],
            ['%d'],
            ['%d']
        );
        
        // Update page ownership in user_info table
        $userInfoRepo->transferPageOwnership($old_owner, $new_owner_id, $page_id);
        
        // Log the change
        if (function_exists('bcc_trust_log_audit')) {
            bcc_trust_log_audit('page_owner_changed', [
                'page_id' => $page_id,
                'old_owner' => $old_owner,
                'new_owner' => $new_owner_id
            ]);
        }
    }
}

/**
 * Helper: Increment user page count
 */
function bcc_trust_increment_user_page_count($user_id) {
    $repo = bcc_trust_get_userInfoRepo(); // This now comes from helpers.php
    
    // Note: We don't know the new page ID here, so this function is kept
    // for backward compatibility but should be replaced with direct repo calls
    $repo->incrementPageCount($user_id);
}

/**
 * Helper: Decrement user page count
 */
function bcc_trust_decrement_user_page_count($user_id) {
    $repo = bcc_trust_get_userInfoRepo(); // This now comes from helpers.php
    $repo->decrementPageCount($user_id);
}
if (!defined('ABSPATH')) exit;

function bcc_label_swap($translated, $text, $domain) {

    // Only target PeepSo-related domains
    if (
        $domain !== 'peepso-core' &&
        $domain !== 'peepso-block-theme' &&
        $domain !== 'pageso' &&
        $domain !== 'default'
    ) {
        return $translated;
    }

    if ($text === 'Pages') return 'Projects';
    if ($text === 'Page') return 'Project';
    if ($text === 'PeepSo Pages') return 'PeepSo Projects';

    return $translated;

}



add_filter('gettext', 'bcc_label_swap', 999, 3);
add_filter('gettext_with_context', function($translated, $text, $context, $domain) {
    return bcc_label_swap($translated, $text, $domain);
}, 999, 4);