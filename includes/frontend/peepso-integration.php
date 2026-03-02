<?php
/**
 * PeepSo Pages Integration for Trust Engine
 * 
 * @package BCC_Trust_Engine
 * @subpackage Frontend
 * @version 1.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BCC_PeepSo_Pages_Integration {
    
    /**
     * Check if PeepSo Pages extension is active
     */
    public static function is_peepso_pages_active() {
        return class_exists('PeepSoPage') || 
               defined('PEEPSO_PAGES_PLUGIN_VERSION') ||
               function_exists('PeepSoPage');
    }
    
    /**
     * Get page data with trust score
     */
    public static function get_page_with_trust_score($page_id) {
        global $wpdb;
        
        // Get PeepSo page data
        $pages_table = $wpdb->prefix . 'peepso_pages';
        $page = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$pages_table} WHERE ID = %d",
            $page_id
        ));
        
        if (!$page) {
            return null;
        }
        
        // Get trust score
        $scores_table = bcc_trust_scores_table();
        $score = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$scores_table} WHERE page_id = %d",
            $page_id
        ));
        
        // Get page owner
        $page_owner = bcc_trust_get_page_owner($page_id);
        
        return (object) array(
            'page' => $page,
            'trust_score' => $score ?: self::get_default_score($page_id, $page_owner),
            'owner_id' => $page_owner
        );
    }
    
    /**
     * Get default score for new page
     */
    private static function get_default_score($page_id, $owner_id) {
        return (object) array(
            'page_id' => $page_id,
            'page_owner_id' => $owner_id,
            'total_score' => 50.00,
            'positive_score' => 0,
            'negative_score' => 0,
            'vote_count' => 0,
            'unique_voters' => 0,
            'confidence_score' => 0,
            'reputation_tier' => 'neutral',
            'endorsement_count' => 0,
            'last_calculated_at' => current_time('mysql')
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
                    <div class="bcc-page-trust-badge" style="display: inline-block; margin-left: 10px; padding: 3px 8px; border-radius: 3px; background: <?php echo $tier_info['color']; ?>; color: #fff; font-size: 12px;">
                        <?php echo $tier_info['icon']; ?> <?php echo number_format($score->total_score, 1); ?> (<?php echo $tier_info['label']; ?>)
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
        // Initialize trust score for new page
        $scores_table = bcc_trust_scores_table();
        global $wpdb;
        
        $wpdb->insert(
            $scores_table,
            array(
                'page_id' => $page_id,
                'page_owner_id' => $user_id,
                'total_score' => 50.00,
                'last_calculated_at' => current_time('mysql')
            ),
            array('%d', '%d', '%f', '%s')
        );
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
    global $wpdb;
    $scores_table = bcc_trust_scores_table();
    $wpdb->delete($scores_table, ['page_id' => $page_id], ['%d']);
});

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
    
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $userInfoTable = bcc_trust_user_info_table();
    
    // Get the page owner (usually current user)
    $owner_id = get_current_user_id();
    
    // Check if page already has a score entry
    $exists = $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM {$scoresTable} WHERE page_id = %d",
        $page_id
    ));
    
    if (!$exists) {
        // Initialize trust score for the new page
        $wpdb->insert(
            $scoresTable,
            [
                'page_id' => $page_id,
                'page_owner_id' => $owner_id,
                'total_score' => 50.00, // Start at neutral
                'positive_score' => 0,
                'negative_score' => 0,
                'vote_count' => 0,
                'unique_voters' => 0,
                'confidence_score' => 0.5,
                'reputation_tier' => 'neutral',
                'endorsement_count' => 0,
                'last_calculated_at' => current_time('mysql')
            ],
            [
                '%d', '%d', '%f', '%f', '%f', 
                '%d', '%d', '%f', '%s', '%d', '%s'
            ]
        );
        
        // Log the creation
        bcc_trust_log_audit('page_created', [
            'page_id' => $page_id,
            'user_id' => $owner_id,
            'action' => 'create'
        ]);
        
        // Update user's page count in user_info table
        bcc_trust_increment_user_page_count($owner_id);
    }
}

/**
 * Handle AJAX page creation (catches the actual AJAX request)
 */
function bcc_trust_handle_ajax_page_creation() {
    // Check nonce
    if (!wp_verify_nonce($_POST['_wpnonce'], 'peepso_page_create')) {
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
    
    // Check if this is a new page or update
    if (!$update) {
        // New page created in admin
        bcc_trust_handle_page_creation($post_id, []);
    } else {
        // Existing page updated - check if owner changed
        $old_owner = get_post_meta($post_id, '_peepso_page_owner_id', true);
        $new_owner = $post->post_author;
        
        if ($old_owner && $old_owner != $new_owner) {
            bcc_trust_handle_owner_change($page_id, $new_owner);
        }
    }
}

/**
 * Handle page owner change
 */
function bcc_trust_handle_owner_change($page_id, $new_owner_id) {
    global $wpdb;
    
    $scoresTable = bcc_trust_scores_table();
    $userInfoTable = bcc_trust_user_info_table();
    
    // Get old owner
    $old_owner = $wpdb->get_var($wpdb->prepare(
        "SELECT page_owner_id FROM {$scoresTable} WHERE page_id = %d",
        $page_id
    ));
    
    if ($old_owner) {
        // Update page owner in scores table
        $wpdb->update(
            $scoresTable,
            ['page_owner_id' => $new_owner_id],
            ['page_id' => $page_id],
            ['%d'],
            ['%d']
        );
        
        // Decrement old owner's page count
        if ($old_owner != $new_owner_id) {
            bcc_trust_decrement_user_page_count($old_owner);
            bcc_trust_increment_user_page_count($new_owner_id);
        }
        
        // Log the change
        bcc_trust_log_audit('page_owner_changed', [
            'page_id' => $page_id,
            'old_owner' => $old_owner,
            'new_owner' => $new_owner_id
        ]);
    }
}

/**
 * Helper: Increment user page count
 */
function bcc_trust_increment_user_page_count($user_id) {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();
    
    // Update the user's page count
    $wpdb->query($wpdb->prepare(
        "UPDATE {$userInfoTable} SET pages_owned = pages_owned + 1 WHERE user_id = %d",
        $user_id
    ));
    
    // Also update the page_ids_owned JSON if needed
    $user_info = $wpdb->get_row($wpdb->prepare(
        "SELECT page_ids_owned FROM {$userInfoTable} WHERE user_id = %d",
        $user_id
    ));
    
    if ($user_info) {
        $page_ids = [];
        if (!empty($user_info->page_ids_owned)) {
            $page_ids = json_decode($user_info->page_ids_owned, true);
            if (!is_array($page_ids)) {
                $page_ids = [];
            }
        }
        
        // Note: We don't know the new page ID here yet, so we'll need to handle
        // this separately after page creation
    }
}

/**
 * Helper: Decrement user page count
 */
function bcc_trust_decrement_user_page_count($user_id) {
    global $wpdb;
    
    $userInfoTable = bcc_trust_user_info_table();
    
    $wpdb->query($wpdb->prepare(
        "UPDATE {$userInfoTable} SET pages_owned = GREATEST(pages_owned - 1, 0) WHERE user_id = %d",
        $user_id
    ));
}