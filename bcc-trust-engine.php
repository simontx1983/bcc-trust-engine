<?php
/**
 * Plugin Name: Blue Collar Crypto – Trust Engine
 * Description: Core reputation and trust system for Blue Collar Crypto. Handles votes, scoring, and reputation infrastructure.
 * Version: 1.0.0
 * Author: Blue Collar Labs LLC
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * ======================================================
 * CONSTANTS
 * ======================================================
 */

define('BCC_TRUST_VERSION', '1.0.0');
define('BCC_TRUST_PATH', plugin_dir_path(__FILE__));
define('BCC_TRUST_URL', plugin_dir_url(__FILE__));

/**
 * ======================================================
 * LOAD BOOTSTRAP
 * ======================================================
 */

require_once BCC_TRUST_PATH . 'bootstrap.php';

/**
 * ======================================================
 * ACTIVATION / UNINSTALL
 * ======================================================
 */

register_activation_hook(__FILE__, function () {
    // Load tables.php
    require_once BCC_TRUST_PATH . 'includes/database/tables.php';
    
    error_log('BCC Trust: Activation started');
    
    // Create tables - this will succeed even without PeepSo
    if (function_exists('bcc_trust_create_tables')) {
        $result = bcc_trust_create_tables();
        error_log('BCC Trust: Table creation result: ' . ($result ? 'success' : 'failed'));
    } else {
        error_log('BCC Trust: bcc_trust_create_tables function not found');
    }
    
    // Set initial database version
    update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
    
    // Clear any existing cron jobs first
    wp_clear_scheduled_hook('bcc_trust_daily_cleanup');
    wp_clear_scheduled_hook('bcc_trust_hourly_recalc');
    
    // Schedule cron jobs
    if (!wp_next_scheduled('bcc_trust_daily_cleanup')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_cleanup');
        error_log('BCC Trust: Scheduled daily cleanup');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_recalc')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_recalc');
        error_log('BCC Trust: Scheduled hourly recalculation');
    }
    
    error_log('BCC Trust: Activation completed');
});

register_deactivation_hook(__FILE__, function () {
    // Clear scheduled cron jobs
    wp_clear_scheduled_hook('bcc_trust_daily_cleanup');
    wp_clear_scheduled_hook('bcc_trust_hourly_recalc');
    
    error_log('BCC Trust: Deactivation completed');
});

/**
 * Render trust widget for a PeepSo page
 * 
 * @param array $args Widget arguments
 */
function bcc_trust_render_widget($args = []) {
    $page_id = isset($args['page_id']) ? intval($args['page_id']) : 0;
    
    if (!$page_id) {
        return;
    }
    
    $show_actions = isset($args['show_actions']) ? $args['show_actions'] : true;
    
    ?>
    <div class="bcc-trust-wrapper" 
         data-page-id="<?php echo esc_attr($page_id); ?>"
         data-target="<?php echo esc_attr($page_id); ?>">
        
        <div class="bcc-trust-header">
            <strong>Trust Score:</strong>
            <span class="bcc-score-value">Loading...</span>
            <span class="bcc-tier-label"></span>
        </div>
        
        <div class="bcc-trust-details" style="font-size:0.9em; color:#666; margin:5px 0;">
            <span class="bcc-confidence-level"></span>
            <span class="bcc-vote-total"></span>
            <span class="bcc-endorsement-total"></span>
        </div>
        
        <?php if ($show_actions && is_user_logged_in()): ?>
        <div class="bcc-trust-actions" style="margin-top:10px;">
            <button class="bcc-vote-button button button-small" data-type="1">⬆ Upvote</button>
            <button class="bcc-vote-button button button-small" data-type="-1">⬇ Downvote</button>
            <button class="bcc-endorse-button button button-small">⭐ Endorse</button>
        </div>
        <?php endif; ?>
        
        <div class="bcc-status-message" style="margin-top:8px; min-height:20px;"></div>
    </div>
    <?php
}

// Alias for backward compatibility
if (!function_exists('bcc_trust_display_widget')) {
    function bcc_trust_display_widget($page_id, $show_actions = true) {
        bcc_trust_render_widget([
            'page_id' => $page_id,
            'show_actions' => $show_actions
        ]);
    }
}

/**
 * Hook into PeepSo page creation to initialize trust scores
 */

// When a page is created through the dialog
add_action('peepso_action_page_create_after', 'bcc_trust_handle_page_creation', 10, 2);

// Alternative: Hook into PeepSo's AJAX page creation
add_action('wp_ajax_peepso_page_create', 'bcc_trust_handle_ajax_page_creation', 5); // Priority 5 to run before PeepSo's handler

// When page is published/updated via admin
add_action('save_post_peepso-page', 'bcc_trust_handle_page_save', 10, 3);

// When page owner changes
add_action('peepso_page_after_owner_change', 'bcc_trust_handle_owner_change', 10, 2);