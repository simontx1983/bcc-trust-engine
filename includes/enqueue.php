<?php
/**
 * BCC Trust Engine - Asset Enqueue
 * 
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

/*
============================================================
FRONTEND ASSETS
============================================================
*/

add_action('wp_enqueue_scripts', 'bcc_trust_enqueue_frontend');

function bcc_trust_enqueue_frontend() {
    $js_dir = BCC_TRUST_URL . 'assets/js/';
    $css_dir = BCC_TRUST_URL . 'assets/css/';
    $js_path = BCC_TRUST_PATH . 'assets/js/';
    $css_path = BCC_TRUST_PATH . 'assets/css/';
    
    $fingerprint_loaded = false;
    
    // ======================================================
    // Device Fingerprinting (only on pages with widgets)
    // ======================================================
    if (bcc_trust_should_load_fingerprint()) {
        if (file_exists($js_path . 'fingerprint.js')) {
            wp_enqueue_script(
                'bcc-trust-fingerprint',
                $js_dir . 'fingerprint.js',
                [], // No dependencies
                BCC_TRUST_VERSION,
                true
            );
            $fingerprint_loaded = true;
        }
    }
    
    // ======================================================
    // Frontend Main JavaScript
    // ======================================================
    if (file_exists($js_path . 'trust-frontend.js')) {
        // Set up dependencies - only include fingerprint if it was loaded
        $dependencies = ['jquery'];
        if ($fingerprint_loaded) {
            $dependencies[] = 'bcc-trust-fingerprint';
        }
        
        wp_enqueue_script(
            'bcc-trust-frontend',
            $js_dir . 'trust-frontend.js',
            $dependencies,
            BCC_TRUST_VERSION,
            true
        );

        // Localize script with data
        wp_localize_script(
            'bcc-trust-frontend',
            'bccTrust',
            [
                'nonce'               => wp_create_nonce('wp_rest'),
                'rest_url'            => esc_url_raw(rest_url('bcc-trust/v1/')),
                'logged_in'           => is_user_logged_in(),
                'user_id'             => get_current_user_id(),
                'ajax_url'            => admin_url('admin-ajax.php'),
                'login_url'            => wp_login_url(),
                'fingerprint_enabled'  => bcc_trust_is_fingerprint_enabled() && $fingerprint_loaded,
                'debug'                => (defined('WP_DEBUG') && WP_DEBUG)
            ]
        );
    }

    // ======================================================
    // Frontend CSS
    // ======================================================
    if (file_exists($css_path . 'trust-frontend.css')) {
        wp_enqueue_style(
            'bcc-trust-frontend',
            $css_dir . 'trust-frontend.css',
            [],
            BCC_TRUST_VERSION
        );

        // Dynamic CSS variables
        wp_add_inline_style(
            'bcc-trust-frontend',
            bcc_trust_get_dynamic_css()
        );
    }
}

/**
 * Check if fingerprint should be loaded on this page
 */
function bcc_trust_should_load_fingerprint() {
    // Don't load in admin
    if (is_admin()) {
        return false;
    }
    
    // Check if there's a trust widget on the page
    if (is_singular()) {
        $post = get_post();
        if ($post && has_shortcode($post->post_content, 'bcc_trust')) {
            return true;
        }
    }
    
    // Load if it's a PeepSo page
    if (function_exists('is_peepso_page') && is_peepso_page()) {
        return true;
    }
    
    // Check if any widget is active that might need it
    if (is_active_widget(false, false, 'bcc_trust_widget', true)) {
        return true;
    }
    
    // Allow filtering
    return apply_filters('bcc_trust_load_fingerprint', false);
}

/**
 * Check if fingerprinting is enabled
 */
function bcc_trust_is_fingerprint_enabled() {
    return apply_filters('bcc_trust_fingerprint_enabled', true);
}

/*
============================================================
ADMIN ASSETS
============================================================
*/

add_action('admin_enqueue_scripts', 'bcc_trust_enqueue_admin');

function bcc_trust_enqueue_admin($hook) {
    // Only load on our admin pages
    $trust_pages = ['bcc-trust-dashboard', 'bcc-trust-moderation', 'bcc-trust-settings', 'bcc-trust-logs'];
    $current_page = isset($_GET['page']) ? sanitize_key($_GET['page']) : '';
    
    if (!in_array($current_page, $trust_pages)) {
        return;
    }

    $js_dir = BCC_TRUST_URL . 'assets/js/';
    $css_dir = BCC_TRUST_URL . 'assets/css/';
    $js_path = BCC_TRUST_PATH . 'assets/js/';
    $css_path = BCC_TRUST_PATH . 'assets/css/';

    // ======================================================
    // Chart.js for admin charts
    // ======================================================
    if ($current_page === 'bcc-trust-dashboard') {
        wp_enqueue_script(
            'chart-js',
            'https://cdn.jsdelivr.net/npm/chart.js@3.9.1/dist/chart.min.js',
            [],
            '3.9.1',
            true
        );
    }

    // ======================================================
    // Admin JavaScript
    // ======================================================
    if (file_exists($js_path . 'admin.js')) {
        $dependencies = ['jquery', 'wp-api'];
        
        // Add jQuery UI tooltip if available
        if (wp_script_is('jquery-ui-tooltip', 'registered')) {
            $dependencies[] = 'jquery-ui-tooltip';
        }
        
        // Add Chart.js as dependency if on dashboard and it was loaded
        if ($current_page === 'bcc-trust-dashboard' && wp_script_is('chart-js', 'enqueued')) {
            $dependencies[] = 'chart-js';
        }
        
        wp_enqueue_script(
            'bcc-trust-admin',
            $js_dir . 'admin.js',
            $dependencies,
            BCC_TRUST_VERSION,
            true
        );

        wp_localize_script(
            'bcc-trust-admin',
            'bccTrustAdmin',
            [
                'nonce'         => wp_create_nonce('wp_rest'),
                'rest_url'      => esc_url_raw(rest_url('bcc-trust/v1/')),
                'current_page'  => $current_page,
                'strings'       => [
                    // Confirmation messages
                    'confirm_suspend'           => __('Are you sure you want to suspend this user?', 'bcc-trust'),
                    'confirm_unsuspend'         => __('Are you sure you want to unsuspend this user?', 'bcc-trust'),
                    'confirm_clear_votes'        => __('Are you sure you want to clear all votes? This cannot be undone.', 'bcc-trust'),
                    'confirm_clear_fingerprints' => __('Are you sure you want to clear all device fingerprints?', 'bcc-trust'),
                    'confirm_reanalyze'          => __('Reanalyze this user? This may take a moment.', 'bcc-trust'),
                    'confirm_bulk_suspend'       => __('Are you sure you want to suspend the selected users?', 'bcc-trust'),
                    'confirm_bulk_unsuspend'     => __('Are you sure you want to unsuspend the selected users?', 'bcc-trust'),
                    'confirm_bulk_clear_votes'   => __('Clear votes for selected users? This cannot be undone.', 'bcc-trust'),
                    'confirm_bulk_reanalyze'     => __('Reanalyze selected users? This may take a moment.', 'bcc-trust'),
                    
                    // Status messages
                    'error'                      => __('An error occurred', 'bcc-trust'),
                    'success'                    => __('Success', 'bcc-trust'),
                    'loading'                    => __('Loading...', 'bcc-trust'),
                    'no_data'                    => __('No data available', 'bcc-trust'),
                    'select_items'               => __('Please select at least one item', 'bcc-trust'),
                    
                    // Tooltips
                    'tooltip_fraud_score'         => __('Higher score indicates higher risk', 'bcc-trust'),
                    'tooltip_confidence'          => __('Confidence level based on data volume', 'bcc-trust'),
                    'tooltip_vote_weight'         => __('How much this user\'s vote counts', 'bcc-trust'),
                ]
            ]
        );
    }

    // ======================================================
    // Admin CSS
    // ======================================================
    if (file_exists($css_path . 'admin.css')) {
        wp_enqueue_style(
            'bcc-trust-admin',
            $css_dir . 'admin.css',
            [],
            BCC_TRUST_VERSION
        );
    }
}

/*
============================================================
DYNAMIC CSS
============================================================
*/

function bcc_trust_get_dynamic_css() {
    $primary_color   = get_option('bcc_trust_primary_color', '#2196f3');
    $success_color   = get_option('bcc_trust_success_color', '#4caf50');
    $warning_color   = get_option('bcc_trust_warning_color', '#ff9800');
    $error_color     = get_option('bcc_trust_error_color', '#f44336');
    $neutral_color   = get_option('bcc_trust_neutral_color', '#9e9e9e');
    
    $critical_color  = get_option('bcc_trust_critical_color', '#9c27b0');
    $info_color      = get_option('bcc_trust_info_color', '#00bcd4');

    return "
        :root {
            --bcc-primary: {$primary_color};
            --bcc-success: {$success_color};
            --bcc-warning: {$warning_color};
            --bcc-error: {$error_color};
            --bcc-neutral: {$neutral_color};
            --bcc-critical: {$critical_color};
            --bcc-info: {$info_color};
            
            --bcc-tier-elite: #ffd700;
            --bcc-tier-trusted: #4caf50;
            --bcc-tier-neutral: #9e9e9e;
            --bcc-tier-caution: #ff9800;
            --bcc-tier-risky: #f44336;
            
            --bcc-risk-critical: #9c27b0;
            --bcc-risk-high: #f44336;
            --bcc-risk-medium: #ff9800;
            --bcc-risk-low: #2196f3;
            --bcc-risk-minimal: #4caf50;
        }
        
        .bcc-tier-elite { color: var(--bcc-tier-elite); }
        .bcc-tier-trusted { color: var(--bcc-tier-trusted); }
        .bcc-tier-neutral { color: var(--bcc-tier-neutral); }
        .bcc-tier-caution { color: var(--bcc-tier-caution); }
        .bcc-tier-risky { color: var(--bcc-tier-risky); }
        
        .bcc-risk-critical { color: var(--bcc-risk-critical); }
        .bcc-risk-high { color: var(--bcc-risk-high); }
        .bcc-risk-medium { color: var(--bcc-risk-medium); }
        .bcc-risk-low { color: var(--bcc-risk-low); }
        .bcc-risk-minimal { color: var(--bcc-risk-minimal); }
    ";
}

/*
============================================================
CONDITIONAL LOADING
============================================================
*/

/**
 * Check if trust widget should be loaded on current page
 */
add_filter('bcc_trust_should_load', 'bcc_trust_check_page_for_widget');

function bcc_trust_check_page_for_widget($should_load) {
    if ($should_load) {
        return true;
    }
    
    // Check if current post has the shortcode
    if (is_singular()) {
        $post = get_post();
        if ($post && has_shortcode($post->post_content, 'bcc_trust')) {
            return true;
        }
    }
    
    // Check if it's a PeepSo page
    if (function_exists('is_peepso_page') && is_peepso_page()) {
        return true;
    }
    
    return $should_load;
}

/**
 * Preload REST API data for faster rendering
 */
add_action('wp_head', 'bcc_trust_preload_rest_data');

function bcc_trust_preload_rest_data() {
    if (!bcc_trust_should_load_fingerprint()) {
        return;
    }
    
    // Only preload on pages with a specific page ID
    $page_id = get_queried_object_id();
    if (!$page_id) {
        return;
    }
    
    ?>
    <link rel="preload" href="<?php echo esc_url(rest_url('bcc-trust/v1/page/' . $page_id . '/score')); ?>" as="fetch" crossorigin>
    <?php
}