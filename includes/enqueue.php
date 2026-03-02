<?php
/**
 * BCC Trust Engine - Asset Enqueue
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
    // Check if file exists before enqueuing
    $js_file = BCC_TRUST_URL . 'assets/js/trust-frontend.js';
    $css_file = BCC_TRUST_URL . 'assets/css/trust-frontend.css';
    
    // Frontend JavaScript
    if (file_exists(BCC_TRUST_PATH . 'assets/js/trust-frontend.js')) {
        wp_enqueue_script(
            'bcc-trust-frontend',
            $js_file,
            ['jquery'],
            BCC_TRUST_VERSION,
            true
        );

        // Localize script with data
        wp_localize_script(
            'bcc-trust-frontend',
            'bccTrust',
            [
                'nonce'      => wp_create_nonce('wp_rest'),
                'rest_url'   => esc_url_raw(rest_url('bcc-trust/v1/')),
                'logged_in'  => is_user_logged_in(),
                'user_id'    => get_current_user_id(),
                'ajax_url'   => admin_url('admin-ajax.php'),
                'debug'      => defined('WP_DEBUG') && WP_DEBUG
            ]
        );
    }

    // Frontend CSS
    if (file_exists(BCC_TRUST_PATH . 'assets/css/trust-frontend.css')) {
        wp_enqueue_style(
            'bcc-trust-frontend',
            $css_file,
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

/*
============================================================
ADMIN ASSETS
============================================================
*/

add_action('admin_enqueue_scripts', 'bcc_trust_enqueue_admin');

function bcc_trust_enqueue_admin($hook) {
    // Only load on our admin pages
    if (strpos($hook, 'bcc-trust') === false) {
        return;
    }

    $js_file = BCC_TRUST_URL . 'assets/js/admin.js';
    $css_file = BCC_TRUST_URL . 'assets/css/admin.css';

    // Admin JavaScript
    if (file_exists(BCC_TRUST_PATH . 'assets/js/admin.js')) {
        wp_enqueue_script(
            'bcc-trust-admin',
            $js_file,
            ['jquery', 'wp-api'],
            BCC_TRUST_VERSION,
            true
        );

        wp_localize_script(
            'bcc-trust-admin',
            'bccTrustAdmin',
            [
                'nonce'     => wp_create_nonce('wp_rest'),
                'rest_url'  => esc_url_raw(rest_url('bcc-trust/v1/')),
                'strings'   => [
                    'confirm_suspend'   => __('Are you sure you want to suspend this user?', 'bcc-trust'),
                    'confirm_unsuspend' => __('Are you sure you want to unsuspend this user?', 'bcc-trust'),
                    'error'             => __('An error occurred', 'bcc-trust'),
                    'success'           => __('Success', 'bcc-trust')
                ]
            ]
        );
    }

    // Admin CSS
    if (file_exists(BCC_TRUST_PATH . 'assets/css/admin.css')) {
        wp_enqueue_style(
            'bcc-trust-admin',
            $css_file,
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
    $primary_color = get_option('bcc_trust_primary_color', '#2196f3');
    $success_color = get_option('bcc_trust_success_color', '#4caf50');
    $warning_color = get_option('bcc_trust_warning_color', '#ff9800');
    $error_color   = get_option('bcc_trust_error_color', '#f44336');
    $neutral_color = get_option('bcc_trust_neutral_color', '#9e9e9e');

    return "
        :root {
            --bcc-primary: {$primary_color};
            --bcc-success: {$success_color};
            --bcc-warning: {$warning_color};
            --bcc-error: {$error_color};
            --bcc-neutral: {$neutral_color};
            
            --bcc-tier-elite: #ffd700;
            --bcc-tier-trusted: #4caf50;
            --bcc-tier-neutral: #9e9e9e;
            --bcc-tier-caution: #ff9800;
            --bcc-tier-risky: #f44336;
        }
    ";
}