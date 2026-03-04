<?php
/**
 * Trust Engine Admin Dashboard - Menu Registration
 *
 * @package BCC_Trust_Engine
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Register admin menu
 */
add_action('admin_menu', function () {
    add_menu_page(
        'Trust Engine Dashboard',
        'Trust Engine',
        'manage_options',
        'bcc-trust-dashboard',
        'bcc_trust_render_dashboard',
        'dashicons-shield',
        26
    );
});

/**
 * Main dashboard render function - delegates to dashboard-view.php
 */
function bcc_trust_render_dashboard() {
    if (!current_user_can('manage_options')) {
        return;
    }

    // Load the view which contains all the tab rendering
    $view_file = BCC_TRUST_PATH . 'includes/dashboard-view.php';
    if (file_exists($view_file)) {
        include $view_file;
    } else {
        wp_die('Dashboard view file not found at: ' . $view_file);
    }
}