<?php
if (!defined('ABSPATH')) exit;

/**
 * Helper functions for BCC Trust Engine
 */

// ======================================================
// COLOR HELPER FUNCTIONS
// ======================================================

/**
 * Get color for score
 */
function bcc_trust_get_score_color($score) {
    if ($score >= 80) return '#f44336';
    if ($score >= 60) return '#ff9800';
    if ($score >= 40) return '#2196f3';
    if ($score >= 20) return '#4caf50';
    return '#8bc34a';
}

/**
 * Get color for risk level
 */
function bcc_trust_get_risk_color($risk_level) {
    $colors = [
        'critical' => '#9c27b0',
        'high' => '#f44336',
        'medium' => '#ff9800',
        'low' => '#2196f3',
        'minimal' => '#4caf50',
        'unknown' => '#9e9e9e'
    ];
    return $colors[$risk_level] ?? $colors['unknown'];
}

/**
 * Get color for tier
 */
function bcc_trust_get_tier_color($tier) {
    $colors = [
        'elite' => '#ffd700',
        'trusted' => '#4caf50',
        'neutral' => '#9e9e9e',
        'caution' => '#ff9800',
        'risky' => '#f44336',
        'insufficient_data' => '#9e9e9e'
    ];
    return $colors[$tier] ?? '#9e9e9e';
}

// ======================================================
// IP HELPER FUNCTIONS
// ======================================================

/**
 * Get client IP address with proxy support
 */
function bcc_trust_get_client_ip() {
    $ipHeaders = [
        'HTTP_CF_CONNECTING_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR'
    ];

    foreach ($ipHeaders as $header) {
        if (!empty($_SERVER[$header])) {
            $ip = $_SERVER[$header];
            if ($header === 'HTTP_X_FORWARDED_FOR') {
                $ips = explode(',', $ip);
                $ip = trim($ips[0]);
            }
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return sanitize_text_field($ip);
            }
        }
    }
    return '0.0.0.0';
}

// ======================================================
// TIME HELPER FUNCTIONS
// ======================================================

/**
 * Format time ago
 */
function bcc_trust_time_ago($datetime) {
    $time = strtotime($datetime);
    $now = time();
    $diff = $now - $time;

    if ($diff < 60) {
        return $diff . ' seconds ago';
    } elseif ($diff < 3600) {
        $mins = floor($diff / 60);
        return $mins . ' minute' . ($mins > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 86400) {
        $hours = floor($diff / 3600);
        return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
    } elseif ($diff < 2592000) {
        $days = floor($diff / 86400);
        return $days . ' day' . ($days > 1 ? 's' : '') . ' ago';
    } else {
        return date('Y-m-d H:i', $time);
    }
}

// ======================================================
// TRUST/RISK INFO FUNCTIONS
// ======================================================

/**
 * Get trust tier label with color
 */
function bcc_trust_get_tier_info($tier) {
    $tiers = [
        'elite' => ['label' => 'Elite', 'color' => '#ffd700', 'icon' => '👑'],
        'trusted' => ['label' => 'Trusted', 'color' => '#4caf50', 'icon' => '⭐'],
        'neutral' => ['label' => 'Neutral', 'color' => '#9e9e9e', 'icon' => '➖'],
        'caution' => ['label' => 'Caution', 'color' => '#ff9800', 'icon' => '⚠️'],
        'risky' => ['label' => 'Risky', 'color' => '#f44336', 'icon' => '❗'],
    ];
    return $tiers[$tier] ?? $tiers['neutral'];
}

/**
 * Get risk level info
 */
function bcc_trust_get_risk_info($level) {
    $levels = [
        'critical' => ['label' => 'Critical', 'color' => '#9c27b0', 'action' => 'Immediate review'],
        'high' => ['label' => 'High', 'color' => '#f44336', 'action' => 'Review soon'],
        'medium' => ['label' => 'Medium', 'color' => '#ff9800', 'action' => 'Monitor'],
        'low' => ['label' => 'Low', 'color' => '#2196f3', 'action' => 'Normal'],
        'minimal' => ['label' => 'Minimal', 'color' => '#4caf50', 'action' => 'Trusted'],
    ];
    return $levels[$level] ?? $levels['minimal'];
}

// ======================================================
// DEBUG FUNCTIONS
// ======================================================

/**
 * Debug log helper
 */
function bcc_trust_debug_log($message, $data = []) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        error_log('BCC Trust: ' . $message . ' - ' . json_encode($data));
    }
}

// ======================================================
// VALIDATION FUNCTIONS
// ======================================================

/**
 * Check if current page is a PeepSo page
 */
function bcc_trust_is_peepso_page() {
    return function_exists('is_peepso_page') && is_peepso_page();
}

/**
 * Get user's trust level badge HTML
 */
function bcc_trust_get_user_badge($user_id) {
    $fraud_score = (int) get_user_meta($user_id, 'bcc_trust_fraud_score', true);
    $trust_rank = (float) get_user_meta($user_id, 'bcc_trust_graph_rank', true);
    
    if ($fraud_score > 70) {
        return '<span class="bcc-user-badge bcc-risk-high" title="High Risk User">⚠️ High Risk</span>';
    } elseif ($fraud_score > 40) {
        return '<span class="bcc-user-badge bcc-risk-medium" title="Medium Risk User">⚡ Medium Risk</span>';
    } elseif ($trust_rank > 0.8) {
        return '<span class="bcc-user-badge bcc-trust-high" title="Highly Trusted">🌟 Trusted</span>';
    }
    return '';
}

/**
 * Sanitize and validate page ID
 */
function bcc_trust_validate_page_id($page_id) {
    $page_id = absint($page_id);
    if (!$page_id) {
        return false;
    }
    
    $post = get_post($page_id);
    if (!$post) {
        return false;
    }
    
    return $page_id;
}

/**
 * Get memory usage in human readable format
 */
function bcc_trust_memory_usage() {
    $size = memory_get_usage(true);
    $unit = ['b', 'kb', 'mb', 'gb', 'tb', 'pb'];
    return @round($size / pow(1024, ($i = floor(log($size, 1024)))), 2) . ' ' . $unit[$i];
}
