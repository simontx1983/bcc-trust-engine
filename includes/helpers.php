<?php
if (!defined('ABSPATH')) exit;

/**
 * Helper functions for BCC Trust Engine
 * 
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

// ======================================================
// COLOR HELPER FUNCTIONS
// ======================================================

/**
 * Get color for score
 */
function bcc_trust_get_score_color($score) {
    if ($score >= 80) return '#f44336'; // Red - High risk
    if ($score >= 60) return '#ff9800'; // Orange - Medium-high risk
    if ($score >= 40) return '#2196f3'; // Blue - Medium risk
    if ($score >= 20) return '#4caf50'; // Green - Low risk
    return '#8bc34a'; // Light green - Minimal risk
}

/**
 * Get color for risk level
 */
function bcc_trust_get_risk_color($risk_level) {
    $colors = [
        'critical' => '#9c27b0', // Purple
        'high' => '#f44336',      // Red
        'medium' => '#ff9800',    // Orange
        'low' => '#2196f3',       // Blue
        'minimal' => '#4caf50',   // Green
        'unknown' => '#9e9e9e'    // Grey
    ];
    return $colors[$risk_level] ?? $colors['unknown'];
}

/**
 * Get color for tier
 */
function bcc_trust_get_tier_color($tier) {
    $colors = [
        'elite' => '#ffd700',      // Gold
        'trusted' => '#4caf50',    // Green
        'neutral' => '#9e9e9e',    // Grey
        'caution' => '#ff9800',    // Orange
        'risky' => '#f44336',      // Red
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
    if (!$datetime) {
        return 'Never';
    }
    
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
 * Get trust tier label with color and icon
 */
function bcc_trust_get_tier_info($tier) {
    $tiers = [
        'elite' => [
            'label' => 'Elite', 
            'color' => '#ffd700', 
            'icon' => '👑',
            'description' => 'Highly trusted and influential'
        ],
        'trusted' => [
            'label' => 'Trusted', 
            'color' => '#4caf50', 
            'icon' => '⭐',
            'description' => 'Reliable and consistent'
        ],
        'neutral' => [
            'label' => 'Neutral', 
            'color' => '#9e9e9e', 
            'icon' => '➖',
            'description' => 'Average trust score'
        ],
        'caution' => [
            'label' => 'Caution', 
            'color' => '#ff9800', 
            'icon' => '⚠️',
            'description' => 'Some concerns detected'
        ],
        'risky' => [
            'label' => 'Risky', 
            'color' => '#f44336', 
            'icon' => '❗',
            'description' => 'High risk, proceed with caution'
        ],
    ];
    return $tiers[$tier] ?? $tiers['neutral'];
}

/**
 * Get risk level info
 */
function bcc_trust_get_risk_info($level) {
    $levels = [
        'critical' => [
            'label' => 'Critical', 
            'color' => '#9c27b0', 
            'action' => 'Immediate review required'
        ],
        'high' => [
            'label' => 'High', 
            'color' => '#f44336', 
            'action' => 'Review soon'
        ],
        'medium' => [
            'label' => 'Medium', 
            'color' => '#ff9800', 
            'action' => 'Monitor'
        ],
        'low' => [
            'label' => 'Low', 
            'color' => '#2196f3', 
            'action' => 'Normal activity'
        ],
        'minimal' => [
            'label' => 'Minimal', 
            'color' => '#4caf50', 
            'action' => 'Trusted'
        ],
    ];
    return $levels[$level] ?? $levels['minimal'];
}

// ======================================================
// USER INFO FUNCTIONS (using user_info table)
// ======================================================

/**
 * Get user's trust badge HTML from user_info table
 */
function bcc_trust_get_user_badge($user_id) {
    if (!$user_id) {
        return '';
    }
    
    // Get user info from repository
    if (class_exists('\\BCCTrust\\Repositories\\UserInfoRepository')) {
        try {
            $repo = new \BCCTrust\Repositories\UserInfoRepository();
            $userInfo = $repo->getByUserId($user_id);
            
            if ($userInfo) {
                $fraud_score = $userInfo->fraud_score;
                $trust_rank = $userInfo->trust_rank;
                $risk_level = $userInfo->risk_level;
                $is_verified = $userInfo->is_verified;
                
                // Build badge based on user data
                $badge = '<span class="bcc-user-badge">';
                
                if ($fraud_score > 70) {
                    $badge .= '<span class="bcc-risk-critical" title="Critical Risk User">🔴 Critical Risk</span>';
                } elseif ($fraud_score > 50) {
                    $badge .= '<span class="bcc-risk-high" title="High Risk User">⚠️ High Risk</span>';
                } elseif ($fraud_score > 30) {
                    $badge .= '<span class="bcc-risk-medium" title="Medium Risk User">⚡ Medium Risk</span>';
                } elseif ($trust_rank > 0.8) {
                    $badge .= '<span class="bcc-trust-high" title="Highly Trusted">🌟 Trusted</span>';
                } elseif ($is_verified) {
                    $badge .= '<span class="bcc-verified" title="Verified User">✅ Verified</span>';
                }
                
                $badge .= '</span>';
                return $badge;
            }
        } catch (Exception $e) {
            bcc_trust_debug_log('Error getting user badge', ['user_id' => $user_id, 'error' => $e->getMessage()]);
        }
    }
    
    // Fallback to legacy meta if repository not available
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
 * Get fraud alert badge for a page
 */
function bcc_trust_get_fraud_alert_badge($page_id) {
    if (!$page_id) {
        return '';
    }
    
    if (class_exists('\\BCCTrust\\Repositories\\ScoreRepository')) {
        try {
            $repo = new \BCCTrust\Repositories\ScoreRepository();
            $score = $repo->getByPageId($page_id);
            
            if ($score && $score->hasFraudAlerts()) {
                $count = $score->getFraudAlertCount();
                return '<span class="bcc-fraud-alert-badge" title="Suspicious activity detected">⚠️ Fraud Alert (' . $count . ')</span>';
            }
        } catch (Exception $e) {
            bcc_trust_debug_log('Error getting fraud alert badge', ['page_id' => $page_id, 'error' => $e->getMessage()]);
        }
    }
    
    return '';
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
 * Check if current page is a PeepSo Page (not group or profile)
 */
function bcc_trust_is_peepso_page_type() {
    if (!function_exists('is_peepso_page')) {
        return false;
    }
    
    return is_peepso_page() && 
           (get_query_var('page') || get_query_var('peepso-page'));
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
    
    // Check if it's a valid post type (page, peepso-page, etc.)
    $valid_types = ['page', 'peepso-page', 'post'];
    if (!in_array($post->post_type, $valid_types)) {
        return false;
    }
    
    return $page_id;
}

// ======================================================
// FORMATTING FUNCTIONS
// ======================================================

/**
 * Format trust score for display
 */
function bcc_trust_format_score($score, $decimals = 1) {
    return number_format($score, $decimals);
}

/**
 * Format confidence as percentage
 */
function bcc_trust_format_confidence($confidence) {
    return round($confidence * 100) . '%';
}

// ======================================================
// DEBUG FUNCTIONS
// ======================================================

/**
 * Debug log helper
 */
function bcc_trust_debug_log($message, $data = []) {
    if (defined('WP_DEBUG') && WP_DEBUG) {
        $log_message = 'BCC Trust: ' . $message;
        if (!empty($data)) {
            $log_message .= ' - ' . json_encode($data);
        }
        error_log($log_message);
    }
}

/**
 * Get memory usage in human readable format
 */
function bcc_trust_memory_usage() {
    $size = memory_get_usage(true);
    $unit = ['b', 'kb', 'mb', 'gb', 'tb', 'pb'];
    return @round($size / pow(1024, ($i = floor(log($size, 1024)))), 2) . ' ' . $unit[$i];
}

/**
 * Get execution time
 */
function bcc_trust_execution_time($start = null) {
    if ($start === null) {
        return microtime(true);
    }
    return round((microtime(true) - $start) * 1000, 2) . 'ms';
}

// ======================================================
// ARRAY HELPER FUNCTIONS
// ======================================================

/**
 * Safe json_decode with error handling
 */
function bcc_trust_json_decode($json, $assoc = true) {
    if (empty($json)) {
        return $assoc ? [] : null;
    }
    
    $data = json_decode($json, $assoc);
    
    if (json_last_error() !== JSON_ERROR_NONE) {
        bcc_trust_debug_log('JSON decode error', ['error' => json_last_error_msg()]);
        return $assoc ? [] : null;
    }
    
    return $data;
}

function bcc_trust_recalculate_page_score($page_id) {
    if (class_exists('BCC_Page_Score_Calculator')) {
        $calculator = new BCC_Page_Score_Calculator();
        return $calculator->recalculate_page_score($page_id);
    }
    return false;
}