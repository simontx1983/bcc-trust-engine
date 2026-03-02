<?php
if (!defined('ABSPATH')) {
    exit;
}

/*
============================================================
DATABASE
============================================================
*/
require_once BCC_TRUST_PATH . 'includes/database/tables.php';
require_once BCC_TRUST_PATH . 'includes/database/queries.php';

/*
============================================================
SECURITY - Core
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Security/TransactionManager.php';
require_once BCC_TRUST_PATH . 'app/Security/RateLimiter.php';
require_once BCC_TRUST_PATH . 'app/Security/AuditLogger.php';
require_once BCC_TRUST_PATH . 'app/Security/FraudDetector.php';


/*
============================================================
VALUE OBJECTS - NEW
============================================================
*/
require_once BCC_TRUST_PATH . 'app/ValueObjects/PageScore.php';


/*
============================================================
SECURITY - Enhanced Detection (NEW)
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Security/DeviceFingerprinter.php';
require_once BCC_TRUST_PATH . 'app/Security/BehavioralAnalyzer.php';
require_once BCC_TRUST_PATH . 'app/Security/TrustGraph.php';
require_once BCC_TRUST_PATH . 'app/Security/MLFraudDetector.php';

/*
============================================================
REPOSITORIES
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Repositories/VoteRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/ScoreRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/EndorsementRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/VerificationRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/ReputationRepository.php';

/*
============================================================
SERVICES
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Services/VoteService.php';
require_once BCC_TRUST_PATH . 'app/Services/EndorsementService.php';
require_once BCC_TRUST_PATH . 'app/Services/VerificationService.php';
require_once BCC_TRUST_PATH . 'app/Services/TrustScoreCalculator.php';


/*
============================================================
CONTROLLERS
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Controllers/TrustRestController.php';

add_action('rest_api_init', function () {
    if (class_exists('\\BCCTrust\\Controllers\\TrustRestController')) {
        \BCCTrust\Controllers\TrustRestController::register_routes();
    }
});

/*
============================================================
ASSETS
============================================================
*/
require_once BCC_TRUST_PATH . 'includes/enqueue.php';

/*
============================================================
FRONTEND
============================================================
*/
require_once BCC_TRUST_PATH . 'includes/frontend/shortcode.php';
require_once BCC_TRUST_PATH . 'includes/frontend/peepso-integration.php';
require_once BCC_TRUST_PATH . 'includes/frontend/trust-widget.php';

/*
============================================================
ADMIN
============================================================
*/
if (is_admin()) {
    require_once BCC_TRUST_PATH . 'includes/admin/dashboard.php';
    require_once BCC_TRUST_PATH . 'includes/admin/moderation.php';
}

/*
============================================================
INIT
============================================================
*/

add_action('init', function () {
    load_plugin_textdomain(
        'bcc-trust',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages'
    );
});

// ======================================================
// ENHANCED CRON JOBS
// ======================================================

/**
 * Daily cleanup job - Remove old data
 */
add_action('bcc_trust_daily_cleanup', function() {
    global $wpdb;
    
    // Clean verifications table
    $verifications_table = bcc_trust_verifications_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$verifications_table'") == $verifications_table;
    if ($table_exists) {
        $wpdb->query(
            "DELETE FROM {$verifications_table} WHERE expires_at < UTC_TIMESTAMP()"
        );
    }
    
    // Clean old activity logs
    if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
        $activity_table = bcc_trust_activity_table();
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$activity_table'") == $activity_table;
        if ($table_exists) {
            \BCCTrust\Security\AuditLogger::cleanOldLogs(90);
        }
    }
    
    // Clean old fingerprint records
    if (class_exists('\\BCCTrust\\Security\\DeviceFingerprinter')) {
        \BCCTrust\Security\DeviceFingerprinter::cleanOldRecords(90);
    }
    
    // Clean old eligibility cache
    $eligibility_table = bcc_trust_eligibility_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$eligibility_table'") == $eligibility_table;
    if ($table_exists) {
        $wpdb->query(
            "DELETE FROM {$eligibility_table} WHERE expires_at < NOW()"
        );
    }
});

/**
 * Hourly recalculation job - Update stale scores
 */
add_action('bcc_trust_hourly_recalc', function() {
    global $wpdb;
    
    $scores_table = bcc_trust_scores_table();
    $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$scores_table'") == $scores_table;
    
    if (!$table_exists) {
        return;
    }
    
    // Recalculate stale scores
    if (class_exists('BCC_Page_Score_Calculator')) {
        $calculator = new BCC_Page_Score_Calculator();
        
        $pages = $wpdb->get_col(
            $wpdb->prepare(
                "SELECT page_id FROM {$scores_table} 
                 WHERE last_calculated_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
                 LIMIT %d",
                100
            )
        );
        
        foreach ($pages as $page_id) {
            if (method_exists($calculator, 'recalculate_page_score')) {
                $calculator->recalculate_page_score($page_id);
            }
        }
    }
});

/**
 * Daily ML model update - Update fraud detection models
 */
add_action('bcc_trust_daily_ml_update', function() {
    if (!class_exists('\\BCCTrust\\Security\\MLFraudDetector')) {
        return;
    }
    
    $mlDetector = new \BCCTrust\Security\MLFraudDetector();
    
    // Get active users from last 30 days
    global $wpdb;
    $audit_table = bcc_trust_activity_table();
    
    $active_users = $wpdb->get_col("
        SELECT DISTINCT user_id FROM {$audit_table}
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        LIMIT 1000
    ");
    
    foreach ($active_users as $user_id) {
        // Extract features and update predictions
        $prediction = $mlDetector->predictFraudProbability($user_id);
        
        // Store prediction in user meta
        update_user_meta($user_id, 'bcc_trust_ml_prediction', $prediction['probability']);
        update_user_meta($user_id, 'bcc_trust_ml_risk_level', $prediction['risk_level']);
        update_user_meta($user_id, 'bcc_trust_ml_features', $prediction['features']);
        update_user_meta($user_id, 'bcc_trust_ml_updated', time());
        
        // Take action for high-risk users
        if ($prediction['risk_level'] === 'critical' || $prediction['risk_level'] === 'high') {
            if (!get_user_meta($user_id, 'bcc_trust_suspended', true)) {
                // Flag for admin review instead of auto-suspend
                update_user_meta($user_id, 'bcc_trust_needs_review', true);
                update_user_meta($user_id, 'bcc_trust_review_reason', 'ml_high_risk');
                
                \BCCTrust\Security\AuditLogger::log('ml_high_risk_detected', $user_id, [
                    'risk_level' => $prediction['risk_level'],
                    'probability' => $prediction['probability']
                ], 'user');
            }
        }
    }
});

/**
 * Hourly trust graph update
 */
add_action('bcc_trust_hourly_graph_update', function() {
    if (!class_exists('\\BCCTrust\\Security\\TrustGraph')) {
        return;
    }
    
    $graph = new \BCCTrust\Security\TrustGraph();
    
    // Update trust ranks for top 1000 most active users
    global $wpdb;
    $audit_table = bcc_trust_activity_table();
    
    $activeUsers = $wpdb->get_col("
        SELECT DISTINCT user_id FROM {$audit_table}
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
        LIMIT 1000
    ");
    
    foreach ($activeUsers as $userId) {
        $graph->calculateTrustRank($userId);
    }
});

/**
 * Database version check on init
 */
add_action('init', function() {
    // Check if database needs updating
    $current_version = get_option('bcc_trust_db_version', '0.0.0');
    if (version_compare($current_version, BCC_TRUST_VERSION, '<')) {
        require_once BCC_TRUST_PATH . 'includes/database/tables.php';
        if (function_exists('bcc_trust_create_tables')) {
            bcc_trust_create_tables();
            update_option('bcc_trust_db_version', BCC_TRUST_VERSION);
        }
    }
});

/**
 * Schedule cron jobs on plugin activation
 */
function bcc_trust_schedule_cron_jobs() {
    if (!wp_next_scheduled('bcc_trust_daily_cleanup')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_cleanup');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_recalc')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_recalc');
    }
    
    if (!wp_next_scheduled('bcc_trust_daily_ml_update')) {
        wp_schedule_event(time(), 'daily', 'bcc_trust_daily_ml_update');
    }
    
    if (!wp_next_scheduled('bcc_trust_hourly_graph_update')) {
        wp_schedule_event(time(), 'hourly', 'bcc_trust_hourly_graph_update');
    }
}
add_action('wp_loaded', 'bcc_trust_schedule_cron_jobs');

/**
 * Clear cron jobs on deactivation
 */
function bcc_trust_clear_cron_jobs() {
    wp_clear_scheduled_hook('bcc_trust_daily_cleanup');
    wp_clear_scheduled_hook('bcc_trust_hourly_recalc');
    wp_clear_scheduled_hook('bcc_trust_daily_ml_update');
    wp_clear_scheduled_hook('bcc_trust_hourly_graph_update');
}
register_deactivation_hook(BCC_TRUST_PATH . 'bcc-trust-engine.php', 'bcc_trust_clear_cron_jobs');

// ======================================================
// ENHANCED AUTOLOADER
// ======================================================

/**
 * PSR-4 style autoloader for BCC Trust classes
 */
spl_autoload_register(function ($class) {
    // Base directory for our namespace
    $base_dir = BCC_TRUST_PATH . 'app/';
    
    // Check if this is our legacy Page Score Calculator class
    if ($class === 'BCC_Page_Score_Calculator') {
        $file = BCC_TRUST_PATH . 'includes/services/class-page-score-calculator.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    
    // Handle BCCTrust namespace
    if (strpos($class, 'BCCTrust\\') === 0) {
        // Remove namespace prefix
        $class_path = str_replace('BCCTrust\\', '', $class);
        
        // Convert namespace separators to directory separators
        $class_path = str_replace('\\', '/', $class_path);
        
        // Build file path
        $file = $base_dir . $class_path . '.php';
        
        // Debug log in development
        if (defined('WP_DEBUG') && WP_DEBUG) {
            if (!file_exists($file)) {
                error_log("BCC Trust Autoloader: File not found for class {$class} at {$file}");
            }
        }
        
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    
    return false;
});

/**
 * Load helper functions
 */
require_once BCC_TRUST_PATH . 'includes/helpers.php';

/**
 * Check system requirements on admin pages
 */
if (is_admin()) {
    add_action('admin_notices', function() {
        // Check PHP version
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            echo '<div class="notice notice-error"><p>';
            echo 'BCC Trust Engine requires PHP 7.4 or higher. You are running PHP ' . PHP_VERSION;
            echo '</p></div>';
        }
        
        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, '5.8', '<')) {
            echo '<div class="notice notice-warning"><p>';
            echo 'BCC Trust Engine recommends WordPress 5.8 or higher for optimal performance.';
            echo '</p></div>';
        }
        
        // Check if tables were created successfully
        global $wpdb;
        $scores_table = bcc_trust_scores_table();
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$scores_table'") == $scores_table;
        
        if (!$table_exists) {
            echo '<div class="notice notice-error"><p>';
            echo 'BCC Trust Engine database tables were not created. Please deactivate and reactivate the plugin.';
            echo '</p></div>';
        }
    });
}

/**
 * Initialize plugin components
 */
add_action('plugins_loaded', function() {
    // Check if PeepSo is active
    if (!defined('PEEPSO_VERSION')) {
        add_action('admin_notices', function() {
            echo '<div class="notice notice-warning"><p>';
            echo 'BCC Trust Engine works best with PeepSo. Some features may be limited.';
            echo '</p></div>';
        });
    }
});
