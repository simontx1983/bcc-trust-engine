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
require_once BCC_TRUST_PATH . 'includes/helpers.php';

/*
============================================================
HOOKS - All WordPress hooks moved here
============================================================
*/
require_once BCC_TRUST_PATH . 'includes/hooks.php';

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
SECURITY - Enhanced Detection
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
require_once BCC_TRUST_PATH . 'app/Repositories/FraudAnalysisRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/PatternRepository.php';
require_once BCC_TRUST_PATH . 'app/Repositories/UserInfoRepository.php';

/*
============================================================
SERVICES
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Services/VoteService.php';
require_once BCC_TRUST_PATH . 'app/Services/EndorsementService.php';
require_once BCC_TRUST_PATH . 'app/Services/VerificationService.php';

/*
============================================================
CONTROLLERS
============================================================
*/
require_once BCC_TRUST_PATH . 'app/Controllers/TrustRestController.php';

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
ENHANCED AUTOLOADER
============================================================
*/

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