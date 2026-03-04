<?php
/**
 * Trust Engine Bootstrap
 *
 * Loads all core components in the correct order.
 *
 * @package BCC_Trust_Engine
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('BCC_ENCRYPTION_KEY')) {
    wp_die('BCC Trust Engine requires BCC_ENCRYPTION_KEY in wp-config.php');
}
require_once BCC_TRUST_PATH . 'includes/config.php';

/*
|--------------------------------------------------------------------------
| CORE HELPERS & DATABASE
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'includes/helpers.php';
require_once BCC_TRUST_PATH . 'includes/database/tables.php';
require_once BCC_TRUST_PATH . 'includes/database/queries.php';
require_once BCC_TRUST_PATH . 'includes/database/hooks.php';


/*
|--------------------------------------------------------------------------
| VALUE OBJECTS
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/ValueObjects/PageScore.php';

/*
|--------------------------------------------------------------------------
| SECURITY CORE
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/Security/TransactionManager.php';
require_once BCC_TRUST_PATH . 'app/Security/RateLimiter.php';
require_once BCC_TRUST_PATH . 'app/Security/AuditLogger.php';
require_once BCC_TRUST_PATH . 'app/Security/FraudDetector.php';

/*
|--------------------------------------------------------------------------
| SECURITY - ENHANCED DETECTION
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/Security/DeviceFingerprinter.php';
require_once BCC_TRUST_PATH . 'app/Security/BehavioralAnalyzer.php';
require_once BCC_TRUST_PATH . 'app/Security/TrustGraph.php';
require_once BCC_TRUST_PATH . 'app/Security/MLFraudDetector.php';

/*
|--------------------------------------------------------------------------
| REPOSITORIES
|--------------------------------------------------------------------------
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
|--------------------------------------------------------------------------
| SERVICES
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/Services/VoteService.php';
require_once BCC_TRUST_PATH . 'app/Services/EndorsementService.php';
require_once BCC_TRUST_PATH . 'app/Services/VerificationService.php';

/*
|--------------------------------------------------------------------------
| GITHUB INTEGRATION
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/Services/github/GitHubOAuthService.php';
require_once BCC_TRUST_PATH . 'app/Services/github/GitHubApiService.php';
require_once BCC_TRUST_PATH . 'app/Services/github/GitHubScoreService.php';
require_once BCC_TRUST_PATH . 'app/Repositories/GitHubRepository.php';
require_once BCC_TRUST_PATH . 'app/Controllers/GitHubController.php';
require_once BCC_TRUST_PATH . 'app/routes/GitHubRoutes.php';

/*
|--------------------------------------------------------------------------
| CONTROLLERS
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'app/Controllers/TrustRestController.php';

/*
|--------------------------------------------------------------------------
| HOOKS - All WordPress hooks
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'includes/hooks.php';

/*
|--------------------------------------------------------------------------
| FRONTEND
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'includes/enqueue.php';
require_once BCC_TRUST_PATH . 'includes/frontend/shortcode.php';
require_once BCC_TRUST_PATH . 'includes/frontend/peepso-integration.php';


/*
|--------------------------------------------------------------------------
| ADMIN - Only load in admin
|--------------------------------------------------------------------------
*/
require_once BCC_TRUST_PATH . 'includes/admin/dashboard.php';



if (is_admin()) {
    // Make sure these files exist before requiring
    $admin_files = [
        'dashboard-action.php',
        'dashboard-controller.php',
        'moderation.php',
        'dashboard.php'
    ];
    
    foreach ($admin_files as $file) {
        $path = BCC_TRUST_PATH . 'includes/admin/' . $file;
        if (file_exists($path)) {
            require_once $path;
        } else {
            error_log("BCC Trust: Missing admin file - {$file}");
        }
    }
}
