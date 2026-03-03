<?php
/**
 * Trust REST Controller
 * 
 * Handles all REST API endpoints with PageScore value objects
 * 
 * @package BCCTrust\Controllers
 * @version 2.1.0
 */

namespace BCCTrust\Controllers;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Exception;

use BCCTrust\Services\VoteService;
use BCCTrust\Services\EndorsementService;
use BCCTrust\Services\VerificationService;
use BCCTrust\Repositories\ScoreRepository;
use BCCTrust\Repositories\UserInfoRepository;
use BCCTrust\Repositories\VoteRepository;
use BCCTrust\Repositories\EndorsementRepository;
use BCCTrust\Security\DeviceFingerprinter;
use BCCTrust\Security\AuditLogger;
use BCCTrust\Security\FraudDetector;
use BCCTrust\ValueObjects\PageScore;

if (!defined('ABSPATH')) {
    exit;
}

class TrustRestController {

    public static function register_routes() {
        // ======================================================
        // PUBLIC ENDPOINTS (for frontend)
        // ======================================================
        
        // Vote endpoints
        register_rest_route('bcc-trust/v1', '/vote', [
            'methods'  => 'POST',
            'callback' => [self::class, 'vote'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        register_rest_route('bcc-trust/v1', '/remove-vote', [
            'methods'  => 'POST',
            'callback' => [self::class, 'remove_vote'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // Endorsement endpoints
        register_rest_route('bcc-trust/v1', '/endorse', [
            'methods'  => 'POST',
            'callback' => [self::class, 'endorse'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        register_rest_route('bcc-trust/v1', '/revoke-endorsement', [
            'methods'  => 'POST',
            'callback' => [self::class, 'revoke_endorsement'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // Score endpoints
        register_rest_route('bcc-trust/v1', '/page/(?P<id>\d+)/score', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_page_score'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('bcc-trust/v1', '/user/(?P<id>\d+)/pages/scores', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_user_pages_scores'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('bcc-trust/v1', '/pages/top', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_top_pages'],
            'permission_callback' => '__return_true'
        ]);

        // Verification endpoint
        register_rest_route('bcc-trust/v1', '/verify-email', [
            'methods'  => 'POST',
            'callback' => [self::class, 'verify_email'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // Device fingerprint endpoint
        register_rest_route('bcc-trust/v1', '/device-fingerprint', [
            'methods'  => 'POST',
            'callback' => [self::class, 'store_fingerprint'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // User status endpoint
        register_rest_route('bcc-trust/v1', '/user/status', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_user_status'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // Report vote endpoint
        register_rest_route('bcc-trust/v1', '/report-vote', [
            'methods'  => 'POST',
            'callback' => [self::class, 'report_vote'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        // ======================================================
        // ADMIN ENDPOINTS (for admin.js)
        // ======================================================
        
        // Fraud statistics
        register_rest_route('bcc-trust/v1', '/fraud/stats', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_fraud_stats'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // High risk users
        register_rest_route('bcc-trust/v1', '/users/high-risk', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_high_risk_users'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Fraud activity
        register_rest_route('bcc-trust/v1', '/activity/fraud', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_fraud_activity'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Trust score trend
        register_rest_route('bcc-trust/v1', '/stats/trust-trend', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_trust_trend'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Risk distribution
        register_rest_route('bcc-trust/v1', '/stats/risk-distribution', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_risk_distribution'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Fraud trend
        register_rest_route('bcc-trust/v1', '/stats/fraud-trend', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_fraud_trend'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Device statistics
        register_rest_route('bcc-trust/v1', '/stats/devices', [
            'methods'  => 'GET',
            'callback' => [self::class, 'get_device_stats'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);

        // Analyze user
        register_rest_route('bcc-trust/v1', '/analyze-user/(?P<id>\d+)', [
            'methods'  => 'POST',
            'callback' => [self::class, 'analyze_user'],
            'permission_callback' => [self::class, 'admin_permission_check']
        ]);
    }

    public static function permission_check(): bool {
        return is_user_logged_in();
    }

    public static function admin_permission_check(): bool {
        return current_user_can('manage_options');
    }

    /**
     * Cast a vote on a page
     */
    public static function vote(WP_REST_Request $request) {
        try {
            $pageId = (int) $request->get_param('page_id');
            $voteType = (int) $request->get_param('vote_type');

            if (!$pageId) {
                throw new Exception('Page ID required');
            }

            if (!in_array($voteType, [1, -1])) {
                throw new Exception('Invalid vote type');
            }

            $fingerprintData = $request->get_param('fingerprint');
            
            if ($fingerprintData) {
                AuditLogger::log('vote_attempt', $pageId, [
                    'vote_type' => $voteType,
                    'fingerprint' => $fingerprintData['hash'] ?? 'unknown',
                    'automation_score' => $fingerprintData['automation_score'] ?? 0
                ], 'page');
            }

            $result = (new VoteService())->castPageVote($pageId, $voteType, $fingerprintData);

            return self::success($result);

        } catch (Exception $e) {
            if (isset($pageId)) {
                AuditLogger::log('vote_error', $pageId, [
                    'error' => $e->getMessage(),
                    'vote_type' => $voteType ?? null
                ], 'page');
            }
            
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Remove a vote
     */
    public static function remove_vote(WP_REST_Request $request) {
        try {
            $pageId = (int) $request->get_param('page_id');

            if (!$pageId) {
                throw new Exception('Page ID required');
            }

            $result = (new VoteService())->removePageVote($pageId);

            return self::success($result);

        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Endorse a page
     */
    public static function endorse(WP_REST_Request $request) {
        try {
            $pageId = (int) $request->get_param('page_id');
            $context = $request->get_param('context') ?? 'general';
            $reason = $request->get_param('reason');

            if (!$pageId) {
                throw new Exception('Page ID required');
            }

            $result = (new EndorsementService())->endorsePage($pageId, $context, $reason);

            // Get updated score using value object
            $repo = new ScoreRepository();
            $score = $repo->getByPageId($pageId);

            return self::success([
                'endorsement' => $result,
                'score' => $score ? $score->toApiResponse() : null
            ]);

        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Revoke an endorsement
     */
    public static function revoke_endorsement(WP_REST_Request $request) {
        try {
            $pageId = (int) $request->get_param('page_id');
            $context = $request->get_param('context') ?? 'general';

            if (!$pageId) {
                throw new Exception('Page ID required');
            }

            $result = (new EndorsementService())->revokePageEndorsement($pageId, $context);

            // Get updated score using value object
            $repo = new ScoreRepository();
            $score = $repo->getByPageId($pageId);

            return self::success([
                'revoked' => $result,
                'score' => $score ? $score->toApiResponse() : null
            ]);

        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Get page score
     */
    public static function get_page_score(WP_REST_Request $request) {
        $pageId = (int) $request['id'];

        $repo = new ScoreRepository();
        $score = $repo->getByPageId($pageId);

        if (!$score) {
            // Get page data for default response
            $page = self::get_peepso_page_data($pageId);
            
            return self::success([
                'page_id' => $pageId,
                'page_title' => $page ? $page->title : '',
                'owner_id' => $page ? $page->owner_id : 0,
                'total_score' => 50.00,
                'reputation_tier' => 'neutral',
                'confidence_score' => 0,
                'vote_count' => 0,
                'unique_voters' => 0,
                'endorsement_count' => 0,
                'positive_score' => 0,
                'negative_score' => 0,
                'status' => 'Average',
                'has_sufficient_data' => false,
                'voter_diversity' => 0,
                'net_score' => 0,
                'has_fraud_alerts' => false
            ]);
        }

        // Get endorsement count if needed
        $endorsement_count = $score->getEndorsementCount();
        if (!$endorsement_count) {
            $endorseService = new EndorsementService();
            $endorsement_count = $endorseService->getPageEndorsementCount($pageId);
        }

        // Get current user's vote and endorsement if logged in
        $userVote = null;
        $userEndorsed = false;
        
        if (is_user_logged_in()) {
            $voteService = new VoteService();
            $userVoteObj = $voteService->getUserPageVote($pageId);
            if ($userVoteObj) {
                $userVote = [
                    'vote_type' => $userVoteObj->vote_type,
                    'weight' => $userVoteObj->weight,
                    'created_at' => $userVoteObj->created_at
                ];
            }
            
            $endorseService = new EndorsementService();
            $userEndorsed = $endorseService->hasEndorsedPage($pageId, get_current_user_id());
        }

        // Get page owner fraud data
        $userInfoRepo = new UserInfoRepository();
        $ownerInfo = $userInfoRepo->getByUserId($score->getPageOwnerId());

        $apiResponse = $score->toApiResponse();
        $apiResponse['page_title'] = get_the_title($pageId);
        $apiResponse['owner_id'] = $score->getPageOwnerId();
        $apiResponse['owner_name'] = get_the_author_meta('display_name', $score->getPageOwnerId());
        $apiResponse['owner_fraud_score'] = $ownerInfo ? $ownerInfo->fraud_score : 0;
        $apiResponse['endorsement_count'] = $endorsement_count;
        $apiResponse['user_vote'] = $userVote;
        $apiResponse['user_endorsed'] = $userEndorsed;
        $apiResponse['last_calculated_at'] = $score->getLastCalculatedAt()->format('Y-m-d H:i:s');

        return self::success($apiResponse);
    }

    /**
     * Get scores for all pages owned by a user
     */
    public static function get_user_pages_scores(WP_REST_Request $request) {
        $userId = (int) $request['id'];

        $repo = new ScoreRepository();
        $pages = $repo->getByOwnerId($userId);

        $result = [];
        foreach ($pages as $page) {
            $result[] = [
                'page_id' => $page->getPageId(),
                'page_title' => $page->post_title ?? get_the_title($page->getPageId()),
                'total_score' => $page->getTotalScore(),
                'reputation_tier' => $page->getReputationTier(),
                'vote_count' => $page->getVoteCount(),
                'confidence_score' => $page->getConfidenceScore(),
                'has_fraud_alerts' => $page->hasFraudAlerts()
            ];
        }

        return self::success([
            'user_id' => $userId,
            'pages' => $result,
            'count' => count($result)
        ]);
    }

    /**
     * Get top pages by trust score
     */
    public static function get_top_pages(WP_REST_Request $request) {
        $limit = min(50, (int) $request->get_param('limit') ?: 10);
        $orderBy = $request->get_param('order_by') ?: 'total_score';
        $tier = $request->get_param('tier');

        $repo = new ScoreRepository();
        
        try {
            if ($tier) {
                $validTiers = ['elite', 'trusted', 'neutral', 'caution', 'risky'];
                if (!in_array($tier, $validTiers)) {
                    return self::error('Invalid tier specified', 400);
                }
                
                $pages = $repo->getByTier($tier, $limit);
            } else {
                $pages = $repo->getTopScored($limit, $orderBy);
            }

            $formatted = [];
            foreach ($pages as $page) {
                $formatted[] = [
                    'page_id' => $page->getPageId(),
                    'page_title' => $page->post_title ?? get_the_title($page->getPageId()),
                    'owner_id' => $page->getPageOwnerId(),
                    'owner_name' => $page->owner_name ?? '',
                    'total_score' => $page->getTotalScore(),
                    'reputation_tier' => $page->getReputationTier(),
                    'vote_count' => $page->getVoteCount(),
                    'endorsement_count' => $page->getEndorsementCount(),
                    'confidence_score' => $page->getConfidenceScore(),
                    'has_fraud_alerts' => $page->hasFraudAlerts()
                ];
            }

            return self::success([
                'pages' => $formatted,
                'total' => count($formatted),
                'order_by' => $orderBy,
                'tier_filter' => $tier
            ]);
            
        } catch (Exception $e) {
            return self::error('Failed to retrieve pages: ' . $e->getMessage(), 500);
        }
    }

    /**
     * Verify email with token
     */
    public static function verify_email(WP_REST_Request $request) {
        try {
            $token = $request->get_param('token');
            $userId = (int) $request->get_param('user_id');

            if (!$userId || !$token) {
                throw new Exception('User ID and token required');
            }

            $result = (new VerificationService())->verifyEmail($userId, $token);

            return self::success([
                'verified' => $result,
                'user_id' => $userId
            ]);

        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Store device fingerprint
     */
    public static function store_fingerprint(WP_REST_Request $request) {
        try {
            $userId = get_current_user_id();
            if (!$userId) {
                throw new Exception('User not authenticated');
            }
            
            $data = $request->get_json_params();
            
            if (empty($data['fingerprint']) || empty($data['fingerprint']['hash'])) {
                throw new Exception('Invalid fingerprint data');
            }

            $fingerprinter = new DeviceFingerprinter();
            
            $automationData = $fingerprinter->detectAutomation();
            
            $fingerprintId = $fingerprinter->storeFingerprint(
                $userId, 
                $data['fingerprint']['hash'],
                $automationData
            );
            
            $userCount = $fingerprinter->getFingerprintUserCount($data['fingerprint']['hash']);
            
            $alert = false;
            if ($userCount > 3) {
                AuditLogger::log('multiple_accounts_detected', $userId, [
                    'fingerprint' => $data['fingerprint']['hash'],
                    'account_count' => $userCount,
                    'automation_score' => $automationData['confidence']
                ], 'user');
                
                $alert = true;
            }
            
            if ($automationData['is_automated'] && $automationData['confidence'] > 70) {
                AuditLogger::log('automation_detected', $userId, [
                    'confidence' => $automationData['confidence'],
                    'signals' => $automationData['signals']
                ], 'user');
                
                // Update user_info table
                global $wpdb;
                $userInfoTable = bcc_trust_user_info_table();
                
                $wpdb->query($wpdb->prepare(
                    "UPDATE {$userInfoTable} 
                     SET automation_score = automation_score + 20,
                         fraud_score = LEAST(100, fraud_score + 20)
                     WHERE user_id = %d",
                    $userId
                ));
                
                $alert = true;
            }
            
            if (!empty($data['data'])) {
                update_user_meta($userId, 'bcc_last_fingerprint_data', [
                    'data' => $data['data'],
                    'time' => time(),
                    'automation' => $automationData
                ]);
            }
            
            return self::success([
                'stored' => true,
                'fingerprint_id' => $fingerprintId,
                'automation_detected' => $automationData['is_automated'],
                'automation_confidence' => $automationData['confidence'],
                'multiple_accounts' => $userCount > 1,
                'account_count' => $userCount,
                'alert' => $alert
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Get user's fraud/trust status from user_info table
     */
    public static function get_user_status(WP_REST_Request $request) {
        try {
            $userId = get_current_user_id();
            if (!$userId) {
                throw new Exception('User not authenticated');
            }
            
            global $wpdb;
            
            // Get user info from user_info table
            $userInfoTable = bcc_trust_user_info_table();
            $fingerprintTable = bcc_trust_fingerprints_table();
            
            $userInfo = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$userInfoTable} WHERE user_id = %d",
                $userId
            ));
            
            // Get fingerprints
            $fingerprints = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$fingerprintTable} 
                 WHERE user_id = %d 
                 ORDER BY last_seen DESC 
                 LIMIT 10",
                $userId
            ));
            
            return self::success([
                'user_id' => $userId,
                'fraud_score' => $userInfo ? (int)$userInfo->fraud_score : 0,
                'automation_score' => $userInfo ? (int)$userInfo->automation_score : 0,
                'behavior_score' => $userInfo ? (int)$userInfo->behavior_score : 0,
                'risk_level' => $userInfo ? $userInfo->risk_level : 'unknown',
                'suspended' => $userInfo ? (bool)$userInfo->is_suspended : false,
                'verified' => $userInfo ? (bool)$userInfo->is_verified : false,
                'stats' => [
                    'votes_cast' => $userInfo ? (int)$userInfo->votes_cast : 0,
                    'endorsements_given' => $userInfo ? (int)$userInfo->endorsements_given : 0,
                    'pages_owned' => $userInfo ? (int)$userInfo->pages_owned : 0,
                    'pages_joined' => $userInfo ? (int)$userInfo->pages_joined : 0,
                    'posts_created' => $userInfo ? (int)$userInfo->posts_created : 0,
                    'comments_made' => $userInfo ? (int)$userInfo->comments_made : 0
                ],
                'fingerprints' => array_map(function($fp) {
                    return [
                        'fingerprint' => substr($fp->fingerprint, 0, 8) . '...',
                        'automation_score' => $fp->automation_score,
                        'first_seen' => $fp->first_seen,
                        'last_seen' => $fp->last_seen,
                        'risk_level' => $fp->risk_level
                    ];
                }, $fingerprints)
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    /**
     * Report a vote
     */
    public static function report_vote(WP_REST_Request $request) {
        try {
            $userId = get_current_user_id();
            if (!$userId) {
                throw new Exception('User not authenticated');
            }
            
            $voteId = (int) $request->get_param('vote_id');
            $reason = sanitize_text_field($request->get_param('reason'));
            
            if (!$voteId) {
                throw new Exception('Vote ID required');
            }
            
            if (!$reason) {
                throw new Exception('Reason required');
            }
            
            global $wpdb;
            $votesTable = bcc_trust_votes_table();
            
            $vote = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$votesTable} WHERE id = %d",
                $voteId
            ));
            
            if (!$vote) {
                throw new Exception('Vote not found');
            }
            
            $flagsTable = bcc_trust_flags_table();
            $existing = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$flagsTable} 
                 WHERE vote_id = %d AND flagger_user_id = %d",
                $voteId,
                $userId
            ));
            
            if ($existing > 0) {
                throw new Exception('You have already reported this vote');
            }
            
            $wpdb->insert(
                $flagsTable,
                [
                    'vote_id' => $voteId,
                    'flagger_user_id' => $userId,
                    'reason' => $reason,
                    'status' => 0,
                    'created_at' => current_time('mysql')
                ],
                ['%d', '%d', '%s', '%d', '%s']
            );
            
            $flagId = $wpdb->insert_id;
            
            AuditLogger::flagCreated($voteId, $userId, $reason);
            
            $flagCount = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$flagsTable} WHERE vote_id = %d",
                $voteId
            ));
            
            if ($flagCount >= 3) {
                $newWeight = $vote->weight * 0.5;
                $wpdb->update(
                    $votesTable,
                    ['weight' => $newWeight],
                    ['id' => $voteId],
                    ['%f'],
                    ['%d']
                );
                
                // Recalculate page score
                if (function_exists('bcc_trust_recalculate_page_score')) {
                    bcc_trust_recalculate_page_score($vote->page_id);
                }
            }
            
            return self::success([
                'reported' => true,
                'flag_id' => $flagId,
                'vote_id' => $voteId,
                'total_flags' => $flagCount
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 400);
        }
    }

    // ======================================================
    // ADMIN ENDPOINTS
    // ======================================================

    /**
     * Get fraud statistics
     */
    public static function get_fraud_stats(WP_REST_Request $request) {
        try {
            $stats = FraudDetector::getStats();
            
            // Add additional stats
            $userInfoRepo = new UserInfoRepository();
            $deviceStats = DeviceFingerprinter::getStats();
            
            return self::success(array_merge($stats, [
                'device_stats' => $deviceStats,
                'total_alerts' => $stats['suspended_users'] ?? 0,
                'high_risk_count' => $stats['risk_distribution']['high'] ?? 0,
                'suspended_count' => $stats['suspended_users'] ?? 0
            ]));
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get high risk users
     */
    public static function get_high_risk_users(WP_REST_Request $request) {
        try {
            $limit = (int) $request->get_param('limit') ?: 20;
            $threshold = (int) $request->get_param('threshold') ?: 70;
            
            $userInfoRepo = new UserInfoRepository();
            $users = $userInfoRepo->getHighRiskUsers($threshold, $limit);
            
            return self::success($users);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get fraud activity
     */
    public static function get_fraud_activity(WP_REST_Request $request) {
        try {
            $limit = (int) $request->get_param('limit') ?: 10;
            
            $activity = AuditLogger::getSuspiciousActivity(24, $limit);
            
            $formatted = [];
            foreach ($activity as $event) {
                $formatted[] = [
                    'id' => $event->id,
                    'user_id' => $event->user_id,
                    'action' => $event->action,
                    'message' => $event->action,
                    'time' => bcc_trust_time_ago($event->created_at),
                    'severity' => self::getSeverityFromAction($event->action)
                ];
            }
            
            return self::success($formatted);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get trust score trend
     */
    public static function get_trust_trend(WP_REST_Request $request) {
        try {
            $days = (int) $request->get_param('days') ?: 30;
            
            global $wpdb;
            $scoresTable = bcc_trust_scores_table();
            
            // Get daily average scores for last N days
            $results = $wpdb->get_results($wpdb->prepare("
                SELECT 
                    DATE(last_calculated_at) as date,
                    AVG(total_score) as avg_score
                FROM {$scoresTable}
                WHERE last_calculated_at > DATE_SUB(NOW(), INTERVAL %d DAY)
                GROUP BY DATE(last_calculated_at)
                ORDER BY date ASC
            ", $days));
            
            $labels = [];
            $scores = [];
            
            foreach ($results as $row) {
                $labels[] = date('M d', strtotime($row->date));
                $scores[] = round($row->avg_score, 1);
            }
            
            return self::success([
                'labels' => $labels,
                'scores' => $scores
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get risk distribution
     */
    public static function get_risk_distribution(WP_REST_Request $request) {
        try {
            $stats = FraudDetector::getStats();
            
            return self::success([
                'critical' => $stats['risk_distribution']['critical'] ?? 0,
                'high' => $stats['risk_distribution']['high'] ?? 0,
                'medium' => $stats['risk_distribution']['medium'] ?? 0,
                'low' => $stats['risk_distribution']['low'] ?? 0,
                'minimal' => $stats['risk_distribution']['minimal'] ?? 0
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get fraud trend
     */
    public static function get_fraud_trend(WP_REST_Request $request) {
        try {
            $days = (int) $request->get_param('days') ?: 30;
            
            global $wpdb;
            $activityTable = bcc_trust_activity_table();
            
            // Get daily fraud detection counts
            $results = $wpdb->get_results($wpdb->prepare("
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM {$activityTable}
                WHERE action LIKE '%fraud%' 
                   OR action LIKE '%suspicious%'
                   OR action LIKE '%flag%'
                AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            ", $days));
            
            $labels = [];
            $counts = [];
            
            foreach ($results as $row) {
                $labels[] = date('M d', strtotime($row->date));
                $counts[] = $row->count;
            }
            
            return self::success([
                'labels' => $labels,
                'counts' => $counts
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Get device statistics
     */
    public static function get_device_stats(WP_REST_Request $request) {
        try {
            $stats = DeviceFingerprinter::getStats();
            
            return self::success([
                'clean' => $stats['total_records'] - $stats['automated_detected'] - $stats['high_risk'],
                'suspicious' => $stats['medium_risk'] ?? 0,
                'automated' => $stats['automated_detected'],
                'shared' => $stats['shared_devices']
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    /**
     * Analyze a user
     */
    public static function analyze_user(WP_REST_Request $request) {
        try {
            $userId = (int) $request['id'];
            
            if (!$userId) {
                throw new Exception('User ID required');
            }
            
            // Run comprehensive fraud analysis
            $analysis = FraudDetector::analyzeFraud($userId);
            
            // Update fraud score
            FraudDetector::updateFraudScore($userId);
            
            return self::success([
                'user_id' => $userId,
                'fraud_score' => $analysis['score'],
                'risk_level' => $analysis['risk_level'],
                'triggers' => $analysis['triggers'],
                'analysis' => $analysis
            ]);
            
        } catch (Exception $e) {
            return self::error($e->getMessage(), 500);
        }
    }

    // ======================================================
    // HELPER METHODS
    // ======================================================

    private static function get_peepso_page_data($pageId) {
        global $wpdb;
        
        $pages_table = $wpdb->prefix . 'peepso_pages';
        
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$pages_table'") == $pages_table;
        
        if ($table_exists) {
            $page = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$pages_table} WHERE ID = %d",
                $pageId
            ));

            if ($page) {
                return (object) [
                    'id' => $page->ID,
                    'title' => $page->name,
                    'owner_id' => $page->owner_id ?? 0
                ];
            }
        }
        
        $post = get_post($pageId);
        if ($post) {
            return (object) [
                'id' => $post->ID,
                'title' => $post->post_title,
                'owner_id' => $post->post_author
            ];
        }
        
        return null;
    }

    private static function getSeverityFromAction($action) {
        if (strpos($action, 'critical') !== false || strpos($action, 'suspend') !== false) {
            return 'critical';
        }
        if (strpos($action, 'high') !== false || strpos($action, 'ring') !== false) {
            return 'high';
        }
        if (strpos($action, 'medium') !== false || strpos($action, 'flag') !== false) {
            return 'medium';
        }
        return 'low';
    }

    private static function success(array $data): WP_REST_Response {
        return new WP_REST_Response([
            'success' => true,
            'data'    => $data
        ], 200);
    }

    private static function error(string $message, int $status): WP_Error {
        return new WP_Error('trust_error', $message, ['status' => $status]);
    }
}