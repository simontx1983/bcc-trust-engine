<?php
/**
 * Trust REST Controller
 * 
 * Handles all REST API endpoints with PageScore value objects
 * 
 * @package BCCTrust\Controllers
 * @version 2.0.0
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
use BCCTrust\Security\DeviceFingerprinter;
use BCCTrust\Security\AuditLogger;
use BCCTrust\ValueObjects\PageScore;

if (!defined('ABSPATH')) {
    exit;
}

class TrustRestController {

    public static function register_routes() {
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
    }

    public static function permission_check(): bool {
        return is_user_logged_in();
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

            // Result already contains properly formatted score from PageScore::toApiResponse()
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
                'net_score' => 0
            ]);
        }

        // Get endorsement count if needed
        $endorsement_count = $score->getEndorsementCount();
        if (!$endorsement_count) {
            $endorseService = new EndorsementService();
            $endorsement_count = $endorseService->getPageEndorsementCount($pageId);
        }

        // Get current user's vote if logged in
        $userVote = null;
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
        }

        $apiResponse = $score->toApiResponse();
        $apiResponse['page_title'] = get_the_title($pageId);
        $apiResponse['owner_id'] = $score->getPageOwnerId();
        $apiResponse['endorsement_count'] = $endorsement_count;
        $apiResponse['user_vote'] = $userVote;
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
                'confidence_score' => $page->getConfidenceScore()
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
                    'confidence_score' => $page->getConfidenceScore()
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
                
                $currentFraud = (int) get_user_meta($userId, 'bcc_trust_fraud_score', true);
                $newFraud = min(100, $currentFraud + 20);
                update_user_meta($userId, 'bcc_trust_fraud_score', $newFraud);
                
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
     * Get user's fraud/trust status
     */
    public static function get_user_status(WP_REST_Request $request) {
        try {
            $userId = get_current_user_id();
            if (!$userId) {
                throw new Exception('User not authenticated');
            }
            
            $fingerprinter = new DeviceFingerprinter();
            
            global $wpdb;
            $fingerprintTable = $wpdb->prefix . 'bcc_trust_device_fingerprints';
            
            $fingerprints = $wpdb->get_results($wpdb->prepare(
                "SELECT * FROM {$fingerprintTable} 
                 WHERE user_id = %d 
                 ORDER BY last_seen DESC 
                 LIMIT 10",
                $userId
            ));
            
            $fraudScore = (int) get_user_meta($userId, 'bcc_trust_fraud_score', true);
            
            $voteWeight = (float) get_user_meta($userId, 'bcc_trust_vote_weight', true);
            if (!$voteWeight) {
                $voteWeight = 1.0;
            }
            
            $suspended = (bool) get_user_meta($userId, 'bcc_trust_suspended', true);
            
            $verified = (bool) get_user_meta($userId, 'bcc_trust_email_verified', true);
            
            $voteCount = (int) get_user_meta($userId, 'bcc_trust_votes_cast', true);
            $endorsementCount = (int) get_user_meta($userId, 'bcc_trust_endorsements_given', true);
            
            return self::success([
                'user_id' => $userId,
                'fraud_score' => $fraudScore,
                'vote_weight' => $voteWeight,
                'suspended' => $suspended,
                'verified' => $verified,
                'stats' => [
                    'votes_cast' => $voteCount,
                    'endorsements_given' => $endorsementCount
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
            $votesTable = $wpdb->prefix . 'bcc_trust_votes';
            
            $vote = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$votesTable} WHERE id = %d",
                $voteId
            ));
            
            if (!$vote) {
                throw new Exception('Vote not found');
            }
            
            $flagsTable = $wpdb->prefix . 'bcc_trust_flags';
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
                
                if (class_exists('BCC_Page_Score_Calculator')) {
                    $calculator = new \BCC_Page_Score_Calculator();
                    $calculator->recalculate_page_score($vote->page_id);
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