<?php
/**
 * Endorsement Service
 *
 * Handles users endorsing PeepSo Pages with enhanced fraud protection
 * Updated to use PageScore value objects and user_info table
 *
 * @package BCCTrust\Services
 * @version 2.1.0
 */

namespace BCCTrust\Services;

use Exception;
use BCCTrust\Repositories\EndorsementRepository;
use BCCTrust\Repositories\ScoreRepository;
use BCCTrust\Repositories\UserInfoRepository;
use BCCTrust\Repositories\VerificationRepository;
use BCCTrust\Security\TransactionManager;
use BCCTrust\Security\RateLimiter;
use BCCTrust\Security\AuditLogger;
use BCCTrust\Security\FraudDetector;
use BCCTrust\Security\DeviceFingerprinter;
use BCCTrust\Security\BehavioralAnalyzer;
use BCCTrust\Security\TrustGraph;
use BCCTrust\ValueObjects\PageScore;

if (!defined('ABSPATH')) {
    exit;
}

class EndorsementService {

    private EndorsementRepository $endorseRepo;
    private ScoreRepository $scoreRepo;
    private UserInfoRepository $userInfoRepo;
    private VerificationRepository $verificationRepo;
    private DeviceFingerprinter $fingerprinter;
    private BehavioralAnalyzer $behavioralAnalyzer;
    private TrustGraph $trustGraph;

    public function __construct() {
        $this->endorseRepo = new EndorsementRepository();
        $this->scoreRepo   = new ScoreRepository();
        $this->userInfoRepo = new UserInfoRepository();
        $this->verificationRepo = new VerificationRepository();
        $this->fingerprinter = new DeviceFingerprinter();
        $this->behavioralAnalyzer = new BehavioralAnalyzer();
        $this->trustGraph = new TrustGraph();
    }

    /**
     * Add endorsement to a page
     */
    public function endorsePage(int $pageId, string $context = 'general', ?string $reason = null, ?array $fingerprintData = null): array {
        if (!is_user_logged_in()) {
            throw new Exception('Authentication required');
        }

        $endorserUserId = get_current_user_id();

        // Verify page exists
        $page = $this->getPeepSoPage($pageId);
        if (!$page) {
            throw new Exception('Invalid page.');
        }

        // Get page owner
        $pageOwnerId = $this->getPageOwnerId($pageId);

        // Can't endorse your own page
        if ($pageOwnerId == $endorserUserId) {
            throw new Exception('You cannot endorse your own page');
        }

        // Check if already endorsed
        if ($this->hasEndorsedPage($pageId, $endorserUserId, $context)) {
            throw new Exception('You have already endorsed this page');
        }

        // Rate limit
        RateLimiter::enforce('endorse', 10, 300);

        // ======================================================
        // FRAUD DETECTION
        // ======================================================

        $fraudAnalysis = FraudDetector::analyzeFraud($endorserUserId);
        
        if ($fraudAnalysis['score'] > 70) {
            AuditLogger::log('suspicious_endorse_attempt', $pageId, [
                'endorser_id' => $endorserUserId,
                'fraud_score' => $fraudAnalysis['score'],
                'risk_level' => $fraudAnalysis['risk_level'],
                'triggers' => $fraudAnalysis['triggers']
            ], 'page');
            throw new Exception('Account under review. Please contact support.');
        }

        // ======================================================
        // DEVICE FINGERPRINTING
        // ======================================================

        $fingerprint = $fingerprintData['hash'] ?? $this->fingerprinter->generateFingerprint();
        $automationData = $this->fingerprinter->detectAutomation();
        $this->fingerprinter->storeFingerprint($endorserUserId, $fingerprint, $automationData);

        $userCount = $this->fingerprinter->getFingerprintUserCount($fingerprint);
        $multiAccountRisk = ($userCount > 3);

        // ======================================================
        // BEHAVIORAL ANALYSIS
        // ======================================================

        $behavior = $this->behavioralAnalyzer->analyzeUserBehavior($endorserUserId);

        // ======================================================
        // TRUST GRAPH ANALYSIS
        // ======================================================

        // Get trust rank from user_info table
        $userInfo = $this->userInfoRepo->getByUserId($endorserUserId);
        $trustRank = $userInfo ? (float) $userInfo->trust_rank : 0;
        
        if (!$trustRank) {
            $trustRank = $this->trustGraph->calculateTrustRank($endorserUserId);
            $this->userInfoRepo->updateTrustRank($endorserUserId, $trustRank);
        }

        $rings = $this->trustGraph->detectVoteRings(3);
        $inVoteRing = false;
        foreach ($rings as $ring) {
            if (in_array($endorserUserId, $ring['users'])) {
                $inVoteRing = true;
                break;
            }
        }

        if ($inVoteRing) {
            AuditLogger::log('vote_ring_endorse_attempt', $pageId, [
                'endorser_id' => $endorserUserId
            ], 'page');
            throw new Exception('Suspicious activity detected. Please contact support.');
        }

        // ======================================================
        // CALCULATE FINAL ENDORSEMENT WEIGHT
        // ======================================================

        $baseWeight = $this->calculateBaseEndorserWeight($endorserUserId);
        
        $adjustedWeight = $this->applyFraudAdjustments(
            $baseWeight,
            $fraudAnalysis,
            $automationData,
            $multiAccountRisk,
            $behavior,
            $trustRank,
            $endorserUserId
        );

        AuditLogger::log('endorse_analysis', $pageId, [
            'endorser_id' => $endorserUserId,
            'base_weight' => $baseWeight,
            'final_weight' => $adjustedWeight,
            'fraud_score' => $fraudAnalysis['score'],
            'automation_detected' => $automationData['is_automated'],
            'behavior_score' => $behavior['behavior_score'] ?? 0,
            'trust_rank' => $trustRank
        ], 'page');

        return TransactionManager::run(function () use (
            $endorserUserId, $pageId, $context, $reason, $page, $pageOwnerId,
            $adjustedWeight, $automationData, $fingerprint, $fraudAnalysis,
            $baseWeight
        ) {
            // Create endorsement
            $endorsementId = $this->endorseRepo->create(
                $endorserUserId,
                $pageId,
                $context,
                $adjustedWeight,
                $reason
            );

            // Apply endorsement bonus using PageScore
            $this->applyEndorsementBonus($pageId, $adjustedWeight);

            // Update endorser's stats in user_info table
            $this->updateEndorserStats($endorserUserId);

            // Update fraud score in user_info table
            $this->updateFraudScore($endorserUserId, $fraudAnalysis, $automationData);

            // Log the endorsement
            AuditLogger::endorse($pageId, $context, [
                'endorser_id' => $endorserUserId,
                'page_owner_id' => $pageOwnerId,
                'weight' => $adjustedWeight,
                'endorsement_id' => $endorsementId,
                'fraud_score' => $fraudAnalysis['score'],
                'automation_score' => $automationData['confidence']
            ]);

            // Get updated endorsement count
            $endorsementCount = $this->getPageEndorsementCount($pageId);

            // Get updated page score as PageScore
            $updatedScore = $this->scoreRepo->getByPageId($pageId);

            return [
                'success'           => true,
                'endorsement_id'    => $endorsementId,
                'page_id'           => $pageId,
                'page_title'        => $page->name ?? $page->post_title,
                'context'           => $context,
                'weight'            => $adjustedWeight,
                'endorsement_count' => $endorsementCount,
                'total_score'       => $updatedScore ? $updatedScore->getTotalScore() : 50,
                'analysis' => [
                    'weight_applied' => $adjustedWeight,
                    'base_weight' => $baseWeight,
                    'fraud_score' => $fraudAnalysis['score'],
                    'risk_level' => $fraudAnalysis['risk_level'],
                    'automation_detected' => $automationData['is_automated']
                ],
                'message'           => 'Endorsement added successfully'
            ];
        });
    }

    /**
     * Apply endorsement bonus using PageScore
     */
    private function applyEndorsementBonus(int $pageId, float $weight): void {
        $score = $this->scoreRepo->getByPageId($pageId);
        
        if (!$score) {
            // Create default score if it doesn't exist
            $pageOwnerId = $this->getPageOwnerId($pageId);
            $score = $this->scoreRepo->createDefault($pageId, $pageOwnerId);
        }

        // Use immutable transformation to add endorsement
        $newScore = $score->withEndorsement();
        
        // Save the updated score
        $this->scoreRepo->save($newScore);
    }

    /**
     * Remove endorsement bonus using PageScore
     */
    private function removeEndorsementBonus(int $pageId, float $weight): void {
        $score = $this->scoreRepo->getByPageId($pageId);
        
        if (!$score) {
            return;
        }

        // Use immutable transformation to remove endorsement
        $newScore = $score->withoutEndorsement();
        
        // Save the updated score
        $this->scoreRepo->save($newScore);
    }

    /**
     * Remove endorsement from a page
     */
    public function revokePageEndorsement(int $pageId, string $context = 'general'): array {
        if (!is_user_logged_in()) {
            throw new Exception('Authentication required');
        }

        $endorserUserId = get_current_user_id();

        RateLimiter::enforce('revoke_endorse', 5, 60);

        return TransactionManager::run(function () use ($endorserUserId, $pageId, $context) {
            // Check if endorsement exists
            $endorsement = $this->endorseRepo->get($endorserUserId, $pageId, $context);
            
            if (!$endorsement) {
                throw new Exception('Endorsement not found');
            }

            // Store weight before deletion
            $weight = $endorsement->weight;

            // Delete endorsement (soft delete)
            $this->endorseRepo->delete($endorserUserId, $pageId, $context);

            // Remove endorsement bonus using PageScore
            $this->removeEndorsementBonus($pageId, $weight);

            // Update endorser's stats in user_info table
            $this->updateEndorserStats($endorserUserId);

            // Log the revocation
            AuditLogger::revokeEndorsement($pageId, $context, [
                'endorser_id' => $endorserUserId,
                'weight' => $weight
            ]);

            // Get updated endorsement count
            $endorsementCount = $this->getPageEndorsementCount($pageId);

            // Get updated page score as PageScore
            $updatedScore = $this->scoreRepo->getByPageId($pageId);

            return [
                'success'           => true,
                'page_id'           => $pageId,
                'context'           => $context,
                'endorsement_count' => $endorsementCount,
                'total_score'       => $updatedScore ? $updatedScore->getTotalScore() : 50,
                'message'           => 'Endorsement revoked successfully'
            ];
        });
    }

    /**
     * Calculate base endorsement weight using user_info table
     */
    private function calculateBaseEndorserWeight(int $userId): float {
        $weight = 1.0;

        // Get user's own page scores
        $userPages = $this->scoreRepo->getByOwnerId($userId);
        
        if (!empty($userPages)) {
            $totalScore = 0;
            foreach ($userPages as $page) {
                $totalScore += $page->getTotalScore();
            }
            $avgScore = $totalScore / count($userPages);
            
            // Apply tier-based weight (with defaults if constants not defined)
            if ($avgScore >= 80) {
                $weight = defined('BCC_TRUST_ENDORSE_ELITE') ? BCC_TRUST_ENDORSE_ELITE : 2.0;
            } elseif ($avgScore >= 65) {
                $weight = defined('BCC_TRUST_ENDORSE_TRUSTED') ? BCC_TRUST_ENDORSE_TRUSTED : 1.5;
            } elseif ($avgScore <= 35) {
                $weight = defined('BCC_TRUST_ENDORSE_RISKY') ? BCC_TRUST_ENDORSE_RISKY : 0.3;
            } elseif ($avgScore <= 45) {
                $weight = defined('BCC_TRUST_ENDORSE_CAUTION') ? BCC_TRUST_ENDORSE_CAUTION : 0.6;
            }
            
            // Page count multiplier
            $pageCount = count($userPages);
            if ($pageCount >= 5) {
                $weight *= 1.2;
            } elseif ($pageCount >= 2) {
                $weight *= 1.1;
            }
        }

        // Check if user is verified using verification repo
        if ($this->verificationRepo->isVerified($userId)) {
            $weight *= 1.2;
        }

        // Time-based multiplier
        $user = get_userdata($userId);
        if ($user) {
            $accountAge = time() - strtotime($user->user_registered);
            $accountYears = $accountAge / (365 * 24 * 60 * 60);
            
            if ($accountYears >= 2) {
                $weight *= 1.2;
            } elseif ($accountYears >= 1) {
                $weight *= 1.1;
            }
        }

        return round($weight, 2);
    }

    /**
     * Apply fraud adjustments to endorsement weight
     */
    private function applyFraudAdjustments(
        float $baseWeight,
        array $fraudAnalysis,
        array $automationData,
        bool $multiAccountRisk,
        array $behavior,
        float $trustRank,
        int $userId
    ): float {
        $weight = $baseWeight;

        // Fraud score adjustment
        if ($fraudAnalysis['score'] > 50) {
            $reduction = ($fraudAnalysis['score'] - 50) / 50;
            $weight *= (1 - $reduction);
        }

        // Automation detection
        if ($automationData['is_automated']) {
            $weight *= 0.1;
        } elseif ($automationData['confidence'] > 50) {
            $weight *= (1 - ($automationData['confidence'] / 200));
        }

        // Multi-account risk
        if ($multiAccountRisk) {
            $weight *= 0.3;
        }

        // Behavioral flags
        if (isset($behavior['behavior_score']) && $behavior['behavior_score'] > 50) {
            $weight *= (1 - ($behavior['behavior_score'] / 200));
        }

        // Trust rank adjustment
        if ($trustRank > 0.8) {
            $weight *= 1.2;
        } elseif ($trustRank < 0.3) {
            $weight *= 0.7;
        }

        // Risk level adjustment
        switch ($fraudAnalysis['risk_level']) {
            case 'high':
                $weight *= 0.3;
                break;
            case 'medium':
                $weight *= 0.6;
                break;
            case 'low':
                $weight *= 0.9;
                break;
        }

        // Apply diminishing returns for very high weights
        if ($weight > 2.0) {
            $weight = 2.0 + (($weight - 2.0) * 0.3);
        }

        // Final safety cap
        $weight = min(3.0, $weight);

        return round(max(0.1, min(3.0, $weight)), 2);
    }

    /**
     * Update fraud score in user_info table based on endorsement activity
     */
    private function updateFraudScore(int $userId, array $fraudAnalysis, array $automationData): void {
        $currentFraud = $fraudAnalysis['score'];
        $increase = 0;

        if ($automationData['is_automated']) {
            $increase += 20;
        }

        if ($fraudAnalysis['risk_level'] === 'high') {
            $increase += 10;
        }

        if ($increase > 0) {
            $newFraud = min(100, $currentFraud + $increase);
            
            // Update user_info table
            $this->userInfoRepo->updateFraudScore($userId, $newFraud);
            
            AuditLogger::log('fraud_score_increased', $userId, [
                'old_score' => $currentFraud,
                'new_score' => $newFraud,
                'reason' => 'endorsement_activity',
                'automation' => $automationData['is_automated']
            ], 'user');
        }
    }

    /**
     * Check if user has endorsed page
     */
    public function hasEndorsedPage(int $pageId, ?int $endorserUserId = null, ?string $context = null): bool {
        $endorserUserId = $endorserUserId ?? get_current_user_id();
        
        if (!$endorserUserId) {
            return false;
        }

        return $this->endorseRepo->hasEndorsed($endorserUserId, $pageId, $context);
    }

    /**
     * Get endorsement count for page
     */
    public function getPageEndorsementCount(int $pageId): int {
        return $this->endorseRepo->countForPage($pageId);
    }

    /**
     * Get endorsements for a page
     */
    public function getPageEndorsements(int $pageId, int $limit = 50): array {
        return $this->endorseRepo->getAllForPage($pageId, $limit);
    }

    /**
     * Get endorsements given by user with fraud data from user_info
     */
    public function getUserEndorsements(?int $endorserUserId = null, int $limit = 20): array {
        $endorserUserId = $endorserUserId ?? get_current_user_id();
        
        if (!$endorserUserId) {
            return [];
        }

        $endorsements = $this->endorseRepo->getByEndorser($endorserUserId, $limit);
        
        // Get user info for fraud score
        $userInfo = $this->userInfoRepo->getByUserId($endorserUserId);
        $fraudScore = $userInfo ? $userInfo->fraud_score : 0;
        
        foreach ($endorsements as &$endorsement) {
            $endorsement->endorser_fraud_score = $fraudScore;
        }
        
        return $endorsements;
    }

    /**
     * Update endorser's stats in user_info table
     */
    private function updateEndorserStats(int $userId): void {
        $endorsementCount = $this->endorseRepo->countByEndorser($userId);
        
        // Update user_info table
        $this->userInfoRepo->updateEndorsementsGiven($userId, $endorsementCount);
    }

    /**
     * Get PeepSo page data
     */
    private function getPeepSoPage(int $pageId): ?object {
        global $wpdb;
        
        $pagesTable = $wpdb->prefix . 'peepso_pages';
        
        $tableExists = $wpdb->get_var("SHOW TABLES LIKE '$pagesTable'") == $pagesTable;
        
        if ($tableExists) {
            $page = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$pagesTable} WHERE ID = %d",
                $pageId
            ));
            
            if ($page) {
                return $page;
            }
        }
        
        return get_post($pageId);
    }

    /**
     * Get page owner ID
     */
    private function getPageOwnerId(int $pageId): int {
        if (function_exists('bcc_trust_get_page_owner')) {
            $ownerId = bcc_trust_get_page_owner($pageId);
            if ($ownerId) {
                return (int) $ownerId;
            }
        }
        
        $post = get_post($pageId);
        return $post ? (int) $post->post_author : 0;
    }

    /**
     * Get endorsement statistics for a user
     */
    public function getUserEndorsementStats(int $userId): array {
        $totalGiven = $this->endorseRepo->countByEndorser($userId);
        $recentEndorsements = $this->endorseRepo->getByEndorser($userId, 10);
        
        $uniquePages = [];
        foreach ($recentEndorsements as $e) {
            $uniquePages[$e->page_id] = true;
        }
        
        return [
            'user_id' => $userId,
            'total_endorsements_given' => $totalGiven,
            'unique_pages_endorsed' => count($uniquePages),
            'recent_endorsements' => array_slice($recentEndorsements, 0, 5),
            'endorsement_weight_avg' => $this->getAverageEndorsementWeight($userId),
            'last_endorsement' => !empty($recentEndorsements) ? $recentEndorsements[0]->created_at : null
        ];
    }

    /**
     * Get average endorsement weight for a user
     */
    private function getAverageEndorsementWeight(int $userId): float {
        global $wpdb;
        
        $table = bcc_trust_endorsements_table();
        
        $avg = $wpdb->get_var($wpdb->prepare(
            "SELECT AVG(weight) FROM {$table}
             WHERE endorser_user_id = %d AND status = 1",
            $userId
        ));
        
        return $avg ? round((float) $avg, 2) : 1.0;
    }

    /**
     * Alias methods for backward compatibility
     */
    public function endorse(int $pageId, string $context = 'general', ?string $reason = null): array {
        return $this->endorsePage($pageId, $context, $reason);
    }

    public function revoke(int $pageId, string $context = 'general'): array {
        return $this->revokePageEndorsement($pageId, $context);
    }

    public function hasEndorsed(int $pageId, ?int $endorserUserId = null, ?string $context = null): bool {
        return $this->hasEndorsedPage($pageId, $endorserUserId, $context);
    }

    public function getEndorsementCount(int $pageId): int {
        return $this->getPageEndorsementCount($pageId);
    }
}
