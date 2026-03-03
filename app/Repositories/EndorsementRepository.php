<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

use Exception;
use BCCTrust\Security\RateLimiter;
use BCCTrust\Security\AuditLogger;
use BCCTrust\Security\FraudDetector;
use BCCTrust\Security\DeviceFingerprinter;
use BCCTrust\Security\BehavioralAnalyzer;
use BCCTrust\Security\TrustGraph;
use BCCTrust\Security\TransactionManager;

class EndorsementRepository {

    private string $table;
    private $fingerprinter;
    private $behavioralAnalyzer;
    private $trustGraph;
    private $scoreRepo;
    private $userInfoRepo;

    public function __construct() {
        global $wpdb;
        $this->table = bcc_trust_endorsements_table();
        $this->fingerprinter = new DeviceFingerprinter();
        $this->behavioralAnalyzer = new BehavioralAnalyzer();
        $this->trustGraph = new TrustGraph();
        $this->scoreRepo = new ScoreRepository();
        $this->userInfoRepo = new UserInfoRepository();
    }

    /**
     * Get specific endorsement
     */
    public function get(int $endorserUserId, int $pageId, string $context = 'general'): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE endorser_user_id = %d
                 AND page_id = %d
                 AND context = %s
                 AND status = 1",
                $endorserUserId,
                $pageId,
                $context
            )
        );
    }

    /**
     * Create endorsement
     */
    public function create(int $endorserUserId, int $pageId, string $context = 'general', float $weight = 3.0, ?string $reason = null): int {
        global $wpdb;

        $existing = $this->get($endorserUserId, $pageId, $context);

        if ($existing) {
            // Reactivate if exists
            $wpdb->update(
                $this->table,
                [
                    'status'     => 1,
                    'weight'     => $weight,
                    'reason'     => $reason,
                    'created_at' => current_time('mysql')
                ],
                ['id' => $existing->id],
                ['%d', '%f', '%s', '%s'],
                ['%d']
            );
            
            return $existing->id;
        } else {
            // Insert new
            $wpdb->insert(
                $this->table,
                [
                    'endorser_user_id' => $endorserUserId,
                    'page_id'          => $pageId,
                    'context'          => $context,
                    'weight'           => $weight,
                    'reason'           => $reason,
                    'status'           => 1,
                    'created_at'       => current_time('mysql')
                ],
                ['%d', '%d', '%s', '%f', '%s', '%d', '%s']
            );
            
            return $wpdb->insert_id;
        }
    }

    /**
     * Delete endorsement (soft delete)
     */
    public function delete(int $endorserUserId, int $pageId, string $context = 'general'): bool {
        global $wpdb;

        $result = $wpdb->update(
            $this->table,
            ['status' => 0],
            [
                'endorser_user_id' => $endorserUserId,
                'page_id'          => $pageId,
                'context'          => $context
            ],
            ['%d'],
            ['%d', '%d', '%s']
        );
        
        return $result !== false;
    }

    /**
     * Get all endorsements for a page
     */
    public function getAllForPage(int $pageId, int $limit = 50): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT e.*, u.display_name as endorser_name
                 FROM {$this->table} e
                 LEFT JOIN {$wpdb->users} u ON e.endorser_user_id = u.ID
                 WHERE e.page_id = %d
                 AND e.status = 1
                 ORDER BY e.created_at DESC
                 LIMIT %d",
                $pageId,
                $limit
            )
        );
    }

    /**
     * Get endorsements given by user
     */
    public function getByEndorser(int $endorserUserId, int $limit = 20): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT e.*, p.post_title as page_title
                 FROM {$this->table} e
                 LEFT JOIN {$wpdb->posts} p ON e.page_id = p.ID
                 WHERE e.endorser_user_id = %d
                 AND e.status = 1
                 ORDER BY e.created_at DESC
                 LIMIT %d",
                $endorserUserId,
                $limit
            )
        );
    }

    /**
     * Count endorsements for a page
     */
    public function countForPage(int $pageId): int {
        global $wpdb;

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table}
                 WHERE page_id = %d
                 AND status = 1",
                $pageId
            )
        );
    }

    /**
     * Count endorsements given by user
     */
    public function countByEndorser(int $endorserUserId): int {
        global $wpdb;

        return (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table}
                 WHERE endorser_user_id = %d
                 AND status = 1",
                $endorserUserId
            )
        );
    }

    /**
     * Get top endorsed pages
     */
    public function getTopEndorsed(string $context = null, int $limit = 10): array {
        global $wpdb;

        $where = "e.status = 1";
        $params = [];

        if ($context) {
            $where .= " AND e.context = %s";
            $params[] = $context;
        }

        $sql = "SELECT 
                    e.page_id, 
                    p.post_title as page_title,
                    COUNT(*) as endorsement_count, 
                    SUM(e.weight) as total_weight
                FROM {$this->table} e
                LEFT JOIN {$wpdb->posts} p ON e.page_id = p.ID
                WHERE {$where}
                GROUP BY e.page_id
                ORDER BY total_weight DESC, endorsement_count DESC
                LIMIT %d";
        
        $params[] = $limit;

        return $wpdb->get_results(
            $wpdb->prepare($sql, $params)
        );
    }

    /**
     * Check if user has endorsed page
     */
    public function hasEndorsed(int $endorserUserId, int $pageId, ?string $context = null): bool {
        global $wpdb;

        $sql = "SELECT COUNT(*) FROM {$this->table}
                WHERE endorser_user_id = %d
                AND page_id = %d
                AND status = 1";
        
        $params = [$endorserUserId, $pageId];

        if ($context) {
            $sql .= " AND context = %s";
            $params[] = $context;
        }

        return (bool) $wpdb->get_var($wpdb->prepare($sql, $params));
    }

    /**
     * Check if user has endorsed page (alias for backward compatibility)
     */
    public function hasEndorsedPage(int $pageId, int $endorserUserId, ?string $context = null): bool {
        return $this->hasEndorsed($endorserUserId, $pageId, $context);
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
     * Calculate base endorser weight using user_info table
     */
    private function calculateBaseEndorserWeight(int $userId): float {
        $weight = 1.0;

        // Get user info from user_info table
        $userInfo = $this->userInfoRepo->getByUserId($userId);
        
        if ($userInfo) {
            // Get user's own page scores
            $userPages = $this->scoreRepo->getByOwnerId($userId);
            
            if (!empty($userPages)) {
                $totalScore = 0;
                foreach ($userPages as $page) {
                    $totalScore += $page->getTotalScore();
                }
                $avgScore = $totalScore / count($userPages);
                
                // Apply tier-based weight
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

            // Check if user is verified
            if ($userInfo->is_verified) {
                $weight *= 1.2;
            }
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
            $originalWeight = $weight;
            $weight = 2.0 + (($weight - 2.0) * 0.3);
        }

        // Final safety cap
        $weight = min(3.0, $weight);

        return round(max(0.1, min(3.0, $weight)), 2);
    }

    /**
     * Apply endorsement bonus
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
     * Update endorser's stats in user_info table
     */
    private function updateEndorserStats(int $userId): void {
        $endorsementCount = $this->countByEndorser($userId);
        
        // Update user_info table
        $this->userInfoRepo->updateEndorsementsGiven($userId, $endorsementCount);
    }

    /**
     * Update fraud score in user_info table
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
     * Get page endorsement count
     */
    public function getPageEndorsementCount(int $pageId): int {
        return $this->countForPage($pageId);
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
        if ($this->hasEndorsed($endorserUserId, $pageId, $context)) {
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
            $endorsementId = $this->create(
                $endorserUserId,
                $pageId,
                $context,
                $adjustedWeight,
                $reason
            );

            // Apply endorsement bonus
            $this->applyEndorsementBonus($pageId, $adjustedWeight);

            // Update endorser's stats
            $this->updateEndorserStats($endorserUserId);

            // Update fraud score
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

            // Get updated page score
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
}