<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) {
    exit;
}

use BCCTrust\Repositories\UserInfoRepository;
use BCCTrust\Repositories\VerificationRepository;
use BCCTrust\Repositories\FraudAnalysisRepository;

class FraudDetector {
    
    /**
     * Cache group for fraud detection results
     */
    const CACHE_GROUP = 'bcc_fraud';
    const CACHE_TTL = 300; // 5 minutes

    /**
     * @var UserInfoRepository
     */
    private static $userInfoRepo;

    /**
     * @var VerificationRepository
     */
    private static $verificationRepo;

    /**
     * @var FraudAnalysisRepository
     */
    private static $fraudAnalysisRepo;

    /**
     * Initialize repositories
     */
    private static function initRepositories(): void {
        if (!self::$userInfoRepo) {
            self::$userInfoRepo = new UserInfoRepository();
        }
        if (!self::$verificationRepo) {
            self::$verificationRepo = new VerificationRepository();
        }
        if (!self::$fraudAnalysisRepo && class_exists('\\BCCTrust\\Repositories\\FraudAnalysisRepository')) {
            self::$fraudAnalysisRepo = new FraudAnalysisRepository();
        }
    }

    /**
     * Detect rapid voting (more than 20 votes in 2 minutes)
     */
    public static function detectRapidVoting(int $userId): bool {
        global $wpdb;

        $table = bcc_trust_activity_table();

        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table}
             WHERE user_id = %d
             AND action IN ('vote_up', 'vote_down')
             AND created_at > (UTC_TIMESTAMP() - INTERVAL 2 MINUTE)",
            $userId
        ));

        return $count > 20;
    }

    /**
     * Detect IP cluster (more than 50 actions in 10 minutes from same IP)
     */
    public static function detectIPCluster(string $ip): bool {
        global $wpdb;

        $table = bcc_trust_activity_table();
        
        // Convert IP to binary for lookup
        $ipBinary = null;
        if ($ip && $ip !== 'unknown') {
            $ipBinary = inet_pton($ip);
        }

        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table}
             WHERE ip_address = %s
             AND created_at > (UTC_TIMESTAMP() - INTERVAL 10 MINUTE)",
            $ipBinary
        ));

        return $count > 50;
    }

    /**
     * Detect vote ring (users consistently voting for each other's pages)
     */
    public static function detectVoteRing(int $userId): bool {
        global $wpdb;

        $votesTable = bcc_trust_votes_table();
        $pagesTable = $wpdb->posts;

        // Find pages where this user votes, and the page owners vote back
        $mutual = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT v1.page_id)
             FROM {$votesTable} v1
             JOIN {$pagesTable} p1 ON v1.page_id = p1.ID
             JOIN {$votesTable} v2 ON v2.voter_user_id = p1.post_author
             JOIN {$pagesTable} p2 ON v2.page_id = p2.ID
             WHERE v1.voter_user_id = %d
             AND v2.voter_user_id = p1.post_author
             AND p2.post_author = %d
             AND v1.status = 1
             AND v2.status = 1",
            $userId,
            $userId
        ));

        return $mutual > 3;
    }

    /**
     * Detect same IP voting for multiple different pages rapidly
     */
    public static function detectMultiAccountVoting(string $ip, int $userId): bool {
        global $wpdb;

        $auditTable = bcc_trust_activity_table();
        
        // Convert IP to binary for lookup
        $ipBinary = null;
        if ($ip && $ip !== 'unknown') {
            $ipBinary = inet_pton($ip);
        }

        $users = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT user_id) 
             FROM {$auditTable}
             WHERE ip_address = %s
             AND user_id != %d
             AND user_id IS NOT NULL
             AND created_at > (UTC_TIMESTAMP() - INTERVAL 1 DAY)",
            $ipBinary,
            $userId
        ));

        return $users > 5;
    }

    /**
     * Detect suspicious voting pattern (all votes same type)
     */
    public static function detectUniformVoting(int $userId): bool {
        global $wpdb;

        $votesTable = bcc_trust_votes_table();

        $stats = $wpdb->get_row($wpdb->prepare(
            "SELECT 
                SUM(CASE WHEN vote_type > 0 THEN 1 ELSE 0 END) as positive,
                SUM(CASE WHEN vote_type < 0 THEN 1 ELSE 0 END) as negative,
                COUNT(*) as total
             FROM {$votesTable}
             WHERE voter_user_id = %d
             AND status = 1
             AND created_at > (UTC_TIMESTAMP() - INTERVAL 7 DAY)",
            $userId
        ));

        if (!$stats || $stats->total < 10) {
            return false;
        }

        // If >90% of votes are the same type
        $positivePercent = $stats->positive / $stats->total;
        return $positivePercent > 0.9 || $positivePercent < 0.1;
    }

    /**
     * Detect rapid vote changes (flip-flopping)
     */
    public static function detectVoteChanging(int $userId, int $minutes = 30): bool {
        global $wpdb;

        $votesTable = bcc_trust_votes_table();

        $changes = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) 
             FROM {$votesTable} v1
             JOIN {$votesTable} v2 ON v1.page_id = v2.page_id
             WHERE v1.voter_user_id = %d
             AND v2.voter_user_id = %d
             AND v1.id != v2.id
             AND v1.vote_type != v2.vote_type
             AND v2.created_at > v1.created_at
             AND v2.created_at > (UTC_TIMESTAMP() - INTERVAL %d MINUTE)
             AND v1.status = 1
             AND v2.status = 1",
            $userId,
            $userId,
            $minutes
        ));

        return $changes > 5;
    }

    /**
     * ======================================================
     * ENHANCED FRAUD DETECTION USING NEW SYSTEMS
     * ======================================================
     */

    /**
     * Comprehensive fraud analysis using all available data
     * 
     * @param int $userId
     * @return array Complete fraud analysis
     */
    public static function analyzeFraud(int $userId): array {
        self::initRepositories();

        // Check cache first
        $cached = wp_cache_get('fraud_analysis_' . $userId, self::CACHE_GROUP);
        if ($cached !== false) {
            return $cached;
        }

        // Get user info from user_info table
        $userInfo = self::$userInfoRepo->getByUserId($userId);

        $results = [
            'triggers' => [],
            'score' => 0,
            'confidence' => 0,
            'risk_level' => 'low',
            'details' => []
        ];

        // ======================================================
        // 1. Legacy fraud detection (existing methods)
        // ======================================================
        
        if (self::detectRapidVoting($userId)) {
            $results['triggers'][] = 'rapid_voting';
            $results['score'] += 30;
            $results['details']['rapid_voting'] = true;
        }

        if (self::detectUniformVoting($userId)) {
            $results['triggers'][] = 'uniform_voting';
            $results['score'] += 20;
            $results['details']['uniform_voting'] = true;
        }

        if (self::detectVoteRing($userId)) {
            $results['triggers'][] = 'vote_ring';
            $results['score'] += 25;
            $results['details']['vote_ring'] = true;
        }

        if (self::detectVoteChanging($userId)) {
            $results['triggers'][] = 'vote_changing';
            $results['score'] += 15;
            $results['details']['vote_changing'] = true;
        }

        $ip = self::getUserIp($userId);
        if ($ip && self::detectMultiAccountVoting($ip, $userId)) {
            $results['triggers'][] = 'multi_account';
            $results['score'] += 25;
            $results['details']['multi_account'] = true;
        }

        // ======================================================
        // 2. Device fingerprinting analysis
        // ======================================================
        
        $fingerprinter = new DeviceFingerprinter();
        $deviceFraudProbability = $fingerprinter->calculateDeviceFraudProbability($userId);
        
        if ($deviceFraudProbability > 0.7) {
            $results['triggers'][] = 'high_device_fraud';
            $results['score'] += 30;
            $results['details']['device_fraud_probability'] = $deviceFraudProbability;
        } elseif ($deviceFraudProbability > 0.4) {
            $results['triggers'][] = 'medium_device_fraud';
            $results['score'] += 15;
            $results['details']['device_fraud_probability'] = $deviceFraudProbability;
        }

        // Check for multiple accounts on same device
        $fingerprints = $fingerprinter->getUserFingerprints($userId);
        foreach ($fingerprints as $fp) {
            $userCount = $fingerprinter->getFingerprintUserCount($fp->fingerprint);
            if ($userCount > 3) {
                $results['triggers'][] = 'shared_device_' . $userCount . '_users';
                $results['score'] += min(30, $userCount * 5);
                $results['details']['shared_device_count'] = $userCount;
                break;
            }
        }

        // ======================================================
        // 3. Behavioral analysis
        // ======================================================
        
        $behavioralAnalyzer = new BehavioralAnalyzer();
        $behavior = $behavioralAnalyzer->analyzeUserBehavior($userId);
        
        $results['details']['behavior_score'] = $behavior['behavior_score'];
        $results['details']['behavior_flags'] = $behavior['flags'];
        
        if ($behavior['behavior_score'] > 70) {
            $results['triggers'][] = 'critical_behavior';
            $results['score'] += 40;
        } elseif ($behavior['behavior_score'] > 50) {
            $results['triggers'][] = 'high_risk_behavior';
            $results['score'] += 25;
        } elseif ($behavior['behavior_score'] > 30) {
            $results['triggers'][] = 'suspicious_behavior';
            $results['score'] += 15;
        }

        // Add specific behavior flags to triggers
        foreach ($behavior['flags'] as $flag) {
            $results['triggers'][] = 'behavior_' . $flag;
        }

        // ======================================================
        // 4. Trust graph analysis
        // ======================================================
        
        $trustGraph = new TrustGraph();
        
        // Get trust rank from user_info table
        $trustRank = $userInfo ? (float) $userInfo->trust_rank : 0;
        if (!$trustRank) {
            $trustRank = $trustGraph->calculateTrustRank($userId);
            if ($userInfo) {
                self::$userInfoRepo->updateTrustRank($userId, $trustRank);
            }
        }
        
        $results['details']['trust_rank'] = $trustRank;
        
        // Low trust rank increases fraud score
        if ($trustRank < 0.2) {
            $results['triggers'][] = 'very_low_trust';
            $results['score'] += 30;
        } elseif ($trustRank < 0.4) {
            $results['triggers'][] = 'low_trust';
            $results['score'] += 15;
        }

        // Check if user is in a vote ring
        $rings = $trustGraph->detectVoteRings(3);
        foreach ($rings as $ring) {
            if (in_array($userId, $ring['users'])) {
                $results['triggers'][] = 'in_vote_ring';
                $results['score'] += 40;
                $results['details']['ring_size'] = $ring['size'];
                $results['details']['ring_strength'] = $ring['strength'];
                break;
            }
        }

        // ======================================================
        // 5. Account age and verification status from user_info
        // ======================================================
        
        if ($userInfo) {
            $user = get_userdata($userId);
            if ($user) {
                $accountAge = time() - strtotime($user->user_registered);
                $accountDays = $accountAge / (24 * 3600);
                
                $results['details']['account_days'] = round($accountDays, 1);
                
                // Very new accounts are higher risk
                if ($accountDays < 1) {
                    $results['triggers'][] = 'brand_new_account';
                    $results['score'] += 20;
                } elseif ($accountDays < 7) {
                    $results['triggers'][] = 'new_account';
                    $results['score'] += 10;
                }
            }

            // Email verification from user_info
            if (!$userInfo->is_verified) {
                $results['triggers'][] = 'unverified_email';
                $results['score'] += 15;
                $results['details']['email_verified'] = false;
            } else {
                $results['details']['email_verified'] = true;
            }
        }

        // ======================================================
        // 6. Calculate final scores and risk level
        // ======================================================
        
        // Cap score at 100
        $results['score'] = min(100, $results['score']);
        
        // Calculate confidence based on data availability
        $dataPoints = count($results['details']);
        $results['confidence'] = min(1, $dataPoints / 15); // Need at least 15 data points for full confidence
        
        // Determine risk level
        $results['risk_level'] = self::getRiskLevel($results['score']);
        
        // Remove duplicate triggers
        $results['triggers'] = array_unique($results['triggers']);
        
        // Cache results
        wp_cache_set('fraud_analysis_' . $userId, $results, self::CACHE_GROUP, self::CACHE_TTL);
        
        return $results;
    }

    /**
     * Get risk level based on score
     */
    private static function getRiskLevel(int $score): string {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'minimal';
    }

    /**
     * Enhanced fraud score calculation using all systems and user_info table
     */
    public static function getEnhancedFraudScore(int $userId): int {
        self::initRepositories();
        
        $analysis = self::analyzeFraud($userId);
        
        // Get existing fraud score from user_info
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        $existingScore = $userInfo ? (int) $userInfo->fraud_score : 0;
        
        // Blend with new analysis (70% new, 30% existing to smooth changes)
        $newScore = (int) round(($analysis['score'] * 0.7) + ($existingScore * 0.3));
        
        // Cap at 100
        $newScore = min(100, max(0, $newScore));
        
        // Update user_info table
        self::$userInfoRepo->updateFraudScore($userId, $newScore);
        
        // Store analysis results in the new fraud_analysis table
        if (self::$fraudAnalysisRepo) {
            // Set expiration to 90 days from now
            $expiresAt = date('Y-m-d H:i:s', strtotime('+90 days'));
            
            self::$fraudAnalysisRepo->storeAnalysis(
                $userId,
                $newScore,
                $analysis['risk_level'],
                $analysis['confidence'],
                $analysis['triggers'],
                $analysis['details'],
                $expiresAt
            );
        }
        
        return $newScore;
    }

    /**
     * Check if user should be auto-suspended
     */
    public static function shouldSuspend(int $userId): bool {
        self::initRepositories();
        
        $analysis = self::analyzeFraud($userId);
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        
        // Auto-suspend conditions
        if ($analysis['score'] >= 85) {
            return true;
        }
        
        // Check for specific critical triggers
        $criticalTriggers = ['in_vote_ring', 'critical_behavior', 'high_device_fraud'];
        foreach ($criticalTriggers as $trigger) {
            if (in_array($trigger, $analysis['triggers'])) {
                // Only suspend if we have high confidence
                if ($analysis['confidence'] > 0.7) {
                    return true;
                }
            }
        }
        
        // Multiple high-risk triggers
        $highRiskCount = 0;
        foreach ($analysis['triggers'] as $trigger) {
            if (strpos($trigger, 'high_') !== false || strpos($trigger, 'critical_') !== false) {
                $highRiskCount++;
            }
        }
        
        if ($highRiskCount >= 3 && $analysis['confidence'] > 0.8) {
            return true;
        }
        
        return false;
    }

    /**
     * Get fraud analysis summary for dashboard
     */
    public static function getFraudSummary(int $userId): array {
        self::initRepositories();
        
        $analysis = self::analyzeFraud($userId);
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        
        return [
            'user_id' => $userId,
            'fraud_score' => $analysis['score'],
            'risk_level' => $analysis['risk_level'],
            'confidence' => round($analysis['confidence'] * 100, 1) . '%',
            'triggers' => $analysis['triggers'],
            'top_concerns' => array_slice($analysis['triggers'], 0, 5),
            'last_updated' => $userInfo ? $userInfo->last_calculated_at : 'never',
            'suspended' => $userInfo ? (bool) $userInfo->is_suspended : false
        ];
    }

    /**
     * Check if user is suspended
     */
    public static function isSuspended(int $userId): bool {
        self::initRepositories();
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        return $userInfo ? (bool) $userInfo->is_suspended : false;
    }

    /**
     * Get original fraud score (legacy method)
     */
    public static function getFraudScore(int $userId): int {
        self::initRepositories();
        
        // Try to get enhanced score first
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        if ($userInfo && $userInfo->fraud_score > 0) {
            return $userInfo->fraud_score;
        }
        
        // Fall back to legacy calculation
        $score = 0;
        $reasons = [];

        if (self::detectRapidVoting($userId)) {
            $score += 30;
            $reasons[] = 'rapid_voting';
        }

        if (self::detectUniformVoting($userId)) {
            $score += 20;
            $reasons[] = 'uniform_voting';
        }

        if (self::detectVoteRing($userId)) {
            $score += 25;
            $reasons[] = 'vote_ring';
        }

        if (self::detectVoteChanging($userId)) {
            $score += 15;
            $reasons[] = 'vote_changing';
        }

        $ip = self::getUserIp($userId);
        if ($ip && self::detectMultiAccountVoting($ip, $userId)) {
            $score += 25;
            $reasons[] = 'multi_account';
        }

        // Log high fraud scores
        if ($score > 50 && class_exists('\\BCCTrust\\Security\\AuditLogger')) {
            AuditLogger::log('fraud_detected', $userId, [
                'score' => $score,
                'reasons' => $reasons
            ], 'user');
        }

        return min(100, $score);
    }

    /**
     * Update fraud score in user_info table
     */
    public static function updateFraudScore(int $userId): void {
        self::initRepositories();
        
        $score = self::getEnhancedFraudScore($userId);
        
        // Auto-suspend if score too high
        if (self::shouldSuspend($userId) && !self::isSuspended($userId)) {
            self::suspendUser($userId, 'auto_suspension', $score);
        }
        
        // Log significant changes
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        $oldScore = $userInfo ? (int) $userInfo->fraud_score : 0;
        
        if (abs($score - $oldScore) > 20) {
            if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
                AuditLogger::log('fraud_score_significant_change', $userId, [
                    'old_score' => $oldScore,
                    'new_score' => $score
                ], 'user');
            }
        }
    }

    /**
     * Suspend a user with reason
     */
    public static function suspendUser(int $userId, string $reason, int $fraudScore = null): void {
        self::initRepositories();
        
        // Update user_info table
        self::$userInfoRepo->suspendUser($userId, $reason);
        
        if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
            AuditLogger::log('user_suspended', $userId, [
                'reason' => $reason,
                'fraud_score' => $fraudScore
            ], 'user');
        }
    }

    /**
     * Unsuspend a user
     */
    public static function unsuspendUser(int $userId): void {
        self::initRepositories();
        
        // Update user_info table
        self::$userInfoRepo->unsuspendUser($userId);
        
        if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
            AuditLogger::log('user_unsuspended', $userId, [], 'user');
        }
    }

    /**
     * Get user's last known IP
     */
    private static function getUserIp(int $userId): ?string {
        global $wpdb;

        $auditTable = bcc_trust_activity_table();

        $ipBinary = $wpdb->get_var($wpdb->prepare(
            "SELECT ip_address 
             FROM {$auditTable}
             WHERE user_id = %d
             AND ip_address IS NOT NULL
             ORDER BY created_at DESC
             LIMIT 1",
            $userId
        ));

        if ($ipBinary) {
            return inet_ntop($ipBinary);
        }

        return null;
    }

    /**
     * Get suspicious users with enhanced filtering
     */
    public static function getSuspiciousUsers(int $threshold = 50, int $limit = 100): array {
        self::initRepositories();
        
        // Query user_info table for high fraud scores
        global $wpdb;
        $userInfoTable = bcc_trust_user_info_table();
        
        $results = $wpdb->get_results($wpdb->prepare("
            SELECT ui.*, u.display_name, u.user_email, u.user_registered
            FROM {$userInfoTable} ui
            JOIN {$wpdb->users} u ON ui.user_id = u.ID
            WHERE ui.fraud_score >= %d
            ORDER BY ui.fraud_score DESC
            LIMIT %d
        ", $threshold, $limit));

        $suspicious = [];
        foreach ($results as $row) {
            $suspicious[] = [
                'id' => $row->user_id,
                'email' => $row->user_email,
                'name' => $row->display_name,
                'registered' => $row->user_registered,
                'fraud_score' => (int) $row->fraud_score,
                'risk_level' => $row->risk_level,
                'automation_score' => $row->automation_score,
                'behavior_score' => $row->behavior_score,
                'suspended' => (bool) $row->is_suspended
            ];
        }

        return $suspicious;
    }

    /**
     * Get fraud statistics for dashboard from user_info table
     */
    public static function getStats(): array {
        global $wpdb;
        
        $userInfoTable = bcc_trust_user_info_table();
        
        $stats = $wpdb->get_row("
            SELECT 
                COUNT(*) as total_users,
                AVG(fraud_score) as avg_fraud_score,
                SUM(CASE WHEN fraud_score >= 80 THEN 1 ELSE 0 END) as critical_risk,
                SUM(CASE WHEN fraud_score BETWEEN 60 AND 79 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN fraud_score BETWEEN 40 AND 59 THEN 1 ELSE 0 END) as medium_risk,
                SUM(CASE WHEN fraud_score BETWEEN 20 AND 39 THEN 1 ELSE 0 END) as low_risk,
                SUM(CASE WHEN fraud_score < 20 THEN 1 ELSE 0 END) as minimal_risk,
                SUM(CASE WHEN is_suspended = 1 THEN 1 ELSE 0 END) as suspended_users
            FROM {$userInfoTable}
        ");
        
        return [
            'total_users' => (int) ($stats->total_users ?? 0),
            'average_fraud_score' => round((float) ($stats->avg_fraud_score ?? 0), 1),
            'risk_distribution' => [
                'critical' => (int) ($stats->critical_risk ?? 0),
                'high' => (int) ($stats->high_risk ?? 0),
                'medium' => (int) ($stats->medium_risk ?? 0),
                'low' => (int) ($stats->low_risk ?? 0),
                'minimal' => (int) ($stats->minimal_risk ?? 0)
            ],
            'suspended_users' => (int) ($stats->suspended_users ?? 0),
            'last_updated' => current_time('mysql')
        ];
    }

    /**
     * Get historical fraud analysis for a user
     */
    public static function getFraudHistory(int $userId, int $limit = 10): array {
        self::initRepositories();
        
        if (!self::$fraudAnalysisRepo) {
            return [];
        }
        
        return self::$fraudAnalysisRepo->getHistoryForUser($userId, $limit);
    }

    /**
     * Clear fraud analysis cache for a user
     */
    public static function clearCache(int $userId): void {
        wp_cache_delete('fraud_analysis_' . $userId, self::CACHE_GROUP);
    }
}