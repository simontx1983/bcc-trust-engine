<?php
/**
 * Vote Service
 * 
 * Handles voting operations with PageScore value objects
 * 
 * @package BCCTrust\Services
 * @version 2.0.0
 */

namespace BCCTrust\Services;

use Exception;
use BCCTrust\Repositories\VoteRepository;
use BCCTrust\Repositories\ScoreRepository;
use BCCTrust\Repositories\ReputationRepository;
use BCCTrust\Security\RateLimiter;
use BCCTrust\Security\AuditLogger;
use BCCTrust\Security\TransactionManager;
use BCCTrust\Security\FraudDetector;
use BCCTrust\Security\DeviceFingerprinter;
use BCCTrust\Security\BehavioralAnalyzer;
use BCCTrust\Security\TrustGraph;
use BCCTrust\ValueObjects\PageScore;
use DateTimeImmutable;

if (!defined('ABSPATH')) exit;

class VoteService {

    private VoteRepository $voteRepo;
    private ScoreRepository $scoreRepo;
    private ReputationRepository $reputationRepo;
    private DeviceFingerprinter $fingerprinter;
    private BehavioralAnalyzer $behavioralAnalyzer;
    private TrustGraph $trustGraph;

    public function __construct() {
        $this->voteRepo = new VoteRepository();
        $this->scoreRepo = new ScoreRepository();
        $this->reputationRepo = new ReputationRepository();
        $this->fingerprinter = new DeviceFingerprinter();
        $this->behavioralAnalyzer = new BehavioralAnalyzer();
        $this->trustGraph = new TrustGraph();
    }

    /**
     * Cast or update a vote on a PeepSo Page
     */
    public function castPageVote(int $pageId, int $voteType, ?array $fingerprintData = null): array {
        $voterId = get_current_user_id();

        if (!$voterId) {
            throw new Exception('Authentication required.');
        }

        if (!in_array($voteType, [-1, 1])) {
            throw new Exception('Invalid vote type.');
        }

        // Verify page exists
        $page = $this->getPeepSoPage($pageId);
        if (!$page) {
            throw new Exception('Invalid page.');
        }

        // Get page owner
        $pageOwnerId = $this->getPageOwnerId($pageId);

        // Can't vote on your own page
        if ($pageOwnerId == $voterId) {
            throw new Exception('You cannot vote on your own page.');
        }

        // Check if already voted same type
        $existingVote = $this->voteRepo->get($voterId, $pageId);
        if ($existingVote && $existingVote->vote_type == $voteType) {
            throw new Exception('You have already cast this vote.');
        }

        // Rate limiting
        RateLimiter::enforce('vote', 30, 3600);

        // ======================================================
        // Get or create current score as PageScore value object
        // ======================================================
        
        $currentScore = $this->scoreRepo->getByPageId($pageId);
        
        if (!$currentScore) {
            // Create default score
            $currentScore = $this->scoreRepo->createDefault($pageId, $pageOwnerId);
        }

        // ======================================================
        // FINGERPRINT AND BOT DETECTION
        // ======================================================
        
        $fingerprint = $fingerprintData['hash'] ?? $this->fingerprinter->generateFingerprint();
        $automationData = $this->fingerprinter->detectAutomation();
        $this->fingerprinter->storeFingerprint($voterId, $fingerprint, $automationData);
        
        $userCount = $this->fingerprinter->getFingerprintUserCount($fingerprint);
        $multiAccountRisk = ($userCount > 3);
        $deviceFraudProbability = $this->fingerprinter->calculateDeviceFraudProbability($voterId);

        // ======================================================
        // BEHAVIORAL ANALYSIS
        // ======================================================
        
        $behavior = $this->behavioralAnalyzer->analyzeUserBehavior($voterId);

        // ======================================================
        // TRUST GRAPH ANALYSIS
        // ======================================================
        
        $trustRank = (float) get_user_meta($voterId, 'bcc_trust_graph_rank', true);
        if (!$trustRank) {
            $trustRank = $this->trustGraph->calculateTrustRank($voterId);
            update_user_meta($voterId, 'bcc_trust_graph_rank', $trustRank);
        }

        // ======================================================
        // FRAUD DETECTION
        // ======================================================
        
        if (FraudDetector::detectRapidVoting($voterId)) {
            AuditLogger::log('fraud_rapid_voting', $pageId, [
                'voter_id' => $voterId,
                'vote_type' => $voteType
            ], 'page');
            throw new Exception('Vote rate limit exceeded.');
        }

        // ======================================================
        // CALCULATE VOTE WEIGHT
        // ======================================================
        
        $baseWeight = $this->calculateBaseVoteWeight($voterId);
        
        $adjustedWeight = $this->applyFraudAdjustments(
            $baseWeight,
            $automationData,
            $multiAccountRisk,
            $deviceFraudProbability,
            $behavior,
            $trustRank,
            $voterId
        );

        // Check if this is a new voter
        $isNewVoter = !$existingVote;

        // ======================================================
        // CREATE NEW SCORE WITH VOTE (immutable transformation)
        // ======================================================
        
        $newScore = $currentScore->withNewVote(
            $adjustedWeight,
            $voteType === 1,  // true for upvote, false for downvote
            $isNewVoter
        );

        // Log the analysis
        AuditLogger::log('vote_analysis', $pageId, [
            'voter_id' => $voterId,
            'base_weight' => $baseWeight,
            'final_weight' => $adjustedWeight,
            'automation_detected' => $automationData['is_automated'],
            'behavior_score' => $behavior['behavior_score'] ?? 0,
            'trust_rank' => $trustRank,
            'score_before' => $currentScore->getTotalScore(),
            'score_after' => $newScore->getTotalScore()
        ], 'page');

        // ======================================================
        // EXECUTE IN TRANSACTION
        // ======================================================
        
        return TransactionManager::run(function () use (
            $voterId, $pageId, $voteType, $page, $pageOwnerId,
            $adjustedWeight, $automationData, $fingerprint, $newScore,
            $baseWeight, $isNewVoter
        ) {
            // Save the new score
            $this->scoreRepo->save($newScore);

            // Convert IP to binary for storage
            $ip = $this->getClientIp();
            $ipBinary = ($ip && $ip !== 'unknown') ? inet_pton($ip) : null;

            // Save vote
            $voteId = $this->voteRepo->upsert([
                'voter_user_id' => $voterId,
                'page_id'       => $pageId,
                'vote_type'     => $voteType,
                'weight'        => $adjustedWeight,
                'reason'        => $this->getDownvoteReason($voteType),
                'explanation'   => null,
                'ip_address'    => $ipBinary
            ]);

            // Update voter's stats
            $this->updateVoterStats($voterId);

            // Log the vote
            AuditLogger::vote($pageId, $voteType, [
                'voter_id' => $voterId,
                'weight' => $adjustedWeight,
                'fingerprint' => substr($fingerprint, 0, 16) . '...'
            ]);

            return [
                'success' => true,
                'vote_id' => $voteId,
                'vote_type' => $voteType,
                'weight' => $adjustedWeight,
                'page_id' => $pageId,
                'score' => $newScore->toApiResponse(),
                'analysis' => [
                    'weight_applied' => $adjustedWeight,
                    'base_weight' => $baseWeight,
                    'automation_detected' => $automationData['is_automated'],
                    'new_voter' => $isNewVoter,
                    'has_sufficient_data' => $newScore->hasSufficientData()
                ]
            ];
        });
    }

    /**
     * Calculate base vote weight from reputation - FIXED CONSTANT REFERENCES
     */
    private function calculateBaseVoteWeight(int $voterId): float {
        // Base weight for neutral users - use global constants with fallbacks
        $weight = defined('BCC_TRUST_WEIGHT_NEUTRAL') ? BCC_TRUST_WEIGHT_NEUTRAL : 0.15;

        // Get voter's reputation
        $reputation = $this->reputationRepo->getByUserId($voterId);
        
        if ($reputation) {
            $tierWeights = [
                'elite' => defined('BCC_TRUST_WEIGHT_ELITE') ? BCC_TRUST_WEIGHT_ELITE : 0.35,
                'trusted' => defined('BCC_TRUST_WEIGHT_TRUSTED') ? BCC_TRUST_WEIGHT_TRUSTED : 0.25,
                'neutral' => defined('BCC_TRUST_WEIGHT_NEUTRAL') ? BCC_TRUST_WEIGHT_NEUTRAL : 0.15,
                'caution' => defined('BCC_TRUST_WEIGHT_CAUTION') ? BCC_TRUST_WEIGHT_CAUTION : 0.08,
                'risky' => defined('BCC_TRUST_WEIGHT_RISKY') ? BCC_TRUST_WEIGHT_RISKY : 0.03
            ];
            
            $tier = $reputation->reputation_tier ?? 'neutral';
            $weight = $tierWeights[$tier] ?? $tierWeights['neutral'];
        }

        // Check if voter is verified
        $verificationRepo = new \BCCTrust\Repositories\VerificationRepository();
        if ($verificationRepo->isVerified($voterId)) {
            $weight *= 1.1;
        }

        // Account age factor
        $user = get_userdata($voterId);
        if ($user) {
            $accountAge = time() - strtotime($user->user_registered);
            $accountDays = $accountAge / (24 * 60 * 60);
            
            $ageNew = defined('BCC_TRUST_AGE_NEW') ? BCC_TRUST_AGE_NEW : 7;
            $ageEstablished = defined('BCC_TRUST_AGE_ESTABLISHED') ? BCC_TRUST_AGE_ESTABLISHED : 30;
            
            if ($accountDays < $ageNew) {
                $weight *= 0.5;
            } elseif ($accountDays < $ageEstablished) {
                $weight *= 0.75;
            }
        }

        return $weight;
    }

    /**
     * Apply fraud adjustments to vote weight
     */
    private function applyFraudAdjustments(
        float $baseWeight,
        array $automationData,
        bool $multiAccountRisk,
        float $deviceFraudProbability,
        array $behavior,
        float $trustRank,
        int $voterId
    ): float {
        $weight = $baseWeight;
        $adjustments = [];

        // Apply diminishing returns for high-weight voters
        if ($weight > 0.3) {
            $originalWeight = $weight;
            $weight = log10($weight * 10) * 0.3;
            $weight = max(0.15, min(0.6, $weight));
        }

        // Automation detection
        if ($automationData['is_automated']) {
            $weight *= 0.1;
        } elseif ($automationData['confidence'] > 50) {
            $weight *= (1 - ($automationData['confidence'] / 200));
        }

        // Multi-account risk
        if ($multiAccountRisk) {
            $weight *= 0.1;
        }

        // Device fraud probability
        if ($deviceFraudProbability > 0.7) {
            $weight *= (1 - $deviceFraudProbability);
        }

        // Behavioral analysis
        if (isset($behavior['behavior_score']) && $behavior['behavior_score'] > 50) {
            $weight *= (1 - ($behavior['behavior_score'] / 200));
        }

        // Trust rank boost
        if ($trustRank > 0.7) {
            $boost = min(0.2, ($trustRank - 0.7) * 0.5);
            $weight *= (1 + $boost);
        }

        // Fraud score from user meta
        $fraudScore = (int) get_user_meta($voterId, 'bcc_trust_fraud_score', true);
        $fraudMedium = defined('BCC_TRUST_FRAUD_MEDIUM') ? BCC_TRUST_FRAUD_MEDIUM : 40;
        if ($fraudScore > $fraudMedium) {
            $weight *= max(0.1, 1 - ($fraudScore / 100));
        }

        // Final safety cap
        $maxVoteWeight = defined('BCC_TRUST_MAX_VOTE_WEIGHT') ? BCC_TRUST_MAX_VOTE_WEIGHT : 0.6;
        $weight = min($maxVoteWeight, $weight);

        return round(max(0.01, min($maxVoteWeight, $weight)), 3);
    }

    /**
     * Remove a vote
     */
    public function removePageVote(int $pageId): array {
        $voterId = get_current_user_id();

        if (!$voterId) {
            throw new Exception('Authentication required.');
        }

        $existingVote = $this->voteRepo->get($voterId, $pageId);
        if (!$existingVote) {
            throw new Exception('No vote found to remove.');
        }

        return TransactionManager::run(function () use ($voterId, $pageId, $existingVote) {
            // Get current score
            $currentScore = $this->scoreRepo->getByPageId($pageId);
            
            if (!$currentScore) {
                throw new Exception('Page score not found');
            }

            // Since we can't easily reverse a vote, we'll recalculate from scratch
            // This is simpler than trying to subtract the vote
            $allVotes = $this->voteRepo->getAllForPage($pageId);
            
            // Remove this user's vote from the list
            $remainingVotes = array_filter($allVotes, function($vote) use ($voterId) {
                return $vote->voter_user_id !== $voterId;
            });

            // Recalculate score from remaining votes
            $newScore = $this->recalculateFromVotes($pageId, $remainingVotes, $currentScore->getPageOwnerId());

            // Soft delete vote
            $this->voteRepo->delete($voterId, $pageId);

            // Save new score
            $this->scoreRepo->save($newScore);

            // Update voter's stats
            $this->updateVoterStats($voterId);

            // Audit log
            AuditLogger::removeVote($pageId, [
                'voter_id' => $voterId,
                'previous_vote' => $existingVote->vote_type,
                'previous_weight' => $existingVote->weight,
                'score_before' => $currentScore->getTotalScore(),
                'score_after' => $newScore->getTotalScore()
            ]);

            return [
                'success' => true,
                'page_id' => $pageId,
                'removed' => true,
                'score' => $newScore->toApiResponse()
            ];
        });
    }

    /**
     * Recalculate score from votes
     */
    private function recalculateFromVotes(int $pageId, array $votes, int $ownerId): PageScore {
        $positive = 0;
        $negative = 0;
        $voterIds = [];
        $lastVoteAt = null;

        foreach ($votes as $vote) {
            // Apply time decay
            $effectiveWeight = $this->applyTimeDecay($vote->weight, $vote->created_at);
            
            if ($vote->vote_type > 0) {
                $positive += $effectiveWeight;
            } else {
                $negative += $effectiveWeight;
            }
            
            $voterIds[$vote->voter_user_id] = true;
            
            if (!$lastVoteAt || strtotime($vote->created_at) > strtotime($lastVoteAt)) {
                $lastVoteAt = $vote->created_at;
            }
        }

        $voteCount = count($votes);
        $uniqueVoters = count($voterIds);

        // Calculate total score (base 50, +/- based on weighted votes)
        $netScore = $positive - $negative;
        $totalScore = 50 + ($netScore * 2); // Each weighted point = 2 score points
        $totalScore = max(0, min(100, $totalScore));

        // Calculate confidence score
        $confidenceScore = $this->calculateConfidenceScore($voteCount, $uniqueVoters, $positive, $negative);

        // Determine reputation tier
        $tier = $this->determineTier($totalScore);

        // Get endorsement count from current score
        $currentScore = $this->scoreRepo->getByPageId($pageId);
        $endorsementCount = $currentScore ? $currentScore->getEndorsementCount() : 0;

        // Create new PageScore
        return new PageScore(
            $pageId,
            $ownerId,
            $totalScore,
            $positive,
            $negative,
            $voteCount,
            $uniqueVoters,
            $confidenceScore,
            $tier,
            $endorsementCount,
            $lastVoteAt ? new DateTimeImmutable($lastVoteAt) : null,
            new DateTimeImmutable()
        );
    }

    /**
     * Calculate confidence score
     */
    private function calculateConfidenceScore(int $voteCount, int $uniqueVoters, float $positive, float $negative): float {
        if ($voteCount === 0) {
            return 0;
        }

        $volumeConfidence = min(1, $voteCount / 50);
        $diversityConfidence = $uniqueVoters / $voteCount;
        
        $totalWeight = $positive + $negative;
        $balanceConfidence = 1.0;
        if ($totalWeight > 0) {
            $balance = abs($positive - $negative) / $totalWeight;
            $balanceConfidence = 1 - ($balance * 0.5);
        }

        return round(
            ($volumeConfidence * 0.5) +
            ($diversityConfidence * 0.3) +
            ($balanceConfidence * 0.2),
            2
        );
    }

    /**
     * Determine reputation tier
     */
    private function determineTier(float $score): string {
        if ($score >= 80) return 'elite';
        if ($score >= 65) return 'trusted';
        if ($score >= 45) return 'neutral';
        if ($score >= 30) return 'caution';
        return 'risky';
    }

    /**
     * Apply time decay to vote weight
     */
    private function applyTimeDecay(float $weight, string $voteDate): float {
        $voteTime = strtotime($voteDate);
        $now = time();
        $daysOld = ($now - $voteTime) / (24 * 3600);
        
        $decayDays = defined('BCC_TRUST_DECAY_DAYS') ? BCC_TRUST_DECAY_DAYS : 90;
        $decayMin = defined('BCC_TRUST_DECAY_MIN') ? BCC_TRUST_DECAY_MIN : 0.3;
        
        if ($daysOld > $decayDays) {
            return 0;
        }
        
        $decayFactor = max($decayMin, 1 - ($daysOld / $decayDays));
        return $weight * $decayFactor;
    }

    /**
     * Get user's vote on page
     */
    public function getUserPageVote(int $pageId, ?int $userId = null): ?object {
        $userId = $userId ?? get_current_user_id();
        
        if (!$userId) {
            return null;
        }

        return $this->voteRepo->get($userId, $pageId);
    }

    /**
     * Check if user has voted on page
     */
    public function hasUserVotedPage(int $pageId, ?int $userId = null): bool {
        return (bool) $this->getUserPageVote($pageId, $userId);
    }

    /**
     * Get user's recent votes
     */
    public function getUserVotes(?int $userId = null, int $limit = 20): array {
        $userId = $userId ?? get_current_user_id();
        
        if (!$userId) {
            return [];
        }

        return $this->voteRepo->getByVoter($userId, $limit);
    }

    /**
     * Get vote statistics for a page
     */
    public function getPageVoteStats(int $pageId): array {
        $stats = $this->voteRepo->getPageStats($pageId);
        $counts = $this->voteRepo->getVoteCountsByType($pageId);

        return [
            'total_votes' => $stats->total_votes ?? 0,
            'unique_voters' => $stats->unique_voters ?? 0,
            'positive_votes' => $counts['upvotes'],
            'negative_votes' => $counts['downvotes'],
            'positive_weight' => $counts['upvote_weight'],
            'negative_weight' => $counts['downvote_weight'],
            'last_vote_at' => $stats->last_vote_at
        ];
    }

    /**
     * Update voter's statistics
     */
    private function updateVoterStats(int $voterId): void {
        $voteCount = $this->voteRepo->countByVoter($voterId);
        update_user_meta($voterId, 'bcc_trust_votes_cast', $voteCount);
        update_user_meta($voterId, 'bcc_trust_last_active', time());
    }

    /**
     * Get downvote reason from request
     */
    private function getDownvoteReason(int $voteType): ?string {
        if ($voteType > 0) {
            return null;
        }
        return sanitize_text_field($_POST['reason'] ?? null);
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
     * Get client IP address
     */
    private function getClientIp(): string {
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

        return 'unknown';
    }

    /**
     * Alias methods for backward compatibility
     */
    public function vote(int $pageId, int $voteType): array {
        return $this->castPageVote($pageId, $voteType);
    }

    public function removeVote(int $pageId): array {
        return $this->removePageVote($pageId);
    }

    public function recalculateScore(int $pageId): array {
        $score = $this->scoreRepo->getByPageId($pageId);
        if (!$score) {
            $ownerId = $this->getPageOwnerId($pageId);
            $score = $this->scoreRepo->createDefault($pageId, $ownerId);
        }
        return $score->toApiResponse();
    }

    public function getUserVote(int $pageId, ?int $userId = null): ?object {
        return $this->getUserPageVote($pageId, $userId);
    }

    public function hasVoted(int $pageId, ?int $userId = null): bool {
        return $this->hasUserVotedPage($pageId, $userId);
    }
}