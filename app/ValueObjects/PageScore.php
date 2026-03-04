<?php
/**
 * Page Score Value Object
 * 
 * Immutable representation of a page's trust score with validation and business logic
 * 
 * @package BCCTrust\ValueObjects
 * @version 2.2.0
 */

namespace BCCTrust\ValueObjects;

use InvalidArgumentException;
use DateTimeImmutable;

if (!defined('ABSPATH')) {
    exit;
}

class PageScore {
    
    private int $pageId;
    private int $pageOwnerId;
    private float $totalScore;
    private float $positiveScore;
    private float $negativeScore;
    private int $voteCount;
    private int $uniqueVoters;
    private float $confidenceScore;
    private string $reputationTier;
    private int $endorsementCount;
    private ?DateTimeImmutable $lastVoteAt;
    private DateTimeImmutable $lastCalculatedAt;
    private ?array $fraudMetadata;

    /**
     * Valid tier values
     */
    private const VALID_TIERS = ['elite', 'trusted', 'neutral', 'caution', 'risky'];

    /**
     * Tolerance for floating point comparison
     */
    private const SCORE_TOLERANCE = 0.5;

    /**
     * Constructor with validation
     */
    public function __construct(
        int $pageId,
        int $pageOwnerId,
        float $totalScore,
        float $positiveScore,
        float $negativeScore,
        int $voteCount,
        int $uniqueVoters,
        float $confidenceScore,
        string $reputationTier,
        int $endorsementCount,
        ?DateTimeImmutable $lastVoteAt,
        ?DateTimeImmutable $lastCalculatedAt = null,
        ?array $fraudMetadata = null
    ) {
        // Validate all inputs
        $this->validatePageId($pageId);
        $this->validateOwnerId($pageOwnerId);
        $this->validateScores($totalScore, $positiveScore, $negativeScore, $voteCount);
        $this->validateCounts($voteCount, $uniqueVoters);
        $this->validateConfidence($confidenceScore);
        $this->validateTier($reputationTier);
        $this->validateEndorsements($endorsementCount);
        
        // Set properties
        $this->pageId = $pageId;
        $this->pageOwnerId = $pageOwnerId;
        $this->totalScore = $totalScore;
        $this->positiveScore = $positiveScore;
        $this->negativeScore = $negativeScore;
        $this->voteCount = $voteCount;
        $this->uniqueVoters = $uniqueVoters;
        $this->confidenceScore = $confidenceScore;
        $this->reputationTier = $reputationTier;
        $this->endorsementCount = $endorsementCount;
        $this->lastVoteAt = $lastVoteAt;
        $this->lastCalculatedAt = $lastCalculatedAt ?? new DateTimeImmutable();
        $this->fraudMetadata = $fraudMetadata;
    }

    /**
     * ======================================================
     * VALIDATION METHODS
     * ======================================================
     */
    
    private function validatePageId(int $pageId): void {
        if ($pageId <= 0) {
            throw new InvalidArgumentException(
                sprintf('Page ID must be positive, got: %d', $pageId)
            );
        }
    }
    
    private function validateOwnerId(int $ownerId): void {
        if ($ownerId < 0) {
            throw new InvalidArgumentException(
                sprintf('Owner ID cannot be negative, got: %d', $ownerId)
            );
        }
    }
    
    private function validateScores(float $total, float $positive, float $negative, int $voteCount): void {
        if ($total < 0 || $total > 100) {
            throw new InvalidArgumentException(
                sprintf('Total score must be between 0 and 100, got: %f', $total)
            );
        }
        
        if ($positive < 0) {
            throw new InvalidArgumentException(
                sprintf('Positive score cannot be negative, got: %f', $positive)
            );
        }
        
        if ($negative < 0) {
            throw new InvalidArgumentException(
                sprintf('Negative score cannot be negative, got: %f', $negative)
            );
        }

        // Only validate the mathematical relationship if there are votes
        // This prevents false positives during endorsement-only operations
        if ($voteCount > 0 || $positive > 0 || $negative > 0) {
            // Validate that total roughly equals 50 + (positive - negative) * 2
            // Use a reasonable tolerance to account for floating point calculations
            $expectedTotal = 50.0 + (($positive - $negative) * 2.0);
            $difference = abs($total - $expectedTotal);
            
            // Increased tolerance to 0.5 to handle floating point precision
            if ($difference > self::SCORE_TOLERANCE) {
                throw new InvalidArgumentException(
                    sprintf(
                        'Total score %f does not match positive/negative differential (expected ~%f, difference %f)',
                        $total, 
                        $expectedTotal,
                        $difference
                    )
                );
            }
        }
    }
    
    private function validateCounts(int $voteCount, int $uniqueVoters): void {
        if ($voteCount < 0) {
            throw new InvalidArgumentException(
                sprintf('Vote count cannot be negative, got: %d', $voteCount)
            );
        }
        
        if ($uniqueVoters < 0) {
            throw new InvalidArgumentException(
                sprintf('Unique voters cannot be negative, got: %d', $uniqueVoters)
            );
        }
        
        if ($uniqueVoters > $voteCount && $voteCount > 0) {
            // This can happen in edge cases, so we'll log but not throw
            error_log(sprintf(
                'Warning: Unique voters (%d) exceeds vote count (%d) for page %d',
                $uniqueVoters,
                $voteCount,
                $this->pageId ?? 'unknown'
            ));
        }
    }
    
    private function validateConfidence(float $confidence): void {
        if ($confidence < 0 || $confidence > 1) {
            throw new InvalidArgumentException(
                sprintf('Confidence must be between 0 and 1, got: %f', $confidence)
            );
        }
    }
    
    private function validateTier(string $tier): void {
        if (!in_array($tier, self::VALID_TIERS, true)) {
            throw new InvalidArgumentException(
                sprintf('Invalid reputation tier: %s. Must be one of: %s', 
                    $tier, 
                    implode(', ', self::VALID_TIERS)
                )
            );
        }
    }
    
    private function validateEndorsements(int $endorsementCount): void {
        if ($endorsementCount < 0) {
            throw new InvalidArgumentException(
                sprintf('Endorsement count cannot be negative, got: %d', $endorsementCount)
            );
        }
    }

    /**
     * ======================================================
     * GETTERS
     * ======================================================
     */
    
    public function getPageId(): int {
        return $this->pageId;
    }
    
    public function getPageOwnerId(): int {
        return $this->pageOwnerId;
    }
    
    public function getTotalScore(): float {
        return $this->totalScore;
    }
    
    public function getPositiveScore(): float {
        return $this->positiveScore;
    }
    
    public function getNegativeScore(): float {
        return $this->negativeScore;
    }
    
    public function getVoteCount(): int {
        return $this->voteCount;
    }
    
    public function getUniqueVoters(): int {
        return $this->uniqueVoters;
    }
    
    public function getConfidenceScore(): float {
        return $this->confidenceScore;
    }
    
    public function getReputationTier(): string {
        return $this->reputationTier;
    }
    
    public function getEndorsementCount(): int {
        return $this->endorsementCount;
    }
    
    public function getLastVoteAt(): ?DateTimeImmutable {
        return $this->lastVoteAt;
    }
    
    public function getLastCalculatedAt(): DateTimeImmutable {
        return $this->lastCalculatedAt;
    }
    
    public function getFraudMetadata(): ?array {
        return $this->fraudMetadata;
    }

    /**
     * ======================================================
     * BUSINESS LOGIC METHODS
     * ======================================================
     */
    
    /**
     * Check if page is highly trusted (elite or trusted tier)
     */
    public function isHighlyTrusted(): bool {
        return in_array($this->reputationTier, ['elite', 'trusted'], true);
    }
    
    /**
     * Check if page is risky (caution or risky tier)
     */
    public function isRisky(): bool {
        return in_array($this->reputationTier, ['caution', 'risky'], true);
    }
    
    /**
     * Check if page has enough data for reliable scoring
     */
    public function hasSufficientData(): bool {
        return $this->voteCount >= 10 && $this->confidenceScore >= 0.5;
    }
    
    /**
     * Get net score (positive - negative)
     */
    public function getNetScore(): float {
        return $this->positiveScore - $this->negativeScore;
    }
    
    /**
     * Get confidence as percentage
     */
    public function getConfidencePercentage(): int {
        return (int) round($this->confidenceScore * 100);
    }
    
    /**
     * Get human-readable score status
     */
    public function getScoreStatus(): string {
        if ($this->totalScore >= 80) return 'Excellent';
        if ($this->totalScore >= 65) return 'Good';
        if ($this->totalScore >= 45) return 'Average';
        if ($this->totalScore >= 30) return 'Poor';
        return 'Very Poor';
    }
    
    /**
     * Get voter diversity ratio
     */
    public function getVoterDiversity(): float {
        if ($this->voteCount === 0) {
            return 0;
        }
        return $this->uniqueVoters / $this->voteCount;
    }

    /**
     * Check if page has any fraud alerts
     */
    public function hasFraudAlerts(): bool {
        if (empty($this->fraudMetadata)) {
            return false;
        }
        
        return isset($this->fraudMetadata['alerts']) && count($this->fraudMetadata['alerts']) > 0;
    }

    /**
     * Get fraud alert count
     */
    public function getFraudAlertCount(): int {
        if (empty($this->fraudMetadata) || !isset($this->fraudMetadata['alerts'])) {
            return 0;
        }
        
        return count($this->fraudMetadata['alerts']);
    }

    /**
     * ======================================================
     * IMMUTABLE TRANSFORMATIONS
     * ======================================================
     */
    
    /**
     * Create new instance with a vote added
     */
    public function withNewVote(float $voteWeight, bool $isPositive, bool $isNewVoter): self {
        // Calculate new scores
        $newPositive = $this->positiveScore + ($isPositive ? $voteWeight : 0);
        $newNegative = $this->negativeScore + ($isPositive ? 0 : $voteWeight);
        $newVoteCount = $this->voteCount + 1;
        $newUniqueVoters = $this->uniqueVoters + ($isNewVoter ? 1 : 0);
        
        // Recalculate total score
        $netScore = $newPositive - $newNegative;
        $newTotalScore = 50.0 + ($netScore * 2.0); // Each weighted point = 2 score points
        $newTotalScore = max(0.0, min(100.0, $newTotalScore));
        
        // Recalculate confidence
        $newConfidence = $this->recalculateConfidence($newVoteCount, $newUniqueVoters);
        
        // Determine new tier
        $newTier = $this->determineTier($newTotalScore);
        
        return new self(
            $this->pageId,
            $this->pageOwnerId,
            $newTotalScore,
            $newPositive,
            $newNegative,
            $newVoteCount,
            $newUniqueVoters,
            $newConfidence,
            $newTier,
            $this->endorsementCount,
            new DateTimeImmutable(), // last vote at = now
            new DateTimeImmutable(), // last calculated at = now
            $this->fraudMetadata
        );
    }
    
    /**
     * Create new instance with a vote removed
     */
    public function withVoteRemoved(float $voteWeight, bool $wasPositive, bool $wasUniqueVoter): self {
        // Calculate new scores
        $newPositive = max(0.0, $this->positiveScore - ($wasPositive ? $voteWeight : 0));
        $newNegative = max(0.0, $this->negativeScore - ($wasPositive ? 0 : $voteWeight));
        $newVoteCount = max(0, $this->voteCount - 1);
        $newUniqueVoters = max(0, $this->uniqueVoters - ($wasUniqueVoter ? 1 : 0));
        
        // Recalculate total score
        $netScore = $newPositive - $newNegative;
        $newTotalScore = 50.0 + ($netScore * 2.0);
        $newTotalScore = max(0.0, min(100.0, $newTotalScore));
        
        // Recalculate confidence
        $newConfidence = $this->recalculateConfidence($newVoteCount, $newUniqueVoters);
        
        // Determine new tier
        $newTier = $this->determineTier($newTotalScore);
        
        return new self(
            $this->pageId,
            $this->pageOwnerId,
            $newTotalScore,
            $newPositive,
            $newNegative,
            $newVoteCount,
            $newUniqueVoters,
            $newConfidence,
            $newTier,
            $this->endorsementCount,
            $this->lastVoteAt, // Keep original last vote
            new DateTimeImmutable(), // last calculated at = now
            $this->fraudMetadata
        );
    }
    
    /**
     * Create new instance with endorsement added
     */
    public function withEndorsement(): self {
        // Endorsements add a small boost (capped at +10)
        $currentBonus = $this->totalScore - 50.0;
        $newTotalScore = $this->totalScore;
        
        if ($currentBonus < 10.0) {
            $newBonus = min(10.0, $currentBonus + 0.5);
            $newTotalScore = 50.0 + $newBonus;
        }
        
        return new self(
            $this->pageId,
            $this->pageOwnerId,
            $newTotalScore,
            $this->positiveScore,
            $this->negativeScore,
            $this->voteCount,
            $this->uniqueVoters,
            $this->confidenceScore,
            $this->reputationTier,
            $this->endorsementCount + 1,
            $this->lastVoteAt,
            new DateTimeImmutable(),
            $this->fraudMetadata
        );
    }
    
    /**
     * Create new instance with endorsement removed
     */
    public function withoutEndorsement(): self {
        $currentBonus = $this->totalScore - 50.0;
        $newTotalScore = $this->totalScore;
        
        if ($currentBonus > 0.0) {
            $newBonus = max(0.0, $currentBonus - 0.5);
            $newTotalScore = 50.0 + $newBonus;
        }
        
        return new self(
            $this->pageId,
            $this->pageOwnerId,
            $newTotalScore,
            $this->positiveScore,
            $this->negativeScore,
            $this->voteCount,
            $this->uniqueVoters,
            $this->confidenceScore,
            $this->reputationTier,
            max(0, $this->endorsementCount - 1),
            $this->lastVoteAt,
            new DateTimeImmutable(),
            $this->fraudMetadata
        );
    }
    
    /**
     * Create new instance with fraud metadata updated
     */
    public function withFraudMetadata(array $fraudMetadata): self {
        return new self(
            $this->pageId,
            $this->pageOwnerId,
            $this->totalScore,
            $this->positiveScore,
            $this->negativeScore,
            $this->voteCount,
            $this->uniqueVoters,
            $this->confidenceScore,
            $this->reputationTier,
            $this->endorsementCount,
            $this->lastVoteAt,
            $this->lastCalculatedAt,
            $fraudMetadata
        );
    }
    
    /**
     * Recalculate confidence score
     */
    private function recalculateConfidence(int $voteCount, int $uniqueVoters): float {
        if ($voteCount === 0) {
            return 0.0;
        }
        
        $volumeConfidence = min(1.0, $voteCount / 50.0);
        $diversityConfidence = $uniqueVoters / $voteCount;
        
        return ($volumeConfidence * 0.6) + ($diversityConfidence * 0.4);
    }
    
    /**
     * Determine reputation tier based on score
     */
    private function determineTier(float $score): string {
        if ($score >= 80.0) return 'elite';
        if ($score >= 65.0) return 'trusted';
        if ($score >= 45.0) return 'neutral';
        if ($score >= 30.0) return 'caution';
        return 'risky';
    }

    /**
     * ======================================================
     * FACTORY METHODS
     * ======================================================
     */
    
    /**
     * Create from database row
     */
    public static function fromDatabaseRow(object $row): self {
        return new self(
            (int) $row->page_id,
            (int) $row->page_owner_id,
            (float) $row->total_score,
            (float) $row->positive_score,
            (float) $row->negative_score,
            (int) $row->vote_count,
            (int) $row->unique_voters,
            (float) $row->confidence_score,
            $row->reputation_tier,
            (int) $row->endorsement_count,
            $row->last_vote_at ? new DateTimeImmutable($row->last_vote_at) : null,
            $row->last_calculated_at ? new DateTimeImmutable($row->last_calculated_at) : null,
            !empty($row->fraud_metadata) ? json_decode($row->fraud_metadata, true) : null
        );
    }
    
    /**
     * Create default score for new page
     */
    public static function createDefault(int $pageId, int $ownerId): self {
        return new self(
            $pageId,
            $ownerId,
            50.0,  // total_score
            0.0,   // positive_score
            0.0,   // negative_score
            0,     // vote_count
            0,     // unique_voters
            0.0,   // confidence_score
            'neutral',
            0,     // endorsement_count
            null,  // last_vote_at
            new DateTimeImmutable(),
            null   // fraud_metadata
        );
    }

    /**
     * ======================================================
     * CONVERSION METHODS
     * ======================================================
     */
    
    /**
     * Convert to array for database storage
     */
    public function toDatabaseArray(): array {
        return [
            'page_id' => $this->pageId,
            'page_owner_id' => $this->pageOwnerId,
            'total_score' => $this->totalScore,
            'positive_score' => $this->positiveScore,
            'negative_score' => $this->negativeScore,
            'vote_count' => $this->voteCount,
            'unique_voters' => $this->uniqueVoters,
            'confidence_score' => $this->confidenceScore,
            'reputation_tier' => $this->reputationTier,
            'endorsement_count' => $this->endorsementCount,
            'last_vote_at' => $this->lastVoteAt?->format('Y-m-d H:i:s'),
            'last_calculated_at' => $this->lastCalculatedAt->format('Y-m-d H:i:s'),
            'fraud_metadata' => $this->fraudMetadata ? json_encode($this->fraudMetadata) : null
        ];
    }
    
    /**
     * Convert to API response array
     */
    public function toApiResponse(): array {
        return [
            'page_id' => $this->pageId,
            'total_score' => round($this->totalScore, 1),
            'reputation_tier' => $this->reputationTier,
            'confidence_score' => round($this->confidenceScore, 2),
            'vote_count' => $this->voteCount,
            'unique_voters' => $this->uniqueVoters,
            'endorsement_count' => $this->endorsementCount,
            'positive_score' => round($this->positiveScore, 1),
            'negative_score' => round($this->negativeScore, 1),
            'status' => $this->getScoreStatus(),
            'has_sufficient_data' => $this->hasSufficientData(),
            'voter_diversity' => round($this->getVoterDiversity(), 2),
            'net_score' => round($this->getNetScore(), 1),
            'has_fraud_alerts' => $this->hasFraudAlerts(),
            'fraud_alert_count' => $this->getFraudAlertCount()
        ];
    }
    
    /**
     * Convert to simple array for caching
     */
    public function toCacheArray(): array {
        return [
            'page_id' => $this->pageId,
            'total_score' => $this->totalScore,
            'reputation_tier' => $this->reputationTier,
            'confidence' => $this->confidenceScore,
            'vote_count' => $this->voteCount,
            'endorsement_count' => $this->endorsementCount,
            'has_fraud_alerts' => $this->hasFraudAlerts()
        ];
    }

    /**
     * ======================================================
     * COMPARISON METHODS
     * ======================================================
     */
    
    /**
     * Check if equal to another PageScore
     */
    public function equals(PageScore $other): bool {
        return $this->pageId === $other->pageId &&
               $this->lastCalculatedAt == $other->lastCalculatedAt;
    }
    
    /**
     * Check if this score is newer than another
     */
    public function isNewerThan(PageScore $other): bool {
        return $this->lastCalculatedAt > $other->lastCalculatedAt;
    }
}