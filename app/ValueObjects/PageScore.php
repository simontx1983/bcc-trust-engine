<?php
/**
 * Page Score Value Object
 * 
 * Immutable representation of a page's trust score with validation and business logic
 * 
 * @package BCCTrust\ValueObjects
 * @version 2.0.0
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

    /**
     * Valid tier values
     */
    private const VALID_TIERS = ['elite', 'trusted', 'neutral', 'caution', 'risky'];

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
        ?DateTimeImmutable $lastCalculatedAt = null
    ) {
        // Validate all inputs
        $this->validatePageId($pageId);
        $this->validateOwnerId($pageOwnerId);
        $this->validateScores($totalScore, $positiveScore, $negativeScore);
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
    
    private function validateScores(float $total, float $positive, float $negative): void {
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
            throw new InvalidArgumentException(
                sprintf('Unique voters (%d) cannot exceed vote count (%d)', $uniqueVoters, $voteCount)
            );
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
        $newTotalScore = 50 + ($netScore * 2); // Each weighted point = 2 score points
        $newTotalScore = max(0, min(100, $newTotalScore));
        
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
            new DateTimeImmutable()  // last calculated at = now
        );
    }
    
    /**
     * Create new instance with endorsement added
     */
    public function withEndorsement(): self {
        // Endorsements add a small boost (capped at +10)
        $currentBonus = $this->totalScore - 50;
        if ($currentBonus < 10) {
            $newBonus = min(10, $currentBonus + 0.5);
            $newTotalScore = 50 + $newBonus;
        } else {
            $newTotalScore = $this->totalScore;
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
            new DateTimeImmutable()
        );
    }
    
    /**
     * Create new instance with endorsement removed
     */
    public function withoutEndorsement(): self {
        $currentBonus = $this->totalScore - 50;
        if ($currentBonus > 0) {
            $newBonus = max(0, $currentBonus - 0.5);
            $newTotalScore = 50 + $newBonus;
        } else {
            $newTotalScore = $this->totalScore;
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
            new DateTimeImmutable()
        );
    }
    
    /**
     * Recalculate confidence score
     */
    private function recalculateConfidence(int $voteCount, int $uniqueVoters): float {
        if ($voteCount === 0) {
            return 0;
        }
        
        $volumeConfidence = min(1, $voteCount / 50);
        $diversityConfidence = $uniqueVoters / $voteCount;
        
        return ($volumeConfidence * 0.6) + ($diversityConfidence * 0.4);
    }
    
    /**
     * Determine reputation tier based on score
     */
    private function determineTier(float $score): string {
        if ($score >= 80) return 'elite';
        if ($score >= 65) return 'trusted';
        if ($score >= 45) return 'neutral';
        if ($score >= 30) return 'caution';
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
            $row->last_calculated_at ? new DateTimeImmutable($row->last_calculated_at) : null
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
            new DateTimeImmutable()
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
            'last_calculated_at' => $this->lastCalculatedAt->format('Y-m-d H:i:s')
        ];
    }
    
    /**
     * Convert to API response array
     */
    public function toApiResponse(): array {
        return [
            'page_id' => $this->pageId,
            'total_score' => $this->totalScore,
            'reputation_tier' => $this->reputationTier,
            'confidence_score' => $this->confidenceScore,
            'vote_count' => $this->voteCount,
            'unique_voters' => $this->uniqueVoters,
            'endorsement_count' => $this->endorsementCount,
            'positive_score' => $this->positiveScore,
            'negative_score' => $this->negativeScore,
            'status' => $this->getScoreStatus(),
            'has_sufficient_data' => $this->hasSufficientData(),
            'voter_diversity' => $this->getVoterDiversity(),
            'net_score' => $this->getNetScore()
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
            'endorsement_count' => $this->endorsementCount
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