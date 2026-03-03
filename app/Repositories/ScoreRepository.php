<?php
/**
 * Score Repository
 * 
 * Handles database operations for page trust scores using PageScore value objects
 * 
 * @package BCCTrust\Repositories
 * @version 2.1.0
 */

namespace BCCTrust\Repositories;

use BCCTrust\ValueObjects\PageScore;
use DateTimeImmutable;
use Exception;
use stdClass;

if (!defined('ABSPATH')) {
    exit;
}

class ScoreRepository {

    private string $table;

    public function __construct() {
        $this->table = bcc_trust_scores_table();
    }

    /**
     * Get score for page as PageScore value object
     */
    public function getByPageId(int $pageId): ?PageScore {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table} WHERE page_id = %d",
                $pageId
            )
        );

        if (!$row) {
            return null;
        }

        return PageScore::fromDatabaseRow($row);
    }

    /**
     * Alias for backward compatibility
     */
    public function get(int $pageId): ?PageScore {
        return $this->getByPageId($pageId);
    }

    /**
     * Get score with page data
     */
    public function getWithPageData(int $pageId): ?object {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT s.*, p.post_title, p.post_author, p.post_status
                 FROM {$this->table} s
                 LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                 WHERE s.page_id = %d",
                $pageId
            )
        );

        if (!$row) {
            return null;
        }

        // Create a stdClass object with all the data
        $result = new stdClass();
        $result->page_id = (int) $row->page_id;
        $result->page_owner_id = (int) $row->page_owner_id;
        $result->total_score = (float) $row->total_score;
        $result->positive_score = (float) $row->positive_score;
        $result->negative_score = (float) $row->negative_score;
        $result->vote_count = (int) $row->vote_count;
        $result->unique_voters = (int) $row->unique_voters;
        $result->confidence_score = (float) $row->confidence_score;
        $result->reputation_tier = $row->reputation_tier;
        $result->endorsement_count = (int) $row->endorsement_count;
        $result->last_vote_at = $row->last_vote_at;
        $result->last_calculated_at = $row->last_calculated_at;
        $result->fraud_metadata = $row->fraud_metadata;
        $result->post_title = $row->post_title;
        $result->post_author = (int) $row->post_author;
        $result->post_status = $row->post_status;

        return $result;
    }

    /**
     * Save PageScore to database
     */
    public function save(PageScore $score): void {
        global $wpdb;

        $data = $score->toDatabaseArray();
        
        $result = $wpdb->replace(
            $this->table,
            $data,
            $this->getFormatSpecifiers($data)
        );

        if ($result === false) {
            throw new Exception('Failed to save page score to database');
        }
    }

    /**
     * Get format specifiers for database operations
     */
    private function getFormatSpecifiers(array $data): array {
        $formats = [];
        
        foreach (array_keys($data) as $field) {
            switch ($field) {
                case 'page_id':
                case 'page_owner_id':
                case 'vote_count':
                case 'unique_voters':
                case 'endorsement_count':
                    $formats[] = '%d';
                    break;
                case 'total_score':
                case 'positive_score':
                case 'negative_score':
                case 'confidence_score':
                    $formats[] = '%f';
                    break;
                case 'reputation_tier':
                case 'last_vote_at':
                case 'last_calculated_at':
                case 'fraud_metadata':
                    $formats[] = '%s';
                    break;
                default:
                    $formats[] = '%s';
            }
        }
        
        return $formats;
    }

    /**
     * Create default score for a new page
     */
    public function createDefault(int $pageId, int $ownerId): PageScore {
        $score = PageScore::createDefault($pageId, $ownerId);
        $this->save($score);
        return $score;
    }

    /**
     * Create if not exists
     */
    public function createIfNotExists(int $pageId, ?int $ownerId = null): PageScore {
        $existing = $this->getByPageId($pageId);
        
        if ($existing) {
            return $existing;
        }

        // Get page owner if not provided
        if (!$ownerId) {
            if (function_exists('bcc_trust_get_page_owner')) {
                $ownerId = bcc_trust_get_page_owner($pageId);
            }
            
            if (!$ownerId) {
                $post = get_post($pageId);
                $ownerId = $post ? (int) $post->post_author : 0;
            }
        }

        if (!$ownerId) {
            throw new Exception('Cannot create score: No owner ID found for page ' . $pageId);
        }

        return $this->createDefault($pageId, $ownerId);
    }

    /**
     * Get scores for multiple pages
     */
    public function getBulk(array $pageIds): array {
        global $wpdb;

        if (empty($pageIds)) {
            return [];
        }

        $placeholders = implode(',', array_fill(0, count($pageIds), '%d'));
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->table} 
                 WHERE page_id IN ({$placeholders})",
                $pageIds
            )
        );

        // Convert to PageScore objects indexed by page_id
        $indexed = [];
        foreach ($results as $row) {
            $indexed[$row->page_id] = PageScore::fromDatabaseRow($row);
        }

        return $indexed;
    }

    /**
     * Get top scored pages
     */
    public function getTopScored(int $limit = 10, string $orderBy = 'total_score'): array {
        global $wpdb;

        $allowedOrders = ['total_score', 'confidence_score', 'vote_count', 'positive_score'];
        if (!in_array($orderBy, $allowedOrders)) {
            $orderBy = 'total_score';
        }

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT s.*, p.post_title, u.display_name as owner_name
                 FROM {$this->table} s
                 LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                 LEFT JOIN {$wpdb->users} u ON s.page_owner_id = u.ID
                 WHERE (p.post_status = 'publish' OR p.post_status IS NULL)
                 ORDER BY s.{$orderBy} DESC
                 LIMIT %d",
                $limit
            )
        );

        $scores = [];
        foreach ($results as $row) {
            $score = PageScore::fromDatabaseRow($row);
            
            // Create a result object with the score and extra data
            $result = new stdClass();
            $result->score = $score;
            $result->post_title = $row->post_title;
            $result->owner_name = $row->owner_name;
            $result->page_id = $score->getPageId();
            $result->total_score = $score->getTotalScore();
            $result->reputation_tier = $score->getReputationTier();
            $result->vote_count = $score->getVoteCount();
            $result->endorsement_count = $score->getEndorsementCount();
            $result->confidence_score = $score->getConfidenceScore();
            $result->has_fraud_alerts = $score->hasFraudAlerts();
            
            $scores[] = $result;
        }

        return $scores;
    }

    /**
     * Get pages by tier
     */
    public function getByTier(string $tier, int $limit = 10, int $offset = 0): array {
        global $wpdb;
        
        $validTiers = ['elite', 'trusted', 'neutral', 'caution', 'risky'];
        if (!in_array($tier, $validTiers)) {
            return [];
        }

        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT s.*, p.post_title, u.display_name as owner_name
             FROM {$this->table} s
             LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
             LEFT JOIN {$wpdb->users} u ON s.page_owner_id = u.ID
             WHERE s.reputation_tier = %s
             AND (p.post_status = 'publish' OR p.post_status IS NULL)
             ORDER BY s.total_score DESC
             LIMIT %d OFFSET %d",
            $tier,
            $limit,
            $offset
        ));

        $scores = [];
        foreach ($results as $row) {
            $score = PageScore::fromDatabaseRow($row);
            
            // Create a result object with the score and extra data
            $result = new stdClass();
            $result->score = $score;
            $result->post_title = $row->post_title;
            $result->owner_name = $row->owner_name;
            $result->page_id = $score->getPageId();
            $result->total_score = $score->getTotalScore();
            $result->reputation_tier = $score->getReputationTier();
            $result->vote_count = $score->getVoteCount();
            $result->endorsement_count = $score->getEndorsementCount();
            $result->confidence_score = $score->getConfidenceScore();
            $result->has_fraud_alerts = $score->hasFraudAlerts();
            
            $scores[] = $result;
        }

        return $scores;
    }

    /**
     * Count pages by tier
     */
    public function countByTier(string $tier): int {
        global $wpdb;
        
        $validTiers = ['elite', 'trusted', 'neutral', 'caution', 'risky'];
        if (!in_array($tier, $validTiers)) {
            return 0;
        }
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE reputation_tier = %s",
            $tier
        ));
    }

    /**
     * Get pages by owner
     */
    public function getByOwnerId(int $ownerId): array {
        global $wpdb;

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT s.*, p.post_title
                 FROM {$this->table} s
                 LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                 WHERE s.page_owner_id = %d
                 ORDER BY s.total_score DESC",
                $ownerId
            )
        );

        $scores = [];
        foreach ($results as $row) {
            $score = PageScore::fromDatabaseRow($row);
            
            // Create a result object with the score and extra data
            $result = new stdClass();
            $result->score = $score;
            $result->post_title = $row->post_title;
            $result->page_id = $score->getPageId();
            $result->total_score = $score->getTotalScore();
            $result->reputation_tier = $score->getReputationTier();
            $result->vote_count = $score->getVoteCount();
            $result->endorsement_count = $score->getEndorsementCount();
            $result->confidence_score = $score->getConfidenceScore();
            $result->has_fraud_alerts = $score->hasFraudAlerts();
            
            $scores[] = $result;
        }

        return $scores;
    }

    /**
     * Get pages with fraud alerts
     */
    public function getPagesWithFraudAlerts(int $limit = 50): array {
        global $wpdb;

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT s.*, p.post_title
                 FROM {$this->table} s
                 LEFT JOIN {$wpdb->posts} p ON s.page_id = p.ID
                 WHERE s.fraud_metadata IS NOT NULL 
                 AND s.fraud_metadata != ''
                 AND s.fraud_metadata LIKE '%\"alerts\":[%'
                 ORDER BY s.last_calculated_at DESC
                 LIMIT %d",
                $limit
            )
        );

        $scores = [];
        foreach ($results as $row) {
            $score = PageScore::fromDatabaseRow($row);
            
            $result = new stdClass();
            $result->score = $score;
            $result->post_title = $row->post_title;
            $result->page_id = $score->getPageId();
            $result->total_score = $score->getTotalScore();
            $result->reputation_tier = $score->getReputationTier();
            $result->fraud_alert_count = $score->getFraudAlertCount();
            
            $scores[] = $result;
        }

        return $scores;
    }

    /**
     * Get statistics
     */
    public function getStats(): object {
        global $wpdb;

        return $wpdb->get_row(
            "SELECT 
                COUNT(*) as total_pages,
                AVG(total_score) as avg_score,
                MIN(total_score) as min_score,
                MAX(total_score) as max_score,
                SUM(vote_count) as total_votes,
                SUM(endorsement_count) as total_endorsements,
                COUNT(CASE WHEN reputation_tier = 'elite' THEN 1 END) as elite_count,
                COUNT(CASE WHEN reputation_tier = 'trusted' THEN 1 END) as trusted_count,
                COUNT(CASE WHEN reputation_tier = 'neutral' THEN 1 END) as neutral_count,
                COUNT(CASE WHEN reputation_tier = 'caution' THEN 1 END) as caution_count,
                COUNT(CASE WHEN reputation_tier = 'risky' THEN 1 END) as risky_count,
                COUNT(CASE WHEN fraud_metadata IS NOT NULL AND fraud_metadata != '' THEN 1 END) as pages_with_fraud_alerts
             FROM {$this->table}"
        );
    }

    /**
     * Increment endorsement count (legacy support)
     */
    public function incrementEndorsementCount(int $pageId): void {
        $score = $this->getByPageId($pageId);
        if ($score) {
            $newScore = $score->withEndorsement();
            $this->save($newScore);
        }
    }

    /**
     * Decrement endorsement count (legacy support)
     */
    public function decrementEndorsementCount(int $pageId): void {
        $score = $this->getByPageId($pageId);
        if ($score) {
            $newScore = $score->withoutEndorsement();
            $this->save($newScore);
        }
    }

    /**
     * Update fraud metadata
     */
    public function updateFraudMetadata(int $pageId, array $fraudMetadata): bool {
        global $wpdb;
        
        $result = $wpdb->update(
            $this->table,
            [
                'fraud_metadata' => json_encode($fraudMetadata),
                'last_calculated_at' => current_time('mysql')
            ],
            ['page_id' => $pageId],
            ['%s', '%s'],
            ['%d']
        );
        
        return $result !== false;
    }

    /**
     * Delete score (for page deletion)
     */
    public function delete(int $pageId): bool {
        global $wpdb;
        
        $result = $wpdb->delete(
            $this->table,
            ['page_id' => $pageId],
            ['%d']
        );
        
        return $result !== false;
    }

    /**
     * Bulk update scores
     */
    public function bulkUpdate(array $scores): int {
        $updated = 0;
        
        foreach ($scores as $score) {
            if ($score instanceof PageScore) {
                try {
                    $this->save($score);
                    $updated++;
                } catch (Exception $e) {
                    // Log error but continue
                    error_log('Failed to update score for page ' . $score->getPageId() . ': ' . $e->getMessage());
                }
            }
        }
        
        return $updated;
    }
}