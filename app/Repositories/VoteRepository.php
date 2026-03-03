<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

use Exception;

class VoteRepository {

    private string $table;
    private $userInfoRepo;

    public function __construct() {
        $this->table = bcc_trust_votes_table();
        $this->userInfoRepo = new UserInfoRepository();
    }

    /**
     * Get vote by voter and page
     */
    public function get(int $voterId, int $pageId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE voter_user_id = %d
                 AND page_id = %d
                 AND status = 1",
                $voterId,
                $pageId
            )
        );
    }

    /**
     * Get any vote (including inactive)
     */
    public function getAny(int $voterId, int $pageId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE voter_user_id = %d
                 AND page_id = %d",
                $voterId,
                $pageId
            )
        );
    }

    /**
     * Get vote by ID
     */
    public function getById(int $voteId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table} WHERE id = %d",
                $voteId
            )
        );
    }

    /**
     * Insert or update vote
     */
    public function upsert(array $data): int {
        global $wpdb;

        // Validate required fields
        if (empty($data['voter_user_id']) || empty($data['page_id']) || !isset($data['vote_type'])) {
            throw new Exception('Missing required vote data');
        }

        $existing = $this->getAny(
            $data['voter_user_id'],
            $data['page_id']
        );

        $now = current_time('mysql');
        
        // Prepare vote data with proper validation
        $voteData = [
            'voter_user_id' => (int) $data['voter_user_id'],
            'page_id'       => (int) $data['page_id'],
            'vote_type'     => (int) $data['vote_type'],
            'weight'        => isset($data['weight']) ? (float) $data['weight'] : 1.0,
            'reason'        => isset($data['reason']) ? sanitize_text_field($data['reason']) : null,
            'explanation'   => isset($data['explanation']) ? sanitize_textarea_field($data['explanation']) : null,
            'ip_address'    => isset($data['ip_address']) ? inet_pton($data['ip_address']) : null,
            'status'        => 1,
            'updated_at'    => $now
        ];

        // Validate vote type
        if (!in_array($voteData['vote_type'], [1, -1])) {
            throw new Exception('Invalid vote type. Must be 1 or -1');
        }

        // Validate weight range
        $voteData['weight'] = max(0.1, min(3.0, $voteData['weight']));

        if ($existing) {
            $wpdb->update(
                $this->table,
                $voteData,
                ['id' => $existing->id],
                $this->getFormatSpecifiers($voteData),
                ['%d']
            );
            
            // Update voter stats if vote type changed
            if ($existing->vote_type != $voteData['vote_type']) {
                $this->updateVoterStats($voteData['voter_user_id']);
            }
            
            return $existing->id;
        } else {
            $voteData['created_at'] = $now;
            
            $wpdb->insert(
                $this->table,
                $voteData,
                $this->getFormatSpecifiers($voteData)
            );
            
            $insertId = $wpdb->insert_id;
            
            // Update voter stats
            $this->updateVoterStats($voteData['voter_user_id']);
            
            return $insertId;
        }
    }

    /**
     * Get format specifiers for database operations
     */
    private function getFormatSpecifiers(array $data): array {
        $formats = [];
        
        foreach (array_keys($data) as $field) {
            switch ($field) {
                case 'voter_user_id':
                case 'page_id':
                case 'vote_type':
                case 'status':
                    $formats[] = '%d';
                    break;
                case 'weight':
                    $formats[] = '%f';
                    break;
                case 'reason':
                case 'explanation':
                case 'created_at':
                case 'updated_at':
                    $formats[] = '%s';
                    break;
                case 'ip_address':
                    $formats[] = '%s'; // VARBINARY is treated as string in wpdb
                    break;
                default:
                    $formats[] = '%s';
            }
        }
        
        return $formats;
    }

    /**
     * Update voter statistics in user_info table
     */
    private function updateVoterStats(int $voterId): void {
        $voteCount = $this->countByVoter($voterId);
        $this->userInfoRepo->updateVotesCast($voterId, $voteCount);
    }

    /**
     * Soft delete vote
     */
    public function delete(int $voterId, int $pageId): bool {
        global $wpdb;

        $result = $wpdb->update(
            $this->table,
            [
                'status'     => 0,
                'updated_at' => current_time('mysql')
            ],
            [
                'voter_user_id' => $voterId,
                'page_id'       => $pageId
            ],
            ['%d', '%s'],
            ['%d', '%d']
        );
        
        if ($result !== false) {
            $this->updateVoterStats($voterId);
        }
        
        return $result !== false;
    }

    /**
     * Hard delete vote (admin only)
     */
    public function hardDelete(int $voteId): bool {
        global $wpdb;
        
        $vote = $this->getById($voteId);
        if (!$vote) {
            return false;
        }
        
        $result = $wpdb->delete(
            $this->table,
            ['id' => $voteId],
            ['%d']
        );
        
        if ($result !== false) {
            $this->updateVoterStats($vote->voter_user_id);
        }
        
        return $result !== false;
    }

    /**
     * Get all active votes for a page
     */
    public function getAllForPage(int $pageId): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT v.*, u.display_name as voter_name,
                        ui.fraud_score, ui.risk_level
                 FROM {$this->table} v
                 LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
                 LEFT JOIN " . bcc_trust_user_info_table() . " ui ON v.voter_user_id = ui.user_id
                 WHERE v.page_id = %d
                 AND v.status = 1
                 ORDER BY v.created_at DESC",
                $pageId
            )
        );
    }

    /**
     * Get votes by voter
     */
    public function getByVoter(int $voterId, int $limit = 20): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT v.*, p.post_title as page_title,
                        s.total_score as page_score
                 FROM {$this->table} v
                 LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
                 LEFT JOIN " . bcc_trust_scores_table() . " s ON v.page_id = s.page_id
                 WHERE v.voter_user_id = %d
                 AND v.status = 1
                 ORDER BY v.created_at DESC
                 LIMIT %d",
                $voterId,
                $limit
            )
        );
    }

    /**
     * Count votes in time window (for rate limiting)
     */
    public function countRecentByVoter(int $voterId, int $minutes = 60): int {
        global $wpdb;

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table}
             WHERE voter_user_id = %d
             AND status = 1
             AND created_at > (UTC_TIMESTAMP() - INTERVAL %d MINUTE)",
            $voterId,
            $minutes
        ));
    }

    /**
     * Count total active votes by voter
     */
    public function countByVoter(int $voterId): int {
        global $wpdb;
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table}
             WHERE voter_user_id = %d
             AND status = 1",
            $voterId
        ));
    }

    /**
     * Get vote statistics for a page
     */
    public function getPageStats(int $pageId): object {
        global $wpdb;

        $stats = $wpdb->get_row($wpdb->prepare(
            "SELECT 
                COUNT(*) as total_votes,
                SUM(CASE WHEN vote_type > 0 THEN weight ELSE 0 END) as total_positive_weight,
                SUM(CASE WHEN vote_type < 0 THEN weight ELSE 0 END) as total_negative_weight,
                COUNT(DISTINCT voter_user_id) as unique_voters,
                MAX(created_at) as last_vote_at,
                AVG(CASE WHEN vote_type > 0 THEN weight ELSE NULL END) as avg_upvote_weight,
                AVG(CASE WHEN vote_type < 0 THEN weight ELSE NULL END) as avg_downvote_weight
             FROM {$this->table}
             WHERE page_id = %d
             AND status = 1",
            $pageId
        ));

        if (!$stats) {
            $stats = (object) [
                'total_votes' => 0,
                'total_positive_weight' => 0,
                'total_negative_weight' => 0,
                'unique_voters' => 0,
                'last_vote_at' => null,
                'avg_upvote_weight' => 0,
                'avg_downvote_weight' => 0
            ];
        }

        return $stats;
    }

    /**
     * Get user's vote on a page
     */
    public function getUserVote(int $pageId, int $userId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT v.*, ui.fraud_score, ui.risk_level
                 FROM {$this->table} v
                 LEFT JOIN " . bcc_trust_user_info_table() . " ui ON v.voter_user_id = ui.user_id
                 WHERE v.page_id = %d
                 AND v.voter_user_id = %d
                 AND v.status = 1
                 LIMIT 1",
                $pageId,
                $userId
            )
        );
    }

    /**
     * Get vote counts by type for a page
     */
    public function getVoteCountsByType(int $pageId): array {
        global $wpdb;

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT vote_type, COUNT(*) as count, SUM(weight) as total_weight
                 FROM {$this->table}
                 WHERE page_id = %d
                 AND status = 1
                 GROUP BY vote_type",
                $pageId
            )
        );

        $counts = [
            'upvotes' => 0,
            'downvotes' => 0,
            'upvote_weight' => 0,
            'downvote_weight' => 0,
            'upvote_avg_weight' => 0,
            'downvote_avg_weight' => 0
        ];

        foreach ($results as $row) {
            if ($row->vote_type > 0) {
                $counts['upvotes'] = (int) $row->count;
                $counts['upvote_weight'] = (float) $row->total_weight;
                $counts['upvote_avg_weight'] = $row->count > 0 ? $row->total_weight / $row->count : 0;
            } else {
                $counts['downvotes'] = (int) $row->count;
                $counts['downvote_weight'] = (float) $row->total_weight;
                $counts['downvote_avg_weight'] = $row->count > 0 ? $row->total_weight / $row->count : 0;
            }
        }

        return $counts;
    }

    /**
     * Get voter reputation weights for a page
     */
    public function getVoterWeights(int $pageId): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT v.voter_user_id, v.weight, ui.fraud_score, ui.reputation_tier
                 FROM {$this->table} v
                 LEFT JOIN " . bcc_trust_user_info_table() . " ui ON v.voter_user_id = ui.user_id
                 WHERE v.page_id = %d
                 AND v.status = 1",
                $pageId
            ),
            OBJECT_K
        );
    }

    /**
     * Get votes with fraud indicators
     */
    public function getVotesWithFraud(int $pageId, float $minFraudScore = 50): array {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare(
            "SELECT v.*, u.display_name, ui.fraud_score, ui.risk_level, ui.automation_score
             FROM {$this->table} v
             JOIN " . bcc_trust_user_info_table() . " ui ON v.voter_user_id = ui.user_id
             JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
             WHERE v.page_id = %d
             AND v.status = 1
             AND ui.fraud_score >= %f
             ORDER BY ui.fraud_score DESC",
            $pageId,
            $minFraudScore
        ));
    }

    /**
     * Get flagged votes
     */
    public function getFlaggedVotes(int $limit = 100): array {
        global $wpdb;
        
        $flagsTable = bcc_trust_flags_table();

        return $wpdb->get_results($wpdb->prepare(
            "SELECT v.*, 
                    COUNT(f.id) as flag_count,
                    GROUP_CONCAT(DISTINCT f.reason) as flag_reasons,
                    u.display_name as voter_name,
                    p.post_title as page_title
             FROM {$this->table} v
             JOIN {$flagsTable} f ON v.id = f.vote_id
             LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
             LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
             WHERE v.status = 1
             AND f.status = 0
             GROUP BY v.id
             ORDER BY flag_count DESC, v.created_at DESC
             LIMIT %d",
            $limit
        ));
    }

    /**
     * Clean up old deleted votes
     */
    public function cleanupOldDeleted(int $days = 30): int {
        global $wpdb;

        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table}
                 WHERE status = 0
                 AND updated_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                $days
            )
        );
    }

    /**
     * Get voting summary for dashboard
     */
    public function getSummary(): object {
        global $wpdb;

        $summary = $wpdb->get_row("
            SELECT 
                COUNT(*) as total_votes,
                COUNT(DISTINCT page_id) as unique_pages,
                COUNT(DISTINCT voter_user_id) as unique_voters,
                SUM(CASE WHEN vote_type > 0 THEN 1 ELSE 0 END) as upvotes,
                SUM(CASE WHEN vote_type < 0 THEN 1 ELSE 0 END) as downvotes,
                SUM(weight) as total_weight,
                AVG(weight) as avg_weight,
                MAX(created_at) as last_vote_at
            FROM {$this->table}
            WHERE status = 1
        ");

        if (!$summary) {
            $summary = (object) [
                'total_votes' => 0,
                'unique_pages' => 0,
                'unique_voters' => 0,
                'upvotes' => 0,
                'downvotes' => 0,
                'total_weight' => 0,
                'avg_weight' => 0,
                'last_vote_at' => null
            ];
        }

        return $summary;
    }
}