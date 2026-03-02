<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

class VoteRepository {

    private string $table;

    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'bcc_trust_votes'; // Fixed table name
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
     * Insert or update vote
     */
    public function upsert(array $data): int {
        global $wpdb;

        $existing = $this->getAny(
            $data['voter_user_id'] ?? $data['voter_id'], // Handle both naming conventions
            $data['page_id']
        );

        $now = current_time('mysql');
        
        // Standardize field names
        $voteData = [
            'voter_user_id' => $data['voter_user_id'] ?? $data['voter_id'],
            'page_id'       => $data['page_id'],
            'vote_type'     => $data['vote_type'],
            'weight'        => $data['weight'] ?? 1.0,
            'reason'        => $data['reason'] ?? null,
            'explanation'   => $data['explanation'] ?? null,
            'ip_address'    => $data['ip_address'] ?? null,
            'status'        => 1,
            'updated_at'    => $now
        ];

        if ($existing) {
            $wpdb->update(
                $this->table,
                $voteData,
                ['id' => $existing->id],
                ['%d', '%d', '%d', '%f', '%s', '%s', '%s', '%d', '%s'],
                ['%d']
            );
            return $existing->id;
        } else {
            $voteData['created_at'] = $now;
            
            $wpdb->insert(
                $this->table,
                $voteData,
                ['%d', '%d', '%d', '%f', '%s', '%s', '%s', '%d', '%s', '%s']
            );
            return $wpdb->insert_id;
        }
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
        
        return $result !== false;
    }

    /**
     * Get all votes for a page
     */
    public function getAllForPage(int $pageId): array {
        global $wpdb;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT v.*, u.display_name as voter_name
                 FROM {$this->table} v
                 LEFT JOIN {$wpdb->users} u ON v.voter_user_id = u.ID
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
                "SELECT v.*, p.post_title as page_title
                 FROM {$this->table} v
                 LEFT JOIN {$wpdb->posts} p ON v.page_id = p.ID
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
     * Count total votes by voter
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

        return $wpdb->get_row($wpdb->prepare(
            "SELECT 
                COUNT(*) as total_votes,
                SUM(CASE WHEN vote_type > 0 THEN weight ELSE 0 END) as total_positive_weight,
                SUM(CASE WHEN vote_type < 0 THEN weight ELSE 0 END) as total_negative_weight,
                COUNT(DISTINCT voter_user_id) as unique_voters,
                MAX(created_at) as last_vote_at
             FROM {$this->table}
             WHERE page_id = %d
             AND status = 1",
            $pageId
        ));
    }

    /**
     * Get user's vote on a page
     */
    public function getUserVote(int $pageId, int $userId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE page_id = %d
                 AND voter_user_id = %d
                 AND status = 1
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
            'downvote_weight' => 0
        ];

        foreach ($results as $row) {
            if ($row->vote_type > 0) {
                $counts['upvotes'] = (int) $row->count;
                $counts['upvote_weight'] = (float) $row->total_weight;
            } else {
                $counts['downvotes'] = (int) $row->count;
                $counts['downvote_weight'] = (float) $row->total_weight;
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
                "SELECT voter_user_id, weight
                 FROM {$this->table}
                 WHERE page_id = %d
                 AND status = 1",
                $pageId
            ),
            OBJECT_K
        );
    }
}