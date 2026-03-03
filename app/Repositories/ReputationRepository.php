<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

use Exception;

class ReputationRepository {
    private string $table;

    public function __construct() {
        $this->table = bcc_trust_reputation_table();
    }

    /**
     * Get reputation record by user ID
     */
    public function getByUserId(int $userId): ?object {
        global $wpdb;
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table} WHERE user_id = %d",
            $userId
        ));
    }

    /**
     * Create or update reputation record
     */
    public function createOrUpdate(int $userId, array $data): void {
        global $wpdb;
        
        $exists = $this->getByUserId($userId);
        
        // Validate and sanitize input data
        $validated = $this->validateData($data);
        
        // Calculate tier based on reputation score
        if (isset($validated['reputation_score'])) {
            $validated['reputation_tier'] = $this->calculateTier($validated['reputation_score']);
        }
        
        // Ensure last_calculated_at is set
        if (!isset($validated['last_calculated_at'])) {
            $validated['last_calculated_at'] = current_time('mysql');
        }
        
        if ($exists) {
            $wpdb->update(
                $this->table,
                $validated,
                ['user_id' => $userId],
                $this->getFormatSpecifiers($validated),
                ['%d']
            );
        } else {
            $validated['user_id'] = $userId;
            $wpdb->insert(
                $this->table,
                $validated,
                $this->getFormatSpecifiers($validated)
            );
        }
    }

    /**
     * Update specific fields for a user
     */
    public function update(int $userId, array $data): bool {
        global $wpdb;
        
        $validated = $this->validateData($data);
        
        if (isset($validated['reputation_score'])) {
            $validated['reputation_tier'] = $this->calculateTier($validated['reputation_score']);
        }
        
        $validated['last_calculated_at'] = current_time('mysql');
        
        $result = $wpdb->update(
            $this->table,
            $validated,
            ['user_id' => $userId],
            $this->getFormatSpecifiers($validated),
            ['%d']
        );
        
        return $result !== false;
    }

    /**
     * Increment votes cast for a user
     */
    public function incrementVotesCast(int $userId, int $count = 1): void {
        global $wpdb;
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET total_votes_cast = total_votes_cast + %d,
                 last_calculated_at = %s
             WHERE user_id = %d",
            $count,
            current_time('mysql'),
            $userId
        ));
    }

    /**
     * Increment votes received for a user
     */
    public function incrementVotesReceived(int $userId, int $count = 1): void {
        global $wpdb;
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET total_votes_received = total_votes_received + %d,
                 last_calculated_at = %s
             WHERE user_id = %d",
            $count,
            current_time('mysql'),
            $userId
        ));
    }

    /**
     * Increment flag count for a user
     */
    public function incrementFlagCount(int $userId, int $count = 1): void {
        global $wpdb;
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET flag_count = flag_count + %d,
                 last_calculated_at = %s
             WHERE user_id = %d",
            $count,
            current_time('mysql'),
            $userId
        ));
    }

    /**
     * Update vote weight for a user
     */
    public function updateVoteWeight(int $userId, float $weight): bool {
        global $wpdb;
        
        // Validate weight range (0.1 to 3.0)
        $weight = max(0.1, min(3.0, $weight));
        
        $result = $wpdb->update(
            $this->table,
            [
                'vote_weight' => $weight,
                'last_calculated_at' => current_time('mysql')
            ],
            ['user_id' => $userId],
            ['%f', '%s'],
            ['%d']
        );
        
        return $result !== false;
    }

    /**
     * Get users with high reputation
     */
    public function getHighReputationUsers(float $minScore = 70, int $limit = 50): array {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT r.*, u.display_name, u.user_email
             FROM {$this->table} r
             JOIN {$wpdb->users} u ON r.user_id = u.ID
             WHERE r.reputation_score >= %f
             ORDER BY r.reputation_score DESC
             LIMIT %d",
            $minScore,
            $limit
        ));
    }

    /**
     * Get users with low reputation
     */
    public function getLowReputationUsers(float $maxScore = 30, int $limit = 50): array {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT r.*, u.display_name, u.user_email
             FROM {$this->table} r
             JOIN {$wpdb->users} u ON r.user_id = u.ID
             WHERE r.reputation_score <= %f
             ORDER BY r.reputation_score ASC
             LIMIT %d",
            $maxScore,
            $limit
        ));
    }

    /**
     * Get users by reputation tier
     */
    public function getByTier(string $tier, int $limit = 100): array {
        global $wpdb;
        
        $validTiers = ['elite', 'trusted', 'neutral', 'caution', 'risky'];
        if (!in_array($tier, $validTiers)) {
            return [];
        }
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT r.*, u.display_name, u.user_email
             FROM {$this->table} r
             JOIN {$wpdb->users} u ON r.user_id = u.ID
             WHERE r.reputation_tier = %s
             ORDER BY r.reputation_score DESC
             LIMIT %d",
            $tier,
            $limit
        ));
    }

    /**
     * Get reputation statistics
     */
    public function getStats(): object {
        global $wpdb;
        
        $stats = $wpdb->get_row("
            SELECT 
                COUNT(*) as total_users,
                AVG(reputation_score) as avg_score,
                MIN(reputation_score) as min_score,
                MAX(reputation_score) as max_score,
                SUM(total_votes_cast) as total_votes_cast,
                SUM(total_votes_received) as total_votes_received,
                SUM(flag_count) as total_flags,
                AVG(vote_weight) as avg_vote_weight,
                SUM(CASE WHEN reputation_tier = 'elite' THEN 1 ELSE 0 END) as elite_count,
                SUM(CASE WHEN reputation_tier = 'trusted' THEN 1 ELSE 0 END) as trusted_count,
                SUM(CASE WHEN reputation_tier = 'neutral' THEN 1 ELSE 0 END) as neutral_count,
                SUM(CASE WHEN reputation_tier = 'caution' THEN 1 ELSE 0 END) as caution_count,
                SUM(CASE WHEN reputation_tier = 'risky' THEN 1 ELSE 0 END) as risky_count
            FROM {$this->table}
        ");
        
        return $stats ?: (object) [
            'total_users' => 0,
            'avg_score' => 0,
            'min_score' => 0,
            'max_score' => 0,
            'total_votes_cast' => 0,
            'total_votes_received' => 0,
            'total_flags' => 0,
            'avg_vote_weight' => 0,
            'elite_count' => 0,
            'trusted_count' => 0,
            'neutral_count' => 0,
            'caution_count' => 0,
            'risky_count' => 0
        ];
    }

    /**
     * Delete reputation record for a user
     */
    public function delete(int $userId): bool {
        global $wpdb;
        
        $result = $wpdb->delete(
            $this->table,
            ['user_id' => $userId],
            ['%d']
        );
        
        return $result !== false;
    }

    /**
     * Validate and sanitize reputation data
     */
    private function validateData(array $data): array {
        $validated = [];
        
        // Allowed fields and their types
        $allowedFields = [
            'reputation_score' => 'float',
            'total_votes_cast' => 'int',
            'total_votes_received' => 'int',
            'flag_count' => 'int',
            'vote_weight' => 'float',
            'reputation_tier' => 'string',
            'last_calculated_at' => 'string'
        ];
        
        foreach ($allowedFields as $field => $type) {
            if (isset($data[$field])) {
                switch ($type) {
                    case 'float':
                        $validated[$field] = (float) $data[$field];
                        // Apply range constraints
                        if ($field === 'reputation_score') {
                            $validated[$field] = max(0, min(100, $validated[$field]));
                        }
                        if ($field === 'vote_weight') {
                            $validated[$field] = max(0.1, min(3.0, $validated[$field]));
                        }
                        break;
                    case 'int':
                        $validated[$field] = max(0, (int) $data[$field]);
                        break;
                    case 'string':
                        if ($field === 'reputation_tier') {
                            $validTiers = ['elite', 'trusted', 'neutral', 'caution', 'risky'];
                            if (in_array($data[$field], $validTiers)) {
                                $validated[$field] = $data[$field];
                            }
                        } else {
                            $validated[$field] = sanitize_text_field($data[$field]);
                        }
                        break;
                }
            }
        }
        
        return $validated;
    }

    /**
     * Get format specifiers for wpdb operations
     */
    private function getFormatSpecifiers(array $data): array {
        $formats = [];
        
        foreach ($data as $field => $value) {
            if (in_array($field, ['user_id'])) {
                continue; // Skip user_id for format specifiers
            }
            
            switch ($field) {
                case 'reputation_score':
                case 'vote_weight':
                    $formats[] = '%f';
                    break;
                case 'total_votes_cast':
                case 'total_votes_received':
                case 'flag_count':
                    $formats[] = '%d';
                    break;
                case 'reputation_tier':
                case 'last_calculated_at':
                    $formats[] = '%s';
                    break;
                default:
                    $formats[] = '%s';
            }
        }
        
        return $formats;
    }

    /**
     * Calculate reputation tier based on score
     */
    private function calculateTier(float $score): string {
        if ($score >= 80) {
            return 'elite';
        } elseif ($score >= 65) {
            return 'trusted';
        } elseif ($score >= 45) {
            return 'neutral';
        } elseif ($score >= 30) {
            return 'caution';
        } else {
            return 'risky';
        }
    }

    /**
     * Initialize reputation for a new user
     */
    public function initializeForUser(int $userId): void {
        $defaults = [
            'reputation_score' => 50.00,
            'total_votes_cast' => 0,
            'total_votes_received' => 0,
            'flag_count' => 0,
            'vote_weight' => 1.0,
            'reputation_tier' => 'neutral',
            'last_calculated_at' => current_time('mysql')
        ];
        
        $this->createOrUpdate($userId, $defaults);
    }

    /**
     * Get reputation score for a user
     */
    public function getScore(int $userId): float {
        $record = $this->getByUserId($userId);
        return $record ? (float) $record->reputation_score : 50.00;
    }

    /**
     * Get vote weight for a user
     */
    public function getVoteWeight(int $userId): float {
        $record = $this->getByUserId($userId);
        return $record ? (float) $record->vote_weight : 1.0;
    }

    /**
     * Get reputation tier for a user
     */
    public function getTier(int $userId): string {
        $record = $this->getByUserId($userId);
        return $record ? $record->reputation_tier : 'neutral';
    }

    /**
     * Check if user has sufficient reputation
     */
    public function hasSufficientReputation(int $userId, float $minScore = 30): bool {
        $score = $this->getScore($userId);
        return $score >= $minScore;
    }

    /**
     * Batch update reputation scores
     */
    public function batchUpdate(array $updates): int {
        global $wpdb;
        
        $updated = 0;
        
        foreach ($updates as $userId => $score) {
            $result = $this->update($userId, ['reputation_score' => $score]);
            if ($result) {
                $updated++;
            }
        }
        
        return $updated;
    }
}