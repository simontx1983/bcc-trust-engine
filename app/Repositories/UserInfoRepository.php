<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

class UserInfoRepository {
    
    private string $table;
    
    public function __construct() {
        $this->table = bcc_trust_user_info_table();
    }
    
    /**
     * Get user info by user ID
     */
    public function getByUserId(int $userId): ?object {
        global $wpdb;
        
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table} WHERE user_id = %d",
            $userId
        ));
    }
    
    /**
     * Get multiple users by IDs
     */
    public function getBulkByUserIds(array $userIds): array {
        global $wpdb;
        
        if (empty($userIds)) {
            return [];
        }
        
        $placeholders = implode(',', array_fill(0, count($userIds), '%d'));
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->table} WHERE user_id IN ({$placeholders})",
                $userIds
            )
        );
        
        $indexed = [];
        foreach ($results as $row) {
            $indexed[$row->user_id] = $row;
        }
        
        return $indexed;
    }
    
    /**
     * Update fraud score
     */
    public function updateFraudScore(int $userId, int $score): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['fraud_score' => $score],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update trust rank
     */
    public function updateTrustRank(int $userId, float $rank): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['trust_rank' => $rank],
            ['user_id' => $userId],
            ['%f'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update votes cast count
     */
    public function updateVotesCast(int $userId, int $count): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['votes_cast' => $count],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update endorsements given count
     */
    public function updateEndorsementsGiven(int $userId, int $count): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['endorsements_given' => $count],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update automation score
     */
    public function updateAutomationScore(int $userId, int $score): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['automation_score' => $score],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update behavior score
     */
    public function updateBehaviorScore(int $userId, int $score): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['behavior_score' => $score],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Update verification status
     */
    public function updateVerificationStatus(int $userId, bool $verified): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['is_verified' => $verified ? 1 : 0],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Suspend user
     */
    public function suspendUser(int $userId, string $reason): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            [
                'is_suspended' => 1,
                'fraud_triggers' => json_encode(['suspension_reason' => $reason])
            ],
            ['user_id' => $userId],
            ['%d', '%s'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Unsuspend user
     */
    public function unsuspendUser(int $userId): bool {
        global $wpdb;
        
        return $wpdb->update(
            $this->table,
            ['is_suspended' => 0],
            ['user_id' => $userId],
            ['%d'],
            ['%d']
        ) !== false;
    }
    
    /**
     * Increment fraud score
     */
    public function incrementFraudScore(int $userId, int $increment, string $reason): bool {
        global $wpdb;
        
        $userInfo = $this->getByUserId($userId);
        $currentTriggers = $userInfo && $userInfo->fraud_triggers ? json_decode($userInfo->fraud_triggers, true) : [];
        $currentTriggers[] = $reason;
        
        return $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} 
             SET fraud_score = LEAST(100, fraud_score + %d),
                 fraud_triggers = %s
             WHERE user_id = %d",
            $increment,
            json_encode(array_unique($currentTriggers)),
            $userId
        )) !== false;
    }
    
    /**
     * Increment page count
     */
    public function incrementPageCount(int $userId, ?int $pageId = null): bool {
        global $wpdb;
        
        if ($pageId) {
            $userInfo = $this->getByUserId($userId);
            $pageIds = $userInfo && $userInfo->page_ids_owned ? json_decode($userInfo->page_ids_owned, true) : [];
            if (!is_array($pageIds)) $pageIds = [];
            $pageIds[] = $pageId;
            
            return $wpdb->update(
                $this->table,
                [
                    'pages_owned' => ($userInfo ? $userInfo->pages_owned : 0) + 1,
                    'page_ids_owned' => json_encode(array_unique($pageIds))
                ],
                ['user_id' => $userId],
                ['%d', '%s'],
                ['%d']
            ) !== false;
        }
        
        return $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} SET pages_owned = pages_owned + 1 WHERE user_id = %d",
            $userId
        )) !== false;
    }
    
    /**
     * Decrement page count
     */
    public function decrementPageCount(int $userId, ?int $pageId = null): bool {
        global $wpdb;
        
        if ($pageId) {
            $userInfo = $this->getByUserId($userId);
            $pageIds = $userInfo && $userInfo->page_ids_owned ? json_decode($userInfo->page_ids_owned, true) : [];
            if (!is_array($pageIds)) $pageIds = [];
            $pageIds = array_values(array_diff($pageIds, [$pageId]));
            
            return $wpdb->update(
                $this->table,
                [
                    'pages_owned' => max(0, ($userInfo ? $userInfo->pages_owned : 0) - 1),
                    'page_ids_owned' => !empty($pageIds) ? json_encode($pageIds) : null
                ],
                ['user_id' => $userId],
                ['%d', '%s'],
                ['%d']
            ) !== false;
        }
        
        return $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table} SET pages_owned = GREATEST(pages_owned - 1, 0) WHERE user_id = %d",
            $userId
        )) !== false;
    }
    
    /**
     * Transfer page ownership
     */
    public function transferPageOwnership(int $oldOwnerId, int $newOwnerId, int $pageId): bool {
        $this->decrementPageCount($oldOwnerId, $pageId);
        $this->incrementPageCount($newOwnerId, $pageId);
        return true;
    }
    
    /**
     * Get high risk users
     */
    public function getHighRiskUsers(int $threshold = 70, int $limit = 100): array {
        global $wpdb;
        
        $results = $wpdb->get_results($wpdb->prepare("
            SELECT ui.*, u.display_name, u.user_email
            FROM {$this->table} ui
            JOIN {$wpdb->users} u ON ui.user_id = u.ID
            WHERE ui.fraud_score >= %d
            ORDER BY ui.fraud_score DESC
            LIMIT %d
        ", $threshold, $limit));
        
        $users = [];
        foreach ($results as $row) {
            $triggers = $row->fraud_triggers ? json_decode($row->fraud_triggers, true) : [];
            $users[] = [
                'id' => $row->user_id,
                'name' => $row->display_name,
                'email' => $row->user_email,
                'fraud_score' => $row->fraud_score,
                'risk_level' => $row->risk_level,
                'triggers' => is_array($triggers) ? $triggers : [],
                'suspended' => (bool) $row->is_suspended
            ];
        }
        
        return $users;
    }
    
    /**
     * Count verified users
     */
    public function countVerified(): int {
        global $wpdb;
        
        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->table} WHERE is_verified = 1"
        );
    }
}