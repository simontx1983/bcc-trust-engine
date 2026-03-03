<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Verification Repository
 *
 * Handles secure email verification tokens.
 */
class VerificationRepository {

    private string $table;
    private $userInfoRepo;

    public function __construct() {
        $this->table = bcc_trust_verifications_table();
        $this->userInfoRepo = new UserInfoRepository();
    }

    /**
     * Create verification token
     */
    public function create(int $userId, string $tokenHash, string $expiresAt): bool {
        global $wpdb;

        // Delete any existing unused tokens for this user
        $wpdb->delete(
            $this->table,
            [
                'user_id' => $userId,
                'verified_at' => null
            ],
            ['%d']
        );

        return (bool) $wpdb->insert(
            $this->table,
            [
                'user_id'           => $userId,
                'verification_code' => $tokenHash,
                'verified_at'       => null,
                'expires_at'        => $expiresAt,
                'created_at'        => current_time('mysql', 1)
            ],
            ['%d', '%s', '%s', '%s', '%s']
        );
    }

    /**
     * Get valid token
     */
    public function getValid(int $userId, string $tokenHash): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE user_id = %d
                 AND verification_code = %s
                 AND verified_at IS NULL
                 AND expires_at > UTC_TIMESTAMP()
                 ORDER BY created_at DESC
                 LIMIT 1",
                $userId,
                $tokenHash
            )
        );
    }

    /**
     * Get token by code (for verification links)
     */
    public function getByCode(string $tokenHash): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE verification_code = %s
                 AND verified_at IS NULL
                 AND expires_at > UTC_TIMESTAMP()
                 ORDER BY created_at DESC
                 LIMIT 1",
                $tokenHash
            )
        );
    }

    /**
     * Get latest token for user
     */
    public function getLatest(int $userId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE user_id = %d
                 ORDER BY created_at DESC
                 LIMIT 1",
                $userId
            )
        );
    }

    /**
     * Check if user is verified
     */
    public function isVerified(int $userId): bool {
        global $wpdb;

        $verified = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT verified_at FROM {$this->table}
                 WHERE user_id = %d
                 AND verified_at IS NOT NULL
                 ORDER BY verified_at DESC
                 LIMIT 1",
                $userId
            )
        );

        return !is_null($verified);
    }

    /**
     * Get verification record for user
     */
    public function getForUser(int $userId): ?object {
        global $wpdb;

        return $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->table}
                 WHERE user_id = %d
                 ORDER BY created_at DESC
                 LIMIT 1",
                $userId
            )
        );
    }

    /**
     * Mark token as verified and update user_info table
     */
    public function markVerified(int $id): void {
        global $wpdb;

        // Get the user_id before marking verified
        $record = $wpdb->get_row($wpdb->prepare(
            "SELECT user_id FROM {$this->table} WHERE id = %d",
            $id
        ));

        if ($record) {
            // Mark token as verified
            $wpdb->update(
                $this->table,
                ['verified_at' => current_time('mysql', 1)],
                ['id' => $id],
                ['%s'],
                ['%d']
            );

            // Update user_info table
            $this->userInfoRepo->updateVerificationStatus($record->user_id, true);
        }
    }

    /**
     * Get verification statistics
     */
    public function getStats(): object {
        global $wpdb;

        $stats = $wpdb->get_row("
            SELECT 
                COUNT(*) as total_tokens,
                COUNT(CASE WHEN verified_at IS NOT NULL THEN 1 END) as verified_count,
                COUNT(CASE WHEN verified_at IS NULL AND expires_at > UTC_TIMESTAMP() THEN 1 END) as pending_count,
                COUNT(CASE WHEN verified_at IS NULL AND expires_at <= UTC_TIMESTAMP() THEN 1 END) as expired_count,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT CASE WHEN verified_at IS NOT NULL THEN user_id END) as verified_users,
                MIN(created_at) as oldest_token,
                MAX(created_at) as newest_token
            FROM {$this->table}
        ");

        if (!$stats) {
            $stats = (object) [
                'total_tokens' => 0,
                'verified_count' => 0,
                'pending_count' => 0,
                'expired_count' => 0,
                'unique_users' => 0,
                'verified_users' => 0,
                'oldest_token' => null,
                'newest_token' => null
            ];
        }

        return $stats;
    }

    /**
     * Get users who haven't verified their email
     */
    public function getUnverifiedUsers(int $limit = 100, int $offset = 0): array {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare("
            SELECT DISTINCT u.ID, u.user_email, u.display_name, u.user_registered,
                   v.created_at as last_verification_sent,
                   v.expires_at
            FROM {$wpdb->users} u
            LEFT JOIN {$this->table} v ON u.ID = v.user_id
            LEFT JOIN {$this->table} v2 ON u.ID = v2.user_id AND v2.verified_at IS NOT NULL
            WHERE v2.id IS NULL
            ORDER BY u.user_registered DESC
            LIMIT %d OFFSET %d
        ", $limit, $offset));
    }

    /**
     * Get verification history for a user
     */
    public function getHistory(int $userId, int $limit = 10): array {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare("
            SELECT * FROM {$this->table}
            WHERE user_id = %d
            ORDER BY created_at DESC
            LIMIT %d
        ", $userId, $limit));
    }

    /**
     * Resend verification count (rate limiting helper)
     */
    public function getResendCount(int $userId, int $hours = 24): int {
        global $wpdb;

        return (int) $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*) FROM {$this->table}
            WHERE user_id = %d
            AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR)
        ", $userId, $hours));
    }

    /**
     * Delete expired tokens (cleanup)
     */
    public function deleteExpired(): int {
        global $wpdb;

        return $wpdb->query(
            "DELETE FROM {$this->table}
             WHERE expires_at < UTC_TIMESTAMP()"
        );
    }

    /**
     * Delete old verified tokens (older than 30 days)
     */
    public function deleteOldVerified(int $days = 30): int {
        global $wpdb;

        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$this->table}
                 WHERE verified_at IS NOT NULL
                 AND verified_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                $days
            )
        );
    }

    /**
     * Delete orphaned tokens (for users that no longer exist)
     */
    public function deleteOrphaned(): int {
        global $wpdb;

        return $wpdb->query("
            DELETE v FROM {$this->table} v
            LEFT JOIN {$wpdb->users} u ON v.user_id = u.ID
            WHERE u.ID IS NULL
        ");
    }

    /**
     * Get verification completion rate
     */
    public function getCompletionRate(): float {
        global $wpdb;

        $result = $wpdb->get_row("
            SELECT 
                COUNT(CASE WHEN verified_at IS NOT NULL THEN 1 END) as verified,
                COUNT(*) as total
            FROM {$this->table}
        ");

        if (!$result || $result->total == 0) {
            return 0;
        }

        return round(($result->verified / $result->total) * 100, 2);
    }

    /**
     * Bulk verify users (admin function)
     */
    public function bulkVerify(array $userIds): int {
        global $wpdb;
        
        if (empty($userIds)) {
            return 0;
        }

        $placeholders = implode(',', array_fill(0, count($userIds), '%d'));
        
        // Mark tokens as verified
        $result = $wpdb->query(
            $wpdb->prepare(
                "UPDATE {$this->table} 
                 SET verified_at = %s
                 WHERE user_id IN ({$placeholders})
                 AND verified_at IS NULL",
                array_merge([current_time('mysql', 1)], $userIds)
            )
        );

        // Update user_info table for each user
        foreach ($userIds as $userId) {
            $this->userInfoRepo->updateVerificationStatus($userId, true);
        }

        return $result ?: 0;
    }

    /**
     * Clean up old data (comprehensive cleanup)
     */
    public function cleanup(int $expiredDays = 1, int $verifiedDays = 30): array {
        $results = [
            'expired_deleted' => 0,
            'verified_deleted' => 0,
            'orphaned_deleted' => 0
        ];

        // Delete expired tokens older than specified days
        if ($expiredDays > 0) {
            $results['expired_deleted'] = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$this->table}
                     WHERE expires_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                    $expiredDays
                )
            );
        }

        // Delete old verified tokens
        if ($verifiedDays > 0) {
            $results['verified_deleted'] = $this->deleteOldVerified($verifiedDays);
        }

        // Delete orphaned records
        $results['orphaned_deleted'] = $this->deleteOrphaned();

        return $results;
    }
}