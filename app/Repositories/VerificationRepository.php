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

    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'bcc_trust_verifications'; // Fixed table name
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
     * Mark token as verified
     */
    public function markVerified(int $id): void {
        global $wpdb;

        $wpdb->update(
            $this->table,
            ['verified_at' => current_time('mysql', 1)],
            ['id' => $id],
            ['%s'],
            ['%d']
        );
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
}