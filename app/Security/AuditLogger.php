<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) {
    exit;
}

class AuditLogger {

    private static string $table;

    /**
     * Initialize table name
     */
    private static function getTable(): string {
        if (!isset(self::$table)) {
            self::$table = bcc_trust_activity_table();
        }
        
        return self::$table;
    }

    /**
     * Log event
     *
     * @param string $action
     * @param int|null $targetId
     * @param array $meta
     * @param string|null $targetType
     * @param int|null $userId
     */
    public static function log(string $action, ?int $targetId = null, array $meta = [], ?string $targetType = null, ?int $userId = null): void {
        global $wpdb;

        $table = self::getTable();
        
        // Check if table exists before inserting
        $tableExists = $wpdb->get_var("SHOW TABLES LIKE '$table'") == $table;
        if (!$tableExists) {
            return; // Silently fail if table doesn't exist
        }

        $currentUserId = $userId ?? get_current_user_id();
        $ip = self::getIp();
        
        // Convert IP to binary for storage
        $ipBinary = null;
        if ($ip && $ip !== 'unknown') {
            $ipBinary = inet_pton($ip);
        }

        $data = [
            'user_id'       => $currentUserId ?: 0, // Default to 0 instead of null
            'action'        => sanitize_text_field($action),
            'target_type'   => $targetType ? sanitize_text_field($targetType) : '',
            'target_id'     => $targetId ?: 0,
            'ip_address'    => $ipBinary,
            'created_at'    => current_time('mysql', 1)
        ];

        $wpdb->insert(
            $table,
            $data,
            ['%d', '%s', '%s', '%d', '%s', '%s']
        );

        // For high-value actions, log to error log as well
        $alertActions = ['fraud', 'suspicious', 'flag', 'block', 'suspend'];
        foreach ($alertActions as $alert) {
            if (strpos($action, $alert) === 0) {
                error_log(sprintf(
                    '[BCC Trust Alert] %s - User: %d, Target: %d (%s), IP: %s',
                    $action,
                    $currentUserId,
                    $targetId ?? 0,
                    $targetType ?? 'unknown',
                    $ip
                ));
                break;
            }
        }
    }

    /**
     * Structured log helpers
     */
    public static function vote(int $pageId, int $voteType, array $meta = []): void {
        self::log('vote_' . ($voteType > 0 ? 'up' : 'down'), $pageId, $meta, 'page');
    }

    public static function removeVote(int $pageId, array $meta = []): void {
        self::log('vote_removed', $pageId, $meta, 'page');
    }

    public static function endorse(int $pageId, string $context = 'general', array $meta = []): void {
        self::log('endorse_' . sanitize_key($context), $pageId, $meta, 'page');
    }

    public static function revokeEndorsement(int $pageId, string $context = 'general', array $meta = []): void {
        self::log('endorse_revoked_' . sanitize_key($context), $pageId, $meta, 'page');
    }

    public static function verificationRequest(int $userId): void {
        self::log('verification_requested', $userId, [], 'user');
    }

    public static function verificationComplete(int $userId): void {
        self::log('email_verified', $userId, [], 'user');
    }

    public static function flagCreated(int $voteId, int $flaggerId, string $reason): void {
        self::log('flag_created', $voteId, [
            'flagger_id' => $flaggerId,
            'reason' => $reason
        ], 'vote');
    }

    public static function flagResolved(int $flagId, int $resolvedBy, string $action): void {
        self::log('flag_resolved', $flagId, [
            'resolved_by' => $resolvedBy,
            'action' => $action
        ], 'flag');
    }

    public static function reputationChange(int $userId, float $oldScore, float $newScore): void {
        self::log('reputation_changed', $userId, [
            'old_score' => $oldScore,
            'new_score' => $newScore,
            'difference' => $newScore - $oldScore
        ], 'user');
    }

    /**
     * Get recent activity for user
     */
    public static function getUserActivity(int $userId, int $limit = 50): array {
        global $wpdb;

        $table = self::getTable();

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE user_id = %d
             ORDER BY created_at DESC
             LIMIT %d",
            $userId,
            $limit
        ));
    }

    /**
     * Get activity by target
     */
    public static function getActivityByTarget(string $targetType, int $targetId, int $limit = 50): array {
        global $wpdb;

        $table = self::getTable();

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE target_type = %s
             AND target_id = %d
             ORDER BY created_at DESC
             LIMIT %d",
            $targetType,
            $targetId,
            $limit
        ));
    }

    /**
     * Get activity by IP
     */
    public static function getActivityByIp(string $ip, int $limit = 50): array {
        global $wpdb;

        $table = self::getTable();
        
        // Convert IP to binary for lookup
        $ipBinary = inet_pton($ip);

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE ip_address = %s
             ORDER BY created_at DESC
             LIMIT %d",
            $ipBinary,
            $limit
        ));
    }

    /**
     * Get suspicious activity
     */
    public static function getSuspiciousActivity(int $hours = 24, int $limit = 100): array {
        global $wpdb;

        $table = self::getTable();

        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE action LIKE 'suspicious%%' 
                OR action LIKE 'fraud%%'
                OR action LIKE 'flag%%'
             AND created_at > (UTC_TIMESTAMP() - INTERVAL %d HOUR)
             ORDER BY created_at DESC
             LIMIT %d",
            $hours,
            $limit
        ));
    }

    /**
     * Get activity summary for dashboard
     */
    public static function getSummary(int $hours = 24): object {
        global $wpdb;

        $table = self::getTable();

        $summary = $wpdb->get_row($wpdb->prepare("
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT target_id) as unique_targets,
                SUM(CASE WHEN action LIKE 'vote_%' THEN 1 ELSE 0 END) as vote_events,
                SUM(CASE WHEN action LIKE 'endorse%' THEN 1 ELSE 0 END) as endorse_events,
                SUM(CASE WHEN action LIKE 'flag%' THEN 1 ELSE 0 END) as flag_events,
                SUM(CASE WHEN action LIKE 'fraud%' OR action LIKE 'suspicious%' THEN 1 ELSE 0 END) as fraud_alerts
            FROM {$table}
            WHERE created_at > (UTC_TIMESTAMP() - INTERVAL %d HOUR)
        ", $hours));

        if (!$summary) {
            $summary = (object) [
                'total_events' => 0,
                'unique_users' => 0,
                'unique_targets' => 0,
                'vote_events' => 0,
                'endorse_events' => 0,
                'flag_events' => 0,
                'fraud_alerts' => 0
            ];
        }

        return $summary;
    }

    /**
     * Get recent events for dashboard
     */
    public static function getRecentEvents(int $limit = 20): array {
        global $wpdb;

        $table = self::getTable();

        return $wpdb->get_results($wpdb->prepare("
            SELECT a.*, u.display_name as user_name
            FROM {$table} a
            LEFT JOIN {$wpdb->users} u ON a.user_id = u.ID
            ORDER BY a.created_at DESC
            LIMIT %d
        ", $limit));
    }

    /**
     * Secure IP detection (Cloud-aware)
     */
    private static function getIp(): string {
        $ip = 'unknown';

        // CloudFlare
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } 
        // X-Forwarded-For (proxies)
        elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($ips[0]);
        } 
        // X-Real-IP (nginx)
        elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $ip = $_SERVER['HTTP_X_REAL_IP'];
        }
        // Remote address
        elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        // Validate IP
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }

        return 'unknown';
    }

    /**
     * Clean old logs (call via cron)
     */
    public static function cleanOldLogs(int $days = 90): int {
        global $wpdb;

        $table = self::getTable();
        
        // Check if table exists
        $tableExists = $wpdb->get_var("SHOW TABLES LIKE '$table'") == $table;
        if (!$tableExists) {
            return 0;
        }

        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$table}
                 WHERE created_at < UTC_TIMESTAMP() - INTERVAL %d DAY",
                $days
            )
        );
    }

    /**
     * Archive old logs (instead of deleting)
     */
    public static function archiveOldLogs(int $days = 90): int {
        global $wpdb;

        $table = self::getTable();
        $archiveTable = $table . '_archive';
        
        // Check if archive table exists, create if not
        $wpdb->query("CREATE TABLE IF NOT EXISTS $archiveTable LIKE $table");
        
        // Move old records to archive
        $moved = $wpdb->query(
            $wpdb->prepare(
                "INSERT INTO $archiveTable 
                 SELECT * FROM $table 
                 WHERE created_at < UTC_TIMESTAMP() - INTERVAL %d DAY",
                $days
            )
        );
        
     
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table 
                 WHERE created_at < UTC_TIMESTAMP() - INTERVAL %d DAY",
                $days
            )
        );
        
        return $moved ?: 0;
    }
}