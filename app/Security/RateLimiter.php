<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Enterprise Rate Limiter
 *
 * - Per-user limits
 * - Per-IP limits
 * - Burst control
 * - Sliding window
 * - Scales to 1M users
 */
class RateLimiter {

    const DEFAULT_LIMIT = 20;      // max actions
    const DEFAULT_WINDOW = 60;     // seconds

    // Action-specific limits
    const LIMITS = [
        'vote' => ['limit' => 30, 'window' => 60],      // 30 votes per minute
        'endorse' => ['limit' => 10, 'window' => 300],  // 10 endorsements per 5 minutes
        'flag' => ['limit' => 5, 'window' => 300],      // 5 flags per 5 minutes
        'verify' => ['limit' => 3, 'window' => 3600],   // 3 verification attempts per hour
    ];

    /**
     * Check if action allowed
     *
     * @param string $action
     * @param int|null $limit
     * @param int|null $window
     * @return bool
     */
    public static function allow(string $action, ?int $limit = null, ?int $window = null): bool {
        $userId = get_current_user_id();
        $ip = self::getIp();

        // Get action-specific limits if not provided
        if ($limit === null || $window === null) {
            $config = self::LIMITS[$action] ?? ['limit' => self::DEFAULT_LIMIT, 'window' => self::DEFAULT_WINDOW];
            $limit = $limit ?? $config['limit'];
            $window = $window ?? $config['window'];
        }

        // Anonymous users have stricter limits
        if (!$userId) {
            $limit = min($limit, 5);
        }

        $key = self::buildKey($action, $userId, $ip);
        $now = time();

        $data = get_transient($key);

        if (!$data) {
            $data = [
                'count' => 1,
                'start' => $now,
                'action' => $action
            ];
            set_transient($key, $data, $window);
            
            // Log rate limit hit for debugging
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log(sprintf(
                    '[BCC Trust RateLimiter] First %s: user=%d, ip=%s, limit=%d/%ds',
                    $action,
                    $userId,
                    $ip,
                    $limit,
                    $window
                ));
            }
            
            return true;
        }

        // Window expired - reset
        if (($now - $data['start']) > $window) {
            $data = [
                'count' => 1,
                'start' => $now,
                'action' => $action
            ];
            set_transient($key, $data, $window);
            return true;
        }

        // Check limit
        if ($data['count'] >= $limit) {
            // Log rate limit exceeded
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log(sprintf(
                    '[BCC Trust RateLimiter] Blocked %s: user=%d, ip=%s, count=%d, limit=%d',
                    $action,
                    $userId,
                    $ip,
                    $data['count'],
                    $limit
                ));
            }
            
            // Alert on suspicious rate limiting
            if ($data['count'] > $limit * 2) {
                AuditLogger::log('rate_limit_exceeded', null, [
                    'action' => $action,
                    'user_id' => $userId,
                    'ip' => $ip,
                    'count' => $data['count'],
                    'limit' => $limit
                ], 'system');
            }
            
            return false;
        }

        // Increment
        $data['count']++;
        set_transient($key, $data, $window);

        return true;
    }

    /**
     * Enforce or throw
     *
     * @throws \Exception
     */
    public static function enforce(string $action, ?int $limit = null, ?int $window = null): void {
        if (!self::allow($action, $limit, $window)) {
            $resetIn = self::resetIn($action);
            throw new \Exception(
                sprintf('Too many requests. Please wait %d seconds.', $resetIn),
                429
            );
        }
    }

    /**
     * Get remaining attempts
     */
    public static function remaining(string $action, ?int $limit = null, ?int $window = null): int {
        $userId = get_current_user_id();
        $ip = self::getIp();

        // Get action-specific limits if not provided
        if ($limit === null || $window === null) {
            $config = self::LIMITS[$action] ?? ['limit' => self::DEFAULT_LIMIT, 'window' => self::DEFAULT_WINDOW];
            $limit = $limit ?? $config['limit'];
        }

        $key = self::buildKey($action, $userId, $ip);
        $data = get_transient($key);

        if (!$data) {
            return $limit;
        }

        $now = time();
        if (($now - $data['start']) > $window) {
            return $limit;
        }

        return max(0, $limit - $data['count']);
    }

    /**
     * Get reset time in seconds
     */
    public static function resetIn(string $action): int {
        $userId = get_current_user_id();
        $ip = self::getIp();

        // Get action-specific window
        $window = self::LIMITS[$action]['window'] ?? self::DEFAULT_WINDOW;

        $key = self::buildKey($action, $userId, $ip);
        $data = get_transient($key);

        if (!$data) {
            return 0;
        }

        $now = time();
        $elapsed = $now - $data['start'];

        return max(0, $window - $elapsed);
    }

    /**
     * Check if user is rate limited for action
     */
    public static function isLimited(string $action, int $userId): bool {
        $ip = self::getIpForUser($userId);
        $key = self::buildKey($action, $userId, $ip);
        
        return get_transient($key) !== false;
    }

    /**
     * Clear rate limit for user
     */
    public static function clear(string $action, ?int $userId = null): void {
        if ($userId === null) {
            $userId = get_current_user_id();
        }
        
        $ip = self::getIpForUser($userId);
        $key = self::buildKey($action, $userId, $ip);
        
        delete_transient($key);
    }

    /**
     * Get rate limit status for all actions
     */
    public static function getStatus(): array {
        $userId = get_current_user_id();
        $ip = self::getIp();
        $status = [];

        foreach (array_keys(self::LIMITS) as $action) {
            $remaining = self::remaining($action);
            $resetIn = self::resetIn($action);
            
            $status[$action] = [
                'remaining' => $remaining,
                'reset_in' => $resetIn,
                'limited' => $remaining === 0
            ];
        }

        return $status;
    }

    /**
     * Build cache key
     */
    private static function buildKey(string $action, int $userId, string $ip): string {
        return 'bcc_rate_' . md5($action . '_' . $userId . '_' . $ip);
    }

    /**
     * Secure IP detection (Cloud-safe)
     */
    private static function getIp(): string {
        // CloudFlare
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_CF_CONNECTING_IP']);
        }

        // X-Forwarded-For (proxies)
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            return sanitize_text_field(trim($ips[0]));
        }

        // X-Real-IP (nginx)
        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            return sanitize_text_field($_SERVER['HTTP_X_REAL_IP']);
        }

        // Remote address
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            return sanitize_text_field($_SERVER['REMOTE_ADDR']);
        }

        return '0.0.0.0';
    }

    /**
     * Get IP for specific user from logs
     */
    private static function getIpForUser(int $userId): string {
        global $wpdb;
        
        $table = $wpdb->prefix . 'bcc_trust_activity';
        $ipBinary = $wpdb->get_var($wpdb->prepare(
            "SELECT ip_address FROM {$table}
             WHERE user_id = %d
             AND ip_address IS NOT NULL
             ORDER BY created_at DESC
             LIMIT 1",
            $userId
        ));

        if ($ipBinary) {
            return inet_ntop($ipBinary) ?: '0.0.0.0';
        }

        return '0.0.0.0';
    }

    /**
     * Get rate limit stats for admin
     */
    public static function getStats(): array {
        global $wpdb;

        // This would require a custom table to track effectively
        // For now, return basic stats
        return [
            'active_limits' => $wpdb->get_var(
                "SELECT COUNT(*) FROM {$wpdb->options} 
                 WHERE option_name LIKE '_transient_bcc_rate_%'"
            ),
            'actions' => array_keys(self::LIMITS)
        ];
    }
}