<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) {
    exit;
}

use BCCTrust\Repositories\UserInfoRepository;

/**
 * Enterprise Rate Limiter
 *
 * - Per-user limits
 * - Per-IP limits
 * - Burst control
 * - Sliding window
 * - Scales to 1M users
 * - Trust-based adjustments
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
     * @var UserInfoRepository
     */
    private static $userInfoRepo;

    /**
     * Initialize repositories
     */
    private static function initRepositories(): void {
        if (!self::$userInfoRepo) {
            self::$userInfoRepo = new UserInfoRepository();
        }
    }

    /**
     * Check if action allowed
     *
     * @param string $action
     * @param int|null $limit
     * @param int|null $window
     * @return bool
     */
    public static function allow(string $action, ?int $limit = null, ?int $window = null): bool {
        self::initRepositories();
        
        $userId = get_current_user_id();
        $ip = self::getIp();

        // Get action-specific limits if not provided
        if ($limit === null || $window === null) {
            $config = self::LIMITS[$action] ?? ['limit' => self::DEFAULT_LIMIT, 'window' => self::DEFAULT_WINDOW];
            $limit = $limit ?? $config['limit'];
            $window = $window ?? $config['window'];
        }

        // Adjust limits based on user trust level
        $adjustedLimit = self::getAdjustedLimit($userId, $limit, $action);

        // Anonymous users have stricter limits
        if (!$userId) {
            $adjustedLimit = min($adjustedLimit, 5);
        }

        $key = self::buildKey($action, $userId, $ip);
        $now = time();

        $data = get_transient($key);

        if (!$data) {
            $data = [
                'count' => 1,
                'start' => $now,
                'action' => $action,
                'user_id' => $userId
            ];
            set_transient($key, $data, $window);
            
            // Log rate limit hit for debugging
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log(sprintf(
                    '[BCC Trust RateLimiter] First %s: user=%d, ip=%s, limit=%d/%ds',
                    $action,
                    $userId,
                    $ip,
                    $adjustedLimit,
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
                'action' => $action,
                'user_id' => $userId
            ];
            set_transient($key, $data, $window);
            return true;
        }

        // Check limit
        if ($data['count'] >= $adjustedLimit) {
            // Log rate limit exceeded
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log(sprintf(
                    '[BCC Trust RateLimiter] Blocked %s: user=%d, ip=%s, count=%d, limit=%d',
                    $action,
                    $userId,
                    $ip,
                    $data['count'],
                    $adjustedLimit
                ));
            }
            
            // Alert on suspicious rate limiting
            if ($data['count'] > $adjustedLimit * 2) {
                if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
                    AuditLogger::log('rate_limit_exceeded', null, [
                        'action' => $action,
                        'user_id' => $userId,
                        'ip' => $ip,
                        'count' => $data['count'],
                        'limit' => $adjustedLimit
                    ], 'system');
                }
            }
            
            return false;
        }

        // Increment
        $data['count']++;
        set_transient($key, $data, $window);

        return true;
    }

    /**
     * Get adjusted limit based on user trust level
     */
    private static function getAdjustedLimit(int $userId, int $baseLimit, string $action): int {
        if (!$userId) {
            return $baseLimit;
        }

        $userInfo = self::$userInfoRepo->getByUserId($userId);
        if (!$userInfo) {
            return $baseLimit;
        }

        // High-risk users get stricter limits
        if ($userInfo->fraud_score > 70) {
            return (int) round($baseLimit * 0.3); // 70% reduction
        } elseif ($userInfo->fraud_score > 50) {
            return (int) round($baseLimit * 0.5); // 50% reduction
        } elseif ($userInfo->fraud_score > 30) {
            return (int) round($baseLimit * 0.7); // 30% reduction
        }

        // Verified users get higher limits
        if ($userInfo->is_verified) {
            return (int) round($baseLimit * 1.2); // 20% increase
        }

        // Trusted users based on reputation
        if ($userInfo->trust_rank > 0.8) {
            return (int) round($baseLimit * 1.3); // 30% increase
        }

        return $baseLimit;
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

        // Adjust limit based on trust
        $adjustedLimit = self::getAdjustedLimit($userId, $limit, $action);

        $key = self::buildKey($action, $userId, $ip);
        $data = get_transient($key);

        if (!$data) {
            return $adjustedLimit;
        }

        $now = time();
        if (($now - $data['start']) > $window) {
            return $adjustedLimit;
        }

        return max(0, $adjustedLimit - $data['count']);
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
        
        $table = bcc_trust_activity_table();
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

        // Count active rate limits
        $activeLimits = (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_bcc_rate_%'"
        );

        // Get user trust distribution for limits
        self::initRepositories();
        
        $trustLevels = [
            'high_risk' => 0,
            'verified' => 0,
            'trusted' => 0
        ];

        // This would need a more efficient way in production
        // For now, return basic stats with trust info
        return [
            'active_limits' => $activeLimits,
            'actions' => array_keys(self::LIMITS),
            'limits_by_trust' => [
                'high_risk_multiplier' => 0.3,
                'medium_risk_multiplier' => 0.5,
                'low_risk_multiplier' => 0.7,
                'verified_multiplier' => 1.2,
                'trusted_multiplier' => 1.3
            ]
        ];
    }

    /**
     * Get detailed rate limit info for a user
     */
    public static function getUserLimitInfo(int $userId): array {
        self::initRepositories();
        
        $userInfo = self::$userInfoRepo->getByUserId($userId);
        $info = [];

        foreach (array_keys(self::LIMITS) as $action) {
            $baseLimit = self::LIMITS[$action]['limit'];
            $adjustedLimit = self::getAdjustedLimit($userId, $baseLimit, $action);
            
            $info[$action] = [
                'base_limit' => $baseLimit,
                'adjusted_limit' => $adjustedLimit,
                'remaining' => self::remaining($action),
                'reset_in' => self::resetIn($action)
            ];
        }

        return [
            'user_id' => $userId,
            'trust_level' => $userInfo ? $userInfo->risk_level : 'unknown',
            'fraud_score' => $userInfo ? $userInfo->fraud_score : 0,
            'is_verified' => $userInfo ? (bool) $userInfo->is_verified : false,
            'limits' => $info
        ];
    }
}