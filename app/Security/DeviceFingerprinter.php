<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) exit;

/**
 * Device Fingerprinter
 * 
 * Handles browser fingerprinting, bot detection, and multi-account detection
 * 
 * @package BCCTrust
 * @subpackage Security
 * @version 1.0.0
 */
class DeviceFingerprinter {
    
    /**
     * Database table name
     */
    private static $table;
    
    /**
     * Known bot user agents
     */
    private const BOT_USER_AGENTS = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
        'python', 'java', 'perl', 'ruby', 'php', 'node',
        'headless', 'phantomjs', 'puppeteer', 'playwright',
        'selenium', 'webdriver', 'chrome-headless', 'headlesschrome'
    ];
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
    }
    
    /**
     * Generate device fingerprint from request data
     * 
     * @return string SHA-256 hash of fingerprint components
     */
    public function generateFingerprint(): string {
        $components = [
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
            'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
            'screen_resolution' => $this->getCookie('bcc_screen'),
            'timezone' => $this->getCookie('bcc_timezone'),
            'platform' => $this->getCookie('bcc_platform'),
            'webgl_vendor' => $this->getCookie('bcc_webgl_vendor'),
            'webgl_renderer' => $this->getCookie('bcc_webgl_renderer'),
            'fonts' => $this->getCookie('bcc_fonts'),
            'cookies_enabled' => $this->getCookie('bcc_cookies'),
            'local_storage' => $this->getCookie('bcc_localstorage'),
            'session_storage' => $this->getCookie('bcc_sessionstorage'),
            'cpu_cores' => $this->getCookie('bcc_cpu_cores'),
            'memory' => $this->getCookie('bcc_memory'),
            'touch_support' => $this->getCookie('bcc_touch'),
            'color_depth' => $this->getCookie('bcc_color_depth'),
            'pixel_ratio' => $this->getCookie('bcc_pixel_ratio'),
            'audio_fingerprint' => $this->getCookie('bcc_audio'),
            'canvas_fingerprint' => $this->getCookie('bcc_canvas'),
            'plugins' => $this->getCookie('bcc_plugins'),
            'languages' => $this->getCookie('bcc_languages'),
            'product' => $this->getCookie('bcc_product'),
            'vendor' => $this->getCookie('bcc_vendor')
        ];
        
        // Remove empty values
        $components = array_filter($components);
        
        // Add IP address first octet for geolocation grouping (privacy-preserving)
        $ip = $this->getClientIp();
        if ($ip && $ip !== '0.0.0.0') {
            $ipParts = explode('.', $ip);
            if (isset($ipParts[0]) && isset($ipParts[1])) {
                $components['ip_network'] = $ipParts[0] . '.' . $ipParts[1] . '.0.0';
            }
        }
        
        // Create hash
        return hash('sha256', json_encode($components) . wp_salt('secure_auth'));
    }
    
    /**
     * Detect headless browsers and automation tools
     * 
     * @return array Automation detection results
     */
    public function detectAutomation(): array {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $headers = $this->getAllHeaders();
        
        $signals = [];
        $confidence = 0;
        
        // Check user agent for bot signatures
        foreach (self::BOT_USER_AGENTS as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                $signals[] = "ua_contains_{$bot}";
                $confidence += 15;
            }
        }
        
        // Check for headless Chrome specific
        if (stripos($userAgent, 'HeadlessChrome') !== false) {
            $signals[] = 'headless_chrome';
            $confidence += 25;
        }
        
        // FIXED: Check if headers is array before accessing
        if (is_array($headers)) {
            // Check for PhantomJS
            if ((isset($headers['Phantom-Version']) && $headers['Phantom-Version']) || 
                (isset($headers['X-Phantom-Viewport']) && $headers['X-Phantom-Viewport']) ||
                stripos($userAgent, 'phantomjs') !== false) {
                $signals[] = 'phantomjs';
                $confidence += 30;
            }
            
            // Check for Selenium
            if ((isset($headers['X-Selenium']) && $headers['X-Selenium']) || 
                (isset($headers['X-Webdriver']) && $headers['X-Webdriver']) ||
                isset($_SERVER['HTTP_WEBDRIVER'])) {
                $signals[] = 'selenium';
                $confidence += 30;
            }
            
            // Check for Puppeteer
            if ((isset($headers['X-Puppeteer']) && $headers['X-Puppeteer']) || 
                (isset($headers['X-Puppeteer-Version']) && $headers['X-Puppeteer-Version'])) {
                $signals[] = 'puppeteer';
                $confidence += 30;
            }
        }
        
        // Check for missing headers that real browsers have
        if (empty($_SERVER['HTTP_ACCEPT'])) {
            $signals[] = 'missing_accept';
            $confidence += 10;
        }
        
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $signals[] = 'missing_language';
            $confidence += 10;
        }
        
        if (empty($_SERVER['HTTP_ACCEPT_ENCODING'])) {
            $signals[] = 'missing_encoding';
            $confidence += 5;
        }
        
        // Check for consistent request timing (from cookie)
        $timingData = $this->getCookie('bcc_request_timing');
        if ($timingData) {
            $timings = json_decode($timingData, true);
            if (is_array($timings) && count($timings) > 5) {
                $variance = $this->calculateTimingVariance($timings);
                if ($variance < 0.1) { // Very consistent timing
                    $signals[] = 'consistent_timing';
                    $confidence += 20;
                }
            }
        }
        
        // Check for WebDriver property (from client-side detection)
        if ($this->getCookie('bcc_webdriver') === 'true') {
            $signals[] = 'webdriver_detected';
            $confidence += 25;
        }
        
        // Check for headless property
        if ($this->getCookie('bcc_headless') === 'true') {
            $signals[] = 'headless_detected';
            $confidence += 25;
        }
        
        // Check for no plugins
        $plugins = $this->getCookie('bcc_plugins');
        if ($plugins === '[]' || $plugins === '') {
            $signals[] = 'no_plugins';
            $confidence += 10;
        }
        
        // Check for missing fonts
        $fonts = $this->getCookie('bcc_fonts');
        if (empty($fonts) || $fonts === '[]') {
            $signals[] = 'no_fonts';
            $confidence += 15;
        }
        
        // Check for headless WebGL
        if ($this->getCookie('bcc_webgl_headless') === 'true') {
            $signals[] = 'headless_webgl';
            $confidence += 20;
        }
        
        // Check for no mouse movement
        if ($this->getCookie('bcc_mouse_moved') === 'false') {
            $signals[] = 'no_mouse_movement';
            $confidence += 15;
        }
        
        // Check for no scroll
        if ($this->getCookie('bcc_scrolled') === 'false') {
            $signals[] = 'no_scroll';
            $confidence += 10;
        }
        
        // Cloud/VPS IP detection (simplified)
        $ip = $this->getClientIp();
        if ($this->isDatacenterIp($ip)) {
            $signals[] = 'datacenter_ip';
            $confidence += 15;
        }
        
        // Determine if automated based on confidence threshold
        $isAutomated = $confidence >= 30;
        
        // Cap confidence at 100
        $confidence = min(100, $confidence);
        
        return [
            'is_automated' => $isAutomated,
            'confidence' => $confidence,
            'signals' => array_unique($signals)
        ];
    }
    
    /**
     * Store fingerprint for user
     * 
     * @param int $userId
     * @param string $fingerprint
     * @param array $automationData
     * @return int|false Insert ID or false on failure
     */
    public function storeFingerprint(int $userId, string $fingerprint, array $automationData = []) {
        global $wpdb;
        
        // Ensure table name is set
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        // Check if this fingerprint exists for other users
        $existingUsers = $wpdb->get_results($wpdb->prepare(
            "SELECT DISTINCT user_id FROM " . self::$table . " 
             WHERE fingerprint = %s AND user_id != %d",
            $fingerprint,
            $userId
        ));
        
        $multipleAccounts = !empty($existingUsers);
        
        // Determine risk level
        $riskLevel = 'low';
        if (isset($automationData['confidence'])) {
            if ($automationData['confidence'] >= 70) {
                $riskLevel = 'high';
            } elseif ($automationData['confidence'] >= 40) {
                $riskLevel = 'medium';
            }
        }
        if ($multipleAccounts && $riskLevel === 'low') {
            $riskLevel = 'medium';
        }
        
        // Check if fingerprint already exists for this user
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT id FROM " . self::$table . " 
             WHERE user_id = %d AND fingerprint = %s",
            $userId,
            $fingerprint
        ));
        
        $ip = $this->getClientIp();
        $ipBinary = ($ip && $ip !== '0.0.0.0') ? inet_pton($ip) : null;
        
        $data = [
            'user_id' => $userId,
            'fingerprint' => $fingerprint,
            'automation_score' => $automationData['confidence'] ?? 0,
            'automation_signals' => !empty($automationData['signals']) ? json_encode($automationData['signals']) : null,
            'last_seen' => current_time('mysql'),
            'ip_address' => $ipBinary,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'risk_level' => $riskLevel
        ];
        
        if ($existing) {
            // Update existing
            $wpdb->update(
                self::$table,
                $data,
                ['id' => $existing->id],
                ['%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s'],
                ['%d']
            );
            
            // If multiple accounts detected, log it
            if ($multipleAccounts && class_exists('\\BCCTrust\\Security\\AuditLogger')) {
                AuditLogger::log('device_sharing_detected', $userId, [
                    'fingerprint' => $fingerprint,
                    'other_users' => wp_list_pluck($existingUsers, 'user_id'),
                    'automation_score' => $automationData['confidence'] ?? 0
                ], 'user');
            }
            
            return $existing->id;
        } else {
            // Insert new
            $data['first_seen'] = current_time('mysql');
            
            $wpdb->insert(
                self::$table,
                $data,
                ['%d', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s']
            );
            
            $insertId = $wpdb->insert_id;
            
            // If multiple accounts detected, log it
            if ($multipleAccounts && class_exists('\\BCCTrust\\Security\\AuditLogger')) {
                AuditLogger::log('device_sharing_detected', $userId, [
                    'fingerprint' => $fingerprint,
                    'other_users' => wp_list_pluck($existingUsers, 'user_id'),
                    'automation_score' => $automationData['confidence'] ?? 0
                ], 'user');
            }
            
            return $insertId;
        }
    }
    
    /**
     * Get number of users associated with a fingerprint
     * 
     * @param string $fingerprint
     * @return int
     */
    public function getFingerprintUserCount(string $fingerprint): int {
        global $wpdb;
        
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT user_id) FROM " . self::$table . " 
             WHERE fingerprint = %s",
            $fingerprint
        ));
    }
    
    /**
     * Get all users sharing a fingerprint
     * 
     * @param string $fingerprint
     * @return array
     */
    public function getUsersByFingerprint(string $fingerprint): array {
        global $wpdb;
        
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT DISTINCT user_id, first_seen, last_seen, automation_score, risk_level
             FROM " . self::$table . " 
             WHERE fingerprint = %s
             ORDER BY last_seen DESC",
            $fingerprint
        ));
    }
    
    /**
     * Get all fingerprints for a user
     * 
     * @param int $userId
     * @return array
     */
    public function getUserFingerprints(int $userId): array {
        global $wpdb;
        
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM " . self::$table . " 
             WHERE user_id = %d
             ORDER BY last_seen DESC",
            $userId
        ));
    }
    
    /**
     * Calculate fraud probability based on device fingerprints
     * 
     * @param int $userId
     * @return float 0-1 probability
     */
    public function calculateDeviceFraudProbability(int $userId): float {
        $fingerprints = $this->getUserFingerprints($userId);
        
        if (empty($fingerprints)) {
            return 0.1; // Low risk - no fingerprint data yet
        }
        
        $scores = [];
        
        foreach ($fingerprints as $fp) {
            $score = 0;
            
            // Automation score contributes
            $score += $fp->automation_score / 100 * 0.4;
            
            // Risk level contributes
            if ($fp->risk_level === 'high') {
                $score += 0.3;
            } elseif ($fp->risk_level === 'medium') {
                $score += 0.15;
            }
            
            // Check if this fingerprint is shared
            $userCount = $this->getFingerprintUserCount($fp->fingerprint);
            if ($userCount > 1) {
                $score += min(0.3, ($userCount - 1) * 0.1);
            }
            
            $scores[] = $score;
        }
        
        // Take the highest score (most suspicious fingerprint)
        $maxScore = max($scores);
        
        // Weight by recency (newer fingerprints matter more)
        $recentFps = array_slice($fingerprints, 0, 3);
        $recentScores = [];
        foreach ($recentFps as $fp) {
            $recentScores[] = $fp->automation_score / 100;
        }
        $avgRecent = !empty($recentScores) ? array_sum($recentScores) / count($recentScores) : 0;
        
        // Combine: 70% max score, 30% recent average
        $finalScore = ($maxScore * 0.7) + ($avgRecent * 0.3);
        
        return min(1, max(0, $finalScore));
    }
    
    /**
     * Check if IP belongs to a datacenter (simplified)
     * 
     * @param string $ip
     * @return bool
     */
    private function isDatacenterIp(string $ip): bool {
        if ($ip === '0.0.0.0') return false;
        
        // Common datacenter IP ranges (simplified)
        $datacenterRanges = [
            'aws' => ['13.', '52.', '54.', '18.', '3.'],
            'google' => ['35.', '104.', '34.', '8.'],
            'azure' => ['40.', '20.', '13.', '52.'],
            'digitalocean' => ['159.', '165.', '138.', '143.'],
            'linode' => ['45.', '50.', '139.', '172.'],
            'vultr' => ['108.', '45.', '104.', '207.']
        ];
        
        foreach ($datacenterRanges as $provider => $ranges) {
            foreach ($ranges as $range) {
                if (strpos($ip, $range) === 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Calculate variance in request timings
     * 
     * @param array $timings
     * @return float
     */
    private function calculateTimingVariance(array $timings): float {
        if (count($timings) < 2) return 1;
        
        $intervals = [];
        for ($i = 1; $i < count($timings); $i++) {
            $intervals[] = $timings[$i] - $timings[$i - 1];
        }
        
        $mean = array_sum($intervals) / count($intervals);
        if ($mean == 0) return 0;
        
        $variance = 0;
        foreach ($intervals as $interval) {
            $variance += pow($interval - $mean, 2);
        }
        $variance /= count($intervals);
        
        $stdDev = sqrt($variance);
        
        // Coefficient of variation (normalized variance)
        return $stdDev / $mean;
    }
    
    /**
     * Get cookie value
     * 
     * @param string $name
     * @return string|null
     */
    private function getCookie(string $name): ?string {
        return isset($_COOKIE[$name]) ? sanitize_text_field($_COOKIE[$name]) : null;
    }
    
    /**
     * Get all HTTP headers
     * 
     * @return array
     */
    private function getAllHeaders(): array {
        $headers = [];
        
        if (function_exists('getallheaders')) {
            $headers = getallheaders();
        } else {
            // Fallback for nginx
            foreach ($_SERVER as $name => $value) {
                if (substr($name, 0, 5) == 'HTTP_') {
                    $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                    $headers[$name] = $value;
                }
            }
        }
        
        return $headers;
    }
    
    /**
     * Get client IP address with proxy support
     * 
     * @return string
     */
    private function getClientIp(): string {
        $ipHeaders = [
            'HTTP_CF_CONNECTING_IP', // CloudFlare
            'HTTP_X_FORWARDED_FOR',  // Proxy
            'HTTP_X_REAL_IP',         // Nginx
            'REMOTE_ADDR'             // Direct
        ];

        foreach ($ipHeaders as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // Handle X-Forwarded-For containing multiple IPs
                if ($header === 'HTTP_X_FORWARDED_FOR') {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
    
    /**
     * Clean up old fingerprint records - FIXED
     * 
     * @param int $days Keep records for this many days
     * @return int Number of deleted records
     */
    public static function cleanOldRecords(int $days = 90): int {
        global $wpdb;
        
        // Ensure table name is set
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        $cutoff = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        
        return $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM " . self::$table . " WHERE last_seen < %s",
                $cutoff
            )
        );
    }
    
    /**
     * Get statistics about fingerprints - FIXED
     * 
     * @return array
     */
    public static function getStats(): array {
        global $wpdb;
        
        // Ensure table name is set
        if (!self::$table) {
            self::$table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        }
        
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM " . self::$table);
        $uniqueUsers = (int) $wpdb->get_var("SELECT COUNT(DISTINCT user_id) FROM " . self::$table);
        $uniqueFingerprints = (int) $wpdb->get_var("SELECT COUNT(DISTINCT fingerprint) FROM " . self::$table);
        
        $automated = (int) $wpdb->get_var("SELECT COUNT(*) FROM " . self::$table . " WHERE automation_score > 50");
        $highRisk = (int) $wpdb->get_var("SELECT COUNT(*) FROM " . self::$table . " WHERE risk_level = 'high'");
        
        $sharedDevices = (int) $wpdb->get_var("
            SELECT COUNT(*) FROM (
                SELECT fingerprint, COUNT(DISTINCT user_id) as user_count
                FROM " . self::$table . "
                GROUP BY fingerprint
                HAVING user_count > 1
            ) as shared
        ");
        
        return [
            'total_records' => $total,
            'unique_users' => $uniqueUsers,
            'unique_fingerprints' => $uniqueFingerprints,
            'automated_detected' => $automated,
            'high_risk' => $highRisk,
            'shared_devices' => $sharedDevices,
            'sharing_ratio' => $uniqueUsers > 0 ? round($sharedDevices / $uniqueUsers * 100, 2) . '%' : '0%'
        ];
    }
}