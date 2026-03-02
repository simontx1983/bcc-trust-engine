<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) exit;

class MLFraudDetector {
    
    /**
     * Extract features for ML model
     */
    public function extractFeatures($userId) {
        $features = [];
        
        // Account features
        $features['account_age_days'] = $this->getAccountAge($userId);
        $features['has_avatar'] = $this->hasAvatar($userId) ? 1 : 0;
        $features['profile_completeness'] = $this->getProfileCompleteness($userId);
        $features['email_verified'] = (int) get_user_meta($userId, 'bcc_trust_email_verified', true);
        $features['posts_count'] = $this->countUserPosts($userId);
        $features['comments_count'] = $this->countUserComments($userId);
        
        // Voting features
        $features['total_votes_cast'] = (int) get_user_meta($userId, 'bcc_trust_votes_cast', true);
        $features['upvote_ratio'] = $this->getUpvoteRatio($userId);
        $features['avg_vote_weight'] = $this->getAvgVoteWeight($userId);
        $features['vote_time_variance'] = $this->getVoteTimeVariance($userId);
        $features['votes_per_session'] = $this->getVotesPerSession($userId);
        $features['vote_burstiness'] = $this->getVoteBurstiness($userId);
        
        // IP features
        $features['unique_ips_30d'] = $this->countUniqueIPs($userId, 30);
        $features['ip_country_changes'] = $this->countIPCountryChanges($userId);
        $features['uses_vpn'] = $this->detectVPN($userId) ? 1 : 0;
        $features['uses_proxy'] = $this->detectProxy($userId) ? 1 : 0;
        $features['ip_reputation'] = $this->getIPReputation($userId);
        
        // Device features
        $features['unique_devices'] = $this->countUniqueDevices($userId);
        $features['automation_score'] = $this->getAutomationScore($userId);
        $features['headless_detected'] = $this->wasHeadlessDetected($userId) ? 1 : 0;
        $features['screen_resolution_consistency'] = $this->getScreenConsistency($userId);
        
        // Behavioral features
        $features['active_hours_per_day'] = $this->getActiveHoursPerDay($userId);
        $features['session_length_avg'] = $this->getAvgSessionLength($userId);
        $features['night_activity_ratio'] = $this->getNightActivityRatio($userId);
        $features['weekend_activity_ratio'] = $this->getWeekendActivityRatio($userId);
        $features['action_interval_avg'] = $this->getAvgActionInterval($userId);
        $features['action_interval_std'] = $this->getActionIntervalStd($userId);
        
        // Social features
        $features['unique_page_owners'] = $this->countUniquePageOwners($userId);
        $features['mutual_voting_count'] = $this->countMutualVotes($userId);
        $features['in_vote_ring'] = $this->inVoteRing($userId) ? 1 : 0;
        $features['followers_count'] = $this->countFollowers($userId);
        $features['following_count'] = $this->countFollowing($userId);
        
        // Normalize features to 0-1 range where appropriate
        return $this->normalizeFeatures($features);
    }
    
    /**
     * Predict fraud probability using logistic regression
     * (Simplified - in production use a proper ML library)
     */
    public function predictFraudProbability($userId) {
        $features = $this->extractFeatures($userId);
        
        // Weighted scoring based on feature importance
        $weights = [
            'automation_score' => 0.15,
            'uses_vpn' => 0.10,
            'headless_detected' => 0.15,
            'vote_time_variance' => 0.08,
            'vote_burstiness' => 0.08,
            'unique_ips_30d' => 0.07,
            'in_vote_ring' => 0.12,
            'upvote_ratio' => 0.05,
            'night_activity_ratio' => 0.05,
            'session_length_avg' => 0.05,
            'account_age_days' => 0.03,
            'email_verified' => 0.03,
            'profile_completeness' => 0.02,
            'followers_count' => 0.02
        ];
        
        $score = 0;
        foreach ($weights as $feature => $weight) {
            $score += ($features[$feature] ?? 0) * $weight;
        }
        
        // Apply sigmoid function to get probability
        $probability = 1 / (1 + exp(-$score));
        
        return [
            'probability' => round($probability, 4),
            'risk_level' => $this->getRiskLevel($probability),
            'features' => $features,
            'timestamp' => time()
        ];
    }
    
    private function getRiskLevel($probability) {
        if ($probability < 0.3) return 'low';
        if ($probability < 0.6) return 'medium';
        if ($probability < 0.8) return 'high';
        return 'critical';
    }
    
    // Feature extraction helper methods
    private function getAccountAge($userId) {
        $user = get_userdata($userId);
        if (!$user) return 0;
        
        $registered = strtotime($user->user_registered);
        $age = (time() - $registered) / (24 * 3600);
        return min(365, $age) / 365; // Normalize to 0-1 (max 1 year)
    }
    
    private function hasAvatar($userId) {
        return (bool) get_user_meta($userId, 'peepso_avatar_image', true);
    }
    
    private function getProfileCompleteness($userId) {
        $fields = ['first_name', 'last_name', 'description', 'peepso_avatar_image', 'peepso_cover_image'];
        $filled = 0;
        foreach ($fields as $field) {
            if (get_user_meta($userId, $field, true)) $filled++;
        }
        return $filled / count($fields);
    }
    
    private function countUserPosts($userId) {
        return count_user_posts($userId);
    }
    
    private function countUserComments($userId) {
        global $wpdb;
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->comments} WHERE user_id = %d",
            $userId
        ));
    }
    
    private function getUpvoteRatio($userId) {
        global $wpdb;
        $votesTable = bcc_trust_votes_table();
        
        $upvotes = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$votesTable} WHERE voter_user_id = %d AND vote_type > 0 AND status = 1",
            $userId
        ));
        
        $total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$votesTable} WHERE voter_user_id = %d AND status = 1",
            $userId
        ));
        
        return $total > 0 ? $upvotes / $total : 0.5;
    }
    
    private function getAvgVoteWeight($userId) {
        global $wpdb;
        $votesTable = bcc_trust_votes_table();
        
        $avg = $wpdb->get_var($wpdb->prepare(
            "SELECT AVG(weight) FROM {$votesTable} WHERE voter_user_id = %d AND status = 1",
            $userId
        ));
        
        return $avg ?: 0;
    }
    
    private function getVoteTimeVariance($userId) {
        global $wpdb;
        $votesTable = bcc_trust_votes_table();
        
        $timestamps = $wpdb->get_col($wpdb->prepare(
            "SELECT UNIX_TIMESTAMP(created_at) FROM {$votesTable}
             WHERE voter_user_id = %d AND status = 1
             ORDER BY created_at DESC
             LIMIT 50",
            $userId
        ));
        
        if (count($timestamps) < 5) return 0;
        
        $intervals = [];
        for ($i = 0; $i < count($timestamps) - 1; $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i + 1];
        }
        
        $avg = array_sum($intervals) / count($intervals);
        $variance = array_sum(array_map(function($val) use ($avg) {
            return pow($val - $avg, 2);
        }, $intervals)) / count($intervals);
        
        // Normalize to 0-1 (assuming max reasonable variance of 3600 seconds)
        return min(1, sqrt($variance) / 3600);
    }
    
    private function getVotesPerSession($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        // Group actions by day and count votes
        $votesPerDay = $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(created_at) as day, COUNT(*) as vote_count
             FROM {$auditTable}
             WHERE user_id = %d AND action LIKE 'vote_%'
             GROUP BY DATE(created_at)
             HAVING vote_count > 0",
            $userId
        ));
        
        if (empty($votesPerDay)) return 0;
        
        $avgVotes = array_sum(array_column($votesPerDay, 'vote_count')) / count($votesPerDay);
        return min(1, $avgVotes / 50); // Normalize, 50 votes/day is very high
    }
    
    private function getVoteBurstiness($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        // Count votes per hour for last 7 days
        $hourlyVotes = $wpdb->get_results($wpdb->prepare(
            "SELECT HOUR(created_at) as hour, COUNT(*) as vote_count
             FROM {$auditTable}
             WHERE user_id = %d AND action LIKE 'vote_%'
               AND created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
             GROUP BY HOUR(created_at)",
            $userId
        ));
        
        if (empty($hourlyVotes)) return 0;
        
        $counts = array_column($hourlyVotes, 'vote_count');
        $max = max($counts);
        $avg = array_sum($counts) / count($counts);
        
        // Burstiness = max/avg, normalized
        $burstiness = $max / $avg;
        return min(1, ($burstiness - 1) / 9); // Normalize, 10x is max
    }
    
    private function countUniqueIPs($userId, $days) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip_address) FROM {$auditTable}
             WHERE user_id = %d AND created_at > DATE_SUB(NOW(), INTERVAL %d DAY)",
            $userId,
            $days
        ));
    }
    
    private function countIPCountryChanges($userId) {
        // Requires IP geolocation database
        // Simplified - assume country is first octet of IP
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $countries = $wpdb->get_col($wpdb->prepare(
            "SELECT DISTINCT SUBSTRING_INDEX(INET_NTOA(ip_address), '.', 1) as country_code
             FROM {$auditTable}
             WHERE user_id = %d AND ip_address IS NOT NULL
             ORDER BY created_at DESC
             LIMIT 100",
            $userId
        ));
        
        return count($countries);
    }
    
    private function detectVPN($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        // Check if IPs are known VPN ranges
        // This would require a VPN IP database
        // Simplified: check ASN from IP (would need external service)
        return 0; // Placeholder
    }
    
    private function detectProxy($userId) {
        return 0; // Placeholder for proxy detection
    }
    
    private function getIPReputation($userId) {
        // Would check IP against threat intelligence feeds
        return 0.5; // Placeholder
    }
    
    private function countUniqueDevices($userId) {
        global $wpdb;
        $fingerprintTable = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT fingerprint) FROM {$fingerprintTable} WHERE user_id = %d",
            $userId
        ));
    }
    
    private function getAutomationScore($userId) {
        global $wpdb;
        $fingerprintTable = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        
        $score = $wpdb->get_var($wpdb->prepare(
            "SELECT automation_score FROM {$fingerprintTable} WHERE user_id = %d ORDER BY last_seen DESC LIMIT 1",
            $userId
        ));
        
        return ($score ?: 0) / 100;
    }
    
    private function wasHeadlessDetected($userId) {
        global $wpdb;
        $fingerprintTable = $wpdb->prefix . 'bcc_trust_device_fingerprints';
        
        $signals = $wpdb->get_var($wpdb->prepare(
            "SELECT automation_signals FROM {$fingerprintTable} WHERE user_id = %d ORDER BY last_seen DESC LIMIT 1",
            $userId
        ));
        
        if (!$signals) return false;
        
        $signals = json_decode($signals, true);
        return in_array('headless', $signals) || in_array('webdriver', $signals);
    }
    
    private function getScreenConsistency($userId) {
        // Check if screen resolution changes (unusual for same user)
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $resolutions = $wpdb->get_col($wpdb->prepare(
            "SELECT SUBSTRING_INDEX(metadata, 'resolution:', -1)
             FROM {$auditTable}
             WHERE user_id = %d AND metadata LIKE '%resolution%'
             LIMIT 20",
            $userId
        ));
        
        if (count($resolutions) < 2) return 1;
        
        $unique = count(array_unique($resolutions));
        return 1 - (($unique - 1) / count($resolutions));
    }
    
    private function getActiveHoursPerDay($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $hoursPerDay = $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(created_at) as day, COUNT(DISTINCT HOUR(created_at)) as hours
             FROM {$auditTable}
             WHERE user_id = %d
             GROUP BY DATE(created_at)
             HAVING hours > 0",
            $userId
        ));
        
        if (empty($hoursPerDay)) return 0;
        
        $avgHours = array_sum(array_column($hoursPerDay, 'hours')) / count($hoursPerDay);
        return min(1, $avgHours / 12); // Normalize, 12 hours/day is high
    }
    
    private function getAvgSessionLength($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        // Simplified - group by day as sessions
        $sessionLengths = $wpdb->get_results($wpdb->prepare(
            "SELECT DATE(created_at) as day,
                    MIN(created_at) as first,
                    MAX(created_at) as last
             FROM {$auditTable}
             WHERE user_id = %d
             GROUP BY DATE(created_at)
             HAVING COUNT(*) > 1",
            $userId
        ));
        
        if (empty($sessionLengths)) return 0;
        
        $lengths = [];
        foreach ($sessionLengths as $session) {
            $lengths[] = (strtotime($session->last) - strtotime($session->first)) / 3600; // hours
        }
        
        $avgLength = array_sum($lengths) / count($lengths);
        return min(1, $avgLength / 4); // Normalize, 4 hours is high
    }
    
    private function getNightActivityRatio($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$auditTable} WHERE user_id = %d",
            $userId
        ));
        
        if ($total < 10) return 0;
        
        $night = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$auditTable}
             WHERE user_id = %d AND HOUR(created_at) BETWEEN 0 AND 5",
            $userId
        ));
        
        return $night / $total;
    }
    
    private function getWeekendActivityRatio($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$auditTable} WHERE user_id = %d",
            $userId
        ));
        
        if ($total < 10) return 0;
        
        $weekend = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$auditTable}
             WHERE user_id = %d AND DAYOFWEEK(created_at) IN (1,7)",
            $userId
        ));
        
        $ratio = $weekend / $total;
        $expectedRatio = 2/7; // ~0.285
        
        // Return deviation from expected (normalized)
        return abs($ratio - $expectedRatio) / $expectedRatio;
    }
    
    private function getAvgActionInterval($userId) {
        global $wpdb;
        $auditTable = bcc_trust_activity_table();
        
        $timestamps = $wpdb->get_col($wpdb->prepare(
            "SELECT UNIX_TIMESTAMP(created_at) FROM {$auditTable}
             WHERE user_id = %d
             ORDER BY created_at DESC
             LIMIT 50",
            $userId
        ));
        
        if (count($timestamps) < 5) return 0;
        
        $intervals = [];
        for ($i = 0; $i < count($timestamps) - 1; $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i + 1];
        }
        
        $avg = array_sum($intervals) / count($intervals);
        return min(1, $avg / 3600); // Normalize, 1 hour is max
    }
    
    private function getActionIntervalStd($userId) {
        global $wpdb;
        
        $timestamps = $wpdb->get_col($wpdb->prepare(
            "SELECT UNIX_TIMESTAMP(created_at) FROM {$auditTable}
             WHERE user_id = %d
             ORDER BY created_at DESC
             LIMIT 50",
            $userId
        ));
        
        if (count($timestamps) < 5) return 0;
        
        $intervals = [];
        for ($i = 0; $i < count($timestamps) - 1; $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i + 1];
        }
        
        $avg = array_sum($intervals) / count($intervals);
        $variance = array_sum(array_map(function($val) use ($avg) {
            return pow($val - $avg, 2);
        }, $intervals)) / count($intervals);
        
        $std = sqrt($variance);
        return min(1, $std / 1800); // Normalize, 30 min std dev is high
    }
    
    private function countUniquePageOwners($userId) {
        global $wpdb;
        $votesTable = bcc_trust_votes_table();
        $scoresTable = bcc_trust_scores_table();
        
        $owners = $wpdb->get_col($wpdb->prepare(
            "SELECT DISTINCT s.page_owner_id
             FROM {$votesTable} v
             JOIN {$scoresTable} s ON v.page_id = s.page_id
             WHERE v.voter_user_id = %d AND v.status = 1",
            $userId
        ));
        
        return count($owners);
    }
    
    private function countMutualVotes($userId) {
        global $wpdb;
        $votesTable = bcc_trust_votes_table();
        $scoresTable = bcc_trust_scores_table();
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT v1.page_id)
             FROM {$votesTable} v1
             JOIN {$scoresTable} s1 ON v1.page_id = s1.page_id
             JOIN {$votesTable} v2 ON v2.voter_user_id = s1.page_owner_id
             JOIN {$scoresTable} s2 ON v2.page_id = s2.page_id
             WHERE v1.voter_user_id = %d
               AND v2.voter_user_id = s1.page_owner_id
               AND s2.page_owner_id = %d
               AND v1.status = 1
               AND v2.status = 1",
            $userId,
            $userId
        ));
    }
    
    private function inVoteRing($userId) {
        $graph = new TrustGraph();
        $rings = $graph->detectVoteRings();
        
        foreach ($rings as $ring) {
            if (in_array($userId, $ring)) return true;
        }
        return false;
    }
    
    private function countFollowers($userId) {
        // PeepSo specific
        if (function_exists('PeepSoUser')) {
            $peepsoUser = PeepSoUser::get_instance($userId);
            return $peepsoUser->get_followers_count();
        }
        return 0;
    }
    
    private function countFollowing($userId) {
        if (function_exists('PeepSoUser')) {
            $peepsoUser = PeepSoUser::get_instance($userId);
            return $peepsoUser->get_following_count();
        }
        return 0;
    }
    
    private function normalizeFeatures($features) {
        // Ensure all features are in 0-1 range
        foreach ($features as $key => $value) {
            if (is_numeric($value)) {
                $features[$key] = min(1, max(0, (float) $value));
            }
        }
        return $features;
    }
}