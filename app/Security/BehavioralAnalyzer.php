<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) exit;

/**
 * Behavioral Analyzer
 * 
 * Analyzes user behavior patterns to detect bots, fraudsters, and suspicious activity
 * 
 * @package BCCTrust
 * @subpackage Security
 * @version 1.0.0
 */
class BehavioralAnalyzer {
    
    /**
     * Database tables
     */
    private string $votesTable;
    private string $activityTable;
    private string $patternsTable;
    private string $scoresTable; // ADDED: Missing property
    
    /**
     * Cache settings
     */
    const CACHE_GROUP = 'bcc_behavior';
    const CACHE_TTL = 3600; // 1 hour
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->votesTable = $wpdb->prefix . 'bcc_trust_votes';
        $this->activityTable = $wpdb->prefix . 'bcc_trust_activity';
        $this->patternsTable = $wpdb->prefix . 'bcc_trust_patterns';
        $this->scoresTable = $wpdb->prefix . 'bcc_trust_page_scores'; // ADDED: Initialize scores table
    }
    
    /**
     * Get risk level based on score - ADDED: Missing method
     */
    private function getRiskLevel(int $score): string {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        if ($score >= 20) return 'low';
        return 'minimal';
    }
    
    /**
     * Analyze user behavior and return risk score and flags
     * 
     * @param int $userId
     * @return array Behavior analysis results
     */
    public function analyzeUserBehavior(int $userId): array {
        // Check cache first
        $cached = wp_cache_get('behavior_' . $userId, self::CACHE_GROUP);
        if ($cached !== false) {
            return $cached;
        }
        
        $patterns = [
            'voting_pattern' => $this->analyzeVotingPattern($userId),
            'temporal_pattern' => $this->analyzeTemporalPattern($userId),
            'engagement_pattern' => $this->analyzeEngagementPattern($userId),
            'social_pattern' => $this->analyzeSocialPattern($userId),
            'browsing_pattern' => $this->analyzeBrowsingPattern($userId),
            'content_pattern' => $this->analyzeContentPattern($userId),
            'consistency_pattern' => $this->analyzeConsistencyPattern($userId)
        ];
        
        $score = 0;
        $flags = [];
        $details = [];
        
        foreach ($patterns as $pattern => $result) {
            if ($result['suspicious']) {
                $score += $result['weight'];
                $flags = array_merge($flags, $result['reasons'] ?? []);
            }
            $details[$pattern] = $result;
        }
        
        // Cap score at 100
        $score = min(100, $score);
        
        // Determine risk level - NOW USING THE ADDED METHOD
        $riskLevel = $this->getRiskLevel($score);
        
        // Store pattern for ML training if high risk
        if ($score > 50) {
            $this->storePattern($userId, 'suspicious_behavior', [
                'score' => $score,
                'flags' => $flags,
                'patterns' => $details
            ], $score / 100);
        }
        
        $result = [
            'behavior_score' => $score,
            'risk_level' => $riskLevel,
            'flags' => array_unique($flags),
            'details' => $details,
            'analyzed_at' => time()
        ];
        
        // Cache for 1 hour
        wp_cache_set('behavior_' . $userId, $result, self::CACHE_GROUP, self::CACHE_TTL);
        
        return $result;
    }
    
    /**
     * Analyze voting pattern for bot-like behavior
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeVotingPattern(int $userId): array {
        global $wpdb;
        
        // Get last 100 votes
        $votes = $wpdb->get_results($wpdb->prepare(
            "SELECT vote_type, created_at, page_id, weight 
             FROM {$this->votesTable}
             WHERE voter_user_id = %d AND status = 1
             ORDER BY created_at DESC
             LIMIT 100",
            $userId
        ));
        
        if (count($votes) < 5) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => [],
                'data_points' => count($votes)
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        // ======================================================
        // 1. Check vote type distribution
        // ======================================================
        $upvotes = 0;
        $downvotes = 0;
        foreach ($votes as $vote) {
            if ($vote->vote_type > 0) $upvotes++;
            else $downvotes++;
        }
        
        $totalVotes = count($votes);
        $upvoteRatio = $upvotes / $totalVotes;
        $metrics['upvote_ratio'] = $upvoteRatio;
        
        // Extreme voting patterns (all upvotes or all downvotes)
        if ($upvoteRatio > 0.98) {
            $suspicious = true;
            $weight += 25;
            $reasons[] = 'extreme_upvoting';
            $metrics['extreme'] = 'up';
        } elseif ($upvoteRatio < 0.02) {
            $suspicious = true;
            $weight += 25;
            $reasons[] = 'extreme_downvoting';
            $metrics['extreme'] = 'down';
        }
        
        // ======================================================
        // 2. Check timing regularity (bots vote at consistent intervals)
        // ======================================================
        $timestamps = array_map(function($v) {
            return strtotime($v->created_at);
        }, $votes);
        
        $intervals = [];
        for ($i = 0; $i < count($timestamps) - 1; $i++) {
            $intervals[] = $timestamps[$i] - $timestamps[$i + 1];
        }
        
        if (!empty($intervals)) {
            $avgInterval = array_sum($intervals) / count($intervals);
            $variance = $this->calculateVariance($intervals);
            $metrics['avg_interval'] = $avgInterval;
            $metrics['interval_variance'] = $variance;
            
            // Very regular intervals (low variance) indicate bot
            if ($variance < 5 && $avgInterval < 300) { // Less than 5 sec variance, under 5 min avg
                $suspicious = true;
                $weight += 30;
                $reasons[] = 'regular_timing';
            }
            
            // Extremely fast voting (under 2 seconds between votes)
            if ($avgInterval < 2) {
                $suspicious = true;
                $weight += 35;
                $reasons[] = 'rapid_fire_voting';
            }
        }
        
        // ======================================================
        // 3. Check for burst patterns (many votes in short time)
        // ======================================================
        $burstThreshold = 5; // votes in 1 minute
        $bursts = 0;
        for ($i = 0; $i < count($timestamps) - $burstThreshold; $i++) {
            if (($timestamps[$i] - $timestamps[$i + $burstThreshold - 1]) < 60) {
                $bursts++;
            }
        }
        
        $metrics['burst_count'] = $bursts;
        if ($bursts > 3) {
            $suspicious = true;
            $weight += 20;
            $reasons[] = 'voting_bursts';
        }
        
        // ======================================================
        // 4. Check for consistent vote weight (all votes same weight)
        // ======================================================
        $weights = array_column($votes, 'weight');
        $uniqueWeights = count(array_unique($weights));
        $metrics['unique_weights'] = $uniqueWeights;
        
        if ($uniqueWeights === 1 && count($weights) > 10) {
            // All votes have exactly the same weight - suspicious
            $suspicious = true;
            $weight += 15;
            $reasons[] = 'uniform_weights';
        }
        
        // ======================================================
        // 5. Check for vote churn (changing votes frequently)
        // ======================================================
        $voteChanges = 0;
        $lastVoteType = null;
        foreach ($votes as $vote) {
            if ($lastVoteType !== null && $vote->vote_type != $lastVoteType) {
                $voteChanges++;
            }
            $lastVoteType = $vote->vote_type;
        }
        
        $metrics['vote_changes'] = $voteChanges;
        if ($voteChanges > $totalVotes * 0.3) { // Changed more than 30% of the time
            $suspicious = true;
            $weight += 15;
            $reasons[] = 'frequent_vote_changes';
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Analyze temporal patterns (time of day, day of week)
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeTemporalPattern(int $userId): array {
        global $wpdb;
        
        // Get activity for last 30 days
        $activities = $wpdb->get_results($wpdb->prepare(
            "SELECT 
                HOUR(created_at) as hour,
                DAYOFWEEK(created_at) as day_of_week,
                COUNT(*) as count,
                DATE(created_at) as date
             FROM {$this->activityTable}
             WHERE user_id = %d
               AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
             GROUP BY DATE(created_at), HOUR(created_at), DAYOFWEEK(created_at)
             ORDER BY created_at DESC",
            $userId
        ));
        
        if (count($activities) < 10) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => [],
                'data_points' => count($activities)
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        // ======================================================
        // 1. Check hourly distribution
        // ======================================================
        $hourlyDistribution = array_fill(0, 24, 0);
        foreach ($activities as $act) {
            $hourlyDistribution[(int)$act->hour] += $act->count;
        }
        
        $total = array_sum($hourlyDistribution);
        $metrics['hourly_distribution'] = $hourlyDistribution;
        
        // Get user's timezone from meta
        $userTimezone = get_user_meta($userId, 'bcc_timezone', true);
        if (!$userTimezone) {
            $userTimezone = 'UTC';
        }
        
        // Calculate sleeping hours (12 AM - 6 AM in user's timezone)
        $sleepingHours = $this->getSleepingHours($userTimezone);
        $sleepActivity = 0;
        
        foreach ($sleepingHours as $hour) {
            $sleepActivity += $hourlyDistribution[$hour] ?? 0;
        }
        
        $sleepRatio = $sleepActivity / max(1, $total);
        $metrics['sleep_ratio'] = $sleepRatio;
        
        // High activity during sleeping hours is suspicious
        if ($sleepRatio > 0.3) { // More than 30% activity during sleep
            $suspicious = true;
            $weight += 25;
            $reasons[] = 'night_owl_activity';
        }
        
        // ======================================================
        // 2. Check for uniform hourly distribution (bots run 24/7)
        // ======================================================
        $activeHours = array_filter($hourlyDistribution, function($count) {
            return $count > 0;
        });
        
        $metrics['active_hours'] = count($activeHours);
        
        if (count($activeHours) > 20) { // Active in more than 20 hours
            $hourlyVariance = $this->calculateVariance(array_values($hourlyDistribution));
            $metrics['hourly_variance'] = $hourlyVariance;
            
            if ($hourlyVariance < 2) { // Very even distribution
                $suspicious = true;
                $weight += 20;
                $reasons[] = 'uniform_hourly_pattern';
            }
        }
        
        // ======================================================
        // 3. Check weekend vs weekday ratio
        // ======================================================
        $weekdayCount = 0;
        $weekendCount = 0;
        
        foreach ($activities as $act) {
            if ($act->day_of_week == 1 || $act->day_of_week == 7) { // 1=Sunday, 7=Saturday
                $weekendCount += $act->count;
            } else {
                $weekdayCount += $act->count;
            }
        }
        
        $totalWeekend = $weekendCount;
        $totalWeekday = $weekdayCount;
        
        // Expected ratio: weekend = 2/7 of total (~28.6%)
        $expectedWeekendRatio = 2/7;
        $actualWeekendRatio = $totalWeekend / max(1, $totalWeekend + $totalWeekday);
        
        $metrics['weekend_ratio'] = $actualWeekendRatio;
        $metrics['expected_weekend_ratio'] = $expectedWeekendRatio;
        
        // If activity is exactly the same every day (bots)
        $weekendDeviation = abs($actualWeekendRatio - $expectedWeekendRatio);
        if ($weekendDeviation < 0.05) { // Within 5% of expected - too perfect
            $suspicious = true;
            $weight += 15;
            $reasons[] = 'perfect_weekly_pattern';
        }
        
        // ======================================================
        // 4. Check for consistent daily activity (same time every day)
        // ======================================================
        $dailyPattern = [];
        foreach ($activities as $act) {
            $key = $act->date . '_' . $act->hour;
            $dailyPattern[$key] = $act->count;
        }
        
        // Look for identical patterns across days
        $patternHashes = [];
        foreach ($activities as $act) {
            $day = $act->date;
            $hourPattern = [];
            for ($h = 0; $h < 24; $h++) {
                $hourPattern[] = $hourlyDistribution[$h] ?? 0;
            }
            $patternHashes[$day] = md5(implode(',', $hourPattern));
        }
        
        $uniquePatterns = count(array_unique($patternHashes));
        $metrics['unique_daily_patterns'] = $uniquePatterns;
        
        if ($uniquePatterns === 1 && count($patternHashes) > 5) {
            // Exactly the same pattern every day - bot
            $suspicious = true;
            $weight += 30;
            $reasons[] = 'identical_daily_patterns';
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Analyze engagement pattern (session length, actions per session)
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeEngagementPattern(int $userId): array {
        global $wpdb;
        
        // Get session data (group actions within 30 minutes as same session)
        $actions = $wpdb->get_results($wpdb->prepare(
            "SELECT created_at, action
             FROM {$this->activityTable}
             WHERE user_id = %d
               AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
             ORDER BY created_at ASC",
            $userId
        ));
        
        if (count($actions) < 10) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => [],
                'data_points' => count($actions)
            ];
        }
        
        // Group into sessions (30 min gap threshold)
        $sessions = [];
        $currentSession = [];
        $lastTime = null;
        
        foreach ($actions as $action) {
            $time = strtotime($action->created_at);
            
            if ($lastTime === null || ($time - $lastTime) > 1800) { // 30 min gap
                if (!empty($currentSession)) {
                    $sessions[] = $currentSession;
                }
                $currentSession = [];
            }
            
            $currentSession[] = $action;
            $lastTime = $time;
        }
        
        if (!empty($currentSession)) {
            $sessions[] = $currentSession;
        }
        
        if (empty($sessions)) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => []
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        // ======================================================
        // 1. Analyze session lengths
        // ======================================================
        $sessionLengths = [];
        $actionsPerSession = [];
        
        foreach ($sessions as $session) {
            if (count($session) < 2) continue;
            
            $first = strtotime($session[0]->created_at);
            $last = strtotime($session[count($session)-1]->created_at);
            $length = $last - $first;
            
            $sessionLengths[] = $length;
            $actionsPerSession[] = count($session);
        }
        
        if (!empty($sessionLengths)) {
            $avgSessionLength = array_sum($sessionLengths) / count($sessionLengths);
            $avgActionsPerSession = array_sum($actionsPerSession) / count($actionsPerSession);
            
            $metrics['avg_session_length'] = $avgSessionLength;
            $metrics['avg_actions_per_session'] = $avgActionsPerSession;
            
            // Extremely short sessions (under 10 seconds)
            if ($avgSessionLength < 10 && $avgActionsPerSession > 5) {
                $suspicious = true;
                $weight += 30;
                $reasons[] = 'ultra_fast_sessions';
            }
            
            // No variance in session length
            $lengthVariance = $this->calculateVariance($sessionLengths);
            $metrics['session_length_variance'] = $lengthVariance;
            
            if ($lengthVariance < 2 && count($sessionLengths) > 5) {
                $suspicious = true;
                $weight += 20;
                $reasons[] = 'uniform_session_lengths';
            }
        }
        
        // ======================================================
        // 2. Check action rate (actions per minute)
        // ======================================================
        $actionRates = [];
        foreach ($sessions as $session) {
            if (count($session) < 3) continue;
            
            $first = strtotime($session[0]->created_at);
            $last = strtotime($session[count($session)-1]->created_at);
            $duration = max(1, ($last - $first) / 60); // minutes
            
            $rate = count($session) / $duration;
            $actionRates[] = $rate;
        }
        
        if (!empty($actionRates)) {
            $avgActionRate = array_sum($actionRates) / count($actionRates);
            $metrics['avg_action_rate'] = $avgActionRate;
            
            // Extremely high action rate (over 30 actions per minute)
            if ($avgActionRate > 30) {
                $suspicious = true;
                $weight += 25;
                $reasons[] = 'superhuman_action_rate';
            }
        }
        
        // ======================================================
        // 3. Check for consistent time between actions
        // ======================================================
        $allIntervals = [];
        for ($i = 0; $i < count($actions) - 1; $i++) {
            $interval = strtotime($actions[$i+1]->created_at) - strtotime($actions[$i]->created_at);
            if ($interval < 3600) { // Less than 1 hour
                $allIntervals[] = $interval;
            }
        }
        
        if (!empty($allIntervals)) {
            $intervalVariance = $this->calculateVariance($allIntervals);
            $metrics['action_interval_variance'] = $intervalVariance;
            
            if ($intervalVariance < 1 && count($allIntervals) > 20) {
                $suspicious = true;
                $weight += 25;
                $reasons[] = 'metronome_timing';
            }
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Analyze social pattern (who they interact with)
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeSocialPattern(int $userId): array {
        global $wpdb;
        
        // Get pages this user votes on - FIXED: Now using $this->scoresTable
        $votedPages = $wpdb->get_results($wpdb->prepare(
            "SELECT DISTINCT v.page_id, s.page_owner_id
             FROM {$this->votesTable} v
             JOIN {$this->scoresTable} s ON v.page_id = s.page_id
             WHERE v.voter_user_id = %d AND v.status = 1
             LIMIT 500",
            $userId
        ));
        
        if (count($votedPages) < 5) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => [],
                'data_points' => count($votedPages)
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        // ======================================================
        // 1. Check diversity of page owners
        // ======================================================
        $ownerIds = array_column($votedPages, 'page_owner_id');
        $uniqueOwners = count(array_unique($ownerIds));
        $metrics['unique_owners'] = $uniqueOwners;
        
        // If voting on many pages by same owner
        $ownerDistribution = array_count_values($ownerIds);
        $maxForOwner = max($ownerDistribution);
        $metrics['max_votes_same_owner'] = $maxForOwner;
        
        if ($maxForOwner > 10 && $uniqueOwners < 3) {
            // Voting mostly for one person's pages
            $suspicious = true;
            $weight += 35;
            $reasons[] = 'single_owner_focus';
        }
        
        // ======================================================
        // 2. Check for reciprocal voting (vote rings)
        // ======================================================
        $mutualVotes = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*)
            FROM {$this->votesTable} v1
            JOIN {$this->scoresTable} s1 ON v1.page_id = s1.page_id
            JOIN {$this->votesTable} v2 ON v2.voter_user_id = s1.page_owner_id
            JOIN {$this->scoresTable} s2 ON v2.page_id = s2.page_id
            WHERE v1.voter_user_id = %d
              AND v2.voter_user_id = s1.page_owner_id
              AND s2.page_owner_id = %d
              AND v1.status = 1
              AND v2.status = 1
        ", $userId, $userId));
        
        $metrics['mutual_votes'] = (int) $mutualVotes;
        
        if ($mutualVotes > 3) {
            $suspicious = true;
            $weight += 30;
            $reasons[] = 'reciprocal_voting';
        }
        
        // ======================================================
        // 3. Check if they only vote for high-reputation users
        // ======================================================
        if (!empty($votedPages)) {
            $pageIds = array_column($votedPages, 'page_id');
            $placeholders = implode(',', array_fill(0, count($pageIds), '%d'));
            
            $pageScores = $wpdb->get_col($wpdb->prepare(
                "SELECT total_score FROM {$this->scoresTable}
                 WHERE page_id IN ({$placeholders})",
                $pageIds
            ));
            
            if (!empty($pageScores)) {
                $avgScore = array_sum($pageScores) / count($pageScores);
                $metrics['avg_page_score_voted'] = $avgScore;
                
                // If they only vote for very high or very low pages
                if ($avgScore > 90 || $avgScore < 10) {
                    $suspicious = true;
                    $weight += 15;
                    $reasons[] = 'extreme_page_focus';
                }
            }
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Analyze browsing pattern (page views before voting)
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeBrowsingPattern(int $userId): array {
        global $wpdb;
        
        // Get page views and votes sequence
        $actions = $wpdb->get_results($wpdb->prepare(
            "SELECT action, target_id, created_at
             FROM {$this->activityTable}
             WHERE user_id = %d
               AND action IN ('page_view', 'vote_up', 'vote_down', 'page_visit')
               AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
             ORDER BY created_at DESC
             LIMIT 200",
            $userId
        ));
        
        if (count($actions) < 10) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => [],
                'data_points' => count($actions)
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        // Check if votes happen without preceding page views
        $votesWithoutViews = 0;
        $totalVotes = 0;
        
        for ($i = 0; $i < count($actions); $i++) {
            if (strpos($actions[$i]->action, 'vote') === 0) {
                $totalVotes++;
                $foundView = false;
                
                // Look for page view of same page in previous 5 minutes
                for ($j = $i + 1; $j < min($i + 20, count($actions)); $j++) {
                    if (($actions[$j]->action === 'page_view' || $actions[$j]->action === 'page_visit') && 
                        $actions[$j]->target_id == $actions[$i]->target_id) {
                        $timeDiff = strtotime($actions[$i]->created_at) - strtotime($actions[$j]->created_at);
                        if ($timeDiff < 300) { // Within 5 minutes
                            $foundView = true;
                            break;
                        }
                    }
                }
                
                if (!$foundView) {
                    $votesWithoutViews++;
                }
            }
        }
        
        $metrics['total_votes'] = $totalVotes;
        $metrics['votes_without_views'] = $votesWithoutViews;
        
        if ($totalVotes > 0) {
            $voteWithoutViewRatio = $votesWithoutViews / $totalVotes;
            $metrics['vote_without_view_ratio'] = $voteWithoutViewRatio;
            
            if ($voteWithoutViewRatio > 0.7) { // Over 70% votes without prior view
                $suspicious = true;
                $weight += 40;
                $reasons[] = 'blind_voting';
            } elseif ($voteWithoutViewRatio > 0.3) {
                $weight += 15;
                $reasons[] = 'frequent_blind_voting';
            }
        }
        
        // Check for extremely fast voting after page view
        $fastVotes = 0;
        for ($i = 0; $i < count($actions); $i++) {
            if ($actions[$i]->action === 'page_view' || $actions[$i]->action === 'page_visit') {
                for ($j = $i - 1; $j >= max(0, $i - 5); $j--) {
                    if (strpos($actions[$j]->action, 'vote') === 0 && 
                        $actions[$j]->target_id == $actions[$i]->target_id) {
                        $timeDiff = strtotime($actions[$j]->created_at) - strtotime($actions[$i]->created_at);
                        if ($timeDiff < 2) { // Less than 2 seconds to vote after viewing
                            $fastVotes++;
                        }
                        break;
                    }
                }
            }
        }
        
        $metrics['fast_votes'] = $fastVotes;
        
        if ($fastVotes > 5) {
            $suspicious = true;
            $weight += 25;
            $reasons[] = 'instant_voting';
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Analyze content creation pattern
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeContentPattern(int $userId): array {
        // This would integrate with PeepSo to check:
        // - Do they create content? (pages, posts, comments)
        // - Is their content meaningful?
        // - Do they engage in discussions?
        
        // For now, use existing data
        $hasPages = count_user_posts($userId) > 0;
        $hasComments = $this->countUserComments($userId) > 0;
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        
        // Users who only vote but never create content are suspicious
        $voteCount = (int) get_user_meta($userId, 'bcc_trust_votes_cast', true);
        
        if ($voteCount > 20 && !$hasPages && !$hasComments) {
            $suspicious = true;
            $weight += 30;
            $reasons[] = 'voter_only_no_content';
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => [
                'has_pages' => $hasPages,
                'has_comments' => $hasComments,
                'vote_count' => $voteCount
            ]
        ];
    }
    
    /**
     * Analyze consistency of behavior over time
     * 
     * @param int $userId
     * @return array
     */
    private function analyzeConsistencyPattern(int $userId): array {
        global $wpdb;
        
        // Get weekly activity for last 3 months
        $weeklyActivity = $wpdb->get_results($wpdb->prepare("
            SELECT 
                WEEK(created_at) as week,
                YEAR(created_at) as year,
                COUNT(*) as action_count
            FROM {$this->activityTable}
            WHERE user_id = %d
              AND created_at > DATE_SUB(NOW(), INTERVAL 90 DAY)
            GROUP BY YEAR(created_at), WEEK(created_at)
            ORDER BY year DESC, week DESC
        ", $userId));
        
        if (count($weeklyActivity) < 4) {
            return [
                'suspicious' => false,
                'weight' => 0,
                'reasons' => []
            ];
        }
        
        $suspicious = false;
        $weight = 0;
        $reasons = [];
        $metrics = [];
        
        $counts = array_column($weeklyActivity, 'action_count');
        $metrics['weekly_counts'] = $counts;
        
        // Check for perfect consistency week to week
        $variance = $this->calculateVariance($counts);
        $metrics['weekly_variance'] = $variance;
        
        if ($variance < 5 && count($counts) > 4) {
            $suspicious = true;
            $weight += 25;
            $reasons[] = 'perfect_weekly_consistency';
        }
        
        // Check for sudden changes in behavior
        $changes = [];
        for ($i = 1; $i < count($counts); $i++) {
            if ($counts[$i-1] > 0) {
                $change = abs($counts[$i] - $counts[$i-1]) / $counts[$i-1];
                $changes[] = $change;
            }
        }
        
        if (!empty($changes)) {
            $avgChange = array_sum($changes) / count($changes);
            $metrics['avg_weekly_change'] = $avgChange;
            
            if ($avgChange < 0.1) { // Less than 10% change week to week
                $suspicious = true;
                $weight += 20;
                $reasons[] = 'minimal_weekly_variance';
            }
        }
        
        return [
            'suspicious' => $suspicious,
            'weight' => $weight,
            'reasons' => $reasons,
            'metrics' => $metrics
        ];
    }
    
    /**
     * Calculate variance of an array
     */
    private function calculateVariance(array $arr): float {
        if (empty($arr)) return 0;
        
        $avg = array_sum($arr) / count($arr);
        if ($avg == 0) return 0;
        
        $squaredDiffs = array_map(function($val) use ($avg) {
            return pow($val - $avg, 2);
        }, $arr);
        
        return sqrt(array_sum($squaredDiffs) / count($arr));
    }
    
    /**
     * Get sleeping hours (12 AM - 6 AM) in UTC based on user timezone
     */
    private function getSleepingHours(string $timezone): array {
        try {
            $userTz = new \DateTimeZone($timezone);
            $now = new \DateTime('now', $userTz);
            
            $offset = $now->getOffset() / 3600; // Offset in hours
            
            // Sleeping hours: 12 AM - 6 AM local time
            $sleepHoursLocal = [0, 1, 2, 3, 4, 5];
            
            // Convert to UTC
            $sleepHoursUTC = array_map(function($hour) use ($offset) {
                return ($hour - $offset + 24) % 24;
            }, $sleepHoursLocal);
            
            return $sleepHoursUTC;
        } catch (\Exception $e) {
            // Default to UTC if timezone invalid
            return [0, 1, 2, 3, 4, 5];
        }
    }
    
    /**
     * Count user comments
     */
    private function countUserComments(int $userId): int {
        global $wpdb;
        
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$wpdb->comments} WHERE user_id = %d",
            $userId
        ));
    }
    
    /**
     * Store behavioral pattern for ML training
     */
    private function storePattern(int $userId, string $type, array $data, float $confidence = 1.0): void {
        global $wpdb;
        
        $wpdb->insert(
            $this->patternsTable,
            [
                'user_id' => $userId,
                'pattern_type' => $type,
                'pattern_data' => json_encode($data),
                'confidence' => $confidence,
                'detected_at' => current_time('mysql'),
                'expires_at' => date('Y-m-d H:i:s', strtotime('+30 days'))
            ],
            ['%d', '%s', '%s', '%f', '%s', '%s']
        );
    }
    
    /**
     * Get behavior statistics for dashboard
     */
    public function getStats(): array {
        global $wpdb;
        
        $totalAnalyzed = $wpdb->get_var("
            SELECT COUNT(DISTINCT user_id) 
            FROM {$wpdb->usermeta} 
            WHERE meta_key = 'bcc_trust_last_behavior_score'
        ");
        
        $avgScore = $wpdb->get_var("
            SELECT AVG(CAST(meta_value AS DECIMAL))
            FROM {$wpdb->usermeta}
            WHERE meta_key = 'bcc_trust_last_behavior_score'
        ");
        
        $highRisk = $wpdb->get_var("
            SELECT COUNT(*)
            FROM {$wpdb->usermeta}
            WHERE meta_key = 'bcc_trust_last_behavior_score'
              AND CAST(meta_value AS DECIMAL) > 70
        ");
        
        // Get most common flags
        $patterns = $wpdb->get_results("
            SELECT pattern_data
            FROM {$this->patternsTable}
            WHERE pattern_type = 'suspicious_behavior'
            ORDER BY detected_at DESC
            LIMIT 1000
        ");
        
        $flagCounts = [];
        foreach ($patterns as $pattern) {
            $data = json_decode($pattern->pattern_data, true);
            if (isset($data['flags']) && is_array($data['flags'])) {
                foreach ($data['flags'] as $flag) {
                    $flagCounts[$flag] = ($flagCounts[$flag] ?? 0) + 1;
                }
            }
        }
        
        arsort($flagCounts);
        $topFlags = array_slice($flagCounts, 0, 10, true);
        
        return [
            'total_users_analyzed' => (int) $totalAnalyzed,
            'average_behavior_score' => round((float) $avgScore, 1),
            'high_risk_users' => (int) $highRisk,
            'top_behavior_flags' => $topFlags,
            'last_updated' => current_time('mysql')
        ];
    }
    
    /**
     * Clear user's behavior cache
     */
    public function clearCache(int $userId): void {
        wp_cache_delete('behavior_' . $userId, self::CACHE_GROUP);
    }
}