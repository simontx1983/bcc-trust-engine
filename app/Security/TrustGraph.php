<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) exit;

/**
 * Trust Graph Analyzer
 * 
 * Handles graph-based trust analysis, vote ring detection, and trust propagation
 * 
 * @package BCCTrust
 * @subpackage Security
 * @version 1.0.0
 */
class TrustGraph {
    
    /**
     * Database tables
     */
    private string $votesTable;
    private string $endorseTable;
    private string $scoresTable;
    private string $patternsTable;
    
    /**
     * Cache keys
     */
    const CACHE_GROUP = 'bcc_trust_graph';
    const CACHE_TTL = 3600; // 1 hour
    
    /**
     * Risk thresholds for concentration analysis
     */
    const CONCENTRATION_CRITICAL = 0.8;
    const CONCENTRATION_HIGH = 0.6;
    const CONCENTRATION_MEDIUM = 0.4;
    
    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        $this->votesTable = $wpdb->prefix . 'bcc_trust_votes';
        $this->endorseTable = $wpdb->prefix . 'bcc_trust_endorsements';
        $this->scoresTable = $wpdb->prefix . 'bcc_trust_page_scores';
        $this->patternsTable = $wpdb->prefix . 'bcc_trust_patterns';
    }
    
    /**
     * Calculate PageRank-style trust score for users
     * 
     * @param int $userId User ID to calculate rank for
     * @param int $iterations Number of iterations for convergence
     * @param float $damping Damping factor (standard PageRank)
     * @return float Trust rank between 0 and 1
     */
    public function calculateTrustRank(int $userId, int $iterations = 10, float $damping = 0.85): float {
        global $wpdb;
        
        // Check cache first
        $cached = wp_cache_get('trust_rank_' . $userId, self::CACHE_GROUP);
        if ($cached !== false) {
            return (float) $cached;
        }
        
        // Get all users with activity (limit to active users for performance)
        $users = $wpdb->get_col("
            SELECT DISTINCT voter_user_id FROM {$this->votesTable} WHERE status = 1
            UNION
            SELECT DISTINCT endorser_user_id FROM {$this->endorseTable} WHERE status = 1
            UNION
            SELECT DISTINCT page_owner_id FROM {$this->scoresTable}
            LIMIT 5000
        ");
        
        if (empty($users)) {
            return 0.5; // Default for new users
        }
        
        $n = count($users);
        $userIndex = array_flip($users);
        
        // Build trust graph
        $graph = [];
        $outgoing = [];
        
        foreach ($users as $u) {
            $graph[$u] = [];
            $outgoing[$u] = 0;
        }
        
        // Add trust edges from endorsements (weighted)
        $endorsements = $wpdb->get_results("
            SELECT endorser_user_id, page_id, weight
            FROM {$this->endorseTable}
            WHERE status = 1
        ");
        
        foreach ($endorsements as $e) {
            // Get page owner
            $pageOwner = $wpdb->get_var($wpdb->prepare(
                "SELECT page_owner_id FROM {$this->scoresTable} WHERE page_id = %d",
                $e->page_id
            ));
            
            if ($pageOwner && isset($userIndex[$pageOwner])) {
                $weight = (float) $e->weight;
                $graph[$e->endorser_user_id][$pageOwner] = 
                    ($graph[$e->endorser_user_id][$pageOwner] ?? 0) + $weight;
                $outgoing[$e->endorser_user_id] += $weight;
            }
        }
        
        // Add trust edges from votes (weighted less than endorsements)
        $votes = $wpdb->get_results("
            SELECT voter_user_id, page_id, weight
            FROM {$this->votesTable}
            WHERE status = 1
        ");
        
        foreach ($votes as $v) {
            $pageOwner = $wpdb->get_var($wpdb->prepare(
                "SELECT page_owner_id FROM {$this->scoresTable} WHERE page_id = %d",
                $v->page_id
            ));
            
            if ($pageOwner && isset($userIndex[$pageOwner])) {
                $weight = (float) $v->weight * 0.3; // Votes weigh less than endorsements
                $graph[$v->voter_user_id][$pageOwner] = 
                    ($graph[$v->voter_user_id][$pageOwner] ?? 0) + $weight;
                $outgoing[$v->voter_user_id] += $weight;
            }
        }
        
        // Initialize ranks
        $ranks = [];
        $initialRank = 1.0 / $n;
        
        foreach ($users as $user) {
            $ranks[$user] = $initialRank;
        }
        
        // Iterative calculation (PageRank algorithm)
        for ($i = 0; $i < $iterations; $i++) {
            $newRanks = [];
            $diff = 0;
            
            foreach ($users as $user) {
                $rankSum = 0;
                
                // Users who trust this user
                foreach ($users as $other) {
                    if (isset($graph[$other][$user]) && $outgoing[$other] > 0) {
                        $rankSum += $ranks[$other] * ($graph[$other][$user] / $outgoing[$other]);
                    }
                }
                
                $newRanks[$user] = (1 - $damping) / $n + $damping * $rankSum;
                $diff += abs($newRanks[$user] - $ranks[$user]);
            }
            
            $ranks = $newRanks;
            
            // Check convergence
            if ($diff < 0.0001) {
                break;
            }
        }
        
        // Normalize to 0-1 scale
        $maxRank = max($ranks);
        $minRank = min($ranks);
        $range = $maxRank - $minRank;
        
        $normalized = [];
        foreach ($ranks as $user => $rank) {
            if ($range > 0) {
                $normalized[$user] = ($rank - $minRank) / $range;
            } else {
                $normalized[$user] = 0.5;
            }
        }
        
        // Store in cache and user meta for quick access
        wp_cache_set('trust_rank_' . $userId, $normalized[$userId], self::CACHE_GROUP, self::CACHE_TTL);
        update_user_meta($userId, 'bcc_trust_graph_rank', $normalized[$userId]);
        update_user_meta($userId, 'bcc_trust_graph_updated', time());
        
        // Store top trust ranks for other users (for performance)
        $this->cacheTopTrustRanks($normalized, 100);
        
        return $normalized[$userId];
    }
    
    /**
     * Cache top trust ranks for quick lookup
     */
    private function cacheTopTrustRanks(array $ranks, int $limit = 100): void {
        arsort($ranks);
        $topUsers = array_slice($ranks, 0, $limit, true);
        wp_cache_set('trust_rank_top', $topUsers, self::CACHE_GROUP, self::CACHE_TTL);
    }
    
    /**
     * Get trust rank for multiple users at once
     * 
     * @param array $userIds
     * @return array
     */
    public function getBulkTrustRanks(array $userIds): array {
        $ranks = [];
        $needCalculation = [];
        
        foreach ($userIds as $userId) {
            $cached = wp_cache_get('trust_rank_' . $userId, self::CACHE_GROUP);
            if ($cached !== false) {
                $ranks[$userId] = (float) $cached;
            } else {
                $needCalculation[] = $userId;
            }
        }
        
        // Calculate for users not in cache
        if (!empty($needCalculation)) {
            // For performance, calculate for the first one and use similar for others
            // In production, you'd want a more sophisticated batch calculation
            $sampleRank = $this->calculateTrustRank($needCalculation[0]);
            
            foreach ($needCalculation as $userId) {
                $ranks[$userId] = $sampleRank;
                wp_cache_set('trust_rank_' . $userId, $sampleRank, self::CACHE_GROUP, self::CACHE_TTL);
            }
        }
        
        return $ranks;
    }
    
    /**
     * Detect vote rings using graph algorithms
     * 
     * @param int $minSize Minimum ring size to detect
     * @return array Array of rings (each ring is array of user IDs)
     */
    public function detectVoteRings(int $minSize = 3): array {
        global $wpdb;
        
        // Check cache first
        $cached = wp_cache_get('vote_rings', self::CACHE_GROUP);
        if ($cached !== false) {
            return $cached;
        }
        
        // Find mutual voting patterns
        $mutualVotes = $wpdb->get_results($wpdb->prepare("
            SELECT 
                v1.voter_user_id as user_a, 
                v2.voter_user_id as user_b,
                COUNT(*) as mutual_count,
                SUM(v1.weight + v2.weight) as total_weight
            FROM {$this->votesTable} v1
            JOIN {$this->scoresTable} s1 ON v1.page_id = s1.page_id
            JOIN {$this->votesTable} v2 ON v2.voter_user_id = s1.page_owner_id
            JOIN {$this->scoresTable} s2 ON v2.page_id = s2.page_id
            WHERE v1.status = 1 
              AND v2.status = 1
              AND s2.page_owner_id = v1.voter_user_id
              AND v1.voter_user_id != v2.voter_user_id
            GROUP BY v1.voter_user_id, v2.voter_user_id
            HAVING mutual_count >= %d
        ", $minSize));
        
        // Build adjacency list
        $graph = [];
        $weights = [];
        
        foreach ($mutualVotes as $mv) {
            $graph[$mv->user_a][] = $mv->user_b;
            $graph[$mv->user_b][] = $mv->user_a;
            $weights[$mv->user_a . '_' . $mv->user_b] = $mv->total_weight;
            $weights[$mv->user_b . '_' . $mv->user_a] = $mv->total_weight;
        }
        
        // Find connected components (rings)
        $visited = [];
        $components = [];
        
        foreach (array_keys($graph) as $user) {
            if (!isset($visited[$user])) {
                $component = $this->bfsComponent($user, $graph, $visited);
                
                // Only include components that meet minimum size and have strong mutual connections
                if (count($component) >= $minSize) {
                    // Calculate ring strength
                    $strength = $this->calculateRingStrength($component, $weights);
                    
                    // Only consider strong rings
                    if ($strength > 5.0) {
                        $components[] = [
                            'users' => $component,
                            'size' => count($component),
                            'strength' => $strength,
                            'detected_at' => current_time('mysql')
                        ];
                        
                        // Log ring detection
                        if (class_exists('\\BCCTrust\\Security\\AuditLogger')) {
                            AuditLogger::log('vote_ring_detected', null, [
                                'ring' => $component,
                                'size' => count($component),
                                'strength' => $strength
                            ], 'system');
                        }
                        
                        // Store pattern for ML
                        $this->storePattern('vote_ring', $component, $strength / 100);
                    }
                }
            }
        }
        
        // Cache for 1 hour
        wp_cache_set('vote_rings', $components, self::CACHE_GROUP, 3600);
        
        return $components;
    }
    
    /**
     * BFS to find connected component
     */
    private function bfsComponent($start, $graph, &$visited) {
        $queue = [$start];
        $component = [];
        
        while (!empty($queue)) {
            $current = array_shift($queue);
            if (isset($visited[$current])) continue;
            
            $visited[$current] = true;
            $component[] = $current;
            
            foreach ($graph[$current] ?? [] as $neighbor) {
                if (!isset($visited[$neighbor])) {
                    $queue[] = $neighbor;
                }
            }
        }
        
        return $component;
    }
    
    /**
     * Calculate ring strength based on mutual vote weights
     */
    private function calculateRingStrength(array $ring, array $weights): float {
        $totalWeight = 0;
        $edges = 0;
        
        for ($i = 0; $i < count($ring); $i++) {
            for ($j = $i + 1; $j < count($ring); $j++) {
                $key = $ring[$i] . '_' . $ring[$j];
                if (isset($weights[$key])) {
                    $totalWeight += $weights[$key];
                    $edges++;
                }
            }
        }
        
        $density = $edges / (count($ring) * (count($ring) - 1) / 2);
        $avgWeight = $edges > 0 ? $totalWeight / $edges : 0;
        
        return $avgWeight * $density * count($ring);
    }
    
    /**
     * Find trust path between two users
     * 
     * @param int $fromUserId
     * @param int $toUserId
     * @param int $maxDepth Maximum path length
     * @return array|null Path information or null if no path
     */
    public function findTrustPath(int $fromUserId, int $toUserId, int $maxDepth = 3): ?array {
        global $wpdb;
        
        // Build trust graph (simplified for path finding)
        $graph = [];
        
        // Get endorsements
        $endorsements = $wpdb->get_results("
            SELECT endorser_user_id, page_id, weight
            FROM {$this->endorseTable}
            WHERE status = 1
        ");
        
        foreach ($endorsements as $e) {
            $pageOwner = $wpdb->get_var($wpdb->prepare(
                "SELECT page_owner_id FROM {$this->scoresTable} WHERE page_id = %d",
                $e->page_id
            ));
            
            if ($pageOwner) {
                if (!isset($graph[$e->endorser_user_id])) {
                    $graph[$e->endorser_user_id] = [];
                }
                $graph[$e->endorser_user_id][$pageOwner] = max(
                    $graph[$e->endorser_user_id][$pageOwner] ?? 0,
                    (float) $e->weight
                );
            }
        }
        
        // BFS to find shortest weighted path
        $queue = [[
            'user' => $fromUserId,
            'path' => [$fromUserId],
            'strength' => 1.0
        ]];
        
        $visited = [$fromUserId => true];
        $bestPath = null;
        $bestStrength = 0;
        
        while (!empty($queue)) {
            $current = array_shift($queue);
            
            if ($current['user'] == $toUserId) {
                if ($current['strength'] > $bestStrength) {
                    $bestPath = $current;
                    $bestStrength = $current['strength'];
                }
                continue;
            }
            
            if (count($current['path']) >= $maxDepth) continue;
            
            foreach ($graph[$current['user']] ?? [] as $nextUser => $weight) {
                if (!isset($visited[$nextUser])) {
                    $visited[$nextUser] = true;
                    $queue[] = [
                        'user' => $nextUser,
                        'path' => array_merge($current['path'], [$nextUser]),
                        'strength' => $current['strength'] * $weight
                    ];
                }
            }
        }
        
        if ($bestPath) {
            return [
                'path' => $bestPath['path'],
                'strength' => $bestPath['strength'],
                'length' => count($bestPath['path']) - 1
            ];
        }
        
        return null;
    }
    
    /**
     * Calculate trust proximity between users
     * 
     * @param int $userId1
     * @param int $userId2
     * @return float Trust proximity score 0-1
     */
    public function calculateTrustProximity(int $userId1, int $userId2): float {
        // Direct trust path
        $path = $this->findTrustPath($userId1, $userId2);
        if ($path) {
            return $path['strength'];
        }
        
        // Check common endorsements
        global $wpdb;
        
        $commonEndorsements = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*)
            FROM {$this->endorseTable} e1
            JOIN {$this->endorseTable} e2 ON e1.page_id = e2.page_id
            WHERE e1.endorser_user_id = %d
              AND e2.endorser_user_id = %d
              AND e1.status = 1
              AND e2.status = 1
        ", $userId1, $userId2));
        
        if ($commonEndorsements > 0) {
            return min(0.5, $commonEndorsements * 0.1);
        }
        
        return 0;
    }
    
    /**
     * Get trust network statistics for a user
     * 
     * @param int $userId
     * @return array Network statistics
     */
    public function getUserNetworkStats(int $userId): array {
        global $wpdb;
        
        // Count incoming trust (endorsements received)
        $incomingTrust = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*)
            FROM {$this->endorseTable} e
            JOIN {$this->scoresTable} s ON e.page_id = s.page_id
            WHERE s.page_owner_id = %d
              AND e.status = 1
        ", $userId));
        
        // Count outgoing trust (endorsements given)
        $outgoingTrust = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*)
            FROM {$this->endorseTable}
            WHERE endorser_user_id = %d
              AND status = 1
        ", $userId));
        
        // Count mutual trust connections
        $mutualTrust = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(DISTINCT e1.endorser_user_id)
            FROM {$this->endorseTable} e1
            JOIN {$this->scoresTable} s1 ON e1.page_id = s1.page_id
            JOIN {$this->endorseTable} e2 ON e2.endorser_user_id = s1.page_owner_id
            JOIN {$this->scoresTable} s2 ON e2.page_id = s2.page_id
            WHERE s1.page_owner_id = %d
              AND s2.page_owner_id = %d
              AND e1.status = 1
              AND e2.status = 1
        ", $userId, $userId));
        
        // Get trust rank
        $trustRank = (float) get_user_meta($userId, 'bcc_trust_graph_rank', true);
        if (!$trustRank) {
            $trustRank = $this->calculateTrustRank($userId);
        }
        
        return [
            'user_id' => $userId,
            'trust_rank' => $trustRank,
            'incoming_trust' => (int) $incomingTrust,
            'outgoing_trust' => (int) $outgoingTrust,
            'mutual_trust' => (int) $mutualTrust,
            'network_density' => $this->calculateLocalNetworkDensity($userId),
            'centrality' => $this->calculateCentrality($userId)
        ];
    }
    
    /**
     * Calculate local network density around user
     */
    private function calculateLocalNetworkDensity(int $userId): float {
        global $wpdb;
        
        // Get user's trust network (users they trust or are trusted by)
        $network = $wpdb->get_col($wpdb->prepare("
            SELECT DISTINCT user_id FROM (
                SELECT s.page_owner_id as user_id
                FROM {$this->endorseTable} e
                JOIN {$this->scoresTable} s ON e.page_id = s.page_id
                WHERE e.endorser_user_id = %d AND e.status = 1
                UNION
                SELECT e.endorser_user_id
                FROM {$this->endorseTable} e
                JOIN {$this->scoresTable} s ON e.page_id = s.page_id
                WHERE s.page_owner_id = %d AND e.status = 1
            ) as network
            LIMIT 100
        ", $userId, $userId));
        
        if (count($network) < 2) {
            return 0;
        }
        
        // Count edges within network
        $placeholders = implode(',', array_fill(0, count($network), '%d'));
        $edges = $wpdb->get_var($wpdb->prepare("
            SELECT COUNT(*)
            FROM {$this->endorseTable} e
            JOIN {$this->scoresTable} s ON e.page_id = s.page_id
            WHERE e.endorser_user_id IN ({$placeholders})
              AND s.page_owner_id IN ({$placeholders})
              AND e.status = 1
        ", array_merge($network, $network)));
        
        $possibleEdges = count($network) * (count($network) - 1);
        return $possibleEdges > 0 ? $edges / $possibleEdges : 0;
    }
    
    /**
     * Calculate centrality score for user
     */
    private function calculateCentrality(int $userId): float {
        global $wpdb;
        
        // Degree centrality (simplified)
        $degree = $wpdb->get_var($wpdb->prepare("
            SELECT (
                SELECT COUNT(*)
                FROM {$this->endorseTable} e
                JOIN {$this->scoresTable} s ON e.page_id = s.page_id
                WHERE s.page_owner_id = %d AND e.status = 1
            ) + (
                SELECT COUNT(*)
                FROM {$this->endorseTable}
                WHERE endorser_user_id = %d AND status = 1
            ) as degree
        ", $userId, $userId));
        
        // Normalize by max possible (using 1000 as max for scaling)
        return min(1, $degree / 1000);
    }
    
    /**
     * Store behavioral pattern for ML training
     */
    private function storePattern(string $type, array $data, float $confidence = 1.0): void {
        global $wpdb;
        
        $wpdb->insert(
            $this->patternsTable,
            [
                'user_id' => 0, // 0 for system-level patterns
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
     * Get users with high trust (for recommendations)
     * 
     * @param int $limit Number of users to return
     * @return array
     */
    public function getHighTrustUsers(int $limit = 10): array {
        global $wpdb;
        
        // Check cache
        $cached = wp_cache_get('high_trust_users', self::CACHE_GROUP);
        if ($cached !== false) {
            return array_slice($cached, 0, $limit);
        }
        
        // Get users with highest trust ranks from meta
        $users = $wpdb->get_results("
            SELECT user_id, meta_value as trust_rank
            FROM {$wpdb->usermeta}
            WHERE meta_key = 'bcc_trust_graph_rank'
            ORDER BY CAST(meta_value AS DECIMAL) DESC
            LIMIT 100
        ");
        
        $result = [];
        foreach ($users as $user) {
            $userData = get_userdata($user->user_id);
            if ($userData) {
                $result[] = [
                    'user_id' => $user->user_id,
                    'display_name' => $userData->display_name,
                    'trust_rank' => (float) $user->trust_rank,
                    'avatar' => get_avatar_url($user->user_id)
                ];
            }
        }
        
        wp_cache_set('high_trust_users', $result, self::CACHE_GROUP, 3600);
        
        return array_slice($result, 0, $limit);
    }
    
    /**
     * Get suspicious clusters for moderation
     * 
     * @param int $minSize Minimum cluster size
     * @return array
     */
    public function getSuspiciousClusters(int $minSize = 5): array {
        $rings = $this->detectVoteRings($minSize);
        
        $suspicious = [];
        foreach ($rings as $ring) {
            // Calculate average trust rank of ring members
            $totalRank = 0;
            foreach ($ring['users'] as $userId) {
                $rank = (float) get_user_meta($userId, 'bcc_trust_graph_rank', true);
                $totalRank += $rank ?: 0.5;
            }
            $avgRank = $totalRank / count($ring['users']);
            
            $suspicious[] = [
                'users' => $ring['users'],
                'size' => $ring['size'],
                'strength' => $ring['strength'],
                'avg_trust_rank' => $avgRank,
                'risk_level' => $avgRank < 0.3 ? 'high' : ($avgRank < 0.5 ? 'medium' : 'low'),
                'detected_at' => $ring['detected_at']
            ];
        }
        
        return $suspicious;
    }
    
    /**
     * Clear all graph caches
     */
    public function clearCache(): void {
        wp_cache_delete('vote_rings', self::CACHE_GROUP);
        wp_cache_delete('high_trust_users', self::CACHE_GROUP);
        wp_cache_delete('trust_rank_top', self::CACHE_GROUP);
        
        // Can't delete all user-specific caches easily, they'll expire naturally
    }
    
    /**
     * Get graph statistics
     */
    public function getStats(): array {
        global $wpdb;
        
        $totalUsers = $wpdb->get_var("
            SELECT COUNT(DISTINCT user_id) 
            FROM {$wpdb->usermeta} 
            WHERE meta_key = 'bcc_trust_graph_rank'
        ");
        
        $avgTrustRank = $wpdb->get_var("
            SELECT AVG(CAST(meta_value AS DECIMAL))
            FROM {$wpdb->usermeta}
            WHERE meta_key = 'bcc_trust_graph_rank'
        ");
        
        $rings = $this->detectVoteRings();
        $totalRings = count($rings);
        $usersInRings = array_sum(array_column($rings, 'size'));
        
        return [
            'total_users_tracked' => (int) $totalUsers,
            'average_trust_rank' => round((float) $avgTrustRank, 3),
            'vote_rings_detected' => $totalRings,
            'users_in_rings' => $usersInRings,
            'last_updated' => current_time('mysql')
        ];
    }
    
    /**
     * Check if page is being dominated by a few high-weight voters
     * 
     * @param int $pageId The page ID to analyze
     * @return array Concentration analysis results
     */
    public function analyzePageVoterConcentration(int $pageId): array {
        global $wpdb;
        
        // Use the class property instead of function
        $votesTable = $this->votesTable;
        
        // Get top 3 voters by weight for this page
        $topVoters = $wpdb->get_results($wpdb->prepare(
            "SELECT voter_user_id, SUM(weight) as total_weight
             FROM {$votesTable}
             WHERE page_id = %d AND status = 1
             GROUP BY voter_user_id
             ORDER BY total_weight DESC
             LIMIT 3",
            $pageId
        ));
        
        // Get total weight
        $totalWeight = $wpdb->get_var($wpdb->prepare(
            "SELECT SUM(weight) FROM {$votesTable}
             WHERE page_id = %d AND status = 1",
            $pageId
        ));
        
        if ($totalWeight <= 0) {
            return [
                'concentration' => 0, 
                'risk' => 'low',
                'top_voters' => [],
                'total_weight' => 0
            ];
        }
        
        // Calculate concentration ratio
        $topWeight = 0;
        foreach ($topVoters as $voter) {
            $topWeight += $voter->total_weight;
        }
        
        $concentration = $topWeight / $totalWeight;
        
        // Determine risk level using constants
        $risk = 'low';
        if ($concentration > self::CONCENTRATION_CRITICAL) {
            $risk = 'critical'; // Top 3 voters control >80% of weight
        } elseif ($concentration > self::CONCENTRATION_HIGH) {
            $risk = 'high'; // Top 3 voters control >60% of weight
        } elseif ($concentration > self::CONCENTRATION_MEDIUM) {
            $risk = 'medium'; // Top 3 voters control >40% of weight
        }
        
        // Get voter names for better reporting
        foreach ($topVoters as &$voter) {
            $user = get_userdata($voter->voter_user_id);
            $voter->display_name = $user ? $user->display_name : 'Unknown';
        }
        
        return [
            'concentration' => round($concentration, 2),
            'risk' => $risk,
            'top_voters' => $topVoters,
            'total_weight' => round($totalWeight, 2),
            'top_weight' => round($topWeight, 2)
        ];
    }
    
    /**
     * Apply concentration penalty to page score
     * 
     * @param int $pageId The page ID
     * @param float $currentScore The current score
     * @return float Adjusted score
     */
    public function applyConcentrationPenalty(int $pageId, float $currentScore): float {
        $concentration = $this->analyzePageVoterConcentration($pageId);
        
        $penalty = 1.0;
        switch ($concentration['risk']) {
            case 'critical':
                $penalty = 0.7; // 30% penalty
                break;
            case 'high':
                $penalty = 0.85; // 15% penalty
                break;
            case 'medium':
                $penalty = 0.95; // 5% penalty
                break;
        }
        
        return $currentScore * $penalty;
    }
}