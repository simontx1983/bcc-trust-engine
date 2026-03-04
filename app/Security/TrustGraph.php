<?php
namespace BCCTrust\Security;

if (!defined('ABSPATH')) exit;

use BCCTrust\Repositories\UserInfoRepository;

/**
 * Trust Graph Analyzer
 *
 * Graph-based trust propagation + vote ring detection
 *
 * @package BCCTrust
 * @subpackage Security
 * @version 2.1.1
 */
class TrustGraph {

    private string $votesTable;
    private string $endorseTable;
    private string $scoresTable;
    private string $patternsTable;

    private UserInfoRepository $userInfoRepo;

    const CACHE_GROUP = 'bcc_trust_graph';
    const CACHE_TTL   = 3600;

    public function __construct() {
        $this->votesTable    = bcc_trust_votes_table();
        $this->endorseTable  = bcc_trust_endorsements_table();
        $this->scoresTable   = bcc_trust_scores_table();
        $this->patternsTable = bcc_trust_patterns_table();
        $this->userInfoRepo  = new UserInfoRepository();
    }

    /**
     * Calculate PageRank-style trust rank for a user (0..1)
     */
    public function calculateTrustRank(int $userId, int $iterations = 10, float $damping = 0.85): float {
        global $wpdb;

        // Cache
        $cached = wp_cache_get('trust_rank_' . $userId, self::CACHE_GROUP);
        if ($cached !== false) {
            return (float) $cached;
        }

        // Users involved in trust actions
        $users = $wpdb->get_col("
            SELECT DISTINCT voter_user_id FROM {$this->votesTable} WHERE status = 1
            UNION
            SELECT DISTINCT endorser_user_id FROM {$this->endorseTable} WHERE status = 1
            UNION
            SELECT DISTINCT page_owner_id FROM {$this->scoresTable}
            LIMIT 5000
        ");

        if (empty($users)) {
            $defaultRank = 0.5;
            wp_cache_set('trust_rank_' . $userId, $defaultRank, self::CACHE_GROUP, self::CACHE_TTL);
            $this->userInfoRepo->updateTrustRank($userId, $defaultRank);
            return $defaultRank;
        }

        $n = count($users);
        $userIndex = array_flip($users);

        // Graph: from_user => [to_user => weight]
        $graph = [];
        $outgoing = [];

        foreach ($users as $u) {
            $graph[$u] = [];
            $outgoing[$u] = 0.0;
        }

        /**
         * Endorsements: stronger edges
         */
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

            if ($pageOwner && isset($userIndex[$pageOwner])) {
                $from = (int) $e->endorser_user_id;
                $to   = (int) $pageOwner;
                $w    = (float) $e->weight;

                $graph[$from][$to] = ($graph[$from][$to] ?? 0) + $w;
                $outgoing[$from]   = ($outgoing[$from] ?? 0) + $w;
            }
        }

        /**
         * Votes: weaker edges
         */
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
                $from = (int) $v->voter_user_id;
                $to   = (int) $pageOwner;
                $w    = (float) $v->weight * 0.2;

                $graph[$from][$to] = ($graph[$from][$to] ?? 0) + $w;
                $outgoing[$from]   = ($outgoing[$from] ?? 0) + $w;
            }
        }

        /**
         * Init ranks
         */
        $ranks = [];
        $initialRank = 1.0 / $n;
        foreach ($users as $u) {
            $ranks[$u] = $initialRank;
        }

        /**
         * PageRank iterations
         */
        for ($i = 0; $i < $iterations; $i++) {
            $newRanks = [];
            $diff = 0.0;

            foreach ($users as $user) {
                $rankSum = 0.0;

                foreach ($users as $other) {
                    if (!isset($graph[$other][$user])) {
                        continue;
                    }
                    if (empty($outgoing[$other]) || $outgoing[$other] <= 0) {
                        continue;
                    }

                    $githubAuthority = $this->getGithubAuthority((int) $other);

                    $rankSum +=
                        $ranks[$other] *
                        $githubAuthority *
                        ($graph[$other][$user] / $outgoing[$other]);
                }

                $newRanks[$user] = (1 - $damping) / $n + $damping * $rankSum;
                $diff += abs($newRanks[$user] - $ranks[$user]);
            }

            $ranks = $newRanks;

            // Convergence
            if ($diff < 0.0001) {
                break;
            }
        }

        /**
         * Normalize 0..1
         */
        $maxRank = max($ranks);
        $minRank = min($ranks);
        $range   = $maxRank - $minRank;

        $normalized = [];
        foreach ($ranks as $u => $rank) {
            $normalized[$u] = ($range > 0) ? (($rank - $minRank) / $range) : 0.5;
        }

        $userRank = $normalized[$userId] ?? 0.5;

        wp_cache_set('trust_rank_' . $userId, $userRank, self::CACHE_GROUP, self::CACHE_TTL);
        $this->userInfoRepo->updateTrustRank($userId, $userRank);

        return $userRank;
    }

    /**
     * GitHub authority multiplier
     * GitHub does NOT directly give trust.
     * It increases how much trust a user can distribute.
     */
    private function getGithubAuthority(int $userId): float {
        $user = $this->userInfoRepo->getByUserId($userId);

        if (!$user || empty($user->github_verified_at)) {
            return 1.0;
        }

        $score = 1.0;

        if (!empty($user->github_account_age_days) && $user->github_account_age_days > 365) {
            $score += 0.10;
        }

        if (!empty($user->github_followers) && $user->github_followers > 20) {
            $score += 0.10;
        }

        if (!empty($user->github_public_repos) && $user->github_public_repos > 10) {
            $score += 0.10;
        }

        if (!empty($user->github_org_count) && $user->github_org_count > 0) {
            $score += 0.10;
        }

        if (!empty($user->github_has_verified_email)) {
            $score += 0.05;
        }

        // Fraud penalty (optional but smart)
        if (!empty($user->fraud_score) && (int) $user->fraud_score > 50) {
            $score *= 0.5;
        }

        return min($score, 1.5);
    }

    /**
     * Detect vote rings (kept as you had it)
     */
    public function detectVoteRings(int $minSize = 3): array {
        global $wpdb;

        $cached = wp_cache_get('vote_rings', self::CACHE_GROUP);
        if ($cached !== false) {
            return $cached;
        }

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

        $graph = [];
        $weights = [];

        foreach ($mutualVotes as $mv) {
            $a = (int) $mv->user_a;
            $b = (int) $mv->user_b;

            $graph[$a] = $graph[$a] ?? [];
            $graph[$b] = $graph[$b] ?? [];

            $graph[$a][] = $b;
            $graph[$b][] = $a;

            $weights["{$a}_{$b}"] = (float) $mv->total_weight;
            $weights["{$b}_{$a}"] = (float) $mv->total_weight;
        }

        $visited = [];
        $components = [];

        foreach (array_keys($graph) as $user) {
            if (isset($visited[$user])) continue;

            $component = $this->bfsComponent($user, $graph, $visited);

            if (count($component) >= $minSize) {
                $strength = $this->calculateRingStrength($component, $weights);

                if ($strength > 5.0) {
                    $components[] = [
                        'users' => $component,
                        'size' => count($component),
                        'strength' => $strength,
                        'detected_at' => current_time('mysql'),
                    ];

                    foreach ($component as $uid) {
                        $this->userInfoRepo->incrementFraudScore((int)$uid, 15, 'vote_ring_member');
                    }
                }
            }
        }

        wp_cache_set('vote_rings', $components, self::CACHE_GROUP, self::CACHE_TTL);

        return $components;
    }

    private function bfsComponent(int $start, array $graph, array &$visited): array {
        $queue = [$start];
        $component = [];

        while (!empty($queue)) {
            $current = array_shift($queue);
            if (isset($visited[$current])) continue;

            $visited[$current] = true;
            $component[] = $current;

            foreach ($graph[$current] ?? [] as $neighbor) {
                if (!isset($visited[$neighbor])) {
                    $queue[] = (int) $neighbor;
                }
            }
        }

        return $component;
    }

    private function calculateRingStrength(array $ring, array $weights): float {
        $totalWeight = 0.0;
        $edges = 0;

        $count = count($ring);

        for ($i = 0; $i < $count; $i++) {
            for ($j = $i + 1; $j < $count; $j++) {
                $key = $ring[$i] . '_' . $ring[$j];
                if (isset($weights[$key])) {
                    $totalWeight += (float) $weights[$key];
                    $edges++;
                }
            }
        }

        if ($count < 2) return 0.0;

        $possibleEdges = ($count * ($count - 1)) / 2;
        $density = $possibleEdges > 0 ? ($edges / $possibleEdges) : 0.0;
        $avgWeight = $edges > 0 ? ($totalWeight / $edges) : 0.0;

        return $avgWeight * $density * $count;
    }

    public function getStats(): array {
        global $wpdb;

        $userInfoTable = bcc_trust_user_info_table();

        $stats = $wpdb->get_row("
            SELECT 
                COUNT(*) as total_users_tracked,
                AVG(trust_rank) as average_trust_rank,
                SUM(CASE WHEN trust_rank > 0.8 THEN 1 ELSE 0 END) as high_trust_count,
                SUM(CASE WHEN trust_rank < 0.2 THEN 1 ELSE 0 END) as low_trust_count
            FROM {$userInfoTable}
            WHERE trust_rank > 0
        ");

        $rings = $this->detectVoteRings();
        $totalRings = count($rings);
        $usersInRings = array_sum(array_column($rings, 'size'));

        return [
            'total_users_tracked' => (int) ($stats->total_users_tracked ?? 0),
            'average_trust_rank' => round((float) ($stats->average_trust_rank ?? 0), 3),
            'high_trust_users' => (int) ($stats->high_trust_count ?? 0),
            'low_trust_users' => (int) ($stats->low_trust_count ?? 0),
            'vote_rings_detected' => $totalRings,
            'users_in_rings' => $usersInRings,
            'last_updated' => current_time('mysql'),
        ];
    }
}