<?php
/**
 * Blue Collar Crypto - Page Score Calculator
 *
 * Handles all trust score calculations for PeepSo business pages
 * Integrates with fraud detection, behavioral analysis, and trust graph
 * 
 * @package BCC_Trust_Engine
 * @subpackage Services
 * @version 2.0.0
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class BCC_Page_Score_Calculator
 * 
 * Manages the calculation and caching of trust scores for PeepSo pages
 * with enhanced fraud detection integration
 */
class BCC_Page_Score_Calculator {

    /**
     * Database tables
     */
    private $votes_table;
    private $scores_table;
    private $endorsements_table;
    private $reputation_table;
    private $fingerprint_table;

    /**
     * Cache group for WordPress object cache
     */
    const CACHE_GROUP = 'bcc_trust_page_scores';

    /**
     * Default trust score for new pages
     */
    const DEFAULT_SCORE = 50.00;

    /**
     * Maximum votes needed for full confidence
     */
    const MAX_CONFIDENCE_VOTES = 50;

    /**
 * Score multipliers for different vote weights
 */
const SCORE_MULTIPLIERS = [
    'elite' => 1.5,      // Elite users' votes count 1.5x
    'trusted' => 1.2,    // Trusted users' votes count 1.2x (was 1.0)
    'neutral' => 1.0,    // Neutral users' votes count normal (was 0.75)
    'caution' => 0.6,    // Caution users' votes count 0.6x (was 0.5)
    'risky' => 0.3,      // Risky users' votes count 0.3x (was 0.25)
    'insufficient_data' => 0.5  // New users start at half weight
];

    /**
     * Constructor
     */
    public function __construct() {
        global $wpdb;
        
        $this->votes_table = $wpdb->prefix . 'bcc_trust_votes';
        $this->scores_table = $wpdb->prefix . 'bcc_trust_page_scores';
        $this->endorsements_table = $wpdb->prefix . 'bcc_trust_endorsements';
        $this->reputation_table = $wpdb->prefix . 'bcc_trust_reputation';
        $this->fingerprint_table = $wpdb->prefix . 'bcc_trust_device_fingerprints';
    }

    /**
     * Calculate or retrieve cached score for a page
     *
     * @param int $page_id PeepSo page ID
     * @param bool $force_recalculate Force recalculation even if cached
     * @return object|false Score object or false on failure
     */
    public function get_page_score($page_id, $force_recalculate = false) {
        // Check cache first (unless forcing recalculation)
        if (!$force_recalculate) {
            $cached_score = wp_cache_get('page_score_' . $page_id, self::CACHE_GROUP);
            if ($cached_score !== false) {
                return $cached_score;
            }
        }

        // Get from database or calculate
        global $wpdb;
        
        $score = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->scores_table} WHERE page_id = %d",
            $page_id
        ));

        // If no score exists or it's stale, calculate fresh
        if (!$score || $this->is_score_stale($score) || $force_recalculate) {
            $score = $this->recalculate_page_score($page_id);
            
            if (!$score) {
                // Create default score for new pages
                $score = $this->create_default_score($page_id);
            }
        }

        // Cache the result (for 1 hour)
        if ($score) {
            wp_cache_set('page_score_' . $page_id, $score, self::CACHE_GROUP, HOUR_IN_SECONDS);
        }

        return $score;
    }

    /**
     * Recalculate trust score for a page from all votes
     * Enhanced with fraud detection and trust graph integration
     *
     * @param int $page_id PeepSo page ID
     * @return object|false Updated score object or false on failure
     */
    public function recalculate_page_score($page_id) {
        global $wpdb;

        // Begin transaction for data consistency
        $wpdb->query('START TRANSACTION');

        try {
            // Get page owner first
            $page_owner = $this->get_page_owner($page_id);
            if (!$page_owner) {
                throw new Exception('Page owner not found');
            }

            // Get all active votes with enhanced voter data
            $votes = $this->get_votes_with_enhanced_weights($page_id);
            
            // Calculate weighted scores with fraud adjustments
            $scores = $this->calculate_enhanced_weighted_scores($votes);
            
            // Get endorsement count with fraud filtering
            $endorsement_count = $this->get_filtered_endorsement_count($page_id);
            
            // Apply endorsement bonus with fraud consideration
            $scores['total_score'] = $this->apply_enhanced_endorsement_bonus(
                $scores['total_score'], 
                $endorsement_count,
                $votes
            );

            // Get page owner's fraud score for context
            $owner_fraud_score = (int) get_user_meta($page_owner, 'bcc_trust_fraud_score', true);
            
            // Apply owner fraud penalty if they're suspicious
            if ($owner_fraud_score > 70) {
                $scores['total_score'] *= 0.7; // 30% penalty for high-risk owners
            } elseif ($owner_fraud_score > 50) {
                $scores['total_score'] *= 0.85; // 15% penalty for medium-risk owners
            }

            // Determine reputation tier with confidence consideration
            $tier = $this->determine_enhanced_reputation_tier(
                $scores['total_score'], 
                $scores['confidence'],
                $scores['fraud_adjusted_confidence']
            );

            // Prepare score data for database
            $score_data = [
                'page_id' => $page_id,
                'page_owner_id' => $page_owner,
                'total_score' => $this->normalize_score($scores['total_score']),
                'positive_score' => $this->normalize_score($scores['positive'], false),
                'negative_score' => $this->normalize_score($scores['negative'], false),
                'vote_count' => $scores['vote_count'],
                'unique_voters' => $scores['unique_voters'],
                'confidence_score' => $scores['confidence'],
                'reputation_tier' => $tier,
                'endorsement_count' => $endorsement_count,
                'last_vote_at' => $scores['last_vote_at'],
                'last_calculated_at' => current_time('mysql')
            ];

            // Add fraud metadata for debugging
            $score_data['fraud_metadata'] = json_encode([
                'total_raw_weight' => $scores['total_raw_weight'],
                'fraud_discounted_weight' => $scores['total_weight_after_fraud'],
                'automated_votes_removed' => $scores['automated_votes_removed'],
                'suspicious_voters' => $scores['suspicious_voters'],
                'owner_fraud_score' => $owner_fraud_score
            ]);

            // Insert or update in database
            $result = $wpdb->replace($this->scores_table, $score_data, [
                '%d', // page_id
                '%d', // page_owner_id
                '%f', // total_score
                '%f', // positive_score
                '%f', // negative_score
                '%d', // vote_count
                '%d', // unique_voters
                '%f', // confidence_score
                '%s', // reputation_tier
                '%d', // endorsement_count
                '%s', // last_vote_at
                '%s', // last_calculated_at
                '%s'  // fraud_metadata
            ]);

            if ($result === false) {
                throw new Exception('Failed to update score in database');
            }

            // Commit transaction
            $wpdb->query('COMMIT');

            // Clear cache
            $this->clear_page_cache($page_id);

            // Trigger action for other plugins
            do_action('bcc_trust_page_score_updated', $page_id, $score_data);

            // Log recalculation for audit
            if (function_exists('bcc_trust_log_audit')) {
                bcc_trust_log_audit('page_score_recalculated', [
                    'page_id' => $page_id,
                    'score' => $scores['total_score'],
                    'tier' => $tier,
                    'votes' => $scores['vote_count']
                ]);
            }

            // Return the updated score as object
            return (object) $score_data;

        } catch (Exception $e) {
            // Rollback on error
            $wpdb->query('ROLLBACK');
            
            // Log error
            $this->log_error('Score recalculation failed', [
                'page_id' => $page_id,
                'error' => $e->getMessage()
            ]);

            return false;
        }
    }

    /**
     * Get all active votes with enhanced voter data including fraud scores
     *
     * @param int $page_id
     * @return array
     */
    private function get_votes_with_enhanced_weights($page_id) {
        global $wpdb;

        $votes = $wpdb->get_results($wpdb->prepare(
            "SELECT 
                v.*,
                COALESCE(r.reputation_tier, 'insufficient_data') as voter_tier,
                COALESCE(r.vote_weight, 1.0) as base_weight,
                COALESCE(uf.meta_value, 0) as fraud_score,
                COALESCE(ua.meta_value, 0) as automation_score,
                f.automation_score as device_automation,
                f.risk_level as device_risk
            FROM {$this->votes_table} v
            LEFT JOIN {$this->reputation_table} r 
                ON v.voter_user_id = r.user_id
            LEFT JOIN {$wpdb->usermeta} uf 
                ON v.voter_user_id = uf.user_id AND uf.meta_key = 'bcc_trust_fraud_score'
            LEFT JOIN {$wpdb->usermeta} ua 
                ON v.voter_user_id = ua.user_id AND ua.meta_key = 'bcc_trust_automation_score'
            LEFT JOIN {$this->fingerprint_table} f
                ON v.voter_user_id = f.user_id AND f.id = (
                    SELECT id FROM {$this->fingerprint_table} 
                    WHERE user_id = v.voter_user_id 
                    ORDER BY last_seen DESC 
                    LIMIT 1
                )
            WHERE v.page_id = %d 
                AND v.status = 1
            ORDER BY v.created_at ASC",
            $page_id
        ));

        // Calculate effective weight for each vote with fraud adjustments
        foreach ($votes as &$vote) {
            $base_multiplier = self::SCORE_MULTIPLIERS[$vote->voter_tier] ?? 1.0;
            
            // Apply fraud score penalty
            $fraud_penalty = 1.0;
            if ($vote->fraud_score > 0) {
                $fraud_penalty = max(0.1, 1 - ($vote->fraud_score / 100));
            }
            
            // Apply automation penalty
            $automation_penalty = 1.0;
            if ($vote->device_automation > 50 || $vote->automation_score > 50) {
                $automation_penalty = 0.3; // 70% penalty for automated votes
            }
            
            // Combine all factors
            $vote->effective_weight = floatval($vote->weight) * $base_multiplier * $fraud_penalty * $automation_penalty;
            $vote->fraud_adjusted = ($fraud_penalty < 1.0 || $automation_penalty < 1.0);
            $vote->original_weight = floatval($vote->weight);
        }

        return $votes;
    }

    /**
     * Calculate weighted scores with fraud detection
     *
     * @param array $votes
     * @return array
     */
    private function calculate_enhanced_weighted_scores($votes) {
        $positive_score = 0;
        $negative_score = 0;
        $positive_raw = 0;
        $negative_raw = 0;
        $voter_ids = [];
        $suspicious_voters = [];
        $automated_votes_removed = 0;
        $last_vote_at = null;

        foreach ($votes as $vote) {
            // Track raw weights for comparison
            if ($vote->vote_type > 0) {
                $positive_raw += $vote->original_weight;
                $positive_score += $vote->effective_weight;
            } else {
                $negative_raw += $vote->original_weight;
                $negative_score += $vote->effective_weight;
            }

            // Track if this vote was adjusted
            if ($vote->fraud_adjusted) {
                $suspicious_voters[] = $vote->voter_user_id;
                if ($vote->device_automation > 70 || $vote->automation_score > 70) {
                    $automated_votes_removed++;
                }
            }

            $voter_ids[$vote->voter_user_id] = true;
            
            if (!$last_vote_at || strtotime($vote->created_at) > strtotime($last_vote_at)) {
                $last_vote_at = $vote->created_at;
            }
        }

        $vote_count = count($votes);
        $unique_voters = count($voter_ids);

        // Calculate net score with fraud-adjusted weights
        $net_score = $positive_score - $negative_score;
        $total_score = self::DEFAULT_SCORE + ($net_score * 2);

        // Calculate raw score for comparison
        $raw_net = $positive_raw - $negative_raw;
        $raw_total = self::DEFAULT_SCORE + ($raw_net * 2);

        // Calculate confidence with fraud consideration
        $confidence = $this->calculate_enhanced_confidence_score(
            $vote_count, 
            $unique_voters, 
            $positive_score, 
            $negative_score,
            count($suspicious_voters),
            $automated_votes_removed
        );

        return [
            'positive' => $positive_score,
            'negative' => $negative_score,
            'total_score' => $total_score,
            'raw_total_score' => $raw_total,
            'vote_count' => $vote_count,
            'unique_voters' => $unique_voters,
            'confidence' => $confidence['standard'],
            'fraud_adjusted_confidence' => $confidence['fraud_adjusted'],
            'last_vote_at' => $last_vote_at,
            'total_raw_weight' => $positive_raw + $negative_raw,
            'total_weight_after_fraud' => $positive_score + $negative_score,
            'automated_votes_removed' => $automated_votes_removed,
            'suspicious_voters' => array_unique($suspicious_voters)
        ];
    }

    /**
     * Calculate enhanced confidence score with fraud detection
     *
     * @param int $vote_count
     * @param int $unique_voters
     * @param float $positive
     * @param float $negative
     * @param int $suspicious_count
     * @param int $automated_count
     * @return array
     */
    private function calculate_enhanced_confidence_score($vote_count, $unique_voters, $positive, $negative, $suspicious_count, $automated_count) {
        if ($vote_count === 0) {
            return ['standard' => 0, 'fraud_adjusted' => 0];
        }

        // Standard confidence calculation
        $volume_confidence = min(1, $vote_count / self::MAX_CONFIDENCE_VOTES);
        $diversity_factor = min(1, $unique_voters / max(1, $vote_count) * 2);
        
        $total_weight = $positive + $negative;
        if ($total_weight > 0) {
            $balance = abs($positive - $negative) / $total_weight;
            $balance_factor = 1 - ($balance * 0.3);
        } else {
            $balance_factor = 0.5;
        }

        $standard_confidence = ($volume_confidence * 0.5) + 
                              ($diversity_factor * 0.3) + 
                              ($balance_factor * 0.2);

        // Fraud-adjusted confidence
        $fraud_penalty = 1.0;
        if ($vote_count > 0) {
            $suspicious_ratio = $suspicious_count / $vote_count;
            $automated_ratio = $automated_count / $vote_count;
            
            $fraud_penalty = 1 - (($suspicious_ratio * 0.5) + ($automated_ratio * 0.8));
            $fraud_penalty = max(0.3, $fraud_penalty);
        }

        $fraud_adjusted_confidence = $standard_confidence * $fraud_penalty;

        return [
            'standard' => min(1, max(0, $standard_confidence)),
            'fraud_adjusted' => min(1, max(0, $fraud_adjusted_confidence))
        ];
    }

    /**
     * Get filtered endorsement count (excluding suspicious users)
     *
     * @param int $page_id
     * @return int
     */
    private function get_filtered_endorsement_count($page_id) {
        global $wpdb;

        // Count endorsements from non-suspicious users only
        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) 
             FROM {$this->endorsements_table} e
             LEFT JOIN {$wpdb->usermeta} uf 
                ON e.endorser_user_id = uf.user_id 
                AND uf.meta_key = 'bcc_trust_fraud_score'
             WHERE e.page_id = %d 
                AND e.status = 1
                AND (uf.meta_value IS NULL OR uf.meta_value < 70)",
            $page_id
        ));
    }

    /**
     * Apply enhanced endorsement bonus with fraud consideration
     *
     * @param float $score
     * @param int $endorsement_count
     * @param array $votes
     * @return float
     */
    private function apply_enhanced_endorsement_bonus($score, $endorsement_count, $votes) {
        if ($endorsement_count <= 0) {
            return $score;
        }

        // Base bonus from endorsements
        $bonus = min(5, $endorsement_count * 0.5);
        
        // Reduce bonus if page has many automated votes
        if (!empty($votes)) {
            $automated_count = 0;
            foreach ($votes as $vote) {
                if ($vote->device_automation > 70 || $vote->automation_score > 70) {
                    $automated_count++;
                }
            }
            
            if ($automated_count > 0) {
                $automated_ratio = $automated_count / count($votes);
                $bonus *= (1 - ($automated_ratio * 0.5));
            }
        }

        return $score + $bonus;
    }

    /**
     * Determine enhanced reputation tier with fraud consideration
     *
     * @param float $score
     * @param float $confidence
     * @param float $fraud_adjusted_confidence
     * @return string
     */
    private function determine_enhanced_reputation_tier($score, $confidence, $fraud_adjusted_confidence) {
        // Use fraud-adjusted confidence for tier decisions
        $effective_confidence = min($confidence, $fraud_adjusted_confidence);
        
        // Reduce effective score if confidence is low
        if ($effective_confidence < 0.5) {
            $score = $score * (0.5 + $effective_confidence);
        }

        // Determine tier by adjusted score
        if ($score >= 80) return 'elite';
        if ($score >= 65) return 'trusted';
        if ($score >= 45) return 'neutral';
        if ($score >= 30) return 'caution';
        return 'risky';
    }

    /**
     * Get page owner from PeepSo (enhanced)
     *
     * @param int $page_id
     * @return int|false
     */
    private function get_page_owner($page_id) {
        // Try the helper function first
        if (function_exists('bcc_trust_get_page_owner')) {
            $owner = bcc_trust_get_page_owner($page_id);
            if ($owner) {
                return $owner;
            }
        }

        global $wpdb;
        
        // Try PeepSo page users table
        $page_users_table = $wpdb->prefix . 'peepso_page_users';
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$page_users_table'") == $page_users_table;
        
        if ($table_exists) {
            $owner = $wpdb->get_var($wpdb->prepare(
                "SELECT user_id FROM {$page_users_table} 
                 WHERE page_id = %d AND role = 'owner' 
                 LIMIT 1",
                $page_id
            ));
            
            if ($owner) {
                return (int) $owner;
            }
        }
        
        // Fallback to post author
        $post = get_post($page_id);
        return $post ? (int) $post->post_author : 0;
    }

    /**
     * Get endorsement count for a page (legacy)
     *
     * @param int $page_id
     * @return int
     */
    private function get_endorsement_count($page_id) {
        global $wpdb;

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->endorsements_table} 
             WHERE page_id = %d AND status = 1",
            $page_id
        ));
    }

    /**
     * Normalize score to reasonable range
     *
     * @param float $score
     * @param bool $apply_range
     * @return float
     */
    private function normalize_score($score, $apply_range = true) {
        $score = round(floatval($score), 2);
        
        if ($apply_range) {
            $score = min(100, max(0, $score));
        }
        
        return $score;
    }

    /**
     * Check if a score is stale
     *
     * @param object $score
     * @return bool
     */
    private function is_score_stale($score) {
        if (!isset($score->last_calculated_at)) {
            return true;
        }

        $last_calc = strtotime($score->last_calculated_at);
        $one_hour_ago = time() - HOUR_IN_SECONDS;

        return $last_calc < $one_hour_ago;
    }

    /**
     * Create default score for a new page
     *
     * @param int $page_id
     * @return object|false
     */
    private function create_default_score($page_id) {
        global $wpdb;

        $page_owner = $this->get_page_owner($page_id);
        if (!$page_owner) {
            return false;
        }

        $default_data = [
            'page_id' => $page_id,
            'page_owner_id' => $page_owner,
            'total_score' => self::DEFAULT_SCORE,
            'positive_score' => 0,
            'negative_score' => 0,
            'vote_count' => 0,
            'unique_voters' => 0,
            'confidence_score' => 0,
            'reputation_tier' => 'neutral', // Changed from 'insufficient_data' to 'neutral'
            'endorsement_count' => 0,
            'last_calculated_at' => current_time('mysql')
        ];

        $result = $wpdb->insert(
            $this->scores_table, 
            $default_data, 
            ['%d', '%d', '%f', '%f', '%f', '%d', '%d', '%f', '%s', '%d', '%s']
        );

        if ($result) {
            return (object) $default_data;
        }

        return false;
    }

    /**
     * Clear page score from cache
     *
     * @param int $page_id
     * @return bool
     */
    public function clear_page_cache($page_id) {
        return wp_cache_delete('page_score_' . $page_id, self::CACHE_GROUP);
    }

    /**
     * Clear all page score caches
     *
     * @return bool
     */
    public function clear_all_caches() {
        do_action('bcc_trust_clear_all_page_caches');
        return true;
    }

    /**
     * Get multiple page scores in one query
     *
     * @param array $page_ids
     * @return array
     */
    public function get_bulk_page_scores($page_ids) {
        if (empty($page_ids)) {
            return [];
        }

        global $wpdb;

        $placeholders = implode(',', array_fill(0, count($page_ids), '%d'));
        
        $scores = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->scores_table} 
                 WHERE page_id IN ({$placeholders})",
                $page_ids
            )
        );

        // Index by page_id for easy lookup
        $indexed_scores = [];
        foreach ($scores as $score) {
            $indexed_scores[$score->page_id] = $score;
        }

        // Fill in missing pages with default scores
        foreach ($page_ids as $page_id) {
            if (!isset($indexed_scores[$page_id])) {
                $default = $this->create_default_score($page_id);
                if ($default) {
                    $indexed_scores[$page_id] = $default;
                }
            }
        }

        return $indexed_scores;
    }

    /**
     * Get top pages by trust score
     *
     * @param int $limit
     * @param string $tier
     * @return array
     */
    public function get_top_pages($limit = 10, $tier = null) {
        global $wpdb;

        $where = '1=1';
        $params = [];

        if ($tier) {
            $where .= ' AND reputation_tier = %s';
            $params[] = $tier;
        }

        $params[] = $limit;

        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$this->scores_table} 
                 WHERE {$where}
                 ORDER BY total_score DESC, confidence_score DESC
                 LIMIT %d",
                $params
            )
        );
    }

    /**
     * Get pages with suspicious voting activity
     *
     * @param int $threshold
     * @return array
     */
    public function get_suspicious_pages($threshold = 30) {
        global $wpdb;

        return $wpdb->get_results($wpdb->prepare("
            SELECT s.*, 
                   (SELECT COUNT(*) FROM {$this->votes_table} v 
                    WHERE v.page_id = s.page_id 
                    AND v.status = 1) as vote_count,
                   (SELECT COUNT(*) FROM {$wpdb->usermeta} um
                    JOIN {$this->votes_table} v ON v.voter_user_id = um.user_id
                    WHERE v.page_id = s.page_id
                    AND um.meta_key = 'bcc_trust_fraud_score'
                    AND um.meta_value > %d) as suspicious_votes
            FROM {$this->scores_table} s
            HAVING suspicious_votes > 5
            ORDER BY suspicious_votes DESC
        ", $threshold));
    }

    /**
     * Log errors for debugging
     *
     * @param string $message
     * @param array $context
     */
    private function log_error($message, $context = []) {
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log(sprintf(
                'BCC Trust Error: %s | Context: %s',
                $message,
                json_encode($context)
            ));
        }

        if (function_exists('bcc_trust_log_audit')) {
            bcc_trust_log_audit('score_calculation_error', [
                'message' => $message,
                'context' => $context
            ]);
        }
    }

    /**
     * Magic method for debugging
     *
     * @return array
     */
    public function __debugInfo() {
        return [
            'votes_table' => $this->votes_table,
            'scores_table' => $this->scores_table,
            'endorsements_table' => $this->endorsements_table,
            'reputation_table' => $this->reputation_table,
            'fingerprint_table' => $this->fingerprint_table,
            'cache_group' => self::CACHE_GROUP,
            'default_score' => self::DEFAULT_SCORE
        ];
    }
}