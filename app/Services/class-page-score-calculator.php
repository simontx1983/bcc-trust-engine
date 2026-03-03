<?php
/**
 * Legacy Page Score Calculator
 * 
 * Wraps the new PageScore value object for backward compatibility
 * This allows existing code to continue working during the transition
 * 
 * @package BCC_Trust_Engine
 * @subpackage Services
 * @version 2.0.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class BCC_Page_Score_Calculator {
    
    /**
     * @var \BCCTrust\Repositories\ScoreRepository
     */
    private $scoreRepo;
    
    /**
     * @var \BCCTrust\Repositories\VoteRepository
     */
    private $voteRepo;
    
    /**
     * @var \BCCTrust\Repositories\EndorsementRepository
     */
    private $endorseRepo;
    
    /**
     * @var \BCCTrust\Repositories\UserInfoRepository
     */
    private $userInfoRepo;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->scoreRepo = new \BCCTrust\Repositories\ScoreRepository();
        $this->voteRepo = new \BCCTrust\Repositories\VoteRepository();
        $this->endorseRepo = new \BCCTrust\Repositories\EndorsementRepository();
        $this->userInfoRepo = new \BCCTrust\Repositories\UserInfoRepository();
    }
    
    /**
     * Get page score (legacy method)
     * 
     * @param int $page_id
     * @param bool $force_recalculate
     * @return object|false
     */
    public function get_page_score($page_id, $force_recalculate = false) {
        $score = $this->scoreRepo->getByPageId($page_id);
        
        if (!$score) {
            return false;
        }
        
        // Convert to legacy object format with properties
        return (object) [
            'page_id' => $score->getPageId(),
            'page_owner_id' => $score->getPageOwnerId(),
            'total_score' => $score->getTotalScore(),
            'positive_score' => $score->getPositiveScore(),
            'negative_score' => $score->getNegativeScore(),
            'vote_count' => $score->getVoteCount(),
            'unique_voters' => $score->getUniqueVoters(),
            'confidence_score' => $score->getConfidenceScore(),
            'reputation_tier' => $score->getReputationTier(),
            'endorsement_count' => $score->getEndorsementCount(),
            'last_vote_at' => $score->getLastVoteAt() ? $score->getLastVoteAt()->format('Y-m-d H:i:s') : null,
            'last_calculated_at' => $score->getLastCalculatedAt()->format('Y-m-d H:i:s'),
            'has_fraud_alerts' => $score->hasFraudAlerts(),
            'fraud_alert_count' => $score->getFraudAlertCount()
        ];
    }
    
    /**
     * Recalculate page score (legacy method)
     * 
     * @param int $page_id
     * @return object|false
     */
    public function recalculate_page_score($page_id) {
        try {
            // Get all active votes
            $votes = $this->voteRepo->getAllForPage($page_id);
            
            // Get page owner
            $owner_id = $this->get_page_owner($page_id);
            
            if (!$owner_id) {
                return false;
            }
            
            // Calculate scores
            $positive = 0;
            $negative = 0;
            $voter_ids = [];
            $last_vote_at = null;
            
            foreach ($votes as $vote) {
                $effective_weight = $this->apply_time_decay($vote->weight, $vote->created_at);
                
                if ($vote->vote_type > 0) {
                    $positive += $effective_weight;
                } else {
                    $negative += $effective_weight;
                }
                
                $voter_ids[$vote->voter_user_id] = true;
                
                if (!$last_vote_at || strtotime($vote->created_at) > strtotime($last_vote_at)) {
                    $last_vote_at = $vote->created_at;
                }
            }
            
            $vote_count = count($votes);
            $unique_voters = count($voter_ids);
            
            // Calculate total score
            $net_score = $positive - $negative;
            $total_score = 50 + ($net_score * 2);
            $total_score = max(0, min(100, $total_score));
            
            // Calculate confidence
            $confidence_score = $this->calculate_confidence_score($vote_count, $unique_voters, $positive, $negative);
            
            // Determine tier
            $tier = $this->determine_tier($total_score);
            
            // Get endorsement count
            $endorsement_count = $this->endorseRepo->countForPage($page_id);
            
            // Get existing score or create new one
            $current_score = $this->scoreRepo->getByPageId($page_id);
            
            if (!$current_score) {
                // Create new using the value object
                $new_score = \BCCTrust\ValueObjects\PageScore::createDefault($page_id, $owner_id);
                $this->scoreRepo->save($new_score);
                $current_score = $new_score;
            }
            
            // Update with new values using immutable transformation
            // Since we can't easily rebuild a PageScore with all these values,
            // we'll use the repository's update method for legacy compatibility
            
            global $wpdb;
            $scores_table = bcc_trust_scores_table();
            
            $wpdb->update(
                $scores_table,
                [
                    'total_score' => $total_score,
                    'positive_score' => $positive,
                    'negative_score' => $negative,
                    'vote_count' => $vote_count,
                    'unique_voters' => $unique_voters,
                    'confidence_score' => $confidence_score,
                    'reputation_tier' => $tier,
                    'endorsement_count' => $endorsement_count,
                    'last_vote_at' => $last_vote_at,
                    'last_calculated_at' => current_time('mysql')
                ],
                ['page_id' => $page_id],
                ['%f', '%f', '%f', '%d', '%d', '%f', '%s', '%d', '%s', '%s'],
                ['%d']
            );
            
            // Get and return the updated score
            return $this->get_page_score($page_id);
            
        } catch (Exception $e) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('BCC Trust Legacy Calculator Error: ' . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * Clear page cache (legacy method)
     * 
     * @param int $page_id
     * @return bool
     */
    public function clear_page_cache($page_id) {
        // The new system doesn't use cache for scores,
        // but we'll keep this method for compatibility
        return true;
    }
    
    /**
     * Clear all page caches (legacy method)
     * 
     * @return bool
     */
    public function clear_all_caches() {
        return true;
    }
    
    /**
     * Get bulk page scores (legacy method)
     * 
     * @param array $page_ids
     * @return array
     */
    public function get_bulk_page_scores($page_ids) {
        $scores = $this->scoreRepo->getBulk($page_ids);
        
        $result = [];
        foreach ($scores as $page_id => $score) {
            $result[$page_id] = (object) [
                'page_id' => $score->getPageId(),
                'page_owner_id' => $score->getPageOwnerId(),
                'total_score' => $score->getTotalScore(),
                'positive_score' => $score->getPositiveScore(),
                'negative_score' => $score->getNegativeScore(),
                'vote_count' => $score->getVoteCount(),
                'unique_voters' => $score->getUniqueVoters(),
                'confidence_score' => $score->getConfidenceScore(),
                'reputation_tier' => $score->getReputationTier(),
                'endorsement_count' => $score->getEndorsementCount(),
                'has_fraud_alerts' => $score->hasFraudAlerts()
            ];
        }
        
        return $result;
    }
    
    /**
     * Get top pages (legacy method)
     * 
     * @param int $limit
     * @param string $tier
     * @return array
     */
    public function get_top_pages($limit = 10, $tier = null) {
        if ($tier) {
            $pages = $this->scoreRepo->getByTier($tier, $limit);
        } else {
            $pages = $this->scoreRepo->getTopScored($limit);
        }
        
        $result = [];
        foreach ($pages as $page) {
            $result[] = (object) [
                'page_id' => $page->getPageId(),
                'page_owner_id' => $page->getPageOwnerId(),
                'total_score' => $page->getTotalScore(),
                'positive_score' => $page->getPositiveScore(),
                'negative_score' => $page->getNegativeScore(),
                'vote_count' => $page->getVoteCount(),
                'unique_voters' => $page->getUniqueVoters(),
                'confidence_score' => $page->getConfidenceScore(),
                'reputation_tier' => $page->getReputationTier(),
                'endorsement_count' => $page->getEndorsementCount(),
                'has_fraud_alerts' => $page->hasFraudAlerts()
            ];
        }
        
        return $result;
    }
    
    /**
     * Get suspicious pages (legacy method) - FIXED to use user_info table
     * 
     * @param int $threshold
     * @return array
     */
    public function get_suspicious_pages($threshold = 30) {
        global $wpdb;
        
        $scores_table = bcc_trust_scores_table();
        $votes_table = bcc_trust_votes_table();
        $user_info_table = bcc_trust_user_info_table();
        
        return $wpdb->get_results($wpdb->prepare("
            SELECT s.*, 
                   (SELECT COUNT(*) FROM {$votes_table} v 
                    WHERE v.page_id = s.page_id 
                    AND v.status = 1) as vote_count,
                   (SELECT COUNT(*) FROM {$user_info_table} ui
                    JOIN {$votes_table} v ON v.voter_user_id = ui.user_id
                    WHERE v.page_id = s.page_id
                    AND ui.fraud_score > %d) as suspicious_votes
            FROM {$scores_table} s
            HAVING suspicious_votes > 5
            ORDER BY suspicious_votes DESC
        ", $threshold));
    }
    
    /**
     * ======================================================
     * PRIVATE HELPER METHODS
     * ======================================================
     */
    
    /**
     * Apply time decay to vote weight
     */
    private function apply_time_decay($weight, $vote_date) {
        $vote_time = strtotime($vote_date);
        $now = time();
        $days_old = ($now - $vote_time) / (24 * 3600);
        
        if ($days_old > defined('BCC_TRUST_DECAY_DAYS') ? BCC_TRUST_DECAY_DAYS : 90) {
            return 0;
        }
        
        $decay_min = defined('BCC_TRUST_DECAY_MIN') ? BCC_TRUST_DECAY_MIN : 0.3;
        $decay_days = defined('BCC_TRUST_DECAY_DAYS') ? BCC_TRUST_DECAY_DAYS : 90;
        
        $decay_factor = max($decay_min, 1 - ($days_old / $decay_days));
        return $weight * $decay_factor;
    }
    
    /**
     * Calculate confidence score
     */
    private function calculate_confidence_score($vote_count, $unique_voters, $positive, $negative) {
        if ($vote_count === 0) {
            return 0;
        }
        
        $volume_confidence = min(1, $vote_count / 50);
        $diversity_confidence = $unique_voters / $vote_count;
        
        $total_weight = $positive + $negative;
        $balance_confidence = 1.0;
        if ($total_weight > 0) {
            $balance = abs($positive - $negative) / $total_weight;
            $balance_confidence = 1 - ($balance * 0.5);
        }
        
        return round(
            ($volume_confidence * 0.5) +
            ($diversity_confidence * 0.3) +
            ($balance_confidence * 0.2),
            2
        );
    }
    
    /**
     * Determine reputation tier
     */
    private function determine_tier($score) {
        if ($score >= 80) return 'elite';
        if ($score >= 65) return 'trusted';
        if ($score >= 45) return 'neutral';
        if ($score >= 30) return 'caution';
        return 'risky';
    }
    
    /**
     * Get page owner
     */
    private function get_page_owner($page_id) {
        if (function_exists('bcc_trust_get_page_owner')) {
            $owner_id = bcc_trust_get_page_owner($page_id);
            if ($owner_id) {
                return $owner_id;
            }
        }
        
        $post = get_post($page_id);
        return $post ? $post->post_author : 0;
    }
    
    /**
     * Magic method for debugging
     */
    public function __debugInfo() {
        return [
            'class' => 'BCC_Page_Score_Calculator (Legacy Wrapper)',
            'note' => 'This class wraps the new PageScore value object for backward compatibility'
        ];
    }
}