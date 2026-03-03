<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

class FraudAnalysisRepository {
    
    private string $table;
    
    public function __construct() {
        $this->table = bcc_trust_fraud_analysis_table();
    }
    
    /**
     * Store fraud analysis result
     */
    public function storeAnalysis(int $userId, int $fraudScore, string $riskLevel, float $confidence, array $triggers, array $details = [], ?string $expiresAt = null): int {
        global $wpdb;
        
        $wpdb->insert(
            $this->table,
            [
                'user_id' => $userId,
                'fraud_score' => $fraudScore,
                'risk_level' => $riskLevel,
                'confidence' => $confidence,
                'triggers' => json_encode($triggers),
                'details' => !empty($details) ? json_encode($details) : null,
                'analyzed_at' => current_time('mysql'),
                'expires_at' => $expiresAt
            ],
            ['%d', '%d', '%s', '%f', '%s', '%s', '%s', '%s']
        );
        
        return $wpdb->insert_id;
    }
    
    /**
     * Get analysis history for user
     */
    public function getHistoryForUser(int $userId, int $limit = 10): array {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->table}
             WHERE user_id = %d
             ORDER BY analyzed_at DESC
             LIMIT %d",
            $userId,
            $limit
        ));
    }
    
    /**
     * Get most recent analysis for user
     */
    public function getLatestForUser(int $userId): ?object {
        global $wpdb;
        
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table}
             WHERE user_id = %d
             ORDER BY analyzed_at DESC
             LIMIT 1",
            $userId
        ));
    }
    
    /**
     * Delete old analyses
     */
    public function deleteExpired(): int {
        global $wpdb;
        
        return $wpdb->query(
            "DELETE FROM {$this->table}
             WHERE expires_at < NOW()"
        );
    }
}