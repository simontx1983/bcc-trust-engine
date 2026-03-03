<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

class PatternRepository {
    
    private string $table;
    
    public function __construct() {
        $this->table = bcc_trust_patterns_table();
    }
    
    /**
     * Store behavioral pattern
     */
    public function storePattern(int $userId, string $type, array $data, float $confidence = 1.0, ?string $expiresAt = null): int {
        global $wpdb;
        
        $wpdb->insert(
            $this->table,
            [
                'user_id' => $userId,
                'pattern_type' => $type,
                'pattern_data' => json_encode($data),
                'confidence' => $confidence,
                'detected_at' => current_time('mysql'),
                'expires_at' => $expiresAt ?? date('Y-m-d H:i:s', strtotime('+30 days'))
            ],
            ['%d', '%s', '%s', '%f', '%s', '%s']
        );
        
        return $wpdb->insert_id;
    }
    
    /**
     * Get patterns for user
     */
    public function getUserPatterns(int $userId, ?string $type = null, int $limit = 50): array {
        global $wpdb;
        
        $sql = "SELECT * FROM {$this->table} WHERE user_id = %d";
        $params = [$userId];
        
        if ($type) {
            $sql .= " AND pattern_type = %s";
            $params[] = $type;
        }
        
        $sql .= " ORDER BY detected_at DESC LIMIT %d";
        $params[] = $limit;
        
        return $wpdb->get_results($wpdb->prepare($sql, $params));
    }
    
    /**
     * Get most common pattern types
     */
    public function getMostCommonTypes(int $limit = 10): array {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT pattern_type, COUNT(*) as count, AVG(confidence) as avg_confidence
             FROM {$this->table}
             GROUP BY pattern_type
             ORDER BY count DESC
             LIMIT %d",
            $limit
        ));
    }
    
    /**
     * Get most common behavior flags
     */
    public function getMostCommonFlags(int $limit = 10): array {
        global $wpdb;
        
        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT pattern_data FROM {$this->table}
             WHERE pattern_type = 'suspicious_behavior'
             ORDER BY detected_at DESC
             LIMIT 1000",
            $limit
        ));
        
        $flagCounts = [];
        foreach ($results as $row) {
            $data = json_decode($row->pattern_data, true);
            if (isset($data['flags']) && is_array($data['flags'])) {
                foreach ($data['flags'] as $flag) {
                    $flagCounts[$flag] = ($flagCounts[$flag] ?? 0) + 1;
                }
            }
        }
        
        arsort($flagCounts);
        return array_slice($flagCounts, 0, $limit, true);
    }
    
    /**
     * Delete expired patterns
     */
    public function deleteExpired(): int {
        global $wpdb;
        
        return $wpdb->query(
            "DELETE FROM {$this->table}
             WHERE expires_at < NOW()"
        );
    }
}