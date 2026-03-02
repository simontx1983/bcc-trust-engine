<?php
namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) exit;

class ReputationRepository {
    private string $table;

    public function __construct() {
        global $wpdb;
        $this->table = $wpdb->prefix . 'bcc_trust_reputation';
    }

    public function getByUserId(int $userId): ?object {
        global $wpdb;
        return $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->table} WHERE user_id = %d",
            $userId
        ));
    }
public function createOrUpdate(int $userId, array $data): void {
    global $wpdb;
    
    $exists = $this->getByUserId($userId);
    
    $defaults = [
        'reputation_score' => 50.00,
        'total_votes_cast' => 0,
        'total_votes_received' => 0,
        'flag_count' => 0,
        'vote_weight' => 1.0,
        'reputation_tier' => 'neutral', // Always start at neutral
        'last_calculated_at' => current_time('mysql')
    ];
    
    $data = array_merge($defaults, $data);
    
    if ($exists) {
        $wpdb->update(
            $this->table,
            $data,
            ['user_id' => $userId],
            null,
            ['%d']
        );
    } else {
        $data['user_id'] = $userId;
        $wpdb->insert($this->table, $data);
    }
}
}