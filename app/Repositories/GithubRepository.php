<?php

namespace BCCTrust\Repositories;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubRepository {

    private string $table;

    public function __construct() {
        $this->table = bcc_trust_user_info_table();
    }


    private function encryptToken(string $token): string {

        if (!defined('BCC_ENCRYPTION_KEY')) {
            return wp_hash($token);
        }

        $method = 'AES-256-CBC';

        $key = hash('sha256', BCC_ENCRYPTION_KEY, true);

        $iv = random_bytes(openssl_cipher_iv_length($method));

        $encrypted = openssl_encrypt(
            $token,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        return base64_encode($iv . $encrypted);
    }

    private function decryptToken(string $data): ?string {

        if (!defined('BCC_ENCRYPTION_KEY')) {
            return $data;
        }

        $method = 'AES-256-CBC';

        $key = hash('sha256', BCC_ENCRYPTION_KEY, true);

        $decoded = base64_decode($data);

        if ($decoded === false) {
            return null;
        }

        $ivLength = openssl_cipher_iv_length($method);

        $iv = substr($decoded, 0, $ivLength);

        $encrypted = substr($decoded, $ivLength);

        $decrypted = openssl_decrypt(
            $encrypted,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        return $decrypted !== false ? $decrypted : null;
    }

    /*
    |--------------------------------------------------------------------------
    | SAVE CONNECTION
    |--------------------------------------------------------------------------
    */

    public function saveConnection(int $userId, array $githubData, string $accessToken): bool {

        global $wpdb;

        $encryptedToken = $this->encryptToken($accessToken);

        // Get emails separately if not in user data
        $emails = $githubData['emails'] ?? [];

        $data = [

            'github_id' => $githubData['id'] ?? null,
            'github_username' => $githubData['login'] ?? null,
            'github_avatar' => $githubData['avatar_url'] ?? null,
            'github_followers' => $githubData['followers'] ?? 0,
            'github_public_repos' => $githubData['public_repos'] ?? 0,
            'github_org_count' => isset($githubData['organizations']) ? count($githubData['organizations']) : 0,
            'github_account_created' => isset($githubData['created_at']) ? date('Y-m-d H:i:s', strtotime($githubData['created_at'])) : null,
            'github_account_age_days' => isset($githubData['created_at'])
                ? $this->calculateAccountAge($githubData['created_at'])
                : 0,
            'github_has_verified_email' => $this->hasVerifiedEmail($emails),
            'github_verified_at' => current_time('mysql'),
            'github_last_synced' => current_time('mysql'),
            'github_access_token' => $encryptedToken

        ];

        $exists = $wpdb->get_var($wpdb->prepare(
            "SELECT user_id FROM {$this->table} WHERE user_id = %d",
            $userId
        ));

        if ($exists) {

            return $wpdb->update(
                $this->table,
                $data,
                ['user_id' => $userId],
                $this->getDataFormats($data),
                ['%d']
            ) !== false;

        }

        $data['user_id'] = $userId;

        return $wpdb->insert(
            $this->table,
            $data,
            $this->getDataFormats($data)
        ) !== false;

    }

    /*
    |--------------------------------------------------------------------------
    | GET CONNECTION
    |--------------------------------------------------------------------------
    */

    public function getConnection(int $userId): ?object {

        global $wpdb;

        $row = $wpdb->get_row($wpdb->prepare(

            "SELECT
                github_id,
                github_username,
                github_avatar,
                github_followers,
                github_public_repos,
                github_org_count,
                github_account_created,
                github_account_age_days,
                github_has_verified_email,
                github_trust_boost,
                github_fraud_reduction,
                github_access_token,
                github_verified_at,
                github_last_synced
            FROM {$this->table}
            WHERE user_id = %d",

            $userId

        ));

        if ($row && $row->github_access_token) {

            $row->github_access_token_decrypted =
                $this->decryptToken($row->github_access_token);

        }

        return $row;

    }

    /*
    |--------------------------------------------------------------------------
    | DISCONNECT
    |--------------------------------------------------------------------------
    */

    public function disconnect(int $userId): bool {

        global $wpdb;

        return $wpdb->update(

            $this->table,

            [
                'github_id' => null,
                'github_username' => null,
                'github_avatar' => null,
                'github_access_token' => null,
                'github_trust_boost' => 0,
                'github_fraud_reduction' => 0,
                'github_followers' => 0,
                'github_public_repos' => 0,
                'github_org_count' => 0,
                'github_account_created' => null,
                'github_account_age_days' => 0,
                'github_has_verified_email' => 0,
                'github_verified_at' => null,
                'github_last_synced' => null
            ],

            ['user_id' => $userId],

            [
                '%d', '%s', '%s', '%s', '%f', '%d', '%d', '%d', 
                '%d', '%d', '%d', '%d', '%s', '%s'
            ],

            ['%d']

        ) !== false;

    }

    /*
    |--------------------------------------------------------------------------
    | APPLY TRUST BOOST
    |--------------------------------------------------------------------------
    */

    public function applyTrustBoost(int $userId, float $trustBoost, int $fraudReduction): bool {

        global $wpdb;

        return $wpdb->query($wpdb->prepare(

            "UPDATE {$this->table}
             SET
                github_trust_boost = %f,
                github_fraud_reduction = %d
             WHERE user_id = %d",

            $trustBoost,
            $fraudReduction,
            $userId

        )) !== false;

    }

    /**
     * Get format types for database columns
     */
    private function getDataFormats(array $data): array {
        $formats = [];
        foreach ($data as $key => $value) {
            if (in_array($key, ['github_id', 'github_followers', 'github_public_repos', 
                               'github_org_count', 'github_account_age_days', 
                               'github_has_verified_email', 'github_fraud_reduction'])) {
                $formats[] = '%d';
            } elseif (in_array($key, ['github_trust_boost'])) {
                $formats[] = '%f';
            } else {
                $formats[] = '%s';
            }
        }
        return $formats;
    }

    private function calculateAccountAge(string $createdAt): int {

        $created = strtotime($createdAt);

        return (int)((time() - $created) / DAY_IN_SECONDS);

    }

    private function hasVerifiedEmail(array $emails): int {

        foreach ($emails as $email) {

            if (!empty($email['verified'])) {
                return 1;
            }

        }

        return 0;

    }

}