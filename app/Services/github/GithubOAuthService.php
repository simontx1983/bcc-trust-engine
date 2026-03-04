<?php
/**
 * GitHub OAuth Service
 *
 * Handles GitHub OAuth authentication flow
 *
 * @package BCC_Trust_Engine
 * @subpackage GitHub
 * @version 2.3.1
 */

namespace BCCTrust\Services\github;

use Exception;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubOAuthService {

    private const AUTH_URL  = 'https://github.com/login/oauth/authorize';
    private const TOKEN_URL = 'https://github.com/login/oauth/access_token';

    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;

    /**
     * Constructor
     */
    public function __construct() {

        $this->clientId     = defined('BCC_GITHUB_CLIENT_ID') ? BCC_GITHUB_CLIENT_ID : '';
        $this->clientSecret = defined('BCC_GITHUB_CLIENT_SECRET') ? BCC_GITHUB_CLIENT_SECRET : '';
        $this->redirectUri  = rest_url('bcc-trust/v1/github/callback');

        if (defined('WP_DEBUG') && WP_DEBUG) {

            if (!$this->clientId) {
                error_log('BCC Trust GitHub: Client ID missing');
            }

            if (!$this->clientSecret) {
                error_log('BCC Trust GitHub: Client Secret missing');
            }

        }
    }

    /**
     * Generate GitHub OAuth authorization URL
     */
    public function getAuthUrl(?string $state = null): string {

        if (!$state) {

            $userId = get_current_user_id();

            if (!$userId) {
                throw new Exception('User must be logged in to initiate GitHub OAuth');
            }

            // Create a unique state parameter
            $nonce = wp_create_nonce('bcc_github_oauth_' . $userId);
            $state = "bcc_github_{$userId}_{$nonce}";
            
            // Store in transient instead of user meta (better for temporary data)
            set_transient('bcc_github_state_' . $userId, $state, 600); // 10 minutes
            set_transient('bcc_github_nonce_' . $userId, $nonce, 600);
            
            error_log('GitHub OAuth: Generated state for user ' . $userId . ': ' . $state);
        }

        $params = [
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'scope'         => 'read:user user:email read:org',
            'state'         => $state,
            'allow_signup'  => 'false'
        ];

        return self::AUTH_URL . '?' . http_build_query($params);
    }

    /**
     * Exchange authorization code for access token
     */
    public function getAccessToken(string $code): string {

        if (!$this->isConfigured()) {
            throw new Exception('GitHub OAuth credentials not configured');
        }

        if (!$code) {
            throw new Exception('Missing authorization code');
        }

        $response = wp_remote_post(self::TOKEN_URL, [
            'body' => [
                'client_id'     => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code'          => $code,
                'redirect_uri'  => $this->redirectUri
            ],
            'headers' => [
                'Accept' => 'application/json'
            ],
            'timeout' => 30
        ]);

        if (is_wp_error($response)) {
            throw new Exception(
                'GitHub token request failed: ' . $response->get_error_message()
            );
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (!empty($data['error'])) {
            $msg = $data['error_description'] ?? $data['error'];
            throw new Exception('GitHub OAuth error: ' . $msg);
        }

        if (empty($data['access_token'])) {
            throw new Exception('No access token returned from GitHub');
        }

        return $data['access_token'];
    }

  /**
 * Validate OAuth state parameter
 * 
 * @param string $state The state parameter from GitHub callback
 * @return array|false Returns array with user_id if valid, false otherwise
 */
public function validateState(string $state) {
    error_log('GitHub OAuth: Validating state: ' . $state);
    
    if (!$state) {
        error_log('GitHub OAuth: No state parameter provided');
        return false;
    }

    // Extract user + nonce
    if (!preg_match('/^bcc_github_(\d+)_([a-f0-9]+)$/', $state, $matches)) {
        error_log('GitHub OAuth: invalid state format -> ' . $state);
        return false;
    }

    $userId = (int) $matches[1];
    $nonce = $matches[2];

    error_log('GitHub OAuth: Extracted user ID: ' . $userId . ', nonce: ' . $nonce);

    // Get stored state from transient
    $storedState = get_transient('bcc_github_state_' . $userId);
    $storedNonce = get_transient('bcc_github_nonce_' . $userId);

    error_log('GitHub OAuth: Stored state: ' . ($storedState ?: 'none') . ', Stored nonce: ' . ($storedNonce ?: 'none'));

    // FOR OAuth CALLBACKS: Just verify against stored values, don't use wp_verify_nonce()
    // Nonces don't work across different sessions/windows
    if ($storedState === $state && $storedNonce === $nonce) {
        error_log('GitHub OAuth: State validation successful for user ' . $userId);
        
        // Clean up used state
        delete_transient('bcc_github_state_' . $userId);
        delete_transient('bcc_github_nonce_' . $userId);
        
        return [
            'user_id' => $userId
        ];
    }

    error_log('GitHub OAuth: verification failed for user ' . $userId);
    
    // Clean up failed state
    delete_transient('bcc_github_state_' . $userId);
    delete_transient('bcc_github_nonce_' . $userId);
    
    return false;
}

    /**
     * Extract user ID from state parameter without validation
     * 
     * @param string $state The state parameter from GitHub callback
     * @return int User ID or 0 if not found
     */
    public function extractUserIdFromState(string $state): int {
        if (preg_match('/^bcc_github_(\d+)_/', $state, $matches)) {
            return (int) $matches[1];
        }
        return 0;
    }

    /**
     * Check if OAuth is configured
     * 
     * @return bool
     */
    public function isConfigured(): bool {
        return !empty($this->clientId) && !empty($this->clientSecret);
    }
}