<?php
/**
 * GitHub Controller
 *
 * Handles GitHub OAuth authentication and verification
 *
 * @package BCC_Trust_Engine
 * @subpackage Controllers
 * @version 2.3.0
 */

namespace BCCTrust\Controllers;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Exception;

use BCCTrust\Services\github\GitHubOAuthService;
use BCCTrust\Services\github\GitHubApiService;
use BCCTrust\Services\github\GitHubScoreService;
use BCCTrust\Repositories\GitHubRepository;
use BCCTrust\Security\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubController {

    /**
     * Register REST routes
     */
    public static function register_routes() {

        register_rest_route('bcc-trust/v1', '/github/auth', [
            'methods' => 'GET',
            'callback' => [self::class, 'getAuthUrl'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        register_rest_route('bcc-trust/v1', '/github/callback', [
            'methods' => 'GET',
            'callback' => [self::class, 'handleCallback'],
            'permission_callback' => '__return_true'
        ]);

        register_rest_route('bcc-trust/v1', '/github/status', [
            'methods' => 'GET',
            'callback' => [self::class, 'getStatus'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        register_rest_route('bcc-trust/v1', '/github/disconnect', [
            'methods' => 'POST',
            'callback' => [self::class, 'disconnect'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

        register_rest_route('bcc-trust/v1', '/github/refresh', [
            'methods' => 'POST',
            'callback' => [self::class, 'refreshData'],
            'permission_callback' => [self::class, 'permission_check']
        ]);

    }

    /**
     * Permission check
     */
    public static function permission_check(): bool {
        return is_user_logged_in();
    }

    /**
     * Generate GitHub OAuth URL
     */
    public static function getAuthUrl() {

        try {

            $userId = get_current_user_id();

            if (!$userId) {
                return new WP_Error('not_logged_in', 'You must be logged in', ['status' => 401]);
            }

            $oauth = new GitHubOAuthService();

            if (!$oauth->isConfigured()) {
                return new WP_Error('github_not_configured', 'GitHub OAuth not configured', ['status' => 500]);
            }

            // Let the service generate the state - don't create it here
            $authUrl = $oauth->getAuthUrl();
            
            error_log('GitHub auth URL generated for user ' . $userId);

            return new WP_REST_Response([
                'success' => true,
                'data' => [
                    'auth_url' => $authUrl
                ]
            ], 200);

        } catch (Exception $e) {

            error_log('GitHub auth error: ' . $e->getMessage());

            return new WP_Error('github_error', $e->getMessage(), ['status' => 500]);
        }

    }

    /**
     * Handle OAuth callback
     */
    public static function handleCallback(WP_REST_Request $request) {

        try {

            $code = $request->get_param('code');
            $state = $request->get_param('state');

            error_log('GitHub callback - Code: ' . ($code ? 'present' : 'missing') . ', State: ' . $state);

            if (!$code || !$state) {
                throw new Exception('Missing OAuth parameters');
            }

            // Use the OAuth service to validate the state
            $oauth = new GitHubOAuthService();
            
            $validation = $oauth->validateState($state);
            
            if (!$validation) {
                error_log('GitHub callback - State validation failed');
                throw new Exception('OAuth state verification failed');
            }

            $userId = $validation['user_id'];
            error_log('GitHub callback - Validated user ID: ' . $userId);

            // Verify user exists
            $user = get_userdata($userId);
            if (!$user) {
                error_log('GitHub callback - User not found: ' . $userId);
                throw new Exception('User not found');
            }

            // Exchange code for token
            error_log('GitHub callback - Exchanging code for token');
            $accessToken = $oauth->getAccessToken($code);

            if (!$accessToken) {
                throw new Exception('Failed to retrieve GitHub access token');
            }

            // Get GitHub user data
            $api = new GitHubApiService();
            error_log('GitHub callback - Fetching user data');
            $githubData = $api->getUserData($accessToken);

            if (empty($githubData['login'])) {
                error_log('GitHub callback - Invalid user data');
                throw new Exception('GitHub user data invalid');
            }

            error_log('GitHub callback - User: ' . $githubData['login']);

            // Save connection
            $repo = new GitHubRepository();
            $repo->saveConnection($userId, $githubData, $accessToken);

            // Calculate scores
            $score = new GitHubScoreService();
            $trustBoost = $score->calculateTrustBoost($githubData);
            $fraudReduction = $score->calculateFraudReduction($githubData, $trustBoost);

            // Apply trust boost
            $repo->applyTrustBoost($userId, $trustBoost, $fraudReduction);

            // Log the event
            if (class_exists('BCCTrust\\Security\\AuditLogger')) {
                AuditLogger::log('github_verified', $userId, [
                    'username' => $githubData['login'],
                    'trust_boost' => $trustBoost,
                    'fraud_reduction' => $fraudReduction,
                    'followers' => $githubData['followers'] ?? 0,
                    'repos' => $githubData['public_repos'] ?? 0
                ], 'user');
            }

            // Get the return URL from session or use profile page
            $return_url = home_url('/profile/');
            
            // Add success parameter
            $redirect_url = add_query_arg('github_verified', 'success', $return_url);
            
            // Redirect back to the site
            wp_redirect($redirect_url);
            exit;

        } catch (Exception $e) {

            error_log('GitHub callback error: ' . $e->getMessage());

            // Clean up any stored state
            if (isset($userId)) {
                delete_transient('bcc_github_state_' . $userId);
                delete_transient('bcc_github_nonce_' . $userId);
            }

            // Get the return URL from session or use home page
            $return_url = home_url('/');
            
            // Add error parameter
            $redirect_url = add_query_arg('github_verified', 'error', $return_url);
            
            // Redirect back to the site
            wp_redirect($redirect_url);
            exit;
        }

    }

    /**
     * Get GitHub connection status
     */
    public static function getStatus() {

        try {

            $userId = get_current_user_id();

            if (!$userId) {
                return new WP_Error('not_logged_in', 'You must be logged in', ['status' => 401]);
            }

            $repo = new GitHubRepository();

            $connection = $repo->getConnection($userId);

            if (!$connection || !$connection->github_username) {

                return new WP_REST_Response([
                    'success' => true,
                    'data' => [
                        'connected' => false,
                        'user_id' => $userId
                    ]
                ], 200);

            }

            return new WP_REST_Response([
                'success' => true,
                'data' => [
                    'connected' => true,
                    'username' => $connection->github_username,
                    'verified_at' => $connection->github_verified_at,
                    'last_synced' => $connection->github_last_synced,
                    'followers' => $connection->github_followers ?? 0,
                    'repos' => $connection->github_public_repos ?? 0,
                    'orgs' => $connection->github_org_count ?? 0,
                    'user_id' => $userId
                ]
            ], 200);

        } catch (Exception $e) {

            return new WP_Error('github_error', $e->getMessage(), ['status' => 500]);

        }

    }

    /**
     * Disconnect GitHub
     */
    public static function disconnect() {

        try {

            $userId = get_current_user_id();

            if (!$userId) {
                return new WP_Error('not_logged_in', 'Login required', ['status' => 401]);
            }

            $repo = new GitHubRepository();

            $connection = $repo->getConnection($userId);

            $username = $connection->github_username ?? 'unknown';

            $repo->disconnect($userId);

            if (class_exists('BCCTrust\\Security\\AuditLogger')) {

                AuditLogger::log('github_disconnected', $userId, [
                    'username' => $username
                ], 'user');

            }

            return new WP_REST_Response([
                'success' => true,
                'data' => [
                    'disconnected' => true,
                    'username' => $username
                ]
            ], 200);

        } catch (Exception $e) {

            return new WP_Error('github_error', $e->getMessage(), ['status' => 500]);

        }

    }

    /**
     * Refresh GitHub data
     */
    public static function refreshData() {

        try {

            $userId = get_current_user_id();

            if (!$userId) {
                return new WP_Error('not_logged_in', 'Login required', ['status' => 401]);
            }

            $repo = new GitHubRepository();
            $api = new GitHubApiService();
            $score = new GitHubScoreService();

            $connection = $repo->getConnection($userId);

            if (!$connection || !$connection->github_username) {
                return new WP_Error('not_connected', 'GitHub not connected', ['status' => 400]);
            }

            $accessToken = $connection->github_access_token_decrypted ?? null;

            if (!$accessToken) {
                throw new Exception('GitHub token missing');
            }

            $githubData = $api->getUserData($accessToken);

            $repo->saveConnection($userId, $githubData, $accessToken);

            $trustBoost = $score->calculateTrustBoost($githubData);
            $fraudReduction = $score->calculateFraudReduction($githubData, $trustBoost);

            $repo->applyTrustBoost($userId, $trustBoost, $fraudReduction);

            return new WP_REST_Response([
                'success' => true,
                'data' => [
                    'refreshed' => true,
                    'username' => $githubData['login'],
                    'trust_boost' => $trustBoost,
                    'fraud_reduction' => $fraudReduction
                ]
            ], 200);

        } catch (Exception $e) {

            return new WP_Error('github_error', $e->getMessage(), ['status' => 500]);

        }

    }

}