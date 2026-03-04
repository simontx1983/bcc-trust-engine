<?php
/**
 * GitHub Verification Service
 *
 * Orchestrates the GitHub verification process
 *
 * @package BCC_Trust_Engine
 * @subpackage GitHub
 */

namespace BCCTrust\Services\github;

use Exception;
use BCCTrust\Repositories\GitHubRepository;
use BCCTrust\Security\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubVerificationService {

    private GitHubOAuthService $oauthService;
    private GitHubApiService $apiService;
    private GitHubScoreService $scoreService;
    private GitHubRepository $repository;

    public function __construct() {

        $this->oauthService = new GitHubOAuthService();
        $this->apiService = new GitHubApiService();
        $this->scoreService = new GitHubScoreService();
        $this->repository = new GitHubRepository();

    }

    /**
     * Get GitHub OAuth URL
     */
    public function getAuthUrl(): string {

        $userId = get_current_user_id();

        if (!$userId) {
            throw new Exception('User must be logged in');
        }

        return $this->oauthService->getAuthUrl();

    }

    /**
     * Verify GitHub user
     */
    public function verifyUser(int $userId, string $code): array {

        if (!$userId) {
            throw new Exception('Invalid user ID');
        }

        if (!$code) {
            throw new Exception('Missing OAuth code');
        }

        $user = get_userdata($userId);

        if (!$user) {
            throw new Exception('User not found');
        }

        try {

            // Exchange code for token
            $accessToken = $this->oauthService->getAccessToken($code);

            // Get GitHub API data
            $githubData = $this->apiService->getUserData($accessToken);

            if (!$githubData || empty($githubData['login'])) {
                throw new Exception('Invalid GitHub response');
            }

            /*
             Save connection first
             Repository normalizes the data
            */

            $saved = $this->repository->saveConnection(
                $userId,
                $githubData,
                $accessToken
            );

            if (!$saved) {
                throw new Exception('Failed to save GitHub connection');
            }

            /*
             Retrieve stored data (source of truth)
            */

            $stored = $this->repository->getConnection($userId);

            if (!$stored) {
                throw new Exception('Stored GitHub record missing');
            }

            /*
             Calculate trust from stored signals
            */

            $trustBoost = $this->scoreService->calculateTrustBoost((array)$stored);

            $fraudReduction = $this->scoreService->calculateFraudReduction(
                (array)$stored,
                $trustBoost
            );

            $this->repository->applyTrustBoost(
                $userId,
                $trustBoost,
                $fraudReduction
            );

            /*
             Audit log
            */

            if (class_exists(AuditLogger::class)) {

                AuditLogger::log('github_verified', $userId, [

                    'github_username' => $stored->github_username ?? $stored->github_login,
                    'trust_boost' => $trustBoost,
                    'fraud_reduction' => $fraudReduction

                ], 'user');

            }

            return [

                'success' => true,

                'github_username' => $stored->github_username ?? $stored->github_login,

                'trust_boost' => $trustBoost,

                'fraud_reduction' => $fraudReduction,

                'user_id' => $userId

            ];

        } catch (Exception $e) {

            if (class_exists(AuditLogger::class)) {

                AuditLogger::log('github_verification_failed', $userId, [

                    'error' => $e->getMessage()

                ], 'user');

            }

            throw $e;

        }

    }

    /**
     * Disconnect GitHub
     */
    public function disconnect(int $userId): bool {

        if (!$userId) {
            return false;
        }

        try {

            $connection = $this->repository->getConnection($userId);

            $username = $connection->github_username ?? $connection->github_login ?? 'unknown';

            $result = $this->repository->disconnect($userId);

            if ($result && class_exists(AuditLogger::class)) {

                AuditLogger::log('github_disconnected', $userId, [

                    'github_username' => $username

                ], 'user');

            }

            return $result;

        } catch (Exception $e) {

            return false;

        }

    }

}