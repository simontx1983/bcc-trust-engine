<?php

namespace BCCTrust\Services\github;

use Exception;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubApiService {

    private const API_BASE = 'https://api.github.com';
    private const USER_AGENT = 'BCC-Trust-Engine';
    private const TIMEOUT = 30;

    /**
     * Get user data from GitHub
     */
    public function getUserData(string $accessToken): array {

        $user = $this->makeRequest('/user', $accessToken);

        $orgs = $this->getUserOrgs($accessToken);

        return [

            'id' => (int) ($user['id'] ?? 0),

            'login' => $user['login'] ?? '',

            'avatar_url' => $user['avatar_url'] ?? '',

            'followers' => (int) ($user['followers'] ?? 0),

            'public_repos' => (int) ($user['public_repos'] ?? 0),

            'created_at' => $user['created_at'] ?? '',

            'email' => $user['email'] ?? '',

            'organizations' => $orgs,

            'type' => $user['type'] ?? 'User'

        ];
    }

    /**
     * GitHub request helper
     */
    private function makeRequest(string $endpoint, string $accessToken): array {

        $response = wp_remote_get(self::API_BASE . $endpoint, [

            'headers' => [

                'Authorization' => 'token ' . $accessToken,

                'Accept' => 'application/vnd.github.v3+json',

                'User-Agent' => self::USER_AGENT,

                'X-GitHub-Api-Version' => '2022-11-28'

            ],

            'timeout' => self::TIMEOUT

        ]);

        if (is_wp_error($response)) {

            throw new Exception($response->get_error_message());

        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code !== 200) {

            throw new Exception('GitHub API error ' . $code);

        }

        return json_decode(wp_remote_retrieve_body($response), true);

    }

    /**
     * Get organizations
     */
    private function getUserOrgs(string $accessToken): array {

        try {

            return $this->makeRequest('/user/orgs', $accessToken);

        } catch (Exception $e) {

            return [];

        }

    }

    /**
     * Check if verified email exists
     */
    public function hasVerifiedEmail(array $githubData): bool {

        return !empty($githubData['email']);

    }

    /**
     * Account age
     */
    public function getAccountAge(array $githubData): int {

        if (empty($githubData['created_at'])) {
            return 0;
        }

        return (int)((time() - strtotime($githubData['created_at'])) / DAY_IN_SECONDS);

    }

}