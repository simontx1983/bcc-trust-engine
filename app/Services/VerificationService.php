<?php
namespace BCCTrust\Services;

use Exception;
use BCCTrust\Repositories\VerificationRepository;
use BCCTrust\Repositories\UserInfoRepository;
use BCCTrust\Security\RateLimiter;
use BCCTrust\Security\AuditLogger;

if (!defined('ABSPATH')) {
    exit;
}

class VerificationService {

    private VerificationRepository $repo;
    private UserInfoRepository $userInfoRepo;

    public function __construct() {
        $this->repo = new VerificationRepository();
        $this->userInfoRepo = new UserInfoRepository();
    }

    /**
     * Request verification email
     */
    public function requestVerification(): array {
        if (!is_user_logged_in()) {
            throw new Exception('Authentication required');
        }

        $userId = get_current_user_id();

        // Check if already verified
        if ($this->isVerified($userId)) {
            throw new Exception('Email already verified');
        }

        // Limit: 3 requests per 10 minutes
        RateLimiter::enforce('verify', 3, 600);

        // Generate secure token
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);

        $expiresAt = gmdate('Y-m-d H:i:s', time() + 3600); // 1 hour expiry

        // Store in database
        $this->repo->create($userId, $tokenHash, $expiresAt);

        // Send email
        $this->sendVerificationEmail($userId, $token);

        // Log the request
        AuditLogger::verificationRequest($userId);

        return [
            'success' => true,
            'message' => 'Verification email sent',
            'expires_in' => 3600
        ];
    }

    /**
     * Verify email with token
     */
    public function verifyEmail(int $userId, string $token): array {
        $tokenHash = hash('sha256', $token);

        $record = $this->repo->getValid($userId, $tokenHash);

        if (!$record) {
            throw new Exception('Invalid or expired verification token');
        }

        // Mark as verified (this will also update user_info via the repository)
        $this->repo->markVerified($record->id);

        // Clear any existing tokens
        $this->cleanupUserTokens($userId);

        // Log verification
        AuditLogger::verificationComplete($userId);

        // Trigger action for other plugins
        do_action('bcc_trust_user_verified', $userId);

        // Get updated user info for response
        $userInfo = $this->userInfoRepo->getByUserId($userId);

        return [
            'success' => true,
            'message' => 'Email verified successfully',
            'verified_at' => current_time('mysql'),
            'user_id' => $userId,
            'trust_boost' => $userInfo ? ($userInfo->trust_rank > 0 ? true : false) : false
        ];
    }

    /**
     * Verify using token only (from email link)
     */
    public function verifyByToken(string $token): array {
        $tokenHash = hash('sha256', $token);

        $record = $this->repo->getByCode($tokenHash);

        if (!$record) {
            throw new Exception('Invalid or expired verification token');
        }

        return $this->verifyEmail($record->user_id, $token);
    }

    /**
     * Check if user is verified using user_info table
     */
    public function isVerified(int $userId): bool {
        // Get from user_info table (source of truth)
        $userInfo = $this->userInfoRepo->getByUserId($userId);
        
        if ($userInfo) {
            return (bool) $userInfo->is_verified;
        }

        // Fallback to repository check if user_info not found
        return $this->repo->isVerified($userId);
    }

    /**
     * Get verification status from user_info table
     */
    public function getVerificationStatus(int $userId): array {
        $record = $this->repo->getForUser($userId);
        $userInfo = $this->userInfoRepo->getByUserId($userId);

        return [
            'user_id' => $userId,
            'is_verified' => $userInfo ? (bool) $userInfo->is_verified : false,
            'verified_at' => $record && $record->verified_at ? $record->verified_at : null,
            'last_request_at' => $record ? $record->created_at : null,
            'token_expires_at' => $record && !$record->verified_at ? $record->expires_at : null,
            'trust_rank' => $userInfo ? $userInfo->trust_rank : 0,
            'fraud_score' => $userInfo ? $userInfo->fraud_score : 0
        ];
    }

    /**
     * Resend verification email
     */
    public function resendVerification(): array {
        if (!is_user_logged_in()) {
            throw new Exception('Authentication required');
        }

        $userId = get_current_user_id();

        // Check if already verified
        if ($this->isVerified($userId)) {
            throw new Exception('Email already verified');
        }

        // Stricter rate limit for resends
        RateLimiter::enforce('verify_resend', 2, 600);

        // Generate new token
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);

        $expiresAt = gmdate('Y-m-d H:i:s', time() + 3600);

        // Create new token (old one will be auto-deleted by repository)
        $this->repo->create($userId, $tokenHash, $expiresAt);

        // Send email
        $this->sendVerificationEmail($userId, $token);

        AuditLogger::log('verification_resend', $userId, [], 'user');

        return [
            'success' => true,
            'message' => 'Verification email resent',
            'expires_in' => 3600
        ];
    }

    /**
     * Send verification email
     */
    private function sendVerificationEmail(int $userId, string $token): void {
        $user = get_userdata($userId);

        if (!$user) {
            throw new Exception('User not found');
        }

        // Build verification URL
        $verifyUrl = add_query_arg([
            'bcc_action' => 'verify',
            'token' => $token,
            'user_id' => $userId
        ], home_url('/verify-email'));

        // Email subject
        $subject = sprintf(
            __('[%s] Verify Your Email Address', 'bcc-trust'),
            get_bloginfo('name')
        );

        // Email message
        $message = sprintf(
            __("Hello %s,\n\nPlease verify your email address by clicking the link below:\n\n%s\n\nThis link will expire in 1 hour.\n\nIf you didn't request this, please ignore this email.", 'bcc-trust'),
            $user->display_name,
            $verifyUrl
        );

        // Send email
        $sent = wp_mail($user->user_email, $subject, $message);

        if (!$sent) {
            throw new Exception('Failed to send verification email');
        }
    }

    /**
     * Clean up old tokens for user
     */
    private function cleanupUserTokens(int $userId): void {
        global $wpdb;
        
        $table = bcc_trust_verifications_table();
        
        $wpdb->delete($table, [
            'user_id' => $userId,
            'verified_at' => null
        ], ['%d']);
    }

    /**
     * Get verification URL for manual sending
     */
    public function getVerificationUrl(int $userId, string $token): string {
        return add_query_arg([
            'bcc_action' => 'verify',
            'token' => $token,
            'user_id' => $userId
        ], home_url('/verify-email'));
    }

    /**
     * Get verification statistics
     */
    public function getStats(): array {
        return [
            'total_verified' => $this->userInfoRepo->countVerified(),
            'total_pending' => $this->repo->getPendingCount(),
            'completion_rate' => $this->repo->getCompletionRate()
        ];
    }

    /**
     * Admin: Manually verify a user
     */
    public function adminVerifyUser(int $userId, int $adminId): bool {
        if (!user_can($adminId, 'manage_options')) {
            throw new Exception('Unauthorized');
        }

        // Check if already verified
        if ($this->isVerified($userId)) {
            return false;
        }

        // Update user_info directly
        $result = $this->userInfoRepo->updateVerificationStatus($userId, true);
        
        if ($result) {
            AuditLogger::log('admin_verified_user', $userId, [
                'admin_id' => $adminId
            ], 'user');
        }

        return $result;
    }

    /**
     * Get users with pending verification
     */
    public function getPendingVerifications(int $limit = 100): array {
        return $this->repo->getUnverifiedUsers($limit);
    }

    /**
     * Alias for backward compatibility
     */
    public function request(): array {
        return $this->requestVerification();
    }

    /**
     * Alias for backward compatibility
     */
    public function verify(int $userId, string $token): array {
        return $this->verifyEmail($userId, $token);
    }
}