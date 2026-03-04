<?php
/**
 * GitHub Score Service
 *
 * Calculates trust scores and fraud reductions based on GitHub user data
 *
 * @package BCC_Trust_Engine
 * @subpackage GitHub
 * @version 2.3.0
 */

namespace BCCTrust\Services\github;

use Exception;

if (!defined('ABSPATH')) {
    exit;
}

class GitHubScoreService {
    
    // Score thresholds
    private const MAX_TRUST_BOOST = 50;
    private const MAX_FRAUD_REDUCTION = 40;
    
    // Weights for different factors
    private const WEIGHT_ACCOUNT_AGE = 0.25;
    private const WEIGHT_FOLLOWERS = 0.20;
    private const WEIGHT_REPOS = 0.15;
    private const WEIGHT_ORGS = 0.10;
    private const WEIGHT_EMAIL = 0.10;
    private const WEIGHT_PROFILE = 0.10;
    private const WEIGHT_ACTIVITY = 0.10;
    
    /**
     * Calculate comprehensive trust boost from GitHub data
     *
     * @param array $githubData Complete GitHub user data
     * @return float Trust boost value (0-50)
     */
    public function calculateTrustBoost(array $githubData): float {
        $scores = [];
        
        // Account age (max 20 points)
        $scores['account_age'] = $this->calculateAccountAgeScore($githubData);
        
        // Followers (max 15 points)
        $scores['followers'] = $this->calculateFollowersScore($githubData);
        
        // Repositories (max 10 points)
        $scores['repositories'] = $this->calculateRepositoriesScore($githubData);
        
        // Organizations (max 10 points)
        $scores['organizations'] = $this->calculateOrganizationsScore($githubData);
        
        // Email verification (max 5 points)
        $scores['email'] = $this->calculateEmailScore($githubData);
        
        // Profile completeness (max 5 points)
        $scores['profile'] = $this->calculateProfileScore($githubData);
        
        // Activity level (max 5 points)
        $scores['activity'] = $this->calculateActivityScore($githubData);
        
        // Gists (max 3 points)
        $scores['gists'] = $this->calculateGistsScore($githubData);
        
        // Account type (bonus)
        $scores['account_type'] = $this->calculateAccountTypeScore($githubData);
        
        // Calculate weighted total
        $totalScore = $this->calculateWeightedScore($scores);
        
        // Apply final caps
        $finalScore = min(self::MAX_TRUST_BOOST, $totalScore);
        
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('BCC Trust GitHub: Trust boost calculation - ' . json_encode([
                'scores' => $scores,
                'total' => $totalScore,
                'final' => $finalScore
            ]));
        }
        
        return round($finalScore, 1);
    }
    
    /**
     * Calculate fraud score reduction based on GitHub data
     *
     * @param array $githubData Complete GitHub user data
     * @param float $trustBoost Calculated trust boost
     * @return int Fraud reduction value (0-40)
     */
    public function calculateFraudReduction(array $githubData, float $trustBoost): int {
        $reduction = (int) floor($trustBoost * 0.6); // Base reduction from trust boost
        
        // Additional reductions for strong signals
        
        // High follower count
        $followers = $githubData['followers'] ?? 0;
        if ($followers > 1000) {
            $reduction += 10;
        } elseif ($followers > 500) {
            $reduction += 5;
        } elseif ($followers > 100) {
            $reduction += 1;
        }
        
        // Multiple organizations
        $orgCount = count($githubData['organizations'] ?? []);
        if ($orgCount > 10) {
            $reduction += 5;
        } elseif ($orgCount > 5) {
            $reduction += 3;
        } elseif ($orgCount > 2) {
            $reduction += 1;
        }
        
        // Very old account
        $accountAge = $this->getAccountAgeInDays($githubData);
        if ($accountAge > 365 * 5) { // 5+ years
            $reduction += 5;
        } elseif ($accountAge > 365 * 3) { // 3+ years
            $reduction += 2;
        } elseif ($accountAge > 365 * 2) { // 2+ years
            $reduction += 1;
        } elseif ($accountAge > 365) { // 1+ year
            $reduction += 1; // Changed from .5 to integer for consistency
        }
        
        // Verified email bonus
        if ($this->hasVerifiedEmail($githubData)) {
            $reduction += 2;
        }
        
        // Complete profile bonus
        $profileScore = $this->calculateProfileScore($githubData);
        if ($profileScore > 3) {
            $reduction += 2;
        }
        
        // Active developer bonus
        if ($this->isActiveDeveloper($githubData)) {
            $reduction += 3;
        }
        
        // Apply cap
        $finalReduction = min(self::MAX_FRAUD_REDUCTION, $reduction);
        
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('BCC Trust GitHub: Fraud reduction calculation - ' . json_encode([
                'base' => floor($trustBoost * 0.6),
                'bonuses' => $reduction - floor($trustBoost * 0.6),
                'total' => $reduction,
                'final' => $finalReduction
            ]));
        }
        
        return $finalReduction;
    }
    
    /**
     * Calculate account age score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-20)
     */
    private function calculateAccountAgeScore(array $githubData): float {
        $days = $this->getAccountAgeInDays($githubData);
        $years = $days / 365;
        
        if ($years >= 10) return 20;
        if ($years >= 8) return 19;
        if ($years >= 6) return 18;
        if ($years >= 5) return 17;
        if ($years >= 4) return 16;
        if ($years >= 3) return 15;
        if ($years >= 2) return 14;
        if ($years >= 1) return 12;
        if ($years >= 0.5) return 8;
        if ($years >= 0.25) return 5;
        if ($years >= 0.1) return 2;
        
        return 0;
    }
    
    /**
     * Calculate followers score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-15)
     */
    private function calculateFollowersScore(array $githubData): float {
        $followers = $githubData['followers'] ?? 0;
        
        if ($followers >= 10000) return 15;
        if ($followers >= 5000) return 14;
        if ($followers >= 2000) return 13;
        if ($followers >= 1000) return 12;
        if ($followers >= 500) return 11;
        if ($followers >= 200) return 10;
        if ($followers >= 100) return 9;
        if ($followers >= 50) return 8;
        if ($followers >= 20) return 7;
        if ($followers >= 10) return 6;
        if ($followers >= 5) return 5;
        if ($followers >= 2) return 3;
        if ($followers >= 1) return 1;
        
        return 0;
    }
    
    /**
     * Calculate repositories score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-10)
     */
    private function calculateRepositoriesScore(array $githubData): float {
        $repos = $githubData['public_repos'] ?? 0;
        
        if ($repos >= 100) return 10;
        if ($repos >= 50) return 9;
        if ($repos >= 30) return 8;
        if ($repos >= 20) return 7;
        if ($repos >= 15) return 6;
        if ($repos >= 10) return 5;
        if ($repos >= 7) return 4;
        if ($repos >= 5) return 3;
        if ($repos >= 3) return 2;
        if ($repos >= 1) return 1;
        
        return 0;
    }
    
    /**
     * Calculate organizations score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-10)
     */
    private function calculateOrganizationsScore(array $githubData): float {
        $orgs = count($githubData['organizations'] ?? []);
        
        if ($orgs >= 20) return 10;
        if ($orgs >= 15) return 9;
        if ($orgs >= 10) return 8;
        if ($orgs >= 7) return 7;
        if ($orgs >= 5) return 6;
        if ($orgs >= 4) return 5;
        if ($orgs >= 3) return 4;
        if ($orgs >= 2) return 3;
        if ($orgs >= 1) return 2;
        
        return 0;
    }
    
    /**
     * Calculate email verification score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-5)
     */
    private function calculateEmailScore(array $githubData): float {
        $score = 0;
        
        // Has any email
        if (!empty($githubData['email'])) {
            $score += 1;
        }
        
        // Has verified email
        if ($this->hasVerifiedEmail($githubData)) {
            $score += 2;
        }
        
        // Email matches domain or is professional
        $email = $githubData['email'] ?? '';
        if (!empty($email)) {
            // Check for professional email (not gmail/yahoo/hotmail)
            $professionalDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
            $domain = substr(strrchr($email, "@"), 1);
            if (!in_array($domain, $professionalDomains)) {
                $score += 1;
            }
        }
        
        return min(5, $score);
    }
    
    /**
     * Calculate profile completeness score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-5)
     */
    private function calculateProfileScore(array $githubData): float {
        $score = 0;
        
        if (!empty($githubData['name'])) $score += 1;
        if (!empty($githubData['bio'])) $score += 1;
        if (!empty($githubData['location'])) $score += 0.5;
        if (!empty($githubData['company'])) $score += 0.5;
        if (!empty($githubData['blog'])) $score += 0.5;
        if (!empty($githubData['twitter_username'])) $score += 0.5;
        if (!empty($githubData['hireable'])) $score += 1;
        
        return min(5, $score);
    }
    
    /**
     * Calculate activity score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-5)
     */
    private function calculateActivityScore(array $githubData): float {
        $score = 0;
        
        // Recent activity
        if (!empty($githubData['updated_at'])) {
            $lastUpdate = strtotime($githubData['updated_at']);
            $daysSinceUpdate = (time() - $lastUpdate) / DAY_IN_SECONDS;
            
            if ($daysSinceUpdate < 7) {
                $score += 2;
            } elseif ($daysSinceUpdate < 30) {
                $score += 1.5;
            } elseif ($daysSinceUpdate < 90) {
                $score += 1;
            } elseif ($daysSinceUpdate < 365) {
                $score += 0.5;
            }
        }
        
        // Following ratio (engagement)
        $following = $githubData['following'] ?? 0;
        $followers = $githubData['followers'] ?? 0;
        if ($following > 0 && $followers > 0) {
            $ratio = min($following / $followers, 2);
            if ($ratio > 0.5) {
                $score += 1;
            }
        }
        
        // Starred repos (interest in community)
        $starred = $githubData['starred'] ?? 0;
        if ($starred > 50) {
            $score += 2;
        } elseif ($starred > 20) {
            $score += 1.5;
        } elseif ($starred > 10) {
            $score += 1;
        } elseif ($starred > 5) {
            $score += 0.5;
        }
        
        return min(5, $score);
    }
    
    /**
     * Calculate gists score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-3)
     */
    private function calculateGistsScore(array $githubData): float {
        $gists = $githubData['public_gists'] ?? 0;
        
        if ($gists >= 20) return 3;
        if ($gists >= 10) return 2;
        if ($gists >= 5) return 1.5;
        if ($gists >= 2) return 1;
        if ($gists >= 1) return 0.5;
        
        return 0;
    }
    
    /**
     * Calculate account type score
     *
     * @param array $githubData GitHub user data
     * @return float Score (0-2)
     */
    private function calculateAccountTypeScore(array $githubData): float {
        // Bonus for being a site admin (trusted by GitHub)
        if (!empty($githubData['site_admin']) && $githubData['site_admin']) {
            return 2;
        }
        
        return 0;
    }
    
    /**
     * Calculate weighted score from individual components
     *
     * @param array $scores Individual component scores
     * @return float Weighted total
     */
    private function calculateWeightedScore(array $scores): float {
        $weights = [
            'account_age' => self::WEIGHT_ACCOUNT_AGE,
            'followers' => self::WEIGHT_FOLLOWERS,
            'repositories' => self::WEIGHT_REPOS,
            'organizations' => self::WEIGHT_ORGS,
            'email' => self::WEIGHT_EMAIL,
            'profile' => self::WEIGHT_PROFILE,
            'activity' => self::WEIGHT_ACTIVITY,
            'gists' => 0.05, // 5% weight
            'account_type' => 0.05, // 5% weight
        ];
        
        $total = 0;
        foreach ($scores as $key => $score) {
            $weight = $weights[$key] ?? 0.1;
            $total += $score * $weight * 4; // Scale factor to reach max 50
        }
        
        return $total;
    }
    
    /**
     * Check if user has verified email
     *
     * @param array $githubData GitHub user data
     * @return bool
     */
    private function hasVerifiedEmail(array $githubData): bool {
        // Check emails array
        if (!empty($githubData['emails'])) {
            foreach ($githubData['emails'] as $email) {
                if (!empty($email['verified'])) {
                    return true;
                }
            }
        }
        
        // Profile email is always verified by GitHub
        return !empty($githubData['email']);
    }
    
    /**
     * Get account age in days
     *
     * @param array $githubData GitHub user data
     * @return int
     */
    private function getAccountAgeInDays(array $githubData): int {
        if (empty($githubData['created_at'])) {
            return 0;
        }
        
        $created = strtotime($githubData['created_at']);
        return (int) ((time() - $created) / DAY_IN_SECONDS);
    }
    
    /**
     * Check if user is an active developer
     *
     * @param array $githubData GitHub user data
     * @return bool
     */
    private function isActiveDeveloper(array $githubData): bool {
        $conditions = 0;
        
        // Has recent activity
        if (!empty($githubData['updated_at'])) {
            $lastUpdate = strtotime($githubData['updated_at']);
            $daysSinceUpdate = (time() - $lastUpdate) / DAY_IN_SECONDS;
            if ($daysSinceUpdate < 30) {
                $conditions++;
            }
        }
        
        // Has repositories
        if (($githubData['public_repos'] ?? 0) >= 5) {
            $conditions++;
        }
        
        // Has followers
        if (($githubData['followers'] ?? 0) >= 10) {
            $conditions++;
        }
        
        // Has organizations
        if (count($githubData['organizations'] ?? []) >= 2) {
            $conditions++;
        }
        
        return $conditions >= 2;
    }
    
    /**
     * Get trust level label based on boost value
     *
     * @param float $trustBoost Calculated trust boost
     * @return string Trust level label
     */
    public function getTrustLevelLabel(float $trustBoost): string {
        if ($trustBoost >= 40) return 'Elite';
        if ($trustBoost >= 30) return 'Highly Trusted';
        if ($trustBoost >= 20) return 'Trusted';
        if ($trustBoost >= 10) return 'Verified';
        if ($trustBoost >= 5) return 'Basic';
        return 'Unverified';
    }
    
    /**
     * Get fraud risk level based on reduction
     *
     * @param int $fraudReduction Calculated fraud reduction
     * @return string Risk level
     */
    public function getRiskLevelLabel(int $fraudReduction): string {
        if ($fraudReduction >= 30) return 'Minimal Risk';
        if ($fraudReduction >= 20) return 'Low Risk';
        if ($fraudReduction >= 10) return 'Medium Risk';
        if ($fraudReduction >= 5) return 'High Risk';
        return 'Critical Risk';
    }
    
    /**
     * Get detailed breakdown of trust factors
     *
     * @param array $githubData GitHub user data
     * @return array Detailed breakdown
     */
    public function getDetailedBreakdown(array $githubData): array {
        return [
            'account_age' => [
                'score' => $this->calculateAccountAgeScore($githubData),
                'details' => $this->getAccountAgeInDays($githubData) . ' days'
            ],
            'followers' => [
                'score' => $this->calculateFollowersScore($githubData),
                'details' => ($githubData['followers'] ?? 0) . ' followers'
            ],
            'repositories' => [
                'score' => $this->calculateRepositoriesScore($githubData),
                'details' => ($githubData['public_repos'] ?? 0) . ' public repos'
            ],
            'organizations' => [
                'score' => $this->calculateOrganizationsScore($githubData),
                'details' => count($githubData['organizations'] ?? []) . ' organizations'
            ],
            'email' => [
                'score' => $this->calculateEmailScore($githubData),
                'details' => $this->hasVerifiedEmail($githubData) ? 'Verified' : 'Not verified'
            ],
            'profile' => [
                'score' => $this->calculateProfileScore($githubData),
                'details' => 'Profile completeness'
            ],
            'activity' => [
                'score' => $this->calculateActivityScore($githubData),
                'details' => 'Recent activity'
            ]
        ];
    }
}