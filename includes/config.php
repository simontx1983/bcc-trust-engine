<?php
if (!defined('ABSPATH')) exit;

/**
 * Configuration constants for BCC Trust Engine
 * 
 * @package BCC_Trust_Engine
 * @version 2.0.0
 */

// ======================================================
// VOTE WEIGHT TIERS
// These control how much a user's vote counts based on
// their reputation tier
// ======================================================
define('BCC_TRUST_WEIGHT_ELITE', 0.35);      // Elite users: 35% weight
define('BCC_TRUST_WEIGHT_TRUSTED', 0.25);     // Trusted users: 25% weight
define('BCC_TRUST_WEIGHT_NEUTRAL', 0.15);     // Neutral users: 15% weight
define('BCC_TRUST_WEIGHT_CAUTION', 0.08);     // Caution users: 8% weight
define('BCC_TRUST_WEIGHT_RISKY', 0.03);       // Risky users: 3% weight

// Maximum vote weight (safety cap)
define('BCC_TRUST_MAX_VOTE_WEIGHT', 0.6);     // No vote can exceed 60% weight

// ======================================================
// ENDORSEMENT WEIGHT TIERS
// Endorsements have higher base weights than votes
// ======================================================
define('BCC_TRUST_ENDORSE_ELITE', 2.0);       // Elite endorsements: 2.0x
define('BCC_TRUST_ENDORSE_TRUSTED', 1.5);     // Trusted endorsements: 1.5x
define('BCC_TRUST_ENDORSE_NEUTRAL', 1.0);     // Neutral endorsements: 1.0x
define('BCC_TRUST_ENDORSE_CAUTION', 0.6);     // Caution endorsements: 0.6x
define('BCC_TRUST_ENDORSE_RISKY', 0.3);       // Risky endorsements: 0.3x

// Maximum endorsement weight (safety cap)
define('BCC_TRUST_MAX_ENDORSE_WEIGHT', 3.0);  // No endorsement can exceed 3.0x

// ======================================================
// SCORE CALCULATOR MULTIPLIERS
// Applied to votes when calculating page scores
// ======================================================
define('BCC_TRUST_MULTIPLIER_ELITE', 1.5);        // Elite votes count 1.5x
define('BCC_TRUST_MULTIPLIER_TRUSTED', 1.2);      // Trusted votes count 1.2x
define('BCC_TRUST_MULTIPLIER_NEUTRAL', 1.0);      // Neutral votes count 1.0x
define('BCC_TRUST_MULTIPLIER_CAUTION', 0.6);      // Caution votes count 0.6x
define('BCC_TRUST_MULTIPLIER_RISKY', 0.3);        // Risky votes count 0.3x
define('BCC_TRUST_MULTIPLIER_INSUFFICIENT', 0.5); // New users start at 0.5x

// ======================================================
// FRAUD SCORE THRESHOLDS
// Risk levels based on fraud score
// ======================================================
define('BCC_TRUST_FRAUD_CRITICAL', 80);    // Score >= 80: Critical risk - auto-suspend
define('BCC_TRUST_FRAUD_HIGH', 60);        // Score 60-79: High risk - manual review
define('BCC_TRUST_FRAUD_MEDIUM', 40);      // Score 40-59: Medium risk - monitor
define('BCC_TRUST_FRAUD_LOW', 20);         // Score 20-39: Low risk - normal
                                            // Score < 20: Minimal risk - trusted

// ======================================================
// ACCOUNT AGE THRESHOLDS (in days)
// Used for trust calculations and fraud detection
// ======================================================
define('BCC_TRUST_AGE_NEW', 7);             // Less than 7 days: New account
define('BCC_TRUST_AGE_ESTABLISHED', 30);    // 7-30 days: Developing account
define('BCC_TRUST_AGE_VERIFIED', 365);      // 30-365 days: Established account
                                            // >365 days: Veteran account

// ======================================================
// VOTE DECAY SETTINGS
// How quickly old votes lose influence
// ======================================================
define('BCC_TRUST_DECAY_DAYS', 90);          // Votes older than 90 days start decaying
define('BCC_TRUST_DECAY_MIN', 0.3);          // Minimum weight after full decay (30%)

// ======================================================
// CONFIDENCE CALCULATION
// Thresholds for data sufficiency
// ======================================================
define('BCC_TRUST_MAX_CONFIDENCE_VOTES', 50); // Votes needed for 100% confidence
define('BCC_TRUST_MIN_VOTES_RELIABLE', 10);   // Minimum votes for reliable scoring

// ======================================================
// RATE LIMITING
// Default limits if not overridden
// ======================================================
define('BCC_TRUST_RATE_LIMIT_DEFAULT', 20);   // Default: 20 actions
define('BCC_TRUST_RATE_WINDOW_DEFAULT', 60);  // Default window: 60 seconds

// ======================================================
// CACHE SETTINGS
// How long to cache various data
// ======================================================
define('BCC_TRUST_CACHE_SCORE', 3600);         // Cache scores for 1 hour
define('BCC_TRUST_CACHE_USER', 300);           // Cache user data for 5 minutes
define('BCC_TRUST_CACHE_FRAUD', 300);          // Cache fraud analysis for 5 minutes

// ======================================================
// CLEANUP SETTINGS
// How long to keep historical data
// ======================================================
define('BCC_TRUST_CLEANUP_FINGERPRINTS', 90);  // Keep fingerprints for 90 days
define('BCC_TRUST_CLEANUP_PATTERNS', 30);      // Keep behavioral patterns for 30 days
define('BCC_TRUST_CLEANUP_FRAUD_ANALYSIS', 90); // Keep fraud analysis for 90 days
define('BCC_TRUST_CLEANUP_ACTIVITY', 90);       // Keep activity logs for 90 days

// ======================================================
// VOTE RING DETECTION
// Thresholds for detecting collusion
// ======================================================
define('BCC_TRUST_RING_MIN_SIZE', 3);          // Minimum users to form a ring
define('BCC_TRUST_RING_MIN_MUTUAL', 3);        // Minimum mutual votes to trigger
define('BCC_TRUST_RING_STRENGTH_THRESHOLD', 5.0); // Minimum strength score

// ======================================================
// DEVICE FINGERPRINTING
// Thresholds for automation detection
// ======================================================
define('BCC_TRUST_AUTOMATION_HIGH', 70);       // >70: High confidence automation
define('BCC_TRUST_AUTOMATION_MEDIUM', 40);     // 40-70: Suspicious
define('BCC_TRUST_AUTOMATION_LOW', 20);        // 20-40: Monitor

// ======================================================
// SUSPENSION THRESHOLDS
// When to auto-suspend users
// ======================================================
define('BCC_TRUST_SUSPEND_SCORE', 85);          // Auto-suspend at fraud score >= 85
define('BCC_TRUST_SUSPEND_CONFIDENCE', 0.8);    // Require 80% confidence for suspension
