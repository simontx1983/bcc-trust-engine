<?php
if (!defined('ABSPATH')) exit;

/**
 * Configuration constants for BCC Trust Engine
 */

// Vote weight tiers
define('BCC_TRUST_WEIGHT_ELITE', 0.35);
define('BCC_TRUST_WEIGHT_TRUSTED', 0.25);
define('BCC_TRUST_WEIGHT_NEUTRAL', 0.15);
define('BCC_TRUST_WEIGHT_CAUTION', 0.08);
define('BCC_TRUST_WEIGHT_RISKY', 0.03);

// Endorsement weight tiers
define('BCC_TRUST_ENDORSE_ELITE', 2.0);
define('BCC_TRUST_ENDORSE_TRUSTED', 1.5);
define('BCC_TRUST_ENDORSE_NEUTRAL', 1.0);
define('BCC_TRUST_ENDORSE_CAUTION', 0.6);
define('BCC_TRUST_ENDORSE_RISKY', 0.3);

// Score calculator multipliers
define('BCC_TRUST_MULTIPLIER_ELITE', 1.5);
define('BCC_TRUST_MULTIPLIER_TRUSTED', 1.2);
define('BCC_TRUST_MULTIPLIER_NEUTRAL', 1.0);
define('BCC_TRUST_MULTIPLIER_CAUTION', 0.6);
define('BCC_TRUST_MULTIPLIER_RISKY', 0.3);
define('BCC_TRUST_MULTIPLIER_INSUFFICIENT', 0.5);

// Fraud score thresholds
define('BCC_TRUST_FRAUD_CRITICAL', 80);
define('BCC_TRUST_FRAUD_HIGH', 60);
define('BCC_TRUST_FRAUD_MEDIUM', 40);
define('BCC_TRUST_FRAUD_LOW', 20);

// Account age thresholds (in days)
define('BCC_TRUST_AGE_NEW', 7);
define('BCC_TRUST_AGE_ESTABLISHED', 30);
define('BCC_TRUST_AGE_VERIFIED', 365);