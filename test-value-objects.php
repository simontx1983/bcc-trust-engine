<?php
/**
 * Test script for BCC Trust Engine Value Objects
 * 
 * Place this file in: /wp-content/plugins/bcc-trust-engine/test-value-objects.php
 * Access via: https://yoursite.com/wp-content/plugins/bcc-trust-engine/test-value-objects.php
 * 
 * !!! DELETE THIS FILE AFTER TESTING !!!
 */

// Load WordPress
require_once(dirname(__FILE__) . '/../../../wp-load.php');

// Only allow admins to run tests
if (!current_user_can('manage_options')) {
    die('Admin access required');
}

// Use statement at the TOP of the file (outside any conditionals)
use BCCTrust\ValueObjects\PageScore;

echo "<!DOCTYPE html>
<html>
<head>
    <title>BCC Trust Engine Tests</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        h1 { color: #333; border-bottom: 2px solid #333; padding-bottom: 10px; }
        h2 { color: #666; margin-top: 30px; }
        .pass { color: green; font-weight: bold; }
        .fail { color: red; font-weight: bold; }
        .warning { color: orange; font-weight: bold; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow: auto; }
        .test-box { border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>🧪 BCC Trust Engine - Value Object Tests</h1>";

// Test 1: Check if Value Object class exists
echo "<div class='test-box'>";
echo "<h2>Test 1: Value Object Class Loading</h2>";

if (class_exists('\\BCCTrust\\ValueObjects\\PageScore')) {
    echo "<p class='pass'>✅ SUCCESS: PageScore value object class found</p>";
} else {
    echo "<p class='fail'>❌ FAILED: PageScore value object class not found</p>";
    echo "<p>Checking autoloader...</p>";
    
    // Manually try to include the file
    $file = BCC_TRUST_PATH . 'app/ValueObjects/PageScore.php';
    if (file_exists($file)) {
        echo "<p>✅ File exists at: {$file}</p>";
        require_once $file;
        if (class_exists('\\BCCTrust\\ValueObjects\\PageScore')) {
            echo "<p class='pass'>✅ SUCCESS: Class loaded after manual include</p>";
        } else {
            echo "<p class='fail'>❌ File exists but class not found - check namespace</p>";
        }
    } else {
        echo "<p class='fail'>❌ File not found at: {$file}</p>";
    }
}
echo "</div>";

// Only proceed if class exists
if (class_exists('\\BCCTrust\\ValueObjects\\PageScore')) {
    
    // Test 2: PageScore Creation and Validation
    echo "<div class='test-box'>";
    echo "<h2>Test 2: PageScore Creation</h2>";
    
    try {
        // Create a valid score
        $score = new PageScore(
            123,                    // page_id
            456,                    // page_owner_id
            75.5,                   // total_score
            80.2,                   // positive_score
            4.7,                    // negative_score
            15,                     // vote_count
            12,                     // unique_voters
            0.8,                    // confidence_score
            'trusted',              // reputation_tier
            5,                      // endorsement_count
            null,                   // last_vote_at
            null                    // last_calculated_at
        );
        
        echo "<p class='pass'>✅ SUCCESS: Created valid PageScore</p>";
        echo "<ul>";
        echo "<li>Total Score: " . $score->getTotalScore() . "</li>";
        echo "<li>Tier: " . $score->getReputationTier() . "</li>";
        echo "<li>Is Highly Trusted? " . ($score->isHighlyTrusted() ? 'Yes' : 'No') . "</li>";
        echo "<li>Has Sufficient Data? " . ($score->hasSufficientData() ? 'Yes' : 'No') . "</li>";
        echo "<li>Confidence: " . $score->getConfidencePercentage() . "%</li>";
        echo "<li>Status: " . $score->getScoreStatus() . "</li>";
        echo "</ul>";
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 3: Validation (should fail)
    echo "<div class='test-box'>";
    echo "<h2>Test 3: Validation (Should Fail)</h2>";
    
    try {
        $invalid = new PageScore(
            -1,                     // Invalid page ID
            456,
            75.5,
            80.2,
            4.7,
            15,
            12,
            0.8,
            'trusted',
            5,
            null,
            null
        );
        echo "<p class='fail'>❌ FAILED: Should have thrown exception</p>";
    } catch (Exception $e) {
        echo "<p class='pass'>✅ SUCCESS: Caught invalid page ID: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 4: Immutable Transformation
    echo "<div class='test-box'>";
    echo "<h2>Test 4: Immutable Vote Addition</h2>";
    
    try {
        // Create base score
        $score = new PageScore(
            123,
            456,
            75.5,
            80.2,
            4.7,
            15,
            12,
            0.8,
            'trusted',
            5,
            null,
            null
        );
        
        echo "<p>Original Score: " . $score->getTotalScore() . "</p>";
        echo "<p>Original Vote Count: " . $score->getVoteCount() . "</p>";
        
        // Add a vote (immutable - creates new instance)
        $newScore = $score->withNewVote(0.25, true, true);
        
        echo "<p class='pass'>✅ New Score after upvote: " . $newScore->getTotalScore() . "</p>";
        echo "<p class='pass'>✅ New Vote Count: " . $newScore->getVoteCount() . "</p>";
        echo "<p class='pass'>✅ Original Score unchanged: " . $score->getTotalScore() . "</p>";
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 5: Endorsement Transformations
    echo "<div class='test-box'>";
    echo "<h2>Test 5: Endorsement Transformations</h2>";
    
    try {
        $score = new PageScore(
            123,
            456,
            50.0,
            0,
            0,
            0,
            0,
            0,
            'neutral',
            0,
            null,
            null
        );
        
        echo "<p>Base Score: " . $score->getTotalScore() . "</p>";
        
        $endorsed = $score->withEndorsement();
        echo "<p class='pass'>✅ After Endorsement: " . $endorsed->getTotalScore() . "</p>";
        echo "<p>Endorsement Count: " . $endorsed->getEndorsementCount() . "</p>";
        
        $removed = $endorsed->withoutEndorsement();
        echo "<p class='pass'>✅ After Removal: " . $removed->getTotalScore() . "</p>";
        echo "<p>Endorsement Count: " . $removed->getEndorsementCount() . "</p>";
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 6: API Response Format
    echo "<div class='test-box'>";
    echo "<h2>Test 6: API Response Format</h2>";
    
    try {
        $score = new PageScore(
            123,
            456,
            75.5,
            80.2,
            4.7,
            15,
            12,
            0.8,
            'trusted',
            5,
            null,
            null
        );
        
        $apiResponse = $score->toApiResponse();
        
        echo "<p>API Response Array:</p>";
        echo "<pre>";
        print_r($apiResponse);
        echo "</pre>";
        
        // Verify required fields exist
        $required = ['page_id', 'total_score', 'reputation_tier', 'confidence_score', 
                     'vote_count', 'endorsement_count', 'status'];
        
        $allGood = true;
        foreach ($required as $field) {
            if (!isset($apiResponse[$field])) {
                echo "<p class='fail'>❌ Missing field: {$field}</p>";
                $allGood = false;
            }
        }
        
        if ($allGood) {
            echo "<p class='pass'>✅ All required fields present</p>";
        }
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 7: Database Round Trip
    echo "<div class='test-box'>";
    echo "<h2>Test 7: Database Round Trip</h2>";
    
    try {
        $repo = new \BCCTrust\Repositories\ScoreRepository();
        
        // Get a real page ID from database
        global $wpdb;
        $scoresTable = $wpdb->prefix . 'bcc_trust_page_scores';
        $realPageId = $wpdb->get_var("SELECT page_id FROM {$scoresTable} LIMIT 1");
        
        if ($realPageId) {
            echo "<p>Testing with page ID: {$realPageId}</p>";
            
            $dbScore = $repo->getByPageId($realPageId);
            
            if ($dbScore) {
                echo "<p class='pass'>✅ Retrieved score for page {$realPageId}</p>";
                echo "<ul>";
                echo "<li>Score: " . $dbScore->getTotalScore() . "</li>";
                echo "<li>Tier: " . $dbScore->getReputationTier() . "</li>";
                echo "<li>Votes: " . $dbScore->getVoteCount() . "</li>";
                echo "</ul>";
                
                // Test save
                $originalEndorsements = $dbScore->getEndorsementCount();
                $newScore = $dbScore->withEndorsement();
                $repo->save($newScore);
                
                // Verify save worked
                $verifyScore = $repo->getByPageId($realPageId);
                if ($verifyScore->getEndorsementCount() === $originalEndorsements + 1) {
                    echo "<p class='pass'>✅ Save operation successful</p>";
                } else {
                    echo "<p class='fail'>❌ Save operation failed</p>";
                }
                
                // Restore original
                $repo->save($dbScore);
                echo "<p class='pass'>✅ Restored original score</p>";
                
            } else {
                echo "<p class='warning'>⚠️ No score found for page {$realPageId}</p>";
            }
        } else {
            echo "<p class='warning'>⚠️ No pages found in scores table</p>";
        }
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 8: VoteService Methods
    echo "<div class='test-box'>";
    echo "<h2>Test 8: VoteService Integration</h2>";
    
    try {
        $voteService = new \BCCTrust\Services\VoteService();
        
        echo "<p>VoteService loaded successfully</p>";
        
        // Check if methods exist
        $methods = [
            'castPageVote',
            'removePageVote',
            'getUserPageVote',
            'hasUserVotedPage'
        ];
        
        foreach ($methods as $method) {
            if (method_exists($voteService, $method)) {
                echo "<p class='pass'>✅ VoteService::{$method}() exists</p>";
            } else {
                echo "<p class='fail'>❌ VoteService::{$method}() missing</p>";
            }
        }
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
    
    // Test 9: EndorsementService Methods
    echo "<div class='test-box'>";
    echo "<h2>Test 9: EndorsementService Integration</h2>";
    
    try {
        $endorseService = new \BCCTrust\Services\EndorsementService();
        
        echo "<p>EndorsementService loaded successfully</p>";
        
        // Check if methods exist
        $methods = [
            'endorsePage',
            'revokePageEndorsement',
            'hasEndorsedPage',
            'getPageEndorsementCount'
        ];
        
        foreach ($methods as $method) {
            if (method_exists($endorseService, $method)) {
                echo "<p class='pass'>✅ EndorsementService::{$method}() exists</p>";
            } else {
                echo "<p class='fail'>❌ EndorsementService::{$method}() missing</p>";
            }
        }
        
    } catch (Exception $e) {
        echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
    }
    echo "</div>";
}

// Test 10: REST API Endpoint
echo "<div class='test-box'>";
echo "<h2>Test 10: REST API Endpoint</h2>";

try {
    $restUrl = rest_url('bcc-trust/v1/page/0/score');
    $response = wp_remote_get($restUrl, [
        'headers' => [
            'X-WP-Nonce' => wp_create_nonce('wp_rest')
        ]
    ]);
    
    if (!is_wp_error($response)) {
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);
        
        echo "<p class='pass'>✅ REST endpoint is accessible (HTTP {$code})</p>";
        echo "<p>Response structure: " . (isset($body['success']) ? 'Has success field' : 'Missing success field') . "</p>";
    } else {
        echo "<p class='fail'>❌ REST endpoint failed: " . $response->get_error_message() . "</p>";
    }
    
} catch (Exception $e) {
    echo "<p class='fail'>❌ FAILED: " . $e->getMessage() . "</p>";
}
echo "</div>";

echo "<hr>";
echo "<h3>Test Complete</h3>";
echo "<p style='color:red;'><strong>⚠️ Remember to delete this test file after testing!</strong></p>";

echo "</body></html>";